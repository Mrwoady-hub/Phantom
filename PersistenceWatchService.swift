import Combine
import Foundation

// MARK: - PersistenceWatchService
//
// Event-driven, real-time persistence monitor.
//
// PROBLEM THIS SOLVES:
//   PersistenceScanner runs once per scan cycle (60–300s). That means a malware
//   LaunchAgent could be installed and active for minutes before Phantom sees it.
//   This service eliminates that window entirely.
//
// HOW IT WORKS:
//   • Uses kqueue via DispatchSource.makeFileSystemObjectSource to watch the 9
//     canonical macOS persistence directories. No polling, no timers — the kernel
//     delivers an event the instant a file is added, removed, or renamed in a
//     watched directory.
//   • On each event, a 300 ms debounce coalesces installer bursts (e.g., a package
//     writing 12 plists fires 12 kqueue events → one rescan).
//   • After the debounce, PersistenceScanner re-scans only the affected directories.
//   • The new file list is diffed against the last snapshot: added / removed items
//     become PersistenceDelta records and are reported immediately via callback.
//   • The caller (AppModel) converts deltas to Incidents, writes to AuditTrailStore,
//     and fires notifications — all without waiting for the next full scan cycle.
//
// THREADING:
//   • kqueue events are delivered on a private DispatchQueue (utility QoS).
//   • The event handler immediately hops to @MainActor via Task { @MainActor in ... }.
//   • All published state and snapshot mutation happens on the main actor.
//
// COVERAGE:
//   ~/Library/LaunchAgents          ← user persistence, highest malware signal
//   /Library/LaunchAgents           ← third-party system-level agents
//   /Library/LaunchDaemons          ← third-party system daemons
//   ~/Library/Preferences/ByHost    ← legacy loginwindow hooks
//   /Library/Extensions             ← third-party kernel extensions
//   /var/at/tabs                    ← user cron jobs
//   /etc/periodic/daily|weekly|monthly  ← periodic scripts

@MainActor
final class PersistenceWatchService: ObservableObject {

    // MARK: - Published State

    @Published private(set) var isWatching:    Bool               = false
    @Published private(set) var lastChangeAt:  Date?
    @Published private(set) var recentDeltas:  [PersistenceDelta] = []

    // MARK: - Callback

    /// Fires on the main actor whenever a persistence change is detected.
    /// Receives the full list of deltas from the most recent change event.
    var onDeltasDetected: (([PersistenceDelta]) -> Void)?

    // MARK: - Internal State

    /// One kqueue watch per directory: (source, open file descriptor).
    /// The cancel handler on each source closes the fd automatically.
    private var watchSources: [(source: any DispatchSourceProtocol, fd: Int32)] = []

    /// Last known file paths per watched directory. Keyed by absolute directory path.
    private var snapshots: [String: Set<String>] = [:]

    /// Debounce: cancelled and recreated on every rapid-fire kqueue event.
    private var debounceTask: Task<Void, Never>?

    /// Directories with pending rescans (accumulated during debounce window).
    private var pendingDirectories: Set<String> = []

    private let scanner    = PersistenceScanner()
    private let eventQueue = DispatchQueue(
        label: "com.woady.phantom.persistence-watch",
        qos:   .utility
    )

    // MARK: - Watched Directories

    static var watchedDirectories: [String] {
        let home = NSHomeDirectory()
        return [
            "\(home)/Library/LaunchAgents",
            "/Library/LaunchAgents",
            "/Library/LaunchDaemons",
            "\(home)/Library/Preferences/ByHost",
            "/Library/Extensions",
            "/var/at/tabs",
            "/etc/periodic/daily",
            "/etc/periodic/weekly",
            "/etc/periodic/monthly"
        ]
    }

    // MARK: - Lifecycle

    func startWatching() {
        guard watchSources.isEmpty else { return }

        // Baseline snapshot so the first diff has something to compare against
        buildInitialSnapshots()

        var activeCount = 0
        for dir in Self.watchedDirectories {
            // O_EVTONLY: open purely for event watching — does not prevent unmount
            // and does not count as an active file descriptor for the directory.
            let fd = Darwin.open(dir, O_EVTONLY)
            guard fd >= 0 else { continue }   // directory doesn't exist — skip silently

            // NOTE_WRITE on a directory fires when entries are added, removed, or
            // renamed inside it. This is exactly the signal we need.
            let source = DispatchSource.makeFileSystemObjectSource(
                fileDescriptor: fd,
                eventMask:      .write,
                queue:          eventQueue
            )

            // Capture directory path by value — the closure runs on eventQueue.
            let capturedDir = dir
            source.setEventHandler { [weak self] in
                // Hop to main actor immediately — all state lives there.
                Task { @MainActor [weak self] in
                    self?.scheduleRescan(for: capturedDir)
                }
            }

            // When the source is cancelled, close the fd.
            source.setCancelHandler { Darwin.close(fd) }
            source.resume()

            watchSources.append((source: source, fd: fd))
            activeCount += 1
        }

        isWatching = activeCount > 0
    }

    func stopWatching() {
        for item in watchSources { item.source.cancel() }
        watchSources.removeAll()
        debounceTask?.cancel()
        debounceTask = nil
        isWatching   = false
    }

    // MARK: - Initial Snapshot

    private func buildInitialSnapshots() {
        let allRecords = scanner.scanLaunchAgentRecords()
        for dir in Self.watchedDirectories {
            let inDir = allRecords.filter { belongsTo(path: $0.path, directory: dir) }
            snapshots[dir] = Set(inDir.map { $0.path })
        }
    }

    // MARK: - Debounced Rescan

    private func scheduleRescan(for directory: String) {
        pendingDirectories.insert(directory)

        // Cancel any in-flight debounce and start a fresh 300 ms window.
        // This coalesces rapid installer bursts into a single rescan.
        debounceTask?.cancel()
        debounceTask = Task { [weak self] in
            do    { try await Task.sleep(for: .milliseconds(300)) }
            catch { return }   // cancelled — another event arrived; let that one handle it
            await self?.performDiffRescan()
        }
    }

    // MARK: - Delta Computation

    /// Rescans affected directories and diffs against snapshots.
    /// Emits deltas to the callback and updates published state.
    private func performDiffRescan() async {
        let dirs = pendingDirectories
        pendingDirectories.removeAll()

        // PersistenceScanner is fast (< 80 ms typical) and already handles all layers.
        let newRecords = scanner.scanLaunchAgentRecords()
        var allDeltas:  [PersistenceDelta] = []

        for dir in dirs {
            let oldPaths = snapshots[dir] ?? []
            let newInDir = newRecords.filter { belongsTo(path: $0.path, directory: dir) }
            let newPaths = Set(newInDir.map { $0.path })

            // ── Added items ────────────────────────────────────────────────────
            for path in newPaths.subtracting(oldPaths) {
                if let rec = newInDir.first(where: { $0.path == path }) {
                    allDeltas.append(PersistenceDelta(kind: .added, record: rec))
                }
            }

            // ── Removed items ──────────────────────────────────────────────────
            // Reconstruct a minimal PersistenceRecord from what we knew before.
            for path in oldPaths.subtracting(newPaths) {
                let record = PersistenceRecord(
                    path:      path,
                    scope:     scopeFor(directory: dir),
                    category:  categoryFor(directory: dir),
                    isSymlink: false,
                    isPlist:   path.hasSuffix(".plist")
                )
                allDeltas.append(PersistenceDelta(kind: .removed, record: record))
            }

            // Update snapshot to new reality
            snapshots[dir] = newPaths
        }

        guard !allDeltas.isEmpty else { return }

        lastChangeAt = Date()
        // Keep the 100 most recent deltas for display
        recentDeltas = Array((allDeltas + recentDeltas).prefix(100))
        onDeltasDetected?(allDeltas)
    }

    // MARK: - Helpers

    /// True if `path` is directly inside `directory` (one level deep or the dir itself).
    private func belongsTo(path: String, directory: String) -> Bool {
        path.hasPrefix(directory + "/") || path == directory
    }

    private func categoryFor(directory: String) -> PersistenceRecord.Category {
        let lower = directory.lowercased()
        if lower.contains("extension")     { return .kernelExtension }
        if lower.contains("/at/tabs")      { return .cron            }
        if lower.contains("launchdaemon")  { return .launchDaemon    }
        if lower.contains("byhost")        { return .loginItem        }
        if lower.contains("periodic")      { return .periodic         }
        return .launchAgent
    }

    private func scopeFor(directory: String) -> String {
        let home = NSHomeDirectory()
        if directory.hasPrefix(home)              { return "user"            }
        if directory.contains("LaunchDaemon")     { return "system-daemon"   }
        if directory.contains("Extension")        { return "kernel"          }
        if directory.contains("periodic")         { return "system-periodic" }
        if directory.contains("/at/tabs")         { return "user-cron"       }
        return "system"
    }
}
