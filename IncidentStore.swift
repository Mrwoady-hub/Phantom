import Foundation

// MARK: - IncidentStore
//
// Persists the current incident list across app launches so the dashboard
// is never blank on cold start.
//
// Storage:  ~/Library/Application Support/Phantom/Phantom-Incidents.json
// Permissions: 0600 (owner read/write), directory 0700.
//
// Design decisions:
//   • Written atomically after every apply(snapshot:) and persistence-delta
//     ingestion — the same event that updates AppModel.incidents.
//   • On load, resolved incidents older than `maxResolvedAge` are pruned to
//     prevent unbounded growth.  Active incidents are never pruned.
//   • No HMAC chain — incidents are reconstruction input for the UI, not a
//     security-critical audit record (that role belongs to AuditTrailStore).
//     Tampering would only affect the display, not detection outcomes.
//   • Clear() removes the file so a deliberate "clear incidents" action also
//     resets the cold-start state.

enum IncidentStore {

    // MARK: - Configuration

    /// Resolved incidents older than this are dropped on save to bound file size.
    /// Active incidents are always retained regardless of age.
    nonisolated private static let maxResolvedAge: TimeInterval = 7 * 24 * 3600   // 7 days

    // MARK: - Storage

    nonisolated private static let directoryName = "Phantom"
    nonisolated private static let fileName      = "Phantom-Incidents.json"

    nonisolated private static var fileURL: URL {
        let base = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first!
        let dir = base.appendingPathComponent(directoryName, isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o700],
            ofItemAtPath: dir.path
        )
        return dir.appendingPathComponent(fileName)
    }

    // MARK: - Public Interface

    /// Loads persisted incidents.  Returns [] on any error or on first launch.
    /// Resolved incidents older than `maxResolvedAge` are silently excluded.
    nonisolated static func load() -> [Incident] {
        guard let data = try? Data(contentsOf: fileURL) else { return [] }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let all = (try? decoder.decode([Incident].self, from: data)) ?? []
        let cutoff = Date().addingTimeInterval(-maxResolvedAge)
        return all.filter { $0.status == .active || $0.lastSeen > cutoff }
    }

    /// Persists the current incident list.  Prunes old resolved items before
    /// writing so the file stays bounded regardless of how long the app runs.
    nonisolated static func save(_ incidents: [Incident]) {
        let cutoff  = Date().addingTimeInterval(-maxResolvedAge)
        let pruned  = incidents.filter { $0.status == .active || $0.lastSeen > cutoff }
        let encoder = JSONEncoder()
        encoder.outputFormatting     = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        guard let data = try? encoder.encode(pruned) else { return }
        try? data.write(to: fileURL, options: .atomic)
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: fileURL.path
        )
    }

    /// Removes the persisted file so the next cold launch starts blank.
    /// Call this from AppModel.clearIncidents().
    nonisolated static func clear() {
        try? FileManager.default.removeItem(at: fileURL)
    }
}
