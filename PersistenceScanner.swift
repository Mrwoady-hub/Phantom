import Foundation

struct PersistenceRecord: Identifiable, Hashable, Sendable {
    let path: String
    let scope: String
    let category: Category
    let isSymlink: Bool
    let isPlist: Bool

    enum Category: String, Sendable {
        case launchAgent     = "Launch Agent"
        case launchDaemon    = "Launch Daemon"
        case loginItem       = "Login Item"
        case cron            = "Cron Job"
        case periodic        = "Periodic Script"
        case kernelExtension = "Kernel Extension"
        case startupItem     = "Startup Item"
        case appScript       = "Application Script"
        case other           = "Other"
    }

    var id: String { "\(category.rawValue):\(path)" }
    var fileName: String { URL(fileURLWithPath: path).lastPathComponent }
    var isUserWritable: Bool { path.hasPrefix(NSHomeDirectory()) }
}

final class PersistenceScanner {

    func scanLaunchAgentRecords() -> [PersistenceRecord] {
        var findings: [PersistenceRecord] = []

        // ── LAYER 1: LaunchAgents — high signal ────────────────────────────────
        // User LaunchAgents: highest priority — user-writable, common malware vector
        findings += scan("/\(NSHomeDirectory())/Library/LaunchAgents",
                         scope: "user", category: .launchAgent, ext: ["plist"])

        // System LaunchAgents/Daemons: third-party software installs here
        // NOTE: We explicitly DO NOT scan /System/Library/LaunchAgents or
        // /System/Library/LaunchDaemons — those are SIP-protected and always Apple.
        findings += scan("/Library/LaunchAgents",
                         scope: "system-agent",  category: .launchAgent,  ext: ["plist"])
        findings += scan("/Library/LaunchDaemons",
                         scope: "system-daemon", category: .launchDaemon, ext: ["plist"])

        // ── LAYER 2: Login Items (macOS 13+ Background Task Management) ────────
        let btmPath = "\(NSHomeDirectory())/Library/Application Support/com.apple.backgroundtaskmanagementd"
        findings += scan(btmPath, scope: "user-login-item", category: .loginItem, ext: nil)

        // ── LAYER 3: Legacy loginwindow ByHost hooks ───────────────────────────
        let byHostPath = "\(NSHomeDirectory())/Library/Preferences/ByHost"
        findings += scan(byHostPath, scope: "user-loginwindow", category: .loginItem, ext: ["plist"])
            .filter { $0.fileName.lowercased().contains("loginwindow") }

        // ── LAYER 4: User crontab ──────────────────────────────────────────────
        let userCrontab = "/var/at/tabs/\(NSUserName())"
        if FileManager.default.fileExists(atPath: userCrontab) {
            findings.append(PersistenceRecord(
                path: userCrontab, scope: "user-cron",
                category: .cron, isSymlink: false, isPlist: false
            ))
        }

        // ── LAYER 5: /etc/periodic custom scripts ─────────────────────────────
        for period in ["daily", "weekly", "monthly"] {
            findings += scan("/etc/periodic/\(period)", scope: "system-periodic",
                             category: .periodic, ext: nil)
        }

        // ── LAYER 6: Third-party Kernel Extensions ────────────────────────────
        // SECURITY NOTE: We scan ONLY /Library/Extensions (third-party KEXTs).
        // /System/Library/Extensions is SIP-protected — contains ~500 Apple KEXTs,
        // all trusted by definition. Scanning it produced 1623 false positives
        // and caused CPU 72% from SecStaticCodeCreateWithPath × 500 calls.
        findings += scan("/Library/Extensions",
                         scope: "kernel", category: .kernelExtension, ext: ["kext"])

        // ── LAYER 7: Legacy StartupItems ──────────────────────────────────────
        findings += scan("/Library/StartupItems", scope: "system-startup",
                         category: .startupItem, ext: nil)

        // ── LAYER 8: Application Script hooks ────────────────────────────────
        let appScriptsPath = "\(NSHomeDirectory())/Library/Application Scripts"
        if let bundles = try? FileManager.default.contentsOfDirectory(atPath: appScriptsPath) {
            for bundle in bundles {
                findings += scan("\(appScriptsPath)/\(bundle)", scope: "app-script",
                                 category: .appScript, ext: nil)
            }
        }

        return findings
    }

    // MARK: - Private

    private func scan(
        _ directory: String,
        scope: String,
        category: PersistenceRecord.Category,
        ext: [String]?
    ) -> [PersistenceRecord] {
        let fm = FileManager.default
        guard let files = try? fm.contentsOfDirectory(atPath: directory) else { return [] }
        let dirURL = URL(fileURLWithPath: directory).standardizedFileURL
        var results: [PersistenceRecord] = []

        for file in files {
            // SECURITY: URL construction prevents "../" path traversal
            let fileURL = dirURL.appendingPathComponent(file).standardizedFileURL
            guard fileURL.path.hasPrefix(dirURL.path) else { continue }

            if let allowed = ext {
                guard allowed.contains(fileURL.pathExtension.lowercased()) else { continue }
            }

            let isSymlink = (try? fm.destinationOfSymbolicLink(atPath: fileURL.path)) != nil
            let isPlist   = fileURL.pathExtension.lowercased() == "plist"

            results.append(PersistenceRecord(
                path:      fileURL.path,
                scope:     scope,
                category:  category,
                isSymlink: isSymlink,
                isPlist:   isPlist
            ))
        }
        return results
    }
}
