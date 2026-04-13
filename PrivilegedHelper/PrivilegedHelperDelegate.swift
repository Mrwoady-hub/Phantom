import Foundation

// MARK: - PrivilegedHelperDelegate
//
// Owns the XPC listener and the run loop. When the app connects,
// it returns an HelperCommandHandler as the exported object.

final class PrivilegedHelperDelegate: NSObject, NSXPCListenerDelegate {

    private let listener: NSXPCListener

    override init() {
        listener = NSXPCListener(machServiceName: SGHelperMachServiceName)
        super.init()
        listener.delegate = self
    }

    func run() {
        listener.resume()
        RunLoop.main.run()   // block indefinitely; launchd manages lifecycle
    }

    // MARK: - NSXPCListenerDelegate

    func listener(
        _ listener: NSXPCListener,
        shouldAcceptNewConnection connection: NSXPCConnection
    ) -> Bool {
        // Export the handler as the SGPrivilegedHelperProtocol implementor
        connection.exportedInterface = NSXPCInterface(with: SGPrivilegedHelperProtocol.self)
        connection.exportedObject    = HelperCommandHandler()
        connection.resume()
        return true
    }
}

// MARK: - HelperCommandHandler
//
// Implements every method in SGPrivilegedHelperProtocol.
// Runs as root — all operations are read-only to limit blast radius.

final class HelperCommandHandler: NSObject, SGPrivilegedHelperProtocol {

    // MARK: - Version

    func getVersion(reply: @escaping (String) -> Void) {
        reply("3.0")
    }

    // MARK: - Privileged lsof

    func runPrivilegedLsof(reply: @escaping (String?) -> Void) {
        reply(shell("/usr/sbin/lsof", args: ["-nP", "-iTCP", "-iUDP"]))
    }

    // MARK: - /etc/hosts audit

    func checkEtcHosts(reply: @escaping ([String]) -> Void) {
        guard let contents = try? String(contentsOfFile: "/etc/hosts", encoding: .utf8)
        else { reply([]); return }

        // Domains whose redirection is always suspicious
        let sensitivePatterns = [
            "apple.com", "icloud.com", "ocsp.apple.com",
            "google.com", "googleapis.com",
            "microsoft.com", "windowsupdate.com",
            "softwareupdate.apple.com"
        ]
        let suspicious: [String] = contents
            .components(separatedBy: "\n")
            .filter { line in
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                guard !trimmed.isEmpty, !trimmed.hasPrefix("#") else { return false }
                let lower = trimmed.lowercased()
                return sensitivePatterns.contains { lower.contains($0) }
                    && !trimmed.hasPrefix("127.0.0.1")
                    && !trimmed.hasPrefix("::1")
            }
        reply(suspicious)
    }

    // MARK: - Kernel Extensions

    func listKernelExtensions(reply: @escaping (String?) -> Void) {
        reply(shell("/usr/sbin/kextstat", args: ["-l", "-b", "com.apple"]))
    }

    // MARK: - Sudoers audit

    func checkSudoers(reply: @escaping ([String]) -> Void) {
        var flaggedLines: [String] = []

        let paths = ["/etc/sudoers"] +
            ((try? FileManager.default.contentsOfDirectory(atPath: "/etc/sudoers.d"))?
                .map { "/etc/sudoers.d/\($0)" } ?? [])

        for path in paths {
            guard let contents = try? String(contentsOfFile: path, encoding: .utf8) else { continue }
            for line in contents.components(separatedBy: "\n") {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                guard !trimmed.isEmpty, !trimmed.hasPrefix("#") else { continue }
                // Flag NOPASSWD grants to non-standard users
                if trimmed.lowercased().contains("nopasswd")
                    && !trimmed.hasPrefix("%admin")
                    && !trimmed.hasPrefix("root")
                    && !trimmed.hasPrefix("%wheel") {
                    flaggedLines.append("[\(path)] \(trimmed)")
                }
            }
        }
        reply(flaggedLines)
    }

    // MARK: - System Persistence

    func listSystemPersistence(reply: @escaping ([String]) -> Void) {
        let dirs = ["/Library/LaunchAgents", "/Library/LaunchDaemons"]
        var results: [String] = []
        for dir in dirs {
            let items = (try? FileManager.default.contentsOfDirectory(atPath: dir)) ?? []
            for item in items where item.hasSuffix(".plist") {
                results.append("\(dir)/\(item)")
            }
        }
        reply(results)
    }

    // MARK: - 3.0 Network Intelligence

    func capturePackets(
        interface: String,
        durationSeconds: Int,
        outputPath: String,
        reply: @escaping (String?) -> Void
    ) {
        // Security: validate inputs before passing to tcpdump
        let safeInterface = interface.filter { $0.isLetter || $0.isNumber || $0 == "." || $0 == "_" || $0 == "-" }
        let safeDuration  = max(2, min(durationSeconds, 60))  // clamp 2–60 seconds
        let safeOutput    = outputPath.hasPrefix("/private/tmp/") ? outputPath : "/private/tmp/phantom-capture.pcap"

        guard FileManager.default.isExecutableFile(atPath: "/usr/sbin/tcpdump") else {
            reply(nil); return
        }

        // NOTE: Do NOT use -G/-W. The -G flag rotates at epoch multiples of N
        // (e.g. -G 5 fires at :00, :05, :10 — not 5s after launch), so the
        // effective capture window is 0–N seconds, often yielding an empty pcap.
        //
        // Instead: launch tcpdump without -G, sleep for the desired duration,
        // then terminate the process. SIGTERM causes tcpdump to flush and finalize
        // the pcap file cleanly before exiting.
        //
        // -i: interface  -w: pcap output  -n: no DNS resolution
        // -s 0: unlimited snaplen (full packet)  -c 2000: safety packet cap
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/sbin/tcpdump")
        task.arguments     = [
            "-i", safeInterface,
            "-w", safeOutput,
            "-n",
            "-s", "0",
            "-c", "2000"
        ]
        task.standardOutput = Pipe()
        task.standardError  = Pipe()

        guard (try? task.run()) != nil else { reply(nil); return }

        // Block for the capture window then send SIGTERM — tcpdump flushes the pcap cleanly.
        Thread.sleep(forTimeInterval: TimeInterval(safeDuration))
        task.terminate()
        task.waitUntilExit()

        guard FileManager.default.fileExists(atPath: safeOutput) else { reply(nil); return }

        // tcpdump runs as root and creates the pcap owned by root.
        // The main app process (normal user) runs ngrep/tshark/zeek against this file.
        // Without explicit world-read permission the scanners get EACCES → 0 events.
        // chmod 644: owner(root) rw, group r, world r — safe for /private/tmp.
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o644],
            ofItemAtPath: safeOutput
        )

        reply(safeOutput)
    }

    func listNetworkInterfaces(reply: @escaping ([String]) -> Void) {
        // `tcpdump -D` lists interfaces; parse "N.ifname (description)"
        guard let output = shell("/usr/sbin/tcpdump", args: ["-D"]) else {
            reply([]); return
        }
        let interfaces: [String] = output
            .components(separatedBy: "\n")
            .filter { !$0.isEmpty }
            .compactMap { line -> String? in
                // Format: "1.en0 (Wi-Fi)"  or  "2.utun3"
                let parts = line.split(separator: ".", maxSplits: 1)
                guard parts.count == 2 else { return nil }
                let name = String(parts[1]).components(separatedBy: " ").first ?? ""
                return name.isEmpty ? nil : name
            }
        reply(interfaces)
    }

    // MARK: - Shell Helper

    private func shell(_ path: String, args: [String]) -> String? {
        let task = Process()
        task.executableURL  = URL(fileURLWithPath: path)
        task.arguments      = args
        let pipe            = Pipe()
        task.standardOutput = pipe
        task.standardError  = Pipe()
        do    { try task.run() }
        catch { return nil }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        task.waitUntilExit()
        return String(data: data, encoding: .utf8)
    }
}
