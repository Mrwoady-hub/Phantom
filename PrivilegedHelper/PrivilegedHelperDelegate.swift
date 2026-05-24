import Foundation

// MARK: - PrivilegedHelperDelegate
//
// Owns the XPC listener and the run loop. When the app connects, it returns
// an HelperCommandHandler as the exported object — but only after the peer
// passes HelperPeerValidator. Unauthorized peers are rejected before any
// privileged operation is exposed.

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
        // Runtime peer validation. SMAuthorizedClients gates install; this
        // gates every live XPC connection. Fail closed.
        guard HelperPeerValidator.isAuthorized(connection: connection) else {
            connection.invalidate()
            return false
        }

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

    nonisolated func getVersion(reply: @escaping (String) -> Void) {
        reply("3.0")
    }

    // MARK: - Privileged lsof

    nonisolated func runPrivilegedLsof(reply: @escaping (String?) -> Void) {
        reply(shell("/usr/sbin/lsof", args: ["-nP", "-iTCP", "-iUDP"]))
    }

    // MARK: - /etc/hosts audit

    nonisolated func checkEtcHosts(reply: @escaping ([String]) -> Void) {
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

    nonisolated func listKernelExtensions(reply: @escaping (String?) -> Void) {
        reply(shell("/usr/sbin/kextstat", args: ["-l", "-b", "com.apple"]))
    }

    // MARK: - Sudoers audit

    nonisolated func checkSudoers(reply: @escaping ([String]) -> Void) {
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

    nonisolated func listSystemPersistence(reply: @escaping ([String]) -> Void) {
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

    /// Per-handler queue used to schedule tcpdump termination without blocking
    /// the XPC handler thread for the full capture window.
    private static let captureQueue = DispatchQueue(
        label: "com.woady.phantom.helper.capture", qos: .utility
    )

    nonisolated func capturePackets(
        interface: String,
        durationSeconds: Int,
        outputPath: String,
        reply: @escaping (String?) -> Void
    ) {
        let safeInterface = interface.filter {
            $0.isLetter || $0.isNumber || $0 == "." || $0 == "_" || $0 == "-"
        }
        guard !safeInterface.isEmpty else { reply(nil); return }

        let safeDuration = max(2, min(durationSeconds, 60))

        // Caller's outputPath is treated as a filename suggestion only.
        // The real path is owned by HelperCaptureOutput.
        let suggested = (outputPath as NSString).lastPathComponent
        guard let safeOutput = HelperCaptureOutput.prepare(suggestedName: suggested) else {
            reply(nil); return
        }

        guard FileManager.default.isExecutableFile(atPath: "/usr/sbin/tcpdump") else {
            reply(nil); return
        }

        // tcpdump rotates incorrectly with -G (fires at epoch boundaries, not
        // N seconds after launch), so we run it open-ended and SIGTERM it
        // after `safeDuration` seconds. SIGTERM causes tcpdump to flush and
        // finalise the pcap cleanly.
        //
        // -i: interface  -w: pcap output  -n: no DNS resolution
        // -s 0: unlimited snaplen          -c 2000: safety packet cap
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/sbin/tcpdump")
        task.arguments = [
            "-i", safeInterface,
            "-w", safeOutput,
            "-n",
            "-s", "0",
            "-c", "2000"
        ]
        task.standardOutput = Pipe()
        task.standardError  = Pipe()

        // terminationHandler fires off-main-runloop when tcpdump exits for
        // any reason (timer SIGTERM, -c packet cap, or its own error).
        // We reply exactly once.
        var replied = false
        let replyOnce: (String?) -> Void = { path in
            guard !replied else { return }
            replied = true
            reply(path)
        }

        task.terminationHandler = { proc in
            Self.captureQueue.async {
                if FileManager.default.fileExists(atPath: safeOutput) {
                    HelperCaptureOutput.finalize(path: safeOutput)
                    replyOnce(safeOutput)
                } else {
                    replyOnce(nil)
                }
                _ = proc   // silence unused warning under strict concurrency
            }
        }

        do {
            try task.run()
        } catch {
            try? FileManager.default.removeItem(atPath: safeOutput)
            replyOnce(nil)
            return
        }

        // Schedule SIGTERM after the capture window. We do NOT block this
        // thread — the helper's XPC handler returns immediately and the
        // terminationHandler above drives the final reply.
        Self.captureQueue.asyncAfter(deadline: .now() + .seconds(safeDuration)) {
            if task.isRunning { task.terminate() }
        }
    }

    nonisolated func listNetworkInterfaces(reply: @escaping ([String]) -> Void) {
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

    nonisolated private func shell(_ path: String, args: [String]) -> String? {
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
