import Foundation

// MARK: - ProcessEntry

struct ProcessEntry: Sendable {
    let pid: Int
    let ppid: Int
    let user: String
    let executablePath: String
    let arguments: String
    var commandName: String { URL(fileURLWithPath: executablePath).lastPathComponent }

    /// Fast-path: skip TrustEvaluator entirely for known-safe system paths.
    /// SecStaticCodeCreateWithPath costs 5-50ms per call — calling it on 300+
    /// processes blows any reasonable scan timeout.
    var isDefinitelySystemProcess: Bool {
        executablePath.hasPrefix("/System/Library/") ||
        executablePath.hasPrefix("/usr/libexec/")     ||
        executablePath.hasPrefix("/usr/sbin/")         ||
        executablePath.hasPrefix("/usr/bin/")          ||
        executablePath.hasPrefix("/bin/")              ||
        executablePath.hasPrefix("/sbin/")             ||
        executablePath.hasPrefix("/Library/Apple/")
    }
}

// MARK: - ProcessMonitor

final class ProcessMonitor {

    func runningProcesses(limit: Int = 512) async -> [ProcessEntry] {
        let raw = await runPS(timeout: 4.0)
        guard !raw.isEmpty else { return [] }

        return raw
            .components(separatedBy: "\n")
            .compactMap(parseLine)
            .prefix(limit)
            .map { $0 }
    }

    // MARK: - Parsing

    private func parseLine(_ line: String) -> ProcessEntry? {
        // Trim first — ps pads with leading spaces for alignment
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return nil }

        // Split with omittingEmptySubsequences:true so leading/multiple spaces
        // between columns don't produce empty tokens.
        // maxSplits:3 → [pid, ppid, user, command-line]
        let parts = trimmed.split(
            separator: " ",
            maxSplits: 3,
            omittingEmptySubsequences: true
        ).map(String.init)

        guard parts.count >= 4 else { return nil }

        // Skip header line — first column is "PID" (text, not a number)
        guard let pid  = Int(parts[0]),
              let ppid = Int(parts[1])
        else { return nil }

        let user        = parts[2]
        let commandLine = parts[3].trimmingCharacters(in: .whitespaces)

        // Split command line: first token = executable, rest = arguments
        let cmdParts       = commandLine.split(separator: " ", maxSplits: 1,
                                               omittingEmptySubsequences: true)
        let executablePath = String(cmdParts.first ?? Substring(commandLine))
        let arguments      = cmdParts.count > 1 ? String(cmdParts[1]) : ""

        guard !executablePath.isEmpty,
              executablePath != "??",
              !executablePath.hasPrefix("(")   // kernel threads: (launchd)
        else { return nil }

        return ProcessEntry(
            pid: pid, ppid: ppid, user: user,
            executablePath: executablePath, arguments: arguments
        )
    }

    // MARK: - Execution

    private func runPS(timeout: TimeInterval) async -> String {
        await withCheckedContinuation { continuation in
            let gate = OneShotGate { continuation.resume(returning: $0) }

            let process       = Process()
            let stdout        = Pipe()
            process.executableURL  = URL(fileURLWithPath: "/bin/ps")
            process.arguments      = ["-axo", "pid,ppid,user,command"]
            process.standardOutput = stdout
            process.standardError  = Pipe()

            process.terminationHandler = { _ in
                let data   = stdout.fileHandleForReading.readDataToEndOfFile()
                let result = String(data: data, encoding: .utf8) ?? ""
                Task { await gate.fire(with: result) }
            }

            do    { try process.run() }
            catch { Task { await gate.fire(with: "") }; return }

            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
                if process.isRunning { process.terminate() }
                Task { await gate.fire(with: "") }
            }
        }
    }
}

// MARK: - OneShotGate

private actor OneShotGate {
    private var handler: ((String) -> Void)?
    init(handler: @escaping (String) -> Void) { self.handler = handler }
    func fire(with value: String) {
        guard let h = handler else { return }
        handler = nil
        h(value)
    }
}
