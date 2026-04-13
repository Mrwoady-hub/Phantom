import Foundation

struct NetworkConnectionRecord: Identifiable, Hashable, Sendable {
    let command: String
    let processID: Int?
    let protocolName: String
    let name: String
    let state: String?

    var id: String { "\(command)|\(processID ?? -1)|\(protocolName)|\(name)|\(state ?? "")" }
    var isListening: Bool { state == "LISTEN" }
    var isExternal: Bool {
        let lower = name.lowercased()
        return !lower.contains("127.0.0.1")
            && !lower.contains("localhost")
            && !lower.contains("::1")
            && !isListening
    }
}

final class NetworkMonitor {

    // MARK: - Cache
    //
    // PERFORMANCE FIX: lsof enumerates every open file descriptor in the kernel
    // for every process. On a typical Mac this is 10,000+ FDs and takes 1-4 seconds.
    // Running it on every 30s scan interval produces "Energy Impact: High" in
    // Activity Monitor and makes the scan feel sluggish.
    //
    // Fix: cache results for 90 seconds. Network connections don't change every
    // 30s in a way that would meaningfully affect security posture. A new malicious
    // connection will be caught within 90s of opening — acceptable for a non-EDR tool.
    //
    // Cache is actor-isolated to avoid data races across concurrent scan invocations.
    private static let cache = NetworkCache()

    func activeConnections() -> [String] {
        activeConnectionRecords().map {
            [$0.command, $0.processID.map(String.init) ?? "-",
             $0.protocolName, $0.name, $0.state ?? ""]
                .joined(separator: " ")
                .trimmingCharacters(in: .whitespacesAndNewlines)
        }
    }

    func activeConnectionRecords() -> [NetworkConnectionRecord] {
        // Synchronous cache check — returns stale results if fresh enough
        if let cached = NetworkMonitor.cache.getSync() { return cached }

        let records = runLsof()
        NetworkMonitor.cache.setSync(records)
        return records
    }

    // MARK: - lsof execution

    private func runLsof() -> [NetworkConnectionRecord] {
        // SECURITY: resolve lsof path — don't assume /usr/sbin/lsof
        let lsofURL = resolvedLsof()
        guard let url = lsofURL else { return [] }

        let task = Process()
        task.executableURL  = url
        task.arguments      = ["-nP", "-iTCP", "-iUDP"]
        let pipe            = Pipe()
        task.standardOutput = pipe
        task.standardError  = Pipe()  // SECURITY: sink stderr

        do    { try task.run() }
        catch { return [] }

        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        task.waitUntilExit()

        guard let output = String(data: data, encoding: .utf8) else { return [] }
        return output.components(separatedBy: "\n").compactMap(parseRecord)
    }

    private func resolvedLsof() -> URL? {
        let known = URL(fileURLWithPath: "/usr/sbin/lsof")
        if FileManager.default.isExecutableFile(atPath: known.path) { return known }
        for dir in (ProcessInfo.processInfo.environment["PATH"] ?? "").components(separatedBy: ":") {
            let candidate = URL(fileURLWithPath: dir).appendingPathComponent("lsof")
            if FileManager.default.isExecutableFile(atPath: candidate.path) { return candidate }
        }
        return nil
    }

    private func parseRecord(_ line: String) -> NetworkConnectionRecord? {
        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !trimmed.hasPrefix("COMMAND ") else { return nil }

        let cols = trimmed.split(whereSeparator: \.isWhitespace).map(String.init)
        guard cols.count >= 9 else { return nil }

        let command  = cols[0]
        let pid      = Int(cols[1])
        let proto    = cols[7]
        let tail     = cols.dropFirst(8).joined(separator: " ")
        guard !tail.isEmpty else { return nil }

        let name: String
        let state: String?
        if let r = tail.range(of: " (") {
            name  = String(tail[..<r.lowerBound])
            state = String(tail[r.upperBound...].dropLast())
        } else {
            name  = tail
            state = nil
        }
        return NetworkConnectionRecord(command: command, processID: pid,
                                       protocolName: proto, name: name, state: state)
    }
}

// MARK: - NetworkCache

/// Thread-safe 90-second result cache. Using a class (not actor) so callers
/// can use it synchronously from non-async contexts.
private final class NetworkCache: @unchecked Sendable {
    private var records: [NetworkConnectionRecord] = []
    private var lastFetch: Date = .distantPast
    private let lock  = NSLock()
    private let ttl: TimeInterval = 90

    func getSync() -> [NetworkConnectionRecord]? {
        lock.lock(); defer { lock.unlock() }
        guard Date().timeIntervalSince(lastFetch) < ttl else { return nil }
        return records
    }

    func setSync(_ newRecords: [NetworkConnectionRecord]) {
        lock.lock(); defer { lock.unlock() }
        records   = newRecords
        lastFetch = Date()
    }
}
