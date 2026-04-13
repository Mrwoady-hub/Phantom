@preconcurrency import Foundation

// MARK: - TcpdumpScanner
//
// Wraps tcpdump for raw packet capture and pcap analysis.
// tcpdump ships pre-installed on macOS at /usr/sbin/tcpdump.
//
// Live capture requires root and runs via the PrivilegedHelper XPC service.
// This scanner handles read-only analysis of existing pcap files (no root needed)
// and provides protocol statistics for the dashboard.

final class TcpdumpScanner {

    private let path = "/usr/sbin/tcpdump"

    nonisolated init() {}

    nonisolated var isAvailable: Bool {
        path.withCString { Darwin.access($0, X_OK) == 0 }
    }

    // MARK: - Analyze existing pcap

    /// Parse a pcap file and return per-packet connection events.
    /// Uses `-r` (read) mode — no capture, no privileges required.
    nonisolated func analyze(pcapPath: String, maxPackets: Int = 300) -> [PacketEvent] {
        guard isAvailable else { return [] }

        let output = shell(path, args: [
            "-r", pcapPath,
            "-n",            // no hostname resolution
            "-tt",           // Unix epoch timestamps
            "-q",            // brief one-line output
            "-c", "\(maxPackets)"
        ])

        return lines(output)
            .filter { !$0.hasPrefix("reading from") }
            .compactMap(parseLine)
    }

    // MARK: - Protocol statistics

    /// Returns a single summary PacketEvent with protocol breakdown counts.
    nonisolated func statistics(pcapPath: String) -> [PacketEvent] {
        guard isAvailable else { return [] }

        // On macOS, tcpdump writes the "reading from file…" header to stderr and
        // packet records to stdout — but in non-TTY contexts it sometimes flips both
        // to stderr. Read both fds and merge so we get the data regardless.
        let raw = shellMerged(path, args: ["-r", pcapPath, "-n", "-tt", "-q"])

        let allLines = raw.components(separatedBy: "\n")
            .filter { !$0.isEmpty && !$0.hasPrefix("reading from") && !$0.hasPrefix("tcpdump:") }
        guard !allLines.isEmpty else { return [] }

        var tcp = 0, udp = 0, icmp = 0, other = 0
        for l in allLines {
            let lo = l.lowercased()
            if lo.contains("tcp")       { tcp   += 1 }
            else if lo.contains("udp")  { udp   += 1 }
            else if lo.contains("icmp") { icmp  += 1 }
            else                        { other += 1 }
        }

        return [PacketEvent(
            tool: .tcpdump,
            category: .connection,
            severity: .low,
            summary: "tcpdump: \(allLines.count) pkts — TCP:\(tcp) UDP:\(udp) ICMP:\(icmp) Other:\(other)",
            detail: "Packet protocol distribution from tcpdump analysis"
        )]
    }

    // MARK: - Line parser

    // tcpdump -tt -q output (example):
    //   1712345678.123456 IP 10.0.0.1.52341 > 8.8.8.8.53: UDP, length 32
    nonisolated private func parseLine(_ line: String) -> PacketEvent? {
        let words = line.split(whereSeparator: \.isWhitespace).map(String.init)
        guard words.count >= 5 else { return nil }

        let ts    = Date(timeIntervalSince1970: Double(words[0]) ?? Date().timeIntervalSince1970)
        var srcStr: String?
        var dstStr: String?
        var proto: String = "IP"

        for (i, w) in words.enumerated() {
            if (w == "IP" || w == "IP6") && i + 3 < words.count {
                srcStr = words[i + 1]
                dstStr = words[i + 3].trimmingCharacters(in: CharacterSet(charactersIn: ":"))
            }
            let wl = w.lowercased()
            if wl.hasPrefix("tcp")  { proto = "TCP"  }
            if wl.hasPrefix("udp")  { proto = "UDP"  }
            if wl.hasPrefix("icmp") { proto = "ICMP" }
        }

        let (srcIP, srcPort) = addressPort(srcStr ?? "")
        let (dstIP, dstPort) = addressPort(dstStr ?? "")

        return PacketEvent(
            timestamp: ts,
            tool: .tcpdump,
            category: .connection,
            severity: .low,
            sourceIP: srcIP,
            destinationIP: dstIP,
            sourcePort: srcPort,
            destinationPort: dstPort,
            proto: proto,
            summary: "tcpdump \(srcStr ?? "?") → \(dstStr ?? "?") [\(proto)]"
        )
    }

    // Parse "192.168.1.1.54321" → ("192.168.1.1", 54321)
    nonisolated private func addressPort(_ s: String) -> (String?, Int?) {
        let parts = s.components(separatedBy: ".")
        if parts.count >= 2, let port = Int(parts.last ?? "") {
            return (parts.dropLast().joined(separator: "."), port)
        }
        // IPv6 format: [::1]:443
        if let colonIdx = s.lastIndex(of: ":") {
            let ip   = String(s[..<colonIdx])
            let port = Int(s[s.index(after: colonIdx)...])
            return (ip, port)
        }
        return (s.isEmpty ? nil : s, nil)
    }

    nonisolated private func lines(_ output: String?) -> [String] {
        (output ?? "").components(separatedBy: "\n").filter { !$0.isEmpty }
    }

    /// Read both stdout AND stderr merged — handles tcpdump's inconsistent fd choice
    /// depending on whether it's attached to a terminal.
    nonisolated private func shellMerged(_ path: String, args: [String]) -> String {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: path)
        task.arguments     = args
        let outPipe = Pipe()
        let errPipe = Pipe()
        task.standardOutput = outPipe
        task.standardError  = errPipe
        guard (try? task.run()) != nil else { return "" }
        let outData = outPipe.fileHandleForReading.readDataToEndOfFile()
        let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
        task.waitUntilExit()
        return (String(data: outData, encoding: .utf8) ?? "")
             + (String(data: errData, encoding: .utf8) ?? "")
    }

    nonisolated private func shell(_ path: String, args: [String]) -> String? {
        let task = Process()
        task.executableURL  = URL(fileURLWithPath: path)
        task.arguments      = args
        let pipe            = Pipe()
        task.standardOutput = pipe
        task.standardError  = Pipe()
        do    { try task.run() } catch { return nil }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        task.waitUntilExit()
        return String(data: data, encoding: .utf8)
    }
}
