@preconcurrency import Foundation

// MARK: - TSharkScanner
//
// Wraps tshark (the Wireshark CLI) for deep protocol dissection.
// tshark decodes 2,000+ protocols and can output structured field data.
//
// Installation:  brew install --cask wireshark
// Binary paths:  /opt/homebrew/bin/tshark  (Apple Silicon)
//                /usr/local/bin/tshark      (Intel)
//                /Applications/Wireshark.app/Contents/MacOS/tshark
//
// This scanner operates on existing pcap files — no root required.
// Live capture (via the PrivilegedHelper) writes a pcap that this scanner reads.

final class TSharkScanner {

    // MARK: - Availability

    private nonisolated var knownPaths: [String] { [
        "/opt/homebrew/bin/tshark",
        "/usr/local/bin/tshark",
        "/Applications/Wireshark.app/Contents/MacOS/tshark"
    ] }

    nonisolated init() {}

    nonisolated var isAvailable: Bool { executablePath != nil }

    nonisolated var executablePath: String? {
        knownPaths.first { path in
            path.withCString { Darwin.access($0, X_OK) == 0 }
        }
    }

    // MARK: - Analyze pcap

    /// Runs all dissectors against the given pcap file and returns PacketEvents.
    nonisolated func analyze(pcapPath: String) -> [PacketEvent] {
        guard let tshark = executablePath else { return [] }
        var events: [PacketEvent] = []
        events += extractConnections(tshark: tshark, pcap: pcapPath)   // TCP SYN sweep — always fires
        events += extractDNS(tshark: tshark, pcap: pcapPath)           // queries + responses
        events += extractTLS(tshark: tshark, pcap: pcapPath)           // Client Hello → SNI
        events += extractHTTP(tshark: tshark, pcap: pcapPath)          // cleartext HTTP
        events += extractSuspiciousPayloads(tshark: tshark, pcap: pcapPath)
        return events
    }

    // MARK: - TCP Connection sweep
    //
    // Captures every new TCP SYN (connection attempt) in the pcap.
    // This is the broadest possible filter — fires even when HTTP/DNS/TLS
    // have nothing to report, so tshark always produces data on real traffic.

    nonisolated private func extractConnections(tshark: String, pcap: String) -> [PacketEvent] {
        let output = shell(tshark, args: [
            "-r", pcap,
            "-Y", "tcp.flags.syn == 1 and tcp.flags.ack == 0",  // SYN only (connection start)
            "-T", "fields",
            "-e", "frame.time_epoch",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "tcp.srcport",
            "-e", "tcp.dstport",
            "-E", "separator=\u{01}"
        ])
        return lines(output).prefix(200).compactMap { line -> PacketEvent? in
            let p = line.components(separatedBy: "\u{01}")
            guard p.count >= 5 else { return nil }
            let ts      = Date(timeIntervalSince1970: Double(p[0]) ?? Date().timeIntervalSince1970)
            let srcIP   = nilIfEmpty(p[1])
            let dstIP   = nilIfEmpty(p[2])
            let srcPort = Int(p[3])
            let dstPort = Int(p[4])
            // Flag connections to unusual high ports or known suspicious destinations
            let suspicious = dstPort.map { $0 > 49151 || [4444, 1337, 31337, 8080, 8443].contains($0) } ?? false
            return PacketEvent(
                timestamp: ts,
                tool: .tshark,
                category: .connection,
                severity: suspicious ? .medium : .low,
                sourceIP: srcIP,
                destinationIP: dstIP,
                sourcePort: srcPort,
                destinationPort: dstPort,
                proto: "TCP",
                summary: "tshark TCP: \(srcIP ?? "?"):\(srcPort ?? 0) → \(dstIP ?? "?"):\(dstPort ?? 0)",
                detail: suspicious ? "Connection to unusual port — may warrant investigation" : nil
            )
        }
    }

    // MARK: - HTTP

    nonisolated private func extractHTTP(tshark: String, pcap: String) -> [PacketEvent] {
        let output = shell(tshark, args: [
            "-r", pcap,
            "-Y", "http.request",
            "-T", "fields",
            "-e", "frame.time_epoch",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "tcp.srcport",
            "-e", "tcp.dstport",
            "-e", "http.request.method",
            "-e", "http.host",
            "-e", "http.request.uri",
            "-e", "http.user_agent",
            "-E", "separator=\u{01}"   // ASCII SOH — unlikely to appear in HTTP fields
        ])
        return lines(output).compactMap(parseHTTPLine)
    }

    nonisolated private func parseHTTPLine(_ line: String) -> PacketEvent? {
        let p = line.components(separatedBy: "\u{01}")
        guard p.count >= 8 else { return nil }

        let ts      = Date(timeIntervalSince1970: Double(p[0]) ?? Date().timeIntervalSince1970)
        let srcIP   = nilIfEmpty(p[1])
        let dstIP   = nilIfEmpty(p[2])
        let srcPort = Int(p[3])
        let dstPort = Int(p[4])
        let method  = nilIfEmpty(p[5])
        let host    = p[6]
        let uri     = p[7].isEmpty ? "/" : p[7]
        let ua      = p.count > 8 ? nilIfEmpty(p[8]) : nil

        let suspicious = suspiciousUA(ua ?? "")
            || host.contains(".onion")
            || host.lowercased().contains("ngrok")
            || uri.lowercased().contains("cmd=")
            || uri.lowercased().contains("exec=")
            || method == "PUT" || method == "DELETE"

        return PacketEvent(
            timestamp: ts,
            tool: .tshark,
            category: .http,
            severity: suspicious ? .medium : .low,
            sourceIP: srcIP,
            destinationIP: dstIP,
            sourcePort: srcPort,
            destinationPort: dstPort,
            proto: "TCP",
            summary: "tshark HTTP \(method ?? "?") \(host)\(uri)",
            detail: ua.map { "User-Agent: \($0)" },
            httpMethod: method,
            httpURL: "http://\(host)\(uri)"
        )
    }

    // MARK: - DNS

    nonisolated private func extractDNS(tshark: String, pcap: String) -> [PacketEvent] {
        // Capture all DNS traffic (queries AND responses) — responses include resolved IPs.
        // Previous filter "dns.flags.response == 0" missed responses and was too narrow
        // for short capture windows.
        let output = shell(tshark, args: [
            "-r", pcap,
            "-Y", "dns",
            "-T", "fields",
            "-e", "frame.time_epoch",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "dns.qry.name",
            "-e", "dns.qry.type",
            "-e", "dns.a",             // resolved IPv4 (present on responses)
            "-e", "dns.flags.response",// 0 = query, 1 = response
            "-E", "separator=\u{01}"
        ])
        return lines(output).compactMap(parseDNSLine)
    }

    nonisolated private func parseDNSLine(_ line: String) -> PacketEvent? {
        let p = line.components(separatedBy: "\u{01}")
        guard p.count >= 4 else { return nil }

        let ts         = Date(timeIntervalSince1970: Double(p[0]) ?? Date().timeIntervalSince1970)
        let srcIP      = nilIfEmpty(p[1])
        let dstIP      = nilIfEmpty(p[2])
        let query      = p[3]
        let qtype      = p.count > 4 ? p[4] : "A"
        let resolved   = p.count > 5 ? nilIfEmpty(p[5]) : nil
        let isResponse = p.count > 6 && p[6] == "1"

        guard !query.isEmpty else { return nil }

        let suspicious = isDGAOrTunnel(query)
        let summary = isResponse
            ? "tshark DNS \(query)\(resolved.map { " → \($0)" } ?? "") [\(qtype)]"
            : "tshark DNS? \(query) [\(qtype)]"

        return PacketEvent(
            timestamp: ts,
            tool: .tshark,
            category: .dns,
            severity: suspicious ? .high : .low,
            sourceIP: srcIP,
            destinationIP: dstIP,
            proto: "UDP",
            summary: summary,
            detail: suspicious ? "High-entropy domain — possible DGA or DNS tunneling" : nil,
            dnsQuery: query
        )
    }

    // MARK: - TLS

    nonisolated private func extractTLS(tshark: String, pcap: String) -> [PacketEvent] {
        // Filter on Client Hello (type 1), NOT Server Hello (type 2).
        // Client Hello fires on EVERY new HTTPS connection and carries SNI in cleartext.
        // Server Hello is far rarer in short capture windows (only on fresh TLS sessions).
        let output = shell(tshark, args: [
            "-r", pcap,
            "-Y", "tls.handshake.type == 1",
            "-T", "fields",
            "-e", "frame.time_epoch",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "tcp.dstport",
            "-e", "tls.handshake.extensions_server_name",   // SNI — hostname being requested
            "-E", "separator=\u{01}"
        ])
        return lines(output).compactMap(parseTLSLine)
    }

    nonisolated private func parseTLSLine(_ line: String) -> PacketEvent? {
        let p = line.components(separatedBy: "\u{01}")
        guard p.count >= 4 else { return nil }

        let ts      = Date(timeIntervalSince1970: Double(p[0]) ?? Date().timeIntervalSince1970)
        let srcIP   = nilIfEmpty(p[1])
        let dstIP   = nilIfEmpty(p[2])
        let dstPort = Int(p[3])
        let sni     = p.count > 4 ? nilIfEmpty(p[4]) : nil

        // Flag connections to non-standard TLS ports (443 and 8443 are normal)
        let unusualPort = dstPort.map { $0 != 443 && $0 != 8443 && $0 != 993 && $0 != 995 } ?? false

        return PacketEvent(
            timestamp: ts,
            tool: .tshark,
            category: .tls,
            severity: unusualPort ? .medium : .low,
            sourceIP: srcIP,
            destinationIP: dstIP,
            destinationPort: dstPort,
            proto: "TCP",
            summary: "tshark TLS → \(sni ?? dstIP ?? "unknown"):\(dstPort ?? 443)\(unusualPort ? " [unusual port]" : "")",
            detail: unusualPort ? "TLS on non-standard port — possible C2 or tunneling" : nil
        )
    }

    // MARK: - Suspicious Payloads

    nonisolated private func extractSuspiciousPayloads(tshark: String, pcap: String) -> [PacketEvent] {
        // Screen for cleartext credential patterns and shell command strings
        let filter = #"tcp contains "password" or tcp contains "passwd" or tcp contains "/bin/sh" or tcp contains "cmd.exe" or tcp contains "mimikatz""#
        let output = shell(tshark, args: [
            "-r", pcap,
            "-Y", filter,
            "-T", "fields",
            "-e", "frame.time_epoch",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "tcp.srcport",
            "-e", "tcp.dstport",
            "-E", "separator=\u{01}"
        ])
        return lines(output).compactMap(parseSuspiciousPayloadLine)
    }

    nonisolated private func parseSuspiciousPayloadLine(_ line: String) -> PacketEvent? {
        let p = line.components(separatedBy: "\u{01}")
        guard p.count >= 5 else { return nil }
        let ts      = Date(timeIntervalSince1970: Double(p[0]) ?? Date().timeIntervalSince1970)
        let srcIP   = nilIfEmpty(p[1])
        let dstIP   = nilIfEmpty(p[2])
        let srcPort = Int(p[3])
        let dstPort = Int(p[4])
        return PacketEvent(
            timestamp: ts,
            tool: .tshark,
            category: .suspicious,
            severity: .high,
            sourceIP: srcIP,
            destinationIP: dstIP,
            sourcePort: srcPort,
            destinationPort: dstPort,
            proto: "TCP",
            summary: "tshark: Suspicious payload (credential/shell pattern in TCP stream)",
            detail: "Packet contains cleartext credential or command execution pattern"
        )
    }

    // MARK: - Helpers

    nonisolated private func isDGAOrTunnel(_ domain: String) -> Bool {
        let labels = domain.lowercased().split(separator: ".")
        if labels.count > 6 { return true }
        if domain.lowercased().contains("dnscat") || domain.lowercased().contains("iodine") { return true }
        return labels.contains { label in
            label.count > 20 && shannonEntropy(String(label)) > 3.5
        }
    }

    nonisolated private func shannonEntropy(_ s: String) -> Double {
        var freq: [Character: Double] = [:]
        for c in s { freq[c, default: 0] += 1 }
        let len = Double(s.count)
        return freq.values.reduce(0.0) { acc, count in
            let p = count / len; return acc - p * log2(p)
        }
    }

    nonisolated private func suspiciousUA(_ ua: String) -> Bool {
        let lower = ua.lowercased()
        return ["curl","wget","python-requests","go-http","libwww","masscan",
                "nmap","zgrab","nuclei","sqlmap","nikto","dirbuster"]
            .contains { lower.contains($0) }
    }

    nonisolated private func lines(_ output: String?) -> [String] {
        (output ?? "").components(separatedBy: "\n").filter { !$0.isEmpty }
    }

    nonisolated private func nilIfEmpty(_ s: String) -> String? { s.isEmpty ? nil : s }

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
