@preconcurrency import Foundation

// MARK: - ZeekScanner
//
// Wraps Zeek (formerly Bro) — the gold-standard network analysis framework.
// Zeek processes pcap files offline and generates structured TSV logs:
//
//   conn.log    — TCP/UDP/ICMP connection records with state machine
//   dns.log     — every DNS query and response
//   http.log    — full HTTP request/response metadata
//   ssl.log     — TLS handshake metadata, SNI, certificate hashes
//   notice.log  — Zeek intelligence notices (port scan, brute force, etc.)
//   weird.log   — protocol anomalies and unexpected conditions
//
// Installation:  brew install zeek
// Binary paths:  /opt/homebrew/bin/zeek  (Apple Silicon)
//                /usr/local/bin/zeek      (Intel)
//                /opt/zeek/bin/zeek       (manual install)

final class ZeekScanner {

    // MARK: - Availability

    private nonisolated var knownPaths: [String] { [
        "/opt/homebrew/bin/zeek",
        "/usr/local/bin/zeek",
        "/opt/zeek/bin/zeek"
    ] }

    nonisolated init() {}

    nonisolated var isAvailable: Bool { executablePath != nil }

    nonisolated var executablePath: String? {
        knownPaths.first { path in
            path.withCString { Darwin.access($0, X_OK) == 0 }
        }
    }

    // MARK: - Analyze pcap

    nonisolated func analyze(pcapPath: String) -> [PacketEvent] {
        guard let zeek = executablePath else { return [] }

        // Zeek writes logs relative to its working directory
        let workDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("sg3-zeek-\(UUID().uuidString)")
        do {
            try FileManager.default.createDirectory(at: workDir, withIntermediateDirectories: true)
        } catch { return [] }
        defer { try? FileManager.default.removeItem(at: workDir) }

        // Run Zeek offline against the pcap.
        // "-C" ignores checksum errors common in loopback/tunnel captures.
        // "LogAscii::use_json=F" keeps default TSV format (faster to parse).
        runZeek(zeek, pcap: pcapPath, workDir: workDir)

        var events: [PacketEvent] = []
        events += parseConnLog(workDir.appendingPathComponent("conn.log"))
        events += parseDNSLog(workDir.appendingPathComponent("dns.log"))
        events += parseHTTPLog(workDir.appendingPathComponent("http.log"))
        events += parseSSLLog(workDir.appendingPathComponent("ssl.log"))
        events += parseNoticeLog(workDir.appendingPathComponent("notice.log"))
        events += parseWeirdLog(workDir.appendingPathComponent("weird.log"))
        return events
    }

    nonisolated private func runZeek(_ zeek: String, pcap: String, workDir: URL) {
        let task = Process()
        task.executableURL       = URL(fileURLWithPath: zeek)
        task.arguments           = ["-C", "-r", pcap]
        task.currentDirectoryURL = workDir
        task.standardOutput      = Pipe()
        task.standardError       = Pipe()
        do { try task.run() } catch { return }
        task.waitUntilExit()
    }

    // MARK: - conn.log
    // #fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service ...

    nonisolated private func parseConnLog(_ url: URL) -> [PacketEvent] {
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return [] }
        return zeekLines(text).compactMap { cols -> PacketEvent? in
            guard cols.count > 7 else { return nil }
            let ts    = zeekTimestamp(cols[0])
            let srcIP = zeekField(cols, 2)
            let srcP  = Int(cols[3])
            let dstIP = zeekField(cols, 4)
            let dstP  = Int(cols[5])
            let proto = cols[6].uppercased()
            let svc   = zeekField(cols, 7) ?? proto
            return PacketEvent(
                timestamp: ts,
                tool: .zeek,
                category: .connection,
                severity: .low,
                sourceIP: srcIP,
                destinationIP: dstIP,
                sourcePort: srcP,
                destinationPort: dstP,
                proto: proto,
                summary: "Zeek conn: \(srcIP ?? "?")→\(dstIP ?? "?"):\(dstP ?? 0) [\(svc)]"
            )
        }
    }

    // MARK: - dns.log
    // #fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto trans_id
    //         rtt query qclass qclass_name qtype qtype_name ...

    nonisolated private func parseDNSLog(_ url: URL) -> [PacketEvent] {
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return [] }
        return zeekLines(text).compactMap { cols -> PacketEvent? in
            guard cols.count > 9 else { return nil }
            let ts    = zeekTimestamp(cols[0])
            let srcIP = zeekField(cols, 2)
            let dstIP = zeekField(cols, 4)
            let query = cols[9]
            let qtype = cols.count > 13 ? cols[13] : "A"
            guard !query.isEmpty, query != "-" else { return nil }
            let suspicious = isDGAOrTunnel(query)
            return PacketEvent(
                timestamp: ts,
                tool: .zeek,
                category: .dns,
                severity: suspicious ? .high : .low,
                sourceIP: srcIP,
                destinationIP: dstIP,
                proto: "UDP",
                summary: "Zeek DNS: \(query) [\(qtype)]",
                detail: suspicious ? "High-entropy domain — possible DGA or DNS tunneling" : nil,
                dnsQuery: query
            )
        }
    }

    // MARK: - http.log
    // #fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p
    //         trans_depth method host uri referrer version user_agent ...

    nonisolated private func parseHTTPLog(_ url: URL) -> [PacketEvent] {
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return [] }
        return zeekLines(text).compactMap { cols -> PacketEvent? in
            guard cols.count > 11 else { return nil }
            let ts     = zeekTimestamp(cols[0])
            let srcIP  = zeekField(cols, 2)
            let dstIP  = zeekField(cols, 4)
            let method = zeekField(cols, 7)
            let host   = cols[8]
            let uri    = cols[9].isEmpty ? "/" : cols[9]
            let ua     = cols.count > 12 ? zeekField(cols, 12) : nil
            let suspicious = suspiciousUA(ua ?? "") || method == "PUT" || method == "DELETE"
            return PacketEvent(
                timestamp: ts,
                tool: .zeek,
                category: .http,
                severity: suspicious ? .medium : .low,
                sourceIP: srcIP,
                destinationIP: dstIP,
                proto: "TCP",
                summary: "Zeek HTTP: \(method ?? "?") \(host)\(uri)",
                detail: ua.map { "UA: \($0)" },
                httpMethod: method,
                httpURL: "http://\(host)\(uri)"
            )
        }
    }

    // MARK: - ssl.log
    // #fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p
    //         version cipher curve server_name ...
    //         subject issuer ...

    nonisolated private func parseSSLLog(_ url: URL) -> [PacketEvent] {
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return [] }
        // Read the field header to find column indices dynamically
        var sniIdx = 9, subjectIdx = 14, issuerIdx = 15
        for line in text.components(separatedBy: "\n") where line.hasPrefix("#fields") {
            let names = line.components(separatedBy: "\t").dropFirst()
            for (i, n) in names.enumerated() {
                switch n {
                case "server_name": sniIdx = i
                case "subject":     subjectIdx = i
                case "issuer":      issuerIdx = i
                default: break
                }
            }
            break
        }
        return zeekLines(text).compactMap { cols -> PacketEvent? in
            guard cols.count > 7 else { return nil }
            let ts      = zeekTimestamp(cols[0])
            let srcIP   = zeekField(cols, 2)
            let dstIP   = zeekField(cols, 4)
            let dstPort = Int(cols[5])
            let sni     = cols.count > sniIdx ? zeekField(cols, sniIdx) : nil
            let subject = cols.count > subjectIdx ? zeekField(cols, subjectIdx) : nil
            let issuer  = cols.count > issuerIdx  ? zeekField(cols, issuerIdx)  : nil
            let selfSigned = subject != nil && issuer != nil && subject == issuer
            return PacketEvent(
                timestamp: ts,
                tool: .zeek,
                category: .tls,
                severity: selfSigned ? .medium : .low,
                sourceIP: srcIP,
                destinationIP: dstIP,
                destinationPort: dstPort,
                proto: "TCP",
                summary: "Zeek TLS → \(sni ?? dstIP ?? "?")\(selfSigned ? " [self-signed]" : "")",
                detail: selfSigned ? "Self-signed certificate — may indicate C2 or misconfiguration" : nil,
                tlsSubject: subject
            )
        }
    }

    // MARK: - notice.log  (Zeek intelligence framework notices)
    // #fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p fuid
    //         file_mime_type file_desc proto note msg ...

    nonisolated private func parseNoticeLog(_ url: URL) -> [PacketEvent] {
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return [] }
        var noteIdx = 10, msgIdx = 11, srcIdx = 2
        for line in text.components(separatedBy: "\n") where line.hasPrefix("#fields") {
            let names = line.components(separatedBy: "\t").dropFirst()
            for (i, n) in names.enumerated() {
                switch n {
                case "note": noteIdx = i
                case "msg":  msgIdx  = i
                case "id.orig_h": srcIdx = i
                default: break
                }
            }
            break
        }
        return zeekLines(text).compactMap { cols -> PacketEvent? in
            guard cols.count > msgIdx else { return nil }
            let ts   = zeekTimestamp(cols[0])
            let note = zeekField(cols, noteIdx)
            let msg  = zeekField(cols, msgIdx)
            let src  = zeekField(cols, srcIdx)
            return PacketEvent(
                timestamp: ts,
                tool: .zeek,
                category: .alert,
                severity: .high,
                sourceIP: src,
                summary: "Zeek Notice: \(note ?? "unknown")",
                detail: msg,
                signatureName: note
            )
        }
    }

    // MARK: - weird.log  (protocol anomalies)

    nonisolated private func parseWeirdLog(_ url: URL) -> [PacketEvent] {
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return [] }
        return zeekLines(text).prefix(20).compactMap { cols -> PacketEvent? in
            guard cols.count > 5 else { return nil }
            let ts    = zeekTimestamp(cols[0])
            let srcIP = zeekField(cols, 2)
            let dstIP = zeekField(cols, 4)
            // "name" field is typically index 6 in weird.log
            let name  = cols.count > 6 ? zeekField(cols, 6) : nil
            return PacketEvent(
                timestamp: ts,
                tool: .zeek,
                category: .suspicious,
                severity: .medium,
                sourceIP: srcIP,
                destinationIP: dstIP,
                summary: "Zeek Anomaly: \(name ?? "protocol weird")",
                signatureName: name
            )
        }
    }

    // MARK: - Helpers

    /// Returns data rows from a Zeek TSV log (skips # comment/header lines).
    nonisolated private func zeekLines(_ text: String) -> [[String]] {
        text.components(separatedBy: "\n")
            .filter { !$0.hasPrefix("#") && !$0.isEmpty }
            .map    { $0.components(separatedBy: "\t") }
    }

    nonisolated private func zeekTimestamp(_ s: String) -> Date {
        Date(timeIntervalSince1970: Double(s) ?? Date().timeIntervalSince1970)
    }

    /// Returns nil for Zeek's placeholder value "-".
    nonisolated private func zeekField(_ cols: [String], _ i: Int) -> String? {
        guard i < cols.count else { return nil }
        return cols[i] == "-" || cols[i].isEmpty ? nil : cols[i]
    }

    nonisolated private func isDGAOrTunnel(_ domain: String) -> Bool {
        let lower = domain.lowercased()
        if lower.contains("dnscat") || lower.contains("iodine") { return true }
        let labels = lower.split(separator: ".")
        if labels.count > 6 { return true }
        return labels.contains { $0.count > 20 && shannonEntropy(String($0)) > 3.5 }
    }

    nonisolated private func shannonEntropy(_ s: String) -> Double {
        var freq: [Character: Double] = [:]
        for c in s { freq[c, default: 0] += 1 }
        let len = Double(s.count)
        return freq.values.reduce(0.0) { acc, p in
            let p = p / len; return acc - p * log2(p)
        }
    }

    nonisolated private func suspiciousUA(_ ua: String) -> Bool {
        let lower = ua.lowercased()
        return ["curl","wget","python-requests","go-http","masscan","nmap","sqlmap"]
            .contains { lower.contains($0) }
    }
}
