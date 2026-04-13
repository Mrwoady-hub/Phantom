@preconcurrency import Foundation

// MARK: - SuricataScanner
//
// Parses Suricata's EVE JSON log for security events.
// Suricata is a high-performance IDS/IPS/NSM engine. When running as a daemon
// it writes all events as newline-delimited JSON to eve.json.
//
// Supported event_types: alert, dns, http, tls, flow, fileinfo
//
// Installation:    brew install suricata
// Start daemon:    suricata -c /opt/homebrew/etc/suricata/suricata.yaml --af-packet -D
// EVE log paths:   /var/log/suricata/eve.json        (root install)
//                  /opt/homebrew/var/log/suricata/eve.json  (Homebrew)
//
// This scanner is read-only — no privileges required to read the log file
// (as long as the file is world-readable, which is Suricata's default).

final class SuricataScanner {

    // MARK: - Log discovery

    nonisolated init() {}

    nonisolated private var candidatePaths: [String] {
        let home = getenv("HOME").map { String(cString: $0) } ?? ""
        return [
            "/var/log/suricata/eve.json",
            "/opt/homebrew/var/log/suricata/eve.json",
            "/usr/local/var/log/suricata/eve.json",
            "\(home)/suricata/eve.json"
        ]
    }

    nonisolated var logPath: String? {
        candidatePaths.first { path in
            path.withCString { Darwin.access($0, F_OK) == 0 }
        }
    }

    /// True if Suricata has been configured and is writing events.
    nonisolated var isActive: Bool { logPath != nil }

    // MARK: - Read recent events

    /// Returns PacketEvents from the last `lookbackSeconds` seconds.
    /// Reads at most the last `maxLines` lines of eve.json (tail approach).
    nonisolated func recentEvents(
        maxLines: Int = 2000,
        lookbackSeconds: TimeInterval = 3600
    ) -> [PacketEvent] {
        guard let path = logPath else { return [] }
        guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { return [] }

        let cutoff = Date().addingTimeInterval(-lookbackSeconds)
        return text
            .components(separatedBy: "\n")
            .filter   { !$0.isEmpty }
            .suffix(maxLines)
            .compactMap { parseEVELine($0, cutoff: cutoff) }
    }

    // MARK: - Public single-line parser (used by PacketCaptureEngine streaming)

    /// Parse a single EVE JSON line. Used by the DispatchSource file-watch handler
    /// in PacketCaptureEngine so new lines are processed the instant they arrive.
    nonisolated func parseSingleLine(_ line: String, cutoff: Date = .distantPast) -> PacketEvent? {
        parseEVELine(line, cutoff: cutoff)
    }

    // MARK: - EVE JSON line parser

    nonisolated private func parseEVELine(_ line: String, cutoff: Date) -> PacketEvent? {
        guard let data = line.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return nil }

        let ts = parseTimestamp(json["timestamp"] as? String ?? "")
        guard ts >= cutoff else { return nil }

        // Common network context
        let srcIP   = json["src_ip"]    as? String
        let dstIP   = json["dest_ip"]   as? String
        let srcPort = json["src_port"]  as? Int
        let dstPort = json["dest_port"] as? Int
        let proto   = json["proto"]     as? String

        switch json["event_type"] as? String ?? "" {
        case "alert":
            return parseAlert(json, ts: ts, src: srcIP, dst: dstIP,
                              srcP: srcPort, dstP: dstPort, proto: proto)
        case "dns":
            return parseDNS(json, ts: ts, src: srcIP, dst: dstIP, proto: proto)
        case "http":
            return parseHTTP(json, ts: ts, src: srcIP, dst: dstIP,
                             srcP: srcPort, dstP: dstPort)
        case "tls":
            return parseTLS(json, ts: ts, src: srcIP, dst: dstIP, dstP: dstPort)
        default:
            return nil
        }
    }

    // MARK: - alert

    nonisolated private func parseAlert(
        _ json: [String: Any], ts: Date,
        src: String?, dst: String?,
        srcP: Int?, dstP: Int?, proto: String?
    ) -> PacketEvent? {
        guard let alert = json["alert"] as? [String: Any] else { return nil }

        let action    = (alert["action"]    as? String ?? "unknown").uppercased()
        let signature = alert["signature"]  as? String ?? "Unknown Suricata Alert"
        let category  = alert["category"]   as? String
        let sev       = alert["severity"]   as? Int ?? 3
        let sid       = alert["signature_id"] as? Int

        let sgSev: Severity
        switch sev {
        case 1: sgSev = .high
        case 2: sgSev = .medium
        default: sgSev = .low
        }

        return PacketEvent(
            timestamp: ts,
            tool: .suricata,
            category: .alert,
            severity: sgSev,
            sourceIP: src,
            destinationIP: dst,
            sourcePort: srcP,
            destinationPort: dstP,
            proto: proto,
            summary: "Suricata [\(action)]: \(signature)",
            detail: category,
            signatureID: sid.map(String.init),
            signatureName: signature
        )
    }

    // MARK: - dns

    nonisolated private func parseDNS(
        _ json: [String: Any], ts: Date,
        src: String?, dst: String?, proto: String?
    ) -> PacketEvent? {
        guard let dns = json["dns"] as? [String: Any] else { return nil }

        let qtype    = (dns["type"] as? String ?? "query").lowercased()
        let isAnswer = qtype == "answer" || qtype == "response"

        // Suricata EVE v1 puts rrname at top level; v2 may only have it inside answers/queries.
        // Try every location so both formats work.
        let answers  = dns["answers"]  as? [[String: Any]] ?? []
        let queries  = dns["queries"]  as? [[String: Any]] ?? []

        let rrname: String = {
            if let v = dns["rrname"] as? String, !v.isEmpty { return v }
            if let v = answers.first?["rrname"] as? String,  !v.isEmpty { return v }
            if let v = queries.first?["rrname"] as? String,  !v.isEmpty { return v }
            return ""
        }()
        guard !rrname.isEmpty else { return nil }

        let rrtype: String = {
            if let v = dns["rrtype"] as? String,            !v.isEmpty { return v }
            if let v = answers.first?["rrtype"] as? String, !v.isEmpty { return v }
            return "A"
        }()

        // Pull the resolved IP out of the first A/AAAA answer record
        let resolvedIP = answers
            .first { $0["rrtype"] as? String == "A" || $0["rrtype"] as? String == "AAAA" }
            .flatMap { $0["rdata"] as? String }

        let summary = isAnswer
            ? "DNS \(rrname)\(resolvedIP.map { " → \($0)" } ?? " [\(rrtype) response]")"
            : "DNS query: \(rrname) [\(rrtype)]"

        return PacketEvent(
            timestamp: ts,
            tool: .suricata,
            category: .dns,
            severity: .low,
            sourceIP: src,
            destinationIP: dst,
            proto: proto ?? "UDP",
            summary: summary,
            detail: isAnswer ? "\(rrtype) response for \(rrname)\(resolvedIP.map { ": \($0)" } ?? "")" : nil,
            dnsQuery: rrname
        )
    }

    // MARK: - http

    nonisolated private func parseHTTP(
        _ json: [String: Any], ts: Date,
        src: String?, dst: String?,
        srcP: Int?, dstP: Int?
    ) -> PacketEvent? {
        guard let http = json["http"] as? [String: Any] else { return nil }

        let method   = http["http_method"]      as? String
        let hostname = http["hostname"]          as? String ?? ""
        let uri      = http["url"]              as? String ?? "/"
        let ua       = http["http_user_agent"]  as? String
        let status   = http["status"]           as? Int

        let suspicious = suspiciousUA(ua ?? "")
            || method == "PUT" || method == "DELETE"
            || (status == nil && method != nil)   // request without response yet

        return PacketEvent(
            timestamp: ts,
            tool: .suricata,
            category: .http,
            severity: suspicious ? .medium : .low,
            sourceIP: src,
            destinationIP: dst,
            sourcePort: srcP,
            destinationPort: dstP,
            proto: "TCP",
            summary: "Suricata HTTP: \(method ?? "?") \(hostname)\(uri)",
            detail: ua.map { "UA: \($0)" },
            httpMethod: method,
            httpURL: "http://\(hostname)\(uri)"
        )
    }

    // MARK: - tls

    nonisolated private func parseTLS(
        _ json: [String: Any], ts: Date,
        src: String?, dst: String?, dstP: Int?
    ) -> PacketEvent? {
        guard let tls = json["tls"] as? [String: Any] else { return nil }

        let sni      = tls["sni"]     as? String
        let subject  = tls["subject"] as? String
        let issuer   = tls["issuerdn"] as? String
        let selfSigned = subject != nil && issuer != nil && subject == issuer

        return PacketEvent(
            timestamp: ts,
            tool: .suricata,
            category: .tls,
            severity: selfSigned ? .medium : .low,
            sourceIP: src,
            destinationIP: dst,
            destinationPort: dstP,
            proto: "TCP",
            summary: "Suricata TLS → \(sni ?? dst ?? "?")\(selfSigned ? " [self-signed]" : "")",
            detail: selfSigned ? "Self-signed certificate — possible C2 or misconfiguration" : nil,
            tlsSubject: subject
        )
    }

    // MARK: - Helpers

    nonisolated private func parseTimestamp(_ s: String) -> Date {
        // EVE format: "2024-01-15T14:30:00.123456+0000"
        var f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let d = f.date(from: s) { return d }
        f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f.date(from: s) ?? Date()
    }

    nonisolated private func suspiciousUA(_ ua: String) -> Bool {
        let lower = ua.lowercased()
        return ["curl","wget","python-requests","go-http","masscan","nmap","sqlmap","nikto","dirbuster"]
            .contains { lower.contains($0) }
    }
}
