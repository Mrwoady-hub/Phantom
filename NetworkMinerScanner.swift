@preconcurrency import Foundation

// MARK: - NetworkMinerScanner
//
// Implements NetworkMiner-style forensic artifact extraction from pcap files.
//
// NetworkMiner (original) is a .NET/Windows application that extracts:
//   • Transmitted files (HTTP, SMB, FTP)
//   • Credentials (FTP USER/PASS, HTTP Basic Auth, Telnet)
//   • DNS host→IP mapping
//   • TLS certificate details
//   • Email metadata (SMTP)
//   • Session summaries
//
// On macOS, we replicate this capability using tshark's protocol dissectors
// and field extraction — same forensic output, native toolchain.
//
// No additional installation required beyond tshark (from brew install --cask wireshark).

final class NetworkMinerScanner {

    // MARK: - Availability

    private nonisolated var tsharkPaths: [String] { [
        "/opt/homebrew/bin/tshark",
        "/usr/local/bin/tshark",
        "/Applications/Wireshark.app/Contents/MacOS/tshark"
    ] }

    nonisolated init() {}

    nonisolated var isAvailable: Bool { tsharkPath != nil }

    nonisolated var tsharkPath: String? {
        tsharkPaths.first { path in
            path.withCString { Darwin.access($0, X_OK) == 0 }
        }
    }

    // MARK: - Extract artifacts

    nonisolated func extractArtifacts(from pcapPath: String) -> [PacketEvent] {
        guard let tshark = tsharkPath else { return [] }
        var events: [PacketEvent] = []
        // Modern traffic (TLS-first) — these always produce events
        events += extractTLSSNI(tshark: tshark, pcap: pcapPath)
        events += extractDNSHostMap(tshark: tshark, pcap: pcapPath)
        // Legacy / cleartext protocols — produce events when present
        events += extractHTTPObjects(tshark: tshark, pcap: pcapPath)
        events += extractCredentials(tshark: tshark, pcap: pcapPath)
        events += extractSMTPMetadata(tshark: tshark, pcap: pcapPath)
        events += extractFTPActivity(tshark: tshark, pcap: pcapPath)
        events += extractTelnet(tshark: tshark, pcap: pcapPath)
        return events
    }

    // MARK: - TLS SNI host map (works on modern encrypted traffic)
    //
    // TLS Client Hello is sent BEFORE encryption is established, so the SNI
    // hostname extension is in plaintext. This is NetworkMiner's primary source
    // of host visibility on modern TLS-heavy traffic.

    nonisolated private func extractTLSSNI(tshark: String, pcap: String) -> [PacketEvent] {
        let rows = tsharkFields(tshark, pcap: pcap,
            filter: "tls.handshake.type == 1",   // Client Hello
            fields: ["frame.time_epoch", "ip.src", "ip.dst", "tcp.dstport",
                     "tls.handshake.extensions_server_name"])
        var seen = Set<String>()
        return rows.compactMap { row -> PacketEvent? in
            guard row.count >= 5 else { return nil }
            let sni = row[4]
            guard !sni.isEmpty else { return nil }
            // One event per unique client→SNI pair per capture window
            let key = "\(row[1])→\(sni)"
            guard seen.insert(key).inserted else { return nil }
            let dstPort = Int(row[3])
            return PacketEvent(
                timestamp: ts(row[0]),
                tool: .networkMiner,
                category: .tls,
                severity: .low,
                sourceIP: nonEmpty(row[1]),
                destinationIP: nonEmpty(row[2]),
                destinationPort: dstPort,
                proto: "TCP",
                summary: "NetworkMiner TLS: \(sni):\(dstPort ?? 443)",
                detail: "SNI hostname from unencrypted TLS Client Hello",
                artifact: sni
            )
        }
    }

    // MARK: - Cleartext credentials

    nonisolated private func extractCredentials(tshark: String, pcap: String) -> [PacketEvent] {
        var events: [PacketEvent] = []

        // FTP USER and PASS commands (cleartext protocol)
        let ftp = tsharkFields(tshark, pcap: pcap,
            filter: "ftp.request.command",
            fields: ["frame.time_epoch","ip.src","ip.dst","ftp.request.command","ftp.request.arg"])
        for row in ftp {
            guard row.count >= 4 else { continue }
            let ts  = ts(row[0])
            let cmd = row[3]
            guard !cmd.isEmpty else { continue }
            let isPass = cmd.uppercased() == "PASS"
            events.append(PacketEvent(
                timestamp: ts,
                tool: .networkMiner,
                category: .artifact,
                severity: .high,
                sourceIP: nonEmpty(row[1]),
                destinationIP: nonEmpty(row[2]),
                proto: "TCP",
                summary: "NetworkMiner: FTP \(cmd) \(isPass ? "[password redacted]" : row.count > 4 ? row[4] : "")",
                detail: "Cleartext FTP credential detected — FTP transmits login data in plaintext",
                artifact: "FTP:\(cmd)"
            ))
        }

        // HTTP Basic Auth header
        let httpAuth = tsharkFields(tshark, pcap: pcap,
            filter: "http.authorization",
            fields: ["frame.time_epoch","ip.src","ip.dst","http.host","http.authorization"])
        for row in httpAuth {
            guard row.count >= 3 else { continue }
            events.append(PacketEvent(
                timestamp: ts(row[0]),
                tool: .networkMiner,
                category: .artifact,
                severity: .high,
                sourceIP: nonEmpty(row[1]),
                destinationIP: nonEmpty(row[2]),
                proto: "TCP",
                summary: "NetworkMiner: HTTP Basic Auth credentials (base64-encoded in cleartext)",
                detail: "Host: \(row.count > 3 ? row[3] : "?")",
                artifact: "HTTP Authorization header"
            ))
        }

        // POP3 USER/PASS
        let pop3 = tsharkFields(tshark, pcap: pcap,
            filter: "pop.request.command",
            fields: ["frame.time_epoch","ip.src","ip.dst","pop.request.command","pop.request.parameter"])
        for row in pop3 {
            guard row.count >= 4 else { continue }
            let cmd = row[3].uppercased()
            guard cmd == "USER" || cmd == "PASS" else { continue }
            events.append(PacketEvent(
                timestamp: ts(row[0]),
                tool: .networkMiner,
                category: .artifact,
                severity: .high,
                sourceIP: nonEmpty(row[1]),
                destinationIP: nonEmpty(row[2]),
                proto: "TCP",
                summary: "NetworkMiner: POP3 \(cmd) \(cmd == "PASS" ? "[redacted]" : row.count > 4 ? row[4] : "")",
                detail: "Cleartext POP3 mail credential",
                artifact: "POP3:\(cmd)"
            ))
        }

        return events
    }

    // MARK: - HTTP object transfers (files)

    nonisolated private func extractHTTPObjects(tshark: String, pcap: String) -> [PacketEvent] {
        let rows = tsharkFields(tshark, pcap: pcap,
            filter: "http.response and http.content_type",
            fields: ["frame.time_epoch","ip.src","ip.dst","http.content_type",
                     "http.content_length","http.response_for.uri"])
        return rows.compactMap { row -> PacketEvent? in
            guard row.count >= 4 else { return nil }
            let contentType = row[3]
            guard !contentType.isEmpty else { return nil }
            let size        = row.count > 4 ? row[4] : "?"
            let uri         = row.count > 5 ? row[5] : ""

            let isExec = contentType.contains("executable")
                      || contentType.contains("x-msdownload")
                      || contentType.contains("octet-stream")
                      || uri.hasSuffix(".exe") || uri.hasSuffix(".sh")
                      || uri.hasSuffix(".dmg") || uri.hasSuffix(".pkg")
                      || uri.hasSuffix(".ps1") || uri.hasSuffix(".bat")

            return PacketEvent(
                timestamp: ts(row[0]),
                tool: .networkMiner,
                category: .artifact,
                severity: isExec ? .high : .low,
                sourceIP: nonEmpty(row[1]),
                destinationIP: nonEmpty(row[2]),
                proto: "TCP",
                summary: "NetworkMiner: HTTP object [\(contentType)] \(size) bytes\(isExec ? " ⚠ executable" : "")",
                detail: uri.isEmpty ? nil : "URI: \(uri)",
                artifact: "\(contentType) (\(size) bytes)"
            )
        }
    }

    // MARK: - DNS host map (queries + responses, all record types)

    nonisolated private func extractDNSHostMap(tshark: String, pcap: String) -> [PacketEvent] {
        // Previous filter required dns.a (IPv4 A record) — misses AAAA, CNAME, MX, and
        // all DNS queries. Now capture ALL DNS traffic so we see every lookup.
        let rows = tsharkFields(tshark, pcap: pcap,
            filter: "dns",
            fields: ["frame.time_epoch", "ip.src", "ip.dst",
                     "dns.qry.name", "dns.a", "dns.aaaa", "dns.flags.response"])
        var seen = Set<String>()
        return rows.compactMap { row -> PacketEvent? in
            guard row.count >= 4 else { return nil }
            let hostname = row[3]
            guard !hostname.isEmpty else { return nil }
            guard seen.insert(hostname).inserted else { return nil }   // deduplicate
            let resolved = row.count > 4 ? nonEmpty(row[4]) : nil     // A record
                        ?? (row.count > 5 ? nonEmpty(row[5]) : nil)   // AAAA record
            let isResponse = row.count > 6 && row[6] == "1"
            let summary = isResponse
                ? "NetworkMiner DNS: \(hostname)\(resolved.map { " → \($0)" } ?? "")"
                : "NetworkMiner DNS?: \(hostname)"
            return PacketEvent(
                timestamp: ts(row[0]),
                tool: .networkMiner,
                category: .dns,
                severity: .low,
                sourceIP: nonEmpty(row[1]),
                destinationIP: nonEmpty(row[2]),
                summary: summary,
                dnsQuery: hostname,
                artifact: resolved.map { "\(hostname) → \($0)" } ?? hostname
            )
        }
    }

    // MARK: - SMTP email metadata

    nonisolated private func extractSMTPMetadata(tshark: String, pcap: String) -> [PacketEvent] {
        let rows = tsharkFields(tshark, pcap: pcap,
            filter: "smtp and smtp.req",
            fields: ["frame.time_epoch","ip.src","ip.dst","smtp.req.command","smtp.req.parameter"])
        return rows.prefix(20).compactMap { row -> PacketEvent? in
            guard row.count >= 4 else { return nil }
            let cmd = row[3]
            guard !cmd.isEmpty, ["MAIL","RCPT","DATA","AUTH"].contains(cmd.uppercased()) else { return nil }
            let param = row.count > 4 ? row[4] : ""
            return PacketEvent(
                timestamp: ts(row[0]),
                tool: .networkMiner,
                category: .artifact,
                severity: .medium,
                sourceIP: nonEmpty(row[1]),
                destinationIP: nonEmpty(row[2]),
                proto: "TCP",
                summary: "NetworkMiner: SMTP \(cmd) \(param.prefix(60))",
                detail: "Email metadata extracted from SMTP session",
                artifact: "SMTP:\(cmd)"
            )
        }
    }

    // MARK: - FTP activity (commands + data)

    nonisolated private func extractFTPActivity(tshark: String, pcap: String) -> [PacketEvent] {
        let rows = tsharkFields(tshark, pcap: pcap,
            filter: "ftp.request.command",
            fields: ["frame.time_epoch","ip.src","ip.dst","ftp.request.command","ftp.request.arg"])
        return rows.prefix(30).compactMap { row -> PacketEvent? in
            guard row.count >= 4 else { return nil }
            let cmd = row[3].uppercased()
            guard !cmd.isEmpty else { return nil }
            // STOR/RETR are data transfer — high interest
            let isTransfer = cmd == "STOR" || cmd == "RETR"
            return PacketEvent(
                timestamp: ts(row[0]),
                tool: .networkMiner,
                category: .artifact,
                severity: isTransfer ? .medium : .low,
                sourceIP: nonEmpty(row[1]),
                destinationIP: nonEmpty(row[2]),
                proto: "TCP",
                summary: "NetworkMiner: FTP \(cmd)\(row.count > 4 && !row[4].isEmpty ? " \(row[4])" : "")",
                detail: isTransfer ? "File \(cmd == "STOR" ? "upload" : "download") via FTP (cleartext)" : nil,
                artifact: "FTP:\(cmd)"
            )
        }
    }

    // MARK: - Telnet (cleartext remote shell)

    nonisolated private func extractTelnet(tshark: String, pcap: String) -> [PacketEvent] {
        let rows = tsharkFields(tshark, pcap: pcap,
            filter: "telnet",
            fields: ["frame.time_epoch","ip.src","ip.dst","tcp.dstport"])
        guard !rows.isEmpty else { return [] }

        // Telnet sessions are inherently cleartext — surface as a single incident
        let firstRow = rows[0]
        return [PacketEvent(
            timestamp: ts(firstRow.count > 0 ? firstRow[0] : ""),
            tool: .networkMiner,
            category: .artifact,
            severity: .high,
            sourceIP: firstRow.count > 1 ? nonEmpty(firstRow[1]) : nil,
            destinationIP: firstRow.count > 2 ? nonEmpty(firstRow[2]) : nil,
            destinationPort: firstRow.count > 3 ? Int(firstRow[3]) : 23,
            proto: "TCP",
            summary: "NetworkMiner: Telnet session — cleartext remote shell (\(rows.count) packets)",
            detail: "Telnet transmits all data including credentials in plaintext. Use SSH instead.",
            artifact: "Telnet session (\(rows.count) packets)"
        )]
    }

    // MARK: - tshark field extraction helper

    nonisolated private func tsharkFields(
        _ tshark: String,
        pcap: String,
        filter: String,
        fields: [String]
    ) -> [[String]] {
        var args = ["-r", pcap, "-Y", filter, "-T", "fields"]
        for f in fields { args += ["-e", f] }
        args += ["-E", "separator=\u{01}"]

        let output = shell(tshark, args: args)
        return (output ?? "")
            .components(separatedBy: "\n")
            .filter { !$0.isEmpty }
            .map    { $0.components(separatedBy: "\u{01}") }
    }

    // MARK: - Helpers

    nonisolated private func ts(_ s: String) -> Date {
        Date(timeIntervalSince1970: Double(s) ?? Date().timeIntervalSince1970)
    }

    /// Return nil if the string is empty, otherwise return the string.
    nonisolated private func nonEmpty(_ s: String) -> String? { s.isEmpty ? nil : s }

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
