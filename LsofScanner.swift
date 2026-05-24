// LsofScanner.swift
//
// Converts NetworkMonitor's cached lsof records into PacketEvents for the
// Network Intel tab.  This eliminates the previous duplicate lsof invocation:
// NetworkMonitor already calls lsof (with a 90-second result cache) for the
// incident-detection pipeline.  LsofScanner now reuses that cached result
// rather than shelling out a second time.
//
// Benefits:
//   • One lsof call per 90-second window instead of two
//   • Both the incident list and the PacketEvent store always reflect the same
//     underlying connection snapshot
//   • NetworkMonitor's NSLock-protected cache is safe to call from nonisolated
//     context (ScanWorker actor)

import Foundation

// MARK: - LsofScanner

final class LsofScanner {

    // nonisolated: LsofScanner has no UI dependencies and no MainActor state.
    // The explicit annotation overrides the project's -default-isolation MainActor
    // so ScanWorker (an actor) can create and call this synchronously.
    nonisolated init() {}

    // MARK: - Public entry point

    /// Returns PacketEvents derived from NetworkMonitor's cached lsof data.
    /// No subprocess is spawned here — the data comes from NetworkMonitor's
    /// 90-second shared cache, which is populated by the telemetry pipeline.
    nonisolated func scan() -> [PacketEvent] {
        let records = NetworkMonitor().activeConnectionRecords()
        return convert(records)
    }

    // MARK: - Conversion

    private nonisolated func convert(_ records: [NetworkConnectionRecord]) -> [PacketEvent] {
        var events: [PacketEvent] = []
        var seen   = Set<String>()
        let now    = Date()

        for record in records {
            // Skip listeners and loopback-only connections
            guard record.isExternal, !record.isListening else { continue }

            let command = record.command

            // Parse "srcIP:srcPort->dstIP:dstPort" or "host:port" from the name field.
            // NetworkMonitor produces strings like "192.168.1.2:54321->1.2.3.4:443".
            let (srcIP, srcPort, dstIP, dstPort) = parseEndpoints(record.name)

            // Skip pure-loopback that isExternal missed
            if let s = srcIP, let d = dstIP,
               s.hasPrefix("127.") && d.hasPrefix("127.") { continue }

            // Dedup — same process + same 5-tuple during one conversion pass
            let key = "\(command)|\(srcIP ?? ""):\(srcPort ?? 0)->\(dstIP ?? ""):\(dstPort ?? 0)"
            guard !seen.contains(key) else { continue }
            seen.insert(key)

            let category  = portCategory(dstPort)
            let severity  = portSeverity(dstPort)
            let portLabel = dstPort.flatMap { portName($0) } ?? ""
            let dest      = dstIP ?? record.name

            let summary = portLabel.isEmpty
                ? "\(command) → \(dest):\(dstPort ?? 0)"
                : "\(command) → \(dest):\(dstPort ?? 0) (\(portLabel))"

            let detail = buildDetail(
                command:   command,
                srcIP:     srcIP ?? "?",
                srcPort:   srcPort,
                dstIP:     dest,
                dstPort:   dstPort,
                portLabel: portLabel,
                severity:  severity
            )

            events.append(PacketEvent(
                timestamp:       now,
                tool:            .tcpdump,   // "built-in macOS" bucket
                category:        category,
                severity:        severity,
                sourceIP:        srcIP,
                destinationIP:   dstIP,
                sourcePort:      srcPort,
                destinationPort: dstPort,
                proto:           record.protocolName,
                summary:         summary,
                detail:          detail
            ))
        }

        return events
    }

    // MARK: - Endpoint parser

    /// Parses a NetworkMonitor name field such as:
    ///   "192.168.1.2:54321->1.2.3.4:443"   (connected)
    ///   "192.168.1.2:80"                     (listener / half-open)
    ///   "hostname:https"                     (pre-resolved)
    private nonisolated func parseEndpoints(
        _ name: String
    ) -> (srcIP: String?, srcPort: Int?, dstIP: String?, dstPort: Int?) {

        // Arrow notation — connected TCP/UDP
        if let arrow = name.range(of: "->") {
            let lhs = String(name[..<arrow.lowerBound])
            let rhs = String(name[arrow.upperBound...])
            return (lastComponent(lhs), portOf(lhs), lastComponent(rhs), portOf(rhs))
        }

        // Single endpoint (listener or UDP)
        return (nil, nil, lastComponent(name), portOf(name))
    }

    /// Extracts the IP/host portion from "ip:port" or "host:service".
    private nonisolated func lastComponent(_ s: String) -> String? {
        guard let colon = s.lastIndex(of: ":") else { return s.isEmpty ? nil : s }
        let host = String(s[..<colon])
        return host.isEmpty ? nil : host
    }

    /// Extracts the numeric port from "ip:port".  Returns nil for named services.
    private nonisolated func portOf(_ s: String) -> Int? {
        guard let colon = s.lastIndex(of: ":") else { return nil }
        return Int(s[s.index(after: colon)...])
    }

    // MARK: - Detail text

    private nonisolated func buildDetail(
        command: String, srcIP: String, srcPort: Int?,
        dstIP: String, dstPort: Int?, portLabel: String, severity: Severity
    ) -> String {
        var parts: [String] = []
        let portStr = portLabel.isEmpty ? (dstPort.map { ":\($0)" } ?? "") : ":\(dstPort ?? 0) (\(portLabel))"
        parts.append("\(command) has an active connection to \(dstIP)\(portStr).")
        switch severity {
        case .high:
            parts.append("⚠ Port \(dstPort ?? 0) is commonly used by malware and C2 frameworks. Investigate immediately.")
        case .medium:
            parts.append("This port is worth reviewing — ensure the connection is expected for '\(command)'.")
        case .low:
            break
        }
        return parts.joined(separator: " ")
    }

    // MARK: - Port helpers

    private nonisolated func portCategory(_ port: Int?) -> PacketEventCategory {
        guard let port else { return .connection }
        switch port {
        case 53:              return .dns
        case 80:              return .http
        case 443, 8443, 993, 995: return .tls
        default:              return .connection
        }
    }

    private nonisolated func portSeverity(_ port: Int?) -> Severity {
        guard let port else { return .low }
        let high: Set<Int> = [4444, 1337, 6667, 23, 445, 3389, 135, 139, 4899, 5554, 9001]
        let med:  Set<Int> = [21, 22, 25, 80, 110, 143, 5900, 8080]
        if high.contains(port) { return .high   }
        if med.contains(port)  { return .medium }
        return .low
    }

    private nonisolated func portName(_ port: Int) -> String? {
        switch port {
        case 21:   return "FTP"
        case 22:   return "SSH"
        case 23:   return "Telnet"
        case 25:   return "SMTP"
        case 53:   return "DNS"
        case 80:   return "HTTP"
        case 110:  return "POP3"
        case 143:  return "IMAP"
        case 443:  return "HTTPS"
        case 445:  return "SMB"
        case 587:  return "SMTP/TLS"
        case 993:  return "IMAPS"
        case 995:  return "POP3S"
        case 1194: return "OpenVPN"
        case 1337: return "Leet/Malware"
        case 3389: return "RDP"
        case 4444: return "Metasploit C2"
        case 5900: return "VNC"
        case 6667: return "IRC"
        case 8080: return "HTTP-alt"
        case 8443: return "HTTPS-alt"
        case 9001: return "Tor"
        default:   return nil
        }
    }
}
