@preconcurrency import Foundation

// MARK: - NgrepScanner
//
// Wraps ngrep — "grep for network packets".
// ngrep searches raw packet payloads for regex/string patterns.
// It can read from live interfaces (root required) or pcap files (no root).
//
// Installation:  brew install ngrep
// Binary paths:  /opt/homebrew/bin/ngrep  (Apple Silicon)
//                /usr/local/bin/ngrep      (Intel)
//
// This scanner operates in read-only mode against existing pcap files.
// The PrivilegedHelper provides the pcap; ngrep searches it for threat patterns.

final class NgrepScanner {

    // MARK: - Availability

    private nonisolated var knownPaths: [String] { [
        "/opt/homebrew/bin/ngrep",
        "/usr/local/bin/ngrep"
    ] }

    nonisolated init() {}

    nonisolated var isAvailable: Bool { executablePath != nil }

    nonisolated var executablePath: String? {
        knownPaths.first { path in
            path.withCString { Darwin.access($0, X_OK) == 0 }
        }
    }

    // MARK: - Quick-reference live-capture patterns
    //
    // These patterns target a live interface (en0 or similar).
    // Phantom passes them to the PrivilegedHelper, which runs ngrep as root.
    // Replace "en0" with the active interface — use `interfaceDiscoveryHint`
    // to surface the right name in the UI.

    struct QuickPattern: Identifiable, Sendable {
        let id          = UUID()
        let title:       String   // short label shown in the UI
        let pattern:     String   // ngrep -e pattern / regex
        let extraArgs:   [String] // additional ngrep flags (excluding -d <iface>)
        let bpfFilter:   String?  // optional BPF expression (e.g. "tcp port 80")
        let description: String   // one-line explanation shown in a tooltip
        let requiresRoot: Bool    // all live-capture patterns need root
    }

    /// Discover the active interface name for the UI hint label.
    /// Runs synchronously — call off the main thread.
    nonisolated func activeInterface() -> String? {
        let task  = Process()
        let pipe  = Pipe()
        task.executableURL  = URL(fileURLWithPath: "/sbin/ifconfig")
        task.standardOutput = pipe
        task.standardError  = Pipe()
        guard (try? task.run()) != nil else { return nil }
        let out = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        task.waitUntilExit()

        // Walk interface blocks; return the first one marked "status: active"
        // that isn't loopback (lo0) or tunnel/utun interfaces.
        var currentIface: String?
        for line in out.components(separatedBy: "\n") {
            if let m = line.range(of: #"^([a-z0-9]+):"#, options: .regularExpression) {
                currentIface = String(line[m]).trimmingCharacters(in: CharacterSet(charactersIn: ":"))
            }
            if line.contains("status: active"),
               let iface = currentIface,
               !iface.hasPrefix("lo"),
               !iface.hasPrefix("utun"),
               !iface.hasPrefix("gif"),
               !iface.hasPrefix("stf") {
                return iface
            }
        }
        return nil
    }

    /// Shell hint the UI can display so users know which command to run first.
    static let interfaceDiscoveryHint =
        #"ifconfig | grep -E '^[a-z0-9]+:|status: active'"#

    static let quickPatterns: [QuickPattern] = [
        QuickPattern(
            title:        "All traffic",
            pattern:      ".",
            extraArgs:    [],
            bpfFilter:    nil,
            description:  "Capture every packet on the interface — useful for a quick sanity-check that ngrep is working.",
            requiresRoot: false   // passive sniff on en0 doesn't strictly need root on macOS
        ),
        QuickPattern(
            title:        "HTTP requests",
            pattern:      #"Host:|GET |POST "#,
            extraArgs:    ["-W", "byline"],
            bpfFilter:    "tcp port 80",
            description:  "Shows HTTP request lines and Host headers — fast way to see unencrypted web traffic.",
            requiresRoot: true
        ),
        QuickPattern(
            title:        "DNS inspection",
            pattern:      #"dns|A\?|AAAA\?"#,
            extraArgs:    ["-W", "byline"],
            bpfFilter:    "udp port 53",
            description:  "DNS-oriented filter for quick domain-lookup visibility. For raw DNS payload detail, use tcpdump.",
            requiresRoot: true
        ),
        QuickPattern(
            title:        "HTTP headers",
            pattern:      "User-Agent:|Cookie:",
            extraArgs:    ["-W", "byline"],
            bpfFilter:    "tcp",
            description:  "Searches for User-Agent and Cookie headers across all TCP traffic.",
            requiresRoot: true
        ),
        QuickPattern(
            title:        "Sensitive strings",
            pattern:      "password|token|apikey",
            extraArgs:    ["-q"],
            bpfFilter:    "tcp",
            description:  "Looks for credential-like strings in TCP payloads — catches cleartext secrets in transit.",
            requiresRoot: true
        ),
        QuickPattern(
            title:        "TLS hex dump",
            pattern:      ".",
            extraArgs:    ["-x"],
            bpfFilter:    "port 443",
            description:  "Hex/ASCII dump of TLS traffic. Ciphertext is unreadable, but packet metadata and handshake structure are visible.",
            requiresRoot: true
        ),
    ]

    // MARK: - Threat signatures

    private struct Signature {
        let pattern: String
        let description: String
        let severity: Severity
        let technique: String?
    }

    private let signatures: [Signature] = [
        // Cleartext credentials
        Signature(pattern: "password=",            description: "Cleartext password in payload",           severity: .high,   technique: "T1552"),
        Signature(pattern: "passwd=",              description: "Cleartext passwd in payload",             severity: .high,   technique: "T1552"),
        Signature(pattern: "Authorization: Basic", description: "HTTP Basic Auth credentials",             severity: .high,   technique: "T1552"),
        Signature(pattern: "Authorization: Bearer",description: "HTTP Bearer token in cleartext",          severity: .medium, technique: "T1552"),
        // Shell command execution in payload
        Signature(pattern: "/bin/sh",              description: "Shell command in network payload",        severity: .high,   technique: "T1059"),
        Signature(pattern: "/bin/bash",            description: "Bash invocation in network payload",      severity: .high,   technique: "T1059"),
        Signature(pattern: "cmd.exe",              description: "Windows cmd.exe in network payload",      severity: .high,   technique: "T1059"),
        Signature(pattern: "powershell",           description: "PowerShell in network payload",           severity: .high,   technique: "T1059"),
        // Known offensive tools
        Signature(pattern: "mimikatz",             description: "Mimikatz credential tool signature",      severity: .high,   technique: "T1003"),
        Signature(pattern: "meterpreter",          description: "Metasploit Meterpreter signature",        severity: .high,   technique: "T1055"),
        Signature(pattern: "cobalt strike",        description: "Cobalt Strike C2 signature",              severity: .high,   technique: "T1071"),
        Signature(pattern: "cobaltstrike",         description: "Cobalt Strike beacon signature",          severity: .high,   technique: "T1071"),
        Signature(pattern: "empire",               description: "PowerShell Empire C2 signature",          severity: .high,   technique: "T1071"),
        // Reconnaissance tools
        Signature(pattern: "masscan",              description: "Masscan port scanner signature",          severity: .medium, technique: "T1046"),
        Signature(pattern: "sqlmap",               description: "SQLMap injection tool signature",         severity: .high,   technique: "T1190"),
        Signature(pattern: "nikto",                description: "Nikto web scanner signature",             severity: .medium, technique: "T1595"),
        Signature(pattern: "dirbuster",            description: "DirBuster web directory scanner",         severity: .medium, technique: "T1595"),
        // Data exfiltration indicators
        Signature(pattern: "X-Exfil",             description: "Potential exfiltration header",            severity: .high,   technique: "T1041"),
        Signature(pattern: "X-Upload-Token",       description: "Custom upload header — potential exfil",  severity: .medium, technique: "T1041"),
        // Beaconing / C2 patterns
        Signature(pattern: "beacon",               description: "Potential C2 beacon keyword",             severity: .medium, technique: "T1071"),
        Signature(pattern: "checkin",              description: "Potential C2 check-in keyword",           severity: .medium, technique: "T1071"),
        Signature(pattern: "heartbeat",            description: "C2 heartbeat keyword in payload",         severity: .low,    technique: "T1071"),
    ]

    // MARK: - Live-capture arg builder

    /// Builds the complete ngrep argument list for a QuickPattern on a given interface.
    ///
    /// Example result for "HTTP requests" on en0:
    ///   ["-d", "en0", "-W", "byline", "Host:|GET |POST ", "tcp port 80"]
    ///
    /// Pass this array to the PrivilegedHelper's XPC method that launches ngrep as root.
    nonisolated func buildLiveArgs(for pattern: QuickPattern, interface: String) -> [String] {
        var args: [String] = ["-d", interface]
        args += pattern.extraArgs
        args.append(pattern.pattern)
        if let bpf = pattern.bpfFilter { args.append(bpf) }
        return args
    }

    // MARK: - Scan

    /// Search the pcap file for threat signatures, TLS SNI hostnames, and HTTP traffic.
    ///
    /// Three sweeps run in sequence:
    ///  1. Threat signatures — cleartext credential/tool patterns (fire on HTTP, FTP, etc.)
    ///  2. TLS SNI — domain names in unencrypted TLS Client Hello on ANY TCP port
    ///  3. HTTP Host — "Host:" header on port 80, guaranteed match on any HTTP traffic
    ///
    /// Sweeps 2 & 3 ensure ngrep always produces events on modern TLS-heavy traffic,
    /// not just on the rare cleartext captures where threat signatures fire.
    nonisolated func scan(pcapPath: String) -> [PacketEvent] {
        guard let ngrep = executablePath else { return [] }
        var events: [PacketEvent] = []

        // 1. Threat signature scan (cleartext protocols)
        for sig in signatures {
            let matches = search(ngrep: ngrep, pcap: pcapPath, pattern: sig.pattern)
            for match in matches {
                events.append(PacketEvent(
                    tool: .ngrep,
                    category: .patternMatch,
                    severity: sig.severity,
                    sourceIP: match.srcIP,
                    destinationIP: match.dstIP,
                    sourcePort: match.srcPort,
                    destinationPort: match.dstPort,
                    proto: match.proto,
                    summary: "ngrep: \(sig.description)",
                    detail: "Matched pattern '\(sig.pattern)' in \(match.proto ?? "IP") payload",
                    rawPayload: match.context,
                    signatureName: sig.technique.map { "MITRE \($0): \(sig.description)" }
                ))
            }
        }

        // 2. TLS SNI scan — matches domain names visible in unencrypted Client Hello.
        //    Searches ALL TCP ports (not just 443) because TLS runs on many ports
        //    (8443, 993, 995, 465, 5228, etc.) and Client Hello is always plaintext.
        events += scanTLSSNI(ngrep: ngrep, pcap: pcapPath)

        // 3. HTTP Host header scan — "Host: apple.com" is guaranteed plaintext on
        //    port 80 and appears in every HTTP/1.1 request. This gives ngrep reliable
        //    output even when all HTTPS sessions are TLS-resumed with no new Client Hello.
        events += scanHTTPHost(ngrep: ngrep, pcap: pcapPath)

        return events
    }

    /// Scans ALL TCP traffic for TLS SNI hostnames.
    ///
    /// The TLS Client Hello is unencrypted (it negotiates the session — there is
    /// no session yet). The SNI extension contains the target hostname as literal
    /// ASCII bytes, matching a domain-name regex even in a "fully encrypted" capture.
    /// Sweeping all TCP (not just port 443) catches TLS on non-standard ports.
    nonisolated private func scanTLSSNI(ngrep: String, pcap: String) -> [PacketEvent] {
        // Pattern matches the ASCII hostname in the SNI extension.
        // Domains appear as e.g. "apple.com", "api.github.com", "cdn.amazon.com".
        // The regex is intentionally broad — any label.tld structure visible in payload.
        let sniPattern = "[a-z0-9-]{1,63}\\.[a-z]{2,10}"

        // Sweep all TCP — TLS runs on 443, 8443, 993, 995, 465, 5228, 4443 and more.
        // BPF "tcp" is broader than listing specific ports and catches everything.
        let matches = search(ngrep: ngrep, pcap: pcap, pattern: sniPattern, extraBPF: "tcp")

        // Deduplicate by client→server pair — one event per destination, not per packet
        var seen = Set<String>()
        return matches.compactMap { match -> PacketEvent? in
            let key = "\(match.srcIP ?? "")→\(match.dstIP ?? ""):\(match.dstPort ?? 443)"
            guard seen.insert(key).inserted else { return nil }
            // Skip port-80 matches here — those are HTTP Host headers handled by scanHTTPHost
            if match.dstPort == 80 { return nil }
            let domain = extractDomain(from: match.context)
            guard let domain else { return nil }  // skip if no clean domain found
            return PacketEvent(
                tool: .ngrep,
                category: .tls,
                severity: .low,
                sourceIP: match.srcIP,
                destinationIP: match.dstIP,
                sourcePort: match.srcPort,
                destinationPort: match.dstPort ?? 443,
                proto: "TCP",
                summary: "ngrep TLS SNI → \(domain)",
                detail: "TLS Client Hello — hostname visible in unencrypted handshake"
            )
        }
    }

    /// Scans HTTP port-80 traffic for the Host header, which is guaranteed plaintext
    /// in every HTTP/1.1 request. "Host: apple.com" → extracted as a connection event.
    nonisolated private func scanHTTPHost(ngrep: String, pcap: String) -> [PacketEvent] {
        // "Host: " appears in every HTTP/1.1 request header, always in cleartext.
        let matches = search(ngrep: ngrep, pcap: pcap,
                             pattern: "Host: ", extraBPF: "tcp port 80")
        var seen = Set<String>()
        return matches.compactMap { match -> PacketEvent? in
            let key = "\(match.srcIP ?? "")→\(match.dstIP ?? "")"
            guard seen.insert(key).inserted else { return nil }
            // Extract the hostname from "Host: apple.com\r\n..." payload
            let host: String? = match.context.components(separatedBy: "Host: ")
                .dropFirst().first
                .map { $0.components(separatedBy: CharacterSet(charactersIn: "\r\n ")).first ?? "" }
                .flatMap { $0.isEmpty ? nil : $0 }
            return PacketEvent(
                tool: .ngrep,
                category: .http,
                severity: .low,
                sourceIP: match.srcIP,
                destinationIP: match.dstIP,
                sourcePort: match.srcPort,
                destinationPort: 80,
                proto: "TCP",
                summary: "ngrep HTTP → \(host ?? match.dstIP ?? "?")",
                detail: "HTTP/1.1 Host header — cleartext request",
                httpURL: host.map { "http://\($0)" }
            )
        }
    }

    /// Extract the first clean domain-shaped token from a raw ngrep payload string.
    nonisolated private func extractDomain(from context: String) -> String? {
        context
            .components(separatedBy: CharacterSet.alphanumerics
                .union(CharacterSet(charactersIn: ".-")).inverted)
            .first(where: { token in
                token.contains(".") &&
                token.count > 4 &&
                !token.hasPrefix(".") &&
                !token.hasSuffix(".") &&
                token.split(separator: ".").last.map { $0.count >= 2 } ?? false
            })
    }

    // MARK: - Internal search

    private struct NgrepMatch {
        let srcIP: String?
        let dstIP: String?
        let srcPort: Int?
        let dstPort: Int?
        let proto: String?
        let context: String
    }

    nonisolated private func search(
        ngrep: String,
        pcap: String,
        pattern: String,
        extraBPF: String? = nil
    ) -> [NgrepMatch] {
        // ngrep -I: read from pcap
        // -q:      quiet mode (header per match only, no dots)
        // -i:      case-insensitive
        // -W byline: one packet header per line
        var args = ["-I", pcap, "-q", "-i", "-W", "byline", pattern]
        if let bpf = extraBPF { args.append(bpf) }
        let output = shell(ngrep, args: args)

        // ngrep output:
        // T 2024/01/15 14:30:00.000000 192.168.1.1:54321 -> 8.8.8.8:80 [AP]
        // <payload line(s)>
        // #  (separator)

        var matches: [NgrepMatch] = []
        var currentHeader: NgrepMatch?
        var contextLines: [String] = []

        for line in (output ?? "").components(separatedBy: "\n") {
            if line.hasPrefix("T ") || line.hasPrefix("U ") || line.hasPrefix("I ") {
                // Save previous match
                if let h = currentHeader {
                    matches.append(NgrepMatch(
                        srcIP: h.srcIP, dstIP: h.dstIP,
                        srcPort: h.srcPort, dstPort: h.dstPort,
                        proto: h.proto,
                        context: contextLines.joined(separator: " ").prefix(200).description
                    ))
                    contextLines = []
                }
                currentHeader = parseNgrepHeader(line)
            } else if line == "#" {
                if let h = currentHeader {
                    matches.append(NgrepMatch(
                        srcIP: h.srcIP, dstIP: h.dstIP,
                        srcPort: h.srcPort, dstPort: h.dstPort,
                        proto: h.proto,
                        context: contextLines.joined(separator: " ").prefix(200).description
                    ))
                }
                currentHeader = nil
                contextLines = []
            } else if currentHeader != nil, !line.isEmpty {
                contextLines.append(line.trimmingCharacters(in: .whitespaces))
            }
        }

        // Flush last match
        if let h = currentHeader {
            matches.append(NgrepMatch(
                srcIP: h.srcIP, dstIP: h.dstIP,
                srcPort: h.srcPort, dstPort: h.dstPort,
                proto: h.proto,
                context: contextLines.joined(separator: " ").prefix(200).description
            ))
        }

        return matches
    }

    // "T 2024/01/15 14:30:00.123456 192.168.1.1:12345 -> 8.8.8.8:80 [AP]"
    nonisolated private func parseNgrepHeader(_ line: String) -> NgrepMatch {
        let words = line.split(whereSeparator: \.isWhitespace).map(String.init)
        let proto = words.first == "T" ? "TCP" : words.first == "U" ? "UDP" : "IP"

        // Find "->": src is the word before it, dst is the word after
        var srcStr: String?, dstStr: String?
        for (i, w) in words.enumerated() {
            if w == "->" && i > 0 && i + 1 < words.count {
                srcStr = words[i - 1]
                dstStr = words[i + 1].trimmingCharacters(in: CharacterSet(charactersIn: "[]APF"))
            }
        }

        let (srcIP, srcPort) = parseHostPort(srcStr ?? "")
        let (dstIP, dstPort) = parseHostPort(dstStr ?? "")

        return NgrepMatch(srcIP: srcIP, dstIP: dstIP,
                          srcPort: srcPort, dstPort: dstPort,
                          proto: proto, context: "")
    }

    nonisolated private func parseHostPort(_ s: String) -> (String?, Int?) {
        if let idx = s.lastIndex(of: ":") {
            let ip   = String(s[..<idx])
            let port = Int(s[s.index(after: idx)...])
            return (ip.isEmpty ? nil : ip, port)
        }
        return (s.isEmpty ? nil : s, nil)
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
