import Foundation

// MARK: - PacketTool
// The seven network security tools integrated in Phantom 3.0.

enum PacketTool: String, Codable, CaseIterable, Hashable, Sendable {
    case tshark       = "tshark"        // Wireshark CLI — deep protocol dissection
    case wireshark    = "wireshark"     // Wireshark (GUI alias; CLI ops use tshark)
    case tcpdump      = "tcpdump"       // Raw packet capture (pre-installed on macOS)
    case zeek         = "zeek"          // Network analysis framework (formerly Bro)
    case suricata     = "suricata"      // IDS/IPS — signature-based alerts
    case ngrep        = "ngrep"         // Pattern-based packet search
    case networkMiner = "networkMiner"  // Artifact extraction (via tshark dissectors on macOS)

    var displayName: String {
        switch self {
        case .tshark:       return "tshark"
        case .wireshark:    return "Wireshark"
        case .tcpdump:      return "tcpdump"
        case .zeek:         return "Zeek"
        case .suricata:     return "Suricata"
        case .ngrep:        return "ngrep"
        case .networkMiner: return "NetworkMiner"
        }
    }

    var symbol: String {
        switch self {
        case .tshark, .wireshark: return "waveform.path.ecg"
        case .tcpdump:            return "antenna.radiowaves.left.and.right"
        case .zeek:               return "eye.trianglebadge.exclamationmark"
        case .suricata:           return "exclamationmark.shield.fill"
        case .ngrep:              return "magnifyingglass.circle.fill"
        case .networkMiner:       return "externaldrive.badge.questionmark"
        }
    }

    var color: String {
        // Used in UI as named colors; map to Color in the view layer
        switch self {
        case .tshark, .wireshark: return "blue"
        case .tcpdump:            return "cyan"
        case .zeek:               return "purple"
        case .suricata:           return "red"
        case .ngrep:              return "orange"
        case .networkMiner:       return "green"
        }
    }
}

// MARK: - PacketEventCategory

enum PacketEventCategory: String, Codable, CaseIterable, Hashable, Sendable {
    case alert        = "alert"         // IDS/IPS signature hit (Suricata, Zeek notice)
    case connection   = "connection"    // TCP/UDP connection summary
    case dns          = "dns"           // DNS query or response
    case http         = "http"          // HTTP request or response
    case tls          = "tls"           // TLS handshake metadata
    case suspicious   = "suspicious"    // Anomaly detected (Zeek weird, payload match)
    case artifact     = "artifact"      // Extracted file, credential, or object
    case patternMatch = "pattern_match" // ngrep signature match

    var title: String {
        switch self {
        case .alert:        return "Alert"
        case .connection:   return "Connection"
        case .dns:          return "DNS"
        case .http:         return "HTTP"
        case .tls:          return "TLS"
        case .suspicious:   return "Suspicious"
        case .artifact:     return "Artifact"
        case .patternMatch: return "Pattern Match"
        }
    }

    var symbol: String {
        switch self {
        case .alert:        return "exclamationmark.triangle.fill"
        case .connection:   return "arrow.left.arrow.right"
        case .dns:          return "globe"
        case .http:         return "network"
        case .tls:          return "lock.fill"
        case .suspicious:   return "questionmark.diamond.fill"
        case .artifact:     return "doc.badge.gearshape"
        case .patternMatch: return "magnifyingglass"
        }
    }
}

// MARK: - PacketEvent

struct PacketEvent: Identifiable, Codable, Hashable, Sendable {
    let id: UUID
    let timestamp: Date
    let tool: PacketTool
    let category: PacketEventCategory
    let severity: Severity

    // Network context
    let sourceIP: String?
    let destinationIP: String?
    let sourcePort: Int?
    let destinationPort: Int?
    let proto: String?

    // Content
    let summary: String
    let detail: String?
    let rawPayload: String?

    // Tool-specific enrichment
    let signatureID: String?    // Suricata SID / Zeek notice type ID
    let signatureName: String?  // Alert/notice name
    let httpMethod: String?
    let httpURL: String?
    let dnsQuery: String?
    let tlsSubject: String?     // x509 subject
    let artifact: String?       // Extracted credential, file, or object label

    nonisolated init(
        id: UUID = UUID(),
        timestamp: Date = Date(),
        tool: PacketTool,
        category: PacketEventCategory,
        severity: Severity = .low,
        sourceIP: String? = nil,
        destinationIP: String? = nil,
        sourcePort: Int? = nil,
        destinationPort: Int? = nil,
        proto: String? = nil,
        summary: String,
        detail: String? = nil,
        rawPayload: String? = nil,
        signatureID: String? = nil,
        signatureName: String? = nil,
        httpMethod: String? = nil,
        httpURL: String? = nil,
        dnsQuery: String? = nil,
        tlsSubject: String? = nil,
        artifact: String? = nil
    ) {
        self.id = id
        self.timestamp = timestamp
        self.tool = tool
        self.category = category
        self.severity = severity
        self.sourceIP = sourceIP
        self.destinationIP = destinationIP
        self.sourcePort = sourcePort
        self.destinationPort = destinationPort
        self.proto = proto
        self.summary = summary
        self.detail = detail
        self.rawPayload = rawPayload
        self.signatureID = signatureID
        self.signatureName = signatureName
        self.httpMethod = httpMethod
        self.httpURL = httpURL
        self.dnsQuery = dnsQuery
        self.tlsSubject = tlsSubject
        self.artifact = artifact
    }

    /// Human-readable "src → dst" label.
    var connectionLabel: String {
        let src = [sourceIP, sourcePort.map(String.init)].compactMap { $0 }.joined(separator: ":")
        let dst = [destinationIP, destinationPort.map(String.init)].compactMap { $0 }.joined(separator: ":")
        if src.isEmpty && dst.isEmpty { return "Unknown" }
        if src.isEmpty { return "→ \(dst)" }
        if dst.isEmpty { return src }
        return "\(src) → \(dst)"
    }
}

// MARK: - ToolActivityState

/// Live runtime status for a single tool, published to the UI.
struct ToolActivityState: Sendable {
    var isRunning:   Bool    = false
    var isAvailable: Bool    = false
    var eventCount:  Int     = 0
    var lastRun:     Date?   = nil
    var statusText:  String  = "Idle"
}

// MARK: - ToolAvailability

struct ToolAvailability: Sendable {
    let tshark:   Bool  // brew install wireshark
    let tcpdump:  Bool  // built-in at /usr/sbin/tcpdump
    let zeek:     Bool  // brew install zeek
    let suricata: Bool  // brew install suricata (checked via EVE log presence)
    let ngrep:    Bool  // brew install ngrep

    var availableCount: Int {
        [tshark, tcpdump, zeek, suricata, ngrep].filter { $0 }.count
    }

    var missingInstalls: [(tool: String, command: String)] {
        var list: [(String, String)] = []
        if !tshark   { list.append(("tshark / Wireshark", "brew install --cask wireshark")) }
        if !zeek     { list.append(("Zeek",               "brew install zeek")) }
        if !suricata { list.append(("Suricata",           "brew install suricata")) }
        if !ngrep    { list.append(("ngrep",              "brew install ngrep")) }
        return list
    }
}
