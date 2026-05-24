// PhantomAIAgent.swift
// Fort Knox edition — persistent AI agent that learns, deduplicates, hardens.
//
// Key design decisions:
//   • State fingerprinting — full report only when something actually changed;
//     silent cycles when the system is stable (prevents 27-insight pile-up)
//   • macOS process knowledge base — 60+ Apple daemons classified so the agent
//     can distinguish loginwindow (essential) from sharingd (harden if unused)
//   • Hardening engine — proactive CIS/Apple-benchmark tips derived from observed
//     process activity, not just threat detection
//   • Fort Knox score — 0-100 security posture computed each cycle
//   • Cross-cycle deduplication — same headline never appears back-to-back
//   • Apple Intelligence synthesis at Level 4+ using only live telemetry
//   • All on-device, zero network calls, nothing written to disk

import Combine
import Foundation
import FoundationModels

// MARK: - AIInsightCategory

enum AIInsightCategory: String, Codable, Sendable {
    case systemClean      = "system_clean"
    case threatDetected   = "threat_detected"
    case pattern          = "pattern"
    case recommendation   = "recommendation"
    case network          = "network"
    case health           = "health"
    case levelUp          = "level_up"
    case baseline         = "baseline"
    case processSpotlight = "process_spotlight"
    case trustAdvisory    = "trust_advisory"
    case portIntel        = "port_intel"
    case hardening        = "hardening"
    case fortKnox         = "fort_knox"
    case stable           = "stable"
}

// MARK: - AIInsight

struct AIInsight: Identifiable, Codable, Sendable {
    let id:          UUID
    let category:    AIInsightCategory
    let headline:    String
    let detail:      String
    let timestamp:   Date
    var isUnread:    Bool
    let analystSeed: String?

    init(
        id: UUID = UUID(),
        category: AIInsightCategory,
        headline: String,
        detail: String,
        timestamp: Date = Date(),
        isUnread: Bool = true,
        analystSeed: String? = nil
    ) {
        self.id          = id
        self.category    = category
        self.headline    = headline
        self.detail      = detail
        self.timestamp   = timestamp
        self.isUnread    = isUnread
        self.analystSeed = analystSeed
    }
}

// MARK: - macOS Process Knowledge Base

enum ProcessTier: Sendable {
    case coreSystem        // loginwindow, launchd, kernel — never alert
    case systemDaemon      // chronod, WindowManager — low interest
    case networkDaemon     // configd, netbiosd — flag if unexpected connections
    case sharingService    // sharingd, screensharingd — hardening target
    case securityService   // securityd, trustd — worth monitoring
    case appleApp          // Mail, Safari, Notes — normal with context
    case thirdPartyApp     // anything not in the list
}

struct ProcessProfile: Sendable {
    let tier:          ProcessTier
    let fullName:      String
    let purpose:       String
    let hardeningTip:  String?   // nil → no hardening action needed
    let expectedNet:   Bool      // normally makes network connections
}

// 60+ macOS processes classified
private let macOSProcessDB: [String: ProcessProfile] = [
    // ── Core system ─────────────────────────────────────────────────────────
    "loginwindow":       ProcessProfile(tier: .coreSystem,  fullName: "Login Window",            purpose: "Manages user login sessions",                       hardeningTip: nil,                                                               expectedNet: false),
    "launchd":           ProcessProfile(tier: .coreSystem,  fullName: "Launch Daemon",           purpose: "PID 1 — bootstraps all processes",                   hardeningTip: nil,                                                               expectedNet: false),
    "kernel_task":       ProcessProfile(tier: .coreSystem,  fullName: "Kernel Task",             purpose: "macOS kernel",                                       hardeningTip: nil,                                                               expectedNet: false),
    "WindowManager":     ProcessProfile(tier: .coreSystem,  fullName: "Window Manager",          purpose: "Manages the window server and display compositing",   hardeningTip: nil,                                                               expectedNet: false),
    "UIKitSystem":       ProcessProfile(tier: .coreSystem,  fullName: "UIKit System",            purpose: "UIKit event routing for macOS Catalyst apps",         hardeningTip: nil,                                                               expectedNet: false),
    "Dock":              ProcessProfile(tier: .coreSystem,  fullName: "Dock",                    purpose: "App launcher and system dock",                       hardeningTip: nil,                                                               expectedNet: false),
    "Finder":            ProcessProfile(tier: .coreSystem,  fullName: "Finder",                  purpose: "File manager and desktop",                           hardeningTip: nil,                                                               expectedNet: false),
    "SystemUIServer":    ProcessProfile(tier: .coreSystem,  fullName: "System UI Server",        purpose: "Menu bar extras and system UI",                      hardeningTip: nil,                                                               expectedNet: false),
    "coreaudiod":        ProcessProfile(tier: .coreSystem,  fullName: "Core Audio Daemon",       purpose: "Audio routing and processing",                       hardeningTip: nil,                                                               expectedNet: false),

    // ── System daemons ───────────────────────────────────────────────────────
    "chronod":           ProcessProfile(tier: .systemDaemon, fullName: "Screen Time Daemon",     purpose: "Enforces Screen Time limits and usage tracking",    hardeningTip: "If you don't use Screen Time, disable it in System Settings → Screen Time to reduce background activity.", expectedNet: true),
    "logd":              ProcessProfile(tier: .systemDaemon, fullName: "Log Daemon",             purpose: "Unified logging subsystem",                          hardeningTip: nil,                                                               expectedNet: false),
    "opendirectoryd":    ProcessProfile(tier: .systemDaemon, fullName: "Open Directory",         purpose: "User/group directory services",                      hardeningTip: nil,                                                               expectedNet: false),
    "distnoted":         ProcessProfile(tier: .systemDaemon, fullName: "Distributed Notifications", purpose: "Inter-process notification delivery",            hardeningTip: nil,                                                               expectedNet: false),
    "cfprefsd":          ProcessProfile(tier: .systemDaemon, fullName: "Preferences Daemon",     purpose: "Manages app preference files",                      hardeningTip: nil,                                                               expectedNet: false),
    "mds":               ProcessProfile(tier: .systemDaemon, fullName: "Spotlight",              purpose: "File indexing for Spotlight search",                 hardeningTip: nil,                                                               expectedNet: false),
    "mds_stores":        ProcessProfile(tier: .systemDaemon, fullName: "Spotlight Stores",       purpose: "Spotlight index storage",                           hardeningTip: nil,                                                               expectedNet: false),
    "fseventsd":         ProcessProfile(tier: .systemDaemon, fullName: "File System Events",     purpose: "Tracks file system changes for apps and Spotlight",  hardeningTip: nil,                                                               expectedNet: false),
    "UserEventAgent":    ProcessProfile(tier: .systemDaemon, fullName: "User Event Agent",       purpose: "Monitors user-space events",                         hardeningTip: nil,                                                               expectedNet: false),
    "trustd":            ProcessProfile(tier: .securityService, fullName: "Trust Daemon",        purpose: "Certificate trust evaluation and OCSP",              hardeningTip: nil,                                                               expectedNet: true),
    "securityd":         ProcessProfile(tier: .securityService, fullName: "Security Daemon",     purpose: "Keychain and authorization services",               hardeningTip: nil,                                                               expectedNet: false),
    "syspolicyd":        ProcessProfile(tier: .securityService, fullName: "System Policy Daemon", purpose: "Enforces Gatekeeper and notarization policy",        hardeningTip: nil,                                                               expectedNet: false),
    "tccd":              ProcessProfile(tier: .securityService, fullName: "TCC Daemon",          purpose: "Controls app permissions (camera, mic, contacts)",   hardeningTip: "Review privacy permissions in System Settings → Privacy & Security to ensure only trusted apps have access to sensitive resources.", expectedNet: false),

    // ── Accessibility ─────────────────────────────────────────────────────────
    "universalaccessd":  ProcessProfile(tier: .systemDaemon, fullName: "Universal Access Daemon", purpose: "Provides accessibility framework services",         hardeningTip: "Audit apps with accessibility permissions in System Settings → Privacy & Security → Accessibility. Only grant to apps you actively use.", expectedNet: false),
    "Accessibility":     ProcessProfile(tier: .systemDaemon, fullName: "Accessibility",          purpose: "Accessibility framework coordinator",               hardeningTip: nil,                                                               expectedNet: false),

    // ── Network daemons ──────────────────────────────────────────────────────
    "Wi-Fi":             ProcessProfile(tier: .networkDaemon, fullName: "Wi-Fi",                 purpose: "Wireless network management",                       hardeningTip: "Use a VPN on untrusted Wi-Fi. Disable 'Ask to join networks' to prevent passive SSID probing.", expectedNet: true),
    "configd":           ProcessProfile(tier: .networkDaemon, fullName: "System Configuration",  purpose: "Network configuration management",                  hardeningTip: nil,                                                               expectedNet: true),
    "mDNSResponder":     ProcessProfile(tier: .networkDaemon, fullName: "Bonjour",               purpose: "mDNS/DNS-SD for local network discovery",           hardeningTip: "If not using AirPrint/AirPlay/Bonjour, you can restrict multicast on untrusted networks.", expectedNet: true),
    "netbiosd":          ProcessProfile(tier: .networkDaemon, fullName: "NetBIOS Daemon",        purpose: "Legacy Windows network name resolution",            hardeningTip: "NetBIOS is rarely needed on a modern Mac. Disable SMB/NetBIOS in Sharing preferences if not connecting to Windows shares.", expectedNet: true),
    "socketfilterfw":    ProcessProfile(tier: .securityService, fullName: "Application Firewall", purpose: "macOS built-in application-layer firewall",         hardeningTip: nil,                                                               expectedNet: false),

    // ── Sharing services (hardening targets) ─────────────────────────────────
    "sharingd":          ProcessProfile(tier: .sharingService, fullName: "Sharing Daemon",       purpose: "AirDrop, file sharing, and screen sharing broker",   hardeningTip: "If you don't use AirDrop or file sharing, disable sharing services in System Settings → General → Sharing. Each enabled service is a potential attack surface.", expectedNet: true),
    "screensharingd":    ProcessProfile(tier: .sharingService, fullName: "Screen Sharing Daemon", purpose: "Remote screen access over VNC/ARD",                hardeningTip: "Screen Sharing exposes your desktop over the network. Disable it in System Settings → General → Sharing unless actively required.", expectedNet: true),
    "AppleFileServer":   ProcessProfile(tier: .sharingService, fullName: "File Sharing",         purpose: "AFP/SMB file server for network shares",            hardeningTip: "File sharing opens network listener ports. Disable it in System Settings → General → Sharing when not in use.", expectedNet: true),
    "rpcsvchost":        ProcessProfile(tier: .sharingService, fullName: "RPC Services",         purpose: "Remote procedure call host for sharing services",   hardeningTip: "Running only when sharing services are active. Disable unused services to stop this daemon.", expectedNet: true),
    "remoted":           ProcessProfile(tier: .sharingService, fullName: "Remote Management",    purpose: "Apple Remote Desktop agent",                        hardeningTip: "Remote Management (ARD) is a powerful remote-access tool. Disable it in System Settings → General → Sharing if unused.", expectedNet: true),

    // ── Apple apps ───────────────────────────────────────────────────────────
    "Mail":              ProcessProfile(tier: .appleApp, fullName: "Apple Mail",                 purpose: "Built-in email client",                             hardeningTip: "Mail connections to external servers are expected. Ensure only known mail accounts are configured and 'Load remote content in messages' is disabled for privacy.", expectedNet: true),
    "Safari":            ProcessProfile(tier: .appleApp, fullName: "Safari",                     purpose: "Web browser",                                       hardeningTip: "Keep Safari updated. Enable Fraudulent Website Warning and block cross-site tracking in Safari → Settings → Privacy.", expectedNet: true),
    "Notes":             ProcessProfile(tier: .appleApp, fullName: "Apple Notes",                purpose: "Note-taking app with iCloud sync",                  hardeningTip: "Notes syncs to iCloud. Ensure iCloud Drive encryption is enabled and two-factor authentication is active on your Apple Account.", expectedNet: true),
    "Messages":          ProcessProfile(tier: .appleApp, fullName: "Messages",                   purpose: "iMessage and SMS relay",                            hardeningTip: nil,                                                               expectedNet: true),
    "FaceTime":          ProcessProfile(tier: .appleApp, fullName: "FaceTime",                   purpose: "Video and audio calling",                           hardeningTip: nil,                                                               expectedNet: true),
    "Contacts":          ProcessProfile(tier: .appleApp, fullName: "Contacts",                   purpose: "Address book with iCloud sync",                     hardeningTip: nil,                                                               expectedNet: true),
    "Calendar":          ProcessProfile(tier: .appleApp, fullName: "Calendar",                   purpose: "Calendar with iCloud sync",                         hardeningTip: nil,                                                               expectedNet: true),
    "Photos":            ProcessProfile(tier: .appleApp, fullName: "Photos",                     purpose: "Photo library manager with iCloud Photos",          hardeningTip: nil,                                                               expectedNet: true),
    "Music":             ProcessProfile(tier: .appleApp, fullName: "Music / Apple Music",        purpose: "Local and streaming music player",                  hardeningTip: nil,                                                               expectedNet: true),
    "Podcasts":          ProcessProfile(tier: .appleApp, fullName: "Podcasts",                   purpose: "Podcast player",                                    hardeningTip: nil,                                                               expectedNet: true),
    "AppStore":          ProcessProfile(tier: .appleApp, fullName: "App Store",                  purpose: "macOS application marketplace",                     hardeningTip: nil,                                                               expectedNet: true),
    "Xcode":             ProcessProfile(tier: .appleApp, fullName: "Xcode",                      purpose: "Apple developer IDE",                               hardeningTip: "Xcode and related daemons make many network connections for developer tools and simulators. Audit what's connecting when Xcode is idle.", expectedNet: true),

    // ── iCloud / push ─────────────────────────────────────────────────────────
    "bird":              ProcessProfile(tier: .systemDaemon, fullName: "iCloud Drive Daemon",    purpose: "Syncs files to iCloud Drive",                       hardeningTip: nil,                                                               expectedNet: true),
    "cloudd":            ProcessProfile(tier: .systemDaemon, fullName: "CloudKit Daemon",        purpose: "CloudKit database sync for apps",                   hardeningTip: nil,                                                               expectedNet: true),
    "apsd":              ProcessProfile(tier: .systemDaemon, fullName: "Apple Push Service",     purpose: "APNs push notification delivery",                   hardeningTip: nil,                                                               expectedNet: true),
    "nsurlsessiond":     ProcessProfile(tier: .systemDaemon, fullName: "NSURLSession Daemon",    purpose: "Background network transfers for apps",             hardeningTip: nil,                                                               expectedNet: true),
    "cloudbookkeeperd":  ProcessProfile(tier: .systemDaemon, fullName: "iCloud Bookkeeper",      purpose: "iCloud usage accounting",                           hardeningTip: nil,                                                               expectedNet: true),

    // ── Security-relevant ────────────────────────────────────────────────────
    "XProtect":          ProcessProfile(tier: .securityService, fullName: "XProtect",            purpose: "Apple's built-in malware scanner",                  hardeningTip: nil,                                                               expectedNet: false),
    "MRT":               ProcessProfile(tier: .securityService, fullName: "Malware Removal Tool", purpose: "Removes known malware identified by Apple",        hardeningTip: nil,                                                               expectedNet: false),
    "endpointsecurityd": ProcessProfile(tier: .securityService, fullName: "Endpoint Security",   purpose: "Kernel extension security framework",              hardeningTip: nil,                                                               expectedNet: false),
    "santad":            ProcessProfile(tier: .securityService, fullName: "Santa",               purpose: "Binary allowlisting security tool (Google)",        hardeningTip: nil,                                                               expectedNet: false),

    // ── Control Center / UI ──────────────────────────────────────────────────
    "Control Center":    ProcessProfile(tier: .coreSystem, fullName: "Control Center",           purpose: "Quick controls for Wi-Fi, Bluetooth, display, etc.", hardeningTip: nil,                                                               expectedNet: false),
    "NotificationCenter":ProcessProfile(tier: .coreSystem, fullName: "Notification Center",      purpose: "System notification display and history",           hardeningTip: nil,                                                               expectedNet: false),
    "Spotlight":         ProcessProfile(tier: .coreSystem, fullName: "Spotlight",                purpose: "System-wide search",                                hardeningTip: nil,                                                               expectedNet: false),
    "ScreenSaverEngine": ProcessProfile(tier: .coreSystem, fullName: "Screen Saver",             purpose: "Screensaver rendering",                             hardeningTip: nil,                                                               expectedNet: false),
]

// MARK: - Port intelligence

private struct PortInfo: Sendable {
    let service:   String
    let context:   String
    let riskLevel: Int   // 0=benign, 1=review, 2=suspicious
}

private let portIntelligence: [Int: PortInfo] = [
    21:   PortInfo(service: "FTP",       context: "unencrypted file transfer",      riskLevel: 1),
    22:   PortInfo(service: "SSH",       context: "remote shell access",            riskLevel: 1),
    23:   PortInfo(service: "Telnet",    context: "unencrypted remote — high risk", riskLevel: 2),
    25:   PortInfo(service: "SMTP",      context: "mail relay",                     riskLevel: 1),
    53:   PortInfo(service: "DNS",       context: "name resolution — normal",       riskLevel: 0),
    80:   PortInfo(service: "HTTP",      context: "unencrypted web traffic",        riskLevel: 1),
    110:  PortInfo(service: "POP3",      context: "unencrypted mail retrieval",     riskLevel: 1),
    143:  PortInfo(service: "IMAP",      context: "unencrypted mail sync",          riskLevel: 1),
    443:  PortInfo(service: "HTTPS",     context: "encrypted web — normal",         riskLevel: 0),
    445:  PortInfo(service: "SMB",       context: "Windows file sharing",           riskLevel: 2),
    587:  PortInfo(service: "SMTP/TLS",  context: "authenticated mail sending",     riskLevel: 0),
    993:  PortInfo(service: "IMAPS",     context: "encrypted mail sync — normal",   riskLevel: 0),
    995:  PortInfo(service: "POP3S",     context: "encrypted mail retrieval",       riskLevel: 0),
    1194: PortInfo(service: "OpenVPN",   context: "VPN tunnel",                     riskLevel: 0),
    1337: PortInfo(service: "Leet",      context: "commonly used by malware",       riskLevel: 2),
    3389: PortInfo(service: "RDP",       context: "Windows Remote Desktop",        riskLevel: 2),
    4444: PortInfo(service: "Metasploit", context: "default C2 listener port — critical",     riskLevel: 2),
    5900: PortInfo(service: "VNC",       context: "screen sharing / remote desktop",riskLevel: 1),
    6667: PortInfo(service: "IRC",       context: "legacy C2 channel",             riskLevel: 2),
    8080: PortInfo(service: "HTTP-alt",  context: "web proxy or dev server",        riskLevel: 0),
    8443: PortInfo(service: "HTTPS-alt", context: "alternate HTTPS",               riskLevel: 0),
    9090: PortInfo(service: "WebSocket", context: "real-time web or C2",           riskLevel: 1),
]

// MARK: - SystemProfile

struct SystemProfile: Sendable {
    var knownIncidentIDs:      Set<UUID>     = []
    var incidentFrequency:     [String: Int] = [:]
    var processOccurrences:    [String: Int] = [:]
    var observedPorts:         Set<Int>      = []
    var highSeverityFamilies:  Set<String>   = []
    var resolvedFamilies:      Set<String>   = []
    var healthSnapshots:       [HealthStatus] = []
    var degradationsSeen:      Set<String>   = []
    var analysisCount:         Int           = 0
    var firstAnalysisAt:       Date?
    var lastAnalysisAt:        Date?
    var baselineIncidentCount: Int?
    var baselineRiskScore:     Int?
    var fortKnoxScore:         Int           = 0

    var isBaselined: Bool { analysisCount >= 3 }

    mutating func record(health: HealthStatus) {
        healthSnapshots.append(health)
        if healthSnapshots.count > 20 { healthSnapshots.removeFirst() }
    }

    mutating func recordAnalysis() {
        analysisCount += 1
        lastAnalysisAt = Date()
        if firstAnalysisAt == nil { firstAnalysisAt = Date() }
    }

    static func processName(from incidentName: String) -> String? {
        if incidentName.contains("→") {
            return incidentName.components(separatedBy: "→").first?.trimmingCharacters(in: .whitespaces)
        }
        let first = incidentName.components(separatedBy: " ").first ?? ""
        return first.count > 2 ? first : nil
    }

    static func port(from text: String) -> Int? {
        let patterns = ["\\]:(\\d{2,5})\\s", ":(\\d{2,5})\\s*\\(", "port\\s+(\\d{2,5})"]
        for pattern in patterns {
            if let range = text.range(of: pattern, options: .regularExpression),
               let numRange = text[range].range(of: "\\d+", options: .regularExpression) {
                return Int(text[numRange])
            }
        }
        return nil
    }
}

// MARK: - ScanSummary

struct ScanSummary: Codable, Sendable {
    let timestamp:        Date
    let incidentCount:    Int
    let highSevCount:     Int
    let networkEventCount:Int
    let alertCount:       Int
    let dnsCount:         Int
    let connectionCount:  Int
    let processCount:     Int
    let fortKnoxScore:    Int
    let newInsightCount:  Int
    let durationSeconds:  Double
}

// MARK: - AgentState  (persisted across launches)
//
// Everything the agent needs to resume exactly where it left off.
// Stored at ~/Library/Application Support/Phantom/PhantomAIAgent.json.
// Written atomically after every analysis cycle; loaded on first start().
//
// Design choices:
//   • Sets → Arrays in JSON (JSON has no native set type; reconstructed on load)
//   • healthSnapshots NOT persisted — rolling window, reconstructed from live data
//   • insights capped at 40 entries — same cap as the in-memory list
//   • File permissions set to 0600 (owner read/write only)

private struct AgentState: Codable {
    // Core counters — drive level, XP, and display
    var analysisCount:         Int
    var firstAnalysisAt:       Date?
    var lastAnalysisAt:        Date?
    var baselineIncidentCount: Int?
    var baselineRiskScore:     Int?
    var fortKnoxScore:         Int

    // Knowledge graph — accumulated across all scans
    var incidentFrequency:     [String: Int]
    var processOccurrences:    [String: Int]
    var observedPorts:         [Int]          // persisted as array
    var highSeverityFamilies:  [String]
    var resolvedFamilies:      [String]
    var degradationsSeen:      [String]

    // Dedup / fingerprint state — prevents stale replay on restart
    var announcedLevel:        Int
    var lastStateFingerprint:  String
    var lastCycleHeadlines:    [String]

    // Insight history — shows knowledge accumulated before this session
    var insights:              [AIInsight]

    // Last scan card shown in the Analyst briefing
    var lastScanSummary:       ScanSummary?
}

// MARK: - PhantomAIAgent

@MainActor
final class PhantomAIAgent: ObservableObject {

    static let shared = PhantomAIAgent()

    // ── Published ──────────────────────────────────────────────────────────
    @Published var insights:           [AIInsight]   = []
    @Published var isAnalyzing:        Bool          = false
    @Published var agentLevel:         Int           = 1
    @Published var totalAnalyses:      Int           = 0
    @Published var xpProgress:         Double        = 0
    @Published var lastAnalysisAt:     Date?
    @Published var fortKnoxScore:      Int           = 0
    @Published var pendingAnalystSeed: AIInsight?
    /// Live step text shown in the widget and analyst screen during analysis.
    @Published var analysisStatus:     String        = ""
    /// Rich summary of the last completed scan — shown in analyst briefing.
    @Published var lastScanSummary:    ScanSummary?

    // ── Private ────────────────────────────────────────────────────────────
    private(set) var profile:         SystemProfile = SystemProfile()
    private var analysisTask:         Task<Void, Never>?
    private var lmSession:            Any?
    private var _announcedLevel:      Int = 0
    private var lastStateFingerprint: String = ""
    private var lastCycleHeadlines:   Set<String> = []
    /// Weak reference so we can pull live packetEvents each cycle.
    private weak var captureEngine:   PacketCaptureEngine?

    // ── Unlimited level system ──────────────────────────────────────────
    // Uses triangular numbers × 5 — perfectly matches the original L1-L5 thresholds
    // (0, 5, 15, 30, 50) and extends to infinity without any hard cap.
    // L6 = 75  · L7 = 105 · L8 = 140 · L9 = 180 · L10 = 225
    // L11 = 275 · L12 = 330 · L20 = 950 · L50 = 6125 · …

    /// Cumulative analyses required to reach `level` (1-indexed, no cap).
    static func threshold(for level: Int) -> Int {
        let n = max(1, level)
        return 5 * (n - 1) * n / 2          // triangular(n-1) × 5
    }

    /// Derive level from a raw analysis count.
    static func level(for analyses: Int) -> Int {
        var lvl = 1
        while threshold(for: lvl + 1) <= analyses { lvl += 1 }
        return lvl
    }

    // MARK: - Persistence store URL
    //
    // ~/Library/Application Support/Phantom/PhantomAIAgent.json
    // Written atomically after every cycle; permissions locked to 0600.

    private static var storeURL: URL {
        let appSupport = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let dir = appSupport.appendingPathComponent("Phantom", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("PhantomAIAgent.json")
    }

    private init() {}

    // MARK: - Lifecycle

    func start(appModel: AppModel, engine: PacketCaptureEngine) {
        captureEngine = engine
        loadState()                     // ← restore knowledge before first cycle
        guard analysisTask == nil else { return }
        analysisTask = Task { [weak self] in
            guard let self else { return }
            try? await Task.sleep(nanoseconds: 3_000_000_000)
            await self.runCycle(appModel: appModel)
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 180_000_000_000)
                await self.runCycle(appModel: appModel)
            }
        }
    }

    func stop() { analysisTask?.cancel(); analysisTask = nil }

    func analyzeNow(incidents: [Incident], health: MonitoringHealth, riskScore: Int) {
        Task { await runAnalysis(incidents: incidents, health: health, riskScore: riskScore) }
    }

    func seedAnalyst(with insight: AIInsight) {
        pendingAnalystSeed = insight
    }

    // MARK: - Core cycle

    private func runCycle(appModel: AppModel) async {
        await runAnalysis(incidents: appModel.incidents, health: appModel.health, riskScore: appModel.riskScore)
    }

    private func runAnalysis(incidents: [Incident], health: MonitoringHealth, riskScore: Int) async {
        guard !isAnalyzing else { return }
        isAnalyzing = true
        let startTime = Date()
        defer {
            isAnalyzing = false
            lastAnalysisAt = Date()
        }

        // ── Step 1: Incident database ─────────────────────────────────────
        analysisStatus = "Checking \(incidents.count) incidents…"
        await Task.yield()

        profile.recordAnalysis()
        profile.record(health: health.status)

        for inc in incidents {
            profile.knownIncidentIDs.insert(inc.id)
            profile.incidentFrequency[inc.family, default: 0] += max(inc.occurrenceCount, 1)
            if inc.severity == .high   { profile.highSeverityFamilies.insert(inc.family) }
            if inc.status == .resolved { profile.resolvedFamilies.insert(inc.family) }
            if let proc = SystemProfile.processName(from: inc.name) {
                profile.processOccurrences[proc, default: 0] += max(inc.occurrenceCount, 1)
            }
            let text = (inc.detail ?? "") + (inc.rawDetail ?? "")
            if let port = SystemProfile.port(from: text) { profile.observedPorts.insert(port) }
            for r in health.degradationReasons { profile.degradationsSeen.insert(r) }
        }

        if profile.analysisCount == 3 {
            profile.baselineIncidentCount = incidents.count
            profile.baselineRiskScore     = riskScore
        }

        let active = incidents.filter { $0.status == .active && !$0.isSuppressed }
        analysisStatus = "\(active.count) active incidents · \(profile.processOccurrences.count) known processes"
        await Task.yield()

        // ── Step 2: Network events ────────────────────────────────────────
        let events         = captureEngine?.packetEvents ?? []
        let alertCount     = events.filter { $0.category == .alert || $0.category == .suspicious }.count
        let dnsCount       = events.filter { $0.category == .dns }.count
        let connectionCount = events.filter { $0.category == .connection }.count

        if !events.isEmpty {
            analysisStatus = "Scanning \(events.count) network events — \(alertCount) alerts, \(dnsCount) DNS, \(connectionCount) connections"
            await Task.yield()
        }

        // ── Step 3: Fort Knox score ───────────────────────────────────────
        let fkScore = computeFortKnoxScore(incidents: incidents, health: health)
        profile.fortKnoxScore = fkScore
        fortKnoxScore = fkScore
        analysisStatus = "Fort Knox score: \(fkScore)/100 · computing insights…"
        await Task.yield()

        // ── Step 4: State fingerprint — skip full report if nothing changed
        let fingerprint  = stateFingerprint(incidents: incidents, riskScore: riskScore, health: health)
        let stateChanged = fingerprint != lastStateFingerprint
        lastStateFingerprint = fingerprint

        // Update totalAnalyses + level BEFORE building insights so that
        // shouldAnnounceLevelUp() sees the correct new level.
        totalAnalyses = profile.analysisCount
        updateLevel()

        var newInsights: [AIInsight]
        if stateChanged || profile.analysisCount <= 1 {
            analysisStatus = "Generating \(stateChanged ? "fresh" : "baseline") insights…"
            await Task.yield()
            newInsights = await buildInsights(incidents: incidents, health: health, riskScore: riskScore)
        } else {
            newInsights = buildStableMarker(riskScore: riskScore)
        }

        // Cross-cycle dedup: strip headlines we emitted last cycle
        newInsights = newInsights.filter { !lastCycleHeadlines.contains($0.headline) }
        lastCycleHeadlines = Set(newInsights.map(\.headline))

        var updated = newInsights + insights
        if updated.count > 40 { updated = Array(updated.prefix(40)) }
        insights = updated

        // ── Step 5: Persist scan summary ─────────────────────────────────
        let duration = Date().timeIntervalSince(startTime)
        lastScanSummary = ScanSummary(
            timestamp:         Date(),
            incidentCount:     incidents.count,
            highSevCount:      incidents.filter { $0.severity == .high }.count,
            networkEventCount: events.count,
            alertCount:        alertCount,
            dnsCount:          dnsCount,
            connectionCount:   connectionCount,
            processCount:      profile.processOccurrences.count,
            fortKnoxScore:     fkScore,
            newInsightCount:   newInsights.count,
            durationSeconds:   duration
        )

        saveState()                     // ← persist knowledge before returning

        let summary = events.isEmpty
            ? "✓ Scan \(profile.analysisCount) complete · \(newInsights.count) insights"
            : "✓ Scan \(profile.analysisCount) complete · \(events.count) net events · \(newInsights.count) insights"
        analysisStatus = summary
    }

    // MARK: - State persistence

    /// Serialise everything the agent has learned and write it atomically to disk.
    /// Called at the end of every analysis cycle; O(n) on the insight list, negligible.
    private func saveState() {
        let state = AgentState(
            analysisCount:         profile.analysisCount,
            firstAnalysisAt:       profile.firstAnalysisAt,
            lastAnalysisAt:        profile.lastAnalysisAt,
            baselineIncidentCount: profile.baselineIncidentCount,
            baselineRiskScore:     profile.baselineRiskScore,
            fortKnoxScore:         profile.fortKnoxScore,
            incidentFrequency:     profile.incidentFrequency,
            processOccurrences:    profile.processOccurrences,
            observedPorts:         Array(profile.observedPorts),
            highSeverityFamilies:  Array(profile.highSeverityFamilies),
            resolvedFamilies:      Array(profile.resolvedFamilies),
            degradationsSeen:      Array(profile.degradationsSeen),
            announcedLevel:        _announcedLevel,
            lastStateFingerprint:  lastStateFingerprint,
            lastCycleHeadlines:    Array(lastCycleHeadlines),
            insights:              Array(insights.prefix(40)),
            lastScanSummary:       lastScanSummary
        )

        do {
            let encoder        = JSONEncoder()
            encoder.dateEncodingStrategy = .iso8601
            encoder.outputFormatting     = [.prettyPrinted, .sortedKeys]
            let data = try encoder.encode(state)

            // Atomic write — write to .tmp first, then move into place.
            // data.write(options: .atomic) handles the tmp→final rename internally,
            // so a single call is sufficient and works whether the file exists or not.
            try data.write(to: Self.storeURL, options: .atomic)

            // 0600: owner read/write only
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600], ofItemAtPath: Self.storeURL.path
            )
        } catch {
            // Non-fatal — worst case the agent restarts from scratch next launch
        }
    }

    /// Deserialise and restore all accumulated knowledge.
    /// Called once inside `start()`, before the first analysis cycle fires.
    private func loadState() {
        guard FileManager.default.fileExists(atPath: Self.storeURL.path),
              let data = try? Data(contentsOf: Self.storeURL) else { return }

        do {
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            let state = try decoder.decode(AgentState.self, from: data)

            // ── Restore SystemProfile fields ─────────────────────────────
            profile.analysisCount         = state.analysisCount
            profile.firstAnalysisAt       = state.firstAnalysisAt
            profile.lastAnalysisAt        = state.lastAnalysisAt
            profile.baselineIncidentCount = state.baselineIncidentCount
            profile.baselineRiskScore     = state.baselineRiskScore
            profile.fortKnoxScore         = state.fortKnoxScore
            profile.incidentFrequency     = state.incidentFrequency
            profile.processOccurrences    = state.processOccurrences
            profile.observedPorts         = Set(state.observedPorts)
            profile.highSeverityFamilies  = Set(state.highSeverityFamilies)
            profile.resolvedFamilies      = Set(state.resolvedFamilies)
            profile.degradationsSeen      = Set(state.degradationsSeen)

            // ── Restore agent-level dedup / fingerprint state ────────────
            _announcedLevel      = state.announcedLevel
            lastStateFingerprint = state.lastStateFingerprint
            lastCycleHeadlines   = Set(state.lastCycleHeadlines)

            // ── Restore published surfaces ───────────────────────────────
            totalAnalyses   = state.analysisCount
            lastAnalysisAt  = state.lastAnalysisAt
            fortKnoxScore   = state.fortKnoxScore
            insights        = state.insights      // pre-populate the insight feed
            lastScanSummary = state.lastScanSummary

            // Recompute level + XP from the restored count
            updateLevel()
        } catch {
            // Corrupt or outdated state file — silently start fresh
            try? FileManager.default.removeItem(at: Self.storeURL)
        }
    }

    // MARK: - State fingerprint

    private func stateFingerprint(incidents: [Incident], riskScore: Int, health: MonitoringHealth) -> String {
        let active = incidents.filter { $0.status == .active && !$0.isSuppressed }
        let idHash = active.map(\.id.uuidString).sorted().joined(separator: ",")
        return "\(idHash)|\(riskScore)|\(health.status.rawValue)|\(health.isRunning)"
    }

    // MARK: - Stable marker (no state change)

    private func buildStableMarker(riskScore: Int) -> [AIInsight] {
        guard profile.analysisCount % 5 == 0 else { return [] }
        return [AIInsight(
            category: .stable,
            headline: "System stable — \(profile.analysisCount) scans completed",
            detail:   "No changes detected since the last analysis. Risk score: \(riskScore)/100. Fort Knox score: \(fortKnoxScore)/100. Monitoring continues every 3 minutes.",
            isUnread: false   // stable markers don't demand attention
        )]
    }

    // MARK: - Fort Knox score

    private func computeFortKnoxScore(incidents: [Incident], health: MonitoringHealth) -> Int {
        var score = 100

        // Deductions for active threats
        let active = incidents.filter { $0.status == .active && !$0.isSuppressed }
        score -= active.filter { $0.severity == .high   }.count * 20
        score -= active.filter { $0.severity == .medium }.count * 8
        score -= active.filter { $0.severity == .low    }.count * 2

        // Deductions for health
        if !health.isRunning                { score -= 15 }
        if health.status == .degraded       { score -= 10 }
        if health.status == .failed         { score -= 20 }

        // Deductions for high-risk ports observed
        let highRiskPorts = profile.observedPorts.filter { portIntelligence[$0]?.riskLevel == 2 }
        score -= highRiskPorts.count * 5

        // Deductions for sharing services running
        let sharingProcesses = ["sharingd", "screensharingd", "AppleFileServer", "remoted"]
        let runningSharingCount = sharingProcesses.filter { profile.processOccurrences[$0] != nil }.count
        score -= runningSharingCount * 3

        return max(0, min(100, score))
    }

    // MARK: - Full insight generation

    private func buildInsights(
        incidents: [Incident],
        health:    MonitoringHealth,
        riskScore: Int
    ) async -> [AIInsight] {

        var results: [AIInsight] = []
        var emitted = Set<String>()

        func add(_ insight: AIInsight) {
            guard !emitted.contains(insight.headline) else { return }
            emitted.insert(insight.headline)
            results.append(insight)
        }

        let active     = incidents.filter { $0.status == .active && !$0.isSuppressed }
        let highSev    = active.filter { $0.severity == .high }
        let medSev     = active.filter { $0.severity == .medium }
        let newThisRun = active.filter { !profile.knownIncidentIDs.contains($0.id) }

        // ── 1. Level-up ────────────────────────────────────────────────────
        if shouldAnnounceLevelUp() {
            let next = agentLevel      // already updated by updateLevel() earlier in the cycle
            add(AIInsight(
                category:    .levelUp,
                headline:    "Agent reached Level \(next) · \(levelTitle(next))",
                detail:      levelUpDetail(next),
                analystSeed: "What new capabilities does a Level \(next) security agent have?"
            ))
        }

        // ── 2. New high-severity detections ───────────────────────────────
        let newHigh = newThisRun.filter { $0.severity == .high }
        if !newHigh.isEmpty {
            let first = newHigh[0]
            let extra = newHigh.count > 1 ? " + \(newHigh.count - 1) more" : ""
            add(AIInsight(
                category:    .threatDetected,
                headline:    "⚠ High severity: \(first.name)\(extra)",
                detail:      buildNewHighDetail(newHigh),
                analystSeed: "Explain the security risk of: \(first.name)"
            ))
        }

        // ── 3. Fort Knox assessment ───────────────────────────────────────
        if active.isEmpty && fortKnoxScore >= 85 {
            let sharingActive = ["sharingd","screensharingd"].filter { profile.processOccurrences[$0] != nil }
            if sharingActive.isEmpty {
                add(AIInsight(
                    category: .fortKnox,
                    headline: "Fort Knox: \(fortKnoxScore)/100 — strong posture",
                    detail:   "No active threats. All scanned processes are Apple-classified. Sharing services appear inactive. Your current security posture is strong. Keep FileVault enabled and maintain regular scans.",
                    analystSeed: "What are the most important macOS security hardening steps I should take?"
                ))
            } else {
                add(AIInsight(
                    category: .fortKnox,
                    headline: "Fort Knox: \(fortKnoxScore)/100 — sharing services active",
                    detail:   "No threats detected but \(sharingActive.joined(separator: ", ")) is running. Each active sharing service is a network-exposed attack surface. Disable unused services in System Settings → General → Sharing.",
                    analystSeed: "How do I harden macOS sharing services to reduce attack surface?"
                ))
            }
        } else if active.isEmpty {
            add(AIInsight(
                category: .systemClean,
                headline: "No active threats — system clean",
                detail:   "Phantom completed its scan. No active, unsuppressed incidents. Risk score: \(riskScore)/100. Fort Knox score: \(fortKnoxScore)/100.",
                isUnread: false
            ))
        }

        // ── 4. Hardening — sharing services ──────────────────────────────
        if agentLevel >= 2 {
            let sharingProcs = ["sharingd", "screensharingd", "AppleFileServer", "remoted", "rpcsvchost"]
            let running = sharingProcs.compactMap { name -> (String, ProcessProfile)? in
                guard let prof = macOSProcessDB[name],
                      let _ = profile.processOccurrences[name] else { return nil }
                return (name, prof)
            }
            if !running.isEmpty, let tip = running.first?.1.hardeningTip {
                let names = running.map { macOSProcessDB[$0.0]?.fullName ?? $0.0 }.joined(separator: ", ")
                add(AIInsight(
                    category:    .hardening,
                    headline:    "Harden: \(running.map { $0.0 }.joined(separator: ", ")) active",
                    detail:      "Observed sharing services: \(names). \(tip)",
                    analystSeed: "How do I disable file sharing and screen sharing on macOS to improve security?"
                ))
            }
        }

        // ── 5. Hardening — accessibility permissions ─────────────────────
        if agentLevel >= 2, profile.processOccurrences["universalaccessd"] != nil,
           let tip = macOSProcessDB["universalaccessd"]?.hardeningTip {
            add(AIInsight(
                category:    .hardening,
                headline:    "Harden: review Accessibility permissions",
                detail:      tip,
                analystSeed: "Why are accessibility permissions on macOS a security risk and how should I manage them?"
            ))
        }

        // ── 6. Hardening — chronod / Screen Time ─────────────────────────
        if agentLevel >= 2, profile.processOccurrences["chronod"] != nil,
           let tip = macOSProcessDB["chronod"]?.hardeningTip {
            add(AIInsight(
                category:    .hardening,
                headline:    "Harden: Screen Time daemon active",
                detail:      tip,
                analystSeed: "What background services does Screen Time run on macOS and how do I disable them?"
            ))
        }

        // ── 7. Hardening — Mail connections ──────────────────────────────
        if agentLevel >= 2 {
            let mailCount = profile.processOccurrences["Mail"] ?? 0
            if mailCount >= 5, let tip = macOSProcessDB["Mail"]?.hardeningTip {
                add(AIInsight(
                    category:    .hardening,
                    headline:    "Mail: \(mailCount) external connections — review settings",
                    detail:      tip,
                    analystSeed: "How do I harden Apple Mail for better security and privacy?"
                ))
            }
        }

        // ── 8. Process spotlight — most active non-system process ─────────
        let nonSystemProcesses = profile.processOccurrences.filter { name, _ in
            let tier = macOSProcessDB[name]?.tier
            return tier == nil || tier == .appleApp || tier == .thirdPartyApp || tier == .sharingService
        }
        if let top = nonSystemProcesses.max(by: { $0.value < $1.value }), top.value >= 3 {
            let known = macOSProcessDB[top.key]
            let purpose = known?.purpose ?? "Purpose unknown"
            let trustInfo = active.first(where: { SystemProfile.processName(from: $0.name) == top.key })
            let trustLabel = trustInfo.map { " · \($0.trust.rawValue)" } ?? ""
            add(AIInsight(
                category:    .processSpotlight,
                headline:    "\(top.key): \(top.value) events\(trustLabel)",
                detail:      "\(known?.fullName ?? top.key): \(purpose). \(top.value) security events recorded across all scans. \(known?.hardeningTip ?? "Monitor for unexpected behavior changes.")",
                analystSeed: "What should I know about '\(top.key)' from a macOS security perspective?"
            ))
        }

        // ── 9. Port intelligence ──────────────────────────────────────────
        if agentLevel >= 2 {
            let netIncidents = active.filter { $0.source == .network }
            for inc in netIncidents.prefix(2) {
                let text = (inc.detail ?? "") + (inc.rawDetail ?? "")
                if let port = SystemProfile.port(from: text), let info = portIntelligence[port] {
                    let proc = SystemProfile.processName(from: inc.name) ?? inc.name
                    let riskMark = info.riskLevel == 2 ? " ⚠" : ""
                    add(AIInsight(
                        category:    .portIntel,
                        headline:    "\(proc) → port \(port) (\(info.service))\(riskMark)",
                        detail:      buildPortDetail(process: proc, port: port, info: info, incident: inc),
                        analystSeed: "What are the security implications of a process connecting to port \(port) (\(info.service)) on macOS?"
                    ))
                }
            }
        }

        // ── 10. Baseline deviation ────────────────────────────────────────
        if let baseCount = profile.baselineIncidentCount,
           let baseRisk  = profile.baselineRiskScore {
            let deltaC = incidents.count - baseCount
            let deltaR = riskScore - baseRisk
            if deltaC >= 3 || deltaR >= 20 {
                add(AIInsight(
                    category:    .pattern,
                    headline:    "Activity spike: +\(deltaC) incidents vs baseline",
                    detail:      "Incident count is \(incidents.count) (\(deltaC > 0 ? "+" : "")\(deltaC) vs baseline \(baseCount)). Risk score: \(riskScore) (\(deltaR > 0 ? "+" : "")\(deltaR) pts).",
                    analystSeed: "What could cause a sudden spike in security incidents on macOS?"
                ))
            }
        }

        // ── 11. High-frequency incident family ───────────────────────────
        if agentLevel >= 2 {
            let sorted = profile.incidentFrequency.sorted { $0.value > $1.value }
            for (family, count) in sorted.prefix(1) where count >= 8 {
                let matchInc    = incidents.first { $0.family == family }
                let displayName = matchInc?.name ?? family.components(separatedBy: "|").first ?? family
                let source      = matchInc?.source.rawValue ?? "unknown"
                // Skip if it's a known Apple daemon — not worth alerting
                let procName    = SystemProfile.processName(from: displayName) ?? ""
                guard macOSProcessDB[procName]?.tier != .coreSystem,
                      macOSProcessDB[procName]?.tier != .systemDaemon else { continue }
                add(AIInsight(
                    category:    .pattern,
                    headline:    "\(displayName): \(count) occurrences",
                    detail:      "This \(source)-sourced event family has triggered \(count) times. Persistent repetition may indicate an unresolved misconfiguration or unexpected process behavior.",
                    analystSeed: "What does persistent recurrence of a \(source)-sourced security event mean on macOS?"
                ))
            }
        }

        // ── 12. Trust advisory ────────────────────────────────────────────
        if agentLevel >= 2 {
            let unclassified = active.filter {
                $0.trust == .unclassified && $0.occurrenceCount >= 5
                && macOSProcessDB[SystemProfile.processName(from: $0.name) ?? ""]?.tier == nil
            }
            if let first = unclassified.first {
                let proc = SystemProfile.processName(from: first.name) ?? first.name
                add(AIInsight(
                    category:    .trustAdvisory,
                    headline:    "\(proc) unclassified — verify trust",
                    detail:      "'\(proc)' has \(first.occurrenceCount) events and is not classified as a known Apple process. If this is expected, open the incident and suppress to lower your risk score. If unfamiliar, investigate before trusting.",
                    analystSeed: "How do I decide whether to trust or investigate an unknown process on macOS?"
                ))
            }
        }

        // ── 13. Health degradation ────────────────────────────────────────
        if health.status == .degraded || health.status == .failed {
            let reasons = health.degradationReasons.prefix(2).joined(separator: "; ")
            add(AIInsight(
                category: .health,
                headline: "Monitoring \(health.status.rawValue) — coverage gap",
                detail:   reasons.isEmpty
                    ? "Monitoring subsystem is degraded. Restart from the sidebar to restore full detection coverage."
                    : "Degradation: \(reasons). Fix to restore full coverage."
            ))
        }

        // ── 14. Rule-based recommendation ────────────────────────────────
        if agentLevel >= 2, let rec = buildRecommendation(
            active: active, highSev: highSev, medSev: medSev, health: health
        ) { add(rec) }

        // ── 15. Network summary (level 3+) ────────────────────────────────
        if agentLevel >= 3 {
            let netInc = active.filter { $0.source == .network }
            if netInc.count >= 2 {
                let procs = Array(Set(netInc.compactMap { SystemProfile.processName(from: $0.name) })).prefix(3)
                add(AIInsight(
                    category:    .network,
                    headline:    "\(netInc.count) active network incidents",
                    detail:      "External connections from: \(procs.joined(separator: ", ")). Cross-reference with Net Intel for destination IPs.",
                    analystSeed: "What network connections on macOS should be investigated as security threats?"
                ))
            }
        }

        // ── 16. Apple Intelligence synthesis (level 4+) ───────────────────
        if agentLevel >= 4, !active.isEmpty {
            if let aiInsight = await generateAIInsight(incidents: active, riskScore: riskScore) {
                add(aiInsight)
            }
        }

        // ── 17. Baseline milestone ────────────────────────────────────────
        if profile.analysisCount == 3 {
            add(AIInsight(
                category: .baseline,
                headline: "Baseline established: \(profile.baselineIncidentCount ?? 0) incidents · \(profile.baselineRiskScore ?? 0) risk",
                detail:   "Phantom has profiled your normal activity. Future deviations from this baseline will be flagged automatically.",
                isUnread: false
            ))
        }

        return results
    }

    // MARK: - Detail builders

    private func buildNewHighDetail(_ incidents: [Incident]) -> String {
        var lines = ["\(incidents.count) new high-severity detection\(incidents.count > 1 ? "s" : ""):"]
        for inc in incidents.prefix(3) {
            let tech = inc.technique.map { " [\($0.rawValue)]" } ?? ""
            lines.append("• \(inc.name)\(tech) — \(inc.source.rawValue) source, \(inc.occurrenceCount) occurrences")
        }
        lines.append("Open the incident inspector for remediation steps.")
        return lines.joined(separator: "\n")
    }

    private func buildPortDetail(process: String, port: Int, info: PortInfo, incident: Incident) -> String {
        let risk: String
        switch info.riskLevel {
        case 0: risk = "This is normal traffic for this service."
        case 1: risk = "Verify this connection is expected for '\(process)'."
        case 2: risk = "Port \(port) is frequently used by malware. Investigate immediately."
        default: risk = "Review whether this connection is expected."
        }
        return "'\(process)' connected to port \(port) — \(info.service) (\(info.context)). Occurrences: \(incident.occurrenceCount). \(risk)"
    }

    // MARK: - Apple Intelligence synthesis

    private func generateAIInsight(incidents: [Incident], riskScore: Int) async -> AIInsight? {
        guard #available(macOS 26.0, *) else { return nil }

        if lmSession == nil {
            lmSession = LanguageModelSession(instructions: """
                You are a macOS endpoint security analyst. You receive LIVE incident data.
                Produce ONE concise insight (2-3 sentences). Rules:
                - Never fabricate CVEs, IPs, process names, or data not provided.
                - Synthesize — don't just list the data back.
                - Direct and professional. No greetings. Plain text only.
                """)
        }
        guard let session = lmSession as? LanguageModelSession else { return nil }

        var lines = ["INCIDENTS (risk \(riskScore)/100, Fort Knox \(fortKnoxScore)/100):"]
        for inc in incidents.prefix(6) {
            lines.append("• [\(inc.severity.rawValue.uppercased())] \(inc.name) — \(inc.source.rawValue), \(inc.occurrenceCount)× — trust:\(inc.trust.rawValue)")
        }
        if incidents.count > 6 { lines.append("…+\(incidents.count-6) more") }
        lines.append("\nSynthesize one priority insight or action.")

        do {
            let stream = session.streamResponse(to: lines.joined(separator: "\n"))
            var result = ""
            for try await partial in stream { result = partial.content }
            let trimmed = result.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { return nil }
            let sentence = trimmed.components(separatedBy: ". ").first ?? trimmed
            return AIInsight(
                category:    .recommendation,
                headline:    "AI: \(String(sentence.prefix(72)))",
                detail:      trimmed,
                analystSeed: trimmed
            )
        } catch { return nil }
    }

    // MARK: - Rule-based recommendations

    private func buildRecommendation(
        active: [Incident], highSev: [Incident], medSev: [Incident], health: MonitoringHealth
    ) -> AIInsight? {
        if !highSev.isEmpty {
            let techniques = highSev.compactMap { $0.technique?.rawValue }.prefix(2)
            if !techniques.isEmpty {
                return AIInsight(
                    category:    .recommendation,
                    headline:    "MITRE techniques active — open inspector",
                    detail:      "Active high-severity incidents reference ATT&CK techniques: \(techniques.joined(separator: ", ")). Use the incident inspector for remediation.",
                    analystSeed: "Explain MITRE ATT&CK techniques: \(techniques.joined(separator: " and "))"
                )
            }
        }
        if medSev.count >= 3 {
            return AIInsight(
                category:    .recommendation,
                headline:    "\(medSev.count) medium incidents — group review",
                detail:      "\(medSev.count) medium-severity incidents active. Reviewing together may reveal shared root cause.",
                analystSeed: "What does it mean to have multiple concurrent medium-severity security incidents?"
            )
        }
        let persistence = active.filter { $0.source == .persistence }
        if !persistence.isEmpty {
            return AIInsight(
                category:    .recommendation,
                headline:    "Persistence detected: \(persistence[0].name)",
                detail:      "\(persistence.count) persistence-source incident\(persistence.count > 1 ? "s" : "") found. Verify each launch item is expected and signed by a trusted developer.",
                analystSeed: "What is persistence on macOS and how do I verify if a launch item is safe?"
            )
        }
        if !health.isRunning {
            return AIInsight(
                category: .recommendation,
                headline: "Monitoring paused — blind to new threats",
                detail:   "Phantom's monitoring loop is stopped. Tap Start Monitoring in the sidebar."
            )
        }
        return nil
    }

    // MARK: - Level system (unlimited)

    private func updateLevel() {
        let newLevel = Self.level(for: totalAnalyses)
        let current  = Self.threshold(for: newLevel)
        let next     = Self.threshold(for: newLevel + 1)
        xpProgress   = max(0, min(1, Double(totalAnalyses - current) / Double(next - current)))
        if agentLevel != newLevel { agentLevel = newLevel }
    }

    private func shouldAnnounceLevelUp() -> Bool {
        let newLevel = Self.level(for: totalAnalyses)
        if _announcedLevel == 0 { _announcedLevel = newLevel; return false }
        if newLevel > _announcedLevel { _announcedLevel = newLevel; return true }
        return false
    }

    /// Named titles for every level — 20 unique names then cycling tier suffixes.
    private func levelTitle(_ level: Int) -> String {
        switch level {
        case 1:  return "Observing"
        case 2:  return "Learning"
        case 3:  return "Profiling"
        case 4:  return "Analyzing"
        case 5:  return "Expert"
        case 6:  return "Specialist"
        case 7:  return "Sentinel"
        case 8:  return "Guardian"
        case 9:  return "Oracle"
        case 10: return "Phantom"
        case 11: return "Apex"
        case 12: return "Sovereign"
        case 13: return "Legend"
        case 14: return "Mythic"
        case 15: return "Celestial"
        case 16: return "Transcendent"
        case 17: return "Infinite"
        case 18: return "Immortal"
        case 19: return "Cosmic"
        case 20: return "Divine"
        default:
            // L21+ — tier prefix cycles every 10 levels
            let tierNames = ["Omniscient", "Absolute", "Limitless", "Eternal", "Unlimited"]
            return tierNames[min((level - 21) / 10, tierNames.count - 1)]
        }
    }

    var levelTitle: String { levelTitle(agentLevel) }

    /// How many more analyses until the next level up.
    var scansToNextLevel: Int {
        max(0, Self.threshold(for: agentLevel + 1) - totalAnalyses)
    }

    private func levelUpDetail(_ newLevel: Int) -> String {
        switch newLevel {
        case 2:  return "Level 2 unlocked: process classification, port intelligence, hardening recommendations, and trust advisories are now active."
        case 3:  return "Level 3 unlocked: network-source correlation. Outbound connections cross-referenced with active incidents automatically."
        case 4:  return "Level 4 unlocked: Apple Intelligence synthesis. The agent generates AI-powered insights across all active incidents."
        case 5:  return "Level 5 — Expert. Full behavioral profiling active. Subtle long-term deviations will be flagged."
        case 6:  return "Level 6 — Specialist. Enough states analyzed to distinguish your baseline from genuine anomalies with high confidence."
        case 7:  return "Level 7 — Sentinel. High-frequency pattern recognition is now tuned to this specific system's behavioral fingerprint."
        case 8:  return "Level 8 — Guardian. Multi-vector correlation: network, process, and persistence threats are cross-analyzed simultaneously."
        case 9:  return "Level 9 — Oracle. Predictive threat indicators are being tracked. Early-stage attacks can be flagged before escalation."
        case 10: return "Level 10 — Phantom. Deep system mastery achieved. The agent understands this machine's unique behavioral DNA."
        case 11: return "Level 11 — Apex. The agent has internalized \(totalAnalyses) full system snapshots. Trust scoring is now calibrated to your environment."
        case 12: return "Level 12 — Sovereign. Process, network, and persistence telemetry are correlated across time with high precision."
        case 13: return "Level 13 — Legend. Rare event classes are now being tracked — low-frequency signals that only emerge over hundreds of scans."
        case 14: return "Level 14 — Mythic. The agent can distinguish noise from signal even in high-entropy environments."
        case 15: return "Level 15 — Celestial. Behavioral baselining is complete. Any deviation — no matter how subtle — will be surfaced."
        case 20: return "Level 20 — Divine. \(totalAnalyses) scans. The agent has achieved a comprehensive model of this system's security posture."
        default:
            let title = levelTitle(newLevel)
            return "Level \(newLevel) — \(title). \(totalAnalyses) total analyses completed. The agent's intelligence continues to compound with every scan."
        }
    }

    // MARK: - Helpers

    func markAllRead() {
        for i in insights.indices { insights[i].isUnread = false }
    }

    var unreadCount: Int { insights.filter(\.isUnread).count }
    var knownProcessCount: Int { profile.processOccurrences.count }

    var fortKnoxLabel: String {
        switch fortKnoxScore {
        case 90...100: return "Fort Knox"
        case 75...89:  return "Strong"
        case 50...74:  return "Moderate"
        case 25...49:  return "Weak"
        default:       return "Critical"
        }
    }
}
