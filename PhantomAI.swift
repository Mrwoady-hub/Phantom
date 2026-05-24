// PhantomAI.swift
// On-device AI analyst for Phantom endpoint security.
//
// Generation strategy (priority order):
//   1. Apple Intelligence (FoundationModels) — instruction-tuned on-device LLM,
//      streams tokens natively, maintains conversation context across exchanges.
//   2. Curated cybersecurity knowledge base — word-by-word streaming fallback
//      used when Apple Intelligence is unavailable or returns an error.
//
// Security model:
//   • All inference is on-device — no network calls, ever
//   • No incident data ever leaves the process
//   • Conversations are held in memory only — never written to disk
//   • User input is sanitised before prompt construction
//   • Session is wiped on dismiss
//   • Rate-limiting prevents rapid-fire generation abuse

import Combine
import CoreML
import Foundation
import FoundationModels

// MARK: - AIMessage

struct AIMessage: Identifiable {
    enum Role { case user, assistant }
    let id        = UUID()
    let role:       Role
    var content:    String
    var isStreaming: Bool
    let timestamp:  Date

    init(role: Role, content: String = "", isStreaming: Bool = false) {
        self.role       = role
        self.content    = content
        self.isStreaming = isStreaming
        self.timestamp  = Date()
    }
}

// MARK: - PhantomAI

@MainActor
final class PhantomAI: ObservableObject {

    // ── Published state ────────────────────────────────────────────────────

    /// Incident-specific session (cleared on sheet dismiss).
    @Published var messages:          [AIMessage] = []
    @Published var isGenerating:      Bool        = false

    /// General analyst chat (persists while the app is open).
    @Published var analystMessages:   [AIMessage] = []
    @Published var isAnalystGenerating: Bool      = false

    @Published var loadError: String?

    // ── Private ────────────────────────────────────────────────────────────

    private var model:     MLModel?
    private var tokenizer: GPT2Tokenizer?

    /// Persistent FoundationModels sessions — kept alive so conversation
    /// context accumulates across exchanges within the same session.
    private var analystLMSession:  Any?
    private var incidentLMSession: Any?

    /// Live system context injected into the analyst session on first use.
    /// Set by the view layer whenever real telemetry is available.
    private var pendingSystemContext: String?

    /// Cached live data used to answer system-status queries directly
    /// without going through the LLM (prevents hallucinated threat reports).
    private var cachedIncidents: [Incident] = []
    private var cachedHealth:    MonitoringHealth?

    /// System prompt injected into every LanguageModelSession.
    private static let systemPrompt = """
        You are Phantom AI, an expert cybersecurity analyst embedded in Phantom \
        — a professional macOS endpoint security monitoring application used by \
        security engineers and incident responders.

        Tone: direct, precise, and professional. No casual greetings, filler \
        phrases, or "Hey there!" openers. Get straight to the analysis.

        CRITICAL RULES — violating these is a serious error:
        1. NEVER fabricate, invent, or hallucinate threat data, CVE numbers, \
           malware names, IP addresses, file paths, or incident details. \
           If you do not have real telemetry data confirming a threat exists, \
           say so explicitly. Do not generate plausible-sounding fake reports.
        2. When asked about THIS system's current status ("check my system", \
           "any threats?", "scan my system"), ONLY report what the LIVE \
           PHANTOM TELEMETRY block in your context shows. If the telemetry \
           shows 0 incidents, say the system is clean — do not add imaginary \
           findings. If no telemetry is provided, say you cannot see live data \
           and direct the user to the Incidents and Net Intel tabs.
        3. Clearly distinguish between (a) real detections from Phantom's \
           telemetry and (b) general educational information about attack \
           techniques. Never present (b) as if it were (a).

        Expertise (for educational questions):
        • Attack techniques and MITRE ATT&CK tactics, techniques, procedures
        • Malware families, ransomware, APT groups, threat actors
        • Incident response, threat hunting, digital forensics
        • Vulnerability management — CVE, CVSS, EPSS, CISA KEV catalogue
        • Network security, lateral movement, defence-in-depth
        • macOS and Windows endpoint hardening

        Response style:
        • 2–4 focused paragraphs for conceptual questions
        • Reference MITRE ATT&CK T-numbers where relevant
        • Prioritise actionable defensive guidance over theory
        • If asked something unrelated to cybersecurity, say: \
          "I'm focused on endpoint security — ask me about a specific topic."

        You run entirely on-device. No data ever leaves this Mac.
        """

    /// Rate-limit: minimum gap between generation requests.
    private var lastRequestDate: Date      = .distantPast
    private let minRequestGap:   TimeInterval = 0.5

    // ── Singleton ──────────────────────────────────────────────────────────

    static let shared = PhantomAI()

    private init() {
        Task { await loadModel() }
    }

    // MARK: - Model loading

    func loadModel() async {
        guard model == nil else { return }
        do {
            let config = MLModelConfiguration()
            config.computeUnits = .cpuAndNeuralEngine

            // Xcode compiles .mlpackage → .mlmodelc at build time; look for the compiled form.
            guard let modelURL = Bundle.main.url(forResource: "PhantomAI", withExtension: "mlmodelc")
                              ?? Bundle.main.url(forResource: "PhantomAI", withExtension: "mlmodelc", subdirectory: "Resources")
            else { loadError = "PhantomAI model not found in bundle"; return }

            let mlModel = try await MLModel.load(contentsOf: modelURL, configuration: config)

            guard let vocabURL  = Bundle.main.url(forResource: "vocab",  withExtension: "json")
                               ?? Bundle.main.url(forResource: "vocab",  withExtension: "json",  subdirectory: "Resources"),
                  let mergesURL = Bundle.main.url(forResource: "merges", withExtension: "txt")
                               ?? Bundle.main.url(forResource: "merges", withExtension: "txt",   subdirectory: "Resources")
            else { loadError = "Tokenizer files not found in bundle"; return }

            let tok      = try GPT2Tokenizer(vocabURL: vocabURL, mergesURL: mergesURL)
            model        = mlModel
            tokenizer    = tok
        } catch {
            loadError = error.localizedDescription
        }
    }

    /// Retry after a load error (e.g. first launch before bundle is fully written).
    func retryLoad() async {
        model     = nil
        tokenizer = nil
        loadError = nil
        await loadModel()
    }

    var isReady: Bool { model != nil && tokenizer != nil }

    // MARK: - Session management (security)

    /// Wipe the incident session. Call on sheet dismiss.
    func clearSession() {
        messages.removeAll()
        isGenerating = false
        incidentLMSession = nil   // drop conversation context
    }

    /// Wipe the general analyst chat.
    func clearAnalystSession() {
        analystMessages.removeAll()
        isAnalystGenerating = false
        analystLMSession   = nil   // drop conversation context
        pendingSystemContext = nil
    }

    /// Called by the view layer to inject a live snapshot of what Phantom
    /// currently sees on the endpoint.  The context is woven into the next
    /// analyst session that gets created so the AI can answer system-specific
    /// questions ("check my system", "any active threats?") with real data.
    func setSystemContext(incidents: [Incident], health: MonitoringHealth) {
        // Cache for direct-response queries that bypass the LLM.
        cachedIncidents = incidents
        cachedHealth    = health

        let active = incidents.filter { !$0.isSuppressed }
        let high   = active.filter { $0.severity == .high }.count
        let med    = active.filter { $0.severity == .medium }.count
        let low    = active.filter { $0.severity == .low }.count

        var lines: [String] = [
            "=== LIVE PHANTOM TELEMETRY ===",
            "Monitoring status : \(health.isRunning ? "Running" : "Stopped") — \(health.status.rawValue.capitalized)",
        ]

        if let last = health.lastSuccessfulScanAt {
            let ago = Int(-last.timeIntervalSinceNow / 60)
            lines.append("Last scan         : \(ago == 0 ? "just now" : "\(ago) min ago")")
        }

        lines.append("Active incidents  : \(active.count) total  (\(high) high · \(med) medium · \(low) low)")

        if !active.isEmpty {
            lines.append("")
            lines.append("Top detections:")
            for i in active.prefix(5) {
                let tech = i.technique.map { " [\($0.rawValue)]" } ?? ""
                lines.append("  • [\(i.severity.rawValue.uppercased())] \(i.name)\(tech)")
            }
        }

        if !health.degradationReasons.isEmpty {
            lines.append("")
            lines.append("Degradation reasons: \(health.degradationReasons.joined(separator: ", "))")
        }

        lines.append("=== END TELEMETRY ===")
        pendingSystemContext = lines.joined(separator: "\n")

        // If a session already exists, destroy it so it gets rebuilt
        // with the new context on the next message.
        analystLMSession = nil
    }

    // MARK: - Public API

    /// Generate the initial threat explanation (auto-fires on sheet open).
    func explain(incident: Incident) async {
        await generate(
            userDisplay: "Explain this detection",
            prompt: buildExplainPrompt(for: incident)
        )
    }

    /// "How does this attack work?"
    func askAttackVector(incident: Incident) async {
        await generate(
            userDisplay: "How does this attack work?",
            prompt: buildAttackVectorPrompt(for: incident)
        )
    }

    /// MITRE ATT&CK technique deep-dive.
    func askMitreContext(incident: Incident) async {
        guard incident.technique != nil else { return }
        await generate(
            userDisplay: "Explain the MITRE technique",
            prompt: buildMitrePrompt(for: incident)
        )
    }

    /// Concrete remediation steps.
    func askRemediation(incident: Incident) async {
        await generate(
            userDisplay: "What's the remediation?",
            prompt: buildRemediationPrompt(for: incident)
        )
    }

    /// False-positive triage.
    func askFalsePositive(incident: Incident) async {
        await generate(
            userDisplay: "Could this be a false positive?",
            prompt: buildFalsePositivePrompt(for: incident)
        )
    }

    /// Threat actor / campaign context.
    func askThreatActor(incident: Incident) async {
        await generate(
            userDisplay: "What threat actors use this?",
            prompt: buildThreatActorPrompt(for: incident)
        )
    }

    /// Free-form follow-up question tied to an incident.
    func chat(message: String, incident: Incident) async {
        let safe = sanitize(message)
        guard !safe.isEmpty else { return }
        await generate(
            userDisplay: safe,
            prompt: buildChatPrompt(message: safe, incident: incident),
            forAnalyst: false
        )
    }

    // MARK: - Agent → Analyst bridge

    /// Called when the user taps "Ask AI →" on an agent insight.
    /// Clears any existing session and starts a fresh focused discussion.
    func seedFromAgent(insight: AIInsight) async {
        clearAnalystSession()
        // Use the insight's dedicated seed question if provided, otherwise build one
        let question = insight.analystSeed ?? "Tell me more about: \(insight.headline)"
        await analystChat(message: question)
    }

    // MARK: - General analyst chat (no incident required)

    /// Start a topic in the general analyst session.
    func analystChat(message: String) async {
        let safe = sanitize(message)
        guard !safe.isEmpty else { return }

        // Determine the right path BEFORE touching the LLM.
        // The LLM only receives genuine cybersecurity education questions.
        let prompt: String
        if PhantomAI.isSystemStatusQuery(safe) {
            prompt = "__SYSTEM_STATUS__"      // direct factual report from telemetry
        } else if PhantomAI.isCapabilityMismatch(safe) {
            prompt = "__CAPABILITY_MISMATCH__" // explain what Phantom can/can't do
        } else {
            prompt = safe                      // send to LLM
        }
        await generate(userDisplay: safe, prompt: prompt, forAnalyst: true)
    }

    /// Queries that ask for a live status report of THIS Mac.
    private nonisolated static func isSystemStatusQuery(_ msg: String) -> Bool {
        let lower = msg.lowercased()
        let patterns = ["check my system", "scan my system", "check system",
                        "any threats", "any active threats", "am i safe",
                        "is my system safe", "what do you see", "system status",
                        "current status", "any incidents", "show me incidents",
                        "any detections", "what's happening on my", "whats on my"]
        return patterns.contains { lower.contains($0) }
    }

    /// Queries asking Phantom to do something it fundamentally cannot do —
    /// run network tests, execute commands, check hardware metrics, etc.
    private nonisolated static func isCapabilityMismatch(_ msg: String) -> Bool {
        let lower = msg.lowercased()
        let patterns = [
            // Network/speed tests
            "speed check", "speed test", "bandwidth", "network speed",
            "download speed", "upload speed", "ping test", "latency test",
            // Antivirus / active scanning
            "virus scan", "antivirus", "malware scan", "full scan",
            "run a scan", "deep scan", "quick scan", "run scan",
            // Hardware/OS metrics
            "cpu usage", "ram usage", "memory usage", "disk usage",
            "battery", "temperature", "check cpu", "check ram",
            "check memory", "check disk", "storage space",
            // Things requiring internet
            "check weather", "what time", "search the web", "browse",
            "connect to internet", "download update",
            // Command execution
            "run a command", "execute", "open terminal", "run script",
            "run a speed", "run a network", "run a performance",
        ]
        return patterns.contains { lower.contains($0) }
    }

    /// Builds a clear, honest redirect when the user asks for something
    /// Phantom doesn't do — no LLM involvement so no hallucination risk.
    private func buildCapabilityRedirect(for message: String) -> String {
        let lower = message.lowercased()

        if lower.contains("speed") || lower.contains("bandwidth") || lower.contains("latency") || lower.contains("ping") {
            return "Phantom doesn't run network speed or latency tests — that requires active measurement tools. For network speed, use fast.com or the built-in Wireless Diagnostics app (hold Option → click Wi-Fi menu → Open Wireless Diagnostics). From a security standpoint, I can analyse suspicious outbound connections and unusual bandwidth patterns detected by the Net Intel tab. Want me to explain what network anomalies Phantom does watch for?"
        }
        if lower.contains("virus scan") || lower.contains("antivirus") || lower.contains("malware scan") || lower.contains("full scan") || lower.contains("run a scan") || lower.contains("deep scan") {
            return "Phantom isn't a traditional antivirus scanner — it's a behavioural endpoint monitor. Rather than scanning files for known signatures, it watches process execution, network connections, persistence mechanisms, and system logs in real time. This catches attacks that evade signature-based AV (living-off-the-land, fileless malware, zero-days). For signature scanning, XProtect is built into macOS and runs automatically. ClamAV (open source) or Malwarebytes for Mac can do on-demand file scans. Want me to explain how Phantom's behavioural approach differs from traditional AV?"
        }
        if lower.contains("cpu") || lower.contains("ram") || lower.contains("memory") || lower.contains("disk") || lower.contains("battery") || lower.contains("temperature") || lower.contains("storage") {
            return "Phantom doesn't monitor hardware metrics — use Activity Monitor (Cmd+Space → Activity Monitor) for CPU, RAM, and disk usage, or iStatMenus for a persistent menu-bar view. From a security angle, unexpected CPU or RAM spikes can indicate crypto-mining malware (T1496) or a process injecting into legitimate applications. If you see something suspicious in Activity Monitor, bring the process name here and I can help analyse it."
        }
        return "Phantom is focused on endpoint security monitoring — it watches for threats across process activity, network connections, and persistence mechanisms, but it can't execute commands, access the internet, or interface with external services. Ask me about specific attack techniques, incident analysis, MITRE ATT&CK, or what Phantom's monitors are actually detecting."
    }

    /// Builds a factual status report directly from Phantom's cached telemetry
    /// without any LLM involvement.  Called for system-check queries to
    /// eliminate the hallucination risk entirely.
    private func buildSystemStatusReport() -> String {
        let active = cachedIncidents.filter { !$0.isSuppressed }
        let health = cachedHealth

        var lines: [String] = []

        // ── Monitoring status ──────────────────────────────────────────────
        if let h = health {
            let statusStr = h.isRunning
                ? (h.status == .healthy ? "Running — all monitors healthy." : "Running — \(h.status.rawValue).")
                : "Stopped."
            lines.append("Phantom monitoring: \(statusStr)")
            if let last = h.lastSuccessfulScanAt {
                let ago = max(0, Int(-last.timeIntervalSinceNow / 60))
                lines.append("Last scan: \(ago == 0 ? "just now" : "\(ago) minute\(ago == 1 ? "" : "s") ago").")
            }
        } else {
            lines.append("Phantom monitoring: status unknown.")
        }

        lines.append("")

        // ── Active incidents ───────────────────────────────────────────────
        if active.isEmpty {
            lines.append("Active incidents: none. No threats detected on this endpoint.")
        } else {
            let high = active.filter { $0.severity == .high }.count
            let med  = active.filter { $0.severity == .medium }.count
            let low  = active.filter { $0.severity == .low }.count
            lines.append("Active incidents: \(active.count) (\(high) high · \(med) medium · \(low) low)")
            lines.append("")
            for i in active.prefix(5) {
                let tech = i.technique.map { " — \($0.rawValue) \($0.title)" } ?? ""
                lines.append("[\(i.severity.rawValue.uppercased())] \(i.name)\(tech)")
                if let d = i.detail, !d.isEmpty { lines.append("  \(d)") }
            }
            if active.count > 5 {
                lines.append("…and \(active.count - 5) more. Open the Incidents tab for the full list.")
            }
        }

        // ── Degradation warnings ───────────────────────────────────────────
        if let h = health, !h.degradationReasons.isEmpty {
            lines.append("")
            lines.append("Monitor warnings: \(h.degradationReasons.joined(separator: "; "))")
        }

        lines.append("")
        lines.append("All data is sourced directly from Phantom's real-time telemetry — no inference or estimation.")
        return lines.joined(separator: "\n")
    }

    // MARK: - Core generation

    /// Generates a response using Apple Intelligence (FoundationModels) when
    /// available, with the curated knowledge base as an automatic fallback.
    ///
    /// Apple Intelligence path: streams real tokens from an instruction-tuned
    /// on-device LLM that maintains conversation context across exchanges.
    /// Fallback path: word-by-word streaming from the curated knowledge base.
    private func generate(userDisplay: String, prompt: String, forAnalyst: Bool = false) async {
        if forAnalyst  { guard !isAnalystGenerating else { return } }
        else           { guard !isGenerating        else { return } }

        let now = Date()
        guard now.timeIntervalSince(lastRequestDate) >= minRequestGap else { return }
        lastRequestDate = now

        // ── Append the user message and a streaming placeholder ────────────
        if forAnalyst {
            analystMessages.append(AIMessage(role: .user, content: userDisplay))
            analystMessages.append(AIMessage(role: .assistant, content: "", isStreaming: true))
            isAnalystGenerating = true
        } else {
            messages.append(AIMessage(role: .user, content: userDisplay))
            messages.append(AIMessage(role: .assistant, content: "", isStreaming: true))
            isGenerating = true
        }
        let idx = forAnalyst ? analystMessages.count - 1 : messages.count - 1

        defer {
            if forAnalyst {
                if idx < analystMessages.count { analystMessages[idx].isStreaming = false }
                isAnalystGenerating = false
            } else {
                if idx < messages.count { messages[idx].isStreaming = false }
                isGenerating = false
            }
        }

        // ── 0. Direct paths — LLM never involved ──────────────────────────
        // System-status and capability-mismatch queries are handled here with
        // real data or clear redirects.  The LLM only sees conceptual questions.
        let directResponse: String?
        switch prompt {
        case "__SYSTEM_STATUS__":
            directResponse = buildSystemStatusReport()
        case "__CAPABILITY_MISMATCH__":
            directResponse = buildCapabilityRedirect(for: userDisplay)
        default:
            directResponse = nil
        }

        if let text = directResponse {
            let words = text.components(separatedBy: " ")
            var streamed = ""
            for (i, word) in words.enumerated() {
                streamed += (i == 0 ? "" : " ") + word
                if forAnalyst {
                    if idx < analystMessages.count { analystMessages[idx].content = streamed }
                } else {
                    if idx < messages.count        { messages[idx].content        = streamed }
                }
                try? await Task.sleep(nanoseconds: 25_000_000)
            }
            return   // defer handles finalisation
        }

        // ── 1. Apple Intelligence (FoundationModels) ───────────────────────
        // Get-or-create a persistent session so conversation context carries
        // across multiple exchanges within the same chat session.
        if #available(macOS 26.0, *) {
            let lmSession: LanguageModelSession
        if forAnalyst {
            if analystLMSession == nil {
                // Weave live telemetry into the instructions if available so
                // the model can answer system-specific questions with real data.
                var instructions = PhantomAI.systemPrompt
                if let ctx = pendingSystemContext {
                    instructions += "\n\n" + ctx
                    pendingSystemContext = nil   // consumed — won't repeat
                }
                analystLMSession = LanguageModelSession(instructions: instructions)
            }
            lmSession = analystLMSession as! LanguageModelSession
        } else {
            if incidentLMSession == nil {
                incidentLMSession = LanguageModelSession(
                    instructions: PhantomAI.systemPrompt
                )
            }
            lmSession = incidentLMSession as! LanguageModelSession
        }

        // For incident queries the prompt has useful context (incident name,
        // technique); pass it alongside the human-readable display message.
        let modelInput = (prompt == userDisplay || prompt.isEmpty)
            ? userDisplay
            : "\(prompt)\n\nUser question: \(userDisplay)"

        do {
            let stream = lmSession.streamResponse(to: modelInput)
            for try await partial in stream {
                let text = partial.content
                if forAnalyst {
                    if idx < analystMessages.count { analystMessages[idx].content = text }
                } else {
                    if idx < messages.count        { messages[idx].content        = text }
                }
            }
            return   // success — defer handles finalisation
        } catch {
            // Apple Intelligence unavailable or returned an error;
            // fall through to the knowledge-base fallback below.
            if forAnalyst {
                if idx < analystMessages.count { analystMessages[idx].content = "" }
            } else {
                if idx < messages.count        { messages[idx].content        = "" }
            }
        }
        }

        // ── 2. Knowledge-base fallback (word-by-word streaming) ────────────
        let responseText = PhantomAI.knowledgeBase(for: prompt, userMessage: userDisplay)
        let words = responseText.components(separatedBy: " ")
        var streamed = ""
        for (i, word) in words.enumerated() {
            streamed += (i == 0 ? "" : " ") + word
            if forAnalyst {
                if idx < analystMessages.count { analystMessages[idx].content = streamed }
            } else {
                if idx < messages.count        { messages[idx].content        = streamed }
            }
            try? await Task.sleep(nanoseconds: 40_000_000)   // ~40 ms/word
        }
        // defer finalises isStreaming / isGenerating
    }

    // MARK: - On-device knowledge base

    /// Returns an accurate, curated cybersecurity response for the given prompt.
    /// Matches on the combined prompt + user message text so both the quick-action
    /// chips (which set prompt directly) and free-form chat (which extracts the
    /// user message) hit the right entry.
    private nonisolated static func knowledgeBase(for prompt: String, userMessage: String) -> String {
        let combined = (prompt + " " + userMessage).lowercased()

        // ── Incident-specific response detection ───────────────────────────
        // When the prompt contains a quoted incident name or MITRE tag, return
        // a contextualised analysis rather than a generic topic entry.
        if combined.contains("false positive") {
            return "This detection may be a false positive when the process is a known administrative tool (e.g. PowerShell during patch windows), the source IP belongs to an internal scanner or monitoring agent, or the activity follows a documented change-management ticket. Cross-reference the event with your asset inventory and correlate against user activity logs. If the parent process is a trusted software updater and the network destination is a known CDN, it is likely benign. Tune the detection rule with an exclusion scoped to that specific process hash or user context."
        }
        if combined.contains("threat actor") || combined.contains("who use") {
            return "Advanced persistent threat (APT) groups commonly associated with this technique include APT29 (Cozy Bear), APT41, and Lazarus Group. Financially motivated actors such as FIN7 and the Cl0p ransomware gang also employ it at scale. The MITRE ATT&CK Groups matrix lists specific procedures for each actor. Check threat intelligence feeds (CISA advisories, ISACs, VirusTotal Graph) to see whether the observed indicators—file hashes, C2 IPs, mutex names—have been attributed to a known campaign."
        }
        if combined.contains("remediation") || combined.contains("remediate") || combined.contains("how to fix") {
            return "Immediate steps: isolate the affected endpoint from the network to prevent lateral movement, preserve volatile memory with a tool like WinPmem or `osxpmem` before rebooting, and revoke any credentials that were in scope. Medium-term: patch the exploited vulnerability or misconfiguration, rotate secrets, and deploy an updated detection rule. Long-term: implement least-privilege across service accounts, enable Windows Credential Guard or macOS System Integrity Protection, and schedule purple-team exercises to validate the control improvements."
        }
        if combined.contains("attack vector") || combined.contains("how does this attack") {
            return "The attack begins with initial access—typically a spear-phishing email, exposed RDP port, or supply-chain compromise. The adversary then establishes persistence (scheduled task, run-key, launchd plist) before moving to privilege escalation via token impersonation or kernel exploit. Discovery commands (net user, whoami /all, arp -a) map the environment. Data is staged, optionally exfiltrated over HTTPS or DNS tunnelling, and the final payload deployed. The full sequence maps to MITRE ATT&CK Initial Access → Execution → Persistence → Privilege Escalation → Discovery → Collection → Exfiltration."
        }
        if combined.contains("mitre") && (combined.contains("technique") || combined.contains("t1")) {
            return "MITRE ATT&CK organises adversary behaviour into 14 tactics (columns) and hundreds of techniques (rows). Each technique has a T-number (e.g. T1059 – Command and Scripting Interpreter), sub-techniques (T1059.001 – PowerShell), known procedure examples from real incidents, and recommended mitigations and detections. Use the ATT&CK Navigator to heat-map your current detection coverage and identify gaps. Align your SIEM rules and EDR policies to the specific sub-techniques observed in your threat intelligence."
        }

        // ── General topic entries ──────────────────────────────────────────
        if combined.contains("ransomware") {
            return "Ransomware is malware that encrypts the victim's files and demands payment—typically in cryptocurrency—to restore access. Modern families like LockBit 3.0, BlackCat (ALPHV), and Cl0p operate as Ransomware-as-a-Service (RaaS): affiliates handle initial access and deployment while the core group manages the payment portal and decryptor. The attack chain is: phishing or exposed RDP → credential theft → domain reconnaissance → data exfiltration → encryption across all accessible shares → ransom note. Defence: offline immutable backups, EDR with rollback capability, network micro-segmentation, and disabling SMBv1."
        }
        if combined.contains("sql injection") {
            return "SQL injection (SQLi) is a code injection attack in which an adversary inserts malicious SQL into an input field that is concatenated directly into a database query. A classic example: entering `' OR '1'='1` into a login form bypasses authentication. Blind SQLi infers data by observing true/false responses; time-based blind SQLi uses delays (SLEEP, WAITFOR). Defence: use parameterised queries or prepared statements exclusively, apply a WAF as a secondary control, enforce least-privilege on the database account, and validate all user input server-side. MITRE ATT&CK maps this to T1190 – Exploit Public-Facing Application."
        }
        if combined.contains("lateral movement") {
            return "Lateral movement describes techniques attackers use to progressively move through a network after initial access, seeking higher-value targets or broader access. Common methods: Pass-the-Hash (T1550.002) reuses NTLM hashes without knowing the plaintext password; Pass-the-Ticket (T1550.003) forges Kerberos tickets; WMI and PsExec enable remote command execution; SMB shares spread payloads. Detection relies on monitoring authentication anomalies—accounts logging into unusual hosts, 4648/4624 event IDs in Windows, or SSH lateral hops detected by a UEBA solution."
        }
        if combined.contains("privilege escalat") {
            return "Privilege escalation is the process of gaining elevated permissions beyond what was initially granted. Vertical escalation moves from a standard user to admin or SYSTEM/root; horizontal escalation gains access to another user's resources at the same level. Common techniques: exploiting unpatched kernel vulnerabilities (DirtyPipe, PrintNightmare), abusing misconfigured sudo rules or SUID binaries on Linux, token impersonation via SeImpersonatePrivilege on Windows, or leveraging weak service binary paths (T1574.010). Mitigations: Privileged Access Workstations (PAWs), Just-In-Time (JIT) access, and continuous vulnerability scanning."
        }
        if combined.contains("c2") || combined.contains("command and control") || combined.contains("command-and-control") {
            return "A Command-and-Control (C2) server is the attacker's remote management infrastructure used to issue instructions to compromised hosts (the botnet or implants) and receive exfiltrated data. Modern C2 frameworks—Cobalt Strike, Sliver, Brute Ratel, Havoc—communicate over HTTPS with domain-fronting or via legitimate cloud services (Teams, Slack, OneDrive) to blend into normal traffic. Detection: look for beaconing patterns (consistent interval connections to a single external IP), JA3/JA3S TLS fingerprint mismatches, and DNS queries for recently-registered or DGA domains. MITRE ATT&CK Tactic: Command and Control (TA0011)."
        }
        if combined.contains("kill chain") {
            return "The Cyber Kill Chain (Lockheed Martin, 2011) is a 7-stage attack lifecycle model: 1 Reconnaissance – gathering target info via OSINT, 2 Weaponisation – building an exploit/payload, 3 Delivery – email attachment, watering hole, USB, 4 Exploitation – code execution on the target, 5 Installation – malware persistence, 6 C2 – establishing a back-channel, 7 Actions on Objectives – data theft, destruction, ransomware. Defenders use it to identify which stage a detected indicator belongs to and apply controls upstream. MITRE ATT&CK provides more granularity than the Kill Chain for detection engineering."
        }
        if combined.contains("phishing") {
            return "Phishing is a social-engineering attack that tricks users into revealing credentials or executing malware, most commonly via deceptive email. Spear-phishing targets a specific individual using personalised lures (T1566.001). Smishing uses SMS; vishing uses phone calls. Modern attacks use adversary-in-the-middle (AiTM) proxies like Evilginx2 to bypass MFA by capturing session cookies after the user authenticates. Defence: DMARC/DKIM/SPF on all domains, phishing-resistant MFA (FIDO2 passkeys), browser isolation, and regular simulation training that measures click rates over time."
        }
        if combined.contains("credential dump") || combined.contains("mimikatz") || combined.contains("lsass") {
            return "Credential dumping (T1003) extracts password hashes, plaintext credentials, or Kerberos tickets from memory or disk. Mimikatz's `sekurlsa::logonpasswords` reads credentials from LSASS process memory; DCSync impersonates a Domain Controller to pull hashes from AD replication. On macOS, `/etc/master.passwd` and the keychain are targeted. Defences: enable Windows Credential Guard (virtualises LSASS), deploy EDR rules alerting on LSASS memory reads (OpenProcess with PROCESS_VM_READ), use Protected Users security group for privileged accounts, and audit use of `sekurlsa`, `kerberos::`, or `lsadump::` strings."
        }
        if combined.contains("living off the land") || combined.contains("lolbin") || combined.contains("lotl") {
            return "Living-off-the-Land (LotL) attacks abuse legitimate, pre-installed system binaries—called LOLBins—to execute malicious code without dropping suspicious files. Examples: `certutil.exe -decode` downloads and decodes payloads; `regsvr32 /s /n /u /i:http://…scrobj.dll` executes remote scripts; `wmic process call create` launches arbitrary processes. On macOS, `osascript`, `curl`, and `launchctl` are frequently abused. MITRE maps these to T1218 (System Binary Proxy Execution). Detection: behaviour-based rather than signature-based rules; alert on unexpected parent-child process chains, e.g. Word → cmd.exe → powershell.exe."
        }
        if combined.contains("supply chain") {
            return "A supply chain attack compromises software or hardware before it reaches the end customer. The SolarWinds SUNBURST attack (2020) injected a backdoor into the Orion build pipeline, reaching 18,000 organisations. XZ Utils (CVE-2024-3094) inserted a backdoor into a compression library via a malicious maintainer. Defences: enforce reproducible builds and verify binary hashes against the build environment output; use code-signing with attestation (SLSA framework); audit third-party dependencies with SBOMs (Software Bill of Materials); monitor for unexpected outbound connections from build agents."
        }
        if combined.contains("zero day") || combined.contains("zero-day") || combined.contains("0day") {
            return "A zero-day (0-day) is a vulnerability that is unknown to the vendor and therefore has no patch available. Threat actors, nation-states, and brokers (Zerodium, Crowdfence) actively trade 0-days, with browser and mobile OS chains fetching millions of dollars. The window between discovery and patch availability—the exposure window—is when organisations are most at risk. Mitigations before a patch exists: virtual patching via WAF/IPS rules, network-level restrictions to reduce the attack surface, and behaviour-based detection to catch post-exploitation activity even when the initial exploit is unknown."
        }
        if combined.contains("buffer overflow") {
            return "A buffer overflow occurs when a program writes more data into a fixed-size buffer than it can hold, overwriting adjacent memory. Stack overflows can overwrite the return address to redirect execution (ret2libc, ROP chains). Heap overflows corrupt allocator metadata or adjacent objects. Classic example: the Morris Worm (1988) used a buffer overflow in `fingerd`. Modern mitigations: stack canaries (GCC's `-fstack-protector`), Address Space Layout Randomisation (ASLR), Data Execution Prevention (DEP/NX), and safe languages (Rust, Go) that perform bounds checking at compile time."
        }
        if combined.contains("rootkit") {
            return "A rootkit is a set of tools that hides an attacker's presence on a compromised system by subverting the OS's visibility mechanisms. User-mode rootkits hook Win32 API calls to hide files and processes (T1014). Kernel-mode rootkits (bootkits) modify the kernel itself or the MBR/UEFI firmware, surviving OS reinstalls. LoJax (2018) was the first discovered UEFI rootkit. Detection requires out-of-band visibility: memory forensics tools (Volatility, Rekall), hardware-based integrity checks (Intel TXT, TPM attestation), and hypervisor-based monitoring that operates below the infected OS layer."
        }
        if combined.contains("botnet") {
            return "A botnet is a network of internet-connected devices infected with malware and under centralised control by a threat actor (botmaster). Bots receive commands via IRC, HTTP, or peer-to-peer protocols and are used for DDoS attacks, spam campaigns, credential stuffing, cryptomining, and proxy services. Mirai (2016) assembled 600,000 IoT devices and launched a 1.2 Tbps DDoS. Emotet served as a botnet-for-hire, distributing other malware families. Disruption requires coordinated takedowns (Europol, FBI) or technical sinkholing of C2 domains to redirect infected hosts away from attacker infrastructure."
        }
        if combined.contains("ddos") || combined.contains("denial of service") {
            return "A Distributed Denial-of-Service (DDoS) attack floods a target—server, network link, or application—with traffic to exhaust its resources and make it unavailable. Volumetric attacks (UDP floods, DNS amplification) overwhelm bandwidth; protocol attacks (SYN floods) exhaust connection state tables; application-layer attacks (HTTP floods, Slowloris) target Layer 7 logic. Defence layers: upstream scrubbing centres (Cloudflare Magic Transit, AWS Shield Advanced), rate-limiting and CAPTCHAs at the edge, Anycast routing to distribute load, and BGP blackholing as a last resort for volumetric floods."
        }
        if combined.contains("vulnerability") || combined.contains("cve") {
            return "A vulnerability is a weakness in software, hardware, or a process that can be exploited to compromise confidentiality, integrity, or availability. CVE (Common Vulnerabilities and Exposures) assigns standardised identifiers; CVSS scores (0–10) quantify severity. The CVE lifecycle: discovery → vendor notification (responsible disclosure) → patch development → public disclosure. EPSS (Exploit Prediction Scoring System) estimates the probability of exploitation in the wild within 30 days, helping teams prioritise patching beyond raw CVSS scores. Unpatched known-exploited vulnerabilities are tracked by CISA's KEV catalogue."
        }
        if combined.contains("exploit") {
            return "An exploit is code or a technique that takes advantage of a vulnerability to cause unintended behaviour in a target system—typically arbitrary code execution, privilege escalation, or authentication bypass. Exploits exist on a spectrum: proof-of-concept (PoC) demonstrates viability; functional exploit reliably achieves the goal; weaponised exploit is integrated into an attack framework like Metasploit or Cobalt Strike. Exploit chains combine multiple vulnerabilities to achieve a higher-severity outcome, such as a browser sandbox escape followed by a kernel privilege escalation to achieve full system compromise."
        }
        if combined.contains("malware") {
            return "Malware (malicious software) is any program designed to disrupt, damage, or gain unauthorised access to systems. Categories include: viruses (self-replicating, attach to host files), worms (self-propagating across networks without user action), Trojans (disguised as legitimate software), ransomware (encrypts files for ransom), spyware (exfiltrates data silently), adware, and fileless malware (runs entirely in memory using LOLBins). Analysis approaches: static analysis (strings, PE headers, entropy), dynamic analysis (sandbox detonation in Cuckoo or Any.Run), and manual reverse engineering in Ghidra or IDA Pro."
        }
        if combined.contains("persistence") {
            return "Persistence mechanisms allow attackers to maintain access across reboots, credential rotations, or defensive responses. Windows: Registry Run keys (T1547.001), scheduled tasks (T1053.005), services (T1543.003), DLL hijacking (T1574.001), WMI event subscriptions (T1546.003). macOS/Linux: LaunchAgents/LaunchDaemons, cron jobs, rc.local modifications, SSH authorised_keys backdoors, and systemd unit files. Detection: audit newly created scheduled tasks and services, monitor Run key changes with Sysmon Event ID 13, and baseline authorised_keys files on servers."
        }
        if combined.contains("firewall") {
            return "A firewall enforces an access control policy on network traffic based on rules matching source/destination IP, port, and protocol. Stateful firewalls track TCP connection state; next-generation firewalls (NGFWs) add application awareness, TLS inspection, IPS, and URL filtering. Placement: perimeter firewalls at the internet edge, internal segmentation firewalls between network zones (PCI DSS scope), and host-based firewalls on every endpoint. Common misconfigurations: overly permissive outbound rules (allowing all egress facilitates C2), stale rules accumulate over time creating unintended access, and symmetric rules that allow return traffic from blocked connections."
        }
        if combined.contains("encryption") || combined.contains("cryptograph") {
            return "Encryption converts plaintext into ciphertext using an algorithm and key, ensuring only authorised parties can read the data. Symmetric encryption (AES-256-GCM) uses the same key to encrypt and decrypt—fast, used for bulk data. Asymmetric encryption (RSA-4096, ECDSA) uses a public key to encrypt and a private key to decrypt—used for key exchange and signatures. TLS 1.3 combines both: asymmetric for handshake and key agreement, symmetric (ChaCha20-Poly1305 or AES-GCM) for the session. Attackers target key management weaknesses rather than breaking the cipher itself—hardcoded keys, weak RNG seeds, and insecure key storage are common attack surfaces."
        }
        if combined.contains("intrusion detection") || (combined.contains("ids") && combined.contains("security")) || combined.contains(" ips ") {
            return "An Intrusion Detection System (IDS) monitors network traffic or host activity for signs of malicious behaviour and generates alerts. Network IDS (NIDS) like Suricata or Zeek analyse packet streams against rule signatures and behavioural baselines. Host IDS (HIDS) like OSSEC monitor file integrity, log events, and process activity. An IPS (Intrusion Prevention System) can actively block detected threats inline. Challenges: alert fatigue from high false-positive rates, encrypted traffic reducing signature efficacy, and evasion via fragmentation or encoding. Modern EDR platforms combine HIDS capabilities with behavioural AI to reduce reliance on signatures."
        }
        if combined.contains("endpoint") || combined.contains("edr") {
            return "Endpoint Detection and Response (EDR) platforms provide continuous visibility into endpoint activity—process creation, file writes, registry changes, network connections—and apply behavioural analytics to detect threats that bypass signature-based AV. Key capabilities: telemetry collection (Sysmon-style), threat hunting via query interfaces (Osquery, KQL), automated response actions (process kill, network isolation), and threat intelligence integration. Leading platforms include CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne, and Carbon Black. Phantom monitors endpoints locally using the same kernel-level telemetry sources that feed commercial EDR products."
        }

        // ── Follow-up / conversational detection ──────────────────────────
        // Check the user's raw message (not combined) so doubling from
        // prompt == userMessage doesn't break the match.
        let followUpWords: Set<String> = [
            "more", "explain more", "go on", "continue", "and then", "so",
            "ok", "okay", "yes", "sure", "cool", "thanks", "thank you",
            "got it", "interesting", "what else", "keep going", "tell me more",
            "more detail", "more details", "elaborate", "expand", "and?", "so?"
        ]
        let userTrimmed = userMessage.lowercased()
            .replacingOccurrences(of: "[?!.]", with: "", options: .regularExpression)
            .trimmingCharacters(in: .whitespaces)
        if followUpWords.contains(userTrimmed) || userTrimmed.count < 5 {
            return "I can go deeper on any of these topics — just name one: ransomware, SQL injection, lateral movement, privilege escalation, phishing, credential dumping, living-off-the-land, supply chain attacks, zero-days, buffer overflows, C2 infrastructure, the MITRE ATT&CK kill chain, rootkits, botnets, or DDoS. You can also ask about specific MITRE techniques (e.g. T1059, T1003) or request remediation guidance for any detection."
        }

        // ── Non-cybersecurity / unclear questions ──────────────────────────
        // Detect messages that contain no recognisable security vocabulary.
        let securityKeywords = ["attack", "threat", "malware", "exploit", "vuln",
                                "hack", "breach", "detect", "incident", "firewall",
                                "network", "endpoint", "log", "process", "cve",
                                "password", "credential", "privilege", "payload",
                                "inject", "execution", "persistence", "evasion",
                                "mitre", "apt", "ioc", "lateral", "escalat",
                                "encrypt", "decrypt", "backdoor", "shell", "root",
                                "security", "cyber", "forensic", "sandbox",
                                "recon", "exfil", "command", "control", "agent"]
        let hasSecurityContext = securityKeywords.contains { combined.contains($0) }
        if !hasSecurityContext {
            return "I'm a cybersecurity-focused AI analyst. Ask me about attack techniques, malware families, MITRE ATT&CK tactics, incident response, vulnerability classes, or any of the quick-topic chips below — I can give you accurate, actionable information on all of them."
        }

        // ── Generic cybersecurity fallback ────────────────────────────────
        let topic = PhantomAI.extractTopic(from: userMessage)
        return "In cybersecurity, \(topic) is an area defenders monitor closely. Key controls: enforce least-privilege, ensure process creation and network connections are logged (Sysmon, auditd), deploy EDR with behavioural detection, and map your detection coverage against the relevant MITRE ATT&CK techniques. For specific IOCs or CVE advisories, consult CISA KEV, NIST NVD, and your threat intelligence feeds."
    }

    /// Strips common question prefixes to extract the core noun phrase,
    /// filtering out stop words that would produce nonsensical topic strings.
    private nonisolated static func extractTopic(from message: String) -> String {
        let stopWords: Set<String> = ["more", "you", "me", "it", "that", "this",
                                      "what", "how", "why", "the", "a", "an",
                                      "is", "are", "do", "does", "see", "tell",
                                      "tall", "show", "give", "get"]
        let cleaned = message
            .replacingOccurrences(of: "tall me|tell me (what|about|how|why)", with: "", options: [.regularExpression, .caseInsensitive])
            .replacingOccurrences(of: "^(what is|what are|how does|how do|explain|describe|define)\\s+", with: "", options: [.regularExpression, .caseInsensitive])
            .replacingOccurrences(of: "[?!.]", with: "", options: .regularExpression)
            .trimmingCharacters(in: .whitespaces)
        // Filter out remaining stop words
        let words = cleaned.components(separatedBy: " ")
            .filter { !stopWords.contains($0.lowercased()) && !$0.isEmpty }
        let meaningful = words.joined(separator: " ")
        guard !meaningful.isEmpty else { return "this technique" }
        return meaningful.prefix(1).lowercased() + meaningful.dropFirst()
    }

    // MARK: - Prompt construction

    private func buildExplainPrompt(for i: Incident) -> String {
        let subject = subjectLine(i)
        switch i.source {
        case .process:     return "The process-based detection \"\(subject)\" was triggered because"
        case .network:     return "The network detection \"\(subject)\" indicates"
        case .persistence: return "The persistence mechanism \"\(subject)\" works by"
        case .log:         return "The log-based indicator \"\(subject)\" suggests"
        case .unknown:     return "The security detection \"\(subject)\" indicates"
        }
    }

    private func buildAttackVectorPrompt(for i: Incident) -> String {
        // Knowledge base matches on "attack vector" keyword
        "attack vector \(subjectLine(i))"
    }

    private func buildMitrePrompt(for i: Incident) -> String {
        guard let t = i.technique else { return buildExplainPrompt(for: i) }
        return "mitre att&ck technique \(t.rawValue) \(t.title)"
    }

    private func buildRemediationPrompt(for i: Incident) -> String {
        "remediation for \(sanitize(i.name))"
    }

    private func buildFalsePositivePrompt(for i: Incident) -> String {
        "false positive \(sanitize(i.name))"
    }

    private func buildThreatActorPrompt(for i: Incident) -> String {
        "threat actor \(i.technique.map { "\($0.rawValue) \($0.title)" } ?? sanitize(i.name))"
    }

    private func buildChatPrompt(message: String, incident: Incident) -> String {
        // Pass the user message + incident context; the knowledge base matches
        // on the user's actual question keywords.
        let ctx = "\(sanitize(message)) \(sanitize(incident.name))"
            + (incident.technique.map { " \($0.rawValue) \($0.title)" } ?? "")
        return ctx
    }

    private func subjectLine(_ i: Incident) -> String {
        var parts: [String] = []
        if let t = i.technique { parts.append("\(t.title) (\(t.rawValue))") }
        parts.append(sanitize(i.name))
        if let d = i.detail, !d.isEmpty { parts.append(sanitize(d)) }
        return parts.joined(separator: " — ")
    }

    // MARK: - Input sanitisation (security)

    /// Strip control characters and null bytes; truncate to a safe length.
    func sanitize(_ raw: String, maxLength: Int = 300) -> String {
        String(
            raw.unicodeScalars
                .filter { $0.value >= 32 && $0.value != 127 }
                .prefix(maxLength)
                .map(Character.init)
        )
    }

}

// MARK: - GPT-2 BPE Tokenizer

final class GPT2Tokenizer {

    private let encoder:     [String: Int]
    private let decoder:     [Int: String]
    private let bpeRanks:    [Pair: Int]
    private let byteEncoder: [UInt8: Character]
    private let byteDecoder: [Character: UInt8]

    private nonisolated struct Pair: Hashable { let a: String; let b: String }

    init(vocabURL: URL, mergesURL: URL) throws {
        // ── Byte-level encoder (GPT-2 maps raw bytes to unicode chars) ─────
        var be = [UInt8: Character]()
        var bd = [Character: UInt8]()
        var charList: [Int] = []
        var n = 256
        for b in 0...255 {
            let printable: [Int] = Array(33...126) + Array(161...172) + Array(174...255)
            if printable.contains(b) { charList.append(b) }
            else                     { charList.append(n); n += 1 }
        }
        for i in 0..<256 {
            let byte = UInt8(i)
            let char = Character(UnicodeScalar(charList[i])!)
            be[byte] = char
            bd[char] = byte
        }
        byteEncoder = be
        byteDecoder = bd

        // ── Vocabulary ──────────────────────────────────────────────────────
        let vocabData = try Data(contentsOf: vocabURL)
        guard let vocabJSON = try JSONSerialization.jsonObject(with: vocabData) as? [String: Int]
        else { throw CocoaError(.fileReadCorruptFile) }
        encoder = vocabJSON
        decoder = Dictionary(uniqueKeysWithValues: vocabJSON.map { ($1, $0) })

        // ── BPE merge rules ─────────────────────────────────────────────────
        let mergesText = try String(contentsOf: mergesURL, encoding: .utf8)
        var ranks = [Pair: Int]()
        var rank  = 0
        for line in mergesText.components(separatedBy: "\n") {
            if line.hasPrefix("#") || line.isEmpty { continue }
            let parts = line.split(separator: " ", maxSplits: 1)
            guard parts.count == 2 else { continue }
            ranks[Pair(a: String(parts[0]), b: String(parts[1]))] = rank
            rank += 1
        }
        bpeRanks = ranks
    }

    // MARK: Encode

    nonisolated func encode(_ text: String) -> [Int] {
        var ids: [Int] = []
        for token in gpt2Tokenize(text) {
            let encoded   = token.utf8.compactMap { byteEncoder[$0] }.map(String.init)
            let bpeTokens = bpe(token: encoded)
            ids += bpeTokens.compactMap { encoder[$0] }
        }
        return ids
    }

    // MARK: Decode

    nonisolated func decode(_ ids: [Int]) -> String {
        let text  = ids.compactMap { decoder[$0] }.joined()
        let bytes = text.compactMap { byteDecoder[$0] }
        // If UTF-8 decoding fails (e.g. mid-word boundary during streaming),
        // try dropping trailing bytes one at a time to find the longest valid
        // prefix rather than showing the raw byte-mapped Unicode fallback.
        if let s = String(bytes: bytes, encoding: .utf8) { return s }
        var trimmed = bytes
        while !trimmed.isEmpty {
            trimmed.removeLast()
            if let s = String(bytes: trimmed, encoding: .utf8) { return s }
        }
        return ""
    }

    // MARK: BPE

    private nonisolated func bpe(token: [String]) -> [String] {
        var word = token
        if word.count < 2 { return word }
        while true {
            var bestPair: Pair?
            var bestRank = Int.max
            for i in 0 ..< word.count - 1 {
                let pair = Pair(a: word[i], b: word[i + 1])
                if let rank = bpeRanks[pair], rank < bestRank {
                    bestRank = rank; bestPair = pair
                }
            }
            guard let merge = bestPair else { break }
            var newWord: [String] = []
            var i = 0
            while i < word.count {
                if i < word.count - 1, word[i] == merge.a, word[i + 1] == merge.b {
                    newWord.append(merge.a + merge.b); i += 2
                } else {
                    newWord.append(word[i]); i += 1
                }
            }
            word = newWord
        }
        return word
    }

    // MARK: Tokenisation (approximate GPT-2 regex)

    private nonisolated func gpt2Tokenize(_ text: String) -> [String] {
        var tokens:       [String] = []
        var current                = ""
        var prevWasSpace           = false
        for char in text {
            let isSpace = char.isWhitespace
            let isAlnum = char.isLetter || char.isNumber
            let isPunct = !isAlnum && !isSpace
            if isSpace {
                if !current.isEmpty { tokens.append(current); current = "" }
                prevWasSpace = true
            } else {
                let prefix = prevWasSpace ? " " : ""
                if !current.isEmpty {
                    let curIsAlnum = current.last?.isLetter == true || current.last?.isNumber == true
                    if (isAlnum && isPunct) || (!isAlnum && curIsAlnum) {
                        tokens.append(current)
                        current = prefix + String(char)
                        prevWasSpace = false
                        continue
                    }
                }
                current += (current.isEmpty ? prefix : "") + String(char)
                if current.isEmpty { current = prefix + String(char) }
                prevWasSpace = false
            }
        }
        if !current.isEmpty { tokens.append(current) }
        return tokens
    }
}
