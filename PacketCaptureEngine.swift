import Foundation
import Combine
import OSLog

// MARK: - PacketCaptureEngine
//
// Central orchestrator for Phantom 3.0's network intelligence layer.
// Publishes per-tool activity state so the UI can show each tool's
// live status, event count, and last-run time independently.
//
// Live modes:
//   • startSuricataStream()  — DispatchSource file-watch on the EVE log.
//                              True real-time: fires the instant Suricata
//                              writes a new alert/dns/http/tls line.
//   • startLiveCapture()     — Rolling pcap loop (capture → analyze → repeat).
//                              Feeds tshark / tcpdump / Zeek / ngrep / NetworkMiner.
//   • startAutoRefresh()     — 30s Suricata-only fallback timer when live is off.

@MainActor
final class PacketCaptureEngine: ObservableObject {

    // MARK: - Published State

    @Published private(set) var packetEvents:    [PacketEvent]               = []
    @Published private(set) var toolActivity:    [PacketTool: ToolActivityState] = {
        var d = [PacketTool: ToolActivityState]()
        PacketTool.allCases.forEach { d[$0] = ToolActivityState() }
        return d
    }()
    @Published private(set) var toolStatus:      ToolAvailability
    @Published private(set) var isAnalyzing:     Bool    = false
    @Published private(set) var isLiveCapturing: Bool    = false
    @Published private(set) var liveStatus:      String  = ""
    @Published private(set) var lastScanDate:    Date?
    @Published private(set) var lastError:       String?

    // MARK: - Scan worker (actor — owns all scanner instances off main actor)

    private let scanWorker = ScanWorker()

    private let logger = Logger(subsystem: "Phantom", category: "PacketCaptureEngine")

    // Live capture
    private var liveTask:       Task<Void, Never>?
    private var refreshTimer:   Timer?

    // LogWatcher — 5 s background heartbeat for Suricata poll-mode fallback
    // (used when DispatchSource stream is unavailable, e.g. log file not yet created)
    private let logWatcher = LogWatcher()

    // Suricata real-time file watch
    private var suricataSource:     DispatchSourceFileSystemObject?
    private var suricataHandle:     FileHandle?
    private var suricataFileOffset: UInt64 = 0

    private static let maxStoredEvents = 5000
    private static let captureFile     = "/private/tmp/phantom-capture.pcap"
    private static let captureDuration = 10  // seconds per live capture window
    private static let refreshInterval: TimeInterval = 30

    // MARK: - Init

    init() {
        toolStatus = Self.checkTools()
        syncAvailability()

        // Wire LogWatcher → Suricata poll fallback.
        // Every 5 s it checks for new EVE log entries when the DispatchSource stream
        // is not yet active (Suricata not installed as daemon, log file appearing mid-run, etc.)
        logWatcher.onChange = { [weak self] in
            guard let self, self.suricataSource == nil, self.toolStatus.suricata else { return }
            Task { [weak self] in
                guard let self else { return }
                let ev = await self.scanWorker.recentSuricataEvents(lookbackSeconds: 300)
                if !ev.isEmpty { self.mergeNewEvents(ev, from: .suricata) }
            }
        }
        logWatcher.startWatching()

        // Auto-start Suricata stream immediately — pure file-watch, no root needed.
        // Begins capturing EVE log events before the user even visits the Network Intel tab.
        startSuricataStream()
    }

    // Sync ToolAvailability → toolActivity.isAvailable
    private func syncAvailability() {
        setAvailable(.tshark,       toolStatus.tshark)
        setAvailable(.wireshark,    toolStatus.tshark)   // same binary
        setAvailable(.tcpdump,      toolStatus.tcpdump)
        setAvailable(.zeek,         toolStatus.zeek)
        setAvailable(.suricata,     toolStatus.suricata)
        setAvailable(.ngrep,        toolStatus.ngrep)
        setAvailable(.networkMiner, toolStatus.tshark)   // uses tshark
    }

    private func setAvailable(_ tool: PacketTool, _ available: Bool) {
        toolActivity[tool]?.isAvailable = available
        if !available { toolActivity[tool]?.statusText = "Not installed" }
    }

    // MARK: - Tool availability check

    static func checkTools() -> ToolAvailability {
        let tsharkPaths  = ["/opt/homebrew/bin/tshark", "/usr/local/bin/tshark",
                            "/Applications/Wireshark.app/Contents/MacOS/tshark"]
        let zeekPaths    = ["/opt/homebrew/bin/zeek", "/usr/local/bin/zeek", "/opt/zeek/bin/zeek"]
        let ngrepPaths   = ["/opt/homebrew/bin/ngrep", "/usr/local/bin/ngrep"]
        let suricataLogs = ["/var/log/suricata/eve.json",
                            "/opt/homebrew/var/log/suricata/eve.json",
                            "/usr/local/var/log/suricata/eve.json"]
        return ToolAvailability(
            tshark:   tsharkPaths.contains  { FileManager.default.isExecutableFile(atPath: $0) },
            tcpdump:  FileManager.default.isExecutableFile(atPath: "/usr/sbin/tcpdump"),
            zeek:     zeekPaths.contains    { FileManager.default.isExecutableFile(atPath: $0) },
            suricata: suricataLogs.contains { FileManager.default.fileExists(atPath: $0) },
            ngrep:    ngrepPaths.contains   { FileManager.default.isExecutableFile(atPath: $0) }
        )
    }

    func refreshToolStatus() {
        toolStatus = Self.checkTools()
        syncAvailability()
    }

    // MARK: - Suricata real-time stream

    /// Opens the Suricata EVE log and watches it with DispatchSource.
    /// Every time Suricata writes a new line the handler fires immediately —
    /// no polling, no wait.
    func startSuricataStream() {
        guard toolStatus.suricata, suricataSource == nil else { return }
        // Fetch the log path from the actor synchronously via a detached task.
        // We store it as a local capture for the DispatchSource handler below.
        Task {
            guard let path = await scanWorker.suricataLogPath else { return }
            self.openSuricataSource(path: path)
        }
    }

    private func openSuricataSource(path: String) {
        guard suricataSource == nil else { return }

        guard let fh = FileHandle(forReadingAtPath: path) else { return }
        // Start from the end so we only see new events going forward
        suricataFileOffset = fh.seekToEndOfFile()
        suricataHandle = fh

        let src = DispatchSource.makeFileSystemObjectSource(
            fileDescriptor: fh.fileDescriptor,
            eventMask: .write,
            queue: DispatchQueue.global(qos: .utility)
        )
        src.setEventHandler { [weak self] in
            self?.handleSuricataData()
        }
        src.setCancelHandler { [weak self] in
            self?.suricataHandle = nil
        }
        src.resume()
        suricataSource = src

        toolActivity[.suricata]?.statusText = "Streaming"
        toolActivity[.suricata]?.isRunning  = true
        logger.info("PacketCaptureEngine: Suricata stream started at offset \(self.suricataFileOffset)")
    }

    func stopSuricataStream() {
        suricataSource?.cancel()
        suricataSource = nil
        try? suricataHandle?.close()
        suricataHandle = nil
        toolActivity[.suricata]?.isRunning  = false
        toolActivity[.suricata]?.statusText = "Idle"
    }

    private func handleSuricataData() {
        guard let fh = suricataHandle else { return }
        fh.seek(toFileOffset: suricataFileOffset)
        let data = fh.readDataToEndOfFile()
        suricataFileOffset += UInt64(data.count)
        guard !data.isEmpty, let text = String(data: data, encoding: .utf8) else { return }

        let lines  = text.components(separatedBy: "\n").filter { !$0.isEmpty }
        let cutoff = Date().addingTimeInterval(-3600)
        let worker = scanWorker

        Task { [weak self] in
            guard let self else { return }
            var events: [PacketEvent] = []
            for line in lines {
                if let ev = await worker.parseSuricataLine(line, cutoff: cutoff) {
                    events.append(ev)
                }
            }
            guard !events.isEmpty else { return }
            await MainActor.run { [weak self] in
                guard let self else { return }
                self.mergeNewEvents(events, from: .suricata)
                self.logger.info("PacketCaptureEngine: Suricata stream → \(events.count) new events")
            }
        }
    }

    // MARK: - Auto-refresh (Suricata log poll, fallback when stream is unavailable)

    func startAutoRefresh() {
        guard refreshTimer == nil else { return }
        refreshTimer = Timer.scheduledTimer(
            withTimeInterval: Self.refreshInterval, repeats: true
        ) { [weak self] _ in
            Task { @MainActor [weak self] in
                guard let self, !self.isAnalyzing, !self.isLiveCapturing else { return }
                _ = await self.scan()
            }
        }
    }

    func stopAutoRefresh() {
        refreshTimer?.invalidate()
        refreshTimer = nil
    }

    // MARK: - Live continuous pcap capture

    func startLiveCapture(interface: String = "en0") {
        guard !isLiveCapturing else { return }
        isLiveCapturing = true
        liveStatus = "Starting…"
        stopAutoRefresh()
        startSuricataStream()   // also start real-time Suricata stream

        liveTask = Task { await liveCaptureLoop(interface: interface) }
    }

    func stopLiveCapture() {
        liveTask?.cancel()
        liveTask = nil
        isLiveCapturing = false
        liveStatus = ""
        // NOTE: Suricata stream keeps running — it auto-started at init and must
        // remain active between live-capture sessions so no EVE events are missed.
        startAutoRefresh()
        // Mark pcap tools as idle
        for tool in [PacketTool.tshark, .wireshark, .tcpdump, .zeek, .ngrep, .networkMiner] {
            toolActivity[tool]?.isRunning  = false
            toolActivity[tool]?.statusText = "Idle"
        }
    }

    private func liveCaptureLoop(interface: String) async {
        let helper = PrivilegedHelperClient.shared

        // Initial Suricata load (gets history before the stream catches up)
        liveStatus = "Loading Suricata history…"
        if toolStatus.suricata, suricataSource == nil {
            let ev = await scanWorker.recentSuricataEvents(lookbackSeconds: 3600)
            mergeNewEvents(ev, from: .suricata)
            markTool(.suricata, running: false, status: "Streaming",
                     count: (toolActivity[.suricata]?.eventCount ?? 0) + ev.count)
        }

        while !Task.isCancelled {
            // Kick off a pcap capture window
            liveStatus = "Capturing \(interface) (\(Self.captureDuration)s)…"
            markPcapTools(running: true, status: "Capturing…")

            do {
                let pcapPath = try await helper.capturePackets(
                    interface: interface,
                    durationSeconds: Self.captureDuration,
                    outputPath: Self.captureFile
                )
                if Task.isCancelled { break }

                if let p = pcapPath {
                    liveStatus = "Analyzing…"
                    let pcapEvents = await analyzePcap(at: p)
                    lastScanDate = Date()
                    logger.info("PacketCaptureEngine: live cycle — \(pcapEvents.count) pcap events")
                } else {
                    lastError = "Capture returned no file — is the privileged helper installed?"
                    markPcapTools(running: false, status: "No output")
                }
            } catch {
                lastError = "Capture error: \(error.localizedDescription)"
                markPcapTools(running: false, status: "Error")
                try? await Task.sleep(nanoseconds: 5_000_000_000)
            }

            if Task.isCancelled { break }
            liveStatus = "Live ● next capture in 2s"
            markPcapTools(running: false, status: "Waiting…")
            try? await Task.sleep(nanoseconds: 2_000_000_000)
        }

        await MainActor.run {
            isLiveCapturing = false
            liveStatus = ""
        }
    }

    private func markPcapTools(running: Bool, status: String) {
        for tool in [PacketTool.tshark, .wireshark, .tcpdump, .zeek, .ngrep, .networkMiner] {
            guard toolActivity[tool]?.isAvailable == true else { continue }
            toolActivity[tool]?.isRunning  = running
            toolActivity[tool]?.statusText = status
        }
    }

    // MARK: - Main scan entry point

    func scan(pcapPath: String? = nil) async -> [Incident] {
        guard !isAnalyzing else { return [] }
        isAnalyzing = true
        lastError   = nil
        defer {
            isAnalyzing  = false
            lastScanDate = Date()
        }

        var allNew: [PacketEvent] = []

        // --- Suricata (only poll-scan here if the stream is NOT running) ---
        if toolStatus.suricata && suricataSource == nil {
            markTool(.suricata, running: true, status: "Reading EVE log…")
            let events = await scanWorker.recentSuricataEvents(lookbackSeconds: 3600)
            mergeNewEvents(events, from: .suricata)
            allNew += events
            markTool(.suricata, running: false, status: "Idle",
                     count: (toolActivity[.suricata]?.eventCount ?? 0) + events.count)
        }

        // --- pcap tools ---
        let pcap = pcapPath ?? (FileManager.default.fileExists(atPath: Self.captureFile)
                                ? Self.captureFile : nil)
        if let p = pcap {
            let pcapEvents = await analyzePcap(at: p)
            allNew += pcapEvents
        }

        logger.info("PacketCaptureEngine: scan complete — \(allNew.count) new events total")
        return buildIncidents(from: allNew)
    }

    // MARK: - pcap analysis (parallel, per-tool state updates)

    private func analyzePcap(at pcapPath: String) async -> [PacketEvent] {
        // All scanner calls go through scanWorker (an actor) — they run on its
        // background executor, so the main thread is never blocked.
        let worker = scanWorker
        let status = toolStatus
        let logger = self.logger

        return await withTaskGroup(of: (PacketTool, [PacketEvent]).self) { group in

            if status.tshark {
                group.addTask {
                    await MainActor.run { self.markTool(.tshark, running: true, status: "Analyzing…") }
                    let ev = await worker.runTShark(pcapPath: pcapPath)
                    await MainActor.run { self.markTool(.tshark, running: false, status: "Done",
                        count: (self.toolActivity[.tshark]?.eventCount ?? 0) + ev.count) }
                    return (.tshark, ev)
                }
            }

            if status.tcpdump {
                group.addTask {
                    await MainActor.run { self.markTool(.tcpdump, running: true, status: "Reading pcap…") }
                    let ev = await worker.runTcpdump(pcapPath: pcapPath)
                    await MainActor.run { self.markTool(.tcpdump, running: false, status: "Done",
                        count: (self.toolActivity[.tcpdump]?.eventCount ?? 0) + ev.count) }
                    return (.tcpdump, ev)
                }
            }

            if status.zeek {
                group.addTask {
                    await MainActor.run { self.markTool(.zeek, running: true, status: "Analyzing…") }
                    let ev = await worker.runZeek(pcapPath: pcapPath)
                    await MainActor.run { self.markTool(.zeek, running: false, status: "Done",
                        count: (self.toolActivity[.zeek]?.eventCount ?? 0) + ev.count) }
                    return (.zeek, ev)
                }
            }

            if status.ngrep {
                group.addTask {
                    await MainActor.run { self.markTool(.ngrep, running: true, status: "Scanning signatures…") }
                    let ev = await worker.runNgrep(pcapPath: pcapPath)
                    await MainActor.run { self.markTool(.ngrep, running: false, status: "Done",
                        count: (self.toolActivity[.ngrep]?.eventCount ?? 0) + ev.count) }
                    return (.ngrep, ev)
                }
            }

            if status.tshark {
                group.addTask {
                    await MainActor.run { self.markTool(.networkMiner, running: true, status: "Extracting artifacts…") }
                    let ev = await worker.runNetworkMiner(pcapPath: pcapPath)
                    await MainActor.run { self.markTool(.networkMiner, running: false, status: "Done",
                        count: (self.toolActivity[.networkMiner]?.eventCount ?? 0) + ev.count) }
                    return (.networkMiner, ev)
                }
            }

            var all: [PacketEvent] = []
            for await (tool, events) in group {
                logger.info("PacketCaptureEngine: \(tool.displayName) → \(events.count) events")
                await MainActor.run { self.mergeNewEvents(events, from: tool) }
                all += events
            }
            return all
        }
    }

    // MARK: - Helpers

    private func mergeNewEvents(_ events: [PacketEvent], from tool: PacketTool) {
        guard !events.isEmpty else { return }
        let merged = (events + packetEvents).sorted { $0.timestamp > $1.timestamp }
        packetEvents = Array(merged.prefix(Self.maxStoredEvents))
    }

    private func markTool(_ tool: PacketTool, running: Bool, status: String, count: Int? = nil) {
        toolActivity[tool]?.isRunning  = running
        toolActivity[tool]?.statusText = status
        toolActivity[tool]?.lastRun    = running ? toolActivity[tool]?.lastRun : Date()
        if let c = count { toolActivity[tool]?.eventCount = c }
    }

    // MARK: - Clear

    func clearEvents() {
        packetEvents = []
        for tool in PacketTool.allCases {
            toolActivity[tool]?.eventCount = 0
            toolActivity[tool]?.statusText = "Idle"
        }
        logger.info("PacketCaptureEngine: events cleared")
    }

    // MARK: - Filtered views

    var alertEvents: [PacketEvent] {
        packetEvents.filter { $0.category == .alert || $0.category == .patternMatch || $0.category == .suspicious }
    }
    var artifactEvents: [PacketEvent] {
        packetEvents.filter { $0.category == .artifact }
    }
    var dnsEvents: [PacketEvent] {
        packetEvents.filter { $0.category == .dns }
    }
    var connectionEvents: [PacketEvent] {
        packetEvents.filter { $0.category == .connection }
    }
    var highSeverityCount: Int {
        packetEvents.filter { $0.severity == .high }.count
    }
    func events(for tool: PacketTool) -> [PacketEvent] {
        packetEvents.filter { $0.tool == tool }
    }

    // MARK: - Build Incidents

    private func buildIncidents(from events: [PacketEvent]) -> [Incident] {
        var incidents: [Incident] = []

        for ev in events.filter({ $0.tool == .suricata && $0.category == .alert }).prefix(10) {
            incidents.append(Incident(
                name: ev.signatureName ?? ev.summary,
                severity: ev.severity, confidence: .high,
                detail: ev.detail, source: .network,
                technique: .applicationLayerProtocol, trust: .suspicious,
                recommendedAction: "Investigate Suricata alert. Verify if source IP should be blocked.",
                whySurfaced: "Suricata IDS matched a known threat signature" + (ev.signatureID.map { " (SID \($0))" } ?? "") + ".",
                evidence: buildEvidence(from: ev)))
        }
        for ev in events.filter({ $0.tool == .ngrep && $0.severity != .low }).prefix(10) {
            incidents.append(Incident(
                name: ev.summary, severity: ev.severity, confidence: .medium,
                detail: ev.detail, source: .network,
                technique: .applicationLayerProtocol, trust: .suspicious,
                recommendedAction: "Review matched payload. Isolate host if malicious.",
                whySurfaced: "ngrep detected a known threat signature in network traffic.",
                evidence: buildEvidence(from: ev)))
        }
        let suspDNS = events.filter { $0.category == .dns && $0.severity == .high }
        if !suspDNS.isEmpty {
            incidents.append(Incident(
                name: "Suspicious DNS — possible DGA or tunneling (\(suspDNS.count))",
                severity: .high, confidence: .medium,
                detail: suspDNS.prefix(3).map { $0.dnsQuery ?? $0.summary }.joined(separator: ", "),
                source: .network, technique: .applicationLayerProtocol, trust: .suspicious,
                recommendedAction: "Block domains at DNS resolver. Investigate querying process.",
                whySurfaced: "High-entropy domain names consistent with DGA or DNS tunneling.",
                evidence: suspDNS.prefix(3).flatMap { buildEvidence(from: $0) }))
        }
        for ev in events.filter({ $0.category == .artifact && $0.severity == .high }).prefix(5) {
            incidents.append(Incident(
                name: ev.summary, severity: .high, confidence: .high,
                detail: ev.detail, source: .network,
                technique: .unsecuredCredentials, trust: .suspicious,
                recommendedAction: "Rotate exposed credentials. Migrate to encrypted protocol.",
                whySurfaced: "Cleartext credentials found in network traffic.",
                evidence: buildEvidence(from: ev)))
        }
        let suspTLS = events.filter { $0.category == .tls && $0.severity == .medium }
        if !suspTLS.isEmpty {
            incidents.append(Incident(
                name: "Suspicious TLS certificates (\(suspTLS.count) connections)",
                severity: .medium, confidence: .medium,
                detail: "Self-signed or mismatched certificates in TLS handshakes",
                source: .network, technique: .encryptedChannel, trust: .unclassified,
                recommendedAction: "Verify certificate legitimacy. Self-signed certs on unusual destinations may indicate C2.",
                whySurfaced: "tshark/Zeek detected TLS with self-signed certificates.",
                evidence: suspTLS.prefix(3).flatMap { buildEvidence(from: $0) }))
        }
        for ev in events.filter({ $0.tool == .zeek && $0.category == .alert }).prefix(5) {
            incidents.append(Incident(
                name: "Zeek Notice: \(ev.signatureName ?? "Network anomaly")",
                severity: .high, confidence: .high,
                detail: ev.detail, source: .network,
                technique: .applicationLayerProtocol, trust: .suspicious,
                recommendedAction: "Investigate Zeek notice. Check for port scans, brute force, or C2 beaconing.",
                whySurfaced: "Zeek intelligence framework generated a notice.",
                evidence: buildEvidence(from: ev)))
        }
        return incidents
    }

    private func buildEvidence(from ev: PacketEvent) -> [IncidentEvidence] {
        var e: [IncidentEvidence] = []
        e.append(.init(label: "Tool",      value: ev.tool.displayName))
        e.append(.init(label: "Category",  value: ev.category.title))
        e.append(.init(label: "Timestamp", value: ISO8601DateFormatter().string(from: ev.timestamp)))
        if let v = ev.sourceIP        { e.append(.init(label: "Source IP",   value: v)) }
        if let v = ev.destinationIP   { e.append(.init(label: "Dest IP",     value: v)) }
        if let v = ev.destinationPort { e.append(.init(label: "Dest Port",   value: String(v))) }
        if let v = ev.proto           { e.append(.init(label: "Protocol",    value: v)) }
        if let v = ev.signatureName   { e.append(.init(label: "Signature",   value: v)) }
        if let v = ev.signatureID     { e.append(.init(label: "SID",         value: v)) }
        if let v = ev.httpURL         { e.append(.init(label: "URL",         value: v)) }
        if let v = ev.dnsQuery        { e.append(.init(label: "DNS Query",   value: v)) }
        if let v = ev.tlsSubject      { e.append(.init(label: "TLS Subject", value: v)) }
        if let v = ev.artifact        { e.append(.init(label: "Artifact",    value: v)) }
        return e
    }
}
