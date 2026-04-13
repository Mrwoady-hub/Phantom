import Foundation
import Combine
import AppKit                  // NSWorkspace — for runningApplications in rescanNow()
import ServiceManagement
import UniformTypeIdentifiers
import CryptoKit
import UserNotifications

@MainActor
final class AppModel: NSObject, ObservableObject {

    // MARK: - Published State

    @Published var settings = AppSettings.load()
    @Published private(set) var status: AgentStatus = .unknown
    @Published private(set) var incidents: [Incident] = []
    @Published private(set) var launches: [StartupEvent] = []
    @Published private(set) var auditTrail: [AuditEvent] = []
    @Published var lastError: String?
    @Published private(set) var isBusy = false
    @Published private(set) var riskScore: Int = 0
    @Published var selectedFilter: IncidentFilter = .all
    @Published var selectedState: IncidentStateFilter = .active
    @Published var selectedIncident: Incident?
    @Published var suppressedKeys: Set<String> = []
    @Published private(set) var auditIntegrityOK: Bool = true
    @Published private(set) var scanHistory: [ScanRecord] = []
    @Published private(set) var notificationsAuthorized: Bool = false
    @Published var health = MonitoringHealth(
        status: .offline,
        isRunning: false,
        lastEventAt: nil,
        lastSuccessfulScanAt: nil,
        permissionState: .unknown,
        ingestionHealthy: false,
        persistenceHealthy: true,
        degradationReasons: []
    )

    private let telemetryBroker = TelemetryBroker()
    private var monitoringTask: Task<Void, Never>?
    private var rescanTask: Task<Void, Never>?
    private static let maxAuditEvents = 1000

    // MARK: - Init

    override init() {
        super.init()

        // Tier 1: Upgrade from SHA-256 to HMAC-SHA256 on first run after migration.
        // Must run before verifyChain() so the resealed chain passes verification.
        AuditTrailStore.migrateToHMACIfNeeded()

        let report   = AuditTrailStore.verifyChain()
        let isLegacy = !report.isIntact
            && AuditTrailStore.load().allSatisfy { $0.sequenceNumber == 0 }
        auditIntegrityOK = report.isIntact || isLegacy

        auditTrail     = AuditTrailStore.load()
        suppressedKeys = SuppressionStore.load()
        scanHistory    = ScanHistoryStore.load()

        // Request notification permission if enabled (silently — system will
        // only show the prompt once; subsequent calls return current status).
        if settings.enableNotifications { requestNotificationPermission() }
        refreshNotificationAuthorizationStatus()

        // Tier 3: warm up threat intel feed in the background (disk cache first,
        // then async network refresh if stale — never blocks the UI).
        Task.detached(priority: .background) {
            await ThreatIntelFeed.shared.warmUp()
        }

        launches = [StartupEvent(date: Date(), process: "Phantom")]
        health   = MonitoringHealth(
            status: .degraded,
            isRunning: true,
            lastEventAt: nil,
            lastSuccessfulScanAt: nil,
            permissionState: .unknown,
            ingestionHealthy: false,
            persistenceHealthy: true,
            degradationReasons: ["Initial scan pending."]
        )
        startMonitoringLoop(triggerInitialScan: true)
    }

    deinit {
        monitoringTask?.cancel()
        rescanTask?.cancel()
    }

    // MARK: - Audit

    func auditHistory(for incident: Incident) -> [AuditEvent] {
        auditTrail.filter { $0.incidentFamily == incident.family }
    }

    // MARK: - Derived State

    private var visibleIncidents: [Incident] { incidents.filter { !isSuppressed($0) } }
    var activeIncidents: [Incident]   { visibleIncidents.filter { $0.status == .active } }
    var resolvedIncidents: [Incident] { visibleIncidents.filter { $0.status == .resolved } }
    var filteredIncidents: [Incident] { visibleIncidents.filter(matchesState).filter(matchesFilter) }
    var activeCount: Int   { activeIncidents.count }
    var resolvedCount: Int { resolvedIncidents.count }
    var launchCount: Int   { launches.count }

    var topIncident: Incident? {
        activeIncidents.max(by: { priorityScore($0) < priorityScore($1) })
    }

    var timeline: [TimelineEvent] {
        let inc = visibleIncidents.map {
            TimelineEvent(timestamp: $0.lastSeen, title: $0.name,
                          detail: $0.detail, symbol: symbol(for: $0.source))
        }
        let launch = launches.prefix(15).map {
            TimelineEvent(timestamp: $0.date, title: $0.process,
                          detail: "Observed in process inventory",
                          symbol: "bolt.horizontal.fill")
        }
        return (inc + launch).sorted { $0.timestamp > $1.timestamp }
    }

    var healthMessage: String {
        if !health.degradationReasons.isEmpty {
            return health.degradationReasons.joined(separator: " ")
        }
        switch health.status {
        case .healthy:  return "Telemetry is current."
        case .degraded: return "Telemetry is delayed or partially available."
        case .failed:   return "Telemetry collection failed."
        case .offline:  return "Monitoring is offline."
        }
    }

    // MARK: - Actions

    func saveSettings() {
        settings.scanIntervalSeconds = max(60, settings.scanIntervalSeconds)
        settings.save()
        if status == .running { restartMonitoringLoop() }
        recordAudit(.settingsUpdated, details: "Settings updated.")
    }

    func startMonitoringLoop(triggerInitialScan: Bool = false) {
        guard monitoringTask == nil else { return }
        status = .running
        health = MonitoringHealth(
            status: .degraded,
            isRunning: true,
            lastEventAt: health.lastEventAt,
            lastSuccessfulScanAt: health.lastSuccessfulScanAt,
            permissionState: health.permissionState,
            ingestionHealthy: false,
            persistenceHealthy: health.persistenceHealthy,
            degradationReasons: ["Initial scan pending."]
        )
        recordAudit(.monitoringStarted, details: "Monitoring loop started.")
        if triggerInitialScan { rescanNow() }

        monitoringTask = Task { [weak self] in
            guard let self else { return }
            while !Task.isCancelled {
                let interval  = max(60.0, self.settings.scanIntervalSeconds)
                let tolerance = interval * 0.25
                try? await Task.sleep(
                    for: .seconds(interval),
                    tolerance: .seconds(tolerance),
                    clock: .continuous
                )
                guard !Task.isCancelled else { break }
                self.rescanNow()
            }
        }
    }

    func stopMonitoringLoop() {
        monitoringTask?.cancel(); monitoringTask = nil
        rescanTask?.cancel();     rescanTask     = nil
        isBusy = false
        status = .stopped
        health = MonitoringHealth(
            status: .offline,
            isRunning: false,
            lastEventAt: health.lastEventAt,
            lastSuccessfulScanAt: health.lastSuccessfulScanAt,
            permissionState: health.permissionState,
            ingestionHealthy: false,
            persistenceHealthy: health.persistenceHealthy,
            degradationReasons: ["Monitoring stopped."]
        )
        recordAudit(.monitoringStopped, details: "Monitoring loop stopped.")
    }

    private func restartMonitoringLoop() {
        stopMonitoringLoop()
        startMonitoringLoop()
    }

    func rescanNow() {
        guard rescanTask == nil else { return }
        isBusy    = true
        lastError = nil
        health = MonitoringHealth(
            status: .degraded,
            isRunning: monitoringTask != nil,
            lastEventAt: health.lastEventAt,
            lastSuccessfulScanAt: health.lastSuccessfulScanAt,
            permissionState: health.permissionState,
            ingestionHealthy: false,
            persistenceHealthy: health.persistenceHealthy,
            degradationReasons: ["Scan in progress."]
        )

        // DEADLOCK FIX: fetch app names HERE on the main actor (synchronous, instant).
        // Passing as [String] into the detached task means the scan never needs
        // to hop back to the main actor — which was causing the infinite hang.
        let appNames: [String] = NSWorkspace.shared.runningApplications
            .compactMap { $0.localizedName }

        let broker = telemetryBroker

        rescanTask = Task.detached(priority: .utility) { [weak self, appNames] in
            let snapshot = await broker.capture(
                appNames: appNames,
                preferPrivilegedHelper: false
            )
            await self?.finishRescan(with: snapshot)
        }
    }

    @MainActor
    private func finishRescan(with snapshot: ScanSnapshot) {
        defer { isBusy = false; rescanTask = nil }

        // Capture pre-apply families so we can detect NEW incidents for notifications
        let knownFamilies = Set(incidents.map { $0.family })

        apply(snapshot: snapshot)

        health = MonitoringHealth(
            status:               .healthy,
            isRunning:            monitoringTask != nil,
            lastEventAt:          snapshot.incidents.map { $0.lastSeen }.max() ?? health.lastEventAt,
            lastSuccessfulScanAt: Date(),
            permissionState:      health.permissionState,
            ingestionHealthy:     true,
            persistenceHealthy:   auditIntegrityOK,
            degradationReasons:   []
        )

        // Record a history snapshot for trend analysis
        let active = incidents.filter { $0.status == .active && !isSuppressed($0) }
        let record = ScanRecord(
            riskScore:     riskScore,
            activeCount:   active.count,
            resolvedCount: resolvedCount,
            highCount:     active.filter { $0.severity == .high }.count,
            mediumCount:   active.filter { $0.severity == .medium }.count,
            lowCount:      active.filter { $0.severity == .low }.count
        )
        scanHistory = ScanHistoryStore.append(record)

        // Fire notifications for newly discovered high/medium incidents
        if settings.enableNotifications {
            let newIncidents = active.filter { !knownFamilies.contains($0.family) }
            sendNotifications(for: newIncidents)
        }
    }

    func clearIncidents() {
        incidents.removeAll(); launches.removeAll()
        selectedIncident = nil; riskScore = 0; lastError = nil
        recordAudit(.incidentsCleared, details: "All incidents cleared.")
    }

    func exportIncidents() {
        let panel = NSSavePanel()
        panel.canCreateDirectories = true
        panel.allowedContentTypes  = [.json]
        panel.nameFieldStringValue = "Phantom-Incidents.json"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let enc = JSONEncoder()
            enc.outputFormatting     = [.prettyPrinted, .sortedKeys]
            enc.dateEncodingStrategy = .iso8601
            try enc.encode(incidents).write(to: url, options: .atomic)
            lastError = nil
            recordAudit(.incidentsExported,
                        details: "Exported \(incidents.count) incidents to \(url.lastPathComponent).")
        } catch {
            lastError = "Export failed: \(error.localizedDescription)"
        }
    }

    func acknowledge(_ incident: Incident) {
        incidents = incidents.map { cur in
            guard cur.family == incident.family else { return cur }
            var u = cur; u.acknowledgedAt = Date(); return u
        }
        if let sel = selectedIncident, sel.family == incident.family {
            selectedIncident = incidents.first(where: { $0.family == incident.family })
        }
        riskScore = weightedRiskScore(from: incidents)
        recordAudit(.incidentAcknowledged, incident: incident,
                    details: "Incident acknowledged by operator.")
    }

    func suppress(_ incident: Incident) {
        suppressedKeys.insert(incident.suppressionKey)
        SuppressionStore.save(suppressedKeys)
        let now = Date()
        incidents = incidents.map { cur in
            guard cur.suppressionKey == incident.suppressionKey else { return cur }
            var u = cur; u.suppressedAt = now; return u
        }
        if selectedIncident?.suppressionKey == incident.suppressionKey { selectedIncident = nil }
        riskScore = weightedRiskScore(from: incidents)
        recordAudit(.incidentSuppressed, incident: incident,
                    details: "Incident suppressed by operator.")
    }

    func openIncident(_ incident: Incident) {
        selectedIncident = incidents.first(where: { $0.family == incident.family })
    }
    func closeIncident() { selectedIncident = nil }

    func installLoginItem() {
        do {
            if settings.startAtLogin { try SMAppService.mainApp.register() }
            else                     { try SMAppService.mainApp.unregister() }
            lastError = nil
            recordAudit(.settingsUpdated,
                        details: settings.startAtLogin
                            ? "Login item enabled." : "Login item disabled.")
        } catch {
            lastError = "Login item update failed: \(error.localizedDescription)"
        }
    }

    func clearSuppressionRules() {
        suppressedKeys.removeAll()
        SuppressionStore.save(suppressedKeys)
        incidents = incidents.map { var u = $0; u.suppressedAt = nil; return u }
        riskScore = weightedRiskScore(from: incidents)
        recordAudit(.settingsUpdated, details: "All suppression rules cleared.")
    }

    // MARK: - CSV Export

    func exportIncidentsAsCSV() {
        let panel = NSSavePanel()
        panel.canCreateDirectories  = true
        panel.allowedContentTypes   = [UTType(filenameExtension: "csv") ?? .data]
        panel.nameFieldStringValue  = "Phantom-Incidents.csv"
        guard panel.runModal() == .OK, let url = panel.url else { return }

        let formatter = ISO8601DateFormatter()
        var lines = ["Date,Name,Severity,Confidence,Source,Status,Trust,MITRE Technique,Score,Acknowledged,Suppressed"]
        for inc in incidents {
            let cols: [String] = [
                formatter.string(from: inc.lastSeen),
                "\"\(inc.name.replacingOccurrences(of: "\"", with: "\"\""))\"",
                inc.severity.rawValue,
                inc.confidence.rawValue,
                inc.source.rawValue,
                inc.status.rawValue,
                inc.trust.rawValue,
                inc.technique?.rawValue ?? "",
                String(inc.score),
                inc.isAcknowledged ? "Yes" : "No",
                inc.isSuppressed   ? "Yes" : "No"
            ]
            lines.append(cols.joined(separator: ","))
        }
        let csv = lines.joined(separator: "\n")
        do {
            try csv.write(to: url, atomically: true, encoding: .utf8)
            lastError = nil
            recordAudit(.incidentsExported,
                        details: "Exported \(incidents.count) incidents as CSV to \(url.lastPathComponent).")
        } catch {
            lastError = "CSV export failed: \(error.localizedDescription)"
        }
    }

    // MARK: - Notifications

    func requestNotificationPermission() {
        UNUserNotificationCenter.current().requestAuthorization(
            options: [.alert, .sound, .badge]
        ) { [weak self] granted, _ in
            DispatchQueue.main.async { self?.notificationsAuthorized = granted }
        }
    }

    func refreshNotificationAuthorizationStatus() {
        UNUserNotificationCenter.current().getNotificationSettings { [weak self] settings in
            DispatchQueue.main.async {
                self?.notificationsAuthorized =
                    settings.authorizationStatus == .authorized ||
                    settings.authorizationStatus == .provisional
            }
        }
    }

    private func sendNotifications(for newIncidents: [Incident]) {
        guard notificationsAuthorized else { return }
        // Notify on high-severity immediately; batch medium to avoid alert fatigue.
        let high   = newIncidents.filter { $0.severity == .high }
        let medium = newIncidents.filter { $0.severity == .medium }

        for inc in high.prefix(3) {
            scheduleNotification(
                identifier: inc.family,
                title: "Phantom — High Alert",
                body: inc.name,
                critical: true
            )
        }
        if !medium.isEmpty {
            scheduleNotification(
                identifier: "phantom.medium-batch.\(Date().timeIntervalSince1970)",
                title: "Phantom — \(medium.count) new finding\(medium.count == 1 ? "" : "s")",
                body: medium.prefix(2).map { $0.name }.joined(separator: ", "),
                critical: false
            )
        }
    }

    private func scheduleNotification(
        identifier: String,
        title: String,
        body: String,
        critical: Bool
    ) {
        let content        = UNMutableNotificationContent()
        content.title      = title
        content.body       = body
        content.sound      = critical ? .defaultCritical : .default
        let request = UNNotificationRequest(identifier: identifier, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request)
    }

    // MARK: - Private Helpers

    private func recordAudit(
        _ action: AuditAction,
        incident: Incident? = nil,
        details: String
    ) {
        auditTrail = AuditTrailStore.append(
            action:         action,
            incidentFamily: incident?.family,
            incidentName:   incident?.name,
            details:        details,
            operatorName:   NSUserName()
        )
        if auditTrail.count > Self.maxAuditEvents {
            auditTrail = Array(auditTrail.prefix(Self.maxAuditEvents))
        }
    }

    private func apply(snapshot: ScanSnapshot) {
            // SAFE MERGE: build the existing dictionary without crashing on duplicates.
            // If two incidents share a family key, keep the first one encountered.
            var existing: [String: Incident] = [:]
            for incident in incidents {
                if existing[incident.family] == nil {
                    existing[incident.family] = incident
                }
            }
     
            let incomingFamilies = Set(snapshot.incidents.map { $0.family })
            var merged: [Incident] = []
            var seenFamilies: Set<String> = []   // deduplicate incoming incidents too
     
            for var inc in snapshot.incidents {
                // Deduplicate within the snapshot itself — same family = skip
                guard !seenFamilies.contains(inc.family) else { continue }
                seenFamilies.insert(inc.family)
     
                if let old = existing[inc.family] {
                    inc.firstSeen      = old.firstSeen
                    inc.lastSeen       = Date()
                    inc.acknowledgedAt = old.acknowledgedAt
                    inc.suppressedAt   = old.suppressedAt
                    inc.analystNote    = old.analystNote
                }
                inc.suppressedAt = suppressedKeys.contains(inc.suppressionKey)
                    ? (inc.suppressedAt ?? Date()) : nil
                merged.append(inc)
            }
     
            for (_, var old) in existing where !incomingFamilies.contains(old.family) {
                old.status       = .resolved
                old.suppressedAt = suppressedKeys.contains(old.suppressionKey)
                    ? (old.suppressedAt ?? Date()) : nil
                merged.append(old)
            }
     
            incidents = merged.sorted(by: incidentSort)
            launches  = snapshot.launches
            riskScore = weightedRiskScore(from: incidents)
            status    = monitoringTask == nil ? .stopped : .running
     
            if let sel = selectedIncident {
                selectedIncident = incidents.first(where: {
                    $0.family == sel.family && !isSuppressed($0)
                })
            }
        }

    private func incidentSort(_ l: Incident, _ r: Incident) -> Bool {
        if l.status != r.status { return l.status == .active }
        let lp = priorityScore(l), rp = priorityScore(r)
        if lp != rp { return lp > rp }
        return l.lastSeen > r.lastSeen
    }

    private func priorityScore(_ i: Incident) -> Double {
        var s = Double(i.score) * trustWeight(for: i.trust)
        if i.acknowledgedAt != nil { s *= 0.8 }
        if i.occurrenceCount > 1 {
            s *= min(1.0 + (log(Double(i.occurrenceCount)) / log(2.0)) * 0.12, 1.35)
        }
        return s
    }

    private func weightedRiskScore(from incidents: [Incident]) -> Int {
        let active  = incidents
            .filter { $0.status == .active && !isSuppressed($0) }
            .sorted { priorityScore($0) > priorityScore($1) }
        let weights = [1.0, 0.65, 0.45, 0.30, 0.18]
        var total   = 0.0
        for (i, inc) in active.enumerated() {
            total += priorityScore(inc) * (i < weights.count ? weights[i] : 0.12)
        }
        return min(Int(total.rounded()), 100)
    }

    private func matchesFilter(_ i: Incident) -> Bool {
        switch selectedFilter {
        case .all:         return true
        case .process:     return i.source == .process
        case .network:     return i.source == .network
        case .persistence: return i.source == .persistence
        case .other:       return i.source == .log || i.source == .unknown
        }
    }

    private func matchesState(_ i: Incident) -> Bool {
        switch selectedState {
        case .all:      return true
        case .active:   return i.status == .active
        case .resolved: return i.status == .resolved
        }
    }

    private func isSuppressed(_ i: Incident) -> Bool {
        suppressedKeys.contains(i.suppressionKey) || i.isSuppressed
    }

    private func trustWeight(for trust: IncidentTrust) -> Double {
        switch trust {
        case .trustedSystem:    return 0.25
        case .knownApplication: return 0.55
        case .unclassified:     return 1.0
        case .suspicious:       return 1.25
        }
    }

    private func symbol(for source: IncidentSource) -> String {
        switch source {
        case .process:     return "terminal.fill"
        case .network:     return "network"
        case .persistence: return "externaldrive.fill.badge.checkmark"
        case .log:         return "doc.text.magnifyingglass"
        case .unknown:     return "questionmark.circle"
        }
    }
}
