import Foundation

enum IncidentSource: String, Codable, CaseIterable, Hashable, Sendable {
    case process
    case network
    case persistence
    case log
    case unknown
}

enum IncidentStatus: String, Codable, CaseIterable, Hashable, Sendable {
    case active
    case resolved
}

enum IncidentTrust: String, Codable, CaseIterable, Hashable, Sendable {
    case trustedSystem
    case knownApplication
    case unclassified
    case suspicious
}

struct IncidentEvidence: Identifiable, Codable, Hashable, Sendable {
    let id: UUID
    let label: String
    let value: String

    init(id: UUID = UUID(), label: String, value: String) {
        self.id = id
        self.label = label
        self.value = value
    }
}

struct Incident: Identifiable, Codable, Hashable, Sendable {
    let id: UUID
    let name: String
    let severity: Severity
    let confidence: DetectionConfidence
    let detail: String?
    let source: IncidentSource
    let technique: MitreTechnique?

    var firstSeen: Date
    var lastSeen: Date
    var occurrenceCount: Int
    var status: IncidentStatus
    var score: Int

    var trust: IncidentTrust
    var family: String
    var suppressionKey: String
    var recommendedAction: String
    var whySurfaced: String
    var evidence: [IncidentEvidence]
    var rawDetail: String?
    var acknowledgedAt: Date?
    var suppressedAt: Date?
    var expectedAt: Date?
    var analystNote: String?

    var timestamp: Date { lastSeen }
    var isSuppressed: Bool { suppressedAt != nil }
    var isAcknowledged: Bool { acknowledgedAt != nil }
    var isExpected: Bool { expectedAt != nil }

    init(
        id: UUID = UUID(),
        name: String,
        severity: Severity,
        confidence: DetectionConfidence = .medium,
        detail: String? = nil,
        source: IncidentSource = .unknown,
        technique: MitreTechnique? = nil,
        firstSeen: Date = Date(),
        lastSeen: Date = Date(),
        occurrenceCount: Int = 1,
        status: IncidentStatus = .active,
        score: Int? = nil,
        trust: IncidentTrust = .unclassified,
        family: String? = nil,
        suppressionKey: String? = nil,
        recommendedAction: String? = nil,
        whySurfaced: String? = nil,
        evidence: [IncidentEvidence] = [],
        rawDetail: String? = nil,
        acknowledgedAt: Date? = nil,
        suppressedAt: Date? = nil,
        expectedAt: Date? = nil,
        analystNote: String? = nil
    ) {
        self.id = id
        self.name = name
        self.severity = severity
        self.confidence = confidence
        self.detail = detail
        self.source = source
        self.technique = technique
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen
        self.occurrenceCount = occurrenceCount
        self.status = status
        self.score = score ?? Self.defaultScore(for: severity, confidence: confidence)

        self.trust = trust
        self.family = family ?? Self.defaultFamily(name: name, source: source, technique: technique)
        self.suppressionKey = suppressionKey ?? Self.defaultSuppressionKey(
            source: source,
            name: name,
            technique: technique,
            trust: trust
        )
        self.recommendedAction = recommendedAction ?? Self.defaultRecommendedAction(for: source)
        self.whySurfaced = whySurfaced ?? Self.defaultWhySurfaced(for: source, trust: trust)
        self.evidence = evidence
        self.rawDetail = rawDetail
        self.acknowledgedAt = acknowledgedAt
        self.suppressedAt = suppressedAt
        self.expectedAt = expectedAt
        self.analystNote = analystNote
    }

    mutating func refreshSeen(at date: Date = Date(), occurrenceIncrement: Int = 1) {
        lastSeen = date
        occurrenceCount += max(occurrenceIncrement, 0)
        status = .active
    }

    mutating func resolve(at date: Date = Date()) {
        status = .resolved
        lastSeen = date
    }

    mutating func acknowledge(at date: Date = Date()) {
        acknowledgedAt = date
    }

    mutating func suppress(at date: Date = Date()) {
        suppressedAt = date
    }

    mutating func markExpected(at date: Date = Date()) {
        expectedAt = date
    }

    mutating func clearExpected() {
        expectedAt = nil
    }

    private static func defaultScore(
        for severity: Severity,
        confidence: DetectionConfidence
    ) -> Int {
        let base: Int
        switch severity {
        case .low: base = 10
        case .medium: base = 25
        case .high: base = 50
        }

        let multiplier: Double
        switch confidence {
        case .low: multiplier = 0.6
        case .medium: multiplier = 1.0
        case .high: multiplier = 1.3
        }

        return Int(Double(base) * multiplier)
    }

    private static func defaultFamily(
        name: String,
        source: IncidentSource,
        technique: MitreTechnique?
    ) -> String {
        [
            source.rawValue,
            normalizedKeyComponent(name),
            technique?.rawValue.lowercased() ?? "none"
        ].joined(separator: "|")
    }

    private static func defaultSuppressionKey(
        source: IncidentSource,
        name: String,
        technique: MitreTechnique?,
        trust: IncidentTrust
    ) -> String {
        [
            source.rawValue,
            normalizedKeyComponent(name),
            technique?.rawValue.lowercased() ?? "none",
            trust.rawValue
        ].joined(separator: "::")
    }

    private static func defaultRecommendedAction(for source: IncidentSource) -> String {
        switch source {
        case .process:
            return "Review parent process, executable path, and user context."
        case .network:
            return "Inspect remote endpoint, listener state, and owning process."
        case .persistence:
            return "Verify whether the persistence item is expected and signed by a trusted source."
        case .log:
            return "Correlate this event with nearby process or network activity."
        case .unknown:
            return "Collect additional context before taking action."
        }
    }

    private static func defaultWhySurfaced(for source: IncidentSource, trust: IncidentTrust) -> String {
        switch (source, trust) {
        case (.process, .suspicious):
            return "A suspicious process was observed and ranked highly due to tool profile and execution context."
        case (.network, .suspicious):
            return "External network activity was observed from a suspicious process."
        case (.network, .unclassified):
            return "External network activity was observed from an unclassified process."
        case (.persistence, _):
            return "A persistence item was observed outside Apple-managed defaults."
        case (_, .trustedSystem):
            return "Surfaced for visibility due to repeated activity, but trust context lowers priority."
        case (_, .knownApplication):
            return "Surfaced because repeated activity was observed from a known application."
        default:
            return "Surfaced because the activity could not be confidently classified as expected."
        }
    }

    private static func normalizedKeyComponent(_ value: String) -> String {
        value
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
            .split(whereSeparator: \.isWhitespace)
            .joined(separator: " ")
    }
}
