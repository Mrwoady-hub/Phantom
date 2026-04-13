import Foundation

// MARK: - AuditAction
//
// IMPORTANT: `title` and `tint` are defined as extensions in
// AuditPresentationExtensions_.swift. Do NOT add them here —
// defining them in two places causes "invalid redeclaration".

enum AuditAction: String, Codable, Sendable {
    case monitoringStarted
    case monitoringStopped
    case settingsUpdated
    case incidentsExported
    case incidentsCleared
    case incidentDetected
    case incidentResolved
    case incidentAcknowledged
    case incidentSuppressed
}

// MARK: - AuditEvent

struct AuditEvent: Identifiable, Codable, Sendable {
    let id: UUID
    let timestamp: Date
    let sequenceNumber: Int
    let action: AuditAction
    let incidentFamily: String?
    let incidentName: String?
    let details: String
    let operatorName: String
    let hostName: String
    let previousHash: String?
    let eventHash: String?

    init(
        id: UUID = UUID(),
        timestamp: Date,
        sequenceNumber: Int = 0,
        action: AuditAction,
        incidentFamily: String? = nil,
        incidentName: String? = nil,
        details: String,
        operatorName: String,
        hostName: String = Host.current().localizedName ?? "Unknown Host",
        previousHash: String? = nil,
        eventHash: String? = nil
    ) {
        self.id             = id
        self.timestamp      = timestamp
        self.sequenceNumber = sequenceNumber
        self.action         = action
        self.incidentFamily = incidentFamily
        self.incidentName   = incidentName
        self.details        = details
        self.operatorName   = operatorName
        self.hostName       = hostName
        self.previousHash   = previousHash
        self.eventHash      = eventHash
    }

    private enum CodingKeys: String, CodingKey {
        case id, timestamp, sequenceNumber, action
        case incidentFamily, incidentName, details
        case operatorName, hostName, previousHash, eventHash
    }

    // Custom decoder: decodeIfPresent on all optional/added fields so records
    // persisted before the hash-chain migration decode without throwing.
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id             = try c.decodeIfPresent(UUID.self,       forKey: .id)             ?? UUID()
        timestamp      = try c.decode(Date.self,                forKey: .timestamp)
        sequenceNumber = try c.decodeIfPresent(Int.self,        forKey: .sequenceNumber) ?? 0
        action         = try c.decode(AuditAction.self,         forKey: .action)
        incidentFamily = try c.decodeIfPresent(String.self,     forKey: .incidentFamily)
        incidentName   = try c.decodeIfPresent(String.self,     forKey: .incidentName)
        details        = try c.decode(String.self,              forKey: .details)
        operatorName   = try c.decodeIfPresent(String.self,     forKey: .operatorName)   ?? "Unknown Operator"
        hostName       = try c.decodeIfPresent(String.self,     forKey: .hostName)       ?? "Unknown Host"
        previousHash   = try c.decodeIfPresent(String.self,     forKey: .previousHash)
        eventHash      = try c.decodeIfPresent(String.self,     forKey: .eventHash)
    }
}
