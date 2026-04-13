import Foundation

/// Lightweight snapshot of a single completed scan, persisted for trend analysis.
/// One record is written after every successful telemetry capture.
struct ScanRecord: Identifiable, Codable, Sendable {
    let id: UUID
    let timestamp: Date

    // Aggregate scores & counts at scan completion time
    let riskScore: Int
    let activeCount: Int
    let resolvedCount: Int

    // Severity breakdown of active incidents
    let highCount: Int
    let mediumCount: Int
    let lowCount: Int

    init(
        id: UUID = UUID(),
        timestamp: Date = Date(),
        riskScore: Int,
        activeCount: Int,
        resolvedCount: Int,
        highCount: Int,
        mediumCount: Int,
        lowCount: Int
    ) {
        self.id            = id
        self.timestamp     = timestamp
        self.riskScore     = riskScore
        self.activeCount   = activeCount
        self.resolvedCount = resolvedCount
        self.highCount     = highCount
        self.mediumCount   = mediumCount
        self.lowCount      = lowCount
    }
}
