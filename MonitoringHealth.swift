import Foundation

enum HealthStatus: String, Codable, Sendable {
    case healthy
    case degraded
    case failed
    case offline
}

struct MonitoringHealth: Codable, Sendable {
    let status: HealthStatus
    let isRunning: Bool
    let lastEventAt: Date?
    let lastSuccessfulScanAt: Date?
    let permissionState: PermissionState
    let ingestionHealthy: Bool
    let persistenceHealthy: Bool
    let degradationReasons: [String]
}
