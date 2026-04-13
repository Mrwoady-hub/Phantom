import Foundation

struct SuppressionRule: Identifiable, Codable, Sendable {
    let id: UUID
    let createdAt: Date
    let expiresAt: Date?
    let reason: String
    let executablePath: String?
    let teamIdentifier: String?
    let bundleIdentifier: String?
    let incidentName: String?
}
