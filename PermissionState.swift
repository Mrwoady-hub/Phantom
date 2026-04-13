import Foundation

enum PermissionState: String, Codable, Sendable {
    case granted
    case limited
    case denied
    case unknown
}
