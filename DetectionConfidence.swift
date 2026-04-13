import SwiftUI

enum DetectionConfidence: String, Codable, CaseIterable, Hashable, Sendable {
    case low
    case medium
    case high

    var title: String {
        rawValue.capitalized
    }

    var tint: Color {
        switch self {
        case .low:
            return .gray
        case .medium:
            return .orange
        case .high:
            return .green
        }
    }
}
