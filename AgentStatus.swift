import SwiftUI

enum AgentStatus: String, Codable, CaseIterable, Sendable {
    case unknown
    case running
    case stopped
    case warning
    case error

    var title: String {
        rawValue.capitalized
    }

    var tint: Color {
        switch self {
        case .running:
            return .green
        case .warning:
            return .orange
        case .stopped:
            return .gray
        case .error:
            return .red
        case .unknown:
            return .blue
        }
    }

    var menuBarSymbol: String {
        switch self {
        case .running:
            return "shield.fill"
        case .warning:
            return "exclamationmark.shield.fill"
        case .stopped:
            return "pause.circle.fill"
        case .error:
            return "xmark.shield.fill"
        case .unknown:
            return "shield"
        }
    }
}
