import SwiftUI

extension IncidentStatus {
    var title: String {
        switch self {
        case .active: return "Active"
        case .resolved: return "Resolved"
        }
    }

    var tint: Color {
        switch self {
        case .active: return .red
        case .resolved: return .green
        }
    }
}

extension IncidentSource {
    var title: String {
        switch self {
        case .process: return "Process"
        case .network: return "Network"
        case .persistence: return "Persistence"
        case .log: return "Log"
        case .unknown: return "Unknown"
        }
    }

    var symbol: String {
        switch self {
        case .process: return "terminal.fill"
        case .network: return "network"
        case .persistence: return "externaldrive.fill.badge.checkmark"
        case .log: return "doc.text.magnifyingglass"
        case .unknown: return "questionmark.circle"
        }
    }
}

extension IncidentTrust {
    var title: String {
        switch self {
        case .trustedSystem: return "Trusted"
        case .knownApplication: return "Known App"
        case .unclassified: return "Unclassified"
        case .suspicious: return "Suspicious"
        }
    }

    var tint: Color {
        switch self {
        case .trustedSystem: return .green
        case .knownApplication: return .blue
        case .unclassified: return .orange
        case .suspicious: return .red
        }
    }
}
