import Foundation

extension AppModel {
    var riskLabel: String {
        switch riskScore {
        case 0...19:
            return "Minimal"
        case 20...49:
            return "Elevated"
        case 50...79:
            return "High"
        default:
            return "Critical"
        }
    }
}

extension Incident {
    var trustSummary: String {
        switch trust {
        case .trustedSystem:
            return "This activity maps to a trusted system service."
        case .knownApplication:
            return "This activity appears tied to a known application."
        case .unclassified:
            return "This activity is not yet classified as trusted or suspicious."
        case .suspicious:
            return "This activity matches a higher-risk pattern."
        }
    }
}

extension MonitoringHealth {
    var lastScanText: String {
        guard let lastSuccessfulScanAt else { return "Last scan: —" }
        return "Last scan: \(lastSuccessfulScanAt.formatted(date: .omitted, time: .shortened))"
    }

    var lastEventText: String {
        guard let lastEventAt else { return "Last event: —" }
        return "Last event: \(lastEventAt.formatted(date: .omitted, time: .shortened))"
    }

    var isStale: Bool {
        guard let lastSuccessfulScanAt else { return true }
        return Date().timeIntervalSince(lastSuccessfulScanAt) > 120
    }

    var displayStatus: HealthStatus {
        if !isRunning {
            return .offline
        }
        if status == .healthy && isStale {
            return .degraded
        }
        return status
    }
}
