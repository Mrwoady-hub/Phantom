import SwiftUI

extension AuditAction {
    var title: String {
        switch self {
        case .monitoringStarted: return "Monitoring Started"
        case .monitoringStopped: return "Monitoring Stopped"
        case .settingsUpdated: return "Settings Updated"
        case .incidentsExported: return "Incidents Exported"
        case .incidentsCleared: return "Incidents Cleared"
        case .incidentDetected: return "Incident Detected"
        case .incidentResolved: return "Incident Resolved"
        case .incidentAcknowledged: return "Incident Acknowledged"
        case .incidentSuppressed: return "Incident Suppressed"
        }
    }

    var tint: Color {
        switch self {
        case .monitoringStarted, .incidentDetected:
            return .green
        case .monitoringStopped, .incidentResolved:
            return .gray
        case .settingsUpdated, .incidentsExported:
            return .blue
        case .incidentAcknowledged:
            return .orange
        case .incidentSuppressed, .incidentsCleared:
            return .red
        }
    }
}
