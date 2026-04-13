import Foundation

enum IncidentStateFilter: String, CaseIterable, Identifiable {
    case active
    case resolved
    case all

    var id: String { rawValue }

    var title: String {
        switch self {
        case .active: return "Active"
        case .resolved: return "Resolved"
        case .all: return "All"
        }
    }
}
