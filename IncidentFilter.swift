import Foundation

enum IncidentFilter: String, CaseIterable, Identifiable {
    case all
    case process
    case network
    case persistence
    case other

    var id: String { rawValue }

    var title: String {
        switch self {
        case .all: return "All"
        case .process: return "Process"
        case .network: return "Network"
        case .persistence: return "Persistence"
        case .other: return "Other"
        }
    }
}
