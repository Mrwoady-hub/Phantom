import SwiftUI

extension Severity {
    var title: String {
        String(describing: self)
            .replacingOccurrences(of: "_", with: " ")
            .capitalized
    }
}

// SwiftUI-specific helpers — isolated to @MainActor so Color usage
// does not propagate @MainActor inference to the Severity type itself.
@MainActor
extension Severity {
    var tint: Color {
        switch self {
        case .high:   return .red
        case .medium: return .orange
        case .low:    return .blue
        }
    }
}
