import SwiftUI

extension IncidentTrust {
    var explanation: String {
        switch self {
        case .trustedSystem:
            return "This activity aligns with a trusted system component or service."
        case .knownApplication:
            return "This activity appears tied to a known third-party application."
        case .unclassified:
            return "This activity has not yet been classified as trusted or suspicious."
        case .suspicious:
            return "This activity matches a higher-risk pattern and warrants review."
        }
    }
}
