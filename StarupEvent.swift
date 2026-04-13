import Foundation

struct StartupEvent: Identifiable, Hashable {
    let id = UUID()
    let date: Date
    let process: String
}
