import Foundation

struct TimelineEvent: Identifiable, Hashable, Codable, Sendable {
    let id: UUID
    let timestamp: Date
    let title: String
    let detail: String?
    let symbol: String

    init(
        id: UUID = UUID(),
        timestamp: Date,
        title: String,
        detail: String? = nil,
        symbol: String
    ) {
        self.id = id
        self.timestamp = timestamp
        self.title = title
        self.detail = detail
        self.symbol = symbol
    }
}
