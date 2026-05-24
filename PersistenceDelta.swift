import Foundation

// MARK: - PersistenceDeltaKind

enum PersistenceDeltaKind: String, Codable, Sendable {
    case added    = "Added"
    case removed  = "Removed"
    case modified = "Modified"

    /// Default severity for each kind of change.
    var severity: Severity {
        switch self {
        case .added:    return .high    // new persistence = highest signal
        case .modified: return .high    // modification = potential hijack
        case .removed:  return .medium  // removal could be cleanup or covering tracks
        }
    }

    var systemImage: String {
        switch self {
        case .added:    return "plus.circle.fill"
        case .removed:  return "minus.circle.fill"
        case .modified: return "pencil.circle.fill"
        }
    }
}

// MARK: - PersistenceDelta

/// Represents a single detected change to a persistence mechanism.
/// Created by `PersistenceWatchService` when FSEvents fires for a watched directory.
struct PersistenceDelta: Identifiable, Sendable {
    let id:          UUID
    let kind:        PersistenceDeltaKind
    let record:      PersistenceRecord   // current (or last-known) state
    let detectedAt:  Date

    init(
        id:         UUID               = UUID(),
        kind:       PersistenceDeltaKind,
        record:     PersistenceRecord,
        detectedAt: Date               = Date()
    ) {
        self.id         = id
        self.kind       = kind
        self.record     = record
        self.detectedAt = detectedAt
    }

    // MARK: - Incident Factory

    /// Converts this delta into an `Incident` that can be merged into the
    /// main incident list and displayed on the dashboard immediately.
    func toIncident() -> Incident {
        let name: String
        switch kind {
        case .added:    name = "⚠️ New Persistence Item — \(record.fileName)"
        case .removed:  name = "Persistence Item Removed — \(record.fileName)"
        case .modified: name = "⚠️ Persistence Item Modified — \(record.fileName)"
        }

        let iso = ISO8601DateFormatter()

        return Incident(
            name:       name,
            severity:   kind.severity,
            confidence: .high,
            detail:     "[\(record.category.rawValue)] \(record.path)",
            source:     .persistence,
            technique:  .bootOrLogonAutostartExecution,
            trust:      .unclassified,
            evidence:   [
                .init(label: "Event",     value: kind.rawValue),
                .init(label: "Path",      value: record.path),
                .init(label: "Category",  value: record.category.rawValue),
                .init(label: "Scope",     value: record.scope),
                .init(label: "Symlink",   value: record.isSymlink ? "Yes ⚠️" : "No"),
                .init(label: "Detected",  value: iso.string(from: detectedAt)),
                .init(label: "Source",    value: "Live Watch (FSEvents / kqueue)")
            ],
            rawDetail: record.path
        )
    }

    // MARK: - Audit Detail

    var auditDetail: String {
        "\(kind.rawValue) [\(record.category.rawValue)] \(record.path)"
    }
}
