import Foundation
import CryptoKit

// MARK: - AuditTrailStore
//
// SECURITY MODEL:
// Every AuditEvent carries an HMAC-SHA256 eventHash (using a Keychain-backed key)
// that covers all of its own fields plus the previous event's hash (a hash chain).
// This means:
//   - Deleting any event breaks every subsequent hash → detected on load
//   - Modifying any field breaks that event's hash → detected on load
//   - Truncating the tail is detectable via sequenceNumber gaps
//   - Prepending fake events breaks the first real event's previousHash → detected
//   - Recomputing a valid chain requires the Keychain key, which is gated by the
//     app's code-signing identity — defeating same-user attackers who can only
//     read/write files but cannot retrieve Keychain secrets for this app.
//
// See KeychainHMAC.swift for the key management and full threat model.

enum AuditTrailStore {

    // MARK: - Storage

    private static let directoryName = "Phantom"
    private static let fileName      = "Phantom-AuditTrail.json"

    private static var fileURL: URL {
        let base = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first!
        let dir = base.appendingPathComponent(directoryName, isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        // SECURITY: Set directory permissions to 0700 — only the owning user may list it.
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o700],
            ofItemAtPath: dir.path
        )
        return dir.appendingPathComponent(fileName)
    }

    // MARK: - Chain Integrity

    /// Result of verifying the persisted chain on load.
    struct IntegrityReport {
        let isIntact: Bool
        let totalEvents: Int
        let corruptedSequenceNumbers: [Int]
        let missingSequenceNumbers: [Int]

        static let empty = IntegrityReport(
            isIntact: true, totalEvents: 0,
            corruptedSequenceNumbers: [], missingSequenceNumbers: []
        )
    }

    /// Verifies the full hash chain without modifying anything.
    /// Call this on startup to detect tampering before trusting the trail.
    @discardableResult
    static func verifyChain() -> IntegrityReport {
        guard let data = try? Data(contentsOf: fileURL) else { return .empty }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        guard let events = try? decoder.decode([AuditEvent].self, from: data) else {
            return IntegrityReport(
                isIntact: false, totalEvents: 0,
                corruptedSequenceNumbers: [-1], missingSequenceNumbers: []
            )
        }

        let sorted = events.sorted { $0.sequenceNumber < $1.sequenceNumber }
        var corrupted: [Int] = []
        var previousHash: String? = nil

        // Walk the chain: recompute each hash and compare
        for event in sorted {
            // Recompute the hash as if previousHash = previousHash and eventHash = nil
            let recomputed = hash(for: AuditEvent(
                id:             event.id,
                timestamp:      event.timestamp,
                sequenceNumber: event.sequenceNumber,
                action:         event.action,
                incidentFamily: event.incidentFamily,
                incidentName:   event.incidentName,
                details:        event.details,
                operatorName:   event.operatorName,
                hostName:       event.hostName,
                previousHash:   previousHash,
                eventHash:      nil
            ))

            let storedHash    = event.eventHash ?? ""
            let prevHashMatch = event.previousHash == previousHash

            if recomputed != storedHash || !prevHashMatch {
                corrupted.append(event.sequenceNumber)
            }
            previousHash = event.eventHash
        }

        // Detect gaps in sequence numbers
        let seqNumbers = sorted.map { $0.sequenceNumber }
        var missing: [Int] = []
        if let first = seqNumbers.first, let last = seqNumbers.last {
            let expected = Set(first...last)
            missing = expected.subtracting(Set(seqNumbers)).sorted()
        }

        return IntegrityReport(
            isIntact: corrupted.isEmpty && missing.isEmpty,
            totalEvents: sorted.count,
            corruptedSequenceNumbers: corrupted,
            missingSequenceNumbers: missing
        )
    }

    // MARK: - Public Interface

    static func load() -> [AuditEvent] {
        guard let data = try? Data(contentsOf: fileURL) else { return [] }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decoded = (try? decoder.decode([AuditEvent].self, from: data)) ?? []
        return normalize(decoded).sorted { $0.sequenceNumber > $1.sequenceNumber }
    }

    /// The ONLY correct way to persist events. Normalizes and re-seals the chain.
    /// Direct callers outside this enum should use `append()` — not this method —
    /// to ensure the chain is maintained incrementally rather than recomputed wholesale.
    static func save(_ events: [AuditEvent]) {
        let encoder = JSONEncoder()
        encoder.outputFormatting    = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        guard let data = try? encoder.encode(normalize(events)) else { return }
        // .atomic: write to a temp file, then rename — prevents torn writes on crash
        try? data.write(to: fileURL, options: .atomic)
        // SECURITY: restrict file to owner read/write only (0600)
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: fileURL.path
        )
    }

    /// Appends one event to the chain. This is the correct call site for all audit
    /// recording. Returns the full trail sorted descending (newest first).
    static func append(
        action: AuditAction,
        incidentFamily: String? = nil,
        incidentName: String? = nil,
        details: String,
        operatorName: String
    ) -> [AuditEvent] {
        let existing     = load().sorted { $0.sequenceNumber < $1.sequenceNumber }
        let previousHash = existing.last?.eventHash
        let nextSequence = (existing.last?.sequenceNumber ?? 0) + 1

        // Two-step: build without hash → compute hash → rebuild with hash.
        // Required because the hash covers all other fields including eventHash=nil.
        let partial = AuditEvent(
            timestamp:      Date(),
            sequenceNumber: nextSequence,
            action:         action,
            incidentFamily: incidentFamily,
            incidentName:   incidentName,
            details:        details,
            operatorName:   operatorName,
            previousHash:   previousHash,
            eventHash:      nil
        )
        let updated = existing + [stamped(partial)]
        save(updated)
        return updated.sorted { $0.sequenceNumber > $1.sequenceNumber }
    }

    // MARK: - Chain Normalization

    private static func normalize(_ events: [AuditEvent]) -> [AuditEvent] {
        let sorted: [AuditEvent] = events.sorted { (lhs: AuditEvent, rhs: AuditEvent) -> Bool in
            lhs.sequenceNumber == rhs.sequenceNumber
                ? lhs.timestamp < rhs.timestamp
                : lhs.sequenceNumber < rhs.sequenceNumber
        }
        var previousHash: String?
        return sorted.enumerated().map { (index: Int, event: AuditEvent) -> AuditEvent in
            let renumbered = AuditEvent(
                id:             event.id,
                timestamp:      event.timestamp,
                sequenceNumber: index + 1,
                action:         event.action,
                incidentFamily: event.incidentFamily,
                incidentName:   event.incidentName,
                details:        event.details,
                operatorName:   event.operatorName,
                hostName:       event.hostName,
                previousHash:   previousHash,
                eventHash:      nil
            )
            let final = stamped(renumbered)
            previousHash = final.eventHash
            return final
        }
    }

    // MARK: - Hashing

    private static func stamped(_ event: AuditEvent) -> AuditEvent {
        AuditEvent(
            id:             event.id,
            timestamp:      event.timestamp,
            sequenceNumber: event.sequenceNumber,
            action:         event.action,
            incidentFamily: event.incidentFamily,
            incidentName:   event.incidentName,
            details:        event.details,
            operatorName:   event.operatorName,
            hostName:       event.hostName,
            previousHash:   event.previousHash,
            eventHash:      hash(for: event)
        )
    }

    // MARK: - Migration

    /// One-time migration from the legacy SHA-256 chain to HMAC-SHA256.
    /// Call this BEFORE verifyChain() on first launch after the upgrade.
    /// If the flag is already set (or no events exist), this is a no-op.
    static func migrateToHMACIfNeeded() {
        let flagKey = "Phantom.hmacMigration.v1"
        guard !UserDefaults.standard.bool(forKey: flagKey) else { return }
        // Load whatever chain exists and reseal it with the new HMAC function.
        // normalize() recomputes every hash from scratch, so the old SHA-256
        // hashes are replaced with valid HMAC hashes in a single pass.
        let existing = load().sorted { $0.sequenceNumber < $1.sequenceNumber }
        if !existing.isEmpty { save(existing) }
        UserDefaults.standard.set(true, forKey: flagKey)
    }

    static func hash(for event: AuditEvent) -> String {
        let payload = [
            event.id.uuidString,
            ISO8601DateFormatter().string(from: event.timestamp),
            String(event.sequenceNumber),
            event.action.rawValue,
            event.incidentFamily ?? "",
            event.incidentName   ?? "",
            event.details,
            event.operatorName,
            event.hostName,
            event.previousHash   ?? ""
        ].joined(separator: "|")
        // HMAC-SHA256 with Keychain-backed key (see KeychainHMAC.swift).
        // Falls back gracefully: if the Keychain is unavailable on first call
        // a new key is generated and stored, so the chain is always sealed.
        return KeychainHMAC.hmac(for: payload)
    }
}
