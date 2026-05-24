import Foundation

// MARK: - SuppressionStore persistence format
//
// Defined at file scope (not nested inside the enum) so its Codable conformance
// is nonisolated by default. Nested types inherit the enclosing type's actor
// isolation; file-private types do not.

private struct SuppressionPayload: Sendable {
    let keys: [String]
    let integrityTag: String

    // Explicit nonisolated Codable conformance prevents the project's
    // -default-isolation MainActor from making the synthesised init(from:)
    // and encode(to:) @MainActor, which would block nonisolated callers.
    nonisolated init(keys: [String], integrityTag: String) {
        self.keys = keys
        self.integrityTag = integrityTag
    }
}

extension SuppressionPayload: Codable {
    nonisolated init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        keys         = try c.decode([String].self, forKey: .keys)
        integrityTag = try c.decode(String.self,   forKey: .integrityTag)
    }
    nonisolated func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(keys,         forKey: .keys)
        try c.encode(integrityTag, forKey: .integrityTag)
    }
    private enum CodingKeys: String, CodingKey { case keys, integrityTag }
}

// MARK: - SuppressionStore
//
// SECURITY UPGRADE from UserDefaults:
//
// UserDefaults (the original storage) is backed by a plist in ~/Library/Preferences/
// and is readable and writable by ANY process running as the same user — including
// the exact malware this app is designed to detect. An attacker could inject their
// own suppressionKey via `defaults write` or direct CFPreferences manipulation,
// silently preventing Phantom from ever surfacing their activity.
//
// This store writes to ~/Library/Application Support/Phantom/ (0600 perms)
// and appends a SHA-256 integrity tag over the sorted key list. If the file is
// modified externally, the tag will not match and we reject the tampered data,
// falling back to an empty suppression set (fail-safe: over-alert rather than
// under-alert).
//
// THREAT MODEL CEILING: The tag is now HMAC-SHA256 with a Keychain-backed key
// (see KeychainHMAC.swift). An attacker who can read the file cannot recompute
// a valid HMAC without extracting the Keychain key, which requires the app's
// code-signing identity. This closes the same-user file-write attack vector.

enum SuppressionStore {

    nonisolated private static let directoryName = "Phantom"
    nonisolated private static let fileName      = "Phantom-Suppressions.json"

    nonisolated private static var fileURL: URL {
        let base = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first!
        let dir = base.appendingPathComponent(directoryName, isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o700],
            ofItemAtPath: dir.path
        )
        return dir.appendingPathComponent(fileName)
    }

    // MARK: - Public interface

    nonisolated static func load() -> Set<String> {
        guard let data = try? Data(contentsOf: fileURL),
              let payload = try? JSONDecoder().decode(SuppressionPayload.self, from: data)
        else { return [] }

        // SECURITY: verify integrity tag before trusting the payload
        let expectedTag = tag(for: payload.keys)
        guard payload.integrityTag == expectedTag else {
            // Fail-safe: tampered suppression list → treat as empty.
            // This means all previously-suppressed incidents become visible again.
            // Over-alerting is preferable to silently missing detections.
            return []
        }

        return Set(payload.keys)
    }

    nonisolated static func save(_ keys: Set<String>) {
        let sorted  = keys.sorted()
        let payload = SuppressionPayload(keys: sorted, integrityTag: tag(for: sorted))
        guard let data = try? JSONEncoder().encode(payload) else { return }
        try? data.write(to: fileURL, options: .atomic)
        // SECURITY: owner read/write only
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: fileURL.path
        )
    }

    // MARK: - Integrity

    nonisolated private static func tag(for keys: [String]) -> String {
        // HMAC-SHA256 with Keychain-backed key — see KeychainHMAC.swift.
        return KeychainHMAC.hmac(for: keys.joined(separator: "|"))
    }
}
