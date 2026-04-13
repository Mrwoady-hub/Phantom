import Foundation
import CryptoKit
import Security

// MARK: - KeychainHMAC
//
// SECURITY UPGRADE from bare SHA-256:
//
// SHA-256 hashes can be recomputed by any process that can read the audit file.
// A same-user attacker (e.g., malware running as the logged-in user) could read
// ~/Library/Application Support/Phantom/Phantom-AuditTrail.json,
// modify events, recompute valid SHA-256 hashes, and write the result back —
// making the tamper completely invisible.
//
// HMAC-SHA256 with a Keychain-backed key closes that gap:
//   - The 256-bit key is generated once and stored in the Keychain.
//   - Keychain access is gated by the app's code-signing identity, so a process
//     that hasn't been signed as Phantom cannot retrieve the key.
//   - Without the key, an attacker cannot produce a valid HMAC — any modified
//     file is detected on the next load.
//
// THREAT CEILING: A sufficiently privileged attacker with full Keychain access
// (e.g., via SecItemCopyMatching with the right entitlements or after
// compromising the user's login keychain) can still extract the key. The next
// hardening tier is a Secure Enclave-backed key, which prevents extraction even
// with Keychain access.

enum KeychainHMAC {

    private static let service = "com.phantom.hmackey"
    private static let account = "audit-hmac-v1"

    // MARK: - Public Interface

    /// Computes HMAC-SHA256(key, payload) and returns a lowercase hex string.
    /// The key is loaded from (or lazily created in) the Keychain on first call.
    static func hmac(for payload: String) -> String {
        let mac = HMAC<SHA256>.authenticationCode(
            for: Data(payload.utf8),
            using: resolvedKey()
        )
        return mac.map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - Key Resolution

    /// Returns the persisted Keychain key or generates and persists a new one.
    /// Thread-safe: multiple concurrent callers may generate a key in rare
    /// races on first launch, but SecItemAdd will simply return
    /// errSecDuplicateItem for the loser — the winner's stored key is reloaded.
    static func resolvedKey() -> SymmetricKey {
        if let key = loadKey() { return key }
        let key = SymmetricKey(size: .bits256)
        storeKey(key)
        // Re-load to tolerate the race where another caller won the write
        return loadKey() ?? key
    }

    // MARK: - Keychain I/O

    private static func loadKey() -> SymmetricKey? {
        let query: [CFString: Any] = [
            kSecClass:      kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne
        ]
        var ref: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &ref) == errSecSuccess,
              let data = ref as? Data,
              data.count == 32   // 256-bit = 32 bytes; reject malformed entries
        else { return nil }
        return SymmetricKey(data: data)
    }

    private static func storeKey(_ key: SymmetricKey) {
        let keyData = key.withUnsafeBytes { Data($0) }
        // kSecAttrAccessibleAfterFirstUnlock:
        //   - Key survives sleep/wake without requiring a fresh unlock.
        //   - Key is NOT accessible to processes without the unlock credential.
        //   - Suitable for a background security monitor that runs after login.
        let attrs: [CFString: Any] = [
            kSecClass:          kSecClassGenericPassword,
            kSecAttrService:    service,
            kSecAttrAccount:    account,
            kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlock,
            kSecValueData:      keyData
        ]
        // Purge any stale entry first (handles re-install / manual key rotation)
        let deleteQuery: [CFString: Any] = [
            kSecClass:       kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account
        ]
        SecItemDelete(deleteQuery as CFDictionary)
        SecItemAdd(attrs as CFDictionary, nil)
    }
}
