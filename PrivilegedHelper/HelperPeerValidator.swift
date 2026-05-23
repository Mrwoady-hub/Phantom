import Foundation
import Security

// MARK: - HelperPeerValidator
//
// Validates that a connecting XPC peer is the Phantom app, signed by the
// expected team and bearing the expected bundle identifier. The helper runs
// as root, so SMAuthorizedClients in the launchd plist is the install-time
// gate; this validator is the run-time gate, applied to every new connection.
//
// Threat model:
//   • SMAuthorizedClients prevents launchd from registering the helper for
//     an unauthorized client at install time, but it does not gate runtime
//     XPC connections from arbitrary local processes. We must reject those
//     ourselves before serving privileged operations.
//
// Mechanism:
//   • NSXPCConnection.auditToken (macOS 11+) gives the peer's audit_token_t.
//   • SecCodeCopyGuestWithAttributes turns the audit token into a SecCode.
//   • SecCodeCheckValidity validates the live signature against a
//     SecRequirement built from a designated requirement string that mirrors
//     the SMAuthorizedClients entry in the launchd plist.
//
// Failure behavior: fail closed — any error or mismatch returns false and
// the listener refuses the connection.

enum HelperPeerValidator {

    /// Designated requirement that matches the Phantom main app.
    /// Mirrors the SMAuthorizedClients value in com.woady.phantom.helper.plist.
    /// If the team ID changes, both strings must be updated together.
    static let requirementString =
        "identifier \"com.woady.phantom\" and anchor apple generic "
      + "and certificate leaf[subject.OU] = \"NYQ3P2YWL5\""

    /// Validate the peer of an NSXPCConnection.
    /// Returns true only if the peer's running code satisfies the requirement.
    ///
    /// `auditToken` on NSXPCConnection is SPI (Apple's documented stance is
    /// that the structure should be treated as opaque). It is widely used in
    /// privileged helpers because the public alternative — processIdentifier
    /// — is vulnerable to PID-reuse attacks. We are a root-only daemon, not
    /// shipped via the App Store, so SPI use here is acceptable. We access
    /// the property by KVC so the call site does not silently break if the
    /// SDK header visibility changes.
    static func isAuthorized(connection: NSXPCConnection) -> Bool {
        guard let token = auditToken(from: connection) else { return false }
        return validate(auditToken: token, requirement: requirementString)
    }

    private static func auditToken(from connection: NSXPCConnection) -> audit_token_t? {
        // KVC over the ObjC `auditToken` property. The runtime may wrap the
        // returned C struct as NSValue or NSData depending on context; we
        // accept either shape and fail closed if neither matches.
        let raw = connection.value(forKey: "auditToken")
        let size = MemoryLayout<audit_token_t>.size
        var token = audit_token_t(val: (0,0,0,0,0,0,0,0))

        if let value = raw as? NSValue {
            withUnsafeMutableBytes(of: &token) { buf in
                value.getValue(buf.baseAddress!, size: size)
            }
            return token
        }
        if let data = raw as? NSData, data.length == size {
            data.getBytes(&token, length: size)
            return token
        }
        return nil
    }

    /// Lower-level entry point — useful for tests that synthesize an audit_token_t.
    static func validate(auditToken: audit_token_t, requirement: String) -> Bool {
        var token = auditToken
        let tokenData = withUnsafeBytes(of: &token) { Data($0) }

        let attributes: [String: Any] = [
            kSecGuestAttributeAudit as String: tokenData
        ]

        var codeRef: SecCode?
        let copyStatus = SecCodeCopyGuestWithAttributes(
            nil, attributes as CFDictionary, [], &codeRef
        )
        guard copyStatus == errSecSuccess, let code = codeRef else { return false }

        var reqRef: SecRequirement?
        let reqStatus = SecRequirementCreateWithString(
            requirement as CFString, [], &reqRef
        )
        guard reqStatus == errSecSuccess, let req = reqRef else { return false }

        let checkStatus = SecCodeCheckValidity(code, [], req)
        return checkStatus == errSecSuccess
    }
}
