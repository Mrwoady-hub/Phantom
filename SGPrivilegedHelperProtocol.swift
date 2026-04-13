import Foundation

// MARK: - SGPrivilegedHelperProtocol
//
// XPC interface between the main app and the privileged helper daemon.
// Both sides (app client + helper listener) conform to this protocol.
//
// Design principles:
//   • Every method is async via reply-block pattern (required for NSXPCInterface).
//   • All parameters and return types must be NSSecureCoding-compatible or
//     primitive types — no Swift-only types cross the XPC boundary.
//   • The helper runs as root; all methods are scoped to read-only observation.
//     No write operations are exposed to limit blast radius if compromised.

@objc protocol SGPrivilegedHelperProtocol {

    /// Returns the helper's version string. Used to verify the correct helper
    /// version is installed before performing privileged operations.
    func getVersion(reply: @escaping (String) -> Void)

    /// Runs `lsof -nP -iTCP -iUDP` as root, returning raw output.
    /// Root-level lsof sees ALL processes, including those owned by other users
    /// and system daemons that user-level lsof cannot enumerate.
    func runPrivilegedLsof(reply: @escaping (String?) -> Void)

    /// Reads `/etc/hosts` and returns lines that look malicious:
    /// - Entries redirecting known domains (Apple, Google, Microsoft) to non-standard IPs
    /// - Entries pointing to RFC-1918 addresses for public hostnames
    func checkEtcHosts(reply: @escaping ([String]) -> Void)

    /// Returns `kextstat` output (kernel extension list) filtered to third-party KEXTs.
    /// Useful for detecting rootkit kernel modules that load before userspace.
    func listKernelExtensions(reply: @escaping (String?) -> Void)

    /// Checks `/etc/sudoers` and `/etc/sudoers.d/` for unexpected entries that
    /// grant NOPASSWD sudo access to non-admin users.
    func checkSudoers(reply: @escaping ([String]) -> Void)

    /// Returns the contents of `/Library/LaunchAgents/` and `/Library/LaunchDaemons/`
    /// that are NOT in the PersistenceScanner's trusted Apple set. Root access
    /// ensures no permission errors on protected plists.
    func listSystemPersistence(reply: @escaping ([String]) -> Void)

    // MARK: - 3.0 Network Intelligence

    /// Captures packets from `interface` for `durationSeconds` seconds using tcpdump.
    /// Writes the result as a pcap file to `outputPath` (must be writable by root).
    /// Returns the output path on success, nil on failure.
    /// Root is required for live packet capture on macOS.
    func capturePackets(
        interface: String,
        durationSeconds: Int,
        outputPath: String,
        reply: @escaping (String?) -> Void
    )

    /// Lists available network interfaces (equivalent to `tcpdump -D`).
    /// Returns an array of interface names suitable for capture.
    func listNetworkInterfaces(reply: @escaping ([String]) -> Void)

}

// MARK: - XPC Service Name

/// Mach service name the helper registers under and the app connects to.
/// Must match the value in the helper's launchd plist.
let SGHelperMachServiceName = "com.woady.phantom.helper"
