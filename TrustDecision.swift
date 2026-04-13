import Foundation
import Security

// MARK: - TrustDecision

struct TrustDecision: Codable, Sendable {
    let level: IncidentTrust
    let reasons: [String]
    let signerCommonName: String?
    let teamIdentifier: String?
    let bundleIdentifier: String?
    let executablePath: String
    let isSystemPath: Bool
    let isSigned: Bool
}

// MARK: - Signing Cache

/// Path-keyed cache so repeated scans don't re-evaluate the same binaries.
/// launchd, Finder, loginwindow don't change between 60s scan intervals.
/// TTL: 5 minutes — long enough to skip re-evaluation across scans,
/// short enough to catch a replaced binary.
private final class SigningCache: @unchecked Sendable {
    private struct Entry {
        let result: (signerCommonName: String?, teamIdentifier: String?,
                     bundleIdentifier: String?, isSigned: Bool)
        let expires: Date
    }
    private var store: [String: Entry] = [:]
    private let lock = NSLock()
    private let ttl: TimeInterval = 300  // 5 minutes

    func get(_ path: String) -> (String?, String?, String?, Bool)? {
        lock.lock(); defer { lock.unlock() }
        guard let entry = store[path], entry.expires > Date() else { return nil }
        return entry.result
    }

    func set(_ path: String, result: (String?, String?, String?, Bool)) {
        lock.lock(); defer { lock.unlock() }
        store[path] = Entry(result: result, expires: Date().addingTimeInterval(ttl))
        // Evict expired entries periodically to prevent unbounded growth
        if store.count > 500 {
            let now = Date()
            store = store.filter { $0.value.expires > now }
        }
    }
}

// MARK: - TrustEvaluator

enum TrustEvaluator {

    private static let cache = SigningCache()

    // MARK: - Process Trust

    static func evaluateProcess(path: String, commandToken: String) -> TrustDecision {
        let normalizedPath = NSString(string: path).standardizingPath
        let signing        = signingMetadata(for: normalizedPath)
        let isSystemPath   = systemPathPrefixes.contains { normalizedPath.hasPrefix($0) }
        let token          = commandToken.lowercased()
        var reasons: [String] = []

        if isSystemPath    { reasons.append("Path is under a system-managed directory.") }
        reasons.append(signing.isSigned ? "Valid code signature." : "Unsigned or signature invalid.")
        if let t = signing.teamIdentifier   { reasons.append("Team: \(t).") }
        if let b = signing.bundleIdentifier { reasons.append("Bundle: \(b).") }
        if let cn = signing.signerCommonName { reasons.append("Signer: \(cn).") }

        let level: IncidentTrust
        if suspiciousTokens.contains(token) {
            reasons.append("Token associated with tunneling or lateral movement.")
            level = .suspicious
        } else if isSystemPath && signing.isSigned {
            level = .trustedSystem
        } else if signing.isSigned && isKnownApp(signing.bundleIdentifier,
                                                  signing.teamIdentifier, normalizedPath) {
            level = .knownApplication
        } else if writableUserPaths.contains(where: { normalizedPath.hasPrefix($0) }) {
            reasons.append("Running from a user-writable path.")
            level = .suspicious
        } else {
            level = .unclassified
        }

        return TrustDecision(level: level, reasons: reasons,
            signerCommonName: signing.signerCommonName,
            teamIdentifier:   signing.teamIdentifier,
            bundleIdentifier: signing.bundleIdentifier,
            executablePath:   normalizedPath,
            isSystemPath:     isSystemPath,
            isSigned:         signing.isSigned)
    }

    // MARK: - Persistence Trust

    static func evaluatePersistence(path: String) -> TrustDecision {
        let normalizedPath = NSString(string: path).standardizingPath
        let fileName       = URL(fileURLWithPath: normalizedPath).lastPathComponent

        // Fast-path 1: SIP-protected — always Apple, no signing check needed
        if normalizedPath.hasPrefix("/System/") ||
           normalizedPath.hasPrefix("/usr/")     ||
           normalizedPath.hasPrefix("/Library/Apple/") {
            return TrustDecision(level: .trustedSystem,
                reasons: ["SIP-protected path — always Apple-managed."],
                signerCommonName: nil, teamIdentifier: nil, bundleIdentifier: nil,
                executablePath: normalizedPath, isSystemPath: true, isSigned: true)
        }

        // Fast-path 2: Apple-namespaced filename — trust regardless of directory
        if fileName.lowercased().hasPrefix("com.apple.") {
            return TrustDecision(level: .trustedSystem,
                reasons: ["Filename is Apple-namespaced (com.apple.*)."],
                signerCommonName: nil, teamIdentifier: nil, bundleIdentifier: nil,
                executablePath: normalizedPath, isSystemPath: false, isSigned: true)
        }

        // Fast-path 3: Non-executable file types — skip signing check entirely.
        // Plists, kext bundles, and cron files are never code-signed executables.
        // SecStaticCodeCreateWithPath on a plist takes ~5ms and always fails.
        let ext = URL(fileURLWithPath: normalizedPath).pathExtension.lowercased()
        let nonExecutableExtensions: Set<String> = ["plist", "sh", "py", "rb", "pl", ""]
        let skipSigning = nonExecutableExtensions.contains(ext)

        let signing: (signerCommonName: String?, teamIdentifier: String?,
                      bundleIdentifier: String?, isSigned: Bool)
        if skipSigning {
            signing = (nil, nil, nil, false)
        } else {
            signing = signingMetadata(for: normalizedPath)
        }

        let lower        = normalizedPath.lowercased()
        let isSystemPath = lower.hasPrefix("/library/")
        var reasons      = ["Persistence item at \(normalizedPath)."]
        if signing.isSigned { reasons.append("Target has valid signing metadata.") }

        let level: IncidentTrust
        if signing.isSigned && isKnownApp(signing.bundleIdentifier,
                                           signing.teamIdentifier, normalizedPath) {
            level = .knownApplication
        } else if normalizedPath.hasPrefix(NSHomeDirectory()) {
            reasons.append("Item is in a user-controlled path.")
            level = .unclassified
        } else {
            level = isSystemPath ? .unclassified : .suspicious
        }

        return TrustDecision(level: level, reasons: reasons,
            signerCommonName: signing.signerCommonName,
            teamIdentifier:   signing.teamIdentifier,
            bundleIdentifier: signing.bundleIdentifier,
            executablePath:   normalizedPath,
            isSystemPath:     isSystemPath,
            isSigned:         signing.isSigned)
    }

    // MARK: - Constants

    private static let systemPathPrefixes = [
        "/System/", "/usr/libexec/", "/usr/bin/", "/bin/", "/sbin/"
    ]
    private static let writableUserPaths = [
        "\(NSHomeDirectory())/Downloads/", "\(NSHomeDirectory())/Desktop/",
        "\(NSHomeDirectory())/Documents/", "/tmp/", "/private/tmp/"
    ]
    private static let suspiciousTokens: Set<String> = [
        "nc","ncat","socat","ngrok","frpc","chisel",
        "python3","python","ruby","osascript","curl","wget",
        "launchctl","screencapture","networksetup","pkill","killall"
    ]

    // MARK: - Known App

    private static func isKnownApp(_ bundle: String?, _ team: String?, _ path: String) -> Bool {
        let knownBundles = ["com.google.","com.microsoft.","com.adobe.","us.zoom.",
                            "org.mozilla.","com.openai.","com.apple.","com.jetbrains.",
                            "com.spotify.","com.dropbox.","com.github.","com.woady."]
        let knownTeams: Set<String> = ["EQHXZ8M8AV","UBF8T346G9","BJ4HAAB9B3",
                                        "2FNC3A47ZF","QKQK8Q2W8V","W6KPYK32ZA",
                                        "QT8Z3BNUY7","G7HH3F8CAK"]
        if let b = bundle, knownBundles.contains(where: { b.hasPrefix($0) }) { return true }
        if let t = team,   knownTeams.contains(t)                             { return true }
        return path.hasPrefix("/Applications/")
    }

    // MARK: - Signing (cached)

    private static func signingMetadata(for path: String) -> (
        signerCommonName: String?, teamIdentifier: String?,
        bundleIdentifier: String?, isSigned: Bool
    ) {
        // Cache hit — no Security framework call needed
        if let cached = cache.get(path) { return cached }

        let result = evaluateSigning(path: path)
        cache.set(path, result: result)
        return result
    }

    private static func evaluateSigning(path: String) -> (
        signerCommonName: String?, teamIdentifier: String?,
        bundleIdentifier: String?, isSigned: Bool
    ) {
        let url = URL(fileURLWithPath: path)
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess,
              let code else {
            return (nil, nil, bundleID(from: url), false)
        }

        // PERFORMANCE: Drop kSecCSCheckAllArchitectures.
        // That flag verifies BOTH arm64 and x86_64 slices via Rosetta on Apple Silicon.
        // For a security monitor we just need isSigned + team/bundle identity.
        // Plain [] is 3-10× faster and sufficient for our trust signal.
        let isSigned = SecStaticCodeCheckValidity(code, [], nil) == errSecSuccess

        var info: CFDictionary?
        guard SecCodeCopySigningInformation(
            code,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &info
        ) == errSecSuccess, let dict = info as? [String: Any] else {
            return (nil, nil, bundleID(from: url), isSigned)
        }

        let b  = dict[kSecCodeInfoIdentifier as String] as? String ?? bundleID(from: url)
        let t  = dict[kSecCodeInfoTeamIdentifier as String] as? String
        let cn = signerCN(from: dict)
        return (cn, t, b, isSigned)
    }

    private static func signerCN(from info: [String: Any]) -> String? {
        guard let certs = info[kSecCodeInfoCertificates as String] as? [SecCertificate],
              let leaf  = certs.first else { return nil }
        var cn: CFString?
        SecCertificateCopyCommonName(leaf, &cn)
        return cn as String?
    }

    private static func bundleID(from url: URL) -> String? {
        var u = url
        while u.path != "/" {
            if u.pathExtension == "app" || u.pathExtension == "xpc" {
                return Bundle(url: u)?.bundleIdentifier
            }
            u.deleteLastPathComponent()
        }
        return nil
    }
}
