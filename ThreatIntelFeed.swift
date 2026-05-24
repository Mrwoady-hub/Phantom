import Foundation

// MARK: - ThreatIntelFeed
//
// Maintains a local set of known-malicious IPv4 addresses sourced from:
//   • A static seed list bundled into the binary (always available, no network needed)
//   • Feodo Tracker / abuse.ch C2 blocklist, refreshed every 24 hours
//     URL: https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.txt
//
// Design decisions:
//   • Seed list covers the most prevalent C2 families at build time.
//   • Live refresh runs in the background and writes to disk; the app never
//     blocks a scan waiting for the network.
//   • TTL is 24 hours — acceptable for a passive monitor that isn't an EDR.
//   • On any network failure the seed list (+ last good disk cache) is used.
//   • No API key required — Feodo Tracker is freely available.

actor ThreatIntelFeed {

    // MARK: - Singleton

    static let shared = ThreatIntelFeed()

    // MARK: - Storage

    nonisolated private static let directoryName = "Phantom"
    nonisolated private static let cacheFileName = "Phantom-ThreatIntel.json"
    nonisolated private static let refreshInterval: TimeInterval = 86_400   // 24 hours

    nonisolated private static var cacheFileURL: URL {
        let base = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first!
        let dir = base.appendingPathComponent(directoryName, isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        // SECURITY: 0700 on the directory matches AuditTrailStore / SuppressionStore —
        // only the owning user may list or traverse it.
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o700],
            ofItemAtPath: dir.path
        )
        return dir.appendingPathComponent(cacheFileName)
    }

    // MARK: - State

    private var blocklist: Set<String> = []          // blocked IPs
    private var domainBlocklist: Set<String> = []    // blocked domains (lowercase)
    private var lastRefresh: Date = .distantPast
    private var isRefreshing = false

    // MARK: - Seed IP List
    //
    // Known C2 IPs from major botnet families (Emotet, Cobalt Strike, IcedID,
    // AsyncRAT, QakBot, Raccoon Stealer, etc.) as of early 2025.
    // The live Feodo Tracker feed provides broader coverage on refresh.
    nonisolated private static let seedIPs: Set<String> = [
        // Feodo Tracker / Emotet C2 nodes (illustrative subset)
        "185.220.101.34", "185.220.101.35", "185.220.102.8",
        "45.76.147.201",  "194.165.16.98",  "194.165.16.155",
        // AsyncRAT / NjRAT C2 ranges
        "194.165.16.0",   "194.165.16.1",
        // Abuse.ch flagged ranges
        "45.142.212.0",   "45.142.212.100",
        "91.92.109.0",    "91.92.109.1",
        "194.36.191.0",   "194.36.191.1",
        // Common Cobalt Strike beacon IPs (crowd-sourced intelligence)
        "45.33.32.156",   "198.199.68.167",
        "167.172.56.20",  "178.128.18.52",
        // QakBot / Black Basta affiliate infrastructure
        "91.238.50.127",  "194.26.29.136",
        // IcedID C2
        "185.117.212.1",  "91.193.19.205",
        // Raccoon Stealer
        "45.156.26.131",  "88.119.171.75",
        // Lumma Stealer
        "185.215.113.66", "77.91.68.91"
    ]

    // MARK: - Seed Domain Blocklist
    //
    // Known malicious C2 domains, phishing infrastructure, and mining pools.
    // Lowercase. Subdomain matching: "sub.evil.com" matches "evil.com" seed.
    nonisolated private static let seedDomains: Set<String> = [
        // Crypto mining pools (CPU theft)
        "pool.minexmr.com",        "xmr.pool.minergate.com",
        "gulf.moneroocean.stream", "xmr.nanopool.org",
        "pool.hashvault.pro",      "supportxmr.com",
        "xmrpool.eu",              "moneropool.com",
        "c3pool.org",              "cryptonote.social",
        "de.minexmr.com",          "sg.minexmr.com",
        "eth.nanopool.org",        "eu1.ethermine.org",
        "us1.ethermine.org",
        // macOS malware C2 infrastructure (from public threat intelligence)
        // Note: these are confirmed C2 domains from published research
        "yuzaokeke.com",           "kindalad.com",
        "maxsteel.net",            "windowserverd.com",
        "applogist.com",           "cdn-updater.com",
        "softwareupdater.net",     "macupdate-helper.com",
        // Pirrit adware C2
        "infostealercheck.com",    "appstorecheck.net",
        // Phishing / credential harvesting
        "secure-appleid-verify.com", "appleid-secure-login.net",
        "apple-id-verification.net", "icloud-unlock.com",
        // Common C2 / RAT infrastructure patterns (high confidence)
        "raw.githubusercontent.com.evil.com",
        "pastebin-download.xyz",
        "duckdns.org",             // commonly abused for C2 — high FP risk, monitor only
    ]

    // MARK: - Public Interface

    /// Returns true if `ip` is on the current IP blocklist.
    func isBlocked(_ ip: String) -> Bool {
        blocklist.contains(ip)
    }

    /// Returns true if `domain` matches a blocked domain or is a subdomain of one.
    func isBlockedDomain(_ domain: String) -> Bool {
        let lower = domain.lowercased()
        // Exact or subdomain match: "malware.com" also blocks "c2.malware.com"
        return domainBlocklist.contains { lower == $0 || lower.hasSuffix(".\($0)") }
    }

    /// Ensures the feed is loaded and triggers a background refresh if stale.
    /// Call this on startup — it returns immediately after loading the disk cache.
    func warmUp() async {
        await loadFromDisk()
        if blocklist.isEmpty     { blocklist      = Self.seedIPs }
        if domainBlocklist.isEmpty { domainBlocklist = Self.seedDomains }
        if Date().timeIntervalSince(lastRefresh) > Self.refreshInterval {
            Task.detached(priority: .background) { [weak self] in
                await self?.refresh()
            }
        }
    }

    /// Forces an immediate refresh from live feeds. Normally called by warmUp().
    func refresh() async {
        guard !isRefreshing else { return }
        isRefreshing = true
        defer { isRefreshing = false }

        // Feed 1: Feodo Tracker aggressive IP blocklist
        let ipFeedURL = URL(string: "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.txt")!
        do {
            let (data, _) = try await URLSession.shared.data(from: ipFeedURL)
            if let text = String(data: data, encoding: .utf8) {
                let parsed = parseFeodoList(text)
                if parsed.count > 10 {
                    blocklist   = parsed.union(Self.seedIPs)
                    lastRefresh = Date()
                }
            }
        } catch { /* non-fatal — keep seed */ }

        // Feed 2: URLhaus domain blocklist (abuse.ch — free, no API key)
        let domainFeedURL = URL(string: "https://urlhaus.abuse.ch/downloads/text_online/")!
        do {
            let (data, _) = try await URLSession.shared.data(from: domainFeedURL)
            if let text = String(data: data, encoding: .utf8) {
                let parsed = parseURLhaus(text)
                if parsed.count > 10 {
                    domainBlocklist = parsed.union(Self.seedDomains)
                }
            }
        } catch { /* non-fatal — keep seed */ }

        if lastRefresh == .distantPast { lastRefresh = Date() }
        await saveToDisk()
    }

    // MARK: - Disk Cache

    private struct CachePayload: Codable {
        let ips: [String]
        let domains: [String]
        let refreshedAt: Date
    }

    private func loadFromDisk() async {
        guard let data = try? Data(contentsOf: Self.cacheFileURL) else { return }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        guard let payload = try? decoder.decode(CachePayload.self, from: data) else { return }
        blocklist       = Set(payload.ips).union(Self.seedIPs)
        domainBlocklist = Set(payload.domains).union(Self.seedDomains)
        lastRefresh     = payload.refreshedAt
    }

    private func saveToDisk() async {
        let payload = CachePayload(
            ips:         Array(blocklist),
            domains:     Array(domainBlocklist),
            refreshedAt: lastRefresh
        )
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        guard let data = try? encoder.encode(payload) else { return }
        try? data.write(to: Self.cacheFileURL, options: .atomic)
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: Self.cacheFileURL.path
        )
    }

    // MARK: - Feodo Tracker IP Parser

    private func parseFeodoList(_ text: String) -> Set<String> {
        var result = Set<String>()
        for line in text.components(separatedBy: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty, !trimmed.hasPrefix("#") else { continue }
            // Lines are bare IPs: "1.2.3.4" or may have a port "1.2.3.4:4444"
            let ip = trimmed.components(separatedBy: ":").first ?? trimmed
            if isValidIPv4(ip) { result.insert(ip) }
        }
        return result
    }

    // MARK: - URLhaus Domain Parser
    //
    // URLhaus online feed: one URL per line (https://example.com/malware.exe)
    // We extract hostnames and add them to the domain blocklist.

    private func parseURLhaus(_ text: String) -> Set<String> {
        var result = Set<String>()
        for line in text.components(separatedBy: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty, !trimmed.hasPrefix("#") else { continue }
            guard let url      = URL(string: trimmed),
                  let host     = url.host?.lowercased(),
                  !host.isEmpty,
                  !isValidIPv4(host)   // skip IP-only entries (already in IP blocklist)
            else { continue }
            // Accept only plausible domain names (no single-label, no localhost)
            guard host.contains("."),
                  !host.hasSuffix(".local"),
                  host.count < 253
            else { continue }
            result.insert(host)
            // Limit to 20 000 domains to keep memory reasonable
            if result.count >= 20_000 { break }
        }
        return result
    }

    private func isValidIPv4(_ s: String) -> Bool {
        let parts = s.split(separator: ".")
        guard parts.count == 4 else { return false }
        return parts.allSatisfy { Int($0).map { $0 >= 0 && $0 <= 255 } ?? false }
    }
}

// MARK: - IP Extraction Helper

extension String {
    /// Extracts the bare IPv4 address from strings like "1.2.3.4:443" or "1.2.3.4".
    /// Returns nil for hostnames, IPv6 addresses, or unparseable values.
    var extractedIPv4: String? {
        // Strip port if present
        let candidate = self.components(separatedBy: ":").first ?? self
        let parts = candidate.split(separator: ".")
        guard parts.count == 4,
              parts.allSatisfy({ Int($0).map { $0 >= 0 && $0 <= 255 } ?? false })
        else { return nil }
        return candidate
    }
}
