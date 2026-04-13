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

    private static let directoryName = "Phantom"
    private static let cacheFileName = "Phantom-ThreatIntel.json"
    private static let refreshInterval: TimeInterval = 86_400   // 24 hours

    private static var cacheFileURL: URL {
        let base = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first!
        let dir = base.appendingPathComponent(directoryName, isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent(cacheFileName)
    }

    // MARK: - State

    private var blocklist: Set<String> = []
    private var lastRefresh: Date = .distantPast
    private var isRefreshing = false

    // MARK: - Seed List
    //
    // A representative sample of known C2 IPs from major botnet families
    // (Emotet, Cobalt Strike, IcedID, AsyncRAT, etc.) as of early 2025.
    // This list is intentionally small — the live feed provides coverage.
    private static let seedIPs: Set<String> = [
        // Feodo Tracker / Emotet historical C2s (illustrative subset)
        "185.220.101.0", "185.220.101.1", "185.220.102.0",
        // Cobalt Strike known beacon IPs (redacted for safety — populated by live feed)
        // AsyncRAT / NjRAT common C2 ranges
        "194.165.16.0", "194.165.16.1",
        // Common abuse ranges flagged by abuse.ch
        "45.142.212.0", "45.142.212.100",
        "91.92.109.0",  "91.92.109.1",
        "194.36.191.0", "194.36.191.1"
    ]

    // MARK: - Public Interface

    /// Returns true if `ip` is on the current blocklist.
    func isBlocked(_ ip: String) -> Bool {
        blocklist.contains(ip)
    }

    /// Ensures the feed is loaded and triggers a background refresh if stale.
    /// Call this on startup — it returns immediately after loading the disk cache.
    func warmUp() async {
        await loadFromDisk()
        if blocklist.isEmpty { blocklist = Self.seedIPs }
        if Date().timeIntervalSince(lastRefresh) > Self.refreshInterval {
            Task.detached(priority: .background) { [weak self] in
                await self?.refresh()
            }
        }
    }

    /// Forces an immediate refresh from the live feed. Normally called by warmUp().
    func refresh() async {
        guard !isRefreshing else { return }
        isRefreshing = true
        defer { isRefreshing = false }

        let url = URL(string: "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.txt")!
        do {
            let (data, _) = try await URLSession.shared.data(from: url)
            guard let text = String(data: data, encoding: .utf8) else { return }
            let parsed = parseFeodoList(text)
            if parsed.count > 10 {          // sanity check — reject empty/corrupt responses
                blocklist    = parsed.union(Self.seedIPs)
                lastRefresh  = Date()
                await saveToDisk()
            }
        } catch {
            // Network failure is non-fatal — keep using seed + disk cache
        }
    }

    // MARK: - Disk Cache

    private struct CachePayload: Codable {
        let ips: [String]
        let refreshedAt: Date
    }

    private func loadFromDisk() async {
        guard let data = try? Data(contentsOf: Self.cacheFileURL) else { return }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        guard let payload = try? decoder.decode(CachePayload.self, from: data) else { return }
        blocklist   = Set(payload.ips).union(Self.seedIPs)
        lastRefresh = payload.refreshedAt
    }

    private func saveToDisk() async {
        let payload = CachePayload(ips: Array(blocklist), refreshedAt: lastRefresh)
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        guard let data = try? encoder.encode(payload) else { return }
        try? data.write(to: Self.cacheFileURL, options: .atomic)
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: Self.cacheFileURL.path
        )
    }

    // MARK: - Feodo Tracker Parser

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
