import Foundation

struct AppSettings: Codable {
    var startAtLogin: Bool = false
    var enableNotifications: Bool = true
    // POWER: default 60s, minimum 60s.
    // Running ps + lsof + filesystem scans every 30s causes Energy Impact: High.
    // 60s is the right baseline for a passive menu-bar security monitor.
    // The "Scan Now" button is always available for on-demand checks.
    var scanIntervalSeconds: Double = 60

    private static let saveKey = "Phantom.AppSettings"

    static func load() -> AppSettings {
        guard let data    = UserDefaults.standard.data(forKey: saveKey),
              let decoded = try? JSONDecoder().decode(AppSettings.self, from: data)
        else { return AppSettings() }
        // Clamp on load — handles existing saves with old 10s default
        var s = decoded
        s.scanIntervalSeconds = max(60, s.scanIntervalSeconds)
        return s
    }

    func save() {
        guard let data = try? JSONEncoder().encode(self) else { return }
        UserDefaults.standard.set(data, forKey: Self.saveKey)
    }
}
