import Foundation

// MARK: - ScanHistoryStore
//
// Persists a rolling window of ScanRecord values so the UI can show risk-score
// trends over time. Records are stored newest-first; the window is capped at
// maxRecords to bound disk and memory use.
//
// Storage: ~/Library/Application Support/Phantom/Phantom-History.json
// Permissions: 0600 (owner read/write only), directory 0700.
// No integrity chain — history is informational, not security-critical.
// Tampering would only affect trend display, not detection outcomes.

enum ScanHistoryStore {

    // MARK: - Configuration

    /// Maximum number of records retained. At the 60-second default scan
    /// interval this is ~25 hours of history; at 300 s it is ~5 days.
    static let maxRecords = 1500

    // MARK: - Storage

    private static let directoryName = "Phantom"
    private static let fileName      = "Phantom-History.json"

    private static var fileURL: URL {
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

    // MARK: - Public Interface

    /// Loads the persisted history, newest first. Returns [] on any error.
    static func load() -> [ScanRecord] {
        guard let data = try? Data(contentsOf: fileURL) else { return [] }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let records = (try? decoder.decode([ScanRecord].self, from: data)) ?? []
        return records.sorted { $0.timestamp > $1.timestamp }
    }

    /// Prepends `record` to the history and trims to `maxRecords`, then persists.
    /// Returns the updated history newest-first.
    @discardableResult
    static func append(_ record: ScanRecord) -> [ScanRecord] {
        var records = load()
        records.insert(record, at: 0)
        if records.count > maxRecords {
            records = Array(records.prefix(maxRecords))
        }
        save(records)
        return records
    }

    // MARK: - Private

    private static func save(_ records: [ScanRecord]) {
        let encoder = JSONEncoder()
        encoder.outputFormatting     = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        guard let data = try? encoder.encode(records) else { return }
        try? data.write(to: fileURL, options: .atomic)
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: fileURL.path
        )
    }
}
