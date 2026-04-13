import Foundation
import OSLog

actor TelemetryBroker {

    enum CollectionPath: String { case localFallback }

    private let logger = Logger(subsystem: "Phantom", category: "TelemetryBroker")
    private var inFlightCapture: Task<ScanSnapshot, Never>?
    private(set) var lastCollectionPath: CollectionPath = .localFallback

    func capture(appNames: [String], preferPrivilegedHelper: Bool = false) async -> ScanSnapshot {
        if let inFlightCapture { return await inFlightCapture.value }

        lastCollectionPath = .localFallback
        let task = Task { [logger, appNames] in
            await Self.captureWithTimeout(appNames: appNames, logger: logger)
        }
        inFlightCapture = task
        let snapshot = await task.value
        inFlightCapture = nil
        return snapshot
    }

    private static func captureWithTimeout(appNames: [String], logger: Logger) async -> ScanSnapshot {
        await withTaskGroup(of: ScanSnapshot.self) { group in
            group.addTask { await ScanSnapshot.capture(appNames: appNames) }
            group.addTask {
                try? await Task.sleep(nanoseconds: 30_000_000_000)
                logger.error("Global telemetry timeout — returning empty snapshot.")
                return ScanSnapshot(incidents: [], launches: [])
            }
            let first = await group.next() ?? ScanSnapshot(incidents: [], launches: [])
            group.cancelAll()
            return first
        }
    }
}
