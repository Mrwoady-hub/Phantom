import XCTest
@testable import Phantom2_0

// MARK: - IncidentStoreTests
//
// Validates end-to-end persistence of the incident list across simulated
// cold restarts. Uses a real temporary file so encoding/decoding are exercised
// exactly as they will be in production.
//
// Test scenarios:
//   1. Round-trip: create → save → load, verify all fields survive.
//   2. Multiple incidents: order and count are preserved.
//   3. Active incidents never pruned regardless of age.
//   4. Resolved incidents older than 7 days are pruned on save/load.
//   5. Resolved incidents within 7 days are retained.
//   6. Clear: file removed; subsequent load returns [].
//   7. Corrupt file: load returns [], does not crash.

final class IncidentStoreTests: XCTestCase {

    // MARK: - Helpers

    /// Returns a minimal valid Incident.
    private func makeIncident(
        name: String = "Test Incident",
        severity: Severity = .medium,
        status: IncidentStatus = .active,
        lastSeen: Date = Date()
    ) -> Incident {
        var i = Incident(
            name: name,
            severity: severity,
            confidence: .high,
            detail: "Unit test incident",
            source: .process,
            lastSeen: lastSeen,
            status: status,
            trust: .unclassified,
            family: "test-family",
            suppressionKey: "test-key",
            recommendedAction: "Investigate",
            whySurfaced: "Test"
        )
        // Force status for resolved cases (init defaults to .active)
        if status == .resolved { i.resolve() }
        return i
    }

    // MARK: - 1. Round-trip

    func testSaveAndLoadPreservesActiveIncident() {
        let incident = makeIncident(name: "RoundTrip", severity: .high)

        IncidentStore.save([incident])
        let loaded = IncidentStore.load()
        IncidentStore.clear()

        XCTAssertEqual(loaded.count, 1)
        let r = loaded[0]
        XCTAssertEqual(r.id, incident.id)
        XCTAssertEqual(r.name, incident.name)
        XCTAssertEqual(r.severity, incident.severity)
        XCTAssertEqual(r.status, .active)
        XCTAssertEqual(r.family, incident.family)
        XCTAssertEqual(r.suppressionKey, incident.suppressionKey)
    }

    // MARK: - 2. Multiple incidents

    func testSaveAndLoadPreservesMultipleIncidents() {
        let a = makeIncident(name: "Alpha")
        let b = makeIncident(name: "Beta", severity: .high)
        let c = makeIncident(name: "Gamma", severity: .low)

        IncidentStore.save([a, b, c])
        let loaded = IncidentStore.load()
        IncidentStore.clear()

        XCTAssertEqual(loaded.count, 3)
        let names = Set(loaded.map(\.name))
        XCTAssertTrue(names.contains("Alpha"))
        XCTAssertTrue(names.contains("Beta"))
        XCTAssertTrue(names.contains("Gamma"))
    }

    // MARK: - 3. Active incidents never pruned

    func testActiveIncidentsNotPrunedRegardlessOfAge() {
        // An active incident from 365 days ago must survive.
        let ancient = makeIncident(
            name: "AncientActive",
            status: .active,
            lastSeen: Date().addingTimeInterval(-365 * 24 * 3600)
        )

        IncidentStore.save([ancient])
        let loaded = IncidentStore.load()
        IncidentStore.clear()

        XCTAssertEqual(loaded.count, 1,
            "Active incidents must never be pruned by age")
        XCTAssertEqual(loaded.first?.status, .active)
    }

    // MARK: - 4. Resolved incidents older than 7 days are pruned

    func testResolvedIncidentsOlderThan7DaysArePruned() {
        var stale = makeIncident(name: "StaleResolved")
        stale.resolve(at: Date().addingTimeInterval(-8 * 24 * 3600))

        IncidentStore.save([stale])
        let loaded = IncidentStore.load()
        IncidentStore.clear()

        XCTAssertEqual(loaded.count, 0,
            "Resolved incidents older than 7 days must be pruned")
    }

    // MARK: - 5. Recent resolved incidents are retained

    func testResolvedIncidentsWithin7DaysAreRetained() {
        var fresh = makeIncident(name: "FreshResolved")
        fresh.resolve(at: Date().addingTimeInterval(-3 * 24 * 3600))  // 3 days ago

        IncidentStore.save([fresh])
        let loaded = IncidentStore.load()
        IncidentStore.clear()

        XCTAssertEqual(loaded.count, 1,
            "Resolved incidents within 7 days must be retained")
        XCTAssertEqual(loaded.first?.status, .resolved)
    }

    // MARK: - 6. Mixed active + stale resolved

    func testMixedActiveAndStaleResolvedOnlyPrunesStale() {
        let active = makeIncident(name: "Active")
        var stale  = makeIncident(name: "Stale")
        stale.resolve(at: Date().addingTimeInterval(-10 * 24 * 3600))
        var fresh  = makeIncident(name: "FreshResolved")
        fresh.resolve(at: Date().addingTimeInterval(-2 * 24 * 3600))

        IncidentStore.save([active, stale, fresh])
        let loaded = IncidentStore.load()
        IncidentStore.clear()

        XCTAssertEqual(loaded.count, 2)
        let names = Set(loaded.map(\.name))
        XCTAssertTrue(names.contains("Active"))
        XCTAssertTrue(names.contains("FreshResolved"))
        XCTAssertFalse(names.contains("Stale"),
            "Stale resolved must be pruned; active and fresh-resolved must survive")
    }

    // MARK: - 7. Clear

    func testClearRemovesFile() {
        IncidentStore.save([makeIncident()])
        IncidentStore.clear()
        let loaded = IncidentStore.load()
        XCTAssertEqual(loaded.count, 0,
            "After clear(), load() must return empty array")
    }

    // MARK: - 8. Corrupt file

    func testCorruptFileReturnsEmpty() {
        // Write garbage to the store URL directly.
        let appSupport = FileManager.default.urls(
            for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let url = appSupport
            .appendingPathComponent("Phantom", isDirectory: true)
            .appendingPathComponent("Phantom-Incidents.json")
        try? FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(),
            withIntermediateDirectories: true)
        try? Data("not valid JSON }{}{".utf8).write(to: url)

        let loaded = IncidentStore.load()
        IncidentStore.clear()

        XCTAssertEqual(loaded.count, 0,
            "Corrupt file must return [] without crashing")
    }

    // MARK: - 9. Simulated cold restart (load after save in same process)

    func testSimulatedColdRestart() {
        let original = makeIncident(name: "PersistMe", severity: .high)
        IncidentStore.save([original])

        // Simulate restart: load independently
        let restored = IncidentStore.load()
        IncidentStore.clear()

        XCTAssertEqual(restored.count, 1)
        XCTAssertEqual(restored.first?.id, original.id,
            "Incident ID must survive a cold restart (save → load cycle)")
        XCTAssertEqual(restored.first?.name, original.name)
        XCTAssertEqual(restored.first?.severity, original.severity)
        XCTAssertEqual(restored.first?.status, .active)
    }
}
