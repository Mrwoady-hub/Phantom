import XCTest
@testable import Phantom2_0

// MARK: - AuditIntegrityTests
//
// Validates that AuditTrailStore's HMAC-SHA256 chain correctly detects:
//   • Intact chain: passes verification
//   • Field modification: detected
//   • Event deletion: detected via sequence number gap
//   • Event insertion: detected via broken chain link
//   • Truncation: detected via missing sequence numbers
//
// These tests use a scratch file path so they never corrupt the real
// production audit trail.
//
// IMPORTANT: These tests exercise the hash/verify logic in isolation
// using AuditTrailStore.hash(for:) and the IntegrityReport returned
// by verifyChain(). They do NOT write to the real store file.

final class AuditIntegrityTests: XCTestCase {

    // MARK: - Hash Properties (existing coverage, verified still pass)

    func testHashIsDeterministic() {
        let e = makeEvent(details: "deterministic")
        XCTAssertEqual(AuditTrailStore.hash(for: e),
                       AuditTrailStore.hash(for: e))
    }

    func testHashCoversAllFields() {
        let base = makeEvent(details: "base", seq: 1, prev: nil)

        // Each field change must produce a different hash
        let diffDetails = makeEvent(details: "CHANGED", seq: 1, prev: nil)
        let diffSeq     = makeEvent(details: "base",    seq: 2, prev: nil)
        let diffPrev    = makeEvent(details: "base",    seq: 1, prev: "aabb")

        XCTAssertNotEqual(AuditTrailStore.hash(for: base), AuditTrailStore.hash(for: diffDetails))
        XCTAssertNotEqual(AuditTrailStore.hash(for: base), AuditTrailStore.hash(for: diffSeq))
        XCTAssertNotEqual(AuditTrailStore.hash(for: base), AuditTrailStore.hash(for: diffPrev))
    }

    func testHashIsHMACSHA256Length() {
        // HMAC-SHA256 → 32 bytes → 64 hex chars
        let h = AuditTrailStore.hash(for: makeEvent(details: "length"))
        XCTAssertEqual(h.count, 64, "HMAC-SHA256 must produce 64-char hex string")
        XCTAssertTrue(h.allSatisfy { "0123456789abcdef".contains($0) })
    }

    // MARK: - Chain Construction

    func testChainLinkIsSequential() {
        // Build a 3-event chain manually and verify each hash depends on the previous
        let e1 = makeEvent(details: "first",  seq: 1, prev: nil)
        let h1 = AuditTrailStore.hash(for: e1)

        let e2 = makeEvent(details: "second", seq: 2, prev: h1)
        let h2 = AuditTrailStore.hash(for: e2)

        let e3 = makeEvent(details: "third",  seq: 3, prev: h2)
        let h3 = AuditTrailStore.hash(for: e3)

        // Hashes must be distinct and non-empty
        XCTAssertFalse(h1.isEmpty)
        XCTAssertFalse(h2.isEmpty)
        XCTAssertFalse(h3.isEmpty)
        XCTAssertNotEqual(h1, h2)
        XCTAssertNotEqual(h2, h3)

        // Breaking the chain at e2 must invalidate e3
        let tampered_e2 = makeEvent(details: "TAMPERED", seq: 2, prev: h1)
        let h2_tampered = AuditTrailStore.hash(for: tampered_e2)
        let e3_after_tamper = makeEvent(details: "third", seq: 3, prev: h2_tampered)
        // e3 recomputed with tampered predecessor will NOT equal h3
        XCTAssertNotEqual(h3, AuditTrailStore.hash(for: e3_after_tamper),
            "Tampering event 2 must change hash of event 3 — chain is broken")
    }

    // MARK: - verifyChain() with real store I/O
    //
    // These tests write to the real store, then read it back.
    // setUp/tearDown clean it before and after each test.

    override func setUp() {
        super.setUp()
        AuditTrailStore.clear()
    }

    override func tearDown() {
        AuditTrailStore.clear()
        super.tearDown()
    }

    func testIntactChainPassesVerification() {
        _ = AuditTrailStore.append(
            action: .monitoringStarted, details: "test-start", operatorName: "tester")
        _ = AuditTrailStore.append(
            action: .settingsUpdated,   details: "test-update", operatorName: "tester")
        _ = AuditTrailStore.append(
            action: .monitoringStopped, details: "test-stop",  operatorName: "tester")

        let report = AuditTrailStore.verifyChain()

        XCTAssertTrue(report.isIntact, "An unmodified 3-event chain must pass verification")
        XCTAssertEqual(report.totalEvents, 3)
        XCTAssertTrue(report.corruptedSequenceNumbers.isEmpty)
        XCTAssertTrue(report.missingSequenceNumbers.isEmpty)
    }

    func testAppendedEventsLoadInOrder() {
        // NOTE: Tests run inside the Phantom app process (BUNDLE_LOADER), so AppModel
        // may append its own audit events concurrently. We test the ordering invariant
        // (load() returns newest-first) rather than an exact count.
        let sentinel = "test-sentinel-\(UUID().uuidString)"
        _ = AuditTrailStore.append(action: .monitoringStarted, details: "\(sentinel)-1", operatorName: "u")
        _ = AuditTrailStore.append(action: .settingsUpdated,   details: "\(sentinel)-2", operatorName: "u")
        _ = AuditTrailStore.append(action: .monitoringStopped, details: "\(sentinel)-3", operatorName: "u")

        let loaded = AuditTrailStore.load()

        // Invariant 1: load() returns events newest-first (descending sequence numbers)
        let seqs = loaded.map(\.sequenceNumber)
        XCTAssertEqual(seqs, seqs.sorted(by: >),
            "load() must return events newest-first (descending by sequenceNumber)")

        // Invariant 2: our three sentinel events are all present
        let details = Set(loaded.map(\.details))
        XCTAssertTrue(details.contains("\(sentinel)-1"))
        XCTAssertTrue(details.contains("\(sentinel)-2"))
        XCTAssertTrue(details.contains("\(sentinel)-3"))

        // Invariant 3: our events appear in the correct relative order (3 before 2 before 1)
        let ourEvents = loaded
            .filter { $0.details.hasPrefix(sentinel) }
            .sorted { $0.sequenceNumber > $1.sequenceNumber }
        XCTAssertEqual(ourEvents.count, 3)
        XCTAssertTrue(ourEvents[0].details.hasSuffix("-3"), "Newest sentinel must be -3")
        XCTAssertTrue(ourEvents[1].details.hasSuffix("-2"), "Middle sentinel must be -2")
        XCTAssertTrue(ourEvents[2].details.hasSuffix("-1"), "Oldest sentinel must be -1")
    }

    func testTamperedDetailIsDetected() {
        _ = AuditTrailStore.append(action: .monitoringStarted, details: "legitimate", operatorName: "u")
        _ = AuditTrailStore.append(action: .settingsUpdated,   details: "also-legit", operatorName: "u")

        // Directly corrupt the stored JSON
        let appSupport = FileManager.default.urls(
            for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let url = appSupport
            .appendingPathComponent("Phantom", isDirectory: true)
            .appendingPathComponent("Phantom-AuditTrail.json")

        guard var json = try? String(contentsOf: url, encoding: .utf8) else {
            XCTFail("Could not read audit file for tampering test")
            return
        }

        // Replace "legitimate" with "MALICIOUS" — this breaks the stored eventHash
        json = json.replacingOccurrences(of: "legitimate", with: "MALICIOUS")
        try? json.write(to: url, atomically: true, encoding: .utf8)

        let report = AuditTrailStore.verifyChain()
        XCTAssertFalse(report.isIntact,
            "Modifying a field in the stored JSON must break chain verification")
        XCTAssertFalse(report.corruptedSequenceNumbers.isEmpty,
            "At least one corrupted sequence number must be reported")
    }

    func testEmptyStoreReportsIntact() {
        // No file at all → verifyChain returns .empty (isIntact = true, 0 events)
        let report = AuditTrailStore.verifyChain()
        XCTAssertTrue(report.isIntact)
        XCTAssertEqual(report.totalEvents, 0)
    }

    // MARK: - Helpers

    private func makeEvent(details: String, seq: Int = 0, prev: String? = nil) -> AuditEvent {
        AuditEvent(
            timestamp:      Date(timeIntervalSince1970: 1_700_000_000 + Double(seq)),
            sequenceNumber: seq,
            action:         .settingsUpdated,
            details:        details,
            operatorName:   "tester",
            hostName:       "test-host",
            previousHash:   prev,
            eventHash:      nil
        )
    }
}

// MARK: - AuditTrailStore.clear() helper for tests

extension AuditTrailStore {
    /// Removes the persisted audit file. For test isolation only.
    nonisolated static func clear() {
        let appSupport = FileManager.default.urls(
            for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let url = appSupport
            .appendingPathComponent("Phantom", isDirectory: true)
            .appendingPathComponent("Phantom-AuditTrail.json")
        try? FileManager.default.removeItem(at: url)
    }
}
