import XCTest
@testable import Phantom2_0

final class AuditChainTests: XCTestCase {

    // MARK: - Hash Determinism

    func testHashIsDeterministic() {
        let event = makeEvent(details: "test-details")
        XCTAssertEqual(AuditTrailStore.hash(for: event),
                       AuditTrailStore.hash(for: event))
    }

    func testDifferentDetailsProduceDifferentHashes() {
        XCTAssertNotEqual(AuditTrailStore.hash(for: makeEvent(details: "alpha")),
                          AuditTrailStore.hash(for: makeEvent(details: "beta")))
    }

    func testDifferentActionsProduceDifferentHashes() {
        XCTAssertNotEqual(
            AuditTrailStore.hash(for: makeEvent(action: .monitoringStarted)),
            AuditTrailStore.hash(for: makeEvent(action: .monitoringStopped))
        )
    }

    func testHashIsHexString() {
        let h = AuditTrailStore.hash(for: makeEvent(details: "hex-check"))
        // HMAC-SHA256 = 32 bytes = 64 lowercase hex characters
        XCTAssertEqual(h.count, 64)
        XCTAssertTrue(h.allSatisfy { "0123456789abcdef".contains($0) },
                      "Hash contains non-hex character")
    }

    func testPreviousHashIsIncludedInOutput() {
        let withPrev    = makeEvent(details: "d", previousHash: "aabbcc")
        let withoutPrev = makeEvent(details: "d", previousHash: nil)
        XCTAssertNotEqual(AuditTrailStore.hash(for: withPrev),
                          AuditTrailStore.hash(for: withoutPrev))
    }

    // MARK: - Sequence Integrity

    func testSequenceNumberAffectsHash() {
        var e1 = makeEvent(details: "x"); _ = e1 // seq 0 (default)
        let e2 = AuditEvent(
            timestamp: e1.timestamp,
            sequenceNumber: 99,
            action: e1.action,
            details: e1.details,
            operatorName: e1.operatorName
        )
        XCTAssertNotEqual(AuditTrailStore.hash(for: e1),
                          AuditTrailStore.hash(for: e2))
    }

    // MARK: - Helpers

    private func makeEvent(
        action: AuditAction = .settingsUpdated,
        details: String = "test",
        previousHash: String? = nil
    ) -> AuditEvent {
        AuditEvent(
            timestamp:    Date(timeIntervalSince1970: 1_700_000_000),
            action:       action,
            details:      details,
            operatorName: "tester",
            hostName:     "test-host",
            previousHash: previousHash,
            eventHash:    nil
        )
    }
}
