import XCTest
@testable import Phantom2_0

final class RiskScoringTests: XCTestCase {

    // MARK: - Default Score Computation

    func testLowSeverityMediumConfidence() {
        let inc = makeIncident(severity: .low, confidence: .medium)
        XCTAssertEqual(inc.score, 10)   // base 10 × 1.0
    }

    func testMediumSeverityMediumConfidence() {
        let inc = makeIncident(severity: .medium, confidence: .medium)
        XCTAssertEqual(inc.score, 25)   // base 25 × 1.0
    }

    func testHighSeverityMediumConfidence() {
        let inc = makeIncident(severity: .high, confidence: .medium)
        XCTAssertEqual(inc.score, 50)   // base 50 × 1.0
    }

    func testHighConfidenceBoostsScore() {
        let med  = makeIncident(severity: .high, confidence: .medium)
        let high = makeIncident(severity: .high, confidence: .high)
        XCTAssertGreaterThan(high.score, med.score)
    }

    func testLowConfidenceReducesScore() {
        let med = makeIncident(severity: .high, confidence: .medium)
        let low = makeIncident(severity: .high, confidence: .low)
        XCTAssertLessThan(low.score, med.score)
    }

    func testHighSeverityHighConfidenceScore() {
        let inc = makeIncident(severity: .high, confidence: .high)
        XCTAssertEqual(inc.score, Int((50.0 * 1.3).rounded()))  // 65
    }

    // MARK: - Suppression State

    func testFreshIncidentIsNotSuppressed() {
        XCTAssertFalse(makeIncident().isSuppressed)
    }

    func testSuppressedIncidentReflectsDate() {
        var inc = makeIncident()
        inc.suppressedAt = Date()
        XCTAssertTrue(inc.isSuppressed)
    }

    // MARK: - Acknowledgement State

    func testFreshIncidentIsNotAcknowledged() {
        XCTAssertFalse(makeIncident().isAcknowledged)
    }

    func testAcknowledgedIncidentReflectsDate() {
        var inc = makeIncident()
        inc.acknowledgedAt = Date()
        XCTAssertTrue(inc.isAcknowledged)
    }

    // MARK: - Family & Suppression Key Stability

    func testFamilyKeyIsStable() {
        let a = makeIncident(name: "Test Incident", source: .process)
        let b = makeIncident(name: "Test Incident", source: .process)
        XCTAssertEqual(a.family, b.family)
    }

    func testDifferentSourcesProduceDifferentFamilyKeys() {
        let proc = makeIncident(name: "Foo", source: .process)
        let net  = makeIncident(name: "Foo", source: .network)
        XCTAssertNotEqual(proc.family, net.family)
    }

    func testSuppressionKeyIncludesTrust() {
        let unclassified = makeIncident(trust: .unclassified)
        let suspicious   = makeIncident(trust: .suspicious)
        XCTAssertNotEqual(unclassified.suppressionKey, suspicious.suppressionKey)
    }

    // MARK: - Status Transitions

    func testFreshIncidentIsActive() {
        XCTAssertEqual(makeIncident().status, .active)
    }

    func testResolveChangesStatus() {
        var inc = makeIncident()
        inc.resolve()
        XCTAssertEqual(inc.status, .resolved)
    }

    func testRefreshSeenIncrementsCount() {
        var inc = makeIncident()
        let before = inc.occurrenceCount
        inc.refreshSeen()
        XCTAssertEqual(inc.occurrenceCount, before + 1)
    }

    // MARK: - Helpers

    private func makeIncident(
        name: String = "Test",
        severity: Severity = .medium,
        confidence: DetectionConfidence = .medium,
        source: IncidentSource = .process,
        trust: IncidentTrust = .unclassified
    ) -> Incident {
        Incident(name: name, severity: severity, confidence: confidence,
                 source: source, trust: trust)
    }
}
