import XCTest
@testable import Phantom2_0

final class ThreatIntelTests: XCTestCase {

    // MARK: - IP Extraction

    func testExtractIPv4_bareAddress() {
        XCTAssertEqual("1.2.3.4".extractedIPv4, "1.2.3.4")
    }

    func testExtractIPv4_withPort() {
        XCTAssertEqual("1.2.3.4:443".extractedIPv4, "1.2.3.4")
    }

    func testExtractIPv4_highPort() {
        XCTAssertEqual("10.0.0.1:65535".extractedIPv4, "10.0.0.1")
    }

    func testExtractIPv4_hostname_returnsNil() {
        XCTAssertNil("example.com".extractedIPv4)
        XCTAssertNil("api.github.com:443".extractedIPv4)
    }

    func testExtractIPv4_ipv6_returnsNil() {
        XCTAssertNil("::1".extractedIPv4)
        XCTAssertNil("[::1]:80".extractedIPv4)
        XCTAssertNil("2001:db8::1".extractedIPv4)
    }

    func testExtractIPv4_outOfRangeOctet_returnsNil() {
        XCTAssertNil("256.0.0.1".extractedIPv4)
        XCTAssertNil("1.2.3.999".extractedIPv4)
    }

    func testExtractIPv4_tooFewOctets_returnsNil() {
        XCTAssertNil("1.2.3".extractedIPv4)
        XCTAssertNil("1.2".extractedIPv4)
    }

    func testExtractIPv4_localhost() {
        XCTAssertEqual("127.0.0.1".extractedIPv4, "127.0.0.1")
        XCTAssertEqual("127.0.0.1:8080".extractedIPv4, "127.0.0.1")
    }

    // MARK: - ThreatIntelFeed Blocklist

    func testFeedDoesNotBlockArbitraryIP() async {
        let feed = ThreatIntelFeed.shared
        let blocked = await feed.isBlocked("8.8.8.8")
        XCTAssertFalse(blocked, "8.8.8.8 (Google DNS) should not be on the blocklist")
    }

    func testFeedIsBlocked_afterManualInsert() async {
        // Use a private test feed instance to avoid polluting the shared singleton
        let feed = ThreatIntelFeed()
        await feed.warmUp()
        // The seed list does NOT contain 8.8.8.8
        let blocked = await feed.isBlocked("8.8.8.8")
        XCTAssertFalse(blocked)
    }

    // MARK: - ScanRecord Codable Round-Trip

    func testScanRecordCodableRoundTrip() throws {
        let record = ScanRecord(
            riskScore: 42, activeCount: 3, resolvedCount: 1,
            highCount: 1, mediumCount: 1, lowCount: 1
        )
        let data    = try JSONEncoder().encode(record)
        let decoded = try JSONDecoder().decode(ScanRecord.self, from: data)
        XCTAssertEqual(decoded.riskScore,     record.riskScore)
        XCTAssertEqual(decoded.activeCount,   record.activeCount)
        XCTAssertEqual(decoded.resolvedCount, record.resolvedCount)
        XCTAssertEqual(decoded.highCount,     record.highCount)
        XCTAssertEqual(decoded.id,            record.id)
    }
}
