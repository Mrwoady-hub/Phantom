import XCTest

// MARK: - HelperCaptureOutputTests
//
// Focused tests for the pcap output filename sanitizer. The full prepare()
// flow touches /var/db and requires root; we only test the pure-function
// guard that strips path separators, shell metacharacters, and dotfiles.

final class HelperCaptureOutputTests: XCTestCase {

    func testSanitize_stripsPathSeparators() {
        XCTAssertEqual(
            HelperCaptureOutput.sanitize(filename: "../../etc/passwd"),
            "passwd"
        )
    }

    func testSanitize_keepsBasenameOnly() {
        XCTAssertEqual(
            HelperCaptureOutput.sanitize(filename: "/private/tmp/foo.pcap"),
            "foo.pcap"
        )
    }

    func testSanitize_stripsShellMetacharacters() {
        XCTAssertEqual(
            HelperCaptureOutput.sanitize(filename: "foo;rm -rf /.pcap"),
            "foorm-rf.pcap"
        )
    }

    func testSanitize_rejectsDotfiles() {
        XCTAssertEqual(
            HelperCaptureOutput.sanitize(filename: ".hidden"),
            "hidden"
        )
    }

    func testSanitize_emptyInputReturnsDefault() {
        XCTAssertEqual(
            HelperCaptureOutput.sanitize(filename: ""),
            "phantom-capture.pcap"
        )
    }

    func testSanitize_allDisallowedReturnsDefault() {
        XCTAssertEqual(
            HelperCaptureOutput.sanitize(filename: "///"),
            "phantom-capture.pcap"
        )
    }

    func testSanitize_preservesUnderscoresAndDashes() {
        XCTAssertEqual(
            HelperCaptureOutput.sanitize(filename: "phantom_capture-2026.pcap"),
            "phantom_capture-2026.pcap"
        )
    }
}
