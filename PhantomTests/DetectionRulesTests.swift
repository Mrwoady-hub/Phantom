import XCTest
@testable import Phantom2_0

// MARK: - DetectionRulesTests
//
// Tests for the five Tier-3 detection rules in TelemetrySnapshot.
// Each test creates a ProcessEntry with controlled fields and asserts
// whether the rule fires (incident returned) or stays silent (nil).

final class DetectionRulesTests: XCTestCase {

    // MARK: - T1036 Masquerading

    func testMasquerading_firesForSystemNameInTmpPath() {
        let entry = makeEntry(path: "/tmp/ls")
        XCTAssertNotNil(ScanSnapshot.masqueradingIncident(for: entry))
    }

    func testMasquerading_firesForCurlInDownloads() {
        let entry = makeEntry(path: "\(NSHomeDirectory())/Downloads/curl")
        XCTAssertNotNil(ScanSnapshot.masqueradingIncident(for: entry))
    }

    func testMasquerading_silentForRealSystemBinary() {
        let entry = makeEntry(path: "/usr/bin/curl")
        XCTAssertNil(ScanSnapshot.masqueradingIncident(for: entry))
    }

    func testMasquerading_silentForUnknownBinaryName() {
        let entry = makeEntry(path: "/tmp/myapp")
        XCTAssertNil(ScanSnapshot.masqueradingIncident(for: entry))
    }

    func testMasquerading_silentForHomebrewBinary() {
        let entry = makeEntry(path: "/opt/homebrew/bin/bash")
        XCTAssertNil(ScanSnapshot.masqueradingIncident(for: entry))
    }

    func testMasquerading_correctTechnique() {
        let entry = makeEntry(path: "/tmp/bash")
        let inc = ScanSnapshot.masqueradingIncident(for: entry)
        XCTAssertEqual(inc?.technique, .masquerading)
        XCTAssertEqual(inc?.source, .process)
        XCTAssertEqual(inc?.severity, .high)
    }

    // MARK: - T1003 Credential Dumping

    func testCredDump_firesForKeychaindump() {
        let entry = makeEntry(path: "/tmp/keychaindump")
        XCTAssertNotNil(ScanSnapshot.credentialDumpingIncident(for: entry))
    }

    func testCredDump_firesForSecurityDumpKeychain() {
        let entry = makeEntry(path: "/usr/bin/security", args: "dump-keychain -d")
        XCTAssertNotNil(ScanSnapshot.credentialDumpingIncident(for: entry))
    }

    func testCredDump_firesForSecurityFindGenericPassword() {
        let entry = makeEntry(path: "/usr/bin/security", args: "find-generic-password -s MyService")
        XCTAssertNotNil(ScanSnapshot.credentialDumpingIncident(for: entry))
    }

    func testCredDump_silentForSecurityListKeychains() {
        let entry = makeEntry(path: "/usr/bin/security", args: "list-keychains")
        XCTAssertNil(ScanSnapshot.credentialDumpingIncident(for: entry))
    }

    func testCredDump_correctTechnique() {
        let entry = makeEntry(path: "/tmp/keychaindump")
        XCTAssertEqual(ScanSnapshot.credentialDumpingIncident(for: entry)?.technique,
                       .osCredentialDumping)
    }

    // MARK: - T1562 Impair Defenses

    func testImpair_firesForPfctlDisable() {
        let entry = makeEntry(path: "/sbin/pfctl", args: "-d")
        XCTAssertNotNil(ScanSnapshot.impairDefensesIncident(for: entry))
    }

    func testImpair_firesForLaunchctlDisable() {
        let entry = makeEntry(path: "/bin/launchctl", args: "disable system/com.apple.auditd")
        XCTAssertNotNil(ScanSnapshot.impairDefensesIncident(for: entry))
    }

    func testImpair_silentForPfctlStatus() {
        let entry = makeEntry(path: "/sbin/pfctl", args: "-s all")
        XCTAssertNil(ScanSnapshot.impairDefensesIncident(for: entry))
    }

    func testImpair_correctTechnique() {
        let entry = makeEntry(path: "/bin/launchctl", args: "bootout system/com.apple.auditd")
        XCTAssertEqual(ScanSnapshot.impairDefensesIncident(for: entry)?.technique,
                       .impairDefenses)
    }

    // MARK: - T1055 Process Injection

    func testInjection_firesForDyldInsertLibraries() {
        let entry = makeEntry(path: "/tmp/launcher",
                              args: "DYLD_INSERT_LIBRARIES=/tmp/evil.dylib /bin/ls")
        XCTAssertNotNil(ScanSnapshot.processInjectionIncident(for: entry))
    }

    func testInjection_firesForDyldFlatNamespace() {
        let entry = makeEntry(path: "/tmp/runner",
                              args: "DYLD_FORCE_FLAT_NAMESPACE=1 /bin/sh")
        XCTAssertNotNil(ScanSnapshot.processInjectionIncident(for: entry))
    }

    func testInjection_silentForCleanProcess() {
        let entry = makeEntry(path: "/Applications/Safari.app/Contents/MacOS/Safari")
        XCTAssertNil(ScanSnapshot.processInjectionIncident(for: entry))
    }

    func testInjection_correctTechnique() {
        let entry = makeEntry(path: "/tmp/x",
                              args: "DYLD_INSERT_LIBRARIES=/tmp/y.dylib")
        XCTAssertEqual(ScanSnapshot.processInjectionIncident(for: entry)?.technique,
                       .processInjection)
    }

    // MARK: - T1082 System Info Discovery

    func testSysInfo_firesForSystemProfilerInTmp() {
        let entry = makeEntry(path: "/tmp/system_profiler")
        XCTAssertNotNil(ScanSnapshot.sysInfoDiscoveryIncident(for: entry))
    }

    func testSysInfo_silentForSystemProfilerInSystemPath() {
        // system_profiler lives at /usr/sbin — isDefinitelySystemProcess = true
        let entry = makeEntry(path: "/usr/sbin/system_profiler")
        XCTAssertNil(ScanSnapshot.sysInfoDiscoveryIncident(for: entry))
    }

    func testSysInfo_correctTechnique() {
        let entry = makeEntry(path: "\(NSHomeDirectory())/Desktop/ioreg")
        XCTAssertEqual(ScanSnapshot.sysInfoDiscoveryIncident(for: entry)?.technique,
                       .systemInformationDiscovery)
    }

    // MARK: - Helpers

    private func makeEntry(
        path: String,
        args: String = "",
        pid: Int = 1234,
        ppid: Int = 1
    ) -> ProcessEntry {
        ProcessEntry(pid: pid, ppid: ppid, user: "testuser",
                     executablePath: path, arguments: args)
    }
}
