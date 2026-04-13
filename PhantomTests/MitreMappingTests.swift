import XCTest
@testable import Phantom2_0

final class MitreMappingTests: XCTestCase {

    // MARK: - Technique Coverage

    func testAllTechniquesHaveNonEmptyTitle() {
        let all: [MitreTechnique] = [
            .commandAndScriptingInterpreter, .applicationLayerProtocol,
            .ingressToolTransfer, .bootOrLogonAutostartExecution,
            .osCredentialDumping, .masquerading, .processInjection,
            .systemInformationDiscovery, .impairDefenses
        ]
        for technique in all {
            XCTAssertFalse(technique.title.isEmpty,
                           "\(technique.rawValue) has an empty title")
        }
    }

    func testAllTechniquesHaveValidATTACKId() {
        let all: [MitreTechnique] = [
            .commandAndScriptingInterpreter, .applicationLayerProtocol,
            .ingressToolTransfer, .bootOrLogonAutostartExecution,
            .osCredentialDumping, .masquerading, .processInjection,
            .systemInformationDiscovery, .impairDefenses
        ]
        let idPattern = #"^T\d{4}$"#
        for technique in all {
            XCTAssertTrue(
                technique.rawValue.range(of: idPattern, options: .regularExpression) != nil,
                "\(technique.rawValue) does not match TNNNN pattern"
            )
        }
    }

    func testReferenceURLsContainTechniqueId() {
        let all: [MitreTechnique] = [
            .commandAndScriptingInterpreter, .applicationLayerProtocol,
            .ingressToolTransfer, .bootOrLogonAutostartExecution,
            .osCredentialDumping, .masquerading, .processInjection,
            .systemInformationDiscovery, .impairDefenses
        ]
        for technique in all {
            XCTAssertTrue(
                technique.referenceURL.absoluteString.contains(technique.rawValue),
                "\(technique.rawValue) URL does not contain the technique ID"
            )
        }
    }

    // MARK: - Codable Round-Trip

    func testMitreTechniqueCodableRoundTrip() throws {
        let original: MitreTechnique = .osCredentialDumping
        let data     = try JSONEncoder().encode(original)
        let decoded  = try JSONDecoder().decode(MitreTechnique.self, from: data)
        XCTAssertEqual(decoded, original)
    }

    // MARK: - Incident Technique Assignment

    func testMasqueradingIncidentHasCorrectTechnique() {
        let entry = ProcessEntry(pid: 1, ppid: 0, user: "u",
                                 executablePath: "/tmp/ls", arguments: "")
        let inc = ScanSnapshot.masqueradingIncident(for: entry)
        XCTAssertEqual(inc?.technique, .masquerading)
    }

    func testCredDumpIncidentHasCorrectTechnique() {
        let entry = ProcessEntry(pid: 1, ppid: 0, user: "u",
                                 executablePath: "/tmp/keychaindump", arguments: "")
        let inc = ScanSnapshot.credentialDumpingIncident(for: entry)
        XCTAssertEqual(inc?.technique, .osCredentialDumping)
    }

    func testImpairDefensesIncidentHasCorrectTechnique() {
        let entry = ProcessEntry(pid: 1, ppid: 0, user: "u",
                                 executablePath: "/sbin/pfctl", arguments: "-d")
        let inc = ScanSnapshot.impairDefensesIncident(for: entry)
        XCTAssertEqual(inc?.technique, .impairDefenses)
    }

    func testInjectionIncidentHasCorrectTechnique() {
        let entry = ProcessEntry(pid: 1, ppid: 0, user: "u",
                                 executablePath: "/tmp/launcher",
                                 arguments: "DYLD_INSERT_LIBRARIES=/evil.dylib")
        let inc = ScanSnapshot.processInjectionIncident(for: entry)
        XCTAssertEqual(inc?.technique, .processInjection)
    }
}
