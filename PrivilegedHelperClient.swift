import Combine
import Foundation
import ServiceManagement

// MARK: - PrivilegedHelperClient
//
// App-side XPC client. Wraps NSXPCConnection with:
//   • SMJobBless installation (first-run prompt for admin password)
//   • Automatic reconnect on invalidation
//   • Async/await wrappers over the reply-block XPC API
//
// Usage:
//   let result = try await PrivilegedHelperClient.shared.runPrivilegedLsof()

@MainActor
final class PrivilegedHelperClient: ObservableObject {

    static let shared = PrivilegedHelperClient()

    @Published private(set) var isInstalled = false
    @Published private(set) var lastError: String?

    private var connection: NSXPCConnection?

    // MARK: - Installation

    /// Installs (or upgrades) the privileged helper via SMJobBless.
    /// Presents a system authorization dialog asking for admin credentials.
    /// Safe to call repeatedly — no-op if the correct version is already installed.
    func installHelperIfNeeded() async {
        do {
            let service = SMAppService.daemon(plistName: "com.woady.phantom.helper.plist")
            if service.status == .enabled {
                isInstalled = true
                return
            }
            try service.register()
            isInstalled = true
            lastError   = nil
        } catch {
            lastError   = "Helper install failed: \(error.localizedDescription)"
            isInstalled = false
        }
    }

    // MARK: - XPC Connection

    private func proxy() throws -> SGPrivilegedHelperProtocol {
        if connection == nil { connection = makeConnection() }
        guard let conn = connection,
              let proxy = conn.remoteObjectProxyWithErrorHandler({ [weak self] error in
                  Task { @MainActor in
                      self?.lastError = "XPC error: \(error.localizedDescription)"
                      self?.connection = nil   // force reconnect on next call
                  }
              }) as? SGPrivilegedHelperProtocol
        else { throw HelperError.connectionFailed }
        return proxy
    }

    private func makeConnection() -> NSXPCConnection {
        let conn = NSXPCConnection(machServiceName: SGHelperMachServiceName,
                                   options: .privileged)
        conn.remoteObjectInterface = NSXPCInterface(with: SGPrivilegedHelperProtocol.self)
        conn.invalidationHandler   = { [weak self] in
            Task { @MainActor in self?.connection = nil }
        }
        conn.resume()
        return conn
    }

    // MARK: - Async Wrappers

    func helperVersion() async throws -> String {
        try await withCheckedThrowingContinuation { cont in
            do {
                try proxy().getVersion { version in cont.resume(returning: version) }
            } catch {
                cont.resume(throwing: error)
            }
        }
    }

    func runPrivilegedLsof() async throws -> String {
        try await withCheckedThrowingContinuation { cont in
            do {
                try proxy().runPrivilegedLsof { output in
                    cont.resume(returning: output ?? "")
                }
            } catch {
                cont.resume(throwing: error)
            }
        }
    }

    func checkEtcHosts() async throws -> [String] {
        try await withCheckedThrowingContinuation { cont in
            do {
                try proxy().checkEtcHosts { lines in cont.resume(returning: lines) }
            } catch {
                cont.resume(throwing: error)
            }
        }
    }

    func listKernelExtensions() async throws -> String {
        try await withCheckedThrowingContinuation { cont in
            do {
                try proxy().listKernelExtensions { output in
                    cont.resume(returning: output ?? "")
                }
            } catch {
                cont.resume(throwing: error)
            }
        }
    }

    func checkSudoers() async throws -> [String] {
        try await withCheckedThrowingContinuation { cont in
            do {
                try proxy().checkSudoers { lines in cont.resume(returning: lines) }
            } catch {
                cont.resume(throwing: error)
            }
        }
    }

    func listSystemPersistence() async throws -> [String] {
        try await withCheckedThrowingContinuation { cont in
            do {
                try proxy().listSystemPersistence { paths in cont.resume(returning: paths) }
            } catch {
                cont.resume(throwing: error)
            }
        }
    }

    // MARK: - 3.0 Network Intelligence

    /// Capture packets from the given interface for `durationSeconds` seconds.
    /// Returns the pcap file path on success, nil if capture failed.
    func capturePackets(
        interface: String = "en0",
        durationSeconds: Int = 10,
        outputPath: String = "/private/tmp/phantom-capture.pcap"
    ) async throws -> String? {
        try await withCheckedThrowingContinuation { cont in
            do {
                try proxy().capturePackets(
                    interface: interface,
                    durationSeconds: durationSeconds,
                    outputPath: outputPath
                ) { path in
                    cont.resume(returning: path)
                }
            } catch {
                cont.resume(throwing: error)
            }
        }
    }

    /// List available network interfaces for capture.
    func listNetworkInterfaces() async throws -> [String] {
        try await withCheckedThrowingContinuation { cont in
            do {
                try proxy().listNetworkInterfaces { interfaces in cont.resume(returning: interfaces) }
            } catch {
                cont.resume(throwing: error)
            }
        }
    }

    // MARK: - Error

    enum HelperError: LocalizedError {
        case connectionFailed
        var errorDescription: String? { "Could not connect to the privileged helper." }
    }
}
