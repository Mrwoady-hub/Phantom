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
        // Race the XPC call against a 3-second timeout.
        //
        // Without this, a missing/unresponsive helper hangs the continuation forever:
        // NSXPCConnection's error handler fires (clearing `connection`) but the reply
        // block never fires, so the continuation never resumes.
        //
        // Using a task group lets Swift structured concurrency cancel the losing task.
        let proxyRef = try proxy()          // capture on @MainActor before the group
        return try await withThrowingTaskGroup(of: String.self) { group in
            group.addTask {
                // XPC reply blocks call back on an arbitrary thread, but the
                // continuation itself is Sendable so this is safe.
                try await withCheckedThrowingContinuation { cont in
                    proxyRef.getVersion { version in cont.resume(returning: version) }
                }
            }
            group.addTask {
                try await Task.sleep(nanoseconds: 3_000_000_000)   // 3 s
                throw HelperError.timeout
            }
            let result = try await group.next()!
            group.cancelAll()
            return result
        }
    }

    func runPrivilegedLsof() async throws -> String {
        let p = try proxy()
        return try await withThrowingTaskGroup(of: String.self) { group in
            group.addTask {
                try await withCheckedThrowingContinuation { cont in
                    p.runPrivilegedLsof { output in cont.resume(returning: output ?? "") }
                }
            }
            group.addTask {
                try await Task.sleep(nanoseconds: 5_000_000_000)   // 5 s
                throw HelperError.timeout
            }
            let result = try await group.next()!
            group.cancelAll()
            return result
        }
    }

    func checkEtcHosts() async throws -> [String] {
        let p = try proxy()
        return try await withThrowingTaskGroup(of: [String].self) { group in
            group.addTask {
                try await withCheckedThrowingContinuation { cont in
                    p.checkEtcHosts { lines in cont.resume(returning: lines) }
                }
            }
            group.addTask {
                try await Task.sleep(nanoseconds: 3_000_000_000)   // 3 s
                throw HelperError.timeout
            }
            let result = try await group.next()!
            group.cancelAll()
            return result
        }
    }

    func listKernelExtensions() async throws -> String {
        let p = try proxy()
        return try await withThrowingTaskGroup(of: String.self) { group in
            group.addTask {
                try await withCheckedThrowingContinuation { cont in
                    p.listKernelExtensions { output in cont.resume(returning: output ?? "") }
                }
            }
            group.addTask {
                try await Task.sleep(nanoseconds: 5_000_000_000)   // 5 s
                throw HelperError.timeout
            }
            let result = try await group.next()!
            group.cancelAll()
            return result
        }
    }

    func checkSudoers() async throws -> [String] {
        let p = try proxy()
        return try await withThrowingTaskGroup(of: [String].self) { group in
            group.addTask {
                try await withCheckedThrowingContinuation { cont in
                    p.checkSudoers { lines in cont.resume(returning: lines) }
                }
            }
            group.addTask {
                try await Task.sleep(nanoseconds: 3_000_000_000)   // 3 s
                throw HelperError.timeout
            }
            let result = try await group.next()!
            group.cancelAll()
            return result
        }
    }

    func listSystemPersistence() async throws -> [String] {
        let p = try proxy()
        return try await withThrowingTaskGroup(of: [String].self) { group in
            group.addTask {
                try await withCheckedThrowingContinuation { cont in
                    p.listSystemPersistence { paths in cont.resume(returning: paths) }
                }
            }
            group.addTask {
                try await Task.sleep(nanoseconds: 5_000_000_000)   // 5 s
                throw HelperError.timeout
            }
            let result = try await group.next()!
            group.cancelAll()
            return result
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
        let p = try proxy()
        // Timeout = capture duration + 5 s headroom for startup/teardown.
        let timeoutNs = UInt64((Double(durationSeconds) + 5.0) * 1_000_000_000)
        return try await withThrowingTaskGroup(of: String?.self) { group in
            group.addTask {
                try await withCheckedThrowingContinuation { cont in
                    p.capturePackets(
                        interface: interface,
                        durationSeconds: durationSeconds,
                        outputPath: outputPath
                    ) { path in cont.resume(returning: path) }
                }
            }
            group.addTask {
                try await Task.sleep(nanoseconds: timeoutNs)
                throw HelperError.timeout
            }
            let result = try await group.next()!
            group.cancelAll()
            return result
        }
    }

    /// List available network interfaces for capture.
    func listNetworkInterfaces() async throws -> [String] {
        let p = try proxy()
        return try await withThrowingTaskGroup(of: [String].self) { group in
            group.addTask {
                try await withCheckedThrowingContinuation { cont in
                    p.listNetworkInterfaces { interfaces in cont.resume(returning: interfaces) }
                }
            }
            group.addTask {
                try await Task.sleep(nanoseconds: 3_000_000_000)   // 3 s
                throw HelperError.timeout
            }
            let result = try await group.next()!
            group.cancelAll()
            return result
        }
    }

    // MARK: - Error

    enum HelperError: LocalizedError {
        case connectionFailed
        case timeout
        var errorDescription: String? {
            switch self {
            case .connectionFailed: return "Could not connect to the privileged helper."
            case .timeout:          return "Helper did not respond within the timeout window."
            }
        }
    }

}
