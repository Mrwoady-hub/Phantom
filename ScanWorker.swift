import Foundation

// MARK: - ScanWorker
//
// An actor that owns all six scanner instances and runs their synchronous
// subprocess / file-read calls on a background executor.
//
// Callers on @MainActor simply `await scanWorker.runXXX(...)` — the actor
// hop moves the blocking work off the main thread automatically, and the
// actor's isolation guarantees data-race safety without any @unchecked Sendable.

actor ScanWorker {

    // MARK: - Scanner instances

    private let tshark       = TSharkScanner()
    private let tcpdump      = TcpdumpScanner()
    private let zeek         = ZeekScanner()
    private let suricata     = SuricataScanner()
    private let ngrep        = NgrepScanner()
    private let networkMiner = NetworkMinerScanner()

    // MARK: - Suricata helpers

    var suricataLogPath: String?   { suricata.logPath }
    var suricataIsActive: Bool     { suricata.isActive }

    func recentSuricataEvents(lookbackSeconds: TimeInterval = 3600) -> [PacketEvent] {
        suricata.recentEvents(lookbackSeconds: lookbackSeconds)
    }

    func parseSuricataLine(_ line: String, cutoff: Date = .distantPast) -> PacketEvent? {
        suricata.parseSingleLine(line, cutoff: cutoff)
    }

    // MARK: - pcap tool runners

    func runTShark(pcapPath: String) -> [PacketEvent] {
        tshark.analyze(pcapPath: pcapPath)
    }

    func runTcpdump(pcapPath: String) -> [PacketEvent] {
        tcpdump.statistics(pcapPath: pcapPath)
    }

    func runZeek(pcapPath: String) -> [PacketEvent] {
        zeek.analyze(pcapPath: pcapPath)
    }

    func runNgrep(pcapPath: String) -> [PacketEvent] {
        ngrep.scan(pcapPath: pcapPath)
    }

    func runNetworkMiner(pcapPath: String) -> [PacketEvent] {
        networkMiner.extractArtifacts(from: pcapPath)
    }
}
