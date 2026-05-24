import Foundation
import AppKit

struct ScanSnapshot: Sendable {
    let incidents: [Incident]
    let launches: [StartupEvent]

    // DEADLOCK FIX:
    // Previous version called `await MainActor.run { NSWorkspace.shared.runningApplications }`
    // from inside Task.detached. That tried to hop to the main actor, but AppModel
    // (on the main actor) was suspended waiting for the scan to finish → deadlock.
    //
    // Fix: accept pre-fetched app names as a parameter.
    // AppModel fetches them on the main actor BEFORE launching the detached scan task,
    // then passes them in. The scan task never touches the main actor at all.
    static func capture(appNames: [String] = []) async -> ScanSnapshot {
        let now = Date()

        // Build timeline from the pre-fetched names (main actor already done)
        let launches: [StartupEvent] = appNames.prefix(20).map {
            StartupEvent(date: now, process: $0)
        }

        // Four sensors run concurrently with individual timeouts
        async let proc = withTimeout(seconds: 8)  { await collectProcessIncidents() }
        async let net  = withTimeout(seconds: 10) { await collectNetworkIncidents() }
        async let pers = withTimeout(seconds: 6)  { await collectPersistenceIncidents() }
        async let fs   = withTimeout(seconds: 8)  { await collectFileSystemIncidents() }

        // Break into two steps to help the type-checker
        let procResults = (await proc ?? []) + (await net ?? [])
        let sysResults  = (await pers ?? []) + (await fs   ?? [])
        let all         = procResults + sysResults
        return ScanSnapshot(incidents: all, launches: launches)
    }

    // MARK: - Per-sensor timeout

    private static func withTimeout<T: Sendable>(
        seconds: Double,
        work: @Sendable @escaping () async -> T
    ) async -> T? {
        await withTaskGroup(of: T?.self) { group in
            group.addTask { await work() }
            group.addTask {
                try? await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
                return nil
            }
            let result = await group.next() ?? nil
            group.cancelAll()
            return result
        }
    }

    // MARK: - Process Detection

    private static func collectProcessIncidents() async -> [Incident] {
        let processes = await ProcessMonitor().runningProcesses()
        var incidents: [Incident] = []

        for entry in processes {
            // --- Tier 1: malware signature database (highest priority) ---
            if let inc = malwareSignatureIncident(for: entry)  { incidents.append(inc) }
            if let inc = cryptoMinerIncident(for: entry)       { incidents.append(inc) }

            // --- Tier 2: behavioral rule-based detectors run on ALL processes ---
            if let inc = masqueradingIncident(for: entry)      { incidents.append(inc) }
            if let inc = credentialDumpingIncident(for: entry) { incidents.append(inc) }
            if let inc = impairDefensesIncident(for: entry)    { incidents.append(inc) }
            if let inc = processInjectionIncident(for: entry)  { incidents.append(inc) }
            if let inc = sysInfoDiscoveryIncident(for: entry)  { incidents.append(inc) }

            // --- Tier 3: parent-child anomalies (requires full process list) ---
            if let inc = parentChildAnomalyIncident(for: entry, allProcesses: processes) {
                incidents.append(inc)
            }

            // --- Existing trust-based detection (unchanged) ---
            guard !entry.isDefinitelySystemProcess else { continue }
            if entry.executablePath.hasPrefix("/Applications/"),
               !isSuspiciousToken(entry.commandName) { continue }

            let trust = TrustEvaluator.evaluateProcess(
                path: entry.executablePath, commandToken: entry.commandName
            )
            guard trust.level == .suspicious ||
                  (trust.level == .unclassified && isHighRiskPath(entry.executablePath))
            else { continue }

            incidents.append(Incident(
                name:       "\(entry.commandName) — \(trust.level.rawValue)",
                severity:   trust.level == .suspicious ? .high : .medium,
                confidence: trust.level == .suspicious ? .high : .medium,
                detail:     "\(entry.executablePath) (PID \(entry.pid), user: \(entry.user))",
                source:     .process,
                technique:  mitreTechnique(for: entry.commandName),
                trust:      trust.level,
                evidence:   processEvidence(entry, trust),
                rawDetail:  "\(entry.executablePath) \(entry.arguments)"
            ))
        }
        return incidents
    }

    // MARK: - Network Detection

    private static func collectNetworkIncidents() async -> [Incident] {
        // Warm up threat intel (no-op if already warm)
        await ThreatIntelFeed.shared.warmUp()

        let connections = NetworkMonitor().activeConnectionRecords()
        var incidents: [Incident] = []

        for conn in connections where conn.isExternal {
            let trust = TrustEvaluator.evaluateProcess(
                path: conn.command, commandToken: conn.command.lowercased()
            )
            guard trust.level == .suspicious || trust.level == .unclassified else { continue }

            // Threat intel — blocked IP
            let remoteIP   = conn.name.extractedIPv4
            let isThreatIP: Bool
            if let ip = remoteIP {
                isThreatIP = await ThreatIntelFeed.shared.isBlocked(ip)
            } else {
                isThreatIP = false
            }

            // Domain threat intel
            let remoteHost  = conn.name.components(separatedBy: ":").first ?? conn.name
            let isThreatDomain = await ThreatIntelFeed.shared.isBlockedDomain(remoteHost)

            // Crypto miner port check
            let remotePort  = conn.name.components(separatedBy: ":").last.flatMap(Int.init) ?? 0
            let isMiningPort = MalwareSignatures.isMiningPort(remotePort)
            let isMiningProcess = MalwareSignatures.isMaliciousName(
                URL(fileURLWithPath: conn.command).lastPathComponent
            )
            let isMiner = isMiningPort || isMiningProcess

            let isAnyThreat = isThreatIP || isThreatDomain || isMiner

            let effectiveSev: Severity = isAnyThreat ? .high
                : trust.level == .suspicious ? .high : .low
            let effectiveConf: DetectionConfidence = isAnyThreat ? .high : .medium

            var labels: [String] = []
            if isThreatIP     { labels.append("BLOCKED IP") }
            if isThreatDomain { labels.append("BLOCKED DOMAIN") }
            if isMiner        { labels.append("CRYPTO MINER") }
            let threatLabel = labels.isEmpty ? "" : " [\(labels.joined(separator: " · "))]"

            let technique: MitreTechnique = isMiner ? .resourceHijacking : .applicationLayerProtocol

            incidents.append(Incident(
                name:       "\(conn.command) → external connection\(threatLabel)",
                severity:   effectiveSev,
                confidence: effectiveConf,
                detail:     "\(conn.command) → \(conn.name) (\(conn.protocolName))",
                source:     .network,
                technique:  technique,
                trust:      isAnyThreat ? .suspicious : trust.level,
                evidence: [
                    .init(label: "Command",       value: conn.command),
                    .init(label: "PID",           value: conn.processID.map(String.init) ?? "—"),
                    .init(label: "Protocol",      value: conn.protocolName),
                    .init(label: "Endpoint",      value: conn.name),
                    .init(label: "State",         value: conn.state ?? "—"),
                    .init(label: "Signed",        value: trust.isSigned ? "Yes" : "No"),
                    .init(label: "Trust",         value: trust.level.rawValue),
                    .init(label: "Threat Intel",  value: isThreatIP ? "BLOCKED IP" : (isThreatDomain ? "BLOCKED DOMAIN" : "No match")),
                    .init(label: "Miner Signal",  value: isMiner ? "YES – stratum port or miner process" : "No")
                ]
            ))
        }
        return incidents
    }

    // MARK: - Persistence Detection

    private static func collectPersistenceIncidents() async -> [Incident] {
        let records   = PersistenceScanner().scanLaunchAgentRecords()
        var incidents: [Incident] = []

        for record in records {
            let trust = TrustEvaluator.evaluatePersistence(path: record.path)
            guard trust.level != .trustedSystem else { continue }

            let shouldSurface: Bool = {
                if trust.level == .suspicious          { return true }
                if record.isSymlink                    { return true }
                if !trust.isSigned                     { return true }
                if record.isUserWritable               { return true }
                if record.category == .kernelExtension { return true }
                if record.category == .cron            { return true }
                return false
            }()
            guard shouldSurface else { continue }

            let severity: Severity = trust.level == .suspicious ? .high
                : trust.level == .unclassified ? .medium : .low

            incidents.append(Incident(
                name:       "\(record.isSymlink ? "⚠️ " : "")\(record.fileName)",
                severity:   severity,
                confidence: trust.isSigned ? .medium : .high,
                detail:     "[\(record.category.rawValue)] \(record.path)",
                source:     .persistence,
                technique:  .bootOrLogonAutostartExecution,
                trust:      trust.level,
                evidence: [
                    .init(label: "Path",     value: record.path),
                    .init(label: "Scope",    value: record.scope),
                    .init(label: "Category", value: record.category.rawValue),
                    .init(label: "Symlink",  value: record.isSymlink ? "Yes ⚠️" : "No"),
                    .init(label: "Signed",   value: trust.isSigned ? "Yes" : "No"),
                    .init(label: "Team ID",  value: trust.teamIdentifier ?? "(unsigned)"),
                    .init(label: "Signer",   value: trust.signerCommonName ?? "(unknown)"),
                    .init(label: "Trust",    value: trust.reasons.joined(separator: "; "))
                ],
                rawDetail: record.path
            ))
        }
        return incidents
    }

    // MARK: - File System Scan (4th sensor)

    /// Scans high-risk drop locations for suspicious or malware-named executables.
    /// Detects: unsigned executables in temp/download paths, known malware filenames,
    /// hidden executable files (dot-prefixed) in the home directory.
    private static func collectFileSystemIncidents() async -> [Incident] {
        var incidents: [Incident] = []
        let fm = FileManager.default

        // ── Scan high-risk drop locations for executables ──────────────────────
        let scanTargets: [(path: String, label: String)] = MalwareSignatures.highRiskDropPaths
            .map { ($0, URL(fileURLWithPath: $0).lastPathComponent) }

        for target in scanTargets {
            guard let files = try? fm.contentsOfDirectory(atPath: target.path) else { continue }

            for file in files.prefix(200) {               // cap to avoid slowdown
                let fullPath = (target.path as NSString).appendingPathComponent(file)
                var isDir: ObjCBool = false
                guard fm.fileExists(atPath: fullPath, isDirectory: &isDir),
                      !isDir.boolValue else { continue }

                // Check execute bit
                let attrs       = (try? fm.attributesOfItem(atPath: fullPath)) ?? [:]
                let perms       = attrs[.posixPermissions] as? Int ?? 0
                let isExecutable = (perms & 0o111) != 0

                let filename    = (file as NSString).lastPathComponent.lowercased()
                let isMalName   = MalwareSignatures.isMaliciousName(filename)

                // Report: known-malware name OR unsigned executable in /tmp
                if isMalName || (isExecutable && (target.path.contains("/tmp") ||
                                                   target.path.contains("Downloads"))) {
                    let trust = TrustEvaluator.evaluateProcess(
                        path: fullPath, commandToken: filename
                    )
                    // Skip if it's a legitimately signed known app
                    guard trust.level != .trustedSystem,
                          trust.level != .knownApplication
                    else { continue }

                    let sev: Severity = isMalName ? .high : .medium
                    incidents.append(Incident(
                        name:       isMalName
                            ? "⚠️ Known Malware Detected — \(file)"
                            : "Suspicious Executable in \(target.label)",
                        severity:   sev,
                        confidence: isMalName ? .high : .medium,
                        detail:     "Executable found in \(target.label): \(fullPath)",
                        source:     .process,
                        technique:  isMalName ? .malwareFamily : .userExecution,
                        trust:      isMalName ? .suspicious : trust.level,
                        evidence: [
                            .init(label: "Path",        value: fullPath),
                            .init(label: "Location",    value: target.label),
                            .init(label: "Executable",  value: isExecutable ? "Yes" : "No"),
                            .init(label: "Signed",      value: trust.isSigned ? "Yes" : "No"),
                            .init(label: "Team ID",     value: trust.teamIdentifier ?? "(unsigned)"),
                            .init(label: "Detection",   value: isMalName
                                ? "Matches known malware name database"
                                : "Unsigned executable in high-risk path")
                        ],
                        rawDetail: fullPath
                    ))
                }
            }
        }

        // ── Hidden executables in home directory ───────────────────────────────
        let homeDir      = NSHomeDirectory()
        let homeContents = (try? fm.contentsOfDirectory(atPath: homeDir)) ?? []
        for item in homeContents where item.hasPrefix(".") {
            let fullPath  = homeDir + "/" + item
            var isDir: ObjCBool = false
            guard fm.fileExists(atPath: fullPath, isDirectory: &isDir),
                  !isDir.boolValue else { continue }

            let attrs    = (try? fm.attributesOfItem(atPath: fullPath)) ?? [:]
            let perms    = attrs[.posixPermissions] as? Int ?? 0
            guard (perms & 0o111) != 0 else { continue }   // skip non-executable hidden files

            // Skip common legit hidden executables
            let knownSafe: Set<String> = [
                ".DS_Store", ".localized", ".CFUserTextEncoding",
                ".bash_history", ".zsh_history", ".profile", ".bashrc", ".zshrc"
            ]
            guard !knownSafe.contains(item) else { continue }

            incidents.append(Incident(
                name:       "Hidden Executable — \(item)",
                severity:   .medium,
                confidence: .medium,
                detail:     "Dot-prefixed file with execute permissions found in home directory",
                source:     .process,
                technique:  .hideArtifacts,
                trust:      .unclassified,
                evidence: [
                    .init(label: "Path",   value: fullPath),
                    .init(label: "Name",   value: item),
                    .init(label: "Reason", value: "Hidden file (dot-prefixed) with execute bit set in home directory")
                ],
                rawDetail: fullPath
            ))
        }

        return incidents
    }

    // MARK: - Extended Detection Rules (internal so unit tests can call them directly)

    /// Checks for T1036 — Masquerading: a binary whose name matches a common system
    /// tool but is running from a non-system path (e.g. /tmp/ls, ~/Downloads/curl).
    static func masqueradingIncident(for entry: ProcessEntry) -> Incident? {
        let systemBinaryNames: Set<String> = [
            "ls","ps","curl","wget","bash","sh","zsh","python","python3","ruby","perl",
            "nc","ssh","scp","sftp","nmap","tar","zip","unzip","chmod","chown","kill",
            "launchctl","osascript","security","system_profiler","ioreg","dscl"
        ]
        let cmd = entry.commandName.lowercased()
        guard systemBinaryNames.contains(cmd),
              !entry.isDefinitelySystemProcess,
              !entry.executablePath.hasPrefix("/Applications/"),
              !entry.executablePath.hasPrefix("/usr/local/"),
              !entry.executablePath.hasPrefix("/opt/homebrew/")
        else { return nil }

        return Incident(
            name:       "Masquerading — \(entry.commandName) in non-system path",
            severity:   .high,
            confidence: .high,
            detail:     "\(entry.executablePath) mimics a system binary name",
            source:     .process,
            technique:  .masquerading,
            trust:      .suspicious,
            evidence:   processEvidence(entry, TrustEvaluator.evaluateProcess(
                path: entry.executablePath, commandToken: cmd
            )),
            rawDetail: entry.executablePath
        )
    }

    /// Checks for T1003 — OS Credential Dumping: processes accessing keychain or
    /// credential stores in ways consistent with credential harvesting tools.
    static func credentialDumpingIncident(for entry: ProcessEntry) -> Incident? {
        let cmdLower = entry.commandName.lowercased()
        let argsLower = entry.arguments.lowercased()

        let isDumpingTool = ["keychaindump", "chainbreaker", "dumpkeychain"].contains(cmdLower)
        let isSecurityDump = cmdLower == "security" && (
            argsLower.contains("dump-keychain") ||
            argsLower.contains("find-generic-password") ||
            argsLower.contains("find-internet-password") ||
            argsLower.contains("export")
        )
        let isMimikatz = ["mimikatz", "pypykatz"].contains(cmdLower)
        guard isDumpingTool || isSecurityDump || isMimikatz else { return nil }

        return Incident(
            name:       "Credential Access — \(entry.commandName)",
            severity:   .high,
            confidence: .high,
            detail:     "Process is performing credential dumping operations",
            source:     .process,
            technique:  .osCredentialDumping,
            trust:      .suspicious,
            evidence:   processEvidence(entry, TrustEvaluator.evaluateProcess(
                path: entry.executablePath, commandToken: cmdLower
            )),
            rawDetail: "\(entry.executablePath) \(entry.arguments)"
        )
    }

    /// Checks for T1082 — System Information Discovery: recon tools probing
    /// hardware, OS, and network configuration from unusual paths or contexts.
    static func sysInfoDiscoveryIncident(for entry: ProcessEntry) -> Incident? {
        let cmd = entry.commandName.lowercased()
        guard ["system_profiler", "ioreg", "sysctl", "sw_vers", "uname",
               "ifconfig", "networksetup", "scutil"].contains(cmd),
              !entry.isDefinitelySystemProcess,
              isHighRiskPath(entry.executablePath) ||
              entry.executablePath.hasPrefix("\(NSHomeDirectory())/")
        else { return nil }

        return Incident(
            name:       "System Recon — \(entry.commandName) from user path",
            severity:   .medium,
            confidence: .medium,
            detail:     "System information tool running from user-controlled path",
            source:     .process,
            technique:  .systemInformationDiscovery,
            trust:      .unclassified,
            evidence:   processEvidence(entry, TrustEvaluator.evaluateProcess(
                path: entry.executablePath, commandToken: cmd
            )),
            rawDetail: "\(entry.executablePath) \(entry.arguments)"
        )
    }

    /// Checks for T1562 — Impair Defenses: attempts to disable security tooling,
    /// firewalls, or system integrity mechanisms.
    static func impairDefensesIncident(for entry: ProcessEntry) -> Incident? {
        let cmd = entry.commandName.lowercased()
        let args = entry.arguments.lowercased()

        let isPfctlDisable  = cmd == "pfctl"      && args.contains("-d")
        let isLaunchctlStop = cmd == "launchctl"  && (
            args.contains("disable") || args.contains("bootout") || args.contains("remove")
        )
        let isCsrutilDisable = cmd == "csrutil"   && args.contains("disable")
        let isKextUnload     = cmd == "kextunload"
        let isSysextUnload   = cmd == "systemextensionsctl" && args.contains("uninstall")

        guard isPfctlDisable || isLaunchctlStop || isCsrutilDisable ||
              isKextUnload   || isSysextUnload
        else { return nil }

        return Incident(
            name:       "Defense Evasion — \(entry.commandName) \(entry.arguments.prefix(40))",
            severity:   .high,
            confidence: .high,
            detail:     "Security mechanism may be disabled or removed",
            source:     .process,
            technique:  .impairDefenses,
            trust:      .suspicious,
            evidence:   processEvidence(entry, TrustEvaluator.evaluateProcess(
                path: entry.executablePath, commandToken: cmd
            )),
            rawDetail: "\(entry.executablePath) \(entry.arguments)"
        )
    }

    /// Checks for T1055 — Process Injection indicators: environment variables or
    /// argument patterns commonly associated with dylib injection on macOS.
    static func processInjectionIncident(for entry: ProcessEntry) -> Incident? {
        let args = entry.arguments
        // DYLD_INSERT_LIBRARIES in arguments is a red flag — legitimate installers
        // use it in controlled contexts; malware uses it to inject into processes.
        guard args.contains("DYLD_INSERT_LIBRARIES") ||
              args.contains("DYLD_FORCE_FLAT_NAMESPACE") ||
              args.lowercased().contains("--inject") ||
              args.lowercased().contains("-inject")
        else { return nil }

        return Incident(
            name:       "Process Injection — \(entry.commandName)",
            severity:   .high,
            confidence: .medium,
            detail:     "Process launched with dylib injection environment variables",
            source:     .process,
            technique:  .processInjection,
            trust:      .suspicious,
            evidence:   processEvidence(entry, TrustEvaluator.evaluateProcess(
                path: entry.executablePath, commandToken: entry.commandName.lowercased()
            )),
            rawDetail: "\(entry.executablePath) \(entry.arguments)"
        )
    }

    // MARK: - New Fort Knox Detection Rules

    /// Checks process name against the comprehensive `MalwareSignatures` database.
    /// This is the highest-signal detector — if a binary name matches a known
    /// malware family, it's an immediate HIGH severity finding.
    static func malwareSignatureIncident(for entry: ProcessEntry) -> Incident? {
        let cmd = entry.commandName.lowercased()
        guard MalwareSignatures.isMaliciousName(cmd) else { return nil }

        let trust = TrustEvaluator.evaluateProcess(
            path: entry.executablePath, commandToken: cmd
        )
        // Signed Apple/known apps with this name are still flagged — malware names
        // are chosen to avoid collisions with system binaries.
        return Incident(
            name:       "⚠️ Known Malware — \(entry.commandName)",
            severity:   .high,
            confidence: .high,
            detail:     "Process name matches known malware/offensive tool database",
            source:     .process,
            technique:  .malwareFamily,
            trust:      .suspicious,
            evidence:   processEvidence(entry, trust) + [
                .init(label: "Detection", value: "Name match in MalwareSignatures database"),
                .init(label: "Category",  value: "Known malware / offensive tool")
            ],
            rawDetail: "\(entry.executablePath) \(entry.arguments)"
        )
    }

    /// Detects crypto-mining processes: known miner binary names, stratum protocol
    /// arguments, and wallet address patterns in command-line arguments.
    static func cryptoMinerIncident(for entry: ProcessEntry) -> Incident? {
        let cmd  = entry.commandName.lowercased()
        let args = entry.arguments.lowercased()

        // Known miner binary name
        let isMinerName = ["xmrig","cpuminer","minerd","xmr-stak","ethminer",
                           "nbminer","cgminer","bfgminer","sgminer","t-rex"].contains(cmd)

        // Stratum protocol in arguments
        let hasStratumArg = args.contains("stratum+tcp") || args.contains("stratum+ssl") ||
                            args.contains("stratum://") || args.contains("-o pool.")

        // Mining pool domain in arguments
        let hasMiningPool = MalwareSignatures.miningPoolDomains.contains { args.contains($0) }

        // Monero wallet address pattern (95-char base58 starting with 4)
        let hasWalletArg  = args.range(of: "\\b4[0-9A-Za-z]{93}\\b",
                                        options: .regularExpression) != nil

        guard isMinerName || hasStratumArg || hasMiningPool || hasWalletArg else { return nil }

        let trust = TrustEvaluator.evaluateProcess(
            path: entry.executablePath, commandToken: cmd
        )
        var signals: [String] = []
        if isMinerName   { signals.append("miner binary name") }
        if hasStratumArg { signals.append("stratum:// protocol in args") }
        if hasMiningPool { signals.append("mining pool domain in args") }
        if hasWalletArg  { signals.append("crypto wallet address in args") }

        return Incident(
            name:       "Crypto Miner — \(entry.commandName)",
            severity:   .high,
            confidence: .high,
            detail:     "Process shows crypto-mining indicators: \(signals.joined(separator: ", "))",
            source:     .process,
            technique:  .resourceHijacking,
            trust:      .suspicious,
            evidence:   processEvidence(entry, trust) + [
                .init(label: "Mining Signals", value: signals.joined(separator: " · "))
            ],
            rawDetail: "\(entry.executablePath) \(entry.arguments)"
        )
    }

    /// Detects anomalous parent-child process relationships: e.g. a web browser or
    /// document editor spawning a shell interpreter — a common Living-off-the-Land
    /// technique used by malware to evade process-based detection.
    static func parentChildAnomalyIncident(
        for entry: ProcessEntry,
        allProcesses: [ProcessEntry]
    ) -> Incident? {
        let cmd = entry.commandName.lowercased()

        // Child must be a script interpreter or shell
        let isInterpreterChild = ["bash","sh","zsh","python","python3","ruby",
                                   "perl","osascript","node","php"].contains(cmd)
        guard isInterpreterChild else { return nil }

        // Find parent
        guard let parent = allProcesses.first(where: { $0.pid == entry.ppid }) else { return nil }
        let parentName = parent.commandName.lowercased()

        // Suspicious parents: GUI apps that shouldn't spawn shells
        let suspiciousParents: Set<String> = [
            "safari", "firefox", "chrome", "chromium", "msedge", "opera",
            "pages", "numbers", "keynote", "word", "excel", "powerpoint",
            "acrobat", "preview", "textedit",
            "finder",
            "mail", "airmail", "spark",
            "slack", "teams", "discord", "zoom"
        ]
        guard suspiciousParents.contains(parentName) else { return nil }

        let trust = TrustEvaluator.evaluateProcess(
            path: entry.executablePath, commandToken: cmd
        )
        return Incident(
            name:       "Suspicious Child Process — \(parent.commandName) → \(entry.commandName)",
            severity:   .high,
            confidence: .high,
            detail:     "\(parent.commandName) spawned shell interpreter \(entry.commandName) (PID \(entry.pid))",
            source:     .process,
            technique:  .commandAndScriptingInterpreter,
            trust:      .suspicious,
            evidence:   processEvidence(entry, trust) + [
                .init(label: "Parent",       value: parent.commandName),
                .init(label: "Parent Path",  value: parent.executablePath),
                .init(label: "Parent PID",   value: String(parent.pid)),
                .init(label: "Anomaly",      value: "GUI app spawned shell — Living-off-the-Land indicator")
            ],
            rawDetail: "\(entry.executablePath) \(entry.arguments)"
        )
    }

    // MARK: - Helpers

    private static func processEvidence(_ e: ProcessEntry, _ t: TrustDecision) -> [IncidentEvidence] {[
        .init(label: "PID",        value: String(e.pid)),
        .init(label: "PPID",       value: String(e.ppid)),
        .init(label: "User",       value: e.user),
        .init(label: "Executable", value: e.executablePath),
        .init(label: "Arguments",  value: e.arguments.isEmpty ? "(none)" : e.arguments),
        .init(label: "Signed",     value: t.isSigned ? "Yes" : "No"),
        .init(label: "Team ID",    value: t.teamIdentifier ?? "(unsigned)"),
        .init(label: "Signer",     value: t.signerCommonName ?? "(unknown)"),
        .init(label: "Trust",      value: t.reasons.joined(separator: "; "))
    ]}

    private static func isHighRiskPath(_ path: String) -> Bool {
        ["\(NSHomeDirectory())/Downloads/", "\(NSHomeDirectory())/Desktop/",
         "/tmp/", "/private/tmp/", "/var/folders/"]
            .contains { path.hasPrefix($0) }
    }

    private static func isSuspiciousToken(_ name: String) -> Bool {
        ["nc","ncat","socat","ngrok","frpc","chisel","python","python3",
         "ruby","perl","osascript","curl","wget","bash","sh","zsh","node",
         "keychaindump","chainbreaker","mimikatz","pypykatz",
         "system_profiler","kextunload","systemextensionsctl"]
            .contains(name.lowercased())
    }

    private static func mitreTechnique(for name: String) -> MitreTechnique? {
        switch name.lowercased() {
        case "python","python3","ruby","perl","osascript","bash","sh","zsh","node":
            return .commandAndScriptingInterpreter
        case "nc","ncat","socat","ngrok","frpc","chisel":
            return .applicationLayerProtocol
        case "curl","wget":
            return .ingressToolTransfer
        case "keychaindump","chainbreaker","mimikatz","pypykatz":
            return .osCredentialDumping
        case "kextunload","systemextensionsctl":
            return .impairDefenses
        case "system_profiler","ioreg","sw_vers":
            return .systemInformationDiscovery
        default: return nil
        }
    }
}
