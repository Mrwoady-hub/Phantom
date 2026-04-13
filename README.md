# Phantom 2.0

> Native macOS endpoint security monitor — real detections, zero dependencies.

[![CI](https://github.com/your-org/Phantom/actions/workflows/ci.yml/badge.svg)](https://github.com/your-org/Phantom/actions/workflows/ci.yml)
![Platform](https://img.shields.io/badge/platform-macOS%2013%2B-blue)
![Swift](https://img.shields.io/badge/swift-5.9%2B-orange)
![License](https://img.shields.io/badge/license-MIT-green)

---

## What it does

Phantom runs as a menu-bar app and continuously monitors three attack surfaces:

| Sensor | How | What it detects |
|--------|-----|-----------------|
| **Process** | `ps -axo pid,ppid,user,command` every N seconds | Suspicious binaries, masquerading, credential dumping, defense evasion, process injection |
| **Network** | `lsof -nP -iTCP -iUDP` (90 s cache) | External connections from unclassified/suspicious processes; C2 IP matching via Feodo Tracker |
| **Persistence** | LaunchAgents, LaunchDaemons, Login Items, cron, KEXTs, App Scripts | Unsigned items, symlinks, user-writable paths |

Every finding is mapped to a **MITRE ATT&CK technique**, scored 0–100, and written to a **Keychain-HMAC-sealed audit trail**.

---

## Detection Coverage

| Technique | ID | Trigger |
|-----------|-----|---------|
| Command & Scripting Interpreter | T1059 | `python`, `ruby`, `osascript`, `bash` from non-system paths |
| Application Layer Protocol | T1071 | `nc`, `socat`, `ngrok`, `chisel` external connections |
| Ingress Tool Transfer | T1105 | `curl`, `wget` from user-writable paths |
| Boot/Logon Autostart Execution | T1547 | LaunchAgent/Daemon outside Apple defaults |
| **OS Credential Dumping** | **T1003** | `keychaindump`, `security dump-keychain`, `mimikatz` |
| **Masquerading** | **T1036** | System binary name (`ls`, `curl`, `bash`) in `/tmp`, `~/Downloads`, etc. |
| **Process Injection** | **T1055** | `DYLD_INSERT_LIBRARIES` or `DYLD_FORCE_FLAT_NAMESPACE` in process args |
| **System Info Discovery** | **T1082** | `system_profiler`, `ioreg`, `sysctl` from user-controlled paths |
| **Impair Defenses** | **T1562** | `pfctl -d`, `launchctl disable`, `csrutil disable`, `kextunload` |

---

## Security Architecture

### Audit Trail
Every operator action (scan start/stop, acknowledge, suppress, export) is written to a **hash-chained audit log**:
- Each event includes an `HMAC-SHA256(Keychain-key, payload)` tag
- The chain links every event to its predecessor — deleting, modifying, or inserting events breaks verification
- Keychain key is `kSecAttrAccessibleAfterFirstUnlock`, scoped to the app's code-signing identity
- File permissions: `0600` (owner read/write only), directory `0700`

### Suppression Store
Suppression rules are integrity-tagged with the same Keychain HMAC. External modification (e.g. via `defaults write`) resets the list to empty — **fail-safe over-alert** rather than silent miss.

### Threat Intel Feed
- Seeds with known C2 botnet IPs at build time
- Fetches [Feodo Tracker aggressive blocklist](https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.txt) every 24 hours
- Cached to disk with `0600` permissions; live refresh never blocks a scan

---

## Architecture

```
Phantom/
├── AppModel.swift              @MainActor observable state machine
├── TelemetryBroker.swift       Sensor orchestration (concurrent, per-sensor timeouts)
├── TelemetrySnapshot.swift     Detection logic (all five sensors + Tier 3 rules)
│
├── Sensors/
│   ├── ProcessMonitor.swift    ps-based process enumeration
│   ├── NetworkMonitor.swift    lsof-based connection monitoring (90 s cache)
│   └── PersistenceScanner.swift LaunchAgent/Daemon/cron/KEXT enumeration
│
├── Security/
│   ├── KeychainHMAC.swift      Keychain-backed HMAC-SHA256 key management
│   ├── AuditTrailStore.swift   Hash-chained audit log (0600 perms)
│   ├── SuppressionStore.swift  Integrity-tagged suppression rules
│   └── TrustDecision.swift     Code-signing evaluation + 5-min signing cache
│
├── Intel/
│   └── ThreatIntelFeed.swift   C2 IP blocklist (Feodo Tracker, 24 h refresh)
│
├── History/
│   ├── ScanRecord.swift        Per-scan risk snapshot
│   └── ScanHistoryStore.swift  Rolling 1,500-record history (≈25 h at 60 s)
│
└── UI/
    ├── MainView.swift          Dashboard + risk trend chart (Swift Charts)
    ├── MenuBarView.swift       Menu-bar popover
    └── SettingsView.swift      Scan interval, notifications, export
```

---

## Requirements

- macOS 13.0 or later (Ventura+)
- Xcode 15+
- No external dependencies — pure native Swift

---

## Building

```bash
git clone https://github.com/your-org/Phantom.git
cd Phantom
open Phantom.xcodeproj
```

Then `⌘R` to build and run, or:

```bash
xcodebuild -project Phantom.xcodeproj \
           -scheme Phantom \
           -configuration Debug \
           build
```

---

## Running Tests

```bash
xcodebuild -project Phantom.xcodeproj \
           -scheme "PhantomTests" \
           -destination "platform=macOS" \
           test
```

Test coverage:
- **AuditChainTests** — HMAC determinism, hex format, chain fields
- **DetectionRulesTests** — all five Tier-3 rules (fire / silent cases)
- **RiskScoringTests** — score computation, suppression, acknowledgement, family/suppression keys
- **ThreatIntelTests** — IPv4 extraction, blocklist lookup, ScanRecord Codable
- **MitreMappingTests** — technique titles, ATT&CK IDs, URL format, Codable

---

## Threat Model

| Threat | Mitigation |
|--------|-----------|
| Naive log editing | SHA-256 hash chain detects any field change |
| Same-user file forgery | Keychain-HMAC requires app code-signing identity to forge |
| Suppression injection | HMAC integrity tag; tampering resets to empty (over-alert) |
| Stale threat intel | 24 h Feodo Tracker refresh + seed list fallback |
| Scan bypass via sleep | `ps`/`lsof` enumerate current state; missed window ≤ scan interval |

**Ceiling**: A privileged attacker with Keychain access can extract the HMAC key. The next hardening tier is a Secure Enclave-backed key.

---

## Roadmap

- [ ] Privileged Helper (SMJobBless) — root-level `lsof`, `/etc/hosts` checks
- [ ] Endpoint Security Framework (ESF) — real-time kernel events
- [ ] User-defined alert rules engine
- [ ] Notarization + Sparkle update feed

---

## License

MIT © 2025 — see [LICENSE](LICENSE) for details.
