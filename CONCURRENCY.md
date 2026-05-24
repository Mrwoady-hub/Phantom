# Phantom Concurrency Policy

**Project flag:** `SWIFT_DEFAULT_ACTOR_ISOLATION = MainActor`  
**Concurrency level:** `SWIFT_STRICT_CONCURRENCY = minimal`  
**Swift version:** 5.0 (Swift 6 warnings emitted, not errors)

Every type in this project is `@MainActor` **by default**. This is intentional for
UI and state types. All infrastructure types must explicitly opt out with `nonisolated`.

---

## Classification Rules

### 1. `@MainActor` — UI, ViewModels, App State
Types that own `@Published` properties or conform to `ObservableObject`.
The `@MainActor` annotation is inherited from the project flag; no explicit annotation needed.

**Examples in Phantom:**
- `AppModel` — the central ViewModel
- `PhantomAIAgent` — AI analysis coordinator with `@Published` state
- `PhantomAI` — interactive analyst with `LanguageModelSession`
- `PacketCaptureEngine` — publishes `helperAvailable`, `helperStatusMessage`, tool states
- `PersistenceWatchService` — `ObservableObject` filesystem watcher
- `PrivilegedHelperClient` — `ObservableObject` XPC client

**Rule:** If a type has `@Published` properties or any SwiftUI/Combine bindings, it stays
on `@MainActor`. Never move these types to a background context.

---

### 2. `actor` — Shared Mutable Async State
Types that own shared mutable state and whose methods are async by nature.

**Examples in Phantom:**
- `TelemetryBroker` — prevents re-entrant scan cycles
- `ScanWorker` — serializes subprocess invocations from multiple callers
- `ThreatIntelFeed` — shared singleton with async network refresh + disk cache
- `AppModel.AuditQueue` — serializes AuditTrailStore writes (prevents chain corruption)
- `AppModel.HistoryQueue` — serializes ScanHistoryStore writes

**Rule:** Use `actor` when you need async-safe shared mutable state. Do NOT use
`actor` for types that are stateless or that only do file/network I/O.

---

### 3. `nonisolated` — Infrastructure Utilities
Types that are stateless or whose thread-safety is guaranteed by other means
(NSLock, immutable data, atomic file writes). These must explicitly opt out of
`@MainActor` isolation.

**Pattern for `final class` scanners (called from `actor ScanWorker`):**
```swift
final class MyScanner {
    nonisolated init() {}                    // ← required
    nonisolated func scan() -> [MyResult] { … }
}
```

**Pattern for `enum` stores (static-only, disk I/O):**
```swift
enum MyStore {
    nonisolated private static let fileName = "…"
    nonisolated private static var fileURL: URL { … }
    nonisolated static func load() -> [T] { … }
    nonisolated static func save(_ items: [T]) { … }
    nonisolated static func clear() { … }
}
```

**Pattern for nested Codable types used by nonisolated stores:**
```swift
// Define at FILE SCOPE, not nested inside the enum/class.
// Nested types inherit enclosing actor isolation — file-scope types do not.
private struct MyPayload: Sendable {
    let value: String
    nonisolated init(value: String) { self.value = value }
}
extension MyPayload: Codable {
    nonisolated init(from decoder: any Decoder) throws { … }
    nonisolated func encode(to encoder: any Encoder) throws { … }
    private enum CodingKeys: String, CodingKey { case value }
}
```

**Examples in Phantom:**
- `AuditTrailStore` — HMAC chain, all methods `nonisolated`
- `ScanHistoryStore` — rolling scan history, all methods `nonisolated`
- `IncidentStore` — incident persistence, all methods `nonisolated`
- `SuppressionStore` — suppression keys with HMAC, all methods `nonisolated`
- `KeychainHMAC` — Keychain-backed HMAC, all methods `nonisolated`
- `MalwareSignatures` — static threat data, all members `nonisolated`
- `NetworkMonitor` — NSLock-protected lsof cache, `nonisolated init()` + methods
- `LsofScanner`, `TcpdumpScanner`, `TSharkScanner`, etc. — subprocess wrappers with `nonisolated init()`
- `PersistenceScanner` — filesystem reader with `nonisolated init()`
- `ProcessMonitor` — `ps` subprocess wrapper with `nonisolated init()`

---

### 4. Plain Value Types — Structs and Enums
Model types with no stored mutable state. These have no actor annotation.
Swift treats value types as implicitly `Sendable` when all stored properties are `Sendable`.

**Pattern:**
```swift
struct MyModel: Identifiable, Codable, Hashable, Sendable {
    let id: UUID
    // All stored properties must be Sendable
    nonisolated init(…) { … }  // Only needed if called from nonisolated context
}
```

**Examples in Phantom:**
- `Incident`, `AuditEvent`, `ScanRecord`, `PacketEvent`
- All enums: `Severity`, `IncidentStatus`, `AgentStatus`, `DetectionConfidence`, etc.
- `NetworkConnectionRecord` — `nonisolated var isExternal`, `isListening` required
  because this struct is used from `LsofScanner`'s `nonisolated` context

---

## The Call Graph That Drives These Rules

```
@MainActor AppModel
    ↓ await
actor TelemetryBroker
    ↓ await
ScanSnapshot.capture() [static async, nonisolated]
    ↓ async let (concurrent)
    actor ScanWorker → nonisolated scanners (LsofScanner, TcpdumpScanner, …)
    nonisolated ProcessMonitor().runningProcesses() [async]
    nonisolated PersistenceScanner().scanLaunchAgentRecords() [sync]
    actor ThreatIntelFeed.shared.isBlocked() [async]
```

Any type that appears in the non-main portion of this graph **must** be `nonisolated`
(or `actor`). Any store that is called from an `actor` body must have `nonisolated`
methods.

---

### 5. IPC / XPC Boundaries — Always `nonisolated`

XPC protocol methods cross a Mach port. They are:
- **cross-process RPC** — no Swift executor involved
- **thread-agnostic** — reply blocks arrive on arbitrary threads
- **executor-agnostic** — the caller may be on any actor or none

Treating them as `@MainActor` is a category error.
`SWIFT_DEFAULT_ACTOR_ISOLATION = MainActor` **must not define IPC boundary semantics**.

**Rule:** Every XPC/IPC protocol requirement, every conforming implementation, and every
helper function called from those implementations must be explicitly `nonisolated`.

**Protocol pattern:**
```swift
// ✅ Correct — nonisolated requirement opts out of project-wide MainActor default
@objc protocol SGPrivilegedHelperProtocol {
    nonisolated func getVersion(reply: @escaping (String) -> Void)
    nonisolated func runPrivilegedLsof(reply: @escaping (String?) -> Void)
    // all other methods also nonisolated
}
```

**Conformance pattern:**
```swift
// ✅ Correct — implementation matches nonisolated requirement
final class HelperCommandHandler: NSObject, SGPrivilegedHelperProtocol {
    nonisolated func getVersion(reply: @escaping (String) -> Void) { reply("3.0") }

    // helper utilities called from nonisolated methods must also be nonisolated
    nonisolated private func shell(_ path: String, args: [String]) -> String? { … }
}
```

**Call-site pattern (app client):**
```swift
// ✅ Correct — capture proxy on @MainActor, call from nonisolated task group
func helperVersion() async throws -> String {
    let p = try proxy()           // @MainActor — safe here
    return try await withThrowingTaskGroup(of: String.self) { group in
        group.addTask {
            try await withCheckedThrowingContinuation { cont in
                p.getVersion { v in cont.resume(returning: v) }   // nonisolated — no warning
            }
        }
        // … timeout task …
    }
}
```

**What this rule covers in Phantom:**
- `SGPrivilegedHelperProtocol` — XPC interface (8 methods)
- `HelperCommandHandler` — helper-side conformance (8 methods + `shell()`)
- `PrivilegedHelperClient` — app-side async wrappers (all use task-group timeout pattern)

**Checklist for new XPC methods:**
- [ ] Protocol requirement is `nonisolated`
- [ ] Conforming implementation is `nonisolated`
- [ ] Any helper/utility called from that implementation is `nonisolated`
- [ ] App-side wrapper uses `let p = try proxy()` before `withThrowingTaskGroup`
- [ ] App-side wrapper has a `HelperError.timeout` task racing the XPC call

---

## Common Mistakes

| Mistake | Symptom | Fix |
|---|---|---|
| `final class Scanner` with no `nonisolated init()` | Warning: "call to main actor-isolated initializer" from ScanWorker | Add `nonisolated init() {}` |
| `static func store()` on a utility enum | Warning: "main actor-isolated static method" from actor context | Add `nonisolated` to the method AND all helpers it calls |
| Nested `struct Payload: Codable` inside `enum Store` | Warning: "main actor-isolated conformance to Decodable" | Move struct to file scope; add explicit `nonisolated init(from:)` and `encode(to:)` |
| `private static let constant = "…"` in a store | Warning: "main actor-isolated static property" from nonisolated method | Add `nonisolated` |
| Calling `nonisolated` method that uses `@MainActor` helper | Warning: "call to main actor-isolated" inside nonisolated | Make the helper `nonisolated` too — isolation leaks upward |
| `@objc protocol` for XPC with no explicit isolation | Warning: "call to main actor-isolated method" inside `group.addTask` | Mark all protocol requirements AND conformances `nonisolated` — fix the contract, not the call site |
| Fixing only the conforming class, not the protocol | Protocol contract is still wrong; next conformer repeats the bug | Always fix at the protocol requirement level first |
| Leaving `private func shell()` implicitly `@MainActor` | `nonisolated` XPC method calls `@MainActor` helper — isolation leaks in | Mark every utility called from a `nonisolated` XPC method as `nonisolated` too |

---

## Upgrading to Swift 6 Strict Concurrency

When ready to upgrade `SWIFT_STRICT_CONCURRENCY` from `minimal` to `complete`:
1. These warnings will become **errors**
2. All the patterns above will be required, not optional
3. Expect additional warnings in view code (SwiftUI uses `@MainActor` extensively)
4. `TelemetrySnapshot.swift` static methods may need `nonisolated` annotations
5. Run `xcodebuild` with `SWIFT_STRICT_CONCURRENCY=targeted` first as an intermediate step

The current `nonisolated` annotations are forward-compatible — they work in both
`minimal` and `complete` modes.
