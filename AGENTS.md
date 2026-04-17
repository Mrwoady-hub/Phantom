# Phantom Agent Guide

This guide applies to all work inside this repository.

## Product Identity

- Product name: `Phantom`
- Repository: `Mrwoady-hub/Phantom`
- Historical name: `SentinelGuard`
- Treat `SentinelGuard` references as legacy unless they are intentionally documenting history.

## Engineering Principles

- Keep the app native to macOS and Swift.
- Prefer Apple frameworks over third-party dependencies.
- Security-sensitive behavior must be explicit, testable, and easy to audit.
- Do not add broad abstractions unless they remove real complexity.
- Preserve user privacy and local-first behavior.

## Repo Hygiene

- Do not commit `.DS_Store`, `.claude`, `xcuserdata`, build output, local logs, or generated user state.
- Keep README and release assets under `docs/`.
- Keep public-facing release notes accurate and conservative.
- Do not rewrite tags or historical releases unless explicitly requested.

## Code Areas Requiring Extra Care

- `TrustDecision.swift`
- `AuditTrailStore.swift`
- `SuppressionStore.swift`
- `KeychainHMAC.swift`
- `PrivilegedHelper/`
- entitlements, launchd, signing, or helper installation behavior

For changes in these areas, explain:

- threat model impact
- failure behavior
- whether the change fails open or fails closed
- test coverage or manual validation performed

## Build and Test

Preferred validation:

```bash
xcodebuild -project Phantom.xcodeproj \
  -scheme Phantom \
  -configuration Debug \
  build

xcodebuild -project Phantom.xcodeproj \
  -scheme PhantomTests \
  -destination "platform=macOS" \
  test
```

If validation cannot be run, say so explicitly and explain why.
