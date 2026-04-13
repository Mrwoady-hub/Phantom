# Phantom v1.1.0

Release date: 2026-04-13

## Highlights

- Renamed the application and repository identity from `SentinelGuard` to `Phantom`
- Replaced the older app layout with a fuller native macOS Swift codebase
- Added telemetry, persistence, trust, audit, threat-intel, and test coverage components
- Added CI workflow scaffolding for the Phantom project

## User-facing changes

- Updated app naming, project structure, and build artifacts to `Phantom`
- Expanded incident presentation and monitoring surfaces
- Improved notification naming consistency for the Phantom product identity

## Engineering changes

- Introduced `Phantom.xcodeproj` and current app/resource structure
- Added audit trail, trust evaluation, telemetry broker, history, and helper-related code
- Added unit test targets covering audit chain, detections, MITRE mapping, risk scoring, and threat intel
- Added repository hygiene improvements:
  - ignore local macOS/Xcode artifacts
  - stop tracking Xcode `xcuserdata`
  - exclude local tool state from version control

## Compatibility notes

- This release is a substantial project-identity transition from the earlier `SentinelGuard` repository state
- Existing local clones should update remotes to `Mrwoady-hub/Phantom`
- Local Xcode user data is no longer intended to be committed
