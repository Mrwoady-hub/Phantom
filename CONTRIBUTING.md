# Contributing to Phantom

Thanks for contributing.

## Principles

- Keep the project Apple-native and dependency-light.
- Prefer clarity and maintainability over cleverness.
- Preserve the security model when changing storage, signing, or audit behavior.
- Avoid unrelated refactors in feature or bug-fix changes.

## Development Expectations

- Target macOS 13+ and current Xcode toolchains used by the repository.
- Follow existing naming and file organization patterns.
- Do not commit local workspace state, generated user data, or machine-specific files.
- Keep pull requests focused and reviewable.

## Before Opening a Pull Request

1. Build the project locally.
2. Run the available test suite.
3. Verify README or release-note updates if behavior or public interfaces changed.
4. Check that no local artifacts were added accidentally.

Example:

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

## Pull Request Guidance

- Describe the problem first, then the implementation.
- Call out security-sensitive changes explicitly.
- Include screenshots for UI changes.
- Keep commit history clean enough to review.

## Areas That Need Extra Care

- `TrustDecision.swift`
- `AuditTrailStore.swift`
- `SuppressionStore.swift`
- `KeychainHMAC.swift`
- helper, entitlement, signing, or launch behavior

Changes in those areas should explain tradeoffs and failure modes clearly.
