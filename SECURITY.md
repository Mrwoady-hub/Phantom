# Security Policy

## Supported Scope

Phantom is an actively developed macOS security project. Security reports are welcome for:

- code-signing or trust-evaluation bypasses
- audit trail integrity failures
- suppression tampering weaknesses
- unsafe local storage or permission handling
- privileged helper or entitlement issues
- release or repository supply-chain concerns

## Reporting a Vulnerability

Please do not open a public GitHub issue for a suspected security vulnerability.

Instead, report it privately with:

- affected version or commit
- impact summary
- reproduction steps
- proof of concept if available
- suggested mitigation if known

If you do not yet have a dedicated private security contact configured on GitHub, add one before inviting public disclosure.

## Disclosure Expectations

- Reasonable time to validate and remediate before public disclosure
- Coordinated disclosure preferred
- Clear reproduction details appreciated

## Out of Scope

The following are generally out of scope unless they lead to a practical security impact:

- style-only issues
- non-exploitable crashes in unsupported local modifications
- issues caused solely by running unsigned or manually altered builds
