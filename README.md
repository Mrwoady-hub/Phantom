# SentinelGuard

**SentinelGuard** is a real-time macOS threat detection platform built in Swift that identifies suspicious behavior using MITRE ATT&CK–mapped techniques, live C2 intelligence feeds, and a tamper-resistant audit trail.

Designed to be lightweight, transparent, and production-ready, SentinelGuard operates with zero external dependencies and is fully notarized for macOS Gatekeeper trust.

---

## Key Capabilities

- Real-time behavioral monitoring on macOS
- Detection logic mapped to **9 MITRE ATT&CK techniques**
- Live Command & Control (C2) threat intelligence blocklists
- Tamper-resistant JSONL audit logging
- Lightweight architecture with zero third-party dependencies
- Apple notarized for Gatekeeper trust
- Designed for transparency and auditability
- Built entirely in Swift

---

## Detection Areas

SentinelGuard focuses on identifying behavior commonly associated with post-compromise activity:

- Suspicious process execution patterns
- Command-line misuse indicators
- Unauthorized scripting activity
- Potential C2 beaconing behavior
- File system persistence techniques
- Privilege escalation indicators
- Data staging indicators
- Abnormal system utility usage
- Indicators aligned to MITRE ATT&CK tactics

---

## Architecture Overview

SentinelGuard consists of two primary components:

### macOS Application (Swift / SwiftUI)

- User interface for visibility and monitoring
- Displays agent status and detected incidents
- Provides structured alert output
- Designed with minimal system overhead

### Monitoring Agent

- Continuously evaluates system activity
- Applies scoring logic to potential threat behavior
- Logs structured security events
- Designed for reliability and tamper resistance

---

## Example Log Output

```json
{
  "timestamp": "2026-03-14T21:33:11Z",
  "event_type": "incident",
  "severity": "high",
  "score": 92,
  "technique": "Command and Scripting Interpreter",
  "process": "curl",
  "reason": "Possible command-and-control communication behavior detected"
}
```

---

## Security Philosophy

SentinelGuard follows several core engineering principles:

- visibility over obscurity
- deterministic detection logic
- minimal attack surface
- audit-friendly structured logging
- operational simplicity
- practical MITRE ATT&CK alignment

---

## Intended Use

SentinelGuard is designed for:

- cybersecurity learning environments
- detection engineering experimentation
- macOS security research
- blue team portfolio demonstration
- lightweight endpoint visibility
- SOC analyst skill development

---

## Project Status

Active development

Current focus areas:

- expanding behavioral detection coverage
- improving scoring accuracy
- refining alert clarity
- strengthening audit integrity
- expanding MITRE ATT&CK mapping depth

---

## Author

George Gonzalez  
Cybersecurity Student | Detection Engineering Focus  
Building practical blue-team tools and security platforms

---

## Disclaimer

This project is intended for educational and research purposes only.

SentinelGuard is not positioned as a replacement for enterprise EDR solutions but as a practical demonstration of detection engineering concepts and macOS telemetry analysis.
