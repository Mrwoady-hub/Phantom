import SwiftUI

// MARK: - NetworkIntelView
//
// Clean numbered-list layout — one entry per detected network event,
// styled like a search-engine AI result: number · blue title · colon · description.
// No tool cards, no split panels, no filter tabs — just the signal.

struct NetworkIntelView: View {

    @EnvironmentObject private var engine: PacketCaptureEngine

    @State private var searchText    = ""
    @State private var liveInterface = "en0"
    @State private var expandedID:   UUID? = nil

    // MARK: - Body

    var body: some View {
        ZStack {
            Color.sgBackground.ignoresSafeArea()
            VStack(spacing: 0) {
                header
                // Helper unavailable banner — shown when the privileged helper is not
                // installed. Live packet capture requires the helper; lsof scanning
                // continues to work regardless.
                if !engine.helperAvailable {
                    helperUnavailableBanner
                }
                Divider().overlay(Color.sgBorder)
                content
            }
        }
        .onAppear {
            // Detect the active network interface (e.g. en0, en1, utun3) once on appear.
            // NgrepScanner.activeInterface() is synchronous — run it off the main thread.
            Task.detached(priority: .utility) {
                let detected = NgrepScanner().activeInterface() ?? "en0"
                await MainActor.run {
                    liveInterface = detected
                    // Only start live capture if the helper is installed and ready.
                    if engine.helperAvailable {
                        engine.startLiveCapture(interface: detected)
                    }
                    // Always run a scan immediately so Suricata events appear without waiting.
                    if engine.packetEvents.isEmpty {
                        Task { _ = await engine.scan() }
                    }
                }
            }
        }
        .onChange(of: engine.helperAvailable) { available in
            // helperAvailable starts false during "Checking…" (resolves in ≤3s).
            // Once it flips to true, auto-start live capture — the user shouldn't
            // have to tap "Go Live" just because the check took a moment.
            if available && !engine.isLiveCapturing {
                engine.startLiveCapture(interface: liveInterface)
            }
        }
        .onDisappear { engine.stopLiveCapture() }
    }

    // MARK: - Helper unavailable banner

    private var helperUnavailableBanner: some View {
        HStack(spacing: 10) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
                .font(.system(size: 13, weight: .semibold))
            VStack(alignment: .leading, spacing: 1) {
                Text("Live Capture Unavailable")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(Color.sgTextPrimary)
                Text(engine.helperStatusMessage)
                    .font(.system(size: 11))
                    .foregroundStyle(Color.sgTextSecondary)
            }
            Spacer()
            // Open the system Settings scene (where the user can install the helper)
            Button("Settings →") {
                NSApp.sendAction(Selector(("showSettingsWindow:")), to: nil, from: nil)
            }
            .font(.system(size: 11, weight: .semibold))
            .foregroundStyle(.orange)
            .buttonStyle(.plain)
        }
        .padding(.horizontal, 16).padding(.vertical, 10)
        .background(Color.orange.opacity(0.08))
    }

    // MARK: - Header (minimal)

    private var header: some View {
        HStack(spacing: 14) {
            // Icon
            ZStack {
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .fill(Color.sgPurple.opacity(0.16))
                    .frame(width: 38, height: 38)
                Image(systemName: "antenna.radiowaves.left.and.right")
                    .font(.system(size: 17, weight: .semibold))
                    .foregroundStyle(Color.sgPurple)
            }

            VStack(alignment: .leading, spacing: 2) {
                Text("Network Intelligence")
                    .font(.system(size: 15, weight: .bold, design: .rounded))
                    .foregroundStyle(Color.sgTextPrimary)
                HStack(spacing: 6) {
                    Circle()
                        .fill(engine.isLiveCapturing ? Color.sgSafe : Color.sgTextTertiary)
                        .frame(width: 6, height: 6)
                    Text(engine.isLiveCapturing
                         ? "Live · \(filteredEvents.count) events"
                         : "\(filteredEvents.count) events")
                        .font(.system(size: 11))
                        .foregroundStyle(Color.sgTextSecondary)
                }
            }

            Spacer()

            // Search
            HStack(spacing: 6) {
                Image(systemName: "magnifyingglass")
                    .font(.system(size: 11))
                    .foregroundStyle(Color.sgTextTertiary)
                TextField("Search…", text: $searchText)
                    .font(.system(size: 12))
                    .foregroundStyle(Color.sgTextPrimary)
                    .textFieldStyle(.plain)
                    .frame(width: 140)
                if !searchText.isEmpty {
                    Button { searchText = "" } label: {
                        Image(systemName: "xmark.circle.fill")
                            .font(.system(size: 10))
                            .foregroundStyle(Color.sgTextTertiary)
                    }.buttonStyle(.plain)
                }
            }
            .padding(.horizontal, 10).padding(.vertical, 6)
            .background(Color.sgSurface)
            .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).stroke(Color.sgBorder))

            // Live toggle
            Button {
                if engine.isLiveCapturing { engine.stopLiveCapture() }
                else { engine.startLiveCapture(interface: liveInterface) }
            } label: {
                HStack(spacing: 5) {
                    Circle()
                        .fill(engine.isLiveCapturing ? Color.sgSafe : Color.sgTextTertiary)
                        .frame(width: 6, height: 6)
                    Text(engine.isLiveCapturing ? "Live" : "Go Live")
                        .font(.system(size: 12, weight: .semibold))
                }
                .padding(.horizontal, 12).padding(.vertical, 7)
                .background(engine.isLiveCapturing ? Color.sgSafe.opacity(0.12) : Color.sgSurfaceRaised)
                .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
                .foregroundStyle(engine.isLiveCapturing ? Color.sgSafe : Color.sgTextSecondary)
                .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .stroke(engine.isLiveCapturing ? Color.sgSafe.opacity(0.35) : Color.sgBorder))
            }
            .buttonStyle(.plain)

            // Scan
            Button { Task { _ = await engine.scan() } } label: {
                HStack(spacing: 5) {
                    if engine.isAnalyzing {
                        ProgressView().scaleEffect(0.65).tint(.white)
                    } else {
                        Image(systemName: "waveform.path.ecg")
                            .font(.system(size: 11, weight: .semibold))
                    }
                    Text(engine.isAnalyzing ? "Scanning…" : "Scan Now")
                        .font(.system(size: 12, weight: .semibold))
                }
                .padding(.horizontal, 12).padding(.vertical, 7)
                .background(Color.sgPurple)
                .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
                .foregroundStyle(.white)
            }
            .buttonStyle(.plain)
            .disabled(engine.isAnalyzing)
        }
        .padding(.horizontal, 24).padding(.vertical, 14)
        .background(Color.sgSurface)
    }

    // MARK: - Content

    private var content: some View {
        let events = filteredEvents
        return Group {
            if events.isEmpty {
                emptyState
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 0) {
                        // "Here are N connections…" lead-in line
                        HStack(spacing: 0) {
                            Text("Here are ")
                                .font(.system(size: 15))
                                .foregroundStyle(Color.sgTextSecondary)
                            Text("\(events.count) network \(events.count == 1 ? "event" : "events")")
                                .font(.system(size: 15, weight: .semibold))
                                .foregroundStyle(Color.sgTextPrimary)
                            Text(" observed on this device:")
                                .font(.system(size: 15))
                                .foregroundStyle(Color.sgTextSecondary)
                        }
                        .padding(.horizontal, 48)
                        .padding(.top, 28)
                        .padding(.bottom, 20)

                        ForEach(Array(events.enumerated()), id: \.element.id) { index, event in
                            NetworkIntelRow(
                                index:      index + 1,
                                event:      event,
                                isExpanded: expandedID == event.id
                            )
                            .onTapGesture {
                                withAnimation(.spring(response: 0.3, dampingFraction: 0.75)) {
                                    expandedID = expandedID == event.id ? nil : event.id
                                }
                            }

                            // Subtle divider between items
                            if index < events.count - 1 {
                                Divider()
                                    .overlay(Color.sgBorder)
                                    .padding(.leading, 48 + 28 + 16)
                                    .padding(.trailing, 48)
                            }
                        }

                        // Bottom breathing room
                        Color.clear.frame(height: 40)
                    }
                }
                .scrollContentBackground(.hidden)
                .background(Color.sgBackground)
            }
        }
    }

    // MARK: - Empty state

    private var emptyState: some View {
        VStack(spacing: 16) {
            Image(systemName: "waveform.path.ecg")
                .font(.system(size: 40))
                .foregroundStyle(Color.sgTextTertiary)
            Text("No network events yet")
                .font(.system(size: 16, weight: .semibold))
                .foregroundStyle(Color.sgTextSecondary)
            Text("Tap Go Live for continuous monitoring, or Scan Now for a one-pass analysis.")
                .font(.system(size: 13))
                .foregroundStyle(Color.sgTextTertiary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 360)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color.sgBackground)
    }

    // MARK: - Filtered events

    private var filteredEvents: [PacketEvent] {
        guard !searchText.isEmpty else { return engine.packetEvents }
        let q = searchText.lowercased()
        return engine.packetEvents.filter {
            $0.summary.lowercased().contains(q)
            || ($0.sourceIP?.contains(q) ?? false)
            || ($0.destinationIP?.contains(q) ?? false)
            || ($0.dnsQuery?.lowercased().contains(q) ?? false)
            || ($0.signatureName?.lowercased().contains(q) ?? false)
            || ($0.artifact?.lowercased().contains(q) ?? false)
            || ($0.httpURL?.lowercased().contains(q) ?? false)
        }
    }
}

// MARK: - NetworkIntelRow

private struct NetworkIntelRow: View {
    let index:      Int
    let event:      PacketEvent
    let isExpanded: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .top, spacing: 16) {
                // ── Index number ───────────────────────────────────────────
                Text("\(index).")
                    .font(.system(size: 16, weight: .bold, design: .rounded))
                    .foregroundStyle(severityColor.opacity(0.85))
                    .frame(width: 28, alignment: .trailing)
                    .padding(.top, 1)

                // ── Body ───────────────────────────────────────────────────
                VStack(alignment: .leading, spacing: 6) {
                    // Title + colon + first-line description (all inline)
                    titleDescriptionText
                        .fixedSize(horizontal: false, vertical: true)

                    // Source badge row
                    HStack(spacing: 8) {
                        // Tool pill
                        HStack(spacing: 3) {
                            Image(systemName: event.tool.symbol)
                                .font(.system(size: 9, weight: .semibold))
                            Text(event.tool.displayName)
                                .font(.system(size: 9, weight: .semibold))
                        }
                        .foregroundStyle(toolColor)
                        .padding(.horizontal, 7).padding(.vertical, 3)
                        .background(toolColor.opacity(0.12))
                        .clipShape(Capsule())

                        // Category
                        Text(event.category.title)
                            .font(.system(size: 9))
                            .foregroundStyle(Color.sgTextTertiary)

                        Spacer()

                        // Timestamp
                        Text(event.timestamp, format: .relative(presentation: .named, unitsStyle: .abbreviated))
                            .font(.system(size: 9))
                            .foregroundStyle(Color.sgTextTertiary)

                        // Expand chevron
                        Image(systemName: isExpanded ? "chevron.up" : "chevron.down")
                            .font(.system(size: 9, weight: .semibold))
                            .foregroundStyle(Color.sgTextTertiary)
                    }
                }
            }
            .padding(.horizontal, 48)
            .padding(.vertical, 16)
            .background(isExpanded ? Color.sgSurface.opacity(0.6) : Color.clear)

            // ── Expanded detail ────────────────────────────────────────────
            if isExpanded {
                expandedDetail
                    .padding(.leading, 48 + 28 + 16)
                    .padding(.trailing, 48)
                    .padding(.bottom, 14)
                    .background(Color.sgSurface.opacity(0.6))
                    .transition(.opacity.combined(with: .move(edge: .top)))
            }
        }
    }

    // MARK: - Inline title+description text

    private var titleDescriptionText: some View {
        // macOS 26: Text + Text concatenation deprecated — use string interpolation instead.
        Text(
            "\(Text(eventTitle).font(.system(size: 14, weight: .semibold)).foregroundStyle(Color.sgBlue)): \(Text(eventDescription).font(.system(size: 14)).foregroundStyle(Color.sgTextPrimary))"
        )
        .lineLimit(isExpanded ? nil : 3)
    }

    // MARK: - Expanded detail fields

    private var expandedDetail: some View {
        VStack(alignment: .leading, spacing: 5) {
            Divider().overlay(Color.sgBorder).padding(.bottom, 4)

            if let src = event.sourceIP {
                detailLine(label: "Source",
                           value: src + (event.sourcePort.map { ":\($0)" } ?? ""))
            }
            if let dst = event.destinationIP {
                let portStr = event.destinationPort.map { p -> String in
                    let svc = portService(p).map { " · \($0)" } ?? ""
                    return ":\(p)\(svc)"
                } ?? ""
                detailLine(label: "Destination", value: dst + portStr)
            }
            if let proto = event.proto { detailLine(label: "Protocol", value: proto) }
            if let sig   = event.signatureName { detailLine(label: "Signature", value: sig) }
            if let sid   = event.signatureID   { detailLine(label: "SID",       value: sid) }
            if let m     = event.httpMethod, let u = event.httpURL {
                detailLine(label: "HTTP", value: "\(m) \(u)")
            }
            if let q  = event.dnsQuery  { detailLine(label: "DNS Query",  value: q) }
            if let tls = event.tlsSubject { detailLine(label: "TLS",       value: tls) }
            if let art = event.artifact  { detailLine(label: "Artifact",   value: art) }
            if let d   = event.detail, !d.isEmpty {
                detailLine(label: "Analysis", value: d)
            }
        }
    }

    private func detailLine(label: String, value: String) -> some View {
        HStack(alignment: .top, spacing: 6) {
            Text(label + ":")
                .font(.system(size: 10, weight: .semibold))
                .foregroundStyle(Color.sgTextSecondary)
                .frame(width: 72, alignment: .leading)
            Text(value)
                .font(.system(size: 10, design: value.contains(".") || value.contains(":") ? .monospaced : .default))
                .foregroundStyle(Color.sgTextPrimary)
                .textSelection(.enabled)
            Spacer(minLength: 0)
        }
    }

    // MARK: - Title derivation

    private var eventTitle: String {
        switch event.category {
        case .alert, .patternMatch:
            return event.signatureName ?? "\(event.tool.displayName) Alert"
        case .dns:
            if let q = event.dnsQuery {
                // Show just the domain part, not the full query if it's a PTR etc.
                return q.count > 50 ? String(q.prefix(50)) + "…" : q
            }
            return "DNS Query"
        case .http:
            if let url = event.httpURL, let host = URL(string: url)?.host {
                return host
            }
            return event.httpMethod.map { "\($0) Request" } ?? "HTTP"
        case .tls:
            if let subj = event.tlsSubject {
                // Strip "CN=" prefix if present
                return subj.replacingOccurrences(of: "CN=", with: "")
            }
            return "TLS Session"
        case .artifact:
            return "Artifact"
        case .connection:
            // lsof-sourced events embed process name before " → "
            if event.summary.contains(" → ") {
                return event.summary.components(separatedBy: " → ").first ?? "Connection"
            }
            if let dst = event.destinationIP {
                let port = event.destinationPort.map { ":\($0)" } ?? ""
                return dst + port
            }
            return event.summary.components(separatedBy: " ").first ?? "Connection"
        case .suspicious:
            return event.summary.count > 60
                ? String(event.summary.prefix(60)) + "…"
                : event.summary
        }
    }

    // MARK: - Description derivation

    private var eventDescription: String {
        switch event.category {
        case .alert, .patternMatch:
            var parts: [String] = []
            let sev = event.severity.rawValue.capitalized
            parts.append("\(event.tool.displayName) flagged a \(sev.lowercased())-severity intrusion detection rule.")
            if let src = event.sourceIP, let dst = event.destinationIP {
                let port = event.destinationPort.map { p -> String in
                    let svc = portService(p).map { " (\($0))" } ?? ""
                    return ":\(p)\(svc)"
                } ?? ""
                parts.append("Traffic: \(src) → \(dst)\(port).")
            }
            if let d = event.detail, !d.isEmpty { parts.append(d) }
            return parts.joined(separator: " ")

        case .dns:
            var parts: [String] = []
            parts.append("DNS name resolution captured by \(event.tool.displayName).")
            if let src = event.sourceIP { parts.append("Querying device: \(src).") }
            if let d = event.detail, !d.isEmpty { parts.append(d) }
            else { parts.append("DNS lookups are normal; unusual or high-frequency queries may indicate DNS tunneling.") }
            return parts.joined(separator: " ")

        case .http:
            var parts: [String] = []
            if let m = event.httpMethod, let u = event.httpURL {
                parts.append("\(m) request to \(u).")
            }
            if let src = event.sourceIP, let dst = event.destinationIP {
                parts.append("\(src) → \(dst).")
            }
            if let d = event.detail, !d.isEmpty { parts.append(d) }
            else { parts.append("Unencrypted HTTP traffic is visible in transit. HTTPS is preferred.") }
            return parts.joined(separator: " ")

        case .tls:
            var parts: [String] = []
            parts.append("Encrypted TLS session negotiated.")
            if let src = event.sourceIP, let dst = event.destinationIP {
                let port = event.destinationPort.map { ":\($0)" } ?? ""
                parts.append("\(src) → \(dst)\(port).")
            }
            if let d = event.detail, !d.isEmpty { parts.append(d) }
            else { parts.append("TLS protects data in transit; the session metadata is still visible.") }
            return parts.joined(separator: " ")

        case .connection:
            var parts: [String] = []
            let proto = event.proto ?? "TCP"
            // lsof-sourced: title is process name, description is the full connection
            if event.summary.contains(" → "), let dst = event.destinationIP {
                let portStr = event.destinationPort.map { p -> String in
                    let svc = portService(p).map { " (\($0))" } ?? ""
                    return ":\(p)\(svc)"
                } ?? ""
                parts.append("\(proto) connection to \(dst)\(portStr).")
                if let d = event.detail, !d.isEmpty { parts.append(d) }
            } else {
                if let src = event.sourceIP, let dst = event.destinationIP {
                    let portStr = event.destinationPort.map { p -> String in
                        let svc = portService(p).map { " (\($0))" } ?? ""
                        return ":\(p)\(svc)"
                    } ?? ""
                    parts.append("\(proto) connection: \(src) → \(dst)\(portStr).")
                }
                if let d = event.detail, !d.isEmpty { parts.append(d) }
                else { parts.append("Captured by \(event.tool.displayName).") }
            }
            return parts.joined(separator: " ")

        case .artifact:
            var parts: [String] = []
            parts.append("Network artifact extracted by \(event.tool.displayName).")
            if let a = event.artifact { parts.append("\(a).") }
            if let d = event.detail, !d.isEmpty { parts.append(d) }
            return parts.joined(separator: " ")

        case .suspicious:
            var parts: [String] = []
            parts.append("\(event.tool.displayName) detected anomalous network behavior.")
            if let src = event.sourceIP { parts.append("Source: \(src).") }
            if let d = event.detail, !d.isEmpty { parts.append(d) }
            return parts.joined(separator: " ")
        }
    }

    // MARK: - Port → service name

    private func portService(_ port: Int) -> String? {
        switch port {
        case 21:   return "FTP"
        case 22:   return "SSH"
        case 23:   return "Telnet"
        case 25:   return "SMTP"
        case 53:   return "DNS"
        case 80:   return "HTTP"
        case 110:  return "POP3"
        case 143:  return "IMAP"
        case 443:  return "HTTPS"
        case 445:  return "SMB"
        case 587:  return "SMTP/TLS"
        case 993:  return "IMAPS"
        case 995:  return "POP3S"
        case 1194: return "OpenVPN"
        case 1337: return "Leet/Malware"
        case 3389: return "RDP"
        case 4444: return "Metasploit C2"
        case 5900: return "VNC"
        case 6667: return "IRC"
        case 8080: return "HTTP-alt"
        case 8443: return "HTTPS-alt"
        default:   return nil
        }
    }

    // MARK: - Colors

    private var severityColor: Color {
        switch event.severity {
        case .high:   return Color(red: 1.0,  green: 0.27, blue: 0.27)
        case .medium: return Color(red: 1.0,  green: 0.62, blue: 0.05)
        case .low:    return Color(red: 0.18, green: 0.85, blue: 0.55)
        }
    }

    private var toolColor: Color {
        switch event.tool {
        case .tshark, .wireshark: return Color(red: 0.20, green: 0.55, blue: 1.0)
        case .tcpdump:            return Color(red: 0.10, green: 0.80, blue: 0.85)
        case .zeek:               return Color(red: 0.65, green: 0.35, blue: 1.0)
        case .suricata:           return Color(red: 1.0,  green: 0.27, blue: 0.27)
        case .ngrep:              return Color(red: 1.0,  green: 0.62, blue: 0.05)
        case .networkMiner:       return Color(red: 0.18, green: 0.85, blue: 0.55)
        }
    }
}

// Design tokens live in MainView.swift (module-level extension Color).
