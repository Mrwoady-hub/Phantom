import SwiftUI

// MARK: - NetworkIntelView
//
// Phantom 3.0 — Real-time Network Intelligence Dashboard
//
// Layout:
//   ┌──────── Header ─ title, stats, Go Live, Scan Now ────────┐
//   │  Tool Cards  (7 cards — one per tool, live status)       │
//   ├──── Category tabs ────────────────────────── Search ─────┤
//   │  Live Event Stream (color by tool) │ Event Detail panel  │
//   └────────────────────────────────────┴─────────────────────┘

struct NetworkIntelView: View {

    @EnvironmentObject private var engine: PacketCaptureEngine

    @State private var selectedTab:   NetworkIntelTab = .all
    @State private var selectedTool:  PacketTool?        // nil = all tools
    @State private var selectedEvent: PacketEvent?
    @State private var searchText     = ""
    @State private var liveInterface  = "en0"

    // MARK: - Body

    var body: some View {
        ZStack {
            Color.sgBackground.ignoresSafeArea()
            VStack(spacing: 0) {
                header
                Divider().overlay(Color.sgBorder)
                toolCardStrip
                Divider().overlay(Color.sgBorder)
                if engine.isLiveCapturing {
                    liveStatusBar
                    Divider().overlay(Color.sgBorder)
                }
                filterBar
                Divider().overlay(Color.sgBorder)
                HStack(spacing: 0) {
                    eventFeed
                        .frame(minWidth: 400, maxWidth: .infinity)
                    Divider().overlay(Color.sgBorder)
                    detailPanel
                        .frame(width: 340)
                }
            }
        }
        .onAppear {
            // Auto-start live capture the moment the Network Intel tab opens.
            // startLiveCapture() is a no-op if already running (safe to call on tab switch).
            // It handles: Suricata stream, pcap capture loop, and auto-refresh coordination.
            // If the privileged helper is not installed, the capture loop shows an error
            // and retries every 5 s — Suricata (no root needed) keeps streaming regardless.
            engine.startLiveCapture(interface: liveInterface)
        }
        .onDisappear {
            engine.stopLiveCapture()
        }
    }

    // MARK: - Header

    private var header: some View {
        HStack(spacing: 12) {
            ZStack {
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .fill(Color.sgPurple.opacity(0.18))
                    .frame(width: 40, height: 40)
                Image(systemName: "antenna.radiowaves.left.and.right")
                    .font(.system(size: 18, weight: .semibold))
                    .foregroundStyle(Color.sgPurple)
            }

            VStack(alignment: .leading, spacing: 2) {
                Text("Network Intelligence")
                    .font(.system(size: 16, weight: .bold, design: .rounded))
                    .foregroundStyle(Color.sgTextPrimary)
                Text("7 tools · real-time analysis")
                    .font(.system(size: 11, weight: .medium))
                    .foregroundStyle(Color.sgTextTertiary)
            }

            Spacer()

            // Stats reflect the currently selected tool so the count always matches the feed.
            let visibleEvents = selectedTool.map { engine.events(for: $0) } ?? engine.packetEvents
            StatPill(
                label: selectedTool.map { $0.displayName } ?? "Events",
                value: "\(visibleEvents.count)",
                color: .sgBlue
            )
            StatPill(label: "Alerts",
                     value: "\(visibleEvents.filter { $0.category == .alert || $0.category == .patternMatch }.count)",
                     color: .sgDanger)
            StatPill(label: "DNS",
                     value: "\(visibleEvents.filter { $0.category == .dns }.count)",
                     color: .sgSafe)

            // Go Live toggle
            Button {
                if engine.isLiveCapturing {
                    engine.stopLiveCapture()
                } else {
                    engine.startLiveCapture(interface: liveInterface)
                }
            } label: {
                HStack(spacing: 6) {
                    Circle()
                        .fill(engine.isLiveCapturing ? Color.sgSafe : Color.sgTextTertiary)
                        .frame(width: 7, height: 7)
                    Text(engine.isLiveCapturing ? "Live" : "Go Live")
                        .font(.system(size: 13, weight: .semibold))
                }
                .padding(.horizontal, 14).padding(.vertical, 8)
                .background(engine.isLiveCapturing ? Color.sgSafe.opacity(0.15) : Color.sgSurfaceRaised)
                .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
                .foregroundStyle(engine.isLiveCapturing ? Color.sgSafe : Color.sgTextSecondary)
                .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .stroke(engine.isLiveCapturing ? Color.sgSafe.opacity(0.4) : Color.sgBorder, lineWidth: 1))
            }
            .buttonStyle(.plain)

            // Manual scan
            Button {
                Task { _ = await engine.scan() }
            } label: {
                HStack(spacing: 6) {
                    if engine.isAnalyzing {
                        ProgressView().scaleEffect(0.7).tint(.white)
                    } else {
                        Image(systemName: "waveform.path.ecg")
                            .font(.system(size: 12, weight: .semibold))
                    }
                    Text(engine.isAnalyzing ? "Analyzing…" : "Scan Now")
                        .font(.system(size: 13, weight: .semibold))
                }
                .padding(.horizontal, 14).padding(.vertical, 8)
                .background(Color.sgPurple)
                .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
                .foregroundStyle(.white)
            }
            .buttonStyle(.plain)
            .disabled(engine.isAnalyzing)
        }
        .padding(.horizontal, 20).padding(.vertical, 14)
        .background(Color.sgSurface)
    }

    // MARK: - Tool Card Strip

    private var toolCardStrip: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                allToolsCard
                Divider().frame(height: 50).overlay(Color.sgBorder)
                ForEach(PacketTool.allCases.filter { $0 != .wireshark }, id: \.self) { tool in
                    ToolCard(
                        tool:       tool,
                        activity:   engine.toolActivity[tool] ?? ToolActivityState(),
                        isSelected: selectedTool == tool,
                        eventCount: engine.events(for: tool).count
                    )
                    .onTapGesture {
                        withAnimation(.easeInOut(duration: 0.15)) {
                            selectedTool  = selectedTool == tool ? nil : tool
                            selectedEvent = nil
                        }
                    }
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 10)
        }
        .background(Color.sgSurface.opacity(0.6))
    }

    private var allToolsCard: some View {
        let isSelected = selectedTool == nil
        return Button {
            withAnimation(.easeInOut(duration: 0.15)) {
                selectedTool  = nil
                selectedEvent = nil
            }
        } label: {
            VStack(spacing: 4) {
                Image(systemName: "circle.grid.3x3.fill")
                    .font(.system(size: 16, weight: .semibold))
                    .foregroundStyle(isSelected ? Color.sgPurple : Color.sgTextTertiary)
                Text("All Tools")
                    .font(.system(size: 10, weight: .bold))
                    .foregroundStyle(isSelected ? Color.sgTextPrimary : Color.sgTextTertiary)
                Text("\(engine.packetEvents.count)")
                    .font(.system(size: 13, weight: .black, design: .rounded))
                    .foregroundStyle(isSelected ? Color.sgPurple : Color.sgTextSecondary)
            }
            .frame(width: 80, height: 72)
            .background(isSelected ? Color.sgPurple.opacity(0.15) : Color.sgSurfaceRaised)
            .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous)
                .stroke(isSelected ? Color.sgPurple.opacity(0.5) : Color.sgBorder, lineWidth: 1))
        }
        .buttonStyle(.plain)
    }

    // MARK: - Live Status Bar

    private var liveStatusBar: some View {
        HStack(spacing: 8) {
            Circle().fill(Color.sgSafe).frame(width: 6, height: 6)
            Text(engine.liveStatus.isEmpty ? "Live capture active" : engine.liveStatus)
                .font(.system(size: 11, weight: .medium))
                .foregroundStyle(Color.sgSafe)
            Spacer()
            HStack(spacing: 4) {
                Text("Interface:")
                    .font(.system(size: 11))
                    .foregroundStyle(Color.sgTextTertiary)
                TextField("en0", text: $liveInterface)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(Color.sgTextPrimary)
                    .textFieldStyle(.plain)
                    .frame(width: 60)
            }
            if let last = engine.lastScanDate {
                Text("Updated \(last, format: .dateTime.hour().minute().second())")
                    .font(.system(size: 10))
                    .foregroundStyle(Color.sgTextTertiary)
            }
        }
        .padding(.horizontal, 20).padding(.vertical, 7)
        .background(Color.sgSafe.opacity(0.06))
    }

    // MARK: - Filter Bar

    private var filterBar: some View {
        HStack(spacing: 0) {
            ForEach(NetworkIntelTab.allCases, id: \.self) { tab in
                Button {
                    selectedTab   = tab
                    selectedEvent = nil
                } label: {
                    HStack(spacing: 5) {
                        Image(systemName: tab.symbol)
                            .font(.system(size: 10, weight: .semibold))
                        Text(tab.label)
                            .font(.system(size: 12, weight: .semibold))
                        let c = tabCount(tab)
                        if c > 0 {
                            Text("\(c)")
                                .font(.system(size: 9, weight: .bold))
                                .padding(.horizontal, 5).padding(.vertical, 2)
                                .background(selectedTab == tab ? Color.white.opacity(0.2) : Color.sgBorder)
                                .clipShape(Capsule())
                        }
                    }
                    .padding(.horizontal, 12).padding(.vertical, 8)
                    .foregroundStyle(selectedTab == tab ? Color.sgTextPrimary : Color.sgTextSecondary)
                    .background(selectedTab == tab ? Color.sgSurfaceRaised : Color.clear)
                }
                .buttonStyle(.plain)
            }
            Spacer()
            HStack(spacing: 6) {
                Image(systemName: "magnifyingglass")
                    .font(.system(size: 11))
                    .foregroundStyle(Color.sgTextTertiary)
                TextField("Search events…", text: $searchText)
                    .font(.system(size: 12))
                    .foregroundStyle(Color.sgTextPrimary)
                    .textFieldStyle(.plain)
                    .frame(width: 160)
                if !searchText.isEmpty {
                    Button { searchText = "" } label: {
                        Image(systemName: "xmark.circle.fill")
                            .font(.system(size: 11))
                            .foregroundStyle(Color.sgTextTertiary)
                    }.buttonStyle(.plain)
                }
            }
            .padding(.horizontal, 10).padding(.vertical, 6)
            .background(Color.sgSurface)
            .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
            .padding(.trailing, 16)
        }
        .background(Color.sgBackground)
    }

    // MARK: - Event Feed

    private var eventFeed: some View {
        let events = filteredEvents
        return Group {
            if events.isEmpty {
                emptyState
            } else {
                List(events, id: \.id) { ev in
                    EventRow(event: ev, isSelected: selectedEvent?.id == ev.id)
                        .listRowBackground(Color.clear)
                        .listRowSeparator(.hidden)
                        .listRowInsets(.init(top: 2, leading: 10, bottom: 2, trailing: 10))
                        .onTapGesture { selectedEvent = ev }
                }
                .listStyle(.plain)
                .scrollContentBackground(.hidden)
            }
        }
        .background(Color.sgBackground)
    }

    private var filteredEvents: [PacketEvent] {
        var base = selectedTool.map { engine.events(for: $0) } ?? engine.packetEvents
        switch selectedTab {
        case .all:         break
        case .alerts:      base = base.filter { $0.category == .alert || $0.category == .patternMatch || $0.category == .suspicious }
        case .dns:         base = base.filter { $0.category == .dns }
        case .connections: base = base.filter { $0.category == .connection }
        case .artifacts:   base = base.filter { $0.category == .artifact }
        case .http:        base = base.filter { $0.category == .http || $0.category == .tls }
        }
        guard !searchText.isEmpty else { return base }
        let q = searchText.lowercased()
        return base.filter {
            $0.summary.lowercased().contains(q) ||
            ($0.sourceIP?.contains(q) ?? false) ||
            ($0.destinationIP?.contains(q) ?? false) ||
            ($0.dnsQuery?.lowercased().contains(q) ?? false) ||
            ($0.signatureName?.lowercased().contains(q) ?? false) ||
            ($0.artifact?.lowercased().contains(q) ?? false)
        }
    }

    private func tabCount(_ tab: NetworkIntelTab) -> Int {
        let base = selectedTool.map { engine.events(for: $0) } ?? engine.packetEvents
        switch tab {
        case .all:         return base.count
        case .alerts:      return base.filter { $0.category == .alert || $0.category == .patternMatch || $0.category == .suspicious }.count
        case .dns:         return base.filter { $0.category == .dns }.count
        case .connections: return base.filter { $0.category == .connection }.count
        case .artifacts:   return base.filter { $0.category == .artifact }.count
        case .http:        return base.filter { $0.category == .http || $0.category == .tls }.count
        }
    }

    private var emptyState: some View {
        VStack(spacing: 14) {
            Image(systemName: selectedTool?.symbol ?? "waveform.path.ecg")
                .font(.system(size: 36))
                .foregroundStyle(Color.sgTextTertiary)

            if let tool = selectedTool, !engine.packetEvents.isEmpty {
                // A specific tool is selected but has no events yet —
                // make this obvious and offer a one-tap escape.
                Text("\(tool.displayName) has no events yet")
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundStyle(Color.sgTextSecondary)
                Text("Events from other tools are still collecting.")
                    .font(.system(size: 12))
                    .foregroundStyle(Color.sgTextTertiary)
                Button {
                    withAnimation(.easeInOut(duration: 0.15)) { selectedTool = nil }
                } label: {
                    Text("Show all \(engine.packetEvents.count) events")
                        .font(.system(size: 12, weight: .semibold))
                        .padding(.horizontal, 14).padding(.vertical, 7)
                        .background(Color.sgBlue.opacity(0.18))
                        .foregroundStyle(Color.sgBlue)
                        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
                }
                .buttonStyle(.plain)
            } else if engine.packetEvents.isEmpty {
                Text("No data yet")
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundStyle(Color.sgTextSecondary)
                Text("Click \"Go Live\" to start continuous capture,\nor \"Scan Now\" for a single pass.")
                    .font(.system(size: 12))
                    .foregroundStyle(Color.sgTextTertiary)
                    .multilineTextAlignment(.center)
            } else {
                Text("No events match filter")
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundStyle(Color.sgTextSecondary)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: - Detail Panel

    private var detailPanel: some View {
        Group {
            if let ev = selectedEvent {
                EventDetailPanel(event: ev) { selectedEvent = nil }
            } else {
                VStack(spacing: 12) {
                    Image(systemName: "shield.lefthalf.filled")
                        .font(.system(size: 30))
                        .foregroundStyle(Color.sgPurple.opacity(0.4))
                    Text("Select an event")
                        .font(.system(size: 13, weight: .medium))
                        .foregroundStyle(Color.sgTextTertiary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(Color.sgBackground)
            }
        }
    }
}

// MARK: - ToolCard

private struct ToolCard: View {
    let tool:       PacketTool
    let activity:   ToolActivityState
    let isSelected: Bool
    let eventCount: Int

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack(spacing: 5) {
                Circle()
                    .fill(dotColor)
                    .frame(width: 6, height: 6)
                Image(systemName: tool.symbol)
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(toolColor)
                Spacer()
                if activity.isRunning {
                    ProgressView()
                        .scaleEffect(0.45)
                        .tint(toolColor)
                        .frame(width: 12, height: 12)
                }
            }
            Text(tool.displayName)
                .font(.system(size: 10, weight: .bold))
                .foregroundStyle(activity.isAvailable ? Color.sgTextPrimary : Color.sgTextTertiary)
                .lineLimit(1)
            Text("\(eventCount)")
                .font(.system(size: 15, weight: .black, design: .rounded))
                .foregroundStyle(activity.isAvailable ? toolColor : Color.sgTextTertiary)
            Text(activity.statusText)
                .font(.system(size: 9, weight: .medium))
                .foregroundStyle(Color.sgTextTertiary)
                .lineLimit(1)
        }
        .frame(width: 90, height: 72)
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .background(isSelected ? toolColor.opacity(0.15) : Color.sgSurfaceRaised)
        .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .stroke(
                    isSelected       ? toolColor.opacity(0.5) :
                    activity.isRunning ? toolColor.opacity(0.3) :
                    Color.sgBorder,
                    lineWidth: 1)
        )
        .opacity(activity.isAvailable ? 1 : 0.42)
    }

    private var dotColor: Color {
        guard activity.isAvailable else { return Color.sgTextTertiary }
        if activity.isRunning  { return Color.sgSafe }
        if activity.lastRun != nil { return Color.sgBlue }
        return Color.sgTextTertiary
    }
    private var toolColor: Color { toolPaletteColor(tool) }
}

// MARK: - EventRow

private struct EventRow: View {
    let event:      PacketEvent
    let isSelected: Bool

    var body: some View {
        HStack(spacing: 8) {
            // Tool-colored stripe
            RoundedRectangle(cornerRadius: 2)
                .fill(toolPaletteColor(event.tool))
                .frame(width: 3, height: 34)

            // Severity dot
            Circle()
                .fill(severityColor)
                .frame(width: 6, height: 6)

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 5) {
                    Text(event.tool.displayName)
                        .font(.system(size: 9, weight: .bold))
                        .foregroundStyle(toolPaletteColor(event.tool))
                        .padding(.horizontal, 5).padding(.vertical, 2)
                        .background(toolPaletteColor(event.tool).opacity(0.12))
                        .clipShape(Capsule())

                    Text(event.category.title)
                        .font(.system(size: 9))
                        .foregroundStyle(Color.sgTextTertiary)

                    Spacer()

                    Text(event.timestamp, format: .dateTime.hour().minute().second())
                        .font(.system(size: 9, design: .monospaced))
                        .foregroundStyle(Color.sgTextTertiary)
                }

                Text(event.summary)
                    .font(.system(size: 11, weight: .medium))
                    .foregroundStyle(Color.sgTextPrimary)
                    .lineLimit(1)

                if let conn = connLabel {
                    Text(conn)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(Color.sgTextTertiary)
                        .lineLimit(1)
                }
            }
        }
        .padding(.vertical, 5)
        .padding(.horizontal, 8)
        .background(isSelected ? toolPaletteColor(event.tool).opacity(0.12) : Color.sgSurface.opacity(0.4))
        .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
    }

    private var severityColor: Color {
        switch event.severity {
        case .high:   return Color.sgDanger
        case .medium: return Color.sgWarning
        case .low:    return Color.sgSafe.opacity(0.5)
        }
    }
    private var connLabel: String? {
        let l = event.connectionLabel
        return (l == "Unknown" || l.isEmpty) ? nil : l
    }
}

// MARK: - EventDetailPanel

private struct EventDetailPanel: View {
    let event:   PacketEvent
    let onClose: () -> Void

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                // Header
                HStack(alignment: .top) {
                    VStack(alignment: .leading, spacing: 6) {
                        HStack(spacing: 5) {
                            HStack(spacing: 4) {
                                Image(systemName: event.tool.symbol)
                                    .font(.system(size: 10, weight: .semibold))
                                Text(event.tool.displayName)
                                    .font(.system(size: 10, weight: .bold))
                            }
                            .foregroundStyle(toolPaletteColor(event.tool))
                            .padding(.horizontal, 7).padding(.vertical, 3)
                            .background(toolPaletteColor(event.tool).opacity(0.14))
                            .clipShape(Capsule())

                            SeverityTag(severity: event.severity)

                            Text(event.category.title)
                                .font(.system(size: 10, weight: .semibold))
                                .foregroundStyle(Color.sgTextSecondary)
                                .padding(.horizontal, 7).padding(.vertical, 3)
                                .background(Color.sgSurfaceRaised)
                                .clipShape(Capsule())
                        }
                        Text(event.summary)
                            .font(.system(size: 13, weight: .bold))
                            .foregroundStyle(Color.sgTextPrimary)
                            .lineLimit(4)
                    }
                    Spacer()
                    Button { onClose() } label: {
                        Image(systemName: "xmark.circle.fill")
                            .font(.system(size: 16))
                            .foregroundStyle(Color.sgTextTertiary)
                    }.buttonStyle(.plain)
                }
                .padding(14)
                .background(Color.sgSurface)

                Divider().overlay(Color.sgBorder)

                if event.sourceIP != nil || event.destinationIP != nil {
                    DetailSection(title: "Network") {
                        if let v = event.sourceIP {
                            DetailRow(label: "Source",
                                      value: "\(v)\(event.sourcePort.map { ":\($0)" } ?? "")")
                        }
                        if let v = event.destinationIP {
                            DetailRow(label: "Destination",
                                      value: "\(v)\(event.destinationPort.map { ":\($0)" } ?? "")")
                        }
                        if let v = event.proto { DetailRow(label: "Protocol", value: v) }
                    }
                }

                DetailSection(title: "Detection") {
                    DetailRow(label: "Tool",     value: event.tool.displayName)
                    DetailRow(label: "Category", value: event.category.title)
                    DetailRow(label: "Severity", value: event.severity.rawValue.capitalized)
                    DetailRow(label: "Time",
                              value: event.timestamp.formatted(.dateTime.year().month().day().hour().minute().second()))
                    if let v = event.signatureName { DetailRow(label: "Signature", value: v) }
                    if let v = event.signatureID   { DetailRow(label: "SID",       value: v) }
                }

                if event.httpURL != nil || event.httpMethod != nil {
                    DetailSection(title: "HTTP") {
                        if let v = event.httpMethod { DetailRow(label: "Method", value: v) }
                        if let v = event.httpURL    { DetailRow(label: "URL",    value: v) }
                    }
                }
                if let q = event.dnsQuery {
                    DetailSection(title: "DNS") { DetailRow(label: "Query", value: q) }
                }
                if let s = event.tlsSubject {
                    DetailSection(title: "TLS") { DetailRow(label: "Subject", value: s) }
                }
                if let a = event.artifact {
                    DetailSection(title: "Artifact") { DetailRow(label: "Content", value: a) }
                }
                if let d = event.detail, !d.isEmpty {
                    DetailSection(title: "Analysis") {
                        Text(d)
                            .font(.system(size: 11))
                            .foregroundStyle(Color.sgTextSecondary)
                            .padding(.horizontal, 14).padding(.bottom, 10)
                    }
                }
                if let raw = event.rawPayload, !raw.isEmpty {
                    DetailSection(title: "Raw Payload") {
                        Text(raw.prefix(500).description)
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundStyle(Color.sgTextSecondary)
                            .padding(.horizontal, 14).padding(.bottom, 10)
                            .lineLimit(12)
                    }
                }
            }
        }
        .background(Color.sgBackground)
    }
}

// MARK: - Supporting Views

private struct DetailSection<Content: View>: View {
    let title: String
    @ViewBuilder let content: () -> Content
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(title.uppercased())
                .font(.system(size: 9, weight: .bold))
                .foregroundStyle(Color.sgTextTertiary)
                .padding(.horizontal, 14).padding(.top, 12).padding(.bottom, 4)
            content()
            Divider().overlay(Color.sgBorder).padding(.top, 4)
        }
    }
}

private struct DetailRow: View {
    let label: String
    let value: String
    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Text(label)
                .font(.system(size: 10, weight: .medium))
                .foregroundStyle(Color.sgTextSecondary)
                .frame(width: 80, alignment: .leading)
            Text(value)
                .font(.system(size: 10,
                              design: value.contains(".") || value.contains(":") ? .monospaced : .default))
                .foregroundStyle(Color.sgTextPrimary)
                .textSelection(.enabled)
            Spacer()
        }
        .padding(.horizontal, 14).padding(.vertical, 2)
    }
}

private struct SeverityTag: View {
    let severity: Severity
    var body: some View {
        Text(severity.rawValue.uppercased())
            .font(.system(size: 8, weight: .black))
            .foregroundStyle(color)
            .padding(.horizontal, 5).padding(.vertical, 3)
            .background(color.opacity(0.15))
            .clipShape(RoundedRectangle(cornerRadius: 4, style: .continuous))
    }
    private var color: Color {
        switch severity {
        case .high:   return Color.sgDanger
        case .medium: return Color.sgWarning
        case .low:    return Color.sgSafe
        }
    }
}

private struct StatPill: View {
    let label: String
    let value: String
    let color: Color
    var body: some View {
        VStack(spacing: 1) {
            Text(value).font(.system(size: 15, weight: .bold, design: .rounded)).foregroundStyle(color)
            Text(label).font(.system(size: 9, weight: .medium)).foregroundStyle(Color.sgTextTertiary)
        }
        .padding(.horizontal, 10).padding(.vertical, 5)
        .background(color.opacity(0.10))
        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
    }
}

// MARK: - NetworkIntelTab

enum NetworkIntelTab: String, CaseIterable {
    case all, alerts, dns, connections, artifacts, http

    var label: String {
        switch self {
        case .all:         return "All"
        case .alerts:      return "Alerts"
        case .dns:         return "DNS"
        case .connections: return "Connections"
        case .artifacts:   return "Artifacts"
        case .http:        return "HTTP/TLS"
        }
    }

    var symbol: String {
        switch self {
        case .all:         return "list.bullet"
        case .alerts:      return "exclamationmark.triangle.fill"
        case .dns:         return "globe"
        case .connections: return "arrow.left.arrow.right"
        case .artifacts:   return "doc.badge.gearshape"
        case .http:        return "lock.shield"
        }
    }
}

// MARK: - Tool color palette (file-scope so ToolCard, EventRow, and DetailPanel all share it)

private func toolPaletteColor(_ tool: PacketTool) -> Color {
    switch tool {
    case .tshark, .wireshark: return Color(red: 0.20, green: 0.55, blue: 1.0)
    case .tcpdump:            return Color(red: 0.10, green: 0.80, blue: 0.85)
    case .zeek:               return Color(red: 0.65, green: 0.35, blue: 1.0)
    case .suricata:           return Color(red: 1.0,  green: 0.27, blue: 0.27)
    case .ngrep:              return Color(red: 1.0,  green: 0.62, blue: 0.05)
    case .networkMiner:       return Color(red: 0.18, green: 0.85, blue: 0.55)
    }
}

// MARK: - Design tokens

private extension Color {
    static let sgBackground    = Color(red: 0.07, green: 0.08, blue: 0.12)
    static let sgSurface       = Color(red: 0.11, green: 0.13, blue: 0.19)
    static let sgSurfaceRaised = Color(red: 0.14, green: 0.17, blue: 0.24)
    static let sgBorder        = Color.white.opacity(0.07)
    static let sgDanger        = Color(red: 1.0,  green: 0.27, blue: 0.27)
    static let sgWarning       = Color(red: 1.0,  green: 0.62, blue: 0.05)
    static let sgSafe          = Color(red: 0.18, green: 0.85, blue: 0.55)
    static let sgBlue          = Color(red: 0.20, green: 0.55, blue: 1.0)
    static let sgPurple        = Color(red: 0.65, green: 0.35, blue: 1.0)
    static let sgTextPrimary   = Color.white
    static let sgTextSecondary = Color.white.opacity(0.55)
    static let sgTextTertiary  = Color.white.opacity(0.30)
}
