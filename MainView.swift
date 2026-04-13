import SwiftUI
import Charts

// MARK: - Design Tokens

private extension Color {
    // Base palette — deep navy, not flat black
    static let sgBackground    = Color(red: 0.07, green: 0.08, blue: 0.12)
    static let sgSurface       = Color(red: 0.11, green: 0.13, blue: 0.19)
    static let sgSurfaceRaised = Color(red: 0.14, green: 0.17, blue: 0.24)
    static let sgBorder        = Color.white.opacity(0.07)

    // Threat colors — vivid, unmistakable
    static let sgDanger   = Color(red: 1.0,  green: 0.27, blue: 0.27)  // hot red
    static let sgWarning  = Color(red: 1.0,  green: 0.62, blue: 0.05)  // amber
    static let sgSafe     = Color(red: 0.18, green: 0.85, blue: 0.55)  // emerald
    static let sgBlue     = Color(red: 0.20, green: 0.55, blue: 1.0)   // electric blue
    static let sgPurple   = Color(red: 0.65, green: 0.35, blue: 1.0)   // violet

    // Text
    static let sgTextPrimary   = Color.white
    static let sgTextSecondary = Color.white.opacity(0.55)
    static let sgTextTertiary  = Color.white.opacity(0.30)
}

// MARK: - MainView

// MARK: - MainTab (3.0)
private enum MainTab { case incidents, networkIntel }

struct MainView: View {
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var engine: PacketCaptureEngine
    @State private var scanPulse = false
    @State private var mainTab: MainTab = .incidents

    var body: some View {
        ZStack {
            // Deep navy canvas
            Color.sgBackground.ignoresSafeArea()

            HStack(spacing: 0) {
                sidebar
                    .frame(width: 280)

                Divider()
                    .overlay(Color.sgBorder)

                // Switch detail pane based on selected tab
                if mainTab == .networkIntel {
                    NetworkIntelView()
                        .environmentObject(engine)
                } else {
                    detail
                }
            }
        }
        .sheet(item: $model.selectedIncident) { incident in
            IncidentInspectorSheet(
                incident: incident,
                history: model.auditHistory(for: incident),
                onAcknowledge: { model.acknowledge(incident) },
                onSuppress:    { model.suppress(incident) },
                onClose:       { model.closeIncident() }
            )
        }
        .onAppear { withAnimation(.easeInOut(duration: 1.4).repeatForever(autoreverses: true)) { scanPulse = true } }
    }

    // MARK: - Sidebar

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Brand header
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 10) {
                    ZStack {
                        Circle()
                            .fill(Color.sgBlue.opacity(0.18))
                            .frame(width: 36, height: 36)
                        Image(systemName: "shield.lefthalf.filled")
                            .font(.system(size: 18, weight: .semibold))
                            .foregroundStyle(Color.sgBlue)
                    }
                    Text("Phantom")
                        .font(.system(size: 17, weight: .bold, design: .rounded))
                        .foregroundStyle(Color.sgTextPrimary)
                }

                Text("Endpoint security monitor")
                    .font(.system(size: 11, weight: .medium))
                    .foregroundStyle(Color.sgTextTertiary)
                    .padding(.leading, 46)
            }
            .padding(.horizontal, 20)
            .padding(.top, 24)
            .padding(.bottom, 20)

            // Status pills
            statusPanel
                .padding(.horizontal, 16)
                .padding(.bottom, 20)

            SGDivider()

            // 3.0 Tab switcher — Incidents vs Network Intel
            HStack(spacing: 6) {
                MainTabButton(
                    label: "Incidents",
                    symbol: "shield.lefthalf.filled",
                    isSelected: mainTab == .incidents,
                    badge: model.activeCount > 0 ? "\(model.activeCount)" : nil
                ) { mainTab = .incidents }

                MainTabButton(
                    label: "Net Intel",
                    symbol: "antenna.radiowaves.left.and.right",
                    isSelected: mainTab == .networkIntel,
                    badge: engine.highSeverityCount > 0 ? "\(engine.highSeverityCount)" : nil
                ) { mainTab = .networkIntel }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)

            SGDivider()

            // Filters (incidents tab only)
            if mainTab == .networkIntel {
                // Net Intel controls
                VStack(alignment: .leading, spacing: 10) {
                    SidebarSectionLabel("Capture")
                    Button {
                        Task { await engine.scan() }
                    } label: {
                        HStack(spacing: 8) {
                            Image(systemName: engine.isAnalyzing ? "rays" : "waveform.path.ecg")
                                .font(.system(size: 12, weight: .semibold))
                                .rotationEffect(.degrees(engine.isAnalyzing ? 360 : 0))
                                .animation(engine.isAnalyzing ? .linear(duration: 1.5).repeatForever(autoreverses: false) : .default, value: engine.isAnalyzing)
                            Text(engine.isAnalyzing ? "Analyzing…" : "Run Analysis")
                                .font(.system(size: 13, weight: .semibold))
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 10)
                        .background(Color.sgPurple)
                        .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
                        .foregroundStyle(.white)
                    }
                    .buttonStyle(.plain)
                    .disabled(engine.isAnalyzing)

                    SGActionButton(title: "Clear Events", icon: "trash", tint: Color.sgDanger.opacity(0.8)) {
                        engine.clearEvents()
                    }

                    if let date = engine.lastScanDate {
                        Text("Last analysis: \(date, format: .dateTime.hour().minute().second())")
                            .font(.system(size: 10, weight: .medium))
                            .foregroundStyle(Color.sgTextTertiary)
                    }
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 18)
            } else {

            // Filters
            VStack(alignment: .leading, spacing: 10) {
                SidebarSectionLabel("Filters")

                SGPicker(label: "Category", selection: $model.selectedFilter) {
                    ForEach(IncidentFilter.allCases, id: \.self) {
                        Text($0.title).tag($0)
                    }
                }
                SGPicker(label: "State", selection: $model.selectedState) {
                    ForEach(IncidentStateFilter.allCases, id: \.self) {
                        Text($0.title).tag($0)
                    }
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 18)

            SGDivider()

            // Actions
            VStack(spacing: 10) {
                // Primary scan button — animated
                Button {
                    model.rescanNow()
                } label: {
                    HStack(spacing: 8) {
                        ZStack {
                            Circle()
                                .fill(Color.sgBlue.opacity(scanPulse && model.isBusy ? 0.3 : 0))
                                .frame(width: 28, height: 28)
                                .scaleEffect(scanPulse && model.isBusy ? 1.4 : 1)
                            Image(systemName: model.isBusy ? "rays" : "arrow.clockwise")
                                .font(.system(size: 13, weight: .semibold))
                                .rotationEffect(.degrees(model.isBusy ? 360 : 0))
                                .animation(model.isBusy ? .linear(duration: 1.5).repeatForever(autoreverses: false) : .default, value: model.isBusy)
                        }
                        Text(model.isBusy ? "Scanning…" : "Scan Now")
                            .font(.system(size: 14, weight: .semibold))
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 12)
                    .background(
                        LinearGradient(
                            colors: [Color.sgBlue, Color(red: 0.10, green: 0.40, blue: 0.95)],
                            startPoint: .topLeading, endPoint: .bottomTrailing
                        )
                    )
                    .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
                    .shadow(color: Color.sgBlue.opacity(0.4), radius: 12, y: 4)
                }
                .buttonStyle(.plain)
                .foregroundStyle(.white)
                .disabled(model.isBusy)

                // Secondary actions
                SGActionButton(
                    title: model.status == .running ? "Stop Monitoring" : "Start Monitoring",
                    icon: model.status == .running ? "pause.fill" : "play.fill",
                    tint: model.status == .running ? Color.sgWarning : Color.sgSafe
                ) {
                    if model.status == .running { model.stopMonitoringLoop() }
                    else { model.startMonitoringLoop() }
                }

                SGActionButton(title: "Export JSON", icon: "square.and.arrow.up", tint: Color.sgTextSecondary) {
                    model.exportIncidents()
                }
                SGActionButton(title: "Export CSV", icon: "tablecells", tint: Color.sgTextSecondary) {
                    model.exportIncidentsAsCSV()
                }

                SGActionButton(title: "Clear All", icon: "trash", tint: Color.sgDanger.opacity(0.8)) {
                    model.clearIncidents()
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 18)
            } // end else (incidents tab)

            Spacer()

            if let error = model.lastError {
                HStack(spacing: 6) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .font(.caption)
                    Text(error)
                        .font(.caption)
                        .lineLimit(2)
                }
                .foregroundStyle(Color.sgDanger)
                .padding(12)
                .background(Color.sgDanger.opacity(0.10))
                .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
                .padding(.horizontal, 16)
                .padding(.bottom, 16)
            }
        }
        .background(Color.sgBackground)
    }

    // MARK: - Status Panel

    private var statusPanel: some View {
        VStack(alignment: .leading, spacing: 8) {
            // Risk score — the headline number
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                Text("\(model.riskScore)")
                    .font(.system(size: 48, weight: .black, design: .rounded))
                    .foregroundStyle(riskGradient)
                Text("/ 100")
                    .font(.system(size: 16, weight: .semibold))
                    .foregroundStyle(Color.sgTextTertiary)
                    .padding(.bottom, 4)
                Spacer()
                Text(model.riskLabel.uppercased())
                    .font(.system(size: 10, weight: .black))
                    .tracking(1.5)
                    .foregroundStyle(riskColor)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 5)
                    .background(riskColor.opacity(0.15))
                    .clipShape(Capsule())
            }

            // Status + health row
            HStack(spacing: 8) {
                StatusPill(
                    label: model.status.title,
                    color: model.status.tint,
                    dot: true
                )
                StatusPill(
                    label: model.health.displayStatus.title,
                    color: healthColor,
                    dot: true
                )
            }

            // Last scan timestamp
            HStack(spacing: 12) {
                Text(model.health.lastScanText)
                Text(model.health.lastEventText)
            }
            .font(.system(size: 10, weight: .medium))
            .foregroundStyle(Color.sgTextTertiary)
        }
        .padding(16)
        .background(Color.sgSurface)
        .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous).stroke(Color.sgBorder))
    }

    private var riskColor: Color {
        switch model.riskScore {
        case 0...19:   return Color.sgSafe
        case 20...49:  return Color.sgWarning
        case 50...79:  return Color.sgWarning
        default:       return Color.sgDanger
        }
    }

    private var riskGradient: LinearGradient {
        LinearGradient(colors: [riskColor, riskColor.opacity(0.7)],
                       startPoint: .leading, endPoint: .trailing)
    }

    private var healthColor: Color {
        switch model.health.displayStatus {
        case .healthy:  return Color.sgSafe
        case .degraded: return Color.sgWarning
        case .failed:   return Color.sgDanger
        case .offline:  return Color.sgTextSecondary
        }
    }

    // MARK: - Detail

    private var detail: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 28) {
                metricRow
                if let top = model.topIncident { heroCard(for: top) }
                incidentsSection
                timelineSection
                if model.scanHistory.count > 1 { riskHistorySection }
            }
            .padding(.horizontal, 28)
            .padding(.vertical, 28)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(Color.sgBackground)
    }

    // MARK: - Risk History Chart

    private var riskHistorySection: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Image(systemName: "chart.line.uptrend.xyaxis")
                    .foregroundStyle(Color.sgBlue)
                Text("Risk Trend")
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundStyle(Color.sgTextPrimary)
                Spacer()
                Text("\(model.scanHistory.count) scans")
                    .font(.system(size: 11, weight: .medium))
                    .foregroundStyle(Color.sgTextTertiary)
            }

            // Show most-recent 60 records (≈1 hour at 60 s intervals)
            let window = Array(model.scanHistory.prefix(60).reversed())

            Chart(window) { record in
                AreaMark(
                    x: .value("Time", record.timestamp),
                    y: .value("Risk", record.riskScore)
                )
                .foregroundStyle(
                    LinearGradient(
                        colors: [Color.sgBlue.opacity(0.35), Color.sgBlue.opacity(0.02)],
                        startPoint: .top, endPoint: .bottom
                    )
                )
                LineMark(
                    x: .value("Time", record.timestamp),
                    y: .value("Risk", record.riskScore)
                )
                .foregroundStyle(Color.sgBlue)
                .lineStyle(StrokeStyle(lineWidth: 2))
                .interpolationMethod(.catmullRom)
            }
            .chartYScale(domain: 0...100)
            .chartYAxis {
                AxisMarks(values: [0, 25, 50, 75, 100]) { value in
                    AxisGridLine().foregroundStyle(Color.sgBorder)
                    AxisValueLabel()
                        .foregroundStyle(Color.sgTextTertiary)
                        .font(.system(size: 10))
                }
            }
            .chartXAxis {
                AxisMarks(preset: .automatic, values: .automatic(desiredCount: 4)) { _ in
                    AxisGridLine().foregroundStyle(Color.sgBorder)
                    AxisValueLabel(format: .dateTime.hour().minute())
                        .foregroundStyle(Color.sgTextTertiary)
                        .font(.system(size: 10))
                }
            }
            .frame(height: 140)

            // Summary stats row beneath the chart
            HStack(spacing: 20) {
                riskStatPill(
                    label: "Current",
                    value: "\(model.riskScore)",
                    color: riskColor(for: model.riskScore)
                )
                if let peak = window.map({ $0.riskScore }).max() {
                    riskStatPill(label: "Peak", value: "\(peak)", color: Color.sgDanger)
                }
                if let avg = window.isEmpty ? nil :
                    Optional(window.map { Double($0.riskScore) }.reduce(0, +) / Double(window.count)) {
                    riskStatPill(label: "Avg", value: String(format: "%.0f", avg), color: Color.sgWarning)
                }
                Spacer()
            }
        }
        .padding(20)
        .background(Color.sgSurface)
        .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous).stroke(Color.sgBorder))
    }

    private func riskStatPill(label: String, value: String, color: Color) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label)
                .font(.system(size: 10, weight: .medium))
                .foregroundStyle(Color.sgTextTertiary)
            Text(value)
                .font(.system(size: 20, weight: .black, design: .rounded))
                .foregroundStyle(color)
        }
    }

    private func riskColor(for score: Int) -> Color {
        switch score {
        case 0...19:  return Color.sgSafe
        case 20...49: return Color.sgWarning
        case 50...79: return Color.sgWarning
        default:      return Color.sgDanger
        }
    }

    // MARK: - Metric Row (CleanMyMac-style bold cards)

    private var metricRow: some View {
        LazyVGrid(
            columns: Array(repeating: GridItem(.flexible(), spacing: 14), count: 5),
            spacing: 14
        ) {
            BoldMetricCard(
                value: "\(model.riskScore)",
                label: "Risk Score",
                sublabel: model.riskLabel,
                icon: "gauge.with.dots.needle.67percent",
                tint: riskColor,
                gradient: [riskColor.opacity(0.25), riskColor.opacity(0.05)]
            )
            BoldMetricCard(
                value: "\(model.activeCount)",
                label: "Active",
                sublabel: "open incidents",
                icon: "exclamationmark.shield.fill",
                tint: model.activeCount > 0 ? Color.sgDanger : Color.sgSafe,
                gradient: [Color.sgDanger.opacity(model.activeCount > 0 ? 0.20 : 0.05),
                           Color.sgDanger.opacity(0.02)]
            )
            BoldMetricCard(
                value: "\(model.resolvedCount)",
                label: "Resolved",
                sublabel: "cleared findings",
                icon: "checkmark.shield.fill",
                tint: Color.sgSafe,
                gradient: [Color.sgSafe.opacity(0.15), Color.sgSafe.opacity(0.02)]
            )
            BoldMetricCard(
                value: "\(model.launches.count)",
                label: "Processes",
                sublabel: "observed",
                icon: "cpu",
                tint: Color.sgBlue,
                gradient: [Color.sgBlue.opacity(0.15), Color.sgBlue.opacity(0.02)]
            )
            BoldMetricCard(
                value: "\(model.incidents.count)",
                label: "Findings",
                sublabel: "total",
                icon: "eye.fill",
                tint: Color.sgPurple,
                gradient: [Color.sgPurple.opacity(0.15), Color.sgPurple.opacity(0.02)]
            )
        }
    }

    // MARK: - Hero Card

    private func heroCard(for incident: Incident) -> some View {
        Button { model.openIncident(incident) } label: {
            ZStack(alignment: .topTrailing) {
                // Background gradient mesh
                LinearGradient(
                    colors: [
                        incident.severity.tint.opacity(0.28),
                        incident.severity.tint.opacity(0.06),
                        Color.sgSurface
                    ],
                    startPoint: .topLeading,
                    endPoint: .bottomTrailing
                )

                // Decorative shield watermark
                Image(systemName: "exclamationmark.shield.fill")
                    .font(.system(size: 120, weight: .black))
                    .foregroundStyle(incident.severity.tint.opacity(0.06))
                    .offset(x: 30, y: -20)

                VStack(alignment: .leading, spacing: 16) {
                    HStack(alignment: .top) {
                        VStack(alignment: .leading, spacing: 6) {
                            HStack(spacing: 6) {
                                Image(systemName: "exclamationmark.shield.fill")
                                    .font(.caption.weight(.bold))
                                    .foregroundStyle(incident.severity.tint)
                                Text("TOP THREAT")
                                    .font(.system(size: 10, weight: .black))
                                    .tracking(2)
                                    .foregroundStyle(incident.severity.tint)
                            }

                            Text(incident.name)
                                .font(.system(size: 22, weight: .black, design: .rounded))
                                .foregroundStyle(Color.sgTextPrimary)
                                .lineLimit(2)
                                .multilineTextAlignment(.leading)
                        }
                        Spacer()
                        VStack(alignment: .trailing, spacing: 6) {
                            SGBadge(text: incident.severity.title.uppercased(),
                                    tint: incident.severity.tint, bold: true)
                            SGBadge(text: incident.trust.title, tint: incident.trust.tint)
                        }
                    }

                    if let detail = incident.detail {
                        Text(detail)
                            .font(.system(size: 13))
                            .foregroundStyle(Color.sgTextSecondary)
                            .lineLimit(2)
                    }

                    HStack(spacing: 8) {
                        SGBadge(text: incident.source.title, tint: Color.sgBlue)
                        SGBadge(text: incident.confidence.title, tint: incident.confidence.tint)
                        Spacer()
                        Text("Risk \(incident.score)")
                            .font(.system(size: 13, weight: .black, design: .rounded))
                            .foregroundStyle(incident.severity.tint)
                    }
                }
                .padding(24)
            }
        }
        .buttonStyle(.plain)
        .frame(maxWidth: .infinity, minHeight: 160)
        .clipShape(RoundedRectangle(cornerRadius: 24, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 24, style: .continuous)
                .stroke(incident.severity.tint.opacity(0.25), lineWidth: 1)
        )
        .shadow(color: incident.severity.tint.opacity(0.15), radius: 20, y: 8)
    }

    // MARK: - Incidents Section

    private var incidentsSection: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Text("Incidents")
                    .font(.system(size: 20, weight: .black, design: .rounded))
                    .foregroundStyle(Color.sgTextPrimary)
                if model.activeCount > 0 {
                    Text("\(model.activeCount)")
                        .font(.system(size: 12, weight: .black))
                        .foregroundStyle(.white)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 3)
                        .background(Color.sgDanger)
                        .clipShape(Capsule())
                }
                Spacer()
            }

            if model.filteredIncidents.isEmpty {
                emptyState(icon: "checkmark.shield.fill",
                           title: "All clear",
                           subtitle: "No incidents match the current filter.",
                           tint: Color.sgSafe)
            } else {
                LazyVStack(spacing: 10) {
                    ForEach(Array(model.filteredIncidents.prefix(25).enumerated()), id: \.offset) { _, incident in
                        SGIncidentCard(incident: incident) {
                            model.openIncident(incident)
                        }
                    }
                }
            }
        }
    }

    // MARK: - Timeline Section

    private var timelineSection: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Timeline")
                .font(.system(size: 20, weight: .black, design: .rounded))
                .foregroundStyle(Color.sgTextPrimary)

            if model.timeline.isEmpty {
                emptyState(icon: "clock.fill",
                           title: "No events yet",
                           subtitle: "Events appear here as scans complete.",
                           tint: Color.sgBlue)
            } else {
                LazyVStack(spacing: 8) {
                    ForEach(Array(model.timeline.prefix(12).enumerated()), id: \.offset) { _, event in
                        HStack(alignment: .center, spacing: 14) {
                            ZStack {
                                Circle()
                                    .fill(Color.sgBlue.opacity(0.15))
                                    .frame(width: 34, height: 34)
                                Image(systemName: event.symbol)
                                    .font(.system(size: 14, weight: .semibold))
                                    .foregroundStyle(Color.sgBlue)
                            }

                            VStack(alignment: .leading, spacing: 2) {
                                Text(event.title)
                                    .font(.system(size: 13, weight: .semibold))
                                    .foregroundStyle(Color.sgTextPrimary)
                                if let detail = event.detail {
                                    Text(detail)
                                        .font(.system(size: 11))
                                        .foregroundStyle(Color.sgTextSecondary)
                                        .lineLimit(1)
                                }
                            }

                            Spacer()

                            Text(event.timestamp.formatted(date: .omitted, time: .shortened))
                                .font(.system(size: 11, weight: .medium).monospacedDigit())
                                .foregroundStyle(Color.sgTextTertiary)
                        }
                        .padding(.horizontal, 16)
                        .padding(.vertical, 12)
                        .background(Color.sgSurface)
                        .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
                        .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).stroke(Color.sgBorder))
                    }
                }
            }
        }
    }

    private func emptyState(icon: String, title: String, subtitle: String, tint: Color) -> some View {
        HStack(spacing: 16) {
            ZStack {
                Circle().fill(tint.opacity(0.12)).frame(width: 48, height: 48)
                Image(systemName: icon)
                    .font(.system(size: 20, weight: .semibold))
                    .foregroundStyle(tint)
            }
            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(.system(size: 14, weight: .bold))
                    .foregroundStyle(Color.sgTextPrimary)
                Text(subtitle)
                    .font(.system(size: 12))
                    .foregroundStyle(Color.sgTextSecondary)
            }
            Spacer()
        }
        .padding(18)
        .background(Color.sgSurface)
        .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous).stroke(Color.sgBorder))
    }

    // MARK: - Shared Components

    private struct BoldMetricCard: View {
        let value: String
        let label: String
        let sublabel: String
        let icon: String
        let tint: Color
        let gradient: [Color]

        var body: some View {
            VStack(alignment: .leading, spacing: 0) {
                HStack {
                    ZStack {
                        Circle().fill(tint.opacity(0.18)).frame(width: 32, height: 32)
                        Image(systemName: icon)
                            .font(.system(size: 14, weight: .semibold))
                            .foregroundStyle(tint)
                    }
                    Spacer()
                }
                .padding(.bottom, 14)

                Text(value)
                    .font(.system(size: 36, weight: .black, design: .rounded))
                    .foregroundStyle(Color.sgTextPrimary)
                    .minimumScaleFactor(0.6)
                    .lineLimit(1)

                Text(label)
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(Color.sgTextSecondary)
                    .padding(.top, 2)

                Text(sublabel)
                    .font(.system(size: 10, weight: .medium))
                    .foregroundStyle(Color.sgTextTertiary)
                    .padding(.top, 1)
            }
            .padding(18)
            .frame(maxWidth: .infinity, minHeight: 140, alignment: .topLeading)
            .background(
                ZStack {
                    Color.sgSurface
                    LinearGradient(colors: gradient, startPoint: .topLeading, endPoint: .bottomTrailing)
                }
            )
            .clipShape(RoundedRectangle(cornerRadius: 20, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 20, style: .continuous).stroke(Color.sgBorder))
        }
    }

    private struct SGIncidentCard: View {
        let incident: Incident
        let onOpen: () -> Void

        var body: some View {
            Button(action: onOpen) {
                HStack(alignment: .center, spacing: 14) {
                    // Severity indicator bar
                    RoundedRectangle(cornerRadius: 3)
                        .fill(incident.severity.tint)
                        .frame(width: 4, height: 46)

                    // Source icon
                    ZStack {
                        Circle()
                            .fill(incident.severity.tint.opacity(0.12))
                            .frame(width: 38, height: 38)
                        Image(systemName: incident.source.symbol)
                            .font(.system(size: 16, weight: .semibold))
                            .foregroundStyle(incident.severity.tint)
                    }

                    VStack(alignment: .leading, spacing: 4) {
                        Text(incident.name)
                            .font(.system(size: 13, weight: .bold))
                            .foregroundStyle(Color.sgTextPrimary)
                            .lineLimit(1)

                        if let detail = incident.detail {
                            Text(detail)
                                .font(.system(size: 11))
                                .foregroundStyle(Color.sgTextSecondary)
                                .lineLimit(1)
                        }

                        HStack(spacing: 6) {
                            SGBadge(text: incident.source.title, tint: .sgBlue)
                            SGBadge(text: incident.trust.title, tint: incident.trust.tint)
                            SGBadge(text: incident.confidence.title, tint: incident.confidence.tint)
                        }
                    }

                    Spacer()

                    VStack(alignment: .trailing, spacing: 6) {
                        SGBadge(text: incident.severity.title.uppercased(),
                                tint: incident.severity.tint, bold: true)
                        Text("Risk \(incident.score)")
                            .font(.system(size: 11, weight: .black, design: .rounded))
                            .foregroundStyle(incident.severity.tint)
                    }
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 12)
                .background(Color.sgSurface)
                .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
                .overlay(
                    RoundedRectangle(cornerRadius: 16, style: .continuous)
                        .stroke(Color.sgBorder)
                )
            }
            .buttonStyle(.plain)
        }
    }

    private struct StatusPill: View {
        let label: String
        let color: Color
        let dot: Bool

        var body: some View {
            HStack(spacing: 5) {
                if dot {
                    Circle().fill(color).frame(width: 6, height: 6)
                }
                Text(label)
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(color)
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
            .background(color.opacity(0.12))
            .clipShape(Capsule())
        }
    }

    private struct SGActionButton: View {
        let title: String
        let icon: String
        let tint: Color
        let action: () -> Void

        var body: some View {
            Button(action: action) {
                HStack(spacing: 8) {
                    Image(systemName: icon)
                        .font(.system(size: 12, weight: .semibold))
                    Text(title)
                        .font(.system(size: 13, weight: .semibold))
                    Spacer()
                }
                .foregroundStyle(tint)
                .padding(.horizontal, 14)
                .padding(.vertical, 10)
                .background(tint.opacity(0.10))
                .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).stroke(tint.opacity(0.15)))
            }
            .buttonStyle(.plain)
        }
    }

    private struct SidebarSectionLabel: View {
        let text: String
        init(_ text: String) { self.text = text }
        var body: some View {
            Text(text.uppercased())
                .font(.system(size: 9, weight: .black))
                .tracking(1.8)
                .foregroundStyle(Color.sgTextTertiary)
                .padding(.bottom, 2)
        }
    }

    private struct SGPicker<SelectionValue: Hashable, Content: View>: View {
        let label: String
        @Binding var selection: SelectionValue
        @ViewBuilder let content: () -> Content

        var body: some View {
            Picker(label, selection: $selection, content: content)
                .labelsHidden()
                .pickerStyle(.menu)
                .font(.system(size: 12, weight: .medium))
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private struct SGBadge: View {
        let text: String
        let tint: Color
        var bold: Bool = false

        var body: some View {
            Text(text)
                .font(.system(size: 10, weight: bold ? .black : .semibold))
                .tracking(bold ? 0.5 : 0)
                .foregroundStyle(tint)
                .padding(.horizontal, 7)
                .padding(.vertical, 3)
                .background(tint.opacity(0.15))
                .clipShape(Capsule())
        }
    }

    private struct SGDivider: View {
        var body: some View {
            Color.sgBorder.frame(height: 1)
        }
    }

    // MARK: - Inspector Sheet

    private struct IncidentInspectorSheet: View {
        let incident: Incident
        let history: [AuditEvent]
        let onAcknowledge: () -> Void
        let onSuppress: () -> Void
        let onClose: () -> Void

        var body: some View {
            ZStack {
                Color.sgBackground.ignoresSafeArea()

                VStack(spacing: 0) {
                    // Sheet header
                    HStack(alignment: .top, spacing: 16) {
                        ZStack {
                            RoundedRectangle(cornerRadius: 14, style: .continuous)
                                .fill(incident.severity.tint.opacity(0.15))
                                .frame(width: 52, height: 52)
                            Image(systemName: incident.source.symbol)
                                .font(.system(size: 22, weight: .semibold))
                                .foregroundStyle(incident.severity.tint)
                        }

                        VStack(alignment: .leading, spacing: 6) {
                            Text(incident.name)
                                .font(.system(size: 18, weight: .black, design: .rounded))
                                .foregroundStyle(Color.sgTextPrimary)
                                .lineLimit(2)

                            HStack(spacing: 6) {
                                SGBadge(text: incident.severity.title.uppercased(),
                                        tint: incident.severity.tint, bold: true)
                                SGBadge(text: incident.status.title, tint: incident.status.tint)
                                SGBadge(text: incident.trust.title, tint: incident.trust.tint)
                                SGBadge(text: incident.source.title, tint: Color.sgBlue)
                            }
                        }
                        Spacer()
                    }
                    .padding(24)
                    .background(
                        LinearGradient(
                            colors: [incident.severity.tint.opacity(0.12), Color.sgBackground],
                            startPoint: .top, endPoint: .bottom
                        )
                    )

                    Color.sgBorder.frame(height: 1)

                    ScrollView {
                        VStack(alignment: .leading, spacing: 20) {
                            if let detail = incident.detail, !detail.isEmpty {
                                SheetSection("Detail") {
                                    Text(detail)
                                        .font(.system(size: 13))
                                        .foregroundStyle(Color.sgTextSecondary)
                                        .textSelection(.enabled)
                                }
                            }

                            SheetSection("Summary") {
                                VStack(spacing: 6) {
                                    SheetRow("Risk Score",   value: "\(incident.score)")
                                    SheetRow("Occurrences",  value: "\(incident.occurrenceCount)")
                                    SheetRow("First Seen",   value: incident.firstSeen.formatted(date: .abbreviated, time: .shortened))
                                    SheetRow("Last Seen",    value: incident.lastSeen.formatted(date: .abbreviated, time: .shortened))
                                    if let technique = incident.technique {
                                        SheetRow("MITRE", value: "\(technique.rawValue) — \(technique.title)")
                                    }
                                }
                            }

                            SheetSection("Trust Reasoning") {
                                Text(incident.trustSummary)
                                    .font(.system(size: 13))
                                    .foregroundStyle(Color.sgTextSecondary)
                                    .textSelection(.enabled)
                            }

                            SheetSection("Recommended Action") {
                                Text(incident.recommendedAction)
                                    .font(.system(size: 13))
                                    .foregroundStyle(Color.sgTextSecondary)
                                    .textSelection(.enabled)
                            }

                            if !incident.evidence.isEmpty {
                                SheetSection("Evidence") {
                                    VStack(spacing: 8) {
                                        ForEach(incident.evidence) { item in
                                            VStack(alignment: .leading, spacing: 3) {
                                                Text(item.label)
                                                    .font(.system(size: 10, weight: .black))
                                                    .tracking(0.8)
                                                    .foregroundStyle(Color.sgTextTertiary)
                                                Text(item.value)
                                                    .font(.system(size: 12, design: .monospaced))
                                                    .foregroundStyle(Color.sgTextPrimary)
                                                    .textSelection(.enabled)
                                            }
                                            .frame(maxWidth: .infinity, alignment: .leading)
                                            .padding(12)
                                            .background(Color.sgSurface)
                                            .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
                                        }
                                    }
                                }
                            }

                            if let raw = incident.rawDetail, !raw.isEmpty {
                                SheetSection("Raw Detail") {
                                    ScrollView(.horizontal) {
                                        Text(raw)
                                            .font(.system(size: 11, design: .monospaced))
                                            .foregroundStyle(Color.sgTextSecondary)
                                            .textSelection(.enabled)
                                            .padding(12)
                                    }
                                    .background(Color.sgSurface)
                                    .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
                                    .frame(minHeight: 80)
                                }
                            }

                            if !history.isEmpty {
                                SheetSection("Audit History") {
                                    VStack(spacing: 6) {
                                        ForEach(history.prefix(10)) { event in
                                            HStack(alignment: .top, spacing: 10) {
                                                Circle()
                                                    .fill(event.action.tint)
                                                    .frame(width: 7, height: 7)
                                                    .padding(.top, 4)
                                                VStack(alignment: .leading, spacing: 2) {
                                                    Text(event.action.title)
                                                        .font(.system(size: 12, weight: .semibold))
                                                        .foregroundStyle(Color.sgTextPrimary)
                                                    Text(event.details)
                                                        .font(.system(size: 11))
                                                        .foregroundStyle(Color.sgTextSecondary)
                                                    Text(event.timestamp.formatted(date: .abbreviated, time: .shortened))
                                                        .font(.system(size: 10).monospacedDigit())
                                                        .foregroundStyle(Color.sgTextTertiary)
                                                }
                                                Spacer()
                                            }
                                            .padding(10)
                                            .background(Color.sgSurface)
                                            .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
                                        }
                                    }
                                }
                            }
                        }
                        .padding(24)
                    }

                    // Action bar
                    Color.sgBorder.frame(height: 1)
                    HStack(spacing: 12) {
                        Button("Acknowledge") { onAcknowledge() }
                            .buttonStyle(SGPrimaryButtonStyle(tint: Color.sgBlue))

                        Button("Suppress") { onSuppress() }
                            .buttonStyle(SGPrimaryButtonStyle(tint: Color.sgWarning))

                        Spacer()

                        Button("Close") { onClose() }
                            .keyboardShortcut(.cancelAction)
                            .buttonStyle(SGGhostButtonStyle())
                    }
                    .padding(20)
                    .background(Color.sgBackground)
                }
            }
            .frame(minWidth: 760, minHeight: 580)
        }

        private struct SheetSection<Content: View>: View {
            let title: String
            @ViewBuilder let content: () -> Content
            init(_ title: String, @ViewBuilder content: @escaping () -> Content) {
                self.title = title; self.content = content
            }
            var body: some View {
                VStack(alignment: .leading, spacing: 10) {
                    Text(title.uppercased())
                        .font(.system(size: 9, weight: .black))
                        .tracking(1.8)
                        .foregroundStyle(Color.sgTextTertiary)
                    content()
                }
            }
        }

        private struct SheetRow: View {
            let label: String
            let value: String
            init(_ label: String, value: String) { self.label = label; self.value = value }
            var body: some View {
                HStack {
                    Text(label)
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundStyle(Color.sgTextSecondary)
                        .frame(width: 110, alignment: .leading)
                    Text(value)
                        .font(.system(size: 12))
                        .foregroundStyle(Color.sgTextPrimary)
                        .textSelection(.enabled)
                    Spacer()
                }
                .padding(.vertical, 6)
            }
        }
    }
}

// MARK: - 3.0 Tab Button

private struct MainTabButton: View {
    let label: String
    let symbol: String
    let isSelected: Bool
    let badge: String?
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 5) {
                Image(systemName: symbol)
                    .font(.system(size: 11, weight: .semibold))
                Text(label)
                    .font(.system(size: 12, weight: .semibold))
                if let b = badge {
                    Text(b)
                        .font(.system(size: 9, weight: .bold))
                        .padding(.horizontal, 5)
                        .padding(.vertical, 2)
                        .background(isSelected ? Color.sgBlue : Color.sgDanger)
                        .clipShape(Capsule())
                        .foregroundStyle(.white)
                }
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 8)
            .foregroundStyle(isSelected ? Color.sgTextPrimary : Color.sgTextSecondary)
            .background(isSelected ? Color.sgSurfaceRaised : Color.sgSurface)
            .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .stroke(isSelected ? Color.sgBlue.opacity(0.4) : Color.sgBorder)
            )
        }
        .buttonStyle(.plain)
    }
}

// MARK: - Button Styles

struct SGPrimaryButtonStyle: ButtonStyle {
    let tint: Color
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 13, weight: .bold))
            .foregroundStyle(.white)
            .padding(.horizontal, 18)
            .padding(.vertical, 10)
            .background(tint.opacity(configuration.isPressed ? 0.7 : 1))
            .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
    }
}

struct SGGhostButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 13, weight: .semibold))
            .foregroundStyle(Color.sgTextSecondary)
            .padding(.horizontal, 18)
            .padding(.vertical, 10)
            .background(Color.sgSurface.opacity(configuration.isPressed ? 0.5 : 1))
            .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).stroke(Color.sgBorder))
    }
}
