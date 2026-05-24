// PhantomAIAnalystView.swift
// Standalone AI cybersecurity analyst — always accessible from the main nav.
// No incident required. Powered entirely on-device by gpt2_cyber5 via Core ML.

import Combine
import SwiftUI

// Design tokens live in MainView.swift (module-level extension Color).

// MARK: - Starter suggestions

private struct Suggestion: Identifiable {
    let id    = UUID()
    let label: String
    let icon:  String
    let tint:  Color
}

private let starterSuggestions: [Suggestion] = [
    Suggestion(label: "How does ransomware work?",        icon: "lock.trianglebadge.exclamationmark.fill", tint: .sgDanger),
    Suggestion(label: "Explain SQL injection",            icon: "chevron.left.forwardslash.chevron.right",  tint: .sgBlue),
    Suggestion(label: "What is lateral movement?",        icon: "arrow.left.arrow.right",                   tint: .sgWarning),
    Suggestion(label: "How does privilege escalation work?", icon: "arrow.up.circle.fill",                  tint: .sgPurple),
    Suggestion(label: "What is a C2 server?",             icon: "antenna.radiowaves.left.and.right",        tint: .sgSafe),
    Suggestion(label: "Explain the cyber kill chain",     icon: "link.circle.fill",                         tint: .sgBlue),
    Suggestion(label: "How does phishing work?",          icon: "envelope.badge.shield.half.filled.fill",   tint: .sgWarning),
    Suggestion(label: "What is credential dumping?",      icon: "key.fill",                                 tint: .sgDanger),
    Suggestion(label: "Explain living off the land",      icon: "leaf.fill",                                tint: .sgSafe),
    Suggestion(label: "How does a supply chain attack work?", icon: "shippingbox.fill",                     tint: .sgPurple),
]

// MARK: - PhantomAIAnalystView

struct PhantomAIAnalystView: View {
    @ObservedObject private var ai    = PhantomAI.shared
    @ObservedObject private var agent = PhantomAIAgent.shared
    @EnvironmentObject private var appModel: AppModel
    @EnvironmentObject private var engine: PacketCaptureEngine

    @State private var inputText    = ""
    @State private var cursorOn     = true
    @FocusState private var focused: Bool

    private let cursorTimer = Timer.publish(every: 0.5, on: .main, in: .common).autoconnect()

    var body: some View {
        ZStack {
            Color.sgBackground.ignoresSafeArea()

            VStack(spacing: 0) {
                analystHeader
                Color.sgBorder.frame(height: 1)

                if ai.analystMessages.isEmpty {
                    welcomeScreen
                } else {
                    messageList
                }

                Color.sgBorder.frame(height: 1)
                inputBar
            }
        }
        .onChange(of: agent.pendingAnalystSeed?.id) { newID in
            guard let seed = agent.pendingAnalystSeed, newID != nil else { return }
            agent.pendingAnalystSeed = nil
            ai.setSystemContext(incidents: appModel.incidents, health: appModel.health)
            Task { await ai.seedFromAgent(insight: seed) }
        }
        .onReceive(cursorTimer) { _ in
            if ai.isAnalystGenerating { cursorOn.toggle() }
            else { cursorOn = false }
        }
        .onAppear {
            // Inject live system telemetry so the AI can answer
            // "check my system" / "any active threats?" with real data.
            ai.setSystemContext(
                incidents: appModel.incidents,
                health:    appModel.health
            )
        }
    }

    // MARK: - Header

    private var analystHeader: some View {
        HStack(spacing: 14) {
            // Animated AI orb
            ZStack {
                Circle()
                    .fill(
                        RadialGradient(
                            colors: [Color.sgPurple.opacity(ai.isAnalystGenerating ? 0.8 : 0.5),
                                     Color.sgBlue.opacity(0.2), Color.clear],
                            center: .center, startRadius: 0, endRadius: 24
                        )
                    )
                    .frame(width: 48, height: 48)
                    .scaleEffect(ai.isAnalystGenerating ? 1.1 : 1.0)
                    .animation(
                        ai.isAnalystGenerating
                            ? .easeInOut(duration: 0.7).repeatForever(autoreverses: true)
                            : .default,
                        value: ai.isAnalystGenerating
                    )

                Image(systemName: "cpu.fill")
                    .font(.system(size: 20, weight: .semibold))
                    .foregroundStyle(
                        LinearGradient(
                            colors: [Color.sgPurple, Color.sgBlue],
                            startPoint: .topLeading, endPoint: .bottomTrailing
                        )
                    )
            }

            VStack(alignment: .leading, spacing: 5) {
                HStack(spacing: 8) {
                    Text("Phantom AI Analyst")
                        .font(.system(size: 16, weight: .black, design: .rounded))
                        .foregroundStyle(Color.sgTextPrimary)

                    if ai.isAnalystGenerating {
                        thinkingBadge
                    } else if ai.isReady {
                        readyBadge
                    } else if ai.loadError != nil {
                        errorBadge
                    } else {
                        loadingBadge
                    }
                }

                // Security strip
                HStack(spacing: 6) {
                    miniChip(icon: "lock.fill",       label: "Air-gapped")
                    miniChip(icon: "cpu",             label: "On-device")
                    miniChip(icon: "eye.slash.fill",  label: "No logs")
                    miniChip(icon: "memorychip.fill", label: "Memory-only")
                }
            }

            Spacer()

            // Message count + clear
            if !ai.analystMessages.isEmpty {
                VStack(alignment: .trailing, spacing: 4) {
                    Text("\(ai.analystMessages.count / 2) exchange\(ai.analystMessages.count / 2 == 1 ? "" : "s")")
                        .font(.system(size: 10, weight: .medium))
                        .foregroundStyle(Color.sgTextTertiary)

                    Button {
                        withAnimation(.easeOut(duration: 0.2)) {
                            ai.clearAnalystSession()
                        }
                    } label: {
                        HStack(spacing: 4) {
                            Image(systemName: "trash")
                                .font(.system(size: 9, weight: .bold))
                            Text("Clear")
                                .font(.system(size: 10, weight: .semibold))
                        }
                        .foregroundStyle(Color.sgDanger.opacity(0.8))
                        .padding(.horizontal, 8)
                        .padding(.vertical, 4)
                        .background(Color.sgDanger.opacity(0.08))
                        .clipShape(Capsule())
                        .overlay(Capsule().stroke(Color.sgDanger.opacity(0.15)))
                    }
                    .buttonStyle(.plain)
                }
            }
        }
        .padding(.horizontal, 28)
        .padding(.vertical, 16)
        .background(
            LinearGradient(
                colors: [Color.sgPurple.opacity(0.10), Color.sgBackground],
                startPoint: .top, endPoint: .bottom
            )
        )
    }

    // MARK: - Welcome / agent briefing screen

    private var welcomeScreen: some View {
        ScrollView {
            VStack(spacing: 24) {

                // ── Agent briefing card ───────────────────────────────────
                agentBriefingCard
                    .padding(.top, 32)

                // Model status card
                if let err = ai.loadError {
                    modelErrorCard(err)
                } else if !ai.isReady {
                    modelLoadingCard
                }

                // ── Dynamic suggestion chips ──────────────────────────────
                VStack(alignment: .leading, spacing: 12) {
                    Text("ASK ME")
                        .font(.system(size: 9, weight: .black))
                        .tracking(1.8)
                        .foregroundStyle(Color.sgTextTertiary)

                    LazyVGrid(
                        columns: [GridItem(.flexible(), spacing: 10), GridItem(.flexible(), spacing: 10)],
                        spacing: 10
                    ) {
                        ForEach(dynamicSuggestions) { s in
                            SuggestionCard(suggestion: s, isDisabled: !ai.isReady || ai.isAnalystGenerating) {
                                Task { await ai.analystChat(message: s.label) }
                            }
                        }
                    }
                }
                .frame(maxWidth: 640)
                .padding(.bottom, 32)
            }
            .frame(maxWidth: .infinity)
            .padding(.horizontal, 36)
        }
        .background(Color.sgBackground)
    }

    // MARK: - Agent briefing card

    private var agentBriefingCard: some View {
        VStack(alignment: .leading, spacing: 0) {
            // ── Card header ───────────────────────────────────────────────
            HStack(spacing: 12) {
                ZStack {
                    Circle()
                        .fill(agent.isAnalyzing
                              ? Color.sgPurple.opacity(0.25)
                              : Color.sgBlue.opacity(0.15))
                        .frame(width: 40, height: 40)
                        .scaleEffect(agent.isAnalyzing ? 1.1 : 1)
                        .animation(
                            agent.isAnalyzing
                                ? .easeInOut(duration: 0.8).repeatForever(autoreverses: true)
                                : .default,
                            value: agent.isAnalyzing
                        )
                    Image(systemName: "brain.head.profile")
                        .font(.system(size: 17, weight: .semibold))
                        .foregroundStyle(agent.isAnalyzing ? Color.sgPurple : Color.sgBlue)
                }

                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 6) {
                        Text("PHANTOM AI AGENT")
                            .font(.system(size: 10, weight: .black))
                            .tracking(1.4)
                            .foregroundStyle(Color.sgTextSecondary)
                        Text("LVL \(agent.agentLevel)")
                            .font(.system(size: 9, weight: .black, design: .rounded))
                            .foregroundStyle(agentLevelColor)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(agentLevelColor.opacity(0.15))
                            .clipShape(Capsule())
                    }

                    if agent.isAnalyzing && !agent.analysisStatus.isEmpty {
                        HStack(spacing: 5) {
                            ProgressView().controlSize(.mini).tint(Color.sgPurple)
                            Text(agent.analysisStatus)
                                .font(.system(size: 10))
                                .foregroundStyle(Color.sgPurple.opacity(0.85))
                                .lineLimit(1)
                                .truncationMode(.tail)
                                .animation(.easeInOut(duration: 0.2), value: agent.analysisStatus)
                        }
                    } else if let at = agent.lastAnalysisAt {
                        Text("Last scan: \(at, format: .relative(presentation: .named, unitsStyle: .abbreviated))")
                            .font(.system(size: 10))
                            .foregroundStyle(Color.sgTextTertiary)
                    } else {
                        Text("Initialising…")
                            .font(.system(size: 10))
                            .foregroundStyle(Color.sgTextTertiary)
                    }
                }

                Spacer()

                // Fort Knox score pill
                if agent.totalAnalyses > 0 {
                    VStack(spacing: 2) {
                        Text("\(agent.fortKnoxScore)")
                            .font(.system(size: 22, weight: .black, design: .rounded))
                            .foregroundStyle(fortKnoxColor)
                        Text("Fort Knox")
                            .font(.system(size: 8, weight: .bold))
                            .foregroundStyle(fortKnoxColor.opacity(0.7))
                    }
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                    .background(fortKnoxColor.opacity(0.10))
                    .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
                    .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).stroke(fortKnoxColor.opacity(0.25), lineWidth: 0.5))
                }
            }
            .padding(18)
            .background(
                LinearGradient(
                    colors: [Color.sgPurple.opacity(0.10), Color.sgBlue.opacity(0.06), Color.sgSurface],
                    startPoint: .topLeading, endPoint: .bottomTrailing
                )
            )

            Color.sgBorder.frame(height: 1)

            // ── Stat grid ─────────────────────────────────────────────────
            let summary = agent.lastScanSummary
            LazyVGrid(
                columns: Array(repeating: GridItem(.flexible(), spacing: 1), count: 4),
                spacing: 1
            ) {
                briefingStat(
                    value: "\(agent.totalAnalyses)",
                    label: "Scans",
                    icon: "arrow.clockwise",
                    color: Color.sgBlue
                )
                briefingStat(
                    value: "\(appModel.incidents.filter { $0.status == .active && !$0.isSuppressed }.count)",
                    label: "Active",
                    icon: "exclamationmark.triangle.fill",
                    color: appModel.incidents.filter { $0.status == .active && !$0.isSuppressed }.isEmpty ? Color.sgSafe : Color.sgDanger
                )
                briefingStat(
                    value: "\(summary?.networkEventCount ?? engine.packetEvents.count)",
                    label: "Net Events",
                    icon: "antenna.radiowaves.left.and.right",
                    color: Color.sgPurple
                )
                briefingStat(
                    value: "\(agent.knownProcessCount)",
                    label: "Processes",
                    icon: "cpu",
                    color: Color(red: 0.15, green: 0.80, blue: 0.75)
                )
            }
            .background(Color.sgSurface)

            // ── Recent insights preview ───────────────────────────────────
            if !agent.insights.isEmpty {
                Color.sgBorder.frame(height: 1)
                VStack(alignment: .leading, spacing: 8) {
                    Text("RECENT FINDINGS")
                        .font(.system(size: 8, weight: .black))
                        .tracking(1.6)
                        .foregroundStyle(Color.sgTextTertiary)
                        .padding(.horizontal, 16)
                        .padding(.top, 12)

                    ForEach(agent.insights.prefix(3)) { insight in
                        HStack(spacing: 10) {
                            Image(systemName: insightIcon(insight.category))
                                .font(.system(size: 10, weight: .semibold))
                                .foregroundStyle(insightColor(insight.category))
                                .frame(width: 20)
                            Text(insight.headline)
                                .font(.system(size: 11, weight: insight.isUnread ? .bold : .medium))
                                .foregroundStyle(insight.isUnread ? Color.white : Color.white.opacity(0.6))
                                .lineLimit(1)
                            Spacer()
                            Text(insight.timestamp, format: .relative(presentation: .named, unitsStyle: .abbreviated))
                                .font(.system(size: 9))
                                .foregroundStyle(Color.sgTextTertiary)
                        }
                        .padding(.horizontal, 16)
                    }
                }
                .padding(.bottom, 14)
            }
        }
        .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous).stroke(Color.sgBorder))
        .frame(maxWidth: 640)
    }

    private func briefingStat(value: String, label: String, icon: String, color: Color) -> some View {
        VStack(spacing: 4) {
            Image(systemName: icon)
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(color)
            Text(value)
                .font(.system(size: 20, weight: .black, design: .rounded))
                .foregroundStyle(Color.sgTextPrimary)
            Text(label)
                .font(.system(size: 9, weight: .medium))
                .foregroundStyle(Color.sgTextTertiary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 14)
        .background(Color.sgSurface)
    }

    private func insightIcon(_ cat: AIInsightCategory) -> String {
        switch cat {
        case .systemClean:      return "checkmark.shield.fill"
        case .threatDetected:   return "exclamationmark.triangle.fill"
        case .pattern:          return "waveform.path.ecg"
        case .recommendation:   return "lightbulb.fill"
        case .network:          return "antenna.radiowaves.left.and.right"
        case .health:           return "heart.fill"
        case .levelUp:          return "star.fill"
        case .baseline:         return "chart.bar.fill"
        case .processSpotlight: return "cpu"
        case .trustAdvisory:    return "shield.slash.fill"
        case .portIntel:        return "network"
        case .hardening:        return "lock.shield"
        case .fortKnox:         return "lock.shield.fill"
        case .stable:           return "checkmark.circle.fill"
        }
    }

    private func insightColor(_ cat: AIInsightCategory) -> Color {
        switch cat {
        case .systemClean, .stable, .hardening: return Color.sgSafe
        case .threatDetected:   return Color.sgDanger
        case .health, .trustAdvisory: return Color.sgWarning
        case .levelUp, .fortKnox: return Color(red: 1.0, green: 0.82, blue: 0.20)
        case .network, .portIntel: return Color(red: 0.15, green: 0.80, blue: 0.75)
        case .pattern, .processSpotlight: return Color.sgPurple
        default: return Color.sgBlue
        }
    }

    // MARK: - Dynamic suggestions (live-aware)

    private var dynamicSuggestions: [Suggestion] {
        var chips: [Suggestion] = []
        let active = appModel.incidents.filter { $0.status == .active && !$0.isSuppressed }
        let netEvents = engine.packetEvents

        // Context-sensitive first chips
        if !active.isEmpty {
            chips.append(Suggestion(
                label: "Brief me on the active incidents",
                icon:  "exclamationmark.shield.fill",
                tint:  .sgDanger
            ))
            chips.append(Suggestion(
                label: "What should I do first?",
                icon:  "arrow.right.circle.fill",
                tint:  .sgWarning
            ))
        } else {
            chips.append(Suggestion(
                label: "Am I safe right now?",
                icon:  "checkmark.shield.fill",
                tint:  .sgSafe
            ))
        }

        if !netEvents.isEmpty {
            chips.append(Suggestion(
                label: "What are you seeing on the network?",
                icon:  "antenna.radiowaves.left.and.right",
                tint:  .sgPurple
            ))
        }

        if agent.totalAnalyses > 0 {
            chips.append(Suggestion(
                label: "What have you found so far?",
                icon:  "brain.head.profile",
                tint:  .sgBlue
            ))
            chips.append(Suggestion(
                label: "How can I improve my Fort Knox score?",
                icon:  "lock.shield.fill",
                tint:  Color(red: 1.0, green: 0.82, blue: 0.20)
            ))
        }

        // Pad with static starters if needed
        let statics = starterSuggestions.filter { s in
            !chips.contains { $0.label == s.label }
        }
        chips.append(contentsOf: statics.prefix(max(0, 8 - chips.count)))
        return Array(chips.prefix(8))
    }

    /// Delegate to MainView's shared palette so the two views always match.
    private var agentLevelColor: Color { MainView.levelColor(for: agent.agentLevel) }

    private var fortKnoxColor: Color {
        switch agent.fortKnoxScore {
        case 90...100: return Color(red: 1.0,  green: 0.82, blue: 0.20)
        case 75...89:  return Color(red: 0.18, green: 0.85, blue: 0.55)
        case 50...74:  return Color(red: 0.20, green: 0.55, blue: 1.0)
        case 25...49:  return Color(red: 1.0,  green: 0.62, blue: 0.05)
        default:       return Color(red: 1.0,  green: 0.27, blue: 0.27)
        }
    }

    // MARK: - Message list

    private var messageList: some View {
        ScrollViewReader { proxy in
            ScrollView {
                VStack(spacing: 14) {
                    ForEach(ai.analystMessages) { msg in
                        AnalystBubble(message: msg, cursorOn: cursorOn, isGenerating: ai.isAnalystGenerating)
                            .id(msg.id)
                    }
                    Color.clear.frame(height: 1).id("bottom")
                }
                .padding(.horizontal, 28)
                .padding(.vertical, 20)
            }
            .background(Color.sgBackground)
            .onChange(of: ai.analystMessages.count) { _ in
                withAnimation(.easeOut(duration: 0.2)) { proxy.scrollTo("bottom", anchor: .bottom) }
            }
            .onChange(of: ai.analystMessages.last?.content) { _ in
                proxy.scrollTo("bottom", anchor: .bottom)
            }
        }
    }

    // MARK: - Input bar

    private var inputBar: some View {
        VStack(spacing: 0) {
            // Quick suggestion chips when conversation is active
            if !ai.analystMessages.isEmpty {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 8) {
                        ForEach(starterSuggestions.prefix(6)) { s in
                            Button {
                                Task { await ai.analystChat(message: s.label) }
                            } label: {
                                HStack(spacing: 4) {
                                    Image(systemName: s.icon)
                                        .font(.system(size: 9, weight: .semibold))
                                    Text(s.label)
                                        .font(.system(size: 10, weight: .semibold))
                                        .lineLimit(1)
                                }
                                .foregroundStyle(s.tint)
                                .padding(.horizontal, 10)
                                .padding(.vertical, 5)
                                .background(s.tint.opacity(0.10))
                                .clipShape(Capsule())
                                .overlay(Capsule().stroke(s.tint.opacity(0.20)))
                            }
                            .buttonStyle(.plain)
                            .disabled(ai.isAnalystGenerating || !ai.isReady)
                            .opacity((ai.isAnalystGenerating || !ai.isReady) ? 0.4 : 1)
                        }
                    }
                    .padding(.horizontal, 20)
                    .padding(.vertical, 8)
                }
                .background(Color.sgSurface.opacity(0.4))
                Color.sgBorder.frame(height: 1)
            }

            // Text field row
            HStack(spacing: 10) {
                ZStack(alignment: .leading) {
                    if inputText.isEmpty {
                        Text("Ask a cybersecurity question…")
                            .font(.system(size: 13))
                            .foregroundStyle(Color.sgTextTertiary)
                            .padding(.leading, 14)
                            .allowsHitTesting(false)
                    }
                    TextField("", text: $inputText)
                        .font(.system(size: 13))
                        .foregroundStyle(Color.sgTextPrimary)
                        .textFieldStyle(.plain)
                        .focused($focused)
                        .padding(.horizontal, 14)
                        .padding(.vertical, 10)
                        .onSubmit { sendMessage() }
                }
                .background(Color.sgSurface)
                .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
                .overlay(
                    RoundedRectangle(cornerRadius: 10, style: .continuous)
                        .stroke(focused ? Color.sgPurple.opacity(0.5) : Color.sgBorder)
                )

                Button(action: sendMessage) {
                    Image(systemName: "arrow.up.circle.fill")
                        .font(.system(size: 30, weight: .semibold))
                        .foregroundStyle(
                            canSend
                                ? LinearGradient(colors: [Color.sgPurple, Color.sgBlue],
                                                 startPoint: .topLeading, endPoint: .bottomTrailing)
                                : LinearGradient(colors: [Color.sgTextTertiary, Color.sgTextTertiary],
                                                 startPoint: .top, endPoint: .bottom)
                        )
                }
                .buttonStyle(.plain)
                .disabled(!canSend)
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 12)
            .background(Color.sgBackground)
        }
    }

    private var canSend: Bool {
        !inputText.trimmingCharacters(in: .whitespaces).isEmpty && !ai.isAnalystGenerating && ai.isReady
    }

    private func sendMessage() {
        let text = inputText.trimmingCharacters(in: .whitespaces)
        guard !text.isEmpty else { return }
        inputText = ""
        Task { await ai.analystChat(message: text) }
    }

    // MARK: - Status badges

    private var readyBadge: some View {
        statusBadge(dot: true, color: .sgSafe, label: "Ready")
    }
    private var thinkingBadge: some View {
        statusBadge(dot: false, color: .sgPurple, label: "Thinking…")
    }
    private var loadingBadge: some View {
        statusBadge(dot: false, color: .sgWarning, label: "Loading model…")
    }
    private var errorBadge: some View {
        statusBadge(dot: true, color: .sgDanger, label: "Model error")
    }

    private func statusBadge(dot: Bool, color: Color, label: String) -> some View {
        HStack(spacing: 4) {
            if dot { Circle().fill(color).frame(width: 5, height: 5) }
            else   { ProgressView().controlSize(.mini).tint(color) }
            Text(label)
                .font(.system(size: 10, weight: .bold))
                .foregroundStyle(color)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 3)
        .background(color.opacity(0.12))
        .clipShape(Capsule())
    }

    private func miniChip(icon: String, label: String) -> some View {
        HStack(spacing: 3) {
            Image(systemName: icon).font(.system(size: 7, weight: .bold))
            Text(label).font(.system(size: 8, weight: .semibold))
        }
        .foregroundStyle(Color.sgTextTertiary)
        .padding(.horizontal, 5).padding(.vertical, 2)
        .background(Color.white.opacity(0.04))
        .clipShape(Capsule())
        .overlay(Capsule().stroke(Color.sgBorder))
    }

    // MARK: - Model state cards

    private var modelLoadingCard: some View {
        HStack(spacing: 14) {
            ProgressView().controlSize(.regular).tint(Color.sgPurple)
            VStack(alignment: .leading, spacing: 3) {
                Text("Loading AI model")
                    .font(.system(size: 13, weight: .bold))
                    .foregroundStyle(Color.sgTextPrimary)
                Text("PhantomAI.mlpackage is initialising on Neural Engine…")
                    .font(.system(size: 11))
                    .foregroundStyle(Color.sgTextSecondary)
            }
            Spacer()
        }
        .padding(16)
        .background(Color.sgSurface)
        .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).stroke(Color.sgBorder))
    }

    private func modelErrorCard(_ error: String) -> some View {
        HStack(spacing: 12) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 20))
                .foregroundStyle(Color.sgWarning)
            VStack(alignment: .leading, spacing: 3) {
                Text("Model unavailable")
                    .font(.system(size: 13, weight: .bold))
                    .foregroundStyle(Color.sgTextPrimary)
                Text(error)
                    .font(.system(size: 11))
                    .foregroundStyle(Color.sgTextSecondary)
            }
            Spacer()
            Button {
                Task { await ai.retryLoad() }
            } label: {
                HStack(spacing: 5) {
                    Image(systemName: "arrow.clockwise")
                        .font(.system(size: 11, weight: .semibold))
                    Text("Retry")
                        .font(.system(size: 12, weight: .semibold))
                }
                .foregroundStyle(Color.sgWarning)
                .padding(.horizontal, 12)
                .padding(.vertical, 7)
                .background(Color.sgWarning.opacity(0.12))
                .clipShape(Capsule())
            }
            .buttonStyle(.plain)
        }
        .padding(16)
        .background(Color.sgWarning.opacity(0.08))
        .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).stroke(Color.sgWarning.opacity(0.2)))
    }
}

// MARK: - SuggestionCard

private struct SuggestionCard: View {
    let suggestion:  Suggestion
    let isDisabled:  Bool
    let onTap:       () -> Void

    var body: some View {
        Button(action: onTap) {
            HStack(spacing: 10) {
                ZStack {
                    Circle()
                        .fill(suggestion.tint.opacity(0.15))
                        .frame(width: 32, height: 32)
                    Image(systemName: suggestion.icon)
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(suggestion.tint)
                }

                Text(suggestion.label)
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(Color.white.opacity(0.85))
                    .multilineTextAlignment(.leading)
                    .lineLimit(2)
                    .fixedSize(horizontal: false, vertical: true)

                Spacer()

                Image(systemName: "arrow.right")
                    .font(.system(size: 10, weight: .bold))
                    .foregroundStyle(Color.white.opacity(0.25))
            }
            .padding(14)
            .background(
                ZStack {
                    Color.sgSurface
                    LinearGradient(
                        colors: [suggestion.tint.opacity(0.07), Color.clear],
                        startPoint: .topLeading, endPoint: .bottomTrailing
                    )
                }
            )
            .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: 14, style: .continuous)
                    .stroke(suggestion.tint.opacity(0.18))
            )
        }
        .buttonStyle(.plain)
        .disabled(isDisabled)
        .opacity(isDisabled ? 0.45 : 1)
    }
}

// MARK: - AnalystBubble

private struct AnalystBubble: View {
    let message:     AIMessage
    let cursorOn:    Bool
    let isGenerating: Bool

    var body: some View {
        HStack(alignment: .bottom, spacing: 12) {
            if message.role == .user { Spacer(minLength: 80) }

            VStack(alignment: message.role == .user ? .trailing : .leading, spacing: 5) {
                // Role label
                HStack(spacing: 5) {
                    if message.role == .assistant {
                        Image(systemName: "cpu.fill")
                            .font(.system(size: 9, weight: .bold))
                            .foregroundStyle(Color.sgPurple)
                        Text("Phantom AI")
                            .font(.system(size: 9, weight: .bold))
                            .foregroundStyle(Color.sgPurple)
                    } else {
                        Text("You")
                            .font(.system(size: 9, weight: .bold))
                            .foregroundStyle(Color.sgBlue)
                        Image(systemName: "person.circle.fill")
                            .font(.system(size: 9, weight: .bold))
                            .foregroundStyle(Color.sgBlue)
                    }
                }

                // Bubble
                if message.role == .user {
                    Text(message.content)
                        .font(.system(size: 13))
                        .foregroundStyle(.white)
                        .textSelection(.enabled)
                        .padding(.horizontal, 14)
                        .padding(.vertical, 10)
                        .background(
                            LinearGradient(
                                colors: [Color.sgBlue, Color(red: 0.10, green: 0.40, blue: 0.95)],
                                startPoint: .topLeading, endPoint: .bottomTrailing
                            )
                        )
                        .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
                        .shadow(color: Color.sgBlue.opacity(0.22), radius: 6, y: 3)
                } else {
                    let displayed = message.content + (message.isStreaming && cursorOn ? "▌" : "")
                    Text(displayed.isEmpty ? " " : displayed)
                        .font(.system(size: 13, design: .serif))
                        .foregroundStyle(Color.sgTextPrimary)
                        .textSelection(.enabled)
                        .lineSpacing(5)
                        .padding(.horizontal, 14)
                        .padding(.vertical, 10)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(
                            ZStack {
                                Color.sgSurface
                                LinearGradient(
                                    colors: [Color.sgPurple.opacity(0.08), Color.clear],
                                    startPoint: .topLeading, endPoint: .bottomTrailing
                                )
                            }
                        )
                        .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
                        .overlay(
                            RoundedRectangle(cornerRadius: 16, style: .continuous)
                                .stroke(message.isStreaming ? Color.sgPurple.opacity(0.4) : Color.sgBorder)
                        )
                }

                Text(message.timestamp, format: .dateTime.hour().minute().second())
                    .font(.system(size: 8).monospacedDigit())
                    .foregroundStyle(Color.sgTextTertiary)
            }

            if message.role == .assistant { Spacer(minLength: 80) }
        }
    }
}
