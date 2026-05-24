// IncidentExplainView.swift
// Interactive AI analyst for detected incidents.
// Powered by PhantomAI — on-device GPT-2 (gpt2_cyber5).
// Air-gapped • No telemetry • Memory-only session

import Combine
import SwiftUI

// Design tokens live in MainView.swift (module-level extension Color).

// MARK: - Quick-action descriptors

private struct QuickAction: Identifiable {
    let id    = UUID()
    let label: String
    let icon:  String
    let tint:  Color
    let fire:  (Incident) async -> Void
}

// MARK: - IncidentExplainView

struct IncidentExplainView: View {
    let incident: Incident

    @ObservedObject private var ai     = PhantomAI.shared
    @Environment(\.dismiss) private var dismiss

    @State private var inputText       = ""
    @State private var cursorOn        = true
    @State private var scrollProxy: ScrollViewProxy? = nil
    @FocusState private var inputFocused: Bool

    // Cursor blink timer
    private let cursorTimer = Timer.publish(every: 0.5, on: .main, in: .common).autoconnect()

    // ── Quick-action chips ────────────────────────────────────────────────

    private var quickActions: [QuickAction] {
        var actions: [QuickAction] = [
            QuickAction(label: "Explain", icon: "sparkles", tint: .sgPurple) {
                await ai.explain(incident: $0)
            },
            QuickAction(label: "Attack Vector", icon: "bolt.trianglebadge.exclamationmark.fill", tint: .sgDanger) {
                await ai.askAttackVector(incident: $0)
            },
            QuickAction(label: "Remediation", icon: "shield.lefthalf.filled.badge.checkmark", tint: .sgSafe) {
                await ai.askRemediation(incident: $0)
            },
            QuickAction(label: "False Positive?", icon: "questionmark.circle.fill", tint: .sgWarning) {
                await ai.askFalsePositive(incident: $0)
            },
            QuickAction(label: "Threat Actors", icon: "person.crop.circle.badge.exclamationmark.fill", tint: .sgBlue) {
                await ai.askThreatActor(incident: $0)
            },
        ]
        if incident.technique != nil {
            actions.insert(
                QuickAction(label: "MITRE \(incident.technique!.rawValue)", icon: "tag.fill", tint: .sgBlue) {
                    await ai.askMitreContext(incident: $0)
                },
                at: 1
            )
        }
        return actions
    }

    // MARK: - Body

    var body: some View {
        ZStack {
            Color.sgBackground.ignoresSafeArea()

            VStack(spacing: 0) {
                header
                Color.sgBorder.frame(height: 1)
                messageList
                Color.sgBorder.frame(height: 1)
                quickActionsBar
                Color.sgBorder.frame(height: 1)
                inputBar
            }
        }
        .frame(minWidth: 680, minHeight: 540)
        .onAppear {
            // Stay one step ahead — auto-explain on open
            if ai.messages.isEmpty, ai.isReady {
                Task { await ai.explain(incident: incident) }
            } else if ai.messages.isEmpty && !ai.isReady {
                // Model still loading — retry after a short wait
                Task {
                    try? await Task.sleep(for: .seconds(1.5))
                    if ai.messages.isEmpty {
                        await ai.explain(incident: incident)
                    }
                }
            }
        }
        .onDisappear {
            // Security: wipe session from memory on dismiss
            ai.clearSession()
        }
        .onReceive(cursorTimer) { _ in
            if ai.isGenerating { cursorOn.toggle() }
            else { cursorOn = false }
        }
    }

    // MARK: - Header

    private var header: some View {
        HStack(spacing: 14) {
            // AI orb
            ZStack {
                Circle()
                    .fill(
                        RadialGradient(
                            colors: [Color.sgPurple.opacity(0.6), Color.sgBlue.opacity(0.3), Color.clear],
                            center: .center,
                            startRadius: 0,
                            endRadius: 22
                        )
                    )
                    .frame(width: 44, height: 44)
                    .blur(radius: ai.isGenerating ? 2 : 0)
                    .animation(.easeInOut(duration: 0.8).repeatForever(autoreverses: true), value: ai.isGenerating)

                Image(systemName: "cpu.fill")
                    .font(.system(size: 18, weight: .semibold))
                    .foregroundStyle(Color.sgPurple)
            }

            VStack(alignment: .leading, spacing: 5) {
                HStack(spacing: 6) {
                    Text("Phantom AI")
                        .font(.system(size: 15, weight: .black, design: .rounded))
                        .foregroundStyle(Color.sgTextPrimary)

                    if ai.isGenerating {
                        generatingDots
                    } else if !ai.messages.isEmpty {
                        statusPill("Ready", color: .sgSafe)
                    }
                }

                // Security guarantees strip
                HStack(spacing: 8) {
                    securityChip(icon: "lock.fill",        label: "Air-gapped")
                    securityChip(icon: "cpu",              label: "On-device")
                    securityChip(icon: "eye.slash.fill",   label: "No logging")
                    securityChip(icon: "trash.fill",       label: "Memory-only")
                }
            }

            Spacer()

            // Incident context chip
            VStack(alignment: .trailing, spacing: 4) {
                Text(incident.name)
                    .font(.system(size: 11, weight: .bold))
                    .foregroundStyle(Color.sgTextPrimary)
                    .lineLimit(1)
                HStack(spacing: 4) {
                    SGBadge(text: incident.severity.title.uppercased(),
                            tint: incident.severity.tint, bold: true)
                    SGBadge(text: incident.source.title, tint: .sgBlue)
                    if let t = incident.technique {
                        SGBadge(text: t.rawValue, tint: .sgPurple)
                    }
                }
            }
        }
        .padding(.horizontal, 22)
        .padding(.vertical, 14)
        .background(
            LinearGradient(
                colors: [Color.sgPurple.opacity(0.10), Color.sgBackground],
                startPoint: .top, endPoint: .bottom
            )
        )
    }

    // MARK: - Message list

    private var messageList: some View {
        ScrollViewReader { proxy in
            ScrollView {
                VStack(spacing: 14) {
                    if ai.messages.isEmpty {
                        emptyState
                    } else {
                        ForEach(ai.messages) { msg in
                            MessageBubble(
                                message:    msg,
                                cursorOn:   cursorOn,
                                isGenerating: ai.isGenerating
                            )
                            .id(msg.id)
                        }
                    }

                    // Anchor for auto-scroll
                    Color.clear.frame(height: 1).id("bottom")
                }
                .padding(.horizontal, 20)
                .padding(.vertical, 16)
            }
            .background(Color.sgBackground)
            .onChange(of: ai.messages.count) { _ in
                withAnimation(.easeOut(duration: 0.2)) {
                    proxy.scrollTo("bottom", anchor: .bottom)
                }
            }
            .onChange(of: ai.messages.last?.content) { _ in
                proxy.scrollTo("bottom", anchor: .bottom)
            }
        }
    }

    // MARK: - Quick-action bar

    private var quickActionsBar: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                ForEach(quickActions) { action in
                    Button {
                        Task { await action.fire(incident) }
                    } label: {
                        HStack(spacing: 5) {
                            Image(systemName: action.icon)
                                .font(.system(size: 10, weight: .semibold))
                            Text(action.label)
                                .font(.system(size: 11, weight: .semibold))
                        }
                        .foregroundStyle(action.tint)
                        .padding(.horizontal, 12)
                        .padding(.vertical, 7)
                        .background(action.tint.opacity(0.12))
                        .clipShape(Capsule())
                        .overlay(Capsule().stroke(action.tint.opacity(0.25)))
                    }
                    .buttonStyle(.plain)
                    .disabled(ai.isGenerating || !ai.isReady)
                    .opacity((ai.isGenerating || !ai.isReady) ? 0.4 : 1)
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 10)
        }
        .background(Color.sgSurface.opacity(0.5))
        .frame(height: 44)
    }

    // MARK: - Input bar

    private var inputBar: some View {
        HStack(spacing: 10) {
            // Analyst input field
            ZStack(alignment: .leading) {
                if inputText.isEmpty {
                    Text("Ask a follow-up question…")
                        .font(.system(size: 13))
                        .foregroundStyle(Color.sgTextTertiary)
                        .padding(.leading, 14)
                        .allowsHitTesting(false)
                }
                TextField("", text: $inputText)
                    .font(.system(size: 13))
                    .foregroundStyle(Color.sgTextPrimary)
                    .textFieldStyle(.plain)
                    .focused($inputFocused)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 10)
                    .onSubmit { sendChat() }
            }
            .background(Color.sgSurface)
            .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .stroke(inputFocused ? Color.sgPurple.opacity(0.5) : Color.sgBorder)
            )

            // Send button
            Button(action: sendChat) {
                Image(systemName: "arrow.up.circle.fill")
                    .font(.system(size: 28, weight: .semibold))
                    .foregroundStyle(
                        inputText.trimmingCharacters(in: .whitespaces).isEmpty || ai.isGenerating
                            ? Color.sgTextTertiary
                            : Color.sgPurple
                    )
            }
            .buttonStyle(.plain)
            .disabled(inputText.trimmingCharacters(in: .whitespaces).isEmpty || ai.isGenerating || !ai.isReady)
            .keyboardShortcut(.return, modifiers: [])

            // Close
            Button("Done") { dismiss() }
                .keyboardShortcut(.cancelAction)
                .buttonStyle(AIGhostButtonStyle())
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
        .background(Color.sgBackground)
    }

    // MARK: - Helpers

    private func sendChat() {
        let text = inputText.trimmingCharacters(in: .whitespaces)
        guard !text.isEmpty else { return }
        inputText = ""
        Task { await ai.chat(message: text, incident: incident) }
    }

    private var emptyState: some View {
        VStack(spacing: 12) {
            if let error = ai.loadError {
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.system(size: 28))
                    .foregroundStyle(Color.sgWarning)
                Text("Model unavailable")
                    .font(.system(size: 14, weight: .bold))
                    .foregroundStyle(Color.sgTextPrimary)
                Text(error)
                    .font(.system(size: 11))
                    .foregroundStyle(Color.sgTextSecondary)
                    .multilineTextAlignment(.center)
                Button {
                    Task { await ai.retryLoad() }
                } label: {
                    HStack(spacing: 5) {
                        Image(systemName: "arrow.clockwise").font(.system(size: 11, weight: .semibold))
                        Text("Retry").font(.system(size: 12, weight: .semibold))
                    }
                    .foregroundStyle(Color.sgWarning)
                    .padding(.horizontal, 14).padding(.vertical, 8)
                    .background(Color.sgWarning.opacity(0.12))
                    .clipShape(Capsule())
                }
                .buttonStyle(.plain)
            } else {
                ProgressView()
                    .controlSize(.regular)
                    .tint(Color.sgPurple)
                Text("Loading AI model…")
                    .font(.system(size: 13))
                    .foregroundStyle(Color.sgTextSecondary)
            }
        }
        .frame(maxWidth: .infinity, minHeight: 200)
    }

    private var generatingDots: some View {
        HStack(spacing: 3) {
            ForEach(0..<3, id: \.self) { i in
                Circle()
                    .fill(Color.sgPurple)
                    .frame(width: 4, height: 4)
                    .opacity(cursorOn ? (i == 0 ? 1.0 : 0.4) : (i == 2 ? 1.0 : 0.4))
                    .animation(
                        .easeInOut(duration: 0.4)
                            .repeatForever(autoreverses: true)
                            .delay(Double(i) * 0.15),
                        value: cursorOn
                    )
            }
        }
    }

    private func statusPill(_ label: String, color: Color) -> some View {
        HStack(spacing: 4) {
            Circle().fill(color).frame(width: 5, height: 5)
            Text(label)
                .font(.system(size: 9, weight: .bold))
                .foregroundStyle(color)
        }
        .padding(.horizontal, 7)
        .padding(.vertical, 3)
        .background(color.opacity(0.12))
        .clipShape(Capsule())
    }

    private func securityChip(icon: String, label: String) -> some View {
        HStack(spacing: 3) {
            Image(systemName: icon)
                .font(.system(size: 7, weight: .bold))
            Text(label)
                .font(.system(size: 8, weight: .semibold))
        }
        .foregroundStyle(Color.sgTextTertiary)
        .padding(.horizontal, 5)
        .padding(.vertical, 2)
        .background(Color.white.opacity(0.04))
        .clipShape(Capsule())
        .overlay(Capsule().stroke(Color.sgBorder))
    }

    // MARK: - Shared badge

    private struct SGBadge: View {
        let text:  String
        let tint:  Color
        var bold:  Bool = false
        var body: some View {
            Text(text)
                .font(.system(size: 9, weight: bold ? .black : .semibold))
                .foregroundStyle(tint)
                .padding(.horizontal, 6)
                .padding(.vertical, 2)
                .background(tint.opacity(0.15))
                .clipShape(Capsule())
        }
    }
}

// MARK: - MessageBubble

private struct MessageBubble: View {
    let message:     AIMessage
    let cursorOn:    Bool
    let isGenerating: Bool

    var body: some View {
        HStack(alignment: .bottom, spacing: 10) {
            if message.role == .user { Spacer(minLength: 60) }

            VStack(alignment: message.role == .user ? .trailing : .leading, spacing: 4) {
                // Sender label
                HStack(spacing: 5) {
                    if message.role == .assistant {
                        Image(systemName: "cpu.fill")
                            .font(.system(size: 9, weight: .bold))
                            .foregroundStyle(Color.sgPurple)
                        Text("Phantom AI")
                            .font(.system(size: 9, weight: .bold))
                            .foregroundStyle(Color.sgPurple)
                    } else {
                        Text("Analyst")
                            .font(.system(size: 9, weight: .bold))
                            .foregroundStyle(Color.sgBlue)
                        Image(systemName: "person.circle.fill")
                            .font(.system(size: 9, weight: .bold))
                            .foregroundStyle(Color.sgBlue)
                    }
                }

                // Bubble
                bubbleBody

                // Timestamp
                Text(message.timestamp, format: .dateTime.hour().minute().second())
                    .font(.system(size: 8).monospacedDigit())
                    .foregroundStyle(Color.sgTextTertiary)
            }

            if message.role == .assistant { Spacer(minLength: 60) }
        }
    }

    @ViewBuilder
    private var bubbleBody: some View {
        if message.role == .user {
            // User bubble — right, blue tint
            Text(message.content)
                .font(.system(size: 13))
                .foregroundStyle(Color.white)
                .textSelection(.enabled)
                .padding(.horizontal, 14)
                .padding(.vertical, 10)
                .background(
                    LinearGradient(
                        colors: [Color.sgBlue, Color(red: 0.10, green: 0.40, blue: 0.95)],
                        startPoint: .topLeading, endPoint: .bottomTrailing
                    )
                )
                .clipShape(BubbleShape(role: .user))
                .shadow(color: Color.sgBlue.opacity(0.25), radius: 6, y: 3)

        } else {
            // Assistant bubble — left, purple tint + streaming cursor
            let displayed = message.content + (message.isStreaming && cursorOn ? "▌" : "")

            ZStack(alignment: .topLeading) {
                // Subtle glow when streaming
                if message.isStreaming {
                    RoundedRectangle(cornerRadius: 16, style: .continuous)
                        .fill(Color.sgPurple.opacity(0.08))
                        .blur(radius: 8)
                }

                Text(displayed.isEmpty ? "…" : displayed)
                    .font(.system(size: 13, design: displayed.count > 60 ? .serif : .default))
                    .foregroundStyle(Color.sgTextPrimary)
                    .textSelection(.enabled)
                    .lineSpacing(4)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(
                        ZStack {
                            Color.sgSurface
                            LinearGradient(
                                colors: [Color.sgPurple.opacity(0.07), Color.clear],
                                startPoint: .topLeading, endPoint: .bottomTrailing
                            )
                        }
                    )
                    .clipShape(BubbleShape(role: .assistant))
                    .overlay(
                        BubbleShape(role: .assistant)
                            .stroke(
                                message.isStreaming
                                    ? Color.sgPurple.opacity(0.4)
                                    : Color.sgBorder,
                                lineWidth: 1
                            )
                    )
            }
        }
    }
}

// MARK: - BubbleShape

private struct BubbleShape: Shape {
    enum Role { case user, assistant }
    let role: Role

    func path(in rect: CGRect) -> Path {
        let r: CGFloat  = 16
        let tail: CGFloat = 6
        var p = Path()

        switch role {
        case .user:
            // Rounded rect, bottom-right is sharp (tail side)
            p.addRoundedRect(in: rect, cornerSize: CGSize(width: r, height: r))

        case .assistant:
            // Rounded rect, bottom-left sharp
            p.addRoundedRect(in: rect, cornerSize: CGSize(width: r, height: r))
        }
        _ = tail  // reserved for future tail detail
        return p
    }
}

// MARK: - Button style

private struct AIGhostButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 13, weight: .semibold))
            .foregroundStyle(Color.white.opacity(0.55))
            .padding(.horizontal, 16)
            .padding(.vertical, 9)
            .background(Color(red: 0.11, green: 0.13, blue: 0.19).opacity(configuration.isPressed ? 0.5 : 1))
            .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).stroke(Color.white.opacity(0.07)))
    }
}
