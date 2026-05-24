import SwiftUI

struct SettingsView: View {
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var engine: PacketCaptureEngine

    var body: some View {
        Form {
            Section("Monitoring") {
                Toggle("Launch at login", isOn: $model.settings.startAtLogin)

                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Text("Scan interval")
                        Spacer()
                        Text(intervalLabel(model.settings.scanIntervalSeconds))
                            .foregroundStyle(.secondary)
                            .monospacedDigit()
                    }
                    // POWER: minimum 60s — below this causes Energy Impact: High
                    // from ps + lsof + filesystem I/O on every cycle.
                    Slider(
                        value: $model.settings.scanIntervalSeconds,
                        in: 60...300,
                        step: 30
                    )
                    Text("Lower intervals increase power usage.")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
            }

            Section("Notifications") {
                Toggle("Enable notifications", isOn: $model.settings.enableNotifications)
                    // macOS 13 form: single-parameter closure receiving the new value.
                    // The macOS 14 (oldValue, newValue) overload would raise the
                    // deployment floor unnecessarily.
                    .onChange(of: model.settings.enableNotifications) { enabled in
                        if enabled { model.requestNotificationPermission() }
                    }

                HStack(spacing: 8) {
                    // Permission status indicator
                    Image(systemName: model.notificationsAuthorized
                          ? "checkmark.circle.fill" : "exclamationmark.circle.fill")
                        .foregroundStyle(model.notificationsAuthorized ? .green : .orange)
                    Text(model.notificationsAuthorized
                         ? "System permission granted"
                         : "System permission not granted")
                        .foregroundStyle(.secondary)
                    Spacer()
                    if !model.notificationsAuthorized {
                        Button("Request Permission") {
                            model.requestNotificationPermission()
                        }
                        .buttonStyle(.borderedProminent)
                        .controlSize(.small)
                    }
                }
                .font(.callout)
                .onAppear { model.refreshNotificationAuthorizationStatus() }
            }

            Section("Network Intelligence") {
                HStack(spacing: 10) {
                    Image(systemName: engine.helperAvailable
                          ? "checkmark.circle.fill" : "exclamationmark.circle.fill")
                        .foregroundStyle(engine.helperAvailable ? .green : .orange)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Privileged Helper")
                            .font(.callout)
                        Text(engine.helperStatusMessage)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    if !engine.helperAvailable {
                        Button("Install Helper") {
                            Task { await engine.installHelper() }
                        }
                        .buttonStyle(.borderedProminent)
                        .controlSize(.small)
                        .tint(.orange)
                    }
                }
                .onAppear { Task { await engine.refreshHelperStatus() } }

                if engine.helperAvailable {
                    Text("Live packet capture is enabled. Raw pcap data is captured by the helper and processed locally — no data leaves this device.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else {
                    Text("Without the helper, Phantom uses lsof for connection monitoring. Live pcap capture (including TShark, tcpdump, Zeek, and Suricata integration) requires the privileged helper.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            Section("Actions") {
                HStack {
                    Button("Save Settings")    { model.saveSettings() }
                    Button("Scan Now")         { model.rescanNow() }
                    Button("Apply Login Item") { model.installLoginItem() }
                    Divider()
                    Button("Export JSON") { model.exportIncidents() }
                    Button("Export CSV")  { model.exportIncidentsAsCSV() }
                }
            }

            if let error = model.lastError, !error.isEmpty {
                Section("Last Error") {
                    Text(error).foregroundStyle(.red)
                }
            }
        }
        .formStyle(.grouped)
        .padding()
        .frame(width: 560, height: 580)
    }

    private func intervalLabel(_ seconds: Double) -> String {
        let s = Int(seconds)
        if s < 120 { return "\(s)s" }
        let m = s / 60
        let r = s % 60
        return r == 0 ? "\(m)m" : "\(m)m \(r)s"
    }
}
