import SwiftUI

struct SettingsView: View {
    @EnvironmentObject private var model: AppModel

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
                    .onChange(of: model.settings.enableNotifications) { _, enabled in
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
        .frame(width: 520, height: 460)
    }

    private func intervalLabel(_ seconds: Double) -> String {
        let s = Int(seconds)
        if s < 120 { return "\(s)s" }
        let m = s / 60
        let r = s % 60
        return r == 0 ? "\(m)m" : "\(m)m \(r)s"
    }
}
