import SwiftUI
import AppKit

struct MenuBarView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            header
            Divider()
            riskSection
            incidentSection
            Divider()
            actionSection
            Divider()
            quitSection
        }
        .padding(14)
        .frame(width: 320)
    }

    private var header: some View {
        HStack {
            Text("Phantom")
                .font(.headline)

            Spacer()

            Text(model.status.title)
                .font(.caption.weight(.semibold))
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .background(model.status.tint.opacity(0.12))
                .foregroundStyle(model.status.tint)
                .clipShape(Capsule())
        }
    }

    private var riskSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Risk Score")
                .font(.caption)
                .foregroundStyle(.secondary)

            Text("\(model.riskScore)")
                .font(.system(size: 30, weight: .bold, design: .rounded))
        }
    }

    @ViewBuilder
    private var incidentSection: some View {
        if let topIncident = model.topIncident {
            VStack(alignment: .leading, spacing: 4) {
                Text("Top Incident")
                    .font(.caption)
                    .foregroundStyle(.secondary)

                Text(topIncident.name)
                    .font(.subheadline.weight(.semibold))
                    .lineLimit(2)

                Text(topIncident.detail ?? topIncident.source.title)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }
        } else {
            Text("No active incidents")
                .font(.subheadline)
                .foregroundStyle(.secondary)
        }
    }

    private var actionSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Button("Rescan Now") {
                model.rescanNow()
            }

            Button(role: .destructive) {
                model.clearIncidents()
            } label: {
                Text("Clear Incidents")
            }
        }
    }

    private var quitSection: some View {
        Button("Quit") {
            NSApp.terminate(nil)
        }
    }
}
