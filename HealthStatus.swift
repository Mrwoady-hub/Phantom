import SwiftUI

// MARK: - HealthBanner / HealthPill views

struct HealthBanner: View {
    let status: HealthStatus
    let message: String

    var body: some View {
        if status.requiresAttention {
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: status.symbol)
                    .foregroundStyle(status.tint)

                VStack(alignment: .leading, spacing: 4) {
                    Text(status.title)
                        .font(.subheadline.weight(.semibold))
                    Text(message.isEmpty ? status.summary : message)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Spacer()
            }
            .padding(12)
            .background(status.tint.opacity(0.10), in: RoundedRectangle(cornerRadius: 12))
            .overlay(
                RoundedRectangle(cornerRadius: 12)
                    .stroke(status.tint.opacity(0.25), lineWidth: 1)
            )
        }
    }
}

struct HealthPill: View {
    let status: HealthStatus

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: status.symbol)
                .font(.caption)
            Text(status.title)
                .font(.caption.weight(.semibold))
        }
        .foregroundStyle(status.tint)
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
        .background(status.tint.opacity(0.14), in: Capsule())
    }
}

// MARK: - HealthStatus presentation extensions
//
// NOTE: title and tint are used by MainView's statusBadge at the line that
// the compiler flagged: `Text(model.health.displayStatus.title)`
// This extension must be compiled as part of the target — if Health_Status.swift
// is not added to the Xcode target, HealthStatus has no `title` member and
// MainView fails with "Value of type 'HealthStatus' has no member 'title'".

extension HealthStatus {
    var title: String {
        switch self {
        case .healthy:  return "Healthy"
        case .degraded: return "Degraded"
        case .failed:   return "Failed"
        case .offline:  return "Offline"
        }
    }

    var tint: Color {
        switch self {
        case .healthy:  return .green
        case .degraded: return .orange
        case .failed:   return .red
        case .offline:  return .gray
        }
    }

    var symbol: String {
        switch self {
        case .healthy:  return "checkmark.circle.fill"
        case .degraded: return "exclamationmark.triangle.fill"
        case .failed:   return "xmark.octagon.fill"
        case .offline:  return "minus.circle.fill"
        }
    }

    var summary: String {
        switch self {
        case .healthy:  return "Telemetry is current and sensors are responding normally."
        case .degraded: return "Telemetry is partially available or delayed."
        case .failed:   return "Telemetry collection failed. Results may be stale."
        case .offline:  return "Monitoring is not currently collecting telemetry."
        }
    }

    var requiresAttention: Bool {
        switch self {
        case .healthy:           return false
        case .degraded, .failed, .offline: return true
        }
    }
}
