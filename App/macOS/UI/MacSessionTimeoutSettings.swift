import SwiftUI
import UIShared

struct MacSessionTimeoutSettings: View {
    let settings: MacSessionTimeoutModel

    var body: some View {
        Section {
            Picker(selection: Binding(get: { settings.policy.mode }, set: settings.setMode)) {
                ForEach(MacSessionTimeoutMode.allCases, id: \.self) { mode in
                    Text(mode.title, tableName: "MacSessionTimeout").tag(mode)
                }
            } label: {
                Text("Timeout", tableName: "MacSessionTimeout")
            }
            .accessibilityIdentifier("settings.session-timeout")

            if settings.policy.mode == .custom {
                TextField(value: Binding(get: { settings.policy.customHoursPart }, set: settings.setCustomHours), format: .number.grouping(.never)) {
                    Text("Hours", tableName: "MacSessionTimeout")
                }
                .accessibilityIdentifier("settings.session-timeout-hours")
                TextField(value: Binding(get: { settings.policy.customMinutesPart }, set: settings.setCustomMinutes), format: .number.grouping(.never)) {
                    Text("Minutes", tableName: "MacSessionTimeout")
                }
                .accessibilityIdentifier("settings.session-timeout-minutes")
            }

            if settings.policy.mode != .never {
                Picker(selection: Binding(get: { settings.policy.action }, set: settings.setAction)) {
                    Text("Lock", tableName: "MacSessionTimeout").tag(MacSessionTimeoutAction.lock)
                    Text("Log Out", tableName: "MacSessionTimeout").tag(MacSessionTimeoutAction.logOut)
                } label: {
                    Text("Timeout Action", tableName: "MacSessionTimeout")
                }
                .accessibilityIdentifier("settings.session-timeout-action")
            }

            if settings.policy.mode.allowsSupplementalLock {
                Toggle(isOn: Binding(get: { settings.policy.alsoLocksOnSleepOrUserSwitch }, set: settings.setSupplementalLock)) {
                    Text("Also lock when the Mac sleeps or switches users", tableName: "MacSessionTimeout")
                }
                .accessibilityIdentifier("settings.session-timeout-guard")
            }
        } header: {
            Text("Session Timeout", tableName: "MacSessionTimeout")
        } footer: {
            VStack(alignment: .leading, spacing: 4) {
                if let help { Text(help, tableName: "MacSessionTimeout") }
                if settings.policy.mode != .never, settings.policy.action == .logOut {
                    Text("Logging out requires signing in again. This also applies after quitting OpenVault.", tableName: "MacSessionTimeout")
                }
            }
        }
    }

    private var help: LocalizedStringKey? {
        switch settings.policy.mode {
        case .never:
            "OpenVault does not time out while it is running. Restarting still requires you to unlock."
        case .onSystemLock:
            "Screen lock detection depends on macOS. If the lock cannot be confirmed, OpenVault locks instead of logging out."
        case .onSystemIdle:
            "Times out after five minutes without input anywhere on this Mac."
        default:
            nil
        }
    }
}

private extension MacSessionTimeoutMode {
    var title: LocalizedStringKey {
        switch self {
        case .oneMinute: "1 minute"
        case .fiveMinutes: "5 minutes"
        case .fifteenMinutes: "15 minutes"
        case .thirtyMinutes: "30 minutes"
        case .oneHour: "1 hour"
        case .fourHours: "4 hours"
        case .onSystemIdle: "On system idle"
        case .onSystemSleep: "On system sleep"
        case .onSystemLock: "On system lock"
        case .onRestart: "On app restart"
        case .never: "Never"
        case .custom: "Custom"
        }
    }
}
