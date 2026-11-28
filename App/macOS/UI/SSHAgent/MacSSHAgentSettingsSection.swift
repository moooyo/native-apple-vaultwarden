import SwiftUI

struct MacSSHAgentSettingsSection: View {
    @Environment(\.macSSHAgent) private var agent
    @Environment(\.locale) private var locale

    var body: some View {
        if let agent {
            Section {
                Toggle(isOn: Binding(get: { agent.enabled }, set: agent.setEnabled)) {
                    Text("Enable SSH Agent", tableName: "MacSSHAgent")
                }
                .accessibilityIdentifier("settings.ssh-agent")
                Picker(selection: Binding(get: { agent.policy }, set: agent.setPolicy)) {
                    ForEach(MacSSHAgentPolicy.allCases, id: \.self) { option in
                        Text(verbatim: macSSHAgentText(option.label, locale: locale)).tag(option)
                    }
                } label: { Text("Before Using a Key", tableName: "MacSSHAgent") }
                .pickerStyle(.menu)
                .accessibilityIdentifier("settings.ssh-agent-policy")
            } footer: {
                if let path = agent.currentSocketPath, let count = agent.itemCount {
                    Text("\(count) SSH keys loaded. To use them, run \(Text(verbatim: exportCommand(path)).monospaced()) in Terminal.",
                         tableName: "MacSSHAgent")
                        .font(.system(size: 12)).foregroundStyle(.secondary)
                        .textSelection(.enabled)
                        .accessibilityIdentifier("settings.ssh-agent-setup")
                }
            }
            .contextMenu { socketActions(agent) }
            if agent.enabled { availabilityIssue(agent) }
        }
    }

    private func exportCommand(_ path: String) -> String {
        "export SSH_AUTH_SOCK='\(path.replacingOccurrences(of: "'", with: "'\\''"))'"
    }

    @ViewBuilder private func socketActions(_ agent: MacSSHAgentController) -> some View {
        if let path = agent.currentSocketPath {
            Button { MacClipboard.copy(path) } label: { Text("Copy Socket Path", tableName: "MacSSHAgent") }
        }
        Menu {
            Picker(selection: Binding(get: { agent.socketMode }, set: agent.setSocketMode)) {
                Text("OpenVault (Default)", tableName: "MacSSHAgent").tag(MacSSHAgentSocketMode.openVault)
                Text("Bitwarden DMG", tableName: "MacSSHAgent").tag(MacSSHAgentSocketMode.bitwardenDMG)
            } label: { Text("SSH Agent Socket Path", tableName: "MacSSHAgent") }
        } label: { Text("SSH Agent Socket Path", tableName: "MacSSHAgent") }
    }

    @ViewBuilder private func availabilityIssue(_ agent: MacSSHAgentController) -> some View {
        let issue: LocalizedStringKey? = switch agent.status {
        case .disabled, .waitingForAccount, .ready: nil
        case .occupied: "The OpenVault socket path is occupied. Close other OpenVault instances before retrying."
        case .compatibilityPathOccupied: "The Bitwarden DMG path is already in use. Disable Bitwarden’s SSH Agent or switch back to the OpenVault path."
        case .compatibilityPathUnavailable: "OpenVault could not create the Bitwarden DMG socket link in your home directory."
        case .pathTooLong: "This Mac’s home path is too long for the OpenSSH socket."
        case .unavailable: "OpenVault could not start the local SSH Agent on this Mac."
        }
        if let issue {
            Section {
                LabeledContent {
                    Button(action: agent.retry) { Text("Retry SSH Agent", tableName: "MacSSHAgent") }
                } label: { Text(issue, tableName: "MacSSHAgent") }
            }
        }
    }
}
