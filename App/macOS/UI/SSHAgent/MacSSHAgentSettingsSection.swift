import SwiftUI

struct MacSSHAgentSettingsSection: View {
    @Environment(\.macSSHAgent) private var agent

    var body: some View {
        if let agent {
            Section {
                Toggle(isOn: Binding(get: { agent.enabled }, set: agent.setEnabled)) {
                    Text("Enable SSH Agent", tableName: "MacSSHAgent")
                }
                .accessibilityIdentifier("settings.ssh-agent")

                if agent.enabled {
                    Picker(selection: Binding(get: { agent.socketMode }, set: agent.setSocketMode)) {
                        Text("OpenVault (Default)", tableName: "MacSSHAgent").tag(MacSSHAgentSocketMode.openVault)
                        Text("Bitwarden DMG", tableName: "MacSSHAgent").tag(MacSSHAgentSocketMode.bitwardenDMG)
                    } label: { Text("SSH Agent Socket Path", tableName: "MacSSHAgent") }
                    .accessibilityIdentifier("settings.ssh-agent-socket-mode")
                    if agent.socketMode == .bitwardenDMG {
                        Text("Reuses ~/.bitwarden-ssh-agent.sock while the vault is unlocked. Do not run both agents with this path.",
                             tableName: "MacSSHAgent")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }

                    Picker(selection: Binding(get: { agent.policy }, set: agent.setPolicy)) {
                        ForEach(MacSSHAgentPolicy.allCases, id: \.self) { option in
                            option.title.tag(option)
                        }
                    } label: { Text("Ask for authorization when using SSH Agent", tableName: "MacSSHAgent") }
                    .accessibilityIdentifier("settings.ssh-agent-policy")

                    if agent.policy == .never {
                        Text("While the vault is unlocked, processes running as your user can request signatures without confirmation.",
                             tableName: "MacSSHAgent")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    } else if agent.policy == .rememberUntilLock {
                        Text("Approval applies to the same local process and key until the vault locks.", tableName: "MacSSHAgent")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                    status(for: agent)
                }
            } header: {
                Text("SSH Agent", tableName: "MacSSHAgent")
            } footer: {
                Text("OpenVault does not change your SSH configuration or environment variables.", tableName: "MacSSHAgent")
            }
        }
    }

    @ViewBuilder private func status(for agent: MacSSHAgentController) -> some View {
        switch agent.status {
        case .waitingForUnlock:
            Text("Unlock OpenVault, then retry your SSH command.", tableName: "MacSSHAgent")
                .font(.footnote)
                .foregroundStyle(.secondary)
        case .ready(let path):
            LabeledContent {
                Button { MacClipboard.copy(path) } label: { Text("Copy Socket Path", tableName: "MacSSHAgent") }
                    .accessibilityIdentifier("settings.ssh-agent-copy-path")
            } label: { Text("Local Socket", tableName: "MacSSHAgent") }
            Text("Use the copied path as the IdentityAgent in your SSH configuration. Do not forward this agent.", tableName: "MacSSHAgent")
                .font(.footnote)
                .foregroundStyle(.secondary)
        case .occupied:
            availabilityIssue("The OpenVault socket path is occupied. Close other OpenVault instances before retrying.", agent: agent)
        case .compatibilityPathOccupied:
            availabilityIssue("The Bitwarden DMG path is already in use. Disable Bitwarden’s SSH Agent or switch back to the OpenVault path.", agent: agent)
        case .compatibilityPathUnavailable:
            availabilityIssue("OpenVault could not create the Bitwarden DMG socket link in your home directory.", agent: agent)
        case .pathTooLong:
            Text("This Mac’s home path is too long for the OpenSSH socket.", tableName: "MacSSHAgent")
                .font(.footnote)
                .foregroundStyle(.secondary)
        case .unavailable:
            availabilityIssue("OpenVault could not start the local SSH Agent on this Mac.", agent: agent)
        }
    }

    private func availabilityIssue(_ key: LocalizedStringKey, agent: MacSSHAgentController) -> some View {
        LabeledContent {
            Button(action: agent.retry) { Text("Retry SSH Agent", tableName: "MacSSHAgent") }
        } label: { Text(key, tableName: "MacSSHAgent") }
    }
}

private extension MacSSHAgentPolicy {
    var title: Text {
        switch self {
        case .always: Text("Always", tableName: "MacSSHAgent")
        case .never: Text("Never", tableName: "MacSSHAgent")
        case .rememberUntilLock: Text("Remember Until the Vault Locks", tableName: "MacSSHAgent")
        }
    }
}
