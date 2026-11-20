import SwiftUI
import UIShared
import DesignSystem

struct MacSidebarView: View {
    @Binding var selection: MacDestination
    let counts: MacSidebarCounts
    let syncModel: SyncStatusModel
    let onSync: () -> Void

    var body: some View {
        List(selection: Binding<MacDestination?>(
            get: { selection },
            set: { if let destination = $0 { selection = destination } }
        )) {
            Section {
                sidebarRow(.all)
                sidebarRow(.favorites)
                sidebarRow(.authenticator)
                sidebarRow(.security)
            }
            Section("类型") {
                sidebarRow(.login)
                sidebarRow(.card)
                sidebarRow(.identity)
                sidebarRow(.secureNote)
            }
            Section("工具") {
                sidebarRow(.generator)
                sidebarRow(.send)
                sidebarRow(.settings)
            }
        }
        .listStyle(.sidebar)
        .accessibilityLabel("OpenVault 侧栏")
        .safeAreaBar(edge: .bottom) { accountFooter }
    }

    private func sidebarRow(_ destination: MacDestination) -> some View {
        Label(destination.title, systemImage: destination.systemImage)
            .badge(counts.value(for: destination).map { Text($0, format: .number) })
            .tag(destination)
    }

    private var accountFooter: some View {
        HStack(spacing: Spacing.sm) {
            OpenVaultMark(size: 28)
            VStack(alignment: .leading, spacing: Spacing.xxs) {
                Text("OpenVault").font(.headline)
                syncLabel.font(.caption)
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, Spacing.lg)
        .padding(.vertical, Spacing.sm)
    }

    @ViewBuilder
    private var syncLabel: some View {
        if syncModel.isSyncing {
            Text("正在同步…").foregroundStyle(.secondary)
        } else if syncModel.errorMessage != nil {
            Button("同步失败 · 重试", action: onSync).buttonStyle(.link)
        } else if let last = syncModel.lastSync {
            Button(action: onSync) {
                Text("已同步 · \(last.formatted(.relative(presentation: .named)))")
            }
            .buttonStyle(.link)
            .help("立即同步")
        } else {
            Button("尚未同步 · 立即同步", action: onSync).buttonStyle(.link)
        }
    }
}
