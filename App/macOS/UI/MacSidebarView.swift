// Xcode-only target (UI-iOS / UI-mac). Not part of the SPM build.
//
// MacSidebarView — the leading column: vault categories (and, later, folders). Selection
// is a `MacCategory` binding owned by `MacMainView`. The sidebar `List` gets Liquid Glass
// chrome automatically; a small sync footer mirrors the sync status.

import SwiftUI
import UIShared
import DesignSystem

@available(macOS 26.0, *)
struct MacSidebarView: View {
    @Binding var selection: MacCategory
    let syncModel: SyncStatusModel

    var body: some View {
        List(selection: $selection) {
            Section("Vault") {
                ForEach(MacCategory.allCases, id: \.self) { category in
                    Label(category.title, systemImage: category.systemImage)
                        .tag(category)
                }
            }
        }
        .listStyle(.sidebar)
        .safeAreaInset(edge: .bottom) {
            syncFooter
        }
    }

    private var syncFooter: some View {
        HStack(spacing: Spacing.sm) {
            if syncModel.isSyncing {
                ProgressView().controlSize(.small)
                Text("Syncing…")
            } else if syncModel.errorMessage != nil {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(Palette.warning)
                Text("Sync failed")
            } else if let last = syncModel.lastSync {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundStyle(Palette.success)
                Text(last.formatted(.relative(presentation: .named)))
                    .lineLimit(1)
            } else {
                Image(systemName: "arrow.triangle.2.circlepath")
                Text("Not synced")
            }
            Spacer(minLength: 0)
        }
        .font(Typography.caption)
        .foregroundStyle(Palette.secondaryText)
        .padding(.horizontal, Spacing.md)
        .padding(.vertical, Spacing.sm)
        .contentShape(Rectangle())
        .onTapGesture { Task { await syncModel.sync() } }
        .accessibilityHint("Tap to sync now")
    }
}
