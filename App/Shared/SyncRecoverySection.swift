import Accessibility
import DesignSystem
import SwiftUI
import UIShared
import VaultRepository

struct SyncAttentionButton: View {
    let model: SyncStatusModel
    let onOpenSettings: () -> Void
    @Environment(\.locale) private var locale

    private var summary: String {
        #if os(macOS)
        MacLocalization.syncStatusDescription(model, locale: locale)
        #else
        model.statusDescription
        #endif
    }

    var body: some View {
        Button(action: onOpenSettings) {
            HStack(spacing: Spacing.sm) {
                Label(summary, systemImage: "exclamationmark.circle")
                Spacer(minLength: Spacing.xs)
                Image(systemName: "chevron.forward").accessibilityHidden(true)
            }
            .font(.subheadline.weight(.medium))
            .frame(minHeight: LayoutMetric.minimumTapTarget)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityHint("打开设置查看同步状态")
        .accessibilityIdentifier("sync.attention")
    }
}

struct SyncRecoverySection: View {
    let model: SyncStatusModel
    @Binding var receipt: String?
    @Environment(\.locale) private var locale

    static func isNeeded(model: SyncStatusModel, receipt: String?) -> Bool {
        model.hasOutstandingChanges || model.isResolving || model.resolutionError != nil || receipt != nil
    }

    var body: some View {
        Section("同步队列") {
            if model.outboxStatus.pendingCount > 0 {
                Label("\(model.outboxStatus.pendingCount) 个条目待上传", systemImage: "arrow.up.circle")
                    .accessibilityIdentifier("sync.queue.pending")
            }
            ForEach(model.outboxStatus.issues) { issue in
                SyncIssueRow(issue: issue, isBusy: model.isSyncing || model.isResolving, onResolve: resolve)
            }
            if !model.outboxStatus.issues.isEmpty, let error = model.errorMessage {
                Label(LocalizedStringKey(error), systemImage: "exclamationmark.circle").foregroundStyle(.secondary)
            }
            if model.isResolving {
                ProgressView("正在处理同步问题…")
            } else if let error = model.resolutionError {
                Label(LocalizedStringKey(error), systemImage: "exclamationmark.circle").foregroundStyle(.secondary)
            } else if let receipt {
                Label(LocalizedStringKey(receipt), systemImage: "checkmark.circle")
                    .foregroundStyle(.secondary)
                    .accessibilityIdentifier("sync.queue.receipt")
            }
        }
    }

    private func resolve(_ issue: VaultOutboxIssue, _ action: VaultOutboxAction) {
        receipt = nil
        Task {
            guard await model.resolve(issue, action: action) else {
                if let error = model.resolutionError { announce(error) }
                return
            }
            let message = switch action {
            case .useServer: "已采用服务器状态。"
            case .keepLocalCopy where issue.kind == .unconfirmedCreate: "已处理同步问题。待上传的副本会显示在队列中。"
            case .keepLocalCopy: "已保留本机副本，等待上传。"
            }
            receipt = message
            announce(message)
        }
    }

    private func announce(_ message: String) {
        #if os(macOS)
        AccessibilityNotification.Announcement(MacLocalization.text(message, locale: locale)).post()
        #else
        AccessibilityNotification.Announcement(message).post()
        #endif
    }
}

private struct SyncIssueRow: View {
    let issue: VaultOutboxIssue
    let isBusy: Bool
    let onResolve: (VaultOutboxIssue, VaultOutboxAction) -> Void
    @State private var confirmation: VaultOutboxIssue?

    var body: some View {
        Button { confirmation = issue } label: {
            HStack(spacing: Spacing.sm) {
                Image(systemName: "exclamationmark.triangle")
                    .foregroundStyle(.secondary)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: Spacing.xxs) {
                    Group {
                        if let name = issue.itemName { Text(name) }
                        else { Text("未命名条目") }
                    }
                    .privacySensitive()
                    Text(Self.title(for: issue.kind)).font(.footnote).foregroundStyle(.secondary)
                }
                .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: Spacing.xs)
                Image(systemName: "chevron.forward")
                    .font(.footnote.weight(.semibold))
                    .foregroundStyle(.secondary)
                    .accessibilityHidden(true)
            }
            #if os(iOS)
            .frame(minHeight: LayoutMetric.minimumTapTarget)
            #endif
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(isBusy)
        .accessibilityIdentifier("sync.issue.\(issue.id)")
        .confirmationDialog("处理同步问题", isPresented: Binding(get: { confirmation != nil }, set: {
            if !$0 { confirmation = nil }
        }), titleVisibility: .visible, presenting: confirmation) { pending in
            if pending.canKeepLocalCopy {
                Button("保留本机副本") { onResolve(pending, .keepLocalCopy) }
                    .accessibilityIdentifier("sync.issue.keepCopy")
            }
            Button(Self.serverAction(for: pending.kind), role: .destructive) { onResolve(pending, .useServer) }
                .accessibilityIdentifier("sync.issue.useServer")
            Button("取消", role: .cancel) {}
        } message: { pending in
            Text(Self.explanation(for: pending))
        }
    }

    private static func title(for kind: VaultOutboxIssue.Kind) -> LocalizedStringKey {
        switch kind {
        case .updateConflict: "条目更改发生冲突"
        case .deleteConflict: "删除未同步"
        case .rejectedCreate: "服务器拒绝创建"
        case .unconfirmedCreate: "创建结果未确认"
        }
    }

    private static func serverAction(for kind: VaultOutboxIssue.Kind) -> LocalizedStringKey {
        switch kind {
        case .updateConflict: "采用服务器状态"
        case .deleteConflict: "取消本机删除"
        case .rejectedCreate, .unconfirmedCreate: "放弃本机条目"
        }
    }

    private static func explanation(for issue: VaultOutboxIssue) -> LocalizedStringKey {
        switch issue.kind {
        case .updateConflict:
            if issue.canKeepLocalCopy {
                "采用服务器状态会舍弃这次本机更改。也可以保留副本，让本机更改成为独立条目，不覆盖服务器上的原条目。"
            } else {
                "采用服务器状态会舍弃这次本机更改。若服务器已删除原条目，本机也会移除它。"
            }
        case .deleteConflict:
            "取消本机的待上传删除操作。服务器上的内容不会更改。"
        case .rejectedCreate:
            if issue.canKeepLocalCopy {
                "可以放弃本机条目，或保留副本并重新排队上传。"
            } else {
                "服务器拒绝了创建请求。放弃只会移除本机条目。"
            }
        case .unconfirmedCreate:
            if issue.canKeepLocalCopy {
                "请先查看服务器是否已有此条目。放弃不会删除服务器上的条目；保留副本将重新上传，可能产生重复条目。"
            } else {
                "请先查看服务器是否已有此条目。放弃不会删除服务器上的条目。"
            }
        }
    }
}
