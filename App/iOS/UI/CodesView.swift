import SwiftUI
import UIShared
import DesignSystem
import VaultRepository
import Generators

@available(iOS 27.0, *)
struct CodesView: View {
    let model: VaultListModel
    let vault: VaultService
    let onAdd: () -> Void

    @Environment(\.horizontalSizeClass) private var sizeClass
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize
    @ScaledMetric(relativeTo: .title) private var tileWidth: CGFloat = 235

    init(model: VaultListModel, vault: VaultService, onAdd: @escaping () -> Void) {
        self.model = model
        self.vault = vault
        self.onAdd = onAdd
    }

    private var entries: [CodeEntry] {
        model.items.compactMap { cipher in
            cipher.openVaultTOTPConfiguration.map { CodeEntry(cipher: cipher, configuration: $0) }
        }.sorted { $0.cipher.openVaultName.localizedStandardCompare($1.cipher.openVaultName) == .orderedAscending }
    }

    var body: some View {
        let visibleEntries = entries
        ScrollView {
            if !visibleEntries.isEmpty {
                if sizeClass == .regular {
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: dynamicTypeSize.isAccessibilitySize ? 300 : tileWidth), spacing: Spacing.lg)], spacing: Spacing.lg) {
                        ForEach(visibleEntries) { entry in
                            CodeEntryButton(entry: entry, vault: vault, isTile: true)
                                .background(Palette.contentBackground)
                                .clipShape(.rect(cornerRadius: 22))
                        }
                    }
                    .padding(.horizontal, Spacing.xl)
                    .frame(maxWidth: 1_200)
                    .frame(maxWidth: .infinity)
                } else {
                    LazyVStack(spacing: 0) {
                        ForEach(visibleEntries) { entry in
                            CodeEntryButton(entry: entry, vault: vault, isTile: false)
                        }
                    }
                    .background(Palette.contentBackground)
                    .clipShape(.rect(cornerRadius: CornerRadius.iPhoneCard))
                    .padding(.horizontal, Spacing.lg)
                }
            }
        }
        .safeAreaPadding(.vertical, Spacing.sm)
        .background(Palette.groupedBackground)
        .navigationTitle("验证码")
        .toolbarTitleDisplayMode(sizeClass == .regular ? .large : .inlineLarge)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button("添加带验证码的登录项", systemImage: "plus", action: onAdd)
                    .accessibilityIdentifier("codes.add")
            }
        }
        .overlay {
            if visibleEntries.isEmpty {
                if model.errorMessage != nil {
                    ContentUnavailableView {
                        Label("无法读取验证码", systemImage: "exclamationmark.circle")
                    } actions: {
                        Button("重试") {
                            Task {
                                if model.hasLoadedContent { await model.refresh() }
                                else { await model.load() }
                            }
                        }
                    }
                } else if !model.canPresentCounts {
                    ProgressView().accessibilityLabel("正在载入")
                } else {
                    ContentUnavailableView("暂无验证码", systemImage: "clock",
                                           description: Text("为登录项添加验证器密钥后，验证码将显示在这里。"))
                }
            }
        }
        .refreshable { await model.refresh() }
    }
}

private struct CodeEntry: Identifiable {
    let cipher: PlaintextCipher
    let configuration: TOTPConfiguration

    var id: String { cipher.openVaultID }
}

@available(iOS 27.0, *)
private struct CodeEntryButton: View {
    let entry: CodeEntry
    let vault: VaultService
    let isTile: Bool

    @Environment(\.dynamicTypeSize) private var dynamicTypeSize
    @Environment(\.accessibilityDifferentiateWithoutColor) private var differentiateWithoutColor
    @ScaledMetric(relativeTo: .title) private var codeSize: CGFloat = 30
    @ScaledMetric(relativeTo: .title) private var tileCodeSize: CGFloat = 32

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            let raw = TOTP.code(for: entry.configuration, at: context.date)
            let seconds = TOTP.secondsRemaining(for: entry.configuration, at: context.date)
            InlineCopyButton(action: copy) { copied in
                VStack(alignment: .leading, spacing: 0) {
                    if isTile {
                        VStack(alignment: .leading, spacing: Spacing.md) {
                            HStack(spacing: Spacing.sm) {
                                BrandBadge(entry.cipher.openVaultName, diameter: 34)
                                VStack(alignment: .leading, spacing: Spacing.xxs) { name; account }
                            }
                            codeLine(raw, seconds: seconds, copied: copied)
                        }
                        .padding(Spacing.lg)
                    } else {
                        let layout = dynamicTypeSize.isAccessibilitySize
                            ? AnyLayout(VStackLayout(alignment: .leading, spacing: Spacing.sm))
                            : AnyLayout(HStackLayout(spacing: Spacing.md))
                        layout {
                            BrandBadge(entry.cipher.openVaultName, diameter: 40)
                            VStack(alignment: .leading, spacing: Spacing.xs) {
                                ViewThatFits(in: .horizontal) {
                                    HStack(spacing: Spacing.xs) { name; account }
                                    VStack(alignment: .leading, spacing: 0) { name; account }
                                }
                                codeLine(raw, seconds: seconds, copied: copied)
                            }
                        }
                        .padding(.horizontal, Spacing.lg)
                        .padding(.vertical, Spacing.sm)
                        .frame(minHeight: 79)
                    }
                    OTPCountdownBar(secondsRemaining: seconds, period: entry.configuration.period)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel(Text(accessibilityTitle))
            .accessibilityHint("剩余 \(seconds) 秒")
            .accessibilityIdentifier("codes.copy.\(entry.id)")
        }
    }

    private var name: some View {
        Text(entry.cipher.openVaultName).font(.subheadline.weight(.semibold))
    }

    private var accessibilityTitle: String {
        let name = entry.cipher.openVaultName
        if let account = entry.cipher.login?.username, !account.isEmpty { return "拷贝\(name)的验证码，\(account)" }
        return "拷贝\(name)的验证码"
    }

    private func copy() {
        Clipboard.copy(TOTP.code(for: entry.configuration, at: .now))
        if let id = entry.cipher.id { Task { await vault.recordUse(id: id) } }
    }

    @ViewBuilder private var account: some View {
        if let user = entry.cipher.login?.username, !user.isEmpty {
            Text(user).font(isTile ? .footnote : .subheadline).foregroundStyle(.secondary)
                .privacySensitive()
        }
    }

    @ViewBuilder private func codeLine(_ raw: String, seconds: Int, copied: Bool) -> some View {
        let value = VaultCodeText(value: raw, font: .system(size: isTile ? tileCodeSize : codeSize,
                                                            weight: .semibold, design: .monospaced))
        let status = OTPRowStatus(seconds: seconds, copied: copied, showsSecondsNormally: differentiateWithoutColor)
        if dynamicTypeSize.isAccessibilitySize {
            VStack(alignment: .leading, spacing: Spacing.xs) {
                value
                ZStack(alignment: .leading) {
                    InlineCopyIndicator().hidden()
                    status
                }
                .fixedSize(horizontal: false, vertical: true)
            }
            .fixedSize(horizontal: false, vertical: true)
        } else {
            ViewThatFits(in: .horizontal) {
                HStack { value; Spacer(minLength: Spacing.xs); status }
                VStack(alignment: .leading) { value; status }
            }
        }
    }
}
