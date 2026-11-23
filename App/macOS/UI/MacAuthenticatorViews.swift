import SwiftUI
import Accessibility
import DesignSystem
import Generators
import UIShared

@MainActor @Observable
final class MacCodeClock {
    var date = Date.now
}

struct MacAuthenticatorListView: View {
    let entries: [MacTOTPEntry]
    let clock: MacCodeClock
    let model: VaultListModel
    @Binding var selection: String?
    var isFiltering = false
    let onNewItem: () -> Void
    let onRetry: () -> Void
    var snapshotRevealed = true
    var now: () -> Date = { .now }
    var copy: @MainActor (String) -> Bool = MacClipboard.copyItem
    @FocusState private var listFocused: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                if model.canShowMacSnapshot {
                    Text(isFiltering ? "\(entries.count) 个结果" : "\(entries.count) 个账户")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Button("新建验证码", systemImage: "plus", action: onNewItem)
                    .labelStyle(.iconOnly).buttonStyle(.bordered).buttonBorderShape(.circle)
                    .help("新建带验证码的登录条目")
            }
            .padding(.horizontal, 16).padding(.vertical, 6)
            List(entries, selection: $selection) { entry in
                MacAuthenticatorRow(entry: entry, date: clock.date, selected: selection == entry.id) {
                    selection = entry.id
                    listFocused = true
                    return copy(TOTP.code(for: entry.configuration, at: now()))
                }
                .listRowSeparator(.hidden).tag(entry.id)
            }
            .listStyle(.inset)
            .focused($listFocused)
            .macVaultSnapshotReveal(snapshotRevealed)
            .overlay {
                if !model.canShowMacSnapshot {
                    MacVaultReadStatus(model: model, onRetry: onRetry)
                } else if entries.isEmpty {
                    if isFiltering { ContentUnavailableView.search }
                    else {
                        ContentUnavailableView("没有验证码", systemImage: "clock", description: Text("为登录条目添加验证器密钥。"))
                    }
                }
            }
        }
        .navigationTitle("Verification codes")
    }
}

struct MacCodeRowReading {
    let grouped: String
    let remaining: Int

    init(_ entry: MacTOTPEntry, at date: Date) {
        grouped = OTPRingMath.formatCode(TOTP.code(for: entry.configuration, at: date))
        remaining = TOTP.secondsRemaining(for: entry.configuration, at: date)
    }

    func warns(whenSelected selected: Bool) -> Bool { !selected && remaining <= 5 }
}

private struct MacAuthenticatorRow: View {
    let entry: MacTOTPEntry
    let date: Date
    let selected: Bool
    let activate: () -> Bool
    @Environment(\.locale) private var locale

    var body: some View {
        let title = entry.cipher.name.nilIfBlank ?? MacLocalization.text("Untitled item", locale: locale)
        let reading = MacCodeRowReading(entry, at: date)
        InlineCopyButton(copy: activate) { copied in
            HStack(spacing: 10) {
                MacVaultItemBadge(entry.cipher, diameter: 30)
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).font(.body.weight(.semibold))
                    Text(reading.grouped).font(.system(size: 15, weight: .semibold, design: .monospaced))
                        .foregroundColor(reading.warns(whenSelected: selected) ? Palette.warning : nil).privacySensitive()
                }.lineLimit(1)
                Spacer(minLength: 4)
                OTPRowStatus(seconds: reading.remaining, copied: copied, showsSecondsNormally: true, font: .caption, alignment: .trailing)
            }
            .frame(minHeight: 50)
        }
        .buttonStyle(.plain).focusable(false)
        .accessibilityLabel(Text("\(title) 验证码，剩余 \(reading.remaining) 秒"))
        .accessibilityHint("选中并拷贝当前验证码")
        .accessibilityIdentifier("mac.code.\(entry.id)")
    }
}

struct MacAuthenticatorDetailView: View {
    let entry: MacTOTPEntry
    let clock: MacCodeClock
    var onCopy: () -> Void = {}
    let onShowLinkedItem: () -> Void
    @State private var codeReceipt: UUID?
    @Environment(\.locale) private var locale

    init(entry: MacTOTPEntry, clock: MacCodeClock, onCopy: @escaping () -> Void = {}, onShowLinkedItem: @escaping () -> Void) {
        self.entry = entry
        self.clock = clock
        self.onCopy = onCopy
        self.onShowLinkedItem = onShowLinkedItem
    }

    var body: some View {
        MacDetailColumn {
            HStack(spacing: 16) {
                MacVaultItemBadge(entry.cipher, diameter: 64)
                VStack(alignment: .leading, spacing: 3) {
                    Text(entry.cipher.name.nilIfBlank ?? MacLocalization.text("Untitled item", locale: locale))
                        .font(.system(size: 26, weight: .bold)).accessibilityAddTraits(.isHeader)
                    Text("\(entry.configuration.isSteam ? "Steam Guard" : "TOTP") · \(entry.configuration.digits) 位 · 每 \(entry.configuration.period) 秒更新")
                        .foregroundStyle(.secondary)
                }
            }.padding(.bottom, 12)
            codeCard
            informationCard
        }
        .focusedSceneValue(\.macItemCommands, MacItemCommandActions(edit: nil, info: nil, username: nil, password: nil, code: copyCode))
        .task(id: codeReceipt) {
            guard codeReceipt != nil else { return }
            do { try await Task.sleep(for: .milliseconds(1600)) } catch { return }
            codeReceipt = nil
        }
    }

    private var codeCard: some View {
        let raw = TOTP.code(for: entry.configuration, at: clock.date)
        let seconds = TOTP.secondsRemaining(for: entry.configuration, at: clock.date)
        return Button(action: copyCode) {
            MacDetailCard {
                VStack(alignment: .leading, spacing: 5) {
                    HStack(spacing: 10) {
                        Text(OTPRingMath.formatCode(raw)).font(.system(size: 44, weight: .semibold, design: .monospaced))
                            .lineLimit(1).minimumScaleFactor(0.65).privacySensitive()
                        Spacer(minLength: 0)
                        if codeReceipt != nil { InlineCopyIndicator() }
                    }
                    Text("\(seconds) 秒后更新").font(.callout.monospacedDigit()).foregroundStyle(.secondary)
                }
                .padding(20)
            }
            .overlay(alignment: .bottom) {
                OTPCountdownBar(secondsRemaining: seconds, period: entry.configuration.period)
            }
            .clipShape(RoundedRectangle(cornerRadius: CornerRadius.macCard))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain).help("拷贝当前验证码")
        .accessibilityLabel(Text(verbatim: MacLocalization.text("Copy verification code", locale: locale)))
        .accessibilityValue(codeReceipt == nil ? MacLocalization.format("Updates in %lld seconds", seconds, locale: locale) : MacLocalization.text("Copied", locale: locale))
        .accessibilityHint(Text("剩余 \(seconds) 秒"), isEnabled: codeReceipt != nil && seconds <= 5)
    }

    private func copyCode() {
        guard copyItemData(TOTP.code(for: entry.configuration, at: .now)) else { codeReceipt = nil; return }
        codeReceipt = UUID()
        AccessibilityNotification.Announcement(MacLocalization.text("Copied", locale: locale)).post()
    }

    private func copyItemData(_ value: String) -> Bool {
        guard MacClipboard.copyItem(value) else { return false }
        onCopy()
        return true
    }

    private var informationCard: some View {
        MacDetailCard {
            VStack(alignment: .leading, spacing: 0) {
                if let account = entry.cipher.login?.username?.nilIfBlank {
                    InlineCopyButton(copy: { copyItemData(account) }) { copied in
                        MacDetailRow("账户") {
                            HStack {
                                Text(account).privacySensitive()
                                if copied { InlineCopyIndicator() }
                            }
                        }
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel(Text(verbatim: MacLocalization.text("Copy account", locale: locale)))
                    Divider().padding(.leading, 16)
                }
                if let website = entry.website, let url = macWebsiteURL(website) {
                    MacDetailRow("网站") {
                        Link(destination: url) { linkLabel(url.host ?? website, symbol: "arrow.up.right") }
                    }
                    Divider().padding(.leading, 16)
                }
                Button(action: onShowLinkedItem) {
                    MacDetailRow("所属登录项") { linkLabel(entry.cipher.name, symbol: "chevron.forward").foregroundStyle(.tint) }
                }.buttonStyle(.plain)
            }
        }
    }

    private func linkLabel(_ title: String, symbol: String) -> some View {
        HStack(spacing: Spacing.xs) {
            Text(title)
            Image(systemName: symbol).font(.caption).accessibilityHidden(true)
        }
    }

}
