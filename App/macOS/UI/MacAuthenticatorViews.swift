import SwiftUI
import Accessibility
import DesignSystem
import Generators

struct MacAuthenticatorListView: View {
    let entries: [MacTOTPEntry]
    @Binding var selection: String?
    var isFiltering = false
    let onNewItem: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("\(entries.count) 个账户").font(.caption).foregroundStyle(.secondary)
                .padding(.horizontal, 16).padding(.vertical, 8)
            TimelineView(.periodic(from: .now, by: 1)) { context in
                List(entries, selection: $selection) { entry in
                    MacAuthenticatorRow(entry: entry, date: context.date).tag(entry.id)
                }
                .listStyle(.inset)
            }
            .overlay {
                if entries.isEmpty {
                    if isFiltering { ContentUnavailableView.search }
                    else {
                        ContentUnavailableView("没有验证码", systemImage: "clock", description: Text("为登录条目添加验证器密钥。"))
                    }
                }
            }
        }
        .navigationTitle("验证码")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button("新建验证码", systemImage: "plus", action: onNewItem).help("新建带验证码的登录条目")
            }
        }
    }
}

private struct MacAuthenticatorRow: View {
    let entry: MacTOTPEntry
    let date: Date

    var body: some View {
        let code = OTPRingMath.formatCode(TOTP.code(for: entry.configuration, at: date))
        let remaining = TOTP.secondsRemaining(for: entry.configuration, at: date)
        HStack(spacing: 10) {
            BrandBadge(entry.cipher.name, diameter: 30)
            VStack(alignment: .leading, spacing: 2) {
                Text(entry.cipher.name.nilIfBlank ?? "未命名条目").font(.body.weight(.semibold))
                Text(code).font(.system(size: 15, weight: .semibold, design: .monospaced)).privacySensitive()
            }.lineLimit(1)
            Spacer(minLength: 4)
            Text("\(remaining) 秒").font(.caption.monospacedDigit()).foregroundStyle(.secondary)
        }
        .frame(minHeight: 50).contentShape(Rectangle())
        .accessibilityElement(children: .combine)
    }
}

struct MacAuthenticatorDetailView: View {
    let entry: MacTOTPEntry
    var onCopy: () -> Void = {}
    let onShowLinkedItem: () -> Void
    @State private var codeReceipt: UUID?

    init(entry: MacTOTPEntry, onCopy: @escaping () -> Void = {}, onShowLinkedItem: @escaping () -> Void) {
        self.entry = entry
        self.onCopy = onCopy
        self.onShowLinkedItem = onShowLinkedItem
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 14) {
                    BrandBadge(entry.cipher.name, diameter: 54)
                    VStack(alignment: .leading, spacing: 3) {
                        Text(entry.cipher.name.nilIfBlank ?? "未命名条目")
                            .font(.system(size: 26, weight: .bold)).accessibilityAddTraits(.isHeader)
                        Text("\(entry.configuration.isSteam ? "Steam Guard" : "TOTP") · \(entry.configuration.digits) 位 · 每 \(entry.configuration.period) 秒更新")
                            .font(.subheadline).foregroundStyle(.secondary)
                    }
                }.padding(.bottom, 10)
                codeCard
                informationCard
            }
            .frame(maxWidth: 680, alignment: .leading).padding(24).frame(maxWidth: .infinity, alignment: .top)
        }
        .focusedSceneValue(\.macItemCommands, MacItemCommandActions(edit: nil, info: nil, username: nil, password: nil, code: copyCode))
        .task(id: codeReceipt) {
            guard codeReceipt != nil else { return }
            do { try await Task.sleep(for: .milliseconds(1600)) } catch { return }
            codeReceipt = nil
        }
    }

    private var codeCard: some View {
        Button(action: copyCode) {
            TimelineView(.periodic(from: .now, by: 1)) { context in
                let raw = TOTP.code(for: entry.configuration, at: context.date)
                let seconds = TOTP.secondsRemaining(for: entry.configuration, at: context.date)
                OpenVaultCard(cornerRadius: CornerRadius.macCard, padding: 20) {
                    VStack(alignment: .leading, spacing: 5) {
                        HStack(spacing: 10) {
                            Text(OTPRingMath.formatCode(raw)).font(.system(size: 44, weight: .semibold, design: .monospaced))
                                .lineLimit(1).minimumScaleFactor(0.65).privacySensitive()
                            if codeReceipt != nil { InlineCopyIndicator() }
                        }
                        Text("\(seconds) 秒后更新").font(.callout.monospacedDigit()).foregroundStyle(.secondary)
                    }
                }
                .overlay(alignment: .bottom) {
                    OTPCountdownBar(secondsRemaining: seconds, period: entry.configuration.period)
                }
                .clipShape(RoundedRectangle(cornerRadius: CornerRadius.macCard))
                .contentShape(Rectangle())
            }
        }
        .buttonStyle(.plain).help("拷贝当前验证码").accessibilityLabel("拷贝验证码")
        .accessibilityValue(codeReceipt == nil ? "" : "已拷贝")
    }

    private func copyCode() {
        MacClipboard.copy(TOTP.code(for: entry.configuration, at: .now))
        onCopy()
        codeReceipt = UUID()
        AccessibilityNotification.Announcement("已拷贝").post()
    }

    private var informationCard: some View {
        OpenVaultCard(cornerRadius: CornerRadius.macCard, padding: 0) {
            VStack(alignment: .leading, spacing: 0) {
                if let account = entry.cipher.login?.username?.nilIfBlank {
                    InlineCopyButton(action: { MacClipboard.copy(account); onCopy() }) { copied in
                        labeledRow("账户") {
                            HStack {
                                Text(account).privacySensitive()
                                if copied { InlineCopyIndicator() }
                            }
                        }
                    }.buttonStyle(.plain).accessibilityLabel("拷贝账户")
                    Divider().padding(.leading, 14)
                }
                if let website = entry.website, let url = macWebsiteURL(website) {
                    labeledRow("网站") { Link(destination: url) { Label(url.host ?? website, systemImage: "arrow.up.right") } }
                    Divider().padding(.leading, 14)
                }
                Button(action: onShowLinkedItem) {
                    labeledRow("所属登录项") { Label(entry.cipher.name, systemImage: "chevron.forward").foregroundStyle(.tint) }
                }.buttonStyle(.plain)
            }
        }
    }

    private func labeledRow<Content: View>(_ title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            content()
        }
        .padding(.horizontal, 14).padding(.vertical, 7)
        .frame(maxWidth: .infinity, minHeight: 44, alignment: .leading).contentShape(Rectangle())
    }
}
