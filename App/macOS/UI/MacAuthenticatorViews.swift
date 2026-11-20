import SwiftUI
import DesignSystem
import Generators

struct MacAuthenticatorListView: View {
    let entries: [MacTOTPEntry]
    @Binding var selection: String?
    let onNewItem: () -> Void

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            List(entries, selection: $selection) { entry in
                MacAuthenticatorRow(entry: entry, date: context.date)
                    .tag(entry.id)
            }
            .listStyle(.inset)
        }
        .overlay {
            if entries.isEmpty {
                ContentUnavailableView(
                    "没有验证码", systemImage: "clock",
                    description: Text("为登录条目设置验证器密钥后，动态验证码会显示在这里。")
                )
            }
        }
        .navigationTitle("验证码")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button("新建条目", systemImage: "plus", action: onNewItem)
                    .help("新建带验证码的登录条目")
            }
        }
    }
}

private struct MacAuthenticatorRow: View {
    let entry: MacTOTPEntry
    let date: Date

    var body: some View {
        let code = OTPRingMath.formatCode(TOTP.code(for: entry.configuration, at: date))
        let seconds = TOTP.secondsRemaining(for: entry.configuration, at: date)
        HStack(spacing: Spacing.sm) {
            BrandBadge(entry.cipher.name, diameter: 30)
            VStack(alignment: .leading, spacing: Spacing.xxs) {
                Text(entry.cipher.name.nilIfBlank ?? "未命名条目")
                    .font(.headline)
                Text(entry.account)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            .lineLimit(1)
            Spacer(minLength: Spacing.xs)
            Text(code)
                .font(.system(.body, design: .monospaced))
                .monospacedDigit()
                .fixedSize()
                .privacySensitive()
                .accessibilityLabel("验证码 \(code)")
            CountdownRing(progress: OTPRingMath.progress(secondsRemaining: seconds, period: entry.configuration.period),
                          size: 14, lineWidth: 2, tint: .primary)
        }
        .frame(minHeight: 40)
        .accessibilityElement(children: .combine)
    }
}

struct MacAuthenticatorDetailView: View {
    let entry: MacTOTPEntry
    let onShowLinkedItem: () -> Void

    @State private var copiedMessage: String?
    @State private var toastID: UUID?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Spacing.lg) {
                HStack(spacing: Spacing.md) {
                    BrandBadge(entry.cipher.name, diameter: 50)
                    VStack(alignment: .leading, spacing: Spacing.xxs) {
                        Text(entry.cipher.name.nilIfBlank ?? "未命名条目")
                            .font(.title2.bold())
                        Text("验证码 · TOTP · \(entry.configuration.period) 秒周期")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                }

                codeCard
                informationCard
                Text("验证码在本机离线生成")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .padding(Spacing.xl)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(MacOpenVaultStyle.detail)
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button("拷贝验证码", systemImage: "doc.on.doc") {
                    copy(TOTP.code(for: entry.configuration, at: .now), message: "已拷贝验证码")
                }
                .help("拷贝当前验证码")
            }
        }
        .copyToast(copiedMessage)
        .task(id: toastID) {
            guard toastID != nil else { return }
            do { try await Task.sleep(for: .seconds(1.6)) } catch { return }
            copiedMessage = nil
        }
    }

    private var codeCard: some View {
        OpenVaultCard(cornerRadius: CornerRadius.macCard) {
            TimelineView(.periodic(from: .now, by: 1)) { context in
                let code = OTPRingMath.formatCode(TOTP.code(for: entry.configuration, at: context.date))
                let seconds = TOTP.secondsRemaining(for: entry.configuration, at: context.date)
                let progress = OTPRingMath.progress(secondsRemaining: seconds, period: entry.configuration.period)
                VStack(spacing: Spacing.sm) {
                    HStack(spacing: Spacing.md) {
                        Text(code)
                            .font(.system(.largeTitle, design: .monospaced).weight(.medium))
                            .monospacedDigit()
                            .privacySensitive()
                            .accessibilityLabel("当前验证码 \(code)")
                        CountdownRing(progress: progress, size: 26, tint: MacOpenVaultStyle.totp)
                    }
                    Text("\(seconds) 秒后更新")
                        .font(.subheadline)
                        .monospacedDigit()
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, minHeight: 80)
            }
        }
    }

    private var informationCard: some View {
        OpenVaultCard(cornerRadius: CornerRadius.macCard, padding: 0) {
            VStack(spacing: 0) {
                valueRow("账户", value: entry.account)
                Divider().padding(.leading, Spacing.lg)
                if let website = entry.website {
                    valueRow("网站", value: website)
                    Divider().padding(.leading, Spacing.lg)
                }
                Button(action: onShowLinkedItem) {
                    HStack {
                        Text("已关联登录项")
                        Spacer()
                        Text(entry.cipher.name.nilIfBlank ?? "未命名条目")
                            .lineLimit(1)
                            .foregroundStyle(.secondary)
                        Image(systemName: "chevron.forward")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .padding(.horizontal, Spacing.lg)
                    .frame(minHeight: 44)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
            }
        }
    }

    private func valueRow(_ label: String, value: String) -> some View {
        HStack {
            Text(label)
            Spacer()
            Text(value)
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
            Button("拷贝\(label)", systemImage: "doc.on.doc") {
                copy(value, message: "已拷贝\(label)")
            }
            .labelStyle(.iconOnly)
            .buttonStyle(.borderless)
            .help("拷贝\(label)")
        }
        .padding(.horizontal, Spacing.lg)
        .frame(minHeight: 44)
    }

    private func copy(_ value: String, message: String) {
        MacClipboard.copy(value)
        copiedMessage = message
        toastID = UUID()
    }
}
