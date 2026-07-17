// Xcode-only target. Not part of the SPM build.
//
// ExtensionViews — lightweight SwiftUI surfaces for the AutoFill extension. The extension
// deliberately links DesignSystem but none of the heavier UI packages. Content remains on an
// opaque grouped layer; only standard buttons and navigation controls receive the system glass
// treatment when rebuilt for the current Apple platforms.

import SwiftUI
import DesignSystem

// MARK: - Unlock

/// The biometric-unlock prompt shown before vending a credential.
struct ExtensionUnlockView: View {
    let onUnlock: () -> Void
    let onCancel: () -> Void

    @State private var didTrigger = false

    var body: some View {
        ExtensionScaffold {
            VStack(spacing: Spacing.xl) {
                ExtensionBrandHeader(
                    markSize: 72,
                    title: "OpenVault",
                    subtitle: "保险库已锁定"
                )

                OpenVaultCard(
                    cornerRadius: ExtensionMetrics.cardRadius,
                    padding: Spacing.xl
                ) {
                    VStack(spacing: Spacing.md) {
                        ZStack {
                            Circle()
                                .fill(Palette.accent.opacity(0.12))
                            Image(systemName: biometricSystemImage)
                                .font(.system(size: 29, weight: .regular))
                                .foregroundStyle(Palette.accent)
                        }
                        .frame(width: 64, height: 64)
                        .accessibilityHidden(true)

                        Text("使用\(biometricName)解锁")
                            .font(Typography.sectionTitle)
                            .foregroundStyle(Palette.primaryText)

                        Text("验证身份后，OpenVault 才会解密并填充你选择的凭据。")
                            .font(Typography.rowSubtitle)
                            .foregroundStyle(Palette.secondaryText)
                            .multilineTextAlignment(.center)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .frame(maxWidth: .infinity)
                }

                VStack(spacing: Spacing.md) {
                    Button(action: onUnlock) {
                        Label("解锁", systemImage: biometricSystemImage)
                            .font(Typography.action)
                            .frame(maxWidth: .infinity, minHeight: 50)
                    }
                    .buttonStyle(.borderedProminent)
                    .buttonBorderShape(.capsule)

                    Button("取消", role: .cancel, action: onCancel)
                        .font(.body.weight(.semibold))
                        .buttonStyle(.bordered)
                        .buttonBorderShape(.capsule)
                        .frame(minHeight: 44)
                }
            }
        }
        .onAppear {
            // Trigger biometrics immediately; the explicit control remains available for retry
            // and gives VoiceOver users a discoverable action.
            guard !didTrigger else { return }
            didTrigger = true
            onUnlock()
        }
    }

    private var biometricName: String {
        #if os(macOS)
        "触控 ID"
        #else
        "生物识别"
        #endif
    }

    private var biometricSystemImage: String {
        #if os(macOS)
        "touchid"
        #else
        "person.badge.key"
        #endif
    }
}

// MARK: - Credential list (picker)

/// Context shown for a service-identifier request. The rows describe requesting sites only;
/// they are deliberately not treated as credential record IDs. Actual credential choices are
/// supplied by `ASCredentialIdentityStore` through the system password UI.
struct ExtensionCredentialListView: View {
    let serviceIdentifiers: [String]
    let onSelect: (String) -> Void
    let onCancel: () -> Void

    var body: some View {
        ExtensionScaffold(verticalAlignment: .top) {
            VStack(spacing: Spacing.xl) {
                HStack(spacing: Spacing.md) {
                    OpenVaultMark(size: 44)

                    VStack(alignment: .leading, spacing: Spacing.xxs) {
                        Text("选择登录项")
                            .font(Typography.sectionTitle)
                            .foregroundStyle(Palette.primaryText)
                        Text("OpenVault 自动填充")
                            .font(Typography.rowSubtitle)
                            .foregroundStyle(Palette.secondaryText)
                    }

                    Spacer(minLength: Spacing.sm)

                    Button("取消", role: .cancel, action: onCancel)
                        .buttonStyle(.bordered)
                        .buttonBorderShape(.capsule)
                }

                if uniqueServiceIdentifiers.isEmpty {
                    OpenVaultCard(
                        cornerRadius: ExtensionMetrics.cardRadius,
                        padding: Spacing.xl
                    ) {
                        VStack(spacing: Spacing.md) {
                            Image(systemName: "key.horizontal")
                                .font(.system(size: 30, weight: .regular))
                                .foregroundStyle(Palette.accent)
                                .accessibilityHidden(true)
                            Text("没有匹配的登录项")
                                .font(.headline)
                                .foregroundStyle(Palette.primaryText)
                            Text("请先在 OpenVault 中保存并同步登录信息，然后再次尝试自动填充。")
                                .font(Typography.rowSubtitle)
                                .foregroundStyle(Palette.secondaryText)
                                .multilineTextAlignment(.center)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        .frame(maxWidth: .infinity)
                    }
                } else {
                    OpenVaultCard(
                        cornerRadius: ExtensionMetrics.cardRadius,
                        padding: 0
                    ) {
                        VStack(spacing: 0) {
                            ForEach(Array(uniqueServiceIdentifiers.enumerated()), id: \.offset) { index, identifier in
                                HStack(spacing: Spacing.md) {
                                    BrandBadge(identifier, diameter: 32)

                                    VStack(alignment: .leading, spacing: Spacing.xxs) {
                                        Text(displayName(for: identifier))
                                            .font(Typography.rowTitle)
                                            .foregroundStyle(Palette.primaryText)
                                            .lineLimit(1)
                                        Text("系统正在请求此站点的登录项")
                                            .font(Typography.rowSubtitle)
                                            .foregroundStyle(Palette.secondaryText)
                                            .lineLimit(1)
                                    }

                                    Spacer(minLength: Spacing.sm)

                                    Image(systemName: "safari")
                                        .font(.system(size: 18, weight: .regular))
                                        .foregroundStyle(Palette.tertiaryText)
                                }
                                .padding(.horizontal, Spacing.lg)
                                .frame(minHeight: 60)
                                .accessibilityElement(children: .combine)

                                if index < uniqueServiceIdentifiers.count - 1 {
                                    Divider()
                                        .padding(.leading, 60)
                                }
                            }
                        }
                    }
                }

                Label("登录项由系统密码建议安全提供", systemImage: "lock.shield")
                    .font(Typography.caption)
                    .foregroundStyle(Palette.tertiaryText)
            }
        }
    }

    private var uniqueServiceIdentifiers: [String] {
        var seen = Set<String>()
        return serviceIdentifiers.compactMap { rawValue in
            let value = rawValue.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !value.isEmpty, seen.insert(value).inserted else { return nil }
            return value
        }
    }

    private func displayName(for identifier: String) -> String {
        if let host = URL(string: identifier)?.host, !host.isEmpty {
            return host
        }
        if let host = URL(string: "https://\(identifier)")?.host, !host.isEmpty {
            return host
        }
        return identifier
    }

}

// MARK: - Configuration

/// The onboarding screen shown when the user enables the provider in Settings → Passwords.
struct ConfigurationView: View {
    let onDone: () -> Void

    var body: some View {
        ExtensionScaffold {
            VStack(spacing: Spacing.xl) {
                ExtensionBrandHeader(
                    markSize: 72,
                    title: "OpenVault 自动填充",
                    subtitle: "已准备就绪"
                )

                OpenVaultCard(
                    cornerRadius: ExtensionMetrics.cardRadius,
                    padding: Spacing.xl
                ) {
                    VStack(alignment: .leading, spacing: Spacing.lg) {
                        ConfigurationStep(
                            systemImage: "checkmark.shield.fill",
                            tint: Palette.success,
                            title: "安全填充已启用",
                            detail: "密码、通行密钥和验证码会在需要时由 OpenVault 提供。"
                        )
                        Divider()
                        ConfigurationStep(
                            systemImage: "arrow.triangle.2.circlepath",
                            tint: Palette.indigo,
                            title: "保持保险库同步",
                            detail: "打开 OpenVault 登录并同步后，最新登录项会自动出现在系统建议中。"
                        )
                        Divider()
                        ConfigurationStep(
                            systemImage: "lock.fill",
                            tint: Palette.accent,
                            title: "按需解密",
                            detail: "扩展只读取本机保险库，并在填充前验证系统生物识别。"
                        )
                    }
                }

                Button(action: onDone) {
                    Text("完成")
                        .font(Typography.action)
                        .frame(maxWidth: .infinity, minHeight: 50)
                }
                .buttonStyle(.borderedProminent)
                .buttonBorderShape(.capsule)
            }
        }
    }
}

// MARK: - Shared extension chrome

private enum ExtensionMetrics {
    static let maximumContentWidth: CGFloat = 460

    #if os(macOS)
    static let cardRadius = CornerRadius.macCard
    #else
    static let cardRadius = CornerRadius.iPhoneCard
    #endif
}

private struct ExtensionScaffold<Content: View>: View {
    let verticalAlignment: Alignment
    private let content: Content

    init(
        verticalAlignment: Alignment = .center,
        @ViewBuilder content: () -> Content
    ) {
        self.verticalAlignment = verticalAlignment
        self.content = content()
    }

    var body: some View {
        GeometryReader { proxy in
            ZStack {
                Palette.groupedBackground
                    .ignoresSafeArea()

                ScrollView {
                    content
                        .frame(maxWidth: ExtensionMetrics.maximumContentWidth)
                        .frame(
                            maxWidth: .infinity,
                            minHeight: max(0, proxy.size.height - Spacing.xxl),
                            alignment: verticalAlignment
                        )
                        .padding(.horizontal, Spacing.xl)
                        .padding(.vertical, Spacing.lg)
                }
                .scrollIndicators(.hidden)
            }
        }
        .tint(Palette.accent)
    }
}

private struct ExtensionBrandHeader: View {
    let markSize: CGFloat
    let title: String
    let subtitle: String

    var body: some View {
        VStack(spacing: Spacing.sm) {
            OpenVaultMark(size: markSize)
            Text(title)
                .font(.title2.weight(.bold))
                .foregroundStyle(Palette.primaryText)
                .multilineTextAlignment(.center)
            Text(subtitle)
                .font(Typography.rowSubtitle)
                .foregroundStyle(Palette.secondaryText)
                .multilineTextAlignment(.center)
        }
    }
}

private struct ConfigurationStep: View {
    let systemImage: String
    let tint: Color
    let title: String
    let detail: String

    var body: some View {
        HStack(alignment: .top, spacing: Spacing.md) {
            Image(systemName: systemImage)
                .font(.system(size: 20, weight: .semibold))
                .foregroundStyle(tint)
                .frame(width: 28, height: 28)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: Spacing.xs) {
                Text(title)
                    .font(.body.weight(.semibold))
                    .foregroundStyle(Palette.primaryText)
                Text(detail)
                    .font(Typography.rowSubtitle)
                    .foregroundStyle(Palette.secondaryText)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}
