// Xcode-only target. Not part of the SPM build.
//
// ExtensionViews — lightweight SwiftUI surfaces for the AutoFill extension. The extension
// deliberately links DesignSystem but none of the heavier UI packages. Content remains on an
// opaque grouped layer; only standard buttons and navigation controls receive the system glass
// treatment when rebuilt for the current Apple platforms.

import SwiftUI
import DesignSystem
import VaultReader

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

/// A bounded manual picker backed by non-secret metadata from `VaultReader`. Its async loader
/// performs biometric unlock before reading the encrypted cache; passwords, TOTP seeds, and
/// passkey private keys are decrypted only after the user selects one row.
@MainActor
struct ExtensionCredentialListView: View {
    let serviceIdentifiers: [String]
    let loadCandidates: () async throws -> [CredentialCandidate]
    let onSelect: (CredentialCandidate) -> Void
    let onCancel: () -> Void

    @State private var candidates: [CredentialCandidate] = []
    @State private var isLoading = true
    @State private var didStartLoading = false
    @State private var isCompleting = false
    @State private var loadFailed = false

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
                        .disabled(isCompleting)
                }

                Text(prompt)
                    .font(Typography.rowSubtitle)
                    .foregroundStyle(Palette.secondaryText)
                    .multilineTextAlignment(.center)

                candidateContent

                Label("只会解密你选择的登录项", systemImage: "lock.shield")
                    .font(Typography.caption)
                    .foregroundStyle(Palette.tertiaryText)
            }
        }
        .task {
            guard !didStartLoading else { return }
            didStartLoading = true
            await reload()
        }
    }

    private var prompt: String {
        guard let first = serviceIdentifiers.first, !first.isEmpty else {
            return "选择一个凭据进行填充。"
        }
        return "选择用于 \(displayName(for: first)) 的凭据。"
    }

    @ViewBuilder
    private var candidateContent: some View {
        if isLoading {
            statusCard {
                ProgressView("正在解锁保险库…")
            }
        } else if loadFailed {
            statusCard {
                Image(systemName: "lock.trianglebadge.exclamationmark")
                    .font(.system(size: 30, weight: .regular))
                    .foregroundStyle(Palette.warning)
                    .accessibilityHidden(true)
                Text("无法打开保险库")
                    .font(.headline)
                    .foregroundStyle(Palette.primaryText)
                Text("请确认 OpenVault 已登录、同步并启用生物识别，然后重试。")
                    .font(Typography.rowSubtitle)
                    .foregroundStyle(Palette.secondaryText)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
                Button("重试") {
                    Task { await reload() }
                }
                .buttonStyle(.bordered)
                .buttonBorderShape(.capsule)
            }
        } else if candidates.isEmpty {
            statusCard {
                Image(systemName: "key.slash")
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
        } else {
            OpenVaultCard(
                cornerRadius: ExtensionMetrics.cardRadius,
                padding: 0
            ) {
                LazyVStack(spacing: 0) {
                    ForEach(Array(candidates.enumerated()), id: \.offset) { index, candidate in
                        Button {
                            guard !isCompleting else { return }
                            isCompleting = true
                            onSelect(candidate)
                        } label: {
                            candidateRow(candidate)
                        }
                        .buttonStyle(.plain)
                        .disabled(isCompleting)

                        if index < candidates.count - 1 {
                            Divider()
                                .padding(.leading, 60)
                        }
                    }
                }
            }
        }
    }

    private func statusCard<Content: View>(
        @ViewBuilder content: () -> Content
    ) -> some View {
        OpenVaultCard(
            cornerRadius: ExtensionMetrics.cardRadius,
            padding: Spacing.xl
        ) {
            VStack(spacing: Spacing.md) {
                content()
            }
            .frame(maxWidth: .infinity, minHeight: 150)
        }
    }

    @ViewBuilder
    private func candidateRow(_ candidate: CredentialCandidate) -> some View {
        HStack(spacing: Spacing.md) {
            BrandBadge(candidate.name, diameter: 32)

            VStack(alignment: .leading, spacing: Spacing.xs) {
                Text(candidate.name)
                    .font(Typography.rowTitle)
                    .foregroundStyle(Palette.primaryText)
                    .lineLimit(1)
                if !candidate.user.isEmpty {
                    Text(candidate.user)
                        .font(Typography.rowSubtitle)
                        .foregroundStyle(Palette.secondaryText)
                        .lineLimit(1)
                }
                if !candidate.serviceIdentifier.isEmpty {
                    Text(candidate.serviceIdentifier)
                        .font(.caption)
                        .foregroundStyle(Palette.secondaryText)
                        .lineLimit(1)
                }
            }

            Spacer(minLength: Spacing.sm)

            Label(kindLabel(for: candidate.kind), systemImage: iconName(for: candidate.kind))
                .labelStyle(.iconOnly)
                .font(.system(size: 18, weight: .regular))
                .foregroundStyle(Palette.accent)
        }
        .padding(.horizontal, Spacing.lg)
        .frame(maxWidth: .infinity, minHeight: 60, alignment: .leading)
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
        .accessibilityLabel(accessibilityLabel(for: candidate))
        .accessibilityHint("轻点以填充")
    }

    private func reload() async {
        isLoading = true
        loadFailed = false
        isCompleting = false
        do {
            candidates = try await loadCandidates()
            isLoading = false
        } catch {
            candidates = []
            isLoading = false
            loadFailed = true
        }
    }

    private func iconName(for kind: CredentialCandidate.Kind) -> String {
        switch kind {
        case .password: "person.badge.key"
        case .oneTimeCode: "timer"
        case .passkey: "person.crop.circle.badge.checkmark"
        }
    }

    private func kindLabel(for kind: CredentialCandidate.Kind) -> String {
        switch kind {
        case .password: "密码"
        case .oneTimeCode: "验证码"
        case .passkey: "通行密钥"
        }
    }

    private func accessibilityLabel(for candidate: CredentialCandidate) -> String {
        [candidate.name, candidate.user, kindLabel(for: candidate.kind)]
            .filter { !$0.isEmpty }
            .joined(separator: "，")
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
