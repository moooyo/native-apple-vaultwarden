import SwiftUI
import UIShared
import DesignSystem
import VaultRepository
import VaultModels
import Generators

@available(iOS 27.0, *)
enum OpenVaultTab: Hashable {
    case vault
    case codes
    case generator
    case send
    case search
}

@available(iOS 27.0, *)
enum VaultWorkspaceSection: String, CaseIterable, Hashable, Identifiable {
    case all
    case favorites
    case codes
    case logins
    case secureNotes
    case cards
    case identities
    case generator
    case send
    case settings

    var id: String { rawValue }

    var title: String {
        switch self {
        case .all: "所有条目"
        case .favorites: "置顶"
        case .codes: "验证码"
        case .logins: "登录"
        case .secureNotes: "安全笔记"
        case .cards: "银行卡"
        case .identities: "身份"
        case .generator: "生成器"
        case .send: "发送"
        case .settings: "设置"
        }
    }

    var systemImage: String {
        switch self {
        case .all: "square.grid.2x2"
        case .favorites: "star"
        case .codes: "clock"
        case .logins: "key"
        case .secureNotes: "note.text"
        case .cards: "creditcard"
        case .identities: "person.text.rectangle"
        case .generator: "sparkles"
        case .send: "paperplane"
        case .settings: "gearshape"
        }
    }

    var isTool: Bool {
        self == .generator || self == .send || self == .settings
    }
}

extension PlaintextCipher {
    var openVaultID: String {
        id ?? "\(type)|\(name)|\(login?.username ?? "")"
    }

    var openVaultName: String {
        name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "未命名条目" : name
    }

    var openVaultSubtitle: String? {
        if let username = login?.username, !username.isEmpty { return username }
        if let note = notes, !note.isEmpty { return note }
        return nil
    }

    var openVaultTOTPConfiguration: TOTPConfiguration? {
        guard let raw = login?.totp, !raw.isEmpty else { return nil }
        return try? TOTP.configuration(from: raw)
    }

    var openVaultKindLabel: String {
        switch CipherType(rawValue: type) {
        case .login: "登录"
        case .secureNote: "安全笔记"
        case .card: "银行卡"
        case .identity: "身份"
        case .sshKey: "SSH 密钥"
        case .unknown: "条目"
        }
    }

    func isIncluded(in section: VaultWorkspaceSection) -> Bool {
        switch section {
        case .all: true
        case .favorites: favorite
        case .codes: openVaultTOTPConfiguration != nil
        case .logins: CipherType(rawValue: type) == .login
        case .secureNotes: CipherType(rawValue: type) == .secureNote
        case .cards: CipherType(rawValue: type) == .card
        case .identities: CipherType(rawValue: type) == .identity
        case .generator, .send, .settings: false
        }
    }
}

@available(iOS 27.0, *)
struct VaultItemRow: View {
    let cipher: PlaintextCipher
    var date: Date? = nil
    var showsFavorite = true
    var compactCode = false
    var showsDisclosureIndicator = true
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize

    var body: some View {
        let configuration = date == nil ? nil : cipher.openVaultTOTPConfiguration
        HStack(spacing: Spacing.md) {
            BrandBadge(cipher.openVaultName, diameter: 32)

            VStack(alignment: .leading, spacing: Spacing.xxs) {
                Text(cipher.openVaultName)
                    .font(.body)
                    .foregroundStyle(.primary)
                    .lineLimit(dynamicTypeSize.isAccessibilitySize ? nil : 1)
                if let subtitle = cipher.openVaultSubtitle {
                    Text(subtitle)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
                if dynamicTypeSize.isAccessibilitySize, let date, let configuration {
                    totp(configuration, at: date)
                }
            }

            Spacer(minLength: Spacing.sm)

            if let date, let configuration {
                if !dynamicTypeSize.isAccessibilitySize { totp(configuration, at: date) }
            } else if showsFavorite, cipher.favorite {
                Image(systemName: "star.fill")
                    .font(.caption)
                    .foregroundStyle(Palette.caution)
                    .accessibilityLabel("已置顶")
            }

            if date == nil, showsDisclosureIndicator {
                Image(systemName: "chevron.right")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(Palette.tertiaryText)
                    .accessibilityHidden(true)
            }
        }
        .frame(minHeight: compactCode ? 48 : 54)
        .contentShape(Rectangle())
    }

    @ViewBuilder
    private func totp(_ configuration: TOTPConfiguration, at date: Date) -> some View {
        let raw = TOTP.code(for: configuration, at: date)
        let code = OTPRingMath.formatCode(raw)
        let remaining = TOTP.secondsRemaining(for: configuration, at: date)
        let progress = OTPRingMath.progress(secondsRemaining: remaining, period: configuration.period)

        HStack(spacing: Spacing.sm) {
            Text(code)
                .font(.system(compactCode ? .subheadline : .title3, design: .monospaced).weight(.medium))
                .monospacedDigit()
                .foregroundStyle(.primary)
                .lineLimit(1)
                .minimumScaleFactor(0.65)
                .privacySensitive()
            CountdownRing(progress: progress, size: compactCode ? 16 : 20,
                          lineWidth: compactCode ? 2 : 2.6)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("验证码 \(raw)")
        .accessibilityValue("剩余 \(remaining) 秒")
    }
}

@available(iOS 27.0, *)
struct VaultFieldButton: View {
    let title: String
    let systemImage: String
    var role: ButtonRole? = nil
    let action: () -> Void

    var body: some View {
        Button(role: role, action: action) {
            Label(title, systemImage: systemImage)
                .labelStyle(.iconOnly)
                .frame(minWidth: 44, minHeight: 44)
                .contentShape(Rectangle())
        }
        .buttonStyle(.borderless)
    }
}

@available(iOS 27.0, *)
struct VaultRowsCard: View {
    let items: [PlaintextCipher]
    let vault: VaultService
    let onChanged: () -> Void
    var onDelete: ((PlaintextCipher) -> Void)? = nil

    var body: some View {
        OpenVaultCard(padding: 0) {
            VStack(spacing: 0) {
                ForEach(Array(items.enumerated()), id: \.element.openVaultID) { index, cipher in
                    NavigationLink {
                        ItemDetailView(model: ItemDetailModel(cipher: cipher), vault: vault,
                                       onChanged: onChanged)
                    } label: {
                        VaultItemRow(cipher: cipher)
                            .padding(.horizontal, Spacing.lg)
                    }
                    .buttonStyle(.plain)
                    .swipeActions(edge: .trailing, allowsFullSwipe: true) {
                        if let onDelete {
                            Button(role: .destructive) { onDelete(cipher) } label: {
                                Label("删除", systemImage: "trash")
                            }
                        }
                    }
                    .swipeActions(edge: .leading) {
                        if let username = cipher.login?.username, !username.isEmpty {
                            Button { Clipboard.copy(username) } label: {
                                Label("复制用户名", systemImage: "doc.on.doc")
                            }
                            .tint(Palette.accent)
                        }
                    }

                    if index < items.count - 1 {
                        Divider().padding(.leading, 60)
                    }
                }
            }
        }
        .swipeActionsContainer()
    }
}

@available(iOS 27.0, *)
struct DashboardStatTile: View {
    let title: String
    let value: Int
    let systemImage: String
    let tint: Color
    var action: (() -> Void)? = nil

    var body: some View {
        Group {
            if let action {
                Button(action: action) { tileContent }
                    .buttonStyle(.plain)
                    .accessibilityAddTraits(.isButton)
            } else {
                tileContent
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(title)，\(value)")
    }

    private var tileContent: some View {
        VStack(alignment: .leading, spacing: Spacing.lg) {
            HStack {
                Image(systemName: systemImage)
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundStyle(.white)
                    .frame(width: 30, height: 30)
                    .background(tint, in: Circle())
                Spacer()
                Text(value, format: .number)
                    .font(.title2.weight(.semibold))
                    .monospacedDigit()
                    .foregroundStyle(Palette.primaryText)
            }
            Text(title)
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(Palette.secondaryText)
        }
        .padding(14)
        .frame(maxWidth: .infinity, minHeight: 112, alignment: .leading)
        .background {
            RoundedRectangle(cornerRadius: CornerRadius.statistic, style: .continuous)
                .fill(Palette.contentBackground)
        }
    }
}

@available(iOS 27.0, *)
struct SettingIconTile: View {
    let systemImage: String
    let color: Color

    var body: some View {
        Image(systemName: systemImage)
            .font(.system(size: 15, weight: .semibold))
            .foregroundStyle(.white)
            .frame(width: 29, height: 29)
            .background(color, in: RoundedRectangle(cornerRadius: CornerRadius.settingIcon,
                                                    style: .continuous))
            .accessibilityHidden(true)
    }
}
