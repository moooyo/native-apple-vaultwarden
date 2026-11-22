import SwiftUI
import UIShared
import DesignSystem
import VaultRepository
import VaultModels
import Generators

enum VaultWorkspaceSection: String, CaseIterable, Hashable, Identifiable {
    case all, favorites, codes, logins, cards, identities, secureNotes, sshKeys

    static let itemTypes: [Self] = [.logins, .codes, .cards, .identities, .secureNotes, .sshKeys]

    var id: String { rawValue }

    var title: String {
        switch self {
        case .all: "全部条目"
        case .favorites: "置顶"
        case .codes: "验证码"
        case .logins: "登录"
        case .cards: "银行卡"
        case .identities: "身份"
        case .secureNotes: "安全笔记"
        case .sshKeys: "SSH 密钥"
        }
    }

    var systemImage: String {
        switch self {
        case .all: "square.grid.2x2"
        case .favorites: "star"
        case .codes: "clock"
        case .logins: "key"
        case .cards: "creditcard"
        case .identities: "person.text.rectangle"
        case .secureNotes: "note.text"
        case .sshKeys: "terminal"
        }
    }
}

extension PlaintextCipher {
    var openVaultID: String { id ?? "\(type)|\(name)|\(login?.username ?? "")" }

    var openVaultName: String {
        name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "未命名条目" : name
    }

    var openVaultSubtitle: String? {
        if let username = login?.username, !username.isEmpty { return username }
        if let card {
            let digits = card.number?.filter(\.isNumber) ?? ""
            let brand = card.brand.flatMap { $0.isEmpty ? nil : $0 } ?? openVaultKindLabel
            return digits.count >= 4 ? "\(brand) •••• \(digits.suffix(4))" : brand
        }
        if let identity {
            let names = [identity.lastName, identity.firstName].compactMap { $0 }.filter { !$0.isEmpty }
            if !names.isEmpty { return "\(openVaultKindLabel) · \(names.joined(separator: " "))" }
        }
        return openVaultKindLabel
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
        case .cards: CipherType(rawValue: type) == .card
        case .identities: CipherType(rawValue: type) == .identity
        case .secureNotes: CipherType(rawValue: type) == .secureNote
        case .sshKeys: CipherType(rawValue: type) == .sshKey
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
    var subtitleOverride: String? = nil
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize
    @AppStorage(SettingsPreference.showsItemIcons) private var showsIcons = true
    @AppStorage(SettingsPreference.showsUsernames) private var showsUsernames = true

    private var subtitle: String? {
        if let subtitleOverride { return subtitleOverride }
        if !showsUsernames, cipher.login?.username?.isEmpty == false { return nil }
        return cipher.openVaultSubtitle
    }

    var body: some View {
        let configuration = date == nil ? nil : cipher.openVaultTOTPConfiguration
        HStack(spacing: Spacing.md) {
            if showsIcons { BrandBadge(cipher.openVaultName, diameter: 36) }
            VStack(alignment: .leading, spacing: Spacing.xxs) {
                Text(cipher.openVaultName)
                    .font(.body)
                    .foregroundStyle(.primary)
                    .lineLimit(dynamicTypeSize.isAccessibilitySize ? nil : 1)
                if let subtitle {
                    Text(subtitle)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .lineLimit(dynamicTypeSize.isAccessibilitySize ? nil : 1)
                        .privacySensitive()
                }
                if dynamicTypeSize.isAccessibilitySize, let date, let configuration {
                    code(configuration, at: date)
                }
            }
            Spacer(minLength: Spacing.sm)
            if let date, let configuration {
                if !dynamicTypeSize.isAccessibilitySize { code(configuration, at: date) }
            } else if showsFavorite, cipher.favorite {
                Image(systemName: "star.fill").font(.caption).foregroundStyle(.orange)
                    .accessibilityLabel("已置顶")
            }
            if date == nil, showsDisclosureIndicator {
                Image(systemName: "chevron.right").font(.caption.weight(.semibold))
                    .foregroundStyle(.tertiary).accessibilityHidden(true)
            }
        }
        .padding(.vertical, Spacing.sm)
        .frame(minHeight: date == nil ? 60 : 62)
        .overlay(alignment: .bottom) {
            if let date, let configuration {
                OTPCountdownBar(secondsRemaining: TOTP.secondsRemaining(for: configuration, at: date),
                                period: configuration.period)
            }
        }
        .contentShape(Rectangle())
    }

    private func code(_ configuration: TOTPConfiguration, at date: Date) -> some View {
        Text(OTPRingMath.formatCode(TOTP.code(for: configuration, at: date)))
            .font(.system(compactCode ? .callout : .title, design: .monospaced).weight(.semibold))
            .monospacedDigit()
            .lineLimit(1)
            .minimumScaleFactor(0.7)
            .privacySensitive()
    }
}

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

struct SettingIconTile: View {
    let systemImage: String
    let color: Color
    @Environment(\.colorScheme) private var colorScheme
    @Environment(\.colorSchemeContrast) private var contrast

    var body: some View {
        Image(systemName: systemImage)
            .font(.system(size: 15, weight: .semibold))
            .foregroundStyle(colorScheme == .dark && contrast == .increased ? Color.black : Color.white)
            .frame(width: 29, height: 29)
            .background(color, in: RoundedRectangle(cornerRadius: CornerRadius.settingIcon))
            .accessibilityHidden(true)
    }
}
