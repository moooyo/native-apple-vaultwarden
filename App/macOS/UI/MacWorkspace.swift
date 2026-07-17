import SwiftUI
import VaultModels
import VaultRepository
import Generators

/// The destinations exposed by the OpenVault macOS sidebar. Destinations without a
/// repository surface still navigate to an honest unavailable/empty state; they never
/// manufacture sample vault data.
@available(macOS 27.0, *)
enum MacDestination: String, Hashable, CaseIterable {
    case all
    case favorites
    case authenticator
    case security
    case login
    case card
    case identity
    case secureNote
    case generator
    case send
    case settings

    var title: String {
        switch self {
        case .all: "所有条目"
        case .favorites: "置顶"
        case .authenticator: "验证码"
        case .security: "安全提醒"
        case .login: "登录"
        case .card: "银行卡"
        case .identity: "身份"
        case .secureNote: "安全笔记"
        case .generator: "生成器"
        case .send: "发送"
        case .settings: "设置"
        }
    }

    var systemImage: String {
        switch self {
        case .all: "square.grid.2x2"
        case .favorites: "star"
        case .authenticator: "clock"
        case .security: "exclamationmark.triangle"
        case .login: "key"
        case .card: "creditcard"
        case .identity: "person"
        case .secureNote: "note.text"
        case .generator: "sparkles"
        case .send: "paperplane"
        case .settings: "gearshape"
        }
    }

    var isVaultFilter: Bool {
        switch self {
        case .all, .favorites, .login, .card, .identity, .secureNote: true
        default: false
        }
    }

    func matches(_ cipher: PlaintextCipher) -> Bool {
        switch self {
        case .all: true
        case .favorites: cipher.favorite
        case .login: cipher.type == CipherType.login.rawValue
        case .card: cipher.type == CipherType.card.rawValue
        case .identity: cipher.type == CipherType.identity.rawValue
        case .secureNote: cipher.type == CipherType.secureNote.rawValue
        default: false
        }
    }
}

@available(macOS 27.0, *)
struct MacSidebarCounts {
    let all: Int
    let favorites: Int
    let authenticators: Int
    let logins: Int
    let cards: Int
    let identities: Int
    let secureNotes: Int

    init(items: [PlaintextCipher], authenticators: [MacTOTPEntry]) {
        all = items.count
        favorites = items.count(where: \.favorite)
        self.authenticators = authenticators.count
        logins = items.count { $0.type == CipherType.login.rawValue }
        cards = items.count { $0.type == CipherType.card.rawValue }
        identities = items.count { $0.type == CipherType.identity.rawValue }
        secureNotes = items.count { $0.type == CipherType.secureNote.rawValue }
    }

    func value(for destination: MacDestination) -> Int? {
        switch destination {
        case .all: all
        case .favorites: favorites
        case .authenticator: authenticators
        case .login: logins
        case .card: cards
        case .identity: identities
        case .secureNote: secureNotes
        case .security, .generator, .send, .settings: nil
        }
    }
}

@available(macOS 27.0, *)
struct MacTOTPEntry: Identifiable, Equatable {
    let cipher: PlaintextCipher
    let configuration: TOTPConfiguration

    var id: String { cipher.macStableID }
    var account: String { cipher.login?.username?.nilIfBlank ?? "未命名账户" }
    var website: String? { cipher.login?.uris.first?.uri.nilIfBlank }

    static func entries(from items: [PlaintextCipher]) -> [MacTOTPEntry] {
        items.compactMap { cipher in
            guard let raw = cipher.login?.totp,
                  let configuration = try? TOTP.configuration(from: raw) else { return nil }
            return MacTOTPEntry(cipher: cipher, configuration: configuration)
        }
    }
}

@available(macOS 27.0, *)
enum MacOpenVaultStyle {
    static let window = Color(red: 26 / 255, green: 27 / 255, blue: 30 / 255)
    static let list = Color(red: 30 / 255, green: 30 / 255, blue: 32 / 255)
    static let detail = Color(red: 35 / 255, green: 35 / 255, blue: 38 / 255)
    static let selected = Color(red: 10 / 255, green: 132 / 255, blue: 1).opacity(0.85)
    static let selectedBlue = Color(red: 10 / 255, green: 132 / 255, blue: 1)
    static let totp = Color(red: 100 / 255, green: 210 / 255, blue: 1)
    static let card = Color.white.opacity(0.05)
    static let hairline = Color.white.opacity(0.08)
    static let primary = Color.white.opacity(0.94)
    static let secondary = Color(red: 235 / 255, green: 235 / 255, blue: 245 / 255).opacity(0.5)
}

extension PlaintextCipher {
    var macStableID: String {
        id ?? "\(type)|\(name)|\(login?.username ?? "")|\(folderID ?? "")"
    }

    var macSubtitle: String? {
        if let username = login?.username?.nilIfBlank { return username }
        return notes?.nilIfBlank
    }

    var macTypeLabel: String {
        switch CipherType(rawValue: type) {
        case .login: "登录"
        case .secureNote: "安全笔记"
        case .card: "银行卡"
        case .identity: "身份"
        case .sshKey: "SSH 密钥"
        case .unknown: "其他"
        }
    }
}

extension String {
    var nilIfBlank: String? {
        trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? nil : self
    }
}
