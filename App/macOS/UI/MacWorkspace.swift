import SwiftUI
import VaultModels
import VaultRepository
import Generators

enum MacVaultWindowID: String, Codable, Hashable { case workspace }
enum MacVaultPhase: Equatable { case loading, login, unlock, main }

enum MacDestination: Hashable {
    case all
    case favorites
    case authenticator
    case login
    case card
    case identity
    case secureNote
    case sshKey
    case folder(String)
    case unfiled
    case generator
    case send
    case archive
    case trash

    var title: String {
        MacLocalization.text(titleKey)
    }

    var titleKey: String {
        switch self {
        case .all: "All items"
        case .favorites: "Favorites"
        case .authenticator: "Verification codes"
        case .login: "Logins"
        case .card: "Cards"
        case .identity: "Identities"
        case .secureNote: "Secure notes"
        case .generator: "Generator"
        case .sshKey: "SSH keys"
        case .folder: "Folder"
        case .unfiled: "No folder"
        case .send: "Send"
        case .archive: "Archive"
        case .trash: "Trash"
        }
    }

    var systemImage: String {
        switch self {
        case .all: "square.grid.2x2"
        case .favorites: "star"
        case .authenticator: "clock"
        case .login: "key"
        case .card: "creditcard"
        case .identity: "person"
        case .secureNote: "note.text"
        case .sshKey: "terminal"
        case .folder: "folder"
        case .unfiled: "tray"
        case .generator: "sparkles"
        case .send: "paperplane"
        case .archive: "archivebox"
        case .trash: "trash"
        }
    }

    var hasList: Bool {
        switch self {
        case .generator, .send: false
        default: true
        }
    }

    var isHiddenCollection: Bool { self == .archive || self == .trash }

    var folderID: String? {
        guard case .folder(let id) = self else { return nil }
        return id
    }

    var initialType: CipherType {
        switch self {
        case .card: .card
        case .identity: .identity
        case .secureNote: .secureNote
        case .sshKey: .sshKey
        default: .login
        }
    }

    func matches(_ cipher: PlaintextCipher) -> Bool {
        switch self {
        case .all, .archive, .trash: true
        case .favorites: cipher.favorite
        case .login: cipher.type == CipherType.login.rawValue
        case .card: cipher.type == CipherType.card.rawValue
        case .identity: cipher.type == CipherType.identity.rawValue
        case .secureNote: cipher.type == CipherType.secureNote.rawValue
        case .sshKey: cipher.type == CipherType.sshKey.rawValue
        case .folder(let id): cipher.folderID == id
        case .unfiled: cipher.folderID == nil
        default: false
        }
    }
}

struct MacSidebarCounts {
    private var values: [MacDestination: Int]

    init(items: [PlaintextCipher], authenticators: Int, archived: Int, trashed: Int, sends: Int?) {
        values = [.all: items.count, .authenticator: authenticators, .archive: archived, .trash: trashed]
        values[.send] = sends
        for item in items {
            if item.favorite { values[.favorites, default: 0] += 1 }
            values[item.folderID.map(MacDestination.folder) ?? .unfiled, default: 0] += 1
            let type: MacDestination
            switch CipherType(rawValue: item.type) {
            case .login: type = .login
            case .card: type = .card
            case .identity: type = .identity
            case .secureNote: type = .secureNote
            case .sshKey: type = .sshKey
            case .unknown: continue
            }
            values[type, default: 0] += 1
        }
    }

    func value(for destination: MacDestination) -> Int? {
        if destination == .send || destination == .generator { return values[destination] }
        return values[destination, default: 0]
    }
}

struct MacTOTPEntry: Identifiable, Equatable {
    let cipher: PlaintextCipher
    let configuration: TOTPConfiguration

    var id: String { cipher.macStableID }
    var account: String { cipher.login?.username?.nilIfBlank ?? MacLocalization.text("Unnamed account") }
    var website: String? { cipher.login?.uris.first?.uri.nilIfBlank }

    static func entries(from items: [PlaintextCipher]) -> [MacTOTPEntry] {
        items.compactMap { cipher in
            guard cipher.type == CipherType.login.rawValue, let raw = cipher.login?.totp,
                  let configuration = try? TOTP.configuration(from: raw) else { return nil }
            return MacTOTPEntry(cipher: cipher, configuration: configuration)
        }
    }
}

extension PlaintextCipher {
    func matchesMacSearch(_ query: String, in destination: MacDestination, folderNames: [String: String] = [:]) -> Bool {
        if query.isEmpty || name.localizedCaseInsensitiveContains(query)
            || macSubtitle?.localizedCaseInsensitiveContains(query) == true
            || login?.uris.contains(where: { $0.uri.localizedCaseInsensitiveContains(query) }) == true { return true }
        guard destination.isHiddenCollection else { return false }
        let folderLabel = folderID.flatMap { folderNames[$0] } ?? (folderID == nil ? MacDestination.unfiled.title : nil)
        return macTypeLabel.localizedCaseInsensitiveContains(query) || folderLabel?.localizedCaseInsensitiveContains(query) == true
    }

    var macStableID: String {
        id ?? "\(type)|\(name)|\(login?.username ?? "")|\(folderID ?? "")"
    }

    var macSubtitle: String? { macSubtitle(in: MacLocalization.interfaceLocale) }

    func macSubtitle(in locale: Locale) -> String? {
        switch CipherType(rawValue: type) {
        case .login: return login?.username?.nilIfBlank ?? login?.uris.compactMap { URL(string: $0.uri)?.host }.first
        case .card:
            let digits = card?.number?.filter(\.isNumber) ?? ""
            return digits.count >= 4 ? MacLocalization.format("Ending in %@", String(digits.suffix(4)), locale: locale) : card?.cardholderName?.nilIfBlank
        case .identity: return identity?.email?.nilIfBlank ?? identity?.username?.nilIfBlank
        case .sshKey: return sshKey?.keyFingerprint?.nilIfBlank
        case .secureNote, .unknown: return nil
        }
    }

    var macTypeLabel: String { macTypeLabel(in: MacLocalization.interfaceLocale) }

    func macTypeLabel(in locale: Locale) -> String {
        let key = switch CipherType(rawValue: type) {
        case .login: "Login"
        case .secureNote: "Secure note"
        case .card: "Card"
        case .identity: "Identity"
        case .sshKey: "SSH key"
        case .unknown: "Other"
        }
        return MacLocalization.text(key, locale: locale)
    }
}

extension String {
    var nilIfBlank: String? {
        trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? nil : self
    }
}
