import Generators
import SwiftUI
import VaultModels
import VaultRepository

enum MacQuickCopyField: String, CaseIterable, Identifiable {
    case username, password, totp, cardNumber, securityCode, note

    var id: Self { self }

    var title: LocalizedStringKey {
        switch self {
        case .username: "Copy username"
        case .password: "Copy password"
        case .totp: "Copy verification code"
        case .cardNumber: "Copy card number"
        case .securityCode: "Copy security code"
        case .note: "Copy note"
        }
    }

    var symbol: String {
        switch self {
        case .username: "person"
        case .password, .securityCode: "key"
        case .totp: "clock"
        case .cardNumber: "number"
        case .note: "document.on.document"
        }
    }

    func isAvailable(in cipher: PlaintextCipher) -> Bool { payload(in: cipher) != nil }

    func value(in cipher: PlaintextCipher, at date: Date = .now) -> String? {
        switch payload(in: cipher) {
        case .text(let value): value
        case .code(let configuration): TOTP.code(for: configuration, at: date)
        case nil: nil
        }
    }

    private func payload(in cipher: PlaintextCipher) -> Payload? {
        guard cipher.id != nil, cipher.deletedDate == nil, cipher.archivedDate == nil,
              cipher.organizationID == nil, self == .username || cipher.reprompt == 0 else { return nil }
        let text: String?
        switch (CipherType(rawValue: cipher.type), self) {
        case (.login, .username): text = cipher.login?.username
        case (.login, .password): text = cipher.login?.password
        case (.login, .totp):
            guard let seed = cipher.login?.totp, let configuration = try? TOTP.configuration(from: seed) else { return nil }
            return .code(configuration)
        case (.card, .cardNumber): text = cipher.card?.number
        case (.card, .securityCode): text = cipher.card?.code
        case (.secureNote, .note): text = cipher.notes
        default: return nil
        }
        guard let text, !text.isEmpty else { return nil }
        return .text(text)
    }

    private enum Payload {
        case text(String)
        case code(TOTPConfiguration)
    }
}

struct MacQuickCopyReceipt {
    let itemID: String
    let field: MacQuickCopyField
    let token = UUID()
}
