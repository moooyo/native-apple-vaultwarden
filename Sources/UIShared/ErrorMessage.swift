import Foundation
import VaultRepository

/// Maps a thrown error into a short, user-presentable message. Centralized so every view
/// model surfaces consistent strings (and so secrets never leak into UI text — only the
/// well-known `RepositoryError` cases produce specific copy; everything else is generic).
extension UnlockModel {
    static func message(for error: Error) -> String { errorString(error) }
}
extension LoginModel {
    static func message(for error: Error) -> String { errorString(error) }
}
extension VaultListModel {
    static func message(for error: Error) -> String { errorString(error) }
}

/// Shared error → message mapping.
func errorString(_ error: Error) -> String {
    guard let repo = error as? RepositoryError else { return "Something went wrong." }
    switch repo {
    case .unsupportedKDF:
        return "This account uses an unsupported encryption setting (Argon2id)."
    case .locked:
        return "The vault is locked."
    case .authenticationFailed:
        return "Incorrect password or unable to unlock."
    case .notAuthenticated:
        return "You are not signed in."
    case .cipherNotFound:
        return "That item could not be found."
    case .organizationCipherKeyUnavailable:
        return "This organization item cannot be edited until its encryption key is available."
    case .missingUserKey:
        return "The server response was missing the vault key."
    case .underlying(let kind, _):
        switch kind {
        case .network: return "Could not reach the server."
        case .store: return "A local storage error occurred."
        case .crypto: return "A decryption error occurred."
        case .sync: return "Sync failed."
        }
    }
}
