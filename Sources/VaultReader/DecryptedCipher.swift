import Foundation
import VaultModels

/// A small value type holding the decrypted fields of a single cipher that the AutoFill
/// extension needs. Deliberately minimal: the extension only ever decrypts ONE selected
/// item and only needs the fields below to complete a credential / passkey request or to
/// show a confirmation. Bulk fields (notes, all custom fields, attachments) are not
/// surfaced here — keeping the footprint small and the plaintext lifetime short.
public struct DecryptedCipher: Sendable, Equatable {
    /// The cipher id this was decrypted from.
    public let id: String
    /// Cipher type raw value (`1=Login, 2=SecureNote, 3=Card, 4=Identity, 5=SshKey`).
    public let type: Int
    /// Decrypted display name (always present for a well-formed cipher).
    public let name: String
    /// Decrypted login username, if this is a login with one.
    public let username: String?
    /// Decrypted login password, if this is a login with one.
    public let password: String?
    /// Decrypted TOTP secret / otpauth URI, if present.
    public let totp: String?
    /// Decrypted login URIs (in stored order), empty when none.
    public let uris: [String]

    public init(id: String, type: Int, name: String, username: String?,
                password: String?, totp: String?, uris: [String]) {
        self.id = id
        self.type = type
        self.name = name
        self.username = username
        self.password = password
        self.totp = totp
        self.uris = uris
    }
}
