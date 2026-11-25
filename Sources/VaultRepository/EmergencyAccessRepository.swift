import CoreFoundation
import CryptoCore
import CryptoKit
import Foundation
import KeyVault
import Networking
import Security
import VaultModels
import VaultStore

public enum EmergencyAccessError: Error, Equatable, Sendable {
    case sessionChanged, invalidEmail, invalidWaitTime, invalidInvitation
    case contactChanged, actionUnavailable, fingerprintMismatch
    case unsupportedKey, unsupportedItem, passwordIncorrect
    case authorizationRequired, serverRejected, unavailable, invalidResponse
}

public struct EmergencyAccessListing: Sendable {
    public let trusted: [EmergencyAccessContact]
    public let granted: [EmergencyAccessContact]
}

public enum EmergencyAccessAction: Sendable, Hashable {
    case reinvite, request, approve, reject, revoke

    public func isAvailable(for contact: EmergencyAccessContact) -> Bool {
        switch self {
        case .reinvite: contact.direction == .trusted && contact.status == .invited && contact.type == .view
        case .request: contact.direction == .granted && contact.status == .confirmed && contact.type == .view
            && EmergencyAccessRepository.waitTimeRange.contains(contact.waitTimeDays)
        case .approve: contact.direction == .trusted && contact.status == .recoveryInitiated && contact.type == .view
        case .reject: contact.direction == .trusted && [.recoveryInitiated, .recoveryApproved].contains(contact.status)
        case .revoke: true
        }
    }
}

/// A one-contact review bound to the active session. The UI cannot replace the key whose
/// fingerprint it displayed with one fetched later or supply an unreviewed key directly.
public struct EmergencyAccessConfirmation: Sendable {
    public let fingerprint: String
    public let contact: EmergencyAccessContact
    fileprivate let publicKey: Data
    fileprivate let lease: AccountSessionLease
}

public struct EmergencyAccessItemSummary: Sendable, Identifiable {
    public let id: UUID
    public let name: String
    public let type: CipherType
    public let isArchived: Bool
}

public struct EmergencyAccessViewIndex: Sendable {
    public let items: [EmergencyAccessItemSummary]
    public let unsupportedItemCount: Int
}

/// Plaintext for exactly the selected item. Never inserted into the ordinary vault, search
/// index, or credential provider; the view discards it on dismissal, lock or loss of focus.
public struct EmergencyAccessItemDetails: Sendable {
    public struct Field: Sendable {
        public let label: String
        public let value: String
    }

    public let name: String
    public let fields: [Field]
}

public actor EmergencyAccessRepository {
    public static let waitTimeRange = 1...90

    private let auth: AuthRepository
    private let api: APIClient
    private let keyVault: KeyVault
    private let store: VaultStore
    private let fingerprintWords: [String]

    private struct Context: Sendable {
        let lease: AccountSessionLease
        let id: UUID
    }

    public init(auth: AuthRepository, api: APIClient, keyVault: KeyVault, store: VaultStore,
                fingerprintWords: [String]) {
        self.auth = auth
        self.api = api
        self.keyVault = keyVault
        self.store = store
        self.fingerprintWords = fingerprintWords
    }

    public func unlockedSessionLease() async -> AccountSessionLease? {
        await auth.unlockedSessionLease()
    }

    public func list(lease: AccountSessionLease) async throws -> EmergencyAccessListing {
        let context = try await context(for: lease)
        async let trusted = contacts(.trusted, context: context)
        async let granted = contacts(.granted, context: context)
        let listing = try await EmergencyAccessListing(trusted: trusted, granted: granted)
        try await check(lease)
        return listing
    }

    public func invite(email: String, waitTimeDays: Int, lease: AccountSessionLease) async throws {
        let email = email.trimmingCharacters(in: .whitespacesAndNewlines)
        let parts = email.split(separator: "@", omittingEmptySubsequences: false)
        guard email.utf8.count <= 254, parts.count == 2, parts.allSatisfy({ !$0.isEmpty }),
              !email.unicodeScalars.contains(where: CharacterSet.whitespacesAndNewlines.union(.controlCharacters).contains) else {
            throw EmergencyAccessError.invalidEmail
        }
        try Self.validateWaitTime(waitTimeDays)
        let context = try await context(for: lease)
        guard let current = await auth.session, email.caseInsensitiveCompare(current.email) != .orderedSame else {
            throw EmergencyAccessError.invalidEmail
        }
        try await empty("POST", ["emergency-access", "invite"], context,
                        body: JSONEncoder().encode(EmergencyAccessInviteRequest(email: email, waitTimeDays: waitTimeDays)))
    }

    /// No full URL is accepted or built. The signed token goes only into the request body;
    /// the server binds the invitation to the account, the invitation ID and the signature.
    public func accept(invitationID: UUID, token: String, lease: AccountSessionLease) async throws {
        let token = token.trimmingCharacters(in: .whitespacesAndNewlines)
        let components = token.split(separator: ".", maxSplits: 3, omittingEmptySubsequences: false)
        guard token.utf8.count <= 8_192, components.count == 3,
              components.allSatisfy({ !$0.isEmpty && $0.utf8.allSatisfy(Self.isJWTByte) }) else {
            throw EmergencyAccessError.invalidInvitation
        }
        let context = try await context(for: lease)
        try await empty("POST", Self.path(invitationID, "accept"), context,
                        body: JSONEncoder().encode(EmergencyAccessAcceptRequest(token: token)))
    }

    public static func canEdit(_ contact: EmergencyAccessContact) -> Bool {
        contact.direction == .trusted && contact.type == .view
            && [.invited, .accepted, .confirmed].contains(contact.status)
    }

    public func edit(_ contact: EmergencyAccessContact, waitTimeDays: Int, lease: AccountSessionLease) async throws {
        guard Self.canEdit(contact) else { throw EmergencyAccessError.actionUnavailable }
        try Self.validateWaitTime(waitTimeDays)
        let context = try await context(for: lease)
        try await requireUnchanged(contact, context: context)
        try await mutate("PUT", Self.path(contact.id), context, contact: contact, status: contact.status,
                         waitTimeDays: waitTimeDays,
                         body: JSONEncoder().encode(EmergencyAccessUpdateRequest(waitTimeDays: waitTimeDays)))
    }

    /// Operates on a snapshot the user has explicitly reviewed. Re-read it immediately before
    /// the action; Vaultwarden still owns transition/authorization checks at dispatch time.
    public func perform(_ action: EmergencyAccessAction, on contact: EmergencyAccessContact,
                        lease: AccountSessionLease) async throws {
        guard action.isAvailable(for: contact) else { throw EmergencyAccessError.actionUnavailable }
        let context = try await context(for: lease)
        try await requireUnchanged(contact, context: context)
        switch action {
        case .reinvite: try await empty("POST", Self.path(contact.id, "reinvite"), context)
        case .request: try await mutate("POST", Self.path(contact.id, "initiate"), context,
                                        contact: contact, status: .recoveryInitiated)
        case .approve: try await mutate("POST", Self.path(contact.id, "approve"), context,
                                        contact: contact, status: .recoveryApproved)
        case .reject: try await mutate("POST", Self.path(contact.id, "reject"), context,
                                       contact: contact, status: .confirmed)
        case .revoke: try await empty("DELETE", Self.path(contact.id), context)
        }
    }

    public static func canConfirm(_ contact: EmergencyAccessContact) -> Bool {
        contact.direction == .trusted && contact.type == .view && contact.status == .accepted
    }

    public func prepareConfirmation(for contact: EmergencyAccessContact,
                                    lease: AccountSessionLease) async throws -> EmergencyAccessConfirmation {
        guard Self.canConfirm(contact) else { throw EmergencyAccessError.actionUnavailable }
        let context = try await context(for: lease)
        try await requireUnchanged(contact, context: context)
        let key = try await publicKey(for: contact.contactID, context: context)
        let fingerprint = try EmergencyAccessCryptography.fingerprint(userID: contact.contactID.uuidString.lowercased(),
                                                                     spki: key, words: fingerprintWords)
        try await check(lease)
        return EmergencyAccessConfirmation(fingerprint: fingerprint, contact: contact, publicKey: key, lease: lease)
    }

    public func confirm(_ confirmation: EmergencyAccessConfirmation, verifiedFingerprint: String) async throws {
        guard verifiedFingerprint.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == confirmation.fingerprint else {
            throw EmergencyAccessError.fingerprintMismatch
        }
        let contact = confirmation.contact
        let lease = confirmation.lease
        let context = try await context(for: lease)
        try await requireUnchanged(contact, context: context)
        // Detect regeneration while the review was open. A fresh key is never used
        // implicitly; even if the server changes it, wrap only to the reviewed bytes.
        guard try await publicKey(for: contact.contactID, context: context) == confirmation.publicKey else {
            throw EmergencyAccessError.contactChanged
        }
        let wrapped = try await withAccountKey(lease) { accountKey in
            try EmergencyAccessCryptography.wrap(accountKey, spki: confirmation.publicKey)
        }
        try await mutate("POST", Self.path(contact.id, "confirm"), context, contact: contact, status: .confirmed,
                         body: JSONEncoder().encode(EmergencyAccessConfirmRequest(wrappedKey: wrapped.stringValue)))
    }

    public static func canView(_ contact: EmergencyAccessContact) -> Bool {
        contact.direction == .granted && contact.type == .view && contact.status == .recoveryApproved
    }

    public func viewIndex(for contact: EmergencyAccessContact, lease: AccountSessionLease) async throws -> EmergencyAccessViewIndex {
        let response = try await fetchView(contact, lease: lease)
        return try await withGrantorKey(response, lease: lease) { key in
            var items: [EmergencyAccessItemSummary] = []
            var seenIDs: Set<UUID> = []
            var unsupported = 0
            for record in response.ciphers {
                try Task.checkCancellation()
                guard let cipher = record.cipher else { unsupported += 1; continue }
                guard record.isExplicitlyPersonal, cipher.deletedDate == nil else { continue }
                guard cipher.viewPassword == true, [0, 1].contains(cipher.reprompt),
                      let id = UUID(uuidString: cipher.id), seenIDs.insert(id).inserted,
                      let summary = try? Self.withItemKey(cipher, accountKey: key, { itemKey in
                          try Self.itemSummary(id: id, cipher: cipher, key: itemKey)
                      }) else { unsupported += 1; continue }
                items.append(summary)
            }
            return EmergencyAccessViewIndex(items: items.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending },
                                            unsupportedItemCount: unsupported)
        }
    }

    /// Do not cache a grant or reuse the grantor key between reads. Vaultwarden authorizes
    /// a fresh `/view` call after the local password check; only this selected item is opened.
    public func readItem(id: UUID, from contact: EmergencyAccessContact, lease: AccountSessionLease,
                         masterPassword: String) async throws -> EmergencyAccessItemDetails {
        guard Self.canView(contact) else { throw EmergencyAccessError.actionUnavailable }
        try await check(lease)
        do { try await auth.verifyMasterPassword(masterPassword, for: lease) }
        catch RepositoryError.authenticationFailed { throw EmergencyAccessError.passwordIncorrect }
        catch { throw EmergencyAccessError.sessionChanged }
        let response = try await fetchView(contact, lease: lease)
        let matches = response.ciphers.filter { $0.cipher.flatMap { UUID(uuidString: $0.id) } == id }
        guard matches.count == 1, let match = matches.first, match.isExplicitlyPersonal,
              let cipher = match.cipher, cipher.deletedDate == nil,
              cipher.viewPassword == true, [0, 1].contains(cipher.reprompt) else {
            throw EmergencyAccessError.unsupportedItem
        }
        return try await withGrantorKey(response, lease: lease) { key in
            do {
                return try Self.withItemKey(cipher, accountKey: key) { itemKey in
                    try Self.itemDetails(id: id, cipher: cipher, key: itemKey)
                }
            } catch { throw EmergencyAccessError.unsupportedItem }
        }
    }

    private func fetchView(_ contact: EmergencyAccessContact, lease: AccountSessionLease) async throws -> EmergencyAccessViewResponse {
        guard Self.canView(contact) else { throw EmergencyAccessError.actionUnavailable }
        let context = try await context(for: lease)
        try await requireUnchanged(contact, context: context)
        let response: EmergencyAccessViewResponse = try await json("POST", Self.path(contact.id, "view"), context)
        guard response.object == "emergencyAccessView" else { throw EmergencyAccessError.invalidResponse }
        return response
    }

    private func withGrantorKey<T>(_ response: EmergencyAccessViewResponse, lease: AccountSessionLease,
                                   _ open: (SymmetricCryptoKey) throws -> T) async throws -> T {
        let protected: EncString
        do {
            guard let wire = try await store.account(id: lease.accountID)?.encPrivateKey,
                  let value = try? EncString(parsing: wire), value.type == .aesCbc256_HmacSha256_B64 else {
                throw EmergencyAccessError.unsupportedKey
            }
            protected = value
        } catch { throw EmergencyAccessError.unsupportedKey }

        return try await withAccountKey(lease) { accountKey in
            let grantorKey: SymmetricCryptoKey
            do {
                var privateDER = try SymmetricCrypto.decrypt(protected, using: accountKey)
                defer { privateDER.withUnsafeMutableBytes(SecureBytes.erase) }
                grantorKey = try EmergencyAccessCryptography.unwrap(EncString(parsing: response.keyEncrypted),
                                                                    pkcs8: privateDER)
            } catch { throw EmergencyAccessError.unsupportedKey }
            defer { grantorKey.erase() }
            return try open(grantorKey)
        }
    }

    private func withAccountKey<T>(_ lease: AccountSessionLease,
                                   _ use: (SymmetricCryptoKey) throws -> T) async throws -> T {
        try await check(lease)
        let result: T
        do {
            let copy: SymmetricCryptoKey
            do { copy = try await keyVault.userKeyForBiometricEnrollment() }
            catch { throw EmergencyAccessError.sessionChanged }
            // A suspended KeyVault call may have acquired a replacement account's key. Do not
            // run the transform against that key. Wipe the owned copy before the publication check.
            defer { copy.erase() }
            try await check(lease)
            result = try use(copy)
        }
        try await check(lease)
        return result
    }

    private static func withItemKey<T>(_ cipher: CipherResponse, accountKey: SymmetricCryptoKey,
                                      _ use: (SymmetricCryptoKey) throws -> T) throws -> T {
        guard let wrapped = cipher.key else { return try use(accountKey) }
        var raw = try SymmetricCrypto.decrypt(wrapped, using: accountKey)
        defer { raw.withUnsafeMutableBytes(SecureBytes.erase) }
        let itemKey = try SymmetricCryptoKey(combined: raw)
        defer { itemKey.erase() }
        return try use(itemKey)
    }

    private static func text(_ field: EncString, key: SymmetricCryptoKey) throws -> String {
        var bytes = try SymmetricCrypto.decrypt(field, using: key)
        defer { bytes.withUnsafeMutableBytes(SecureBytes.erase) }
        guard let value = String(data: bytes, encoding: .utf8) else { throw EmergencyAccessError.unsupportedItem }
        return value
    }

    private static func itemSummary(id: UUID, cipher: CipherResponse, key: SymmetricCryptoKey) throws -> EmergencyAccessItemSummary {
        if case .unknown = cipher.type { throw EmergencyAccessError.unsupportedItem }
        return EmergencyAccessItemSummary(id: id, name: try text(cipher.name, key: key),
                                          type: cipher.type, isArchived: cipher.archivedDate != nil)
    }

    private static func itemDetails(id: UUID, cipher: CipherResponse, key: SymmetricCryptoKey) throws -> EmergencyAccessItemDetails {
        let summary = try itemSummary(id: id, cipher: cipher, key: key)
        var fields: [EmergencyAccessItemDetails.Field] = []
        func append(_ values: [(String, EncString?)]) throws {
            for (label, encrypted) in values {
                if let encrypted { fields.append(.init(label: label, value: try text(encrypted, key: key))) }
            }
        }
        switch cipher.type {
        case .login:
            guard let item = cipher.login else { throw EmergencyAccessError.unsupportedItem }
            try append([("Username", item.username), ("Password", item.password), ("Verification key", item.totp)])
            try append((item.uris ?? []).map { ("Website", $0.uri) })
        case .secureNote:
            break
        case .card:
            guard let item = cipher.card else { throw EmergencyAccessError.unsupportedItem }
            try append([("Cardholder name", item.cardholderName), ("Brand", item.brand), ("Number", item.number),
                        ("Expiration month", item.expMonth), ("Expiration year", item.expYear), ("Security code", item.code)])
        case .identity:
            guard let item = cipher.identity else { throw EmergencyAccessError.unsupportedItem }
            try append([("Title", item.title), ("First name", item.firstName), ("Middle name", item.middleName),
                        ("Last name", item.lastName), ("Username", item.username), ("Company", item.company),
                        ("Email", item.email), ("Phone", item.phone), ("Address", item.address1),
                        ("Address", item.address2), ("Address", item.address3), ("City", item.city),
                        ("State", item.state), ("Postal code", item.postalCode), ("Country", item.country),
                        ("Social security number", item.ssn), ("Passport number", item.passportNumber),
                        ("License number", item.licenseNumber)])
        case .sshKey:
            guard let item = cipher.sshKey else { throw EmergencyAccessError.unsupportedItem }
            try append([("Private key", item.privateKey), ("Public key", item.publicKey), ("Fingerprint", item.keyFingerprint)])
        case .unknown:
            throw EmergencyAccessError.unsupportedItem
        }
        try append([("Notes", cipher.notes)])
        for field in cipher.fields ?? [] {
            guard let value = field.value else { continue }
            // Custom field labels are encrypted data too; never reinterpret them as URL or Markdown.
            let name = try field.name.map { try text($0, key: key) } ?? "Custom field"
            fields.append(.init(label: name, value: try text(value, key: key)))
        }
        return EmergencyAccessItemDetails(name: summary.name, fields: fields)
    }

    private func contacts(_ direction: EmergencyAccessDirection, context: Context) async throws -> [EmergencyAccessContact] {
        let response: EmergencyAccessListResponse = try await json("GET", ["emergency-access", direction.rawValue], context)
        guard response.object == "list", response.continuationToken == nil,
              response.data.allSatisfy({ $0.direction == direction }),
              Set(response.data.map(\.id)).count == response.data.count else {
            throw EmergencyAccessError.invalidResponse
        }
        return response.data
    }

    private func publicKey(for userID: UUID, context: Context) async throws -> Data {
        let response: EmergencyAccessPublicKeyResponse = try await json(
            "GET", ["users", userID.uuidString.lowercased(), "public-key"], context)
        guard response.object == "userKey", response.userID == userID,
              response.publicKey.utf8.count <= 1_024, let raw = Data(base64Encoded: response.publicKey) else {
            throw EmergencyAccessError.unsupportedKey
        }
        return raw
    }

    private func requireUnchanged(_ snapshot: EmergencyAccessContact, context: Context) async throws {
        let latest: EmergencyAccessContact?
        switch snapshot.direction {
        case .trusted: latest = try await json("GET", Self.path(snapshot.id), context)
        case .granted: latest = try await contacts(.granted, context: context).first { $0.id == snapshot.id }
        }
        guard latest == snapshot else { throw EmergencyAccessError.contactChanged }
    }

    private func mutate(_ method: String, _ path: [String], _ context: Context, contact: EmergencyAccessContact,
                        status: EmergencyAccessStatus, waitTimeDays: Int? = nil, body: Data? = nil) async throws {
        let result: EmergencyAccessMutationResponse = try await json(method, path, context, body: body)
        guard result.object == "emergencyAccess", result.id == contact.id, result.type == contact.type,
              result.status == status, result.waitTimeDays == (waitTimeDays ?? contact.waitTimeDays) else {
            throw EmergencyAccessError.invalidResponse
        }
    }

    private func context(for lease: AccountSessionLease) async throws -> Context {
        try await check(lease)
        let id: UUID
        do { id = try await auth.accountActionContext(for: lease) }
        catch {
            try await check(lease)
            if (error as? RepositoryError) == .notAuthenticated { throw EmergencyAccessError.authorizationRequired }
            throw EmergencyAccessError.unavailable
        }
        try await check(lease)
        return Context(lease: lease, id: id)
    }

    private func check(_ lease: AccountSessionLease) async throws {
        try Task.checkCancellation()
        guard await auth.unlockedSessionLease() == lease else { throw EmergencyAccessError.sessionChanged }
        try Task.checkCancellation()
    }

    private func json<T: Decodable & Sendable>(_ method: String, _ path: [String], _ context: Context,
                                                body: Data? = nil) async throws -> T {
        try await request(context) {
            try await api.authenticatedJSON(accountID: context.lease.accountID, contextID: context.id,
                                            method: method, path: path, body: body)
        }
    }

    private func empty(_ method: String, _ path: [String], _ context: Context, body: Data? = nil) async throws {
        try await request(context) {
            try await api.authenticatedEmpty(accountID: context.lease.accountID, contextID: context.id,
                                             method: method, path: path, body: body)
        }
    }

    private func request<T>(_ context: Context, _ send: () async throws -> T) async throws -> T {
        try await check(context.lease)
        let result: T
        do { result = try await send() }
        catch let error as NetworkingError {
            try await check(context.lease)
            // Do not expose transport/response descriptions. A deployment can echo a token
            // or the body of a rejected request, and response field decoders can echo data.
            switch error {
            case .unauthorized, .accessTokenUnavailable: throw EmergencyAccessError.authorizationRequired
            case .accountContextChanged: throw EmergencyAccessError.sessionChanged
            case .http: throw EmergencyAccessError.serverRejected
            case .decoding: throw EmergencyAccessError.invalidResponse
            default: throw EmergencyAccessError.unavailable
            }
        }
        try await check(context.lease)
        return result
    }

    private static func path(_ id: UUID, _ suffix: String? = nil) -> [String] {
        ["emergency-access", id.uuidString.lowercased()] + (suffix.map { [$0] } ?? [])
    }

    private static func validateWaitTime(_ days: Int) throws {
        guard waitTimeRange.contains(days) else { throw EmergencyAccessError.invalidWaitTime }
    }

    private static func isJWTByte(_ byte: UInt8) -> Bool {
        (65...90).contains(byte) || (97...122).contains(byte) || (48...57).contains(byte) || byte == 45 || byte == 95
    }
}

/// Matches Bitwarden SDK `fingerprint.rs` and `enc_string/asymmetric.rs`. These helpers handle
/// only the Vaultwarden-compatible RSA-2048 / 64-byte AES-CBC-HMAC sharing formats.
package enum EmergencyAccessCryptography {
    package static func fingerprint(userID: String, spki: Data, words: [String]) throws -> String {
        try withPublicRSAKey(spki) { _ in }
        guard words.count == 7_776 else { throw EmergencyAccessError.unsupportedKey }
        // HMAC hashes an oversized SPKI key to SHA256(publicKey), which is what Web Vault
        // supplies explicitly to HKDF-Expand. Do not hash the stripped PKCS#1 bytes instead.
        let prk = SymmetricKey(data: SHA256.hash(data: spki))
        let fingerprint = HKDF<SHA256>.expand(pseudoRandomKey: prk, info: Data(userID.utf8), outputByteCount: 32)
        var digits = fingerprint.withUnsafeBytes { Array($0) }
        return (0..<5).map { _ in
            // Repeated divmod of a big-endian 256-bit integer, least significant digit first.
            var remainder = 0
            for i in digits.indices {
                let value = remainder * 256 + Int(digits[i])
                digits[i] = UInt8(value / words.count)
                remainder = value % words.count
            }
            return words[remainder]
        }.joined(separator: "-")
    }

    package static func wrap(_ key: SymmetricCryptoKey, spki: Data) throws -> EncString {
        try withPublicRSAKey(spki) { publicKey in
            let algorithm = SecKeyAlgorithm.rsaEncryptionOAEPSHA1
            guard SecKeyIsAlgorithmSupported(publicKey, .encrypt, algorithm) else { throw EmergencyAccessError.unsupportedKey }
            return try key.withCombinedBytes { bytes in
                guard let raw = noCopyCFData(bytes), let wrapped = SecKeyCreateEncryptedData(publicKey, algorithm, raw, nil),
                      CFDataGetLength(wrapped) == 256 else { throw EmergencyAccessError.unsupportedKey }
                return EncString(type: .rsa2048_OaepSha1_B64, iv: nil, ciphertext: wrapped as Data, mac: nil)
            }
        }
    }

    package static func unwrap(_ key: EncString, pkcs8: Data) throws -> SymmetricCryptoKey {
        let algorithm: SecKeyAlgorithm
        switch key.type {
        case .rsa2048_OaepSha1_B64: algorithm = .rsaEncryptionOAEPSHA1
        case .rsa2048_OaepSha256_B64: algorithm = .rsaEncryptionOAEPSHA256
        default: throw EmergencyAccessError.unsupportedKey
        }
        guard key.ciphertext.count == 256, key.iv == nil, key.mac == nil else { throw EmergencyAccessError.unsupportedKey }
        return try pkcs8.withUnsafeBytes { bytes in
            var sequence = try DER.sequence(bytes)
            guard try sequence.read(0x02).elementsEqual([0]),
                  try sequence.read(0x30).elementsEqual(rsaAlgorithmIdentifier) else { throw EmergencyAccessError.unsupportedKey }
            let pkcs1 = try sequence.read(0x04)
            guard sequence.isAtEnd else { throw EmergencyAccessError.unsupportedKey }
            let privateKey = try importRSA(pkcs1, keyClass: kSecAttrKeyClassPrivate)
            guard SecKeyIsAlgorithmSupported(privateKey, .decrypt, algorithm),
                  let raw = SecKeyCreateDecryptedData(privateKey, algorithm, key.ciphertext as CFData, nil),
                  CFDataGetLength(raw) == 64, let pointer = CFDataGetBytePtr(raw) else {
                throw EmergencyAccessError.unsupportedKey
            }
            return try withExtendedLifetime(raw) {
                // The Security result is immutable. Copy directly to the owned secure key
                // while it is alive; do not materialize a separate Swift plaintext buffer.
                let data = Data(bytesNoCopy: UnsafeMutableRawPointer(mutating: pointer), count: 64, deallocator: .none)
                return try SymmetricCryptoKey(combined: data)
            }
        }
    }

    // DER contents of the rsaEncryption AlgorithmIdentifier (OID 1.2.840.113549.1.1.1 + NULL).
    private static let rsaAlgorithmIdentifier: [UInt8] = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]

    private static func withPublicRSAKey<T>(_ spki: Data, _ use: (SecKey) throws -> T) throws -> T {
        try spki.withUnsafeBytes { bytes in
            var sequence = try DER.sequence(bytes)
            guard try sequence.read(0x30).elementsEqual(rsaAlgorithmIdentifier) else {
                throw EmergencyAccessError.unsupportedKey
            }
            let bits = try sequence.read(0x03)
            guard sequence.isAtEnd, bits.first == 0 else { throw EmergencyAccessError.unsupportedKey }
            let key = try importRSA(UnsafeRawBufferPointer(rebasing: bits.dropFirst()), keyClass: kSecAttrKeyClassPublic)
            return try use(key)
        }
    }

    private static func importRSA(_ pkcs1: UnsafeRawBufferPointer, keyClass: CFString) throws -> SecKey {
        // Supply the validated inner PKCS#1 object to Security; Security parses the RSA
        // integers and performs all cryptographic operations.
        _ = try DER.sequence(pkcs1)
        let attributes = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeyClass: keyClass] as CFDictionary
        guard let bytes = noCopyCFData(pkcs1), let key = SecKeyCreateWithData(bytes, attributes, nil),
              let size = (SecKeyCopyAttributes(key) as? [String: Any])?[kSecAttrKeySizeInBits as String] as? Int,
              size == 2_048 else { throw EmergencyAccessError.unsupportedKey }
        return key
    }

    private static func noCopyCFData(_ bytes: UnsafeRawBufferPointer) -> CFData? {
        guard let base = bytes.bindMemory(to: UInt8.self).baseAddress else { return nil }
        return CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, base, bytes.count, kCFAllocatorNull)
    }

    /// Minimal strict definite-length reader for the two fixed key wrappers, not a general
    /// ASN.1 parser. Borrowed ranges never outlive the enclosing `withUnsafeBytes` call.
    private struct DER {
        let bytes: UnsafeRawBufferPointer
        var offset = 0
        var isAtEnd: Bool { offset == bytes.count }

        static func sequence(_ bytes: UnsafeRawBufferPointer) throws -> DER {
            var parent = DER(bytes: bytes)
            let sequence = try parent.read(0x30)
            guard parent.isAtEnd else { throw EmergencyAccessError.unsupportedKey }
            return DER(bytes: sequence)
        }

        mutating func read(_ tag: UInt8) throws -> UnsafeRawBufferPointer {
            guard bytes.count - offset >= 2, bytes[offset] == tag else { throw EmergencyAccessError.unsupportedKey }
            var length = Int(bytes[offset + 1])
            offset += 2
            if length >= 0x80 {
                let count = length & 0x7f
                guard (1...3).contains(count), bytes.count - offset >= count, bytes[offset] != 0 else {
                    throw EmergencyAccessError.unsupportedKey
                }
                length = 0
                for _ in 0..<count {
                    length = (length << 8) | Int(bytes[offset])
                    offset += 1
                }
                guard length >= 0x80 else { throw EmergencyAccessError.unsupportedKey }
            }
            guard length <= bytes.count - offset else { throw EmergencyAccessError.unsupportedKey }
            let data = UnsafeRawBufferPointer(rebasing: bytes[offset..<(offset + length)])
            offset += length
            return data
        }
    }
}
