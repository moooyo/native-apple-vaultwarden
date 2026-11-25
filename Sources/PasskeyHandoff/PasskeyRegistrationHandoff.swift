import AppShared
import CryptoCore
import Foundation
import KeychainBridge

/// The plaintext payload, used only in memory on either side of the handoff. Its account and
/// queue identifier are authenticated with the rest of the payload, not exposed in an index.
public struct StagedPasskeyRegistration: Codable, Sendable, Equatable {
    fileprivate static let currentVersion = 2
    fileprivate static let maximumBytes = 24_576

    private var version: Int
    public let id: String
    public let accountID: String
    public let cipherID: String?
    public let relyingPartyID: String
    public let userName: String
    public let userDisplayName: String?
    public let userHandle: Data
    public let credentialID: Data
    public let privateKeyPKCS8: Data
    public let creationDate: Date

    public init(
        id: String = UUID().uuidString.lowercased(),
        accountID: String,
        cipherID: String?,
        relyingPartyID: String,
        userName: String,
        userDisplayName: String? = nil,
        userHandle: Data,
        credentialID: Data,
        privateKeyPKCS8: Data,
        creationDate: Date = Date()
    ) {
        version = Self.currentVersion
        self.id = id
        self.accountID = accountID
        self.cipherID = cipherID
        self.relyingPartyID = relyingPartyID
        self.userName = userName
        self.userDisplayName = userDisplayName
        self.userHandle = userHandle
        self.credentialID = credentialID
        self.privateKeyPKCS8 = privateKeyPKCS8
        self.creationDate = creationDate
    }

    public func seal(using encrypt: @Sendable (Data) async throws -> EncString) async throws -> EncString {
        var bytes = try encoded()
        defer { bytes.withUnsafeMutableBytes(SecureBytes.erase) }
        return try await encrypt(bytes)
    }

    package func encoded() throws -> Data {
        guard isValid, version == Self.currentVersion else { throw PasskeyHandoffError.invalidRegistration }
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let bytes = try encoder.encode(self)
        guard bytes.count <= Self.maximumBytes else { throw PasskeyHandoffError.invalidRegistration }
        return bytes
    }

    fileprivate static func decode(
        _ bytes: Data, id: String, accountID: String, version: Int
    ) throws -> Self {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        guard bytes.count <= maximumBytes,
              var value = try? decoder.decode(Self.self, from: bytes),
              value.version == version, value.id == id, value.accountID == accountID, value.isValid else {
            throw PasskeyHandoffError.invalidRegistration
        }
        value.version = currentVersion
        return value
    }

    private var isValid: Bool {
        PasskeyRegistrationHandoff.isValidID(id) && !accountID.isEmpty && !relyingPartyID.isEmpty
            && !userName.isEmpty && !userHandle.isEmpty && !credentialID.isEmpty && !privateKeyPKCS8.isEmpty
    }
}

public enum PasskeyHandoffError: Error, Sendable, Equatable {
    case invalidRegistration
    case sessionChanged
    case keychainUnavailable
    case storageUnavailable
    case legacyMigrationPending
}

public struct SealedPasskeyRegistration: Sendable, Equatable {
    public let id: String
    fileprivate let envelope: EncString

    public func open(
        for accountID: String,
        using decrypt: @Sendable (EncString) async throws -> Data
    ) async throws -> StagedPasskeyRegistration {
        var bytes = try await decrypt(envelope)
        defer { bytes.withUnsafeMutableBytes(SecureBytes.erase) }
        return try StagedPasskeyRegistration.decode(
            bytes, id: id, accountID: accountID, version: StagedPasskeyRegistration.currentVersion
        )
    }
}

public struct PendingPasskeyRegistrations: Sendable {
    public fileprivate(set) var registrations: [SealedPasskeyRegistration] = []
    /// Some v1 entries still require their owner's unlocked app, or a Keychain retry. No v1
    /// plaintext is returned and these entries are not consumed or discarded as corruption.
    public fileprivate(set) var requiresLegacyMigration = false
    public fileprivate(set) var hasUnreadableEntries = false
}

/// Cross-process durable queue used by the AutoFill extension and main app. A successful
/// stage writes an opaque marker, persists only authenticated ciphertext in the Keychain, then
/// atomically promotes the marker to ready. The ready marker is the registration commit point.
public actor PasskeyRegistrationHandoff {
    private struct Marker: Codable {
        let version: Int
        let id: String
    }

    private struct LegacyOwner: Decodable {
        let accountID: String
    }

    public struct LegacyMigration: Sendable {
        fileprivate let accountID: String
        fileprivate let validate: @Sendable () async throws -> Void
        fileprivate let seal: @Sendable (Data) async throws -> EncString
        fileprivate let open: @Sendable (EncString) async throws -> Data

        public init(
            accountID: String,
            validate: @escaping @Sendable () async throws -> Void,
            seal: @escaping @Sendable (Data) async throws -> EncString,
            open: @escaping @Sendable (EncString) async throws -> Data
        ) {
            self.accountID = accountID
            self.validate = validate
            self.seal = seal
            self.open = open
        }
    }

    private static let legacyVersion = 1
    private static let currentVersion = StagedPasskeyRegistration.currentVersion
    private static let maximumEnvelopeBytes = 2 * StagedPasskeyRegistration.maximumBytes

    private let directoryURL: URL
    private let keychain: KeychainBridge
    private let beforeReadyPromotion: @Sendable () async -> Void
    private let afterReadyPromotion: @Sendable () async -> Void

    public init(
        directoryURL: URL,
        keychain: KeychainBridge,
        beforeReadyPromotion: @escaping @Sendable () async -> Void = {},
        afterReadyPromotion: @escaping @Sendable () async -> Void = {}
    ) {
        self.directoryURL = directoryURL
        self.keychain = keychain
        self.beforeReadyPromotion = beforeReadyPromotion
        self.afterReadyPromotion = afterReadyPromotion
    }

    /// Accept only ciphertext sealed under the exact lease passed to `validate`.
    public func stage(
        id: String,
        envelope: EncString,
        sessionID: String,
        ownerGate: AutoFillAccessGate,
        validate: @Sendable () async throws -> Void
    ) async throws {
        try await stage(id: id, envelope: envelope, validate: validate, permitsCommit: {
            ownerGate.permits(sessionID: sessionID)
        })
    }

    package func stage(
        id: String,
        envelope: EncString,
        validate: @Sendable () async throws -> Void,
        permitsCommit: @Sendable () -> Bool
    ) async throws {
        guard Self.isValidID(id), Self.isSupportedEnvelope(envelope) else {
            throw PasskeyHandoffError.invalidRegistration
        }
        try await validate()
        try await persist(id: id, envelope: envelope, validate: validate, permitsCommit: permitsCommit)
        // The rename transferred ownership. A subsequent lock or task cancellation must
        // never roll back the only private key for a registration we can now complete.
        await afterReadyPromotion()
    }

    private func persist(
        id: String, envelope: EncString,
        validate: @Sendable () async throws -> Void, permitsCommit: @Sendable () -> Bool
    ) async throws {
        guard let files = try await HandoffQueueFiles.open(directoryURL, create: true) else {
            throw PasskeyHandoffError.storageUnavailable
        }
        defer { files.close() }
        let staging = Self.stagingName(id)
        let ready = Self.readyName(id)
        let account = Self.sealedAccount(id)
        guard try !files.exists(ready), try !files.exists(staging),
              try await getSecret(account) == nil else {
            throw PasskeyHandoffError.storageUnavailable
        }
        let marker = try JSONEncoder().encode(Marker(version: Self.currentVersion, id: id))
        try files.writeMarker(marker, named: staging)
        do {
            try await setAndConfirm(envelope, account: account)
            await beforeReadyPromotion()
            try Task.checkCancellation()
            try await validate()
            try Task.checkCancellation()
            guard permitsCommit() else { throw PasskeyHandoffError.sessionChanged }
            try files.promote(staging, to: ready)
        } catch {
            // A throwing write might still have committed. Leave a staging cleanup marker
            // unless Keychain gives positive confirmation that the secret is absent.
            if (try? await deleteAndConfirm(account)) != nil { try? files.remove(staging) }
            throw error
        }
    }

    /// Return opaque records. Only the main app may opt in to one-way v1 migration, using
    /// seal/open operations bound to an unlocked lease for the same account.
    public func pendingRegistrations(migrating legacy: LegacyMigration? = nil) async throws -> PendingPasskeyRegistrations {
        var result = PendingPasskeyRegistrations()
        guard let files = try await HandoffQueueFiles.open(directoryURL, create: false) else { return result }
        defer { files.close() }
        for name in try files.names().sorted() {
            try Task.checkCancellation()
            let isStaging = name.hasSuffix(".staging")
            guard isStaging || name.hasSuffix(".pending") else { continue }
            let id = String(name.dropLast(8)) // .staging and .pending are both eight bytes.
            guard Self.isValidID(id) else { continue }
            do {
                guard let marker = try readMarker(name, id: id, files: files) else { continue }
                if isStaging {
                    // A crash before the ready rename cannot have returned an attestation.
                    // In particular, never recover a rejected lease's failed rollback as ready.
                    if marker.version == Self.legacyVersion, legacy == nil {
                        result.requiresLegacyMigration = true
                        continue
                    }
                    let account = marker.version == Self.legacyVersion
                        ? Self.legacyAccount(id) : Self.sealedAccount(id)
                    try await deleteAndConfirm(account)
                    try files.remove(name)
                } else if marker.version == Self.legacyVersion {
                    do {
                        if let sealed = try await migrateLegacy(id: id, using: legacy, files: files) {
                            result.registrations.append(sealed)
                        }
                    } catch {
                        result.requiresLegacyMigration = true
                    }
                } else if let data = try await getSecret(Self.sealedAccount(id)) {
                    result.registrations.append(try Self.sealed(id: id, data: data))
                } else {
                    try files.remove(name)
                }
            } catch {
                // Keep potentially committed data and let healthy entries make progress.
                result.hasUnreadableEntries = true
            }
        }
        return result
    }

    /// Acknowledge only after durable import. Keychain deletion is best-effort in the bridge,
    /// so the marker remains discoverable until a successful readback proves absence.
    public func acknowledge(id: String) async throws {
        guard Self.isValidID(id) else { throw PasskeyHandoffError.invalidRegistration }
        guard let files = try await HandoffQueueFiles.open(directoryURL, create: false) else { return }
        defer { files.close() }
        let name = Self.readyName(id)
        guard let marker = try readMarker(name, id: id, files: files) else { return }
        guard marker.version == Self.currentVersion else { throw PasskeyHandoffError.legacyMigrationPending }
        try await deleteAndConfirm(Self.sealedAccount(id))
        try files.remove(name)
    }

    /// Keep v1 and v2 items separate because a Keychain replacement can delete its predecessor
    /// before failing. Read back and authenticate the replacement before removing the legacy
    /// item. The original opaque marker covers either item through interrupted migration.
    private func migrateLegacy(
        id: String, using migration: LegacyMigration?, files: HandoffQueueFiles
    ) async throws -> SealedPasskeyRegistration? {
        let oldAccount = Self.legacyAccount(id)
        let newAccount = Self.sealedAccount(id)
        guard let migration else { throw PasskeyHandoffError.legacyMigrationPending }
        let storedEnvelope = try await getSecret(newAccount)
        try await migration.validate()
        guard var plaintext = try await getSecret(oldAccount) else {
            if let storedEnvelope {
                let sealed = try Self.sealed(id: id, data: storedEnvelope)
                _ = try await sealed.open(for: migration.accountID, using: migration.open)
                try promoteLegacyMarker(id: id, files: files)
                return sealed
            }
            try files.remove(Self.readyName(id))
            return nil
        }
        defer { plaintext.withUnsafeMutableBytes(SecureBytes.erase) }
        try await migration.validate()
        guard plaintext.count <= StagedPasskeyRegistration.maximumBytes,
              let owner = try? JSONDecoder().decode(LegacyOwner.self, from: plaintext),
              owner.accountID == migration.accountID else { throw PasskeyHandoffError.legacyMigrationPending }
        let registration = try StagedPasskeyRegistration.decode(
            plaintext, id: id, accountID: migration.accountID, version: Self.legacyVersion
        )
        let sealed: SealedPasskeyRegistration
        if let storedEnvelope {
            sealed = try Self.sealed(id: id, data: storedEnvelope)
        } else {
            let envelope = try await registration.seal(using: migration.seal)
            try await setAndConfirm(envelope, account: newAccount)
            sealed = SealedPasskeyRegistration(id: id, envelope: envelope)
        }
        guard try await sealed.open(for: migration.accountID, using: migration.open) == registration else {
            throw PasskeyHandoffError.invalidRegistration
        }
        try await deleteAndConfirm(oldAccount)
        try promoteLegacyMarker(id: id, files: files)
        return sealed
    }

    private func promoteLegacyMarker(id: String, files: HandoffQueueFiles) throws {
        let marker = try JSONEncoder().encode(Marker(version: Self.currentVersion, id: id))
        try files.writeMarker(marker, named: Self.readyName(id))
    }

    private func readMarker(_ name: String, id: String, files: HandoffQueueFiles) throws -> Marker? {
        guard let data = try files.read(name) else { return nil }
        guard let value = try? JSONDecoder().decode(Marker.self, from: data),
              value.id == id, value.version == Self.currentVersion || value.version == Self.legacyVersion else {
            throw PasskeyHandoffError.invalidRegistration
        }
        return value
    }

    private func getSecret(_ account: String) async throws -> Data? {
        do { return try await keychain.getSecret(account: account) }
        catch { throw PasskeyHandoffError.keychainUnavailable }
    }

    private func setAndConfirm(_ envelope: EncString, account: String) async throws {
        guard Self.isSupportedEnvelope(envelope) else { throw PasskeyHandoffError.invalidRegistration }
        let wire = Data(envelope.stringValue.utf8)
        do { try await keychain.setSecret(wire, account: account, biometryGated: false) }
        catch { throw PasskeyHandoffError.keychainUnavailable }
        guard try await getSecret(account) == wire else { throw PasskeyHandoffError.keychainUnavailable }
    }

    private func deleteAndConfirm(_ account: String) async throws {
        await keychain.deleteSecret(account: account)
        guard try await getSecret(account) == nil else { throw PasskeyHandoffError.keychainUnavailable }
    }

    private static func sealed(id: String, data: Data) throws -> SealedPasskeyRegistration {
        guard data.count <= maximumEnvelopeBytes,
              let wire = String(data: data, encoding: .utf8),
              let envelope = try? EncString(parsing: wire), isSupportedEnvelope(envelope) else {
            throw PasskeyHandoffError.invalidRegistration
        }
        return SealedPasskeyRegistration(id: id, envelope: envelope)
    }

    private static func isSupportedEnvelope(_ envelope: EncString) -> Bool {
        envelope.type == .aesCbc256_HmacSha256_B64 && envelope.iv?.count == 16 && envelope.mac?.count == 32
            && !envelope.ciphertext.isEmpty && envelope.ciphertext.count.isMultiple(of: 16)
            && envelope.ciphertext.count <= StagedPasskeyRegistration.maximumBytes + 16
    }

    private static func readyName(_ id: String) -> String { "\(id).pending" }
    private static func stagingName(_ id: String) -> String { "\(id).staging" }
    private static func sealedAccount(_ id: String) -> String { AppShared.KeychainAccount.passkeyRegistrationPrefix + "v2." + id }
    private static func legacyAccount(_ id: String) -> String { AppShared.KeychainAccount.passkeyRegistrationPrefix + id }
    fileprivate static func isValidID(_ id: String) -> Bool { UUID(uuidString: id)?.uuidString.lowercased() == id }
}
