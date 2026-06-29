import Foundation
import CryptoCore
import VaultModels
import VaultStore
import KeyVault
import Networking
import SyncEngine

/// App-facing vault CRUD + read + sync orchestration (design spec §5.9).
///
/// Reads come from the local `VaultStore` (decrypted on demand via the `KeyVault`); writes
/// encrypt fields via the write-path `encryptor`, push through the API (or enqueue to the
/// store's outbox when offline), and update the local store. `sync()` delegates to the
/// injected `SyncEngine`.
///
/// An `actor` so all store/sync access from view models is serialized.
public actor VaultRepository {
    private let api: VaultAPI
    private let store: VaultStore
    private let keyVault: KeyVault
    private let encryptor: VaultEncrypting
    private let syncEngine: SyncEngine
    private let accountID: () async -> String?

    public init(api: VaultAPI, store: VaultStore, keyVault: KeyVault, encryptor: VaultEncrypting,
                syncEngine: SyncEngine, accountID: @escaping () async -> String?) {
        self.api = api
        self.store = store
        self.keyVault = keyVault
        self.encryptor = encryptor
        self.syncEngine = syncEngine
        self.accountID = accountID
    }

    // MARK: - Reads

    /// All ciphers for the active account, decrypted into `PlaintextCipher` values.
    /// A row that fails to decrypt is skipped (soft-fail) rather than aborting the list.
    public func ciphers() async throws -> [PlaintextCipher] {
        let id = try await requireAccountID()
        let rows: [CipherRow]
        do { rows = try await store.allCiphers(accountID: id) }
        catch { throw RepositoryError.store(error) }
        var out: [PlaintextCipher] = []
        for row in rows {
            if let decrypted = try? await decrypt(row) { out.append(decrypted) }
        }
        return out
    }

    /// The decrypted cipher for `id`, or throws `.cipherNotFound`.
    public func cipher(id: String) async throws -> PlaintextCipher {
        let row: CipherRow?
        do { row = try await store.cipher(id: id) }
        catch { throw RepositoryError.store(error) }
        guard let row else { throw RepositoryError.cipherNotFound }
        return try await decrypt(row)
    }

    /// Search the local plaintext index, returning decrypted matches.
    public func search(_ query: String) async throws -> [PlaintextCipher] {
        let id = try await requireAccountID()
        let rows: [CipherRow]
        do { rows = try await store.search(query, accountID: id) }
        catch { throw RepositoryError.store(error) }
        var out: [PlaintextCipher] = []
        for row in rows {
            if let decrypted = try? await decrypt(row) { out.append(decrypted) }
        }
        return out
    }

    // MARK: - Mutations

    /// Create a cipher: encrypt its fields, push to the API (or enqueue to the outbox when
    /// offline), and persist the resulting row locally. Returns the created cipher id.
    @discardableResult
    public func createCipher(_ plaintext: PlaintextCipher) async throws -> String {
        guard await keyVault.isUnlocked else { throw RepositoryError.locked }
        let id = try await requireAccountID()
        let encrypted = try await encryptCipher(plaintext)

        do {
            let created = try await api.createCipher(encrypted.request)
            let row = try await makeRow(from: created, accountID: id)
            try await store.upsertCiphers([row])
            return created.id
        } catch let error as NetworkingError where Self.isOffline(error) {
            // Offline: enqueue to the outbox under a local placeholder id and persist a
            // local row so the item shows immediately.
            let localID = plaintext.id ?? UUID().uuidString
            try await enqueueOutbox(op: .create, entityID: localID, encrypted: encrypted,
                                    lastKnownRevisionDate: nil)
            let row = encrypted.localRow(id: localID, accountID: id)
            try await store.upsertCiphers([row])
            return localID
        } catch {
            throw RepositoryError.network(error)
        }
    }

    /// Update an existing cipher: encrypt, push (or enqueue), and persist.
    public func updateCipher(id: String, _ plaintext: PlaintextCipher) async throws {
        guard await keyVault.isUnlocked else { throw RepositoryError.locked }
        let accountID = try await requireAccountID()
        let existing: CipherRow?
        do { existing = try await store.cipher(id: id) }
        catch { throw RepositoryError.store(error) }
        let lastKnown = existing.flatMap { SyncEngine.parseDate($0.revisionDate) }

        let encrypted = try await encryptCipher(plaintext, lastKnownRevisionDate: lastKnown)

        do {
            let updated = try await api.updateCipher(id: id, encrypted.request)
            let row = try await makeRow(from: updated, accountID: accountID)
            try await store.upsertCiphers([row])
        } catch let error as NetworkingError where Self.isOffline(error) {
            try await enqueueOutbox(op: .update, entityID: id, encrypted: encrypted,
                                    lastKnownRevisionDate: existing?.revisionDate)
            let row = encrypted.localRow(id: id, accountID: accountID)
            try await store.upsertCiphers([row])
        } catch {
            throw RepositoryError.network(error)
        }
    }

    /// Delete a cipher: call the API (or enqueue) and remove the local row.
    public func deleteCipher(id: String) async throws {
        do {
            try await api.deleteCipher(id: id)
        } catch let error as NetworkingError where Self.isOffline(error) {
            let row = OutboxRow(opType: OutboxOp.delete.rawValue,
                                entityType: OutboxEntity.cipher.rawValue,
                                entityID: id, payloadJSON: "{}", lastKnownRevisionDate: nil)
            do { try await store.enqueueOutbox(row) } catch { throw RepositoryError.store(error) }
        } catch {
            throw RepositoryError.network(error)
        }
        try? await store.deleteCipher(id: id)
    }

    // MARK: - Sync / lock

    /// Full sync: flush the outbox first, then pull. Delegates to the injected `SyncEngine`.
    @discardableResult
    public func sync() async throws -> SyncOutcome {
        let id = try await requireAccountID()
        do {
            try await syncEngine.flushOutbox(accountID: id)
            return try await syncEngine.fullSync(accountID: id)
        } catch {
            throw RepositoryError.sync(error)
        }
    }

    /// Lock the vault (zero the in-memory key material in the KeyVault + encryptor).
    public func lock() async {
        await keyVault.lock()
        await encryptor.clear()
    }

    // MARK: - Encryption / decryption

    /// The encrypted form of a cipher: a wire `CipherRequest` for the API plus the wire
    /// strings needed to build a local store row.
    private struct EncryptedCipher: Sendable {
        let request: CipherRequest
        let type: Int
        let folderID: String?
        let favorite: Bool
        let reprompt: Int
        let nameWire: String
        let notesWire: String?
        let blobJSON: String
        let searchText: String

        /// Build a local `CipherRow` (used for the offline/optimistic path and as a fallback).
        func localRow(id: String, accountID: String) -> CipherRow {
            let now = ISO8601DateFormatter().string(from: Date())
            return CipherRow(
                id: id, accountID: accountID, type: type, folderID: folderID,
                favorite: favorite, reprompt: reprompt,
                revisionDate: now, creationDate: now,
                encName: nameWire, encNotes: notesWire, encBlob: blobJSON,
                encCipherKey: nil, searchText: searchText
            )
        }
    }

    /// Encrypt an optional plaintext string under the user key (helper to keep the
    /// per-field encryption straight-line and free of closures crossing actor boundaries).
    private func encOptional(_ s: String?) async throws -> EncString? {
        guard let s else { return nil }
        return try await encryptor.encryptString(s)
    }

    /// Encrypt a plaintext cipher into a request + the bits needed for a local row.
    private func encryptCipher(_ p: PlaintextCipher,
                               lastKnownRevisionDate: Date? = nil) async throws -> EncryptedCipher {
        let nameEnc = try await encryptor.encryptString(p.name)
        let notesEnc = try await encOptional(p.notes)

        var loginReq: CipherLoginRequest?
        var blobLogin: BlobLogin?
        if let login = p.login {
            let userEnc = try await encOptional(login.username)
            let passEnc = try await encOptional(login.password)
            let totpEnc = try await encOptional(login.totp)
            var uriReqs: [CipherLoginUriRequest] = []
            var blobURIs: [BlobURI] = []
            for uri in login.uris {
                let uriEnc = try await encryptor.encryptString(uri.uri)
                uriReqs.append(CipherLoginUriRequest(uri: uriEnc, match: uri.match))
                blobURIs.append(BlobURI(uri: uriEnc.stringValue, match: uri.match))
            }
            loginReq = CipherLoginRequest(username: userEnc, password: passEnc, totp: totpEnc, uris: uriReqs)
            blobLogin = BlobLogin(username: userEnc?.stringValue, password: passEnc?.stringValue,
                                  totp: totpEnc?.stringValue, uris: blobURIs)
        }

        let request = CipherRequest(
            type: p.type, name: nameEnc, notes: notesEnc, folderId: p.folderID,
            favorite: p.favorite, reprompt: p.reprompt, login: loginReq,
            lastKnownRevisionDate: lastKnownRevisionDate
        )

        let blob = BlobRoot(login: blobLogin)
        let blobJSON = (try? blob.json()) ?? "{}"

        // Plaintext search index: name + username + uris (decrypted text the user typed).
        var parts: [String] = [p.name]
        if let user = p.login?.username { parts.append(user) }
        parts.append(contentsOf: p.login?.uris.map(\.uri) ?? [])
        let searchText = parts.joined(separator: " ").lowercased()

        return EncryptedCipher(
            request: request, type: p.type, folderID: p.folderID, favorite: p.favorite,
            reprompt: p.reprompt, nameWire: nameEnc.stringValue, notesWire: notesEnc?.stringValue,
            blobJSON: blobJSON, searchText: searchText
        )
    }

    /// Decrypt a store row into a `PlaintextCipher`. Throws `.locked` if the vault is locked,
    /// `.crypto` on a parse/decrypt failure of a required field.
    private func decrypt(_ row: CipherRow) async throws -> PlaintextCipher {
        guard await keyVault.isUnlocked else { throw RepositoryError.locked }
        let cipherKey = try await resolveCipherKey(row)

        guard let nameWire = row.encName else { throw RepositoryError.crypto(CryptoError.invalidEncString) }
        let name = try await decryptWire(nameWire, cipherKey: cipherKey)
        let notes = await optionalDecrypt(row.encNotes, cipherKey: cipherKey)

        var login: PlaintextCipher.Login?
        if let blob = try? JSONDecoder().decode(BlobRoot.self, from: Data((row.encBlob ?? "{}").utf8)),
           let l = blob.login {
            let user = await optionalDecrypt(l.username, cipherKey: cipherKey)
            let pass = await optionalDecrypt(l.password, cipherKey: cipherKey)
            let totp = await optionalDecrypt(l.totp, cipherKey: cipherKey)
            var uris: [PlaintextCipher.Uri] = []
            for u in l.uris ?? [] {
                if let plain = await optionalDecrypt(u.uri, cipherKey: cipherKey) {
                    uris.append(PlaintextCipher.Uri(uri: plain, match: u.match))
                }
            }
            login = PlaintextCipher.Login(username: user, password: pass, totp: totp, uris: uris)
        }

        return PlaintextCipher(
            id: row.id, type: row.type, name: name, notes: notes,
            folderID: row.folderID, favorite: row.favorite, reprompt: row.reprompt, login: login
        )
    }

    // MARK: - Private helpers

    private func requireAccountID() async throws -> String {
        guard let id = await accountID() else { throw RepositoryError.notAuthenticated }
        return id
    }

    /// Build a local store row from a server `CipherResponse` (reusing SyncEngine's blob /
    /// row mapping shape so reads stay consistent with sync).
    private func makeRow(from cipher: CipherResponse, accountID: String) async throws -> CipherRow {
        let blobJSON = (try? Self.encodeBlob(cipher)) ?? "{}"
        let searchText = await buildSearchText(cipher)
        return CipherRow(
            id: cipher.id, accountID: accountID, type: cipher.type.rawValue,
            folderID: cipher.folderId, organizationID: cipher.organizationId,
            favorite: cipher.favorite, reprompt: cipher.reprompt,
            edit: cipher.edit ?? true, viewPassword: cipher.viewPassword ?? true,
            revisionDate: Self.iso(cipher.revisionDate),
            creationDate: cipher.creationDate.map(Self.iso) ?? Self.iso(cipher.revisionDate),
            deletedDate: cipher.deletedDate.map(Self.iso),
            encName: cipher.name.stringValue, encNotes: cipher.notes?.stringValue,
            encBlob: blobJSON, encCipherKey: cipher.key?.stringValue, searchText: searchText
        )
    }

    private func buildSearchText(_ cipher: CipherResponse) async -> String {
        var cipherKey: SymmetricCryptoKey?
        if let protected = cipher.key {
            cipherKey = try? await keyVault.cipherKey(fromProtected: protected)
        }
        var parts: [String] = []
        if let n = await decEncOptional(cipher.name, cipherKey: cipherKey) { parts.append(n) }
        if let u = await decEncOptional(cipher.login?.username, cipherKey: cipherKey) { parts.append(u) }
        for uri in cipher.login?.uris ?? [] {
            if let s = await decEncOptional(uri.uri, cipherKey: cipherKey) { parts.append(s) }
        }
        return parts.joined(separator: " ").lowercased()
    }

    /// Best-effort decrypt of an optional `EncString` to UTF-8 (returns `nil` on any failure).
    private func decEncOptional(_ enc: EncString?, cipherKey: SymmetricCryptoKey?) async -> String? {
        guard let enc, let data = try? await keyVault.decrypt(enc, cipherKey: cipherKey),
              let s = String(data: data, encoding: .utf8) else { return nil }
        return s
    }

    private func enqueueOutbox(op: OutboxOp, entityID: String, encrypted: EncryptedCipher,
                              lastKnownRevisionDate: String?) async throws {
        let payload = try Self.outboxPayload(from: encrypted)
        let json: String
        do { json = try payload.encodedJSON() } catch { throw RepositoryError.crypto(error) }
        let row = OutboxRow(opType: op.rawValue, entityType: OutboxEntity.cipher.rawValue,
                            entityID: entityID, payloadJSON: json,
                            lastKnownRevisionDate: lastKnownRevisionDate)
        do { try await store.enqueueOutbox(row) } catch { throw RepositoryError.store(error) }
    }

    private func resolveCipherKey(_ row: CipherRow) async throws -> SymmetricCryptoKey? {
        guard let wire = row.encCipherKey else { return nil }
        let protected: EncString
        do { protected = try EncString(parsing: wire) } catch { throw RepositoryError.crypto(error) }
        do { return try await keyVault.cipherKey(fromProtected: protected) }
        catch KeyVaultError.locked { throw RepositoryError.locked }
        catch { throw RepositoryError.crypto(error) }
    }

    private func decryptWire(_ wire: String, cipherKey: SymmetricCryptoKey?) async throws -> String {
        let enc: EncString
        do { enc = try EncString(parsing: wire) } catch { throw RepositoryError.crypto(error) }
        do {
            let data = try await keyVault.decrypt(enc, cipherKey: cipherKey)
            guard let s = String(data: data, encoding: .utf8) else {
                throw RepositoryError.crypto(CryptoError.decryptionFailed)
            }
            return s
        } catch KeyVaultError.locked {
            throw RepositoryError.locked
        } catch let e as RepositoryError {
            throw e
        } catch {
            throw RepositoryError.crypto(error)
        }
    }

    private func optionalDecrypt(_ wire: String?, cipherKey: SymmetricCryptoKey?) async -> String? {
        guard let wire else { return nil }
        return try? await decryptWire(wire, cipherKey: cipherKey)
    }

    // MARK: - Static helpers

    /// HTTP transport/reachability failures that mean "queue this write for later".
    static func isOffline(_ error: NetworkingError) -> Bool {
        switch error {
        case .serverUnreachable, .transport: return true
        default: return false
        }
    }

    static func iso(_ date: Date) -> String {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f.string(from: date)
    }

    /// Encode a server cipher's sub-payload as a JSON blob of EncString wire strings,
    /// matching the `enc_blob` shape used elsewhere (login subset for M1).
    static func encodeBlob(_ cipher: CipherResponse) throws -> String {
        let login = cipher.login.map { l in
            BlobLogin(
                username: l.username?.stringValue, password: l.password?.stringValue,
                totp: l.totp?.stringValue,
                uris: l.uris?.map { BlobURI(uri: $0.uri?.stringValue, match: $0.match?.rawValue) }
            )
        }
        let root = BlobRoot(login: login)
        return try root.json()
    }

    /// Build an `OutboxCipherPayload` from an already-encrypted cipher request.
    private static func outboxPayload(from encrypted: EncryptedCipher) throws -> OutboxCipherPayload {
        let req = encrypted.request
        let login = req.login.map { l in
            OutboxCipherPayload.Login(
                username: l.username?.stringValue, password: l.password?.stringValue,
                totp: l.totp?.stringValue,
                uris: l.uris?.map { OutboxCipherPayload.Uri(uri: $0.uri?.stringValue, match: $0.match) }
            )
        }
        return OutboxCipherPayload(
            type: req.type, name: req.name.stringValue, notes: req.notes?.stringValue,
            folderID: req.folderId, organizationID: req.organizationId,
            favorite: req.favorite, reprompt: req.reprompt, key: req.key?.stringValue,
            login: login
        )
    }
}

// MARK: - Blob JSON (login subset of enc_blob, EncString wire strings)

/// The `enc_blob` JSON shape the repository reads/writes: a login sub-payload of EncString
/// wire strings. Compatible with what `SyncEngine` writes and `VaultReader` reads.
struct BlobRoot: Codable, Sendable {
    var login: BlobLogin?
    func json() throws -> String {
        String(decoding: try JSONEncoder().encode(self), as: UTF8.self)
    }
}

struct BlobLogin: Codable, Sendable {
    var username: String?
    var password: String?
    var totp: String?
    var uris: [BlobURI]?
}

struct BlobURI: Codable, Sendable {
    var uri: String?
    var match: Int?
}
