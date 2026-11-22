import CryptoCore
import Foundation
import KeyVault
import Networking
import SyncEngine
import VaultModels
import VaultStore

public enum VaultSendError: Error, Sendable {
    case invalidDraft, textTooLong, unsupportedFormat, invalidLink, fileTooLarge, unsupportedUpload
}

public actor SendRepository: VaultSendService {
    private let api: APIClient
    private let store: VaultStore
    private let keyVault: KeyVault
    private let encryptor: any VaultEncrypting
    private let auth: AuthRepository
    private let mutations = VaultMutationCoordinator()

    package init(api: APIClient, store: VaultStore, keyVault: KeyVault, encryptor: any VaultEncrypting,
                 auth: AuthRepository) {
        self.api = api
        self.store = store
        self.keyVault = keyVault
        self.encryptor = encryptor
        self.auth = auth
    }

    public func listSends() async throws -> [VaultSend] {
        let lease = try await unlockedLease()
        return try await mutations.withLock { try await self.list(lease: lease) }
    }

    public func createSend(_ draft: VaultSendDraft) async throws -> VaultSend {
        let lease = try await unlockedLease()
        try validate(draft)
        let secret = try SecureRandom.bytes(16)
        let protectedKey = try await encryptor.encrypt(secret, cipherKey: nil)
        let contentKey = try SendCryptography.contentKey(secret: secret)
        var request = try makeRequest(draft, secret: secret, key: contentKey, protectedKey: protectedKey)
        var file: SendUploadFile?
        if draft.kind == .file {
            guard let source = draft.fileURL else { throw VaultSendError.invalidDraft }
            let fileName = try SymmetricCrypto.encrypt(Data(source.lastPathComponent.utf8), using: contentKey)
            let prepared = try SendUploadFile(source: source, encryptedName: fileName, key: contentKey)
            file = prepared
            request.file = .init(fileName: fileName)
            request.fileLength = prepared.encryptedSize
        }
        defer { file?.discard() }
        let body = request
        let upload = file
        return try await mutations.withLock {
            try await self.create(body, upload: upload, lease: lease)
        }
    }

    public func updateSend(id: String, draft: VaultSendDraft) async throws -> VaultSend {
        let lease = try await unlockedLease()
        try validate(draft)
        return try await mutations.withLock { try await self.update(id: id, draft: draft, lease: lease) }
    }

    public func deleteSend(id: String) async throws {
        let lease = try await unlockedLease()
        try await mutations.withLock {
            try await self.check(lease)
            try await self.api.deleteSend(accountID: lease.accountID, id: id)
            try await self.check(lease)
            try? await self.store.evictSend(id: id, accountID: lease.accountID)
        }
    }

    private func list(lease: AccountSessionLease) async throws -> [VaultSend] {
        try await check(lease)
        let base = try await serverBase(lease)
        let generation = try await store.sendCacheGeneration(accountID: lease.accountID)
        let records: [SendResponse]
        do {
            records = try await api.sends(accountID: lease.accountID)
        } catch let error as NetworkingError {
            if error.deniesVaultListingAccess {
                if await auth.currentSessionLease() == lease { try await store.clearSendCache(accountID: lease.accountID) }
                throw error
            }
            switch error {
            case .serverUnreachable, .transport:
                try await check(lease)
                guard let cached = try await store.completeCachedSends(accountID: lease.accountID, ifUnchangedSince: generation) else { throw error }
                let items = try await open(cached, base: base, lease: lease)
                guard try await store.sendCacheGeneration(accountID: lease.accountID) == generation else { throw error }
                return items
            default: throw error
            }
        }
        let items = try await open(records, base: base, lease: lease)
        let applied = try await store.cacheSends(records, accountID: lease.accountID, update: .completeListing, ifUnchangedSince: generation)
        try await check(lease)
        guard let applied, try await store.sendCacheGeneration(accountID: lease.accountID) == applied else {
            throw RepositoryError.underlying(kind: .sync, description: "The Send listing changed during the request")
        }
        return items
    }

    private func open(_ records: [SendResponse], base: URL, lease: AccountSessionLease) async throws -> [VaultSend] {
        var items = [VaultSend]()
        for record in records where record.deletionDate > .now && VaultSendKind(rawValue: record.type.rawValue) != nil {
            try await check(lease)
            items.append(try await decrypt(record, base: base))
        }
        try await check(lease)
        return items.sorted { $0.revisionDate > $1.revisionDate }
    }

    private func create(_ request: SendRequest, upload: SendUploadFile?, lease: AccountSessionLease) async throws -> VaultSend {
        let base = try await serverBase(lease)
        try await check(lease)
        let result: SendResponse
        if let upload {
            var pending = request
            pending.disabled = true
            let reservation = try await api.createFileSend(accountID: lease.accountID, request: pending)
            let record = reservation.sendResponse
            guard record.key == request.key, record.type == .file else { throw VaultSendError.unsupportedUpload }
            do {
                try await check(lease)
                guard reservation.fileUploadType == 0, record.disabled, let file = record.file,
                      file.fileName == request.file?.fileName else {
                    throw VaultSendError.unsupportedUpload
                }
                try await api.uploadSendFile(accountID: lease.accountID, id: record.id, fileID: file.id,
                                             multipart: upload.url, boundary: upload.boundary)
                if request.disabled {
                    result = record
                } else {
                    try await check(lease)
                    var publish = request
                    publish.file = nil
                    publish.fileLength = nil
                    publish.password = nil
                    result = try await api.updateSend(accountID: lease.accountID, id: record.id, request: publish)
                }
            } catch {
                if await auth.currentSessionLease() == lease {
                    do {
                        try await api.deleteSend(accountID: lease.accountID, id: record.id)
                        try? await store.evictSend(id: record.id, accountID: lease.accountID)
                    } catch { }
                }
                throw error
            }
        } else {
            result = try await api.createTextSend(accountID: lease.accountID, request: request)
        }
        guard result.key == request.key, result.type.rawValue == request.type else { throw VaultSendError.unsupportedFormat }
        return try await finish(result, base: base, lease: lease)
    }

    private func update(id: String, draft: VaultSendDraft, lease: AccountSessionLease) async throws -> VaultSend {
        let base = try await serverBase(lease)
        try await check(lease)
        let original = try await api.send(accountID: lease.accountID, id: id)
        guard original.id == id, original.type.rawValue == draft.kind.rawValue, draft.fileURL == nil,
              original.authType.map({ [1, 2].contains($0) }) ?? true else { throw VaultSendError.unsupportedFormat }
        try await check(lease)
        let secret = try await keyVault.decrypt(original.key)
        let contentKey = try SendCryptography.contentKey(secret: secret)
        let request = try makeRequest(draft, secret: secret, key: contentKey, protectedKey: original.key)
        try await check(lease)
        var updated = try await api.updateSend(accountID: lease.accountID, id: id, request: request)
        if draft.removePassword, original.password != nil || original.authType == 1 {
            try await check(lease)
            updated = try await api.removeSendPassword(accountID: lease.accountID, id: id)
        }
        guard updated.id == id, updated.key == original.key else { throw VaultSendError.unsupportedFormat }
        return try await finish(updated, base: base, lease: lease)
    }

    private func finish(_ response: SendResponse, base: URL, lease: AccountSessionLease) async throws -> VaultSend {
        try await check(lease)
        let item = try await decrypt(response, base: base)
        try await check(lease)
        _ = try? await store.cacheSends([response], accountID: lease.accountID, update: .mutation)
        try await check(lease)
        return item
    }

    private func makeRequest(_ draft: VaultSendDraft, secret: Data, key: SymmetricCryptoKey,
                             protectedKey: EncString) throws -> SendRequest {
        func encrypt(_ value: String) throws -> EncString { try SymmetricCrypto.encrypt(Data(value.utf8), using: key) }
        var request = SendRequest(type: draft.kind.rawValue, key: protectedKey, name: try encrypt(draft.name),
                                  deletionDate: draft.deletionDate, hideEmail: draft.hideEmail, disabled: draft.disabled)
        if draft.kind == .text {
            let content = try encrypt(draft.text)
            guard content.stringValue.utf8.count <= 1000 else { throw VaultSendError.textTooLong }
            request.text = .init(text: content, hidden: draft.hideText)
        }
        request.notes = try draft.notes.map(encrypt)
        request.expirationDate = draft.expirationDate
        request.maxAccessCount = draft.maxAccessCount
        if let password = draft.password {
            request.password = try SendCryptography.passwordVerifier(password, secret: secret)
        }
        return request
    }

    private func validate(_ draft: VaultSendDraft) throws {
        let now = Date.now
        guard !draft.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              draft.deletionDate > now, draft.deletionDate <= now.addingTimeInterval(31 * 86_400),
              draft.maxAccessCount.map({ (1...Int(Int32.max)).contains($0) }) ?? true,
              !draft.removePassword || draft.password == nil, draft.password?.isEmpty != true,
              draft.kind != .text || !draft.text.isEmpty,
              draft.kind != .text || draft.fileURL == nil else { throw VaultSendError.invalidDraft }
    }

    private func decrypt(_ response: SendResponse, base: URL) async throws -> VaultSend {
        let secret = try await keyVault.decrypt(response.key)
        let key = try SendCryptography.contentKey(secret: secret)
        func string(_ value: EncString) throws -> String {
            let data = try SymmetricCrypto.decrypt(value, using: key)
            guard let text = String(data: data, encoding: .utf8) else { throw CryptoError.decryptionFailed }
            return text
        }
        guard let kind = VaultSendKind(rawValue: response.type.rawValue) else { throw VaultSendError.unsupportedFormat }
        return try VaultSend(id: response.id, kind: kind, name: string(response.name), text: response.text?.text.map(string),
                             fileName: response.file.map { try string($0.fileName) }, hideText: response.text?.hidden ?? false,
                             deletionDate: response.deletionDate, expirationDate: response.expirationDate,
                             accessCount: response.accessCount, maxAccessCount: response.maxAccessCount,
                             hasPassword: response.password != nil || response.authType == 1,
                             hideEmail: response.hideEmail ?? false, disabled: response.disabled,
                             shareURL: Self.shareURL(base: base, accessID: response.accessId, secret: secret),
                             revisionDate: response.revisionDate, notes: response.notes.map(string))
    }

    private func unlockedLease() async throws -> AccountSessionLease {
        guard let lease = await auth.currentSessionLease() else { throw RepositoryError.notAuthenticated }
        try await check(lease)
        return lease
    }

    private func check(_ lease: AccountSessionLease) async throws {
        try Task.checkCancellation()
        guard await auth.isUnlocked(), await auth.currentSessionLease() == lease else { throw RepositoryError.locked }
    }

    private func serverBase(_ lease: AccountSessionLease) async throws -> URL {
        guard let server = try await store.account(id: lease.accountID)?.serverURL,
              let environment = ServerEnvironment(string: server) else { throw VaultSendError.invalidLink }
        return environment.base
    }

    package static func shareURL(base: URL, accessID: String, secret: Data) throws -> URL {
        guard accessID.utf8.count == 22, accessID.utf8.allSatisfy({
            (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 45 || $0 == 95
        }), secret.count == 16, var parts = URLComponents(url: base, resolvingAgainstBaseURL: false) else {
            throw VaultSendError.invalidLink
        }
        let token = secret.base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        if !parts.percentEncodedPath.hasSuffix("/") { parts.percentEncodedPath += "/" }
        parts.fragment = "/send/\(accessID)/\(token)"
        guard let link = parts.url else { throw VaultSendError.invalidLink }
        return link
    }
}
