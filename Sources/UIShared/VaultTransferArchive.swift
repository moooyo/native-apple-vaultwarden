import Foundation
import VaultModels
import VaultRepository

public struct VaultTransferArchive: Sendable {
    public let folders: [PlaintextFolder]
    public let items: [PlaintextCipher]

    public init(folders: [PlaintextFolder], items: [PlaintextCipher]) {
        self.folders = folders
        self.items = items
    }
}

public enum VaultTransferError: Error, Equatable {
    case invalidFile, unsupportedFile, emptyFile, fileTooLarge, unsupportedItem
    case partialImport(items: Int, folders: Int)
}

public enum VaultTransferCodec {
    public static let maximumBytes = 32 * 1_024 * 1_024
    static let maximumRecords = 20_000

    public static func isEncryptedJSON(_ data: Data) throws -> Bool {
        try checkSize(data)
        return try JSONDecoder().decode(EnvelopeHeader.self, from: data).encrypted ?? false
    }

    public static func decodeJSON(_ data: Data) throws -> VaultTransferArchive {
        try checkSize(data)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .custom { input in
            let value = try input.singleValueContainer().decode(String.self)
            if let date = try? Date.ISO8601FormatStyle(includingFractionalSeconds: true).parse(value) { return date }
            return try Date.ISO8601FormatStyle().parse(value)
        }
        let file = try decoder.decode(BitwardenFile.self, from: data)
        guard file.encrypted != true, file.collections == nil else { throw VaultTransferError.unsupportedFile }
        let folders = (file.folders ?? []).map { PlaintextFolder(id: $0.id, name: $0.name) }
        let items = try file.items.compactMap { item -> PlaintextCipher? in
            guard item.deletedDate == nil else { return nil }
            guard item.organizationId == nil else { throw VaultTransferError.unsupportedFile }
            guard item.passwordHistory?.isEmpty != false, item.attachments?.isEmpty != false,
                  item.archivedDate == nil, item.login?.autofillOnPageLoad != true else { throw VaultTransferError.unsupportedItem }
            let login = item.login.map {
                PlaintextCipher.Login(username: $0.username, password: $0.password, totp: $0.totp,
                                      uris: $0.uris ?? [], fido2Credentials: $0.fido2Credentials ?? [],
                                      passwordRevisionDate: $0.passwordRevisionDate)
            }
            return PlaintextCipher(type: item.type, name: item.name, notes: item.notes, folderID: item.folderId,
                                   favorite: item.favorite ?? false, reprompt: item.reprompt ?? 0,
                                   login: login, card: item.card, identity: item.identity, secureNote: item.secureNote,
                                   sshKey: item.sshKey, fields: item.fields ?? [])
        }
        return try validated(.init(folders: folders, items: items))
    }

    public static func encodeJSON(_ archive: VaultTransferArchive) throws -> Data {
        let items = archive.items.filter { $0.organizationID == nil && $0.deletedDate == nil }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .custom { date, output in
            var container = output.singleValueContainer()
            try container.encode(Date.ISO8601FormatStyle(includingFractionalSeconds: true).format(date))
        }
        let file = BitwardenFile(encrypted: false, folders: archive.folders.map { .init(id: $0.id, name: $0.name) },
                                 items: items.map(TransferItem.init), collections: nil)
        let output = try encoder.encode(file)
        try checkSize(output)
        return output
    }

    public static func validated(_ archive: VaultTransferArchive) throws -> VaultTransferArchive {
        guard archive.items.count <= maximumRecords, archive.folders.count <= maximumRecords else {
            throw VaultTransferError.fileTooLarge
        }
        guard !archive.items.isEmpty || !archive.folders.isEmpty else { throw VaultTransferError.emptyFile }
        let ids = Set(archive.folders.map(\.id))
        guard ids.count == archive.folders.count, archive.folders.allSatisfy({
            !$0.id.isEmpty && !$0.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        }) else { throw VaultTransferError.invalidFile }
        for item in archive.items {
            guard !item.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                  item.folderID.map(ids.contains) != false else { throw VaultTransferError.invalidFile }
            let type = CipherType(rawValue: item.type)
            if case .unknown = type { throw VaultTransferError.unsupportedItem }
            guard (item.login != nil) == (type == .login),
                  (item.card != nil) == (type == .card),
                  (item.identity != nil) == (type == .identity),
                  (item.secureNote != nil) == (type == .secureNote),
                  (item.sshKey != nil) == (type == .sshKey) else { throw VaultTransferError.invalidFile }
        }
        return archive
    }

    static func checkSize(_ data: Data) throws {
        guard !data.isEmpty else { throw VaultTransferError.emptyFile }
        guard data.count <= maximumBytes else { throw VaultTransferError.fileTooLarge }
    }
}

private struct EnvelopeHeader: Decodable { let encrypted: Bool? }
private struct ArchiveFolder: Codable { let id: String; let name: String }
private struct PresenceOnly: Codable {}

private struct BitwardenFile: Codable {
    let encrypted: Bool?
    let folders: [ArchiveFolder]?
    let items: [TransferItem]
    let collections: [IgnoredCollection]?

    struct IgnoredCollection: Codable {}
}

private struct TransferLogin: Codable {
    let username: String?
    let password: String?
    let totp: String?
    let uris: [PlaintextCipher.Uri]?
    let fido2Credentials: [PlaintextCipher.Fido2Credential]?
    let passwordRevisionDate: Date?
    let autofillOnPageLoad: Bool?
}

private struct TransferItem: Codable {
    let id: String?
    let folderId: String?
    let organizationId: String?
    let type: Int
    let name: String
    let notes: String?
    let favorite: Bool?
    let reprompt: Int?
    let fields: [PlaintextCipher.Field]?
    let login: TransferLogin?
    let card: PlaintextCipher.Card?
    let identity: PlaintextCipher.Identity?
    let secureNote: PlaintextCipher.SecureNote?
    let sshKey: PlaintextCipher.SshKey?
    let revisionDate: Date?
    let creationDate: Date?
    let deletedDate: Date?
    let archivedDate: Date?
    let passwordHistory: [PresenceOnly]?
    let attachments: [PresenceOnly]?

    init(_ item: PlaintextCipher) {
        id = item.id
        folderId = item.folderID
        organizationId = nil
        type = item.type
        name = item.name
        notes = item.notes
        favorite = item.favorite
        reprompt = item.reprompt
        fields = item.fields.isEmpty ? nil : item.fields
        login = item.login.map {
            TransferLogin(username: $0.username, password: $0.password, totp: $0.totp,
                          uris: $0.uris, fido2Credentials: $0.fido2Credentials,
                          passwordRevisionDate: $0.passwordRevisionDate, autofillOnPageLoad: nil)
        }
        card = item.card
        identity = item.identity
        secureNote = item.secureNote
        sshKey = item.sshKey
        revisionDate = item.revisionDate
        creationDate = item.creationDate
        deletedDate = nil
        archivedDate = nil
        passwordHistory = nil
        attachments = nil
    }
}

public enum VaultTransferWriter {
    public static func persist(_ input: VaultTransferArchive, to destination: String?,
                               existingFolders: [PlaintextFolder], vault: VaultService,
                               lease: AccountSessionLease) async throws -> Int {
        let archive = try VaultTransferCodec.validated(input)
        if let destination, !existingFolders.contains(where: { $0.id == destination }) {
            throw VaultTransferError.invalidFile
        }
        var mapped: [String: String] = [:]
        var savedFolders = 0
        do {
            if destination == nil {
                var byName = Dictionary(existingFolders.map { ($0.name, $0.id) }, uniquingKeysWith: { first, _ in first })
                for folder in archive.folders {
                    try Task.checkCancellation()
                    if let existing = byName[folder.name] { mapped[folder.id] = existing; continue }
                    let id = try await vault.importFolder(name: folder.name, for: lease)
                    byName[folder.name] = id
                    mapped[folder.id] = id
                    savedFolders += 1
                }
            }
            let items = try archive.items.map { original in
                try Task.checkCancellation()
                var item = original
                item.id = nil
                item.organizationID = nil
                item.protectedCipherKey = nil
                item.folderID = destination ?? item.folderID.flatMap { mapped[$0] }
                return item
            }
            try await vault.importCiphers(items, for: lease)
            return items.count
        } catch let partial as PartialCipherImport {
            throw VaultTransferError.partialImport(items: partial.savedCount, folders: savedFolders)
        } catch {
            guard savedFolders == 0 else {
                throw VaultTransferError.partialImport(items: 0, folders: savedFolders)
            }
            throw error
        }
    }
}
