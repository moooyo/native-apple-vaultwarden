import CryptoCore
import Foundation
import VaultRepository

public enum VaultTransferImportFormat: Sendable {
    case bitwardenJSON, csv(VaultCSVSource), onePassword
}

public enum VaultTransferExportFormat: Sendable {
    case json, encryptedJSON, csv
}

public enum VaultTransferFiles {
    @concurrent public static func isEncrypted(_ data: Data) async throws -> Bool {
        try VaultTransferCodec.isEncryptedJSON(data)
    }

    @concurrent public static func read(_ url: URL) async throws -> Data {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        let values = try url.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
        guard values.isRegularFile == true else { throw VaultTransferError.invalidFile }
        guard (values.fileSize ?? 0) <= VaultTransferCodec.maximumBytes else { throw VaultTransferError.fileTooLarge }
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var data = Data()
        while let chunk = try handle.read(upToCount: 64 * 1_024), !chunk.isEmpty {
            try Task.checkCancellation()
            guard data.count + chunk.count <= VaultTransferCodec.maximumBytes else { throw VaultTransferError.fileTooLarge }
            data.append(chunk)
        }
        return data
    }

    @concurrent public static func decode(_ data: Data, format: VaultTransferImportFormat,
                                           password: String = "") async throws -> VaultTransferArchive {
        switch format {
        case .csv(let source): return try VaultTransferCodec.decodeCSV(data, source: source)
        case .onePassword: return try OnePasswordTransfer.decode(data)
        case .bitwardenJSON:
            if try VaultTransferCodec.isEncryptedJSON(data) {
                return try VaultTransferCodec.decodeJSON(PasswordProtectedExport.decrypt(data, password: password))
            }
            return try VaultTransferCodec.decodeJSON(data)
        }
    }

    @concurrent public static func prepareExport(format: VaultTransferExportFormat, filePassword: String = "",
                                                 masterPassword: String, auth: AuthService, vault: VaultService,
                                                 lease: AccountSessionLease) async throws -> Data {
        try await auth.verifyTransferPassword(masterPassword, for: lease)
        try Task.checkCancellation()
        let archive = try await vault.exportArchive(for: lease)
        try Task.checkCancellation()
        let output: Data
        switch format {
        case .json: output = try VaultTransferCodec.encodeJSON(archive)
        case .csv: output = try VaultTransferCodec.encodeCSV(archive)
        case .encryptedJSON:
            output = try PasswordProtectedExport.encrypt(VaultTransferCodec.encodeJSON(archive), password: filePassword)
        }
        try Task.checkCancellation()
        guard await auth.transferSession() == lease else { throw RepositoryError.locked }
        try Task.checkCancellation()
        return output
    }
}
