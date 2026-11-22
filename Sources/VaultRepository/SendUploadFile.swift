import CryptoCore
import Foundation

struct SendUploadFile: Sendable {
    let url: URL
    let boundary: String
    let encryptedSize: Int

    init(source: URL, encryptedName: EncString, key: SymmetricCryptoKey) throws {
        guard source.isFileURL else { throw VaultSendError.invalidDraft }
        let scoped = source.startAccessingSecurityScopedResource()
        defer { if scoped { source.stopAccessingSecurityScopedResource() } }
        let values = try source.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
        let limit = 500 * 1024 * 1024
        guard values.isRegularFile == true else { throw VaultSendError.invalidDraft }
        guard values.fileSize.map({ $0 <= limit }) ?? true else { throw VaultSendError.fileTooLarge }

        let temp = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        guard FileManager.default.createFile(atPath: temp.path, contents: nil, attributes: [.posixPermissions: 0o600]) else {
            throw CocoaError(.fileWriteUnknown)
        }
        let boundary = "OpenVault-\(UUID().uuidString)"
        do {
            let output = try FileHandle(forWritingTo: temp)
            defer { try? output.close() }
            let input = try FileHandle(forReadingFrom: source)
            defer { try? input.close() }
            let header = "--\(boundary)\r\nContent-Disposition: form-data; name=\"data\"; filename=\"\(encryptedName.stringValue)\"\r\nContent-Type: application/octet-stream\r\n\r\n"
            try output.write(contentsOf: Data(header.utf8))
            encryptedSize = try SendCryptography.writeEncryptedFile(from: input, to: output, using: key, maximumBytes: limit)
            try output.write(contentsOf: Data("\r\n--\(boundary)--\r\n".utf8))
        } catch {
            try? FileManager.default.removeItem(at: temp)
            throw error
        }
        self.url = temp
        self.boundary = boundary
    }

    func discard() { try? FileManager.default.removeItem(at: url) }
}
