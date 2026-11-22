import CryptoCore
import Foundation

func checkSendCryptography(_ runner: inout TestRunner) {
    do {
        let seed = Data(base64Encoded: "Pgui0FK85cNhBGWHAlBHBw==")!
        let contentKey = try SendCryptography.contentKey(secret: seed)
        let name = try EncString(parsing: "2.STIyTrfDZN/JXNDN9zNEMw==|NDLum8BHZpPNYhJo9ggSkg==|UCsCLlBO3QzdPwvMAWs2VVwuE6xwOx/vxOooPObqnEw=")
        let text = try EncString(parsing: "2.2VPyLzk1tMLug0X3x7RkaQ==|mrMt9vbZsCJhJIj4eebKyg==|aZ7JeyndytEMR1+uEBupEvaZuUE69D/ejhfdJL8oKq0=")
        runner.expect(try SymmetricCrypto.decrypt(name, using: contentKey), Data("Test".utf8), "SDK Send name vector")
        runner.expect(try SymmetricCrypto.decrypt(text, using: contentKey), Data("This is a test".utf8), "SDK Send text vector")
        runner.expect(try SendCryptography.passwordVerifier("abc123", secret: seed),
                      "vTIDfdj3FTDbejmMf+mJWpYdMXsxfeSd1Sma3sjCtiQ=", "SDK Send password verifier vector")
        runner.expectThrowsError(CryptoError.invalidKeyLength, "reject a nonstandard Send seed") {
            _ = try SendCryptography.contentKey(secret: Data(count: 32))
        }
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let inputURL = directory.appendingPathComponent("input")
        let outputURL = directory.appendingPathComponent("output")
        let bytes = Data((0..<132_003).map { UInt8(truncatingIfNeeded: $0) })
        try bytes.write(to: inputURL)
        try Data().write(to: outputURL)
        let input = try FileHandle(forReadingFrom: inputURL)
        defer { try? input.close() }
        let output = try FileHandle(forWritingTo: outputURL)
        defer { try? output.close() }
        try output.write(contentsOf: Data("header".utf8))
        let count = try SendCryptography.writeEncryptedFile(from: input, to: output, using: contentKey, maximumBytes: bytes.count)
        let file = Data(try Data(contentsOf: outputURL).dropFirst(6))
        runner.expect(file.first, 2, "Send file uses binary EncString type 2")
        runner.expect(file.count, count, "reserved size excludes multipart framing")
        let encrypted = EncString(type: .aesCbc256_HmacSha256_B64, iv: file.subdata(in: 1..<17),
                                  ciphertext: file.suffix(from: 49), mac: file.subdata(in: 17..<49))
        runner.expectTrue(try SymmetricCrypto.decrypt(encrypted, using: contentKey) == bytes,
                          "streaming Send file authenticates and round-trips multiple chunks")
    } catch {
        runner.expectTrue(false, "Send cryptography: \(error)")
    }
}
