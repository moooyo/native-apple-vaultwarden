import CryptoKit
import Foundation
import Security

enum MacSSHSigningKeyChecks {
    private static let message = Data("OpenVault synthetic SSH signing check".utf8)
    private static let ed25519Name = "ssh-ed25519"

    static func run() throws {
        try checkEd25519()
        try checkECDSA()
        try checkRSA()
        print("SSH signing: verified OpenSSH and PKCS#8 Ed25519, NIST ECDSA and RSA SHA-2; rejected mismatched, encrypted and malformed keys.")
    }

    private static func checkEd25519() throws {
        let key = Curve25519.Signing.PrivateKey()
        let publicBytes = key.publicKey.rawRepresentation
        let seed = key.rawRepresentation
        let blob = field(ed25519Name) + field(publicBytes)
        let publicKey = authorizedKey(ed25519Name, blob: blob)
        let privateFields = field(ed25519Name) + field(publicBytes) + field(seed + publicBytes)
        let openssh = openSSH(blob: blob, privateFields: privateFields)
        let pkcs8 = privateInfo(algorithm: Data([0x06, 0x03, 0x2b, 0x65, 0x70]), key: der(0x04, seed))
        let pkcs8WithPublic = privateInfo(algorithm: Data([0x06, 0x03, 0x2b, 0x65, 0x70]), key: der(0x04, seed), publicKey: publicBytes)

        try require(try MacSSHSigningKey.publicKeyBlob(publicKey: publicKey) == blob, "read an authorized key without private material")
        for privateKey in [openssh, pkcs8, pkcs8WithPublic] {
            try require(try MacSSHSigningKey.publicKeyBlob(privateKey: privateKey, publicKey: publicKey) == blob, "match the Ed25519 key pair")
            let signature = try signatureFields(flags: 0, privateKey: privateKey, publicKey: publicKey)
            try require(signature[0] == Data(ed25519Name.utf8) && signature[1].count == 64 &&
                        key.publicKey.isValidSignature(signature[1], for: message), "verify the Ed25519 signature blob")
        }

        var otherSeed = seed
        otherSeed[otherSeed.startIndex] ^= 1
        var otherPublic = publicBytes
        otherPublic[otherPublic.startIndex] ^= 1
        try reject(.mismatchedKey, "Ed25519 seed must derive the declared public key") {
            let forged = field(ed25519Name) + field(publicBytes) + field(otherSeed + publicBytes)
            _ = try signatureFields(flags: 0, privateKey: openSSH(blob: blob, privateFields: forged), publicKey: publicKey)
        }
        try reject(.mismatchedKey, "the Ed25519 keypair copy must match") {
            let forged = field(ed25519Name) + field(publicBytes) + field(seed + otherPublic)
            _ = try signatureFields(flags: 0, privateKey: openSSH(blob: blob, privateFields: forged), publicKey: publicKey)
        }
        try reject(.mismatchedKey, "the OpenSSH outer public blob must match") {
            let otherBlob = field(ed25519Name) + field(otherPublic)
            _ = try signatureFields(flags: 0, privateKey: openSSH(blob: otherBlob, privateFields: privateFields), publicKey: publicKey)
        }
        try reject(.mismatchedKey, "the PKCS#8 optional public field must match") {
            let forged = privateInfo(algorithm: Data([0x06, 0x03, 0x2b, 0x65, 0x70]), key: der(0x04, seed), publicKey: otherPublic)
            _ = try signatureFields(flags: 0, privateKey: forged, publicKey: publicKey)
        }
        try reject(.unsupportedFlags, "Ed25519 cannot use an RSA flag") {
            _ = try signatureFields(flags: 4, privateKey: openssh, publicKey: publicKey)
        }
        try reject(.unsupportedKey, "encrypted OpenSSH keys are not imported by the agent") {
            _ = try signatureFields(flags: 0, privateKey: openSSH(blob: blob, privateFields: privateFields, cipher: "aes256-ctr"), publicKey: publicKey)
        }
        try reject(.unsupportedKey, "encrypted PKCS#8 keys are not imported by the agent") {
            let encrypted = pem("ENCRYPTED PRIVATE KEY", der(0x30, Data([0x02, 0x01, 0x00])))
            _ = try signatureFields(flags: 0, privateKey: encrypted, publicKey: publicKey)
        }
        try reject(.unsupportedKey, "PKCS#8 attributes are not consumed by the agent") {
            let attribute = der(0x30, der(0x06, Data([0x2a, 0x03])) + der(0x31, der(0x04, Data([1]))))
            let attributed = privateInfo(algorithm: Data([0x06, 0x03, 0x2b, 0x65, 0x70]), key: der(0x04, seed), attributes: attribute)
            _ = try signatureFields(flags: 0, privateKey: attributed, publicKey: publicKey)
        }
        let malformed = [
            openSSH(blob: blob, privateFields: privateFields, check: 0x1243),
            openSSH(blob: blob, privateFields: privateFields, finalPadding: 0xfe),
            openSSH(blob: blob, privateFields: privateFields, keyCount: 2),
            openSSH(blob: blob, privateFields: privateFields, trailing: Data([0])),
            openSSH(blob: blob, privateFields: field(ed25519Name) + integer(UInt32.max)),
            openssh + openssh,
            String(repeating: "A", count: 16 * 1024 + 1),
            pem("PRIVATE KEY", Data([0x30, 0x81, 0x01, 0x00])),
            pem("PRIVATE KEY", Data([0x30, 0x80, 0x00, 0x00])),
            pem("PRIVATE KEY", Data([0x30, 0x83, 0x01, 0, 0])),
            pem("PRIVATE KEY", Data([0x30, 0x82, 0xff, 0xff, 0x00]))
        ]
        for (index, privateKey) in malformed.enumerated() {
            try reject(.invalidKey, "malformed Ed25519 key \(index + 1) is refused") {
                _ = try signatureFields(flags: 0, privateKey: privateKey, publicKey: publicKey)
            }
        }
        try reject(.invalidKey, "trailing public blob data is refused") {
            _ = try MacSSHSigningKey.publicKeyBlob(publicKey: authorizedKey(ed25519Name, blob: blob + Data([0])))
        }
        try reject(.invalidKey, "oversized public blob data is refused") {
            _ = try MacSSHSigningKey.publicKeyBlob(publicKey: authorizedKey(ed25519Name, blob: Data(repeating: 0, count: 2049)))
        }
        try reject(.mismatchedKey, "the public text algorithm must match the binary algorithm") {
            _ = try MacSSHSigningKey.publicKeyBlob(publicKey: authorizedKey("ssh-rsa", blob: blob))
        }
        try reject(.unsupportedKey, "unknown signing types are refused") {
            _ = try MacSSHSigningKey.publicKeyBlob(publicKey: authorizedKey("ssh-dss", blob: field("ssh-dss")))
        }
    }

    private static func checkECDSA() throws {
        let p256 = P256.Signing.PrivateKey()
        try checkCurve("nistp256", point: p256.publicKey.x963Representation, scalar: p256.rawRepresentation, pkcs8: p256.derRepresentation) { raw in
            p256.publicKey.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation: raw), for: SHA256.hash(data: message))
        }
        let p384 = P384.Signing.PrivateKey()
        try checkCurve("nistp384", point: p384.publicKey.x963Representation, scalar: p384.rawRepresentation, pkcs8: p384.derRepresentation) { raw in
            p384.publicKey.isValidSignature(try P384.Signing.ECDSASignature(rawRepresentation: raw), for: SHA384.hash(data: message))
        }
        let p521 = try P521.Signing.PrivateKey(rawRepresentation: Data(repeating: 0, count: 64) + Data([0x6b, 0x91]))
        try checkCurve("nistp521", point: p521.publicKey.x963Representation, scalar: p521.rawRepresentation, pkcs8: p521.derRepresentation) { raw in
            p521.publicKey.isValidSignature(try P521.Signing.ECDSASignature(rawRepresentation: raw), for: SHA512.hash(data: message))
        }
    }

    private static func checkCurve(_ curve: String, point: Data, scalar: Data, pkcs8: Data, verify: (Data) throws -> Bool) throws {
        let format = "ecdsa-sha2-\(curve)"
        let blob = field(format) + field(curve) + field(point)
        let publicKey = authorizedKey(format, blob: blob)
        let shortScalar = Data(scalar.drop(while: { $0 == 0 }))
        let fixedScalar = (scalar.first ?? 0) >= 128 ? Data([0]) + scalar : scalar
        let openFormat = openSSH(blob: blob, privateFields: blob + positiveIntegerField(shortScalar))
        let fixedWidthFormat = openSSH(blob: blob, privateFields: blob + field(fixedScalar))
        for privateKey in [openFormat, fixedWidthFormat, pem("PRIVATE KEY", pkcs8)] {
            try require(try MacSSHSigningKey.publicKeyBlob(privateKey: privateKey, publicKey: publicKey) == blob, "match the \(curve) key pair")
            let signature = try signatureFields(flags: 0, privateKey: privateKey, publicKey: publicKey)
            let fields = try wireFields(signature[1], count: 2)
            var raw = Data()
            for field in fields {
                let width = scalar.count
                guard let first = field.first, first < 128 else { throw SigningCheckFailure(description: "negative \(curve) signature integer") }
                let unsigned = first == 0 ? field.dropFirst() : field
                try require(!unsigned.isEmpty && unsigned.count <= width && (first != 0 || (unsigned.first ?? 0) >= 128),
                            "encode canonical positive mpints in the \(curve) signature")
                raw.append(Data(repeating: 0, count: width - unsigned.count))
                raw.append(unsigned)
            }
            try require(try signature[0] == Data(format.utf8) && verify(raw), "verify the \(curve) signature blob")
        }
        let differentScalar = Data([scalar.last == 1 ? 2 : 1])
        try reject(.mismatchedKey, "the \(curve) scalar must derive the declared public point") {
            let forged = openSSH(blob: blob, privateFields: blob + positiveIntegerField(differentScalar))
            _ = try signatureFields(flags: 0, privateKey: forged, publicKey: publicKey)
        }
        try reject(.invalidKey, "out-of-range \(curve) scalars are refused") {
            let forged = openSSH(blob: blob, privateFields: blob + positiveIntegerField(Data(repeating: 0xff, count: scalar.count)))
            _ = try signatureFields(flags: 0, privateKey: forged, publicKey: publicKey)
        }
        try reject(.invalidKey, "off-curve \(curve) public points are refused") {
            let wrong = Data([4]) + Data(repeating: 0, count: point.count - 1)
            let invalidBlob = field(format) + field(curve) + field(wrong)
            _ = try MacSSHSigningKey.publicKeyBlob(publicKey: authorizedKey(format, blob: invalidBlob))
        }
    }

    private static func checkRSA() throws {
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits: 2048,
            kSecPrivateKeyAttrs: [kSecAttrIsPermanent: false]
        ]
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, nil),
              let publicVerifier = SecKeyCopyPublicKey(key),
              var keyData = SecKeyCopyExternalRepresentation(key, nil) as Data? else {
            throw SigningCheckFailure(description: "generate an ephemeral RSA test key")
        }
        defer { keyData.resetBytes(in: keyData.indices) }
        let fields = try rsaFields(keyData)
        let modulus = fields[1]
        let exponent = fields[2]
        let blob = field("ssh-rsa") + field(exponent) + field(modulus)
        let publicKey = authorizedKey("ssh-rsa", blob: blob)
        let algorithm = Data([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00])
        let pkcs8 = privateInfo(algorithm: algorithm, key: keyData)
        let openSSHKey = openSSH(blob: blob, privateFields: rsaOpenFields(fields))
        let supported: [(UInt32, String, SecKeyAlgorithm)] = [
            (2, "rsa-sha2-256", .rsaSignatureMessagePKCS1v15SHA256),
            (4, "rsa-sha2-512", .rsaSignatureMessagePKCS1v15SHA512),
            (6, "rsa-sha2-256", .rsaSignatureMessagePKCS1v15SHA256)
        ]
        for privateKey in [openSSHKey, pkcs8] {
            try require(try MacSSHSigningKey.publicKeyBlob(privateKey: privateKey, publicKey: publicKey) == blob, "match the RSA key pair")
            for (flags, format, algorithm) in supported {
                let signature = try signatureFields(flags: flags, privateKey: privateKey, publicKey: publicKey)
                try require(signature[0] == Data(format.utf8) && signature[1].count == 256 &&
                            SecKeyVerifySignature(publicVerifier, algorithm, message as CFData, signature[1] as CFData, nil),
                            "verify the fixed-width \(format) signature blob")
            }
        }
        for flags: UInt32 in [0, 1, 8, 10, UInt32.max] {
            try reject(.unsupportedFlags, "RSA must request SHA-2 without unknown flags") {
                _ = try signatureFields(flags: flags, privateKey: openSSHKey, publicKey: publicKey)
            }
        }
        for index in [3, 4, 5, 8] {
            var corrupt = fields
            corrupt[index][corrupt[index].index(before: corrupt[index].endIndex)] ^= 4
            try reject(.invalidKey, "RSA OpenSSH private parameter \(index) must be consistent") {
                _ = try signatureFields(flags: 2, privateKey: openSSH(blob: blob, privateFields: rsaOpenFields(corrupt)), publicKey: publicKey)
            }
        }
        var badCRT = fields
        badCRT[6][badCRT[6].index(before: badCRT[6].endIndex)] ^= 4
        let encoded = der(0x30, badCRT.reduce(into: Data()) { $0.append(der(0x02, $1)) })
        try reject(.invalidKey, "the PKCS#8 encoded CRT exponents must match the private exponent") {
            _ = try signatureFields(flags: 2, privateKey: privateInfo(algorithm: algorithm, key: encoded), publicKey: publicKey)
        }
    }

    private static func rsaOpenFields(_ fields: [Data]) -> Data {
        [1, 2, 3, 8, 4, 5].reduce(into: field("ssh-rsa")) { $0.append(field(fields[$1])) }
    }

    private static func signatureFields(flags: UInt32, privateKey: String, publicKey: String) throws -> [Data] {
        let signature = try MacSSHSigningKey.sign(data: message, flags: flags, privateKey: privateKey, publicKey: publicKey)
        let hostKey = try MacSSHSigningKey.publicKeyBlob(publicKey: publicKey)
        try require(MacSSHSigningKey.verifyHostSignature(signature, for: message, hostKey: hostKey)
                    && !MacSSHSigningKey.verifyHostSignature(signature, for: message + Data([1]), hostKey: hostKey),
                    "the host verifier authenticates the exact exchange hash with the same public key")
        return try wireFields(signature, count: 2)
    }

    private static func wireFields(_ data: Data, count: Int) throws -> [Data] {
        var rest = data[...]
        let fields = try (0..<count).map { _ in
            guard rest.count >= 4 else { throw SigningCheckFailure(description: "decode test SSH field length") }
            let length = rest.prefix(4).reduce(0) { ($0 << 8) | Int($1) }
            rest = rest.dropFirst(4)
            guard rest.count >= length else { throw SigningCheckFailure(description: "decode test SSH field bytes") }
            let value = Data(rest.prefix(length))
            rest = rest.dropFirst(length)
            return value
        }
        try require(rest.isEmpty, "only the expected fields are present in the SSH signature")
        return fields
    }

    private static func rsaFields(_ data: Data) throws -> [Data] {
        var input = data[...]
        var sequence = try readDER(0x30, &input)
        let fields = try (0..<9).map { _ in Data(try readDER(0x02, &sequence)) }
        try require(input.isEmpty && sequence.isEmpty && fields[0] == Data([0]), "decode the generated two-prime RSA fixture")
        return fields
    }

    private static func readDER(_ tag: UInt8, _ data: inout Data.SubSequence) throws -> Data.SubSequence {
        guard data.count >= 2, data.removeFirst() == tag else { throw SigningCheckFailure(description: "decode the generated fixture ASN.1 tag") }
        let prefix = data.removeFirst()
        let size = Int(prefix & 0x7f)
        let length: Int
        if prefix < 128 { length = size }
        else {
            guard (1...2).contains(size), data.count >= size else { throw SigningCheckFailure(description: "decode fixture ASN.1 length") }
            length = (0..<size).reduce(0) { value, _ in (value << 8) | Int(data.removeFirst()) }
        }
        guard data.count >= length else { throw SigningCheckFailure(description: "read fixture ASN.1 bytes") }
        let result = data.prefix(length)
        data = data.dropFirst(length)
        return result
    }

    private static func authorizedKey(_ format: String, blob: Data) -> String {
        "\(format) \(blob.base64EncodedString()) disposable test key\n"
    }

    private static func openSSH(blob: Data, privateFields: Data, cipher: String = "none", check: UInt32 = 0x1242,
                                finalPadding: UInt8? = nil, keyCount: UInt32 = 1, trailing: Data = Data()) -> String {
        var payload = integer(0x1242) + integer(check) + privateFields + field("fixture")
        var padding: UInt8 = 1
        while payload.count % 8 != 0 {
            payload.append(padding)
            padding += 1
        }
        if let finalPadding { payload[payload.index(before: payload.endIndex)] = finalPadding }
        var encoded = Data("openssh-key-v1\0".utf8) + field(cipher) + field(cipher == "none" ? "none" : "bcrypt")
        encoded.append(field(Data()))
        encoded.append(integer(keyCount))
        encoded.append(field(blob))
        encoded.append(field(payload))
        encoded.append(trailing)
        return pem("OPENSSH PRIVATE KEY", encoded)
    }

    private static func privateInfo(algorithm: Data, key: Data, publicKey: Data? = nil, attributes: Data? = nil) -> String {
        var payload = der(0x02, Data([publicKey == nil ? 0 : 1])) + der(0x30, algorithm) + der(0x04, key)
        if let attributes { payload.append(der(0xa0, attributes)) }
        if let publicKey { payload.append(der(0x81, Data([0]) + publicKey)) }
        return pem("PRIVATE KEY", der(0x30, payload))
    }

    private static func pem(_ name: String, _ data: Data) -> String {
        "-----BEGIN \(name)-----\n\(data.base64EncodedString(options: .lineLength64Characters))\n-----END \(name)-----\n"
    }

    private static func der(_ tag: UInt8, _ bytes: Data) -> Data {
        var length = Data()
        if bytes.count < 128 { length.append(UInt8(bytes.count)) }
        else if bytes.count < 256 { length.append(contentsOf: [0x81, UInt8(bytes.count)]) }
        else { length.append(contentsOf: [0x82, UInt8(bytes.count / 256), UInt8(bytes.count % 256)]) }
        return Data([tag]) + length + bytes
    }

    private static func integer(_ value: UInt32) -> Data {
        Data([24, 16, 8, 0].map { UInt8(truncatingIfNeeded: value >> $0) })
    }

    private static func field(_ text: String) -> Data { field(Data(text.utf8)) }

    private static func field(_ bytes: Data) -> Data { integer(UInt32(bytes.count)) + bytes }

    private static func positiveIntegerField(_ bytes: Data) -> Data {
        field((bytes.first ?? 0) < 128 ? bytes : Data([0]) + bytes)
    }

    private static func reject(_ expected: MacSSHSigningKey.Failure, _ message: String, perform: () throws -> Void) throws {
        do { try perform() }
        catch let error as MacSSHSigningKey.Failure where error == expected { return }
        catch { throw SigningCheckFailure(description: message + " (unexpected failure \(error))") }
        throw SigningCheckFailure(description: message)
    }

    private static func require(_ result: Bool, _ message: String) throws {
        guard result else { throw SigningCheckFailure(description: message) }
    }

    private struct SigningCheckFailure: Error, CustomStringConvertible {
        let description: String
    }
}
