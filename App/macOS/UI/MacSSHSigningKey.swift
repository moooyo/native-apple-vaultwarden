import CryptoKit
import Foundation

enum MacSSHSigningKey {
    enum Failure: Error, Equatable {
        case invalidKey
        case unsupportedKey
        case mismatchedKey
        case unsupportedFlags
        case signingFailed
    }

    private static let maximumPEMSize = 16 * 1024
    private static let maximumPublicBlobSize = 2048
    private static let ed25519Name = "ssh-ed25519"
    private static let rsaName = "ssh-rsa"

    static func publicKeyBlob(publicKey: String) throws -> Data {
        try parsePublicKey(publicKey).blob
    }

    static func publicKeyBlob(privateKey: String, publicKey: String) throws -> Data {
        let expected = try parsePublicKey(publicKey)
        _ = try matchingPrivateKey(privateKey, expected: expected)
        return expected.blob
    }

    static func sign(data: Data, flags: UInt32, privateKey: String, publicKey: String) throws -> Data {
        let expected = try parsePublicKey(publicKey)
        switch expected {
        case .rsa: guard [2, 4, 6].contains(flags) else { throw Failure.unsupportedFlags }
        default: guard flags == 0 else { throw Failure.unsupportedFlags }
        }
        let material = try matchingPrivateKey(privateKey, expected: expected)
        do {
            let (format, signature) = try material.signature(for: data, flags: flags)
            return MacSSHKeyEncoding.string(format) + MacSSHKeyEncoding.string(signature)
        } catch let error as Failure {
            throw error
        } catch {
            throw Failure.signingFailed
        }
    }

    private static func parsePublicKey(_ text: String) throws -> PublicMaterial {
        guard text.utf8.count <= maximumPEMSize else { throw Failure.invalidKey }
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        let parts = trimmed.split(maxSplits: 2, whereSeparator: \.isWhitespace)
        guard !trimmed.contains(where: \.isNewline), parts.count >= 2,
              parts[1].utf8.count <= ((maximumPublicBlobSize + 2) / 3) * 4,
              let blob = Data(base64Encoded: String(parts[1])), blob.count <= maximumPublicBlobSize else {
            throw Failure.invalidKey
        }
        let material = try parsePublicBlob(blob)
        guard material.format == parts[0] else { throw Failure.mismatchedKey }
        return material
    }

    private static func parsePublicBlob(_ blob: Data) throws -> PublicMaterial {
        guard blob.count <= maximumPublicBlobSize else { throw Failure.invalidKey }
        var reader = MacSSHKeyReader(blob)
        let format = try reader.name()
        let material: PublicMaterial
        switch format {
        case ed25519Name:
            let bytes = try reader.string(maximum: 32)
            guard bytes.count == 32 else { throw Failure.invalidKey }
            material = .ed25519(bytes)
        case rsaName:
            let exponent = try reader.mpint(maximum: MacSSHRSAKey.maximumExponentSize)
            let modulus = try reader.mpint(maximum: MacSSHRSAKey.maximumModulusSize)
            material = .rsa(try .init(modulus: modulus, exponent: exponent))
        default:
            guard let curve = Curve(algorithm: format) else { throw Failure.unsupportedKey }
            guard try reader.name() == curve.rawValue else { throw Failure.mismatchedKey }
            let point = try reader.string(maximum: curve.width * 2 + 1)
            try curve.validate(point: point)
            material = .ecdsa(curve, point)
        }
        guard reader.isEmpty else { throw Failure.invalidKey }
        return material
    }

    static func verifyHostSignature(_ signature: Data, for session: Data, hostKey: Data) -> Bool {
        do {
            let key = try parsePublicBlob(hostKey)
            var reader = MacSSHKeyReader(signature)
            let algorithm = try reader.name()
            let raw = try reader.string(maximum: maximumPublicBlobSize)
            guard reader.isEmpty else { return false }
            switch key {
            case let .ed25519(bytes):
                guard algorithm == key.format, raw.count == 64 else { return false }
                return try Curve25519.Signing.PublicKey(rawRepresentation: bytes).isValidSignature(raw, for: session)
            case let .ecdsa(curve, point):
                guard algorithm == key.format else { return false }
                var pair = MacSSHKeyReader(raw)
                let r = try pair.mpint(maximum: curve.width)
                let s = try pair.mpint(maximum: curve.width)
                guard pair.isEmpty else { return false }
                let padded = Data(count: curve.width - r.count) + r + Data(count: curve.width - s.count) + s
                switch curve {
                case .p256: return try P256.Signing.PublicKey(x963Representation: point)
                    .isValidSignature(P256.Signing.ECDSASignature(rawRepresentation: padded), for: SHA256.hash(data: session))
                case .p384: return try P384.Signing.PublicKey(x963Representation: point)
                    .isValidSignature(P384.Signing.ECDSASignature(rawRepresentation: padded), for: SHA384.hash(data: session))
                case .p521: return try P521.Signing.PublicKey(x963Representation: point)
                    .isValidSignature(P521.Signing.ECDSASignature(rawRepresentation: padded), for: SHA512.hash(data: session))
                }
            case let .rsa(components):
                return MacSSHRSAKey.verifyHostSignature(raw, for: session, algorithm: algorithm, components: components)
            }
        } catch { return false }
    }

    private static func matchingPrivateKey(_ text: String, expected: PublicMaterial) throws -> PrivateMaterial {
        guard text.utf8.count <= maximumPEMSize else { throw Failure.invalidKey }
        let lines = text.split(whereSeparator: \.isNewline)
        guard lines.count >= 3, let header = lines.first, let footer = lines.last else { throw Failure.invalidKey }
        let isOpenSSH: Bool
        switch (header, footer) {
        case ("-----BEGIN OPENSSH PRIVATE KEY-----", "-----END OPENSSH PRIVATE KEY-----"): isOpenSSH = true
        case ("-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----"): isOpenSSH = false
        default: throw Failure.unsupportedKey
        }
        var encoded = Data(capacity: text.utf8.count)
        for line in lines.dropFirst().dropLast() { encoded.append(contentsOf: line.utf8) }
        defer { encoded.resetBytes(in: encoded.indices) }
        guard var bytes = Data(base64Encoded: encoded), !bytes.isEmpty else {
            throw Failure.invalidKey
        }
        defer { bytes.resetBytes(in: bytes.indices) }
        do {
            let material = try isOpenSSH ? parseOpenSSH(bytes, expected: expected) : parsePKCS8(bytes, expected: expected)
            guard material.publicMaterial == expected else { throw Failure.mismatchedKey }
            return material
        } catch let error as Failure {
            throw error
        } catch {
            throw Failure.invalidKey
        }
    }

    private static func parseOpenSSH(_ bytes: Data, expected: PublicMaterial) throws -> PrivateMaterial {
        var reader = MacSSHKeyReader(bytes)
        let magic = Data("openssh-key-v1\0".utf8)
        guard try reader.bytes(magic.count) == magic else { throw Failure.invalidKey }
        guard try reader.name() == "none", try reader.name() == "none" else { throw Failure.unsupportedKey }
        guard try reader.string(maximum: 0).isEmpty, try reader.uint32() == 1 else { throw Failure.invalidKey }
        guard try reader.string(maximum: maximumPublicBlobSize) == expected.blob else { throw Failure.mismatchedKey }
        let payload = try reader.string(maximum: maximumPEMSize)
        guard reader.isEmpty, payload.count >= 8, payload.count % 8 == 0 else { throw Failure.invalidKey }
        var fields = MacSSHKeyReader(payload)
        let check = try fields.uint32()
        guard try fields.uint32() == check else { throw Failure.invalidKey }
        guard try fields.name() == expected.format else { throw Failure.mismatchedKey }
        let material: PrivateMaterial
        switch expected {
        case .ed25519(let publicBytes):
            let declared = try fields.string(maximum: 32)
            let keypair = try fields.string(maximum: 64)
            guard keypair.count == 64 else { throw Failure.invalidKey }
            guard declared == publicBytes, keypair.suffix(32) == publicBytes else { throw Failure.mismatchedKey }
            material = .ed25519(try Curve25519.Signing.PrivateKey(rawRepresentation: keypair.prefix(32)))
        case .ecdsa(let curve, let point):
            guard try fields.name() == curve.rawValue,
                  try fields.string(maximum: curve.width * 2 + 1) == point else { throw Failure.mismatchedKey }
            let encoded = try fields.string(maximum: curve.width + 1)
            let scalar: Data
            if encoded.count == curve.width, encoded.first == 0 {
                scalar = encoded.drop(while: { $0 == 0 })
                guard !scalar.isEmpty else { throw Failure.invalidKey }
            } else {
                scalar = try MacSSHKeyEncoding.positiveMagnitude(encoded, maximum: curve.width)
            }
            var normalized = Data(repeating: 0, count: curve.width - scalar.count)
            normalized.append(scalar)
            defer { normalized.resetBytes(in: normalized.indices) }
            material = try curve.privateKey(normalized)
        case .rsa(let components):
            let modulus = try fields.mpint(maximum: MacSSHRSAKey.maximumModulusSize)
            let exponent = try fields.mpint(maximum: MacSSHRSAKey.maximumExponentSize)
            guard modulus == components.modulus, exponent == components.exponent else { throw Failure.mismatchedKey }
            let privateExponent = try fields.mpint(maximum: modulus.count)
            let primeLimit = modulus.count / 2 + 1
            let coefficient = try fields.mpint(maximum: primeLimit)
            let firstPrime = try fields.mpint(maximum: primeLimit)
            let secondPrime = try fields.mpint(maximum: primeLimit)
            material = .rsa(try MacSSHRSAKey(components: components, privateExponent: privateExponent,
                                             prime1: firstPrime, prime2: secondPrime, coefficient: coefficient))
        }
        _ = try fields.string(maximum: 4096)
        guard fields.remaining < 8 else { throw Failure.invalidKey }
        let paddingCount = fields.remaining
        for (offset, byte) in try fields.bytes(paddingCount).enumerated() {
            guard byte == UInt8(offset + 1) else { throw Failure.invalidKey }
        }
        return material
    }

    private static func parsePKCS8(_ bytes: Data, expected: PublicMaterial) throws -> PrivateMaterial {
        var der = MacSSHKeyReader(bytes)
        var info = MacSSHKeyReader(try der.derValue(tag: 0x30))
        guard der.isEmpty else { throw Failure.invalidKey }
        let version = try info.derValue(tag: 0x02)
        guard version == Data([0]) || version == Data([1]) else { throw Failure.invalidKey }
        var algorithm = MacSSHKeyReader(try info.derValue(tag: 0x30))
        let oid = try algorithm.derValue(tag: 0x06)
        let privateData = try info.derValue(tag: 0x04)
        guard info.nextByte != 0xa0 else { throw Failure.unsupportedKey }
        let declaredPublic = version == Data([1]) ? try info.derBitString(tag: 0x81) : nil
        guard info.isEmpty else { throw Failure.invalidKey }
        switch expected {
        case .ed25519(let publicBytes):
            guard oid == Data([0x2b, 0x65, 0x70]), algorithm.isEmpty else { throw Failure.mismatchedKey }
            guard declaredPublic.map({ $0 == publicBytes }) ?? true else { throw Failure.mismatchedKey }
            var seed = MacSSHKeyReader(privateData)
            let value = try seed.derValue(tag: 0x04)
            guard seed.isEmpty, value.count == 32 else { throw Failure.invalidKey }
            return .ed25519(try Curve25519.Signing.PrivateKey(rawRepresentation: value))
        case .rsa(let components):
            guard oid == Data([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]) else { throw Failure.mismatchedKey }
            if !algorithm.isEmpty {
                guard try algorithm.derValue(tag: 0x05).isEmpty, algorithm.isEmpty else { throw Failure.invalidKey }
            }
            guard declaredPublic.map({ $0 == components.der }) ?? true else { throw Failure.mismatchedKey }
            return .rsa(try parsePKCS8RSA(privateData, components: components))
        case .ecdsa(let curve, let point):
            guard oid == Data([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]),
                  try algorithm.derValue(tag: 0x06) == curve.oid, algorithm.isEmpty,
                  declaredPublic.map({ $0 == point }) ?? true else { throw Failure.mismatchedKey }
            var privateReader = MacSSHKeyReader(privateData)
            var sec1 = MacSSHKeyReader(try privateReader.derValue(tag: 0x30))
            guard privateReader.isEmpty, try sec1.derValue(tag: 0x02) == Data([1]) else { throw Failure.invalidKey }
            let scalar = try sec1.derValue(tag: 0x04)
            if sec1.nextByte == 0xa0 {
                var parameters = MacSSHKeyReader(try sec1.derValue(tag: 0xa0))
                guard try parameters.derValue(tag: 0x06) == curve.oid, parameters.isEmpty else { throw Failure.mismatchedKey }
            }
            if sec1.nextByte == 0xa1 {
                var publicPoint = MacSSHKeyReader(try sec1.derValue(tag: 0xa1))
                guard try publicPoint.derBitString() == point, publicPoint.isEmpty else { throw Failure.mismatchedKey }
            }
            guard sec1.isEmpty else { throw Failure.invalidKey }
            return try curve.privateKey(scalar)
        }
    }

    private static func parsePKCS8RSA(_ bytes: Data, components: MacSSHRSAKey.Components) throws -> MacSSHRSAKey {
        var der = MacSSHKeyReader(bytes)
        var fields = MacSSHKeyReader(try der.derValue(tag: 0x30))
        guard der.isEmpty, try fields.derValue(tag: 0x02) == Data([0]) else { throw Failure.invalidKey }
        let modulus = try fields.derInteger(maximum: MacSSHRSAKey.maximumModulusSize)
        let exponent = try fields.derInteger(maximum: MacSSHRSAKey.maximumExponentSize)
        guard modulus == components.modulus, exponent == components.exponent else { throw Failure.mismatchedKey }
        let privateExponent = try fields.derInteger(maximum: modulus.count)
        let primeLimit = modulus.count / 2 + 1
        let firstPrime = try fields.derInteger(maximum: primeLimit)
        let secondPrime = try fields.derInteger(maximum: primeLimit)
        let firstExponent = try fields.derInteger(maximum: primeLimit)
        let secondExponent = try fields.derInteger(maximum: primeLimit)
        let coefficient = try fields.derInteger(maximum: primeLimit)
        guard fields.isEmpty else { throw Failure.invalidKey }
        return try MacSSHRSAKey(components: components, privateExponent: privateExponent,
                                prime1: firstPrime, prime2: secondPrime, coefficient: coefficient,
                                encodedDER: bytes, encodedExponent1: firstExponent, encodedExponent2: secondExponent)
    }

    private enum Curve: String, CaseIterable {
        case p256 = "nistp256"
        case p384 = "nistp384"
        case p521 = "nistp521"

        init?(algorithm: String) {
            guard let curve = Self.allCases.first(where: { $0.algorithm == algorithm }) else { return nil }
            self = curve
        }

        var algorithm: String { "ecdsa-sha2-\(rawValue)" }

        var width: Int {
            switch self {
            case .p256: 32
            case .p384: 48
            case .p521: 66
            }
        }

        var oid: Data {
            switch self {
            case .p256: Data([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07])
            case .p384: Data([0x2b, 0x81, 0x04, 0x00, 0x22])
            case .p521: Data([0x2b, 0x81, 0x04, 0x00, 0x23])
            }
        }

        func validate(point: Data) throws {
            guard point.count == width * 2 + 1, point.first == 4 else { throw Failure.invalidKey }
            do {
                switch self {
                case .p256: _ = try P256.Signing.PublicKey(x963Representation: point)
                case .p384: _ = try P384.Signing.PublicKey(x963Representation: point)
                case .p521: _ = try P521.Signing.PublicKey(x963Representation: point)
                }
            } catch {
                throw Failure.invalidKey
            }
        }

        func privateKey(_ bytes: Data) throws -> PrivateMaterial {
            guard bytes.count == width else { throw Failure.invalidKey }
            switch self {
            case .p256: return .p256(try .init(rawRepresentation: bytes))
            case .p384: return .p384(try .init(rawRepresentation: bytes))
            case .p521: return .p521(try .init(rawRepresentation: bytes))
            }
        }
    }

    private enum PublicMaterial: Equatable {
        case ed25519(Data)
        case ecdsa(Curve, Data)
        case rsa(MacSSHRSAKey.Components)

        var format: String {
            switch self {
            case .ed25519: ed25519Name
            case .ecdsa(let curve, _): curve.algorithm
            case .rsa: rsaName
            }
        }

        var blob: Data {
            let name = MacSSHKeyEncoding.string(format)
            switch self {
            case .ed25519(let key): return name + MacSSHKeyEncoding.string(key)
            case .ecdsa(let curve, let key): return name + MacSSHKeyEncoding.string(curve.rawValue) + MacSSHKeyEncoding.string(key)
            case .rsa(let key): return name + MacSSHKeyEncoding.mpint(key.exponent) + MacSSHKeyEncoding.mpint(key.modulus)
            }
        }
    }

    private enum PrivateMaterial {
        case ed25519(Curve25519.Signing.PrivateKey)
        case p256(P256.Signing.PrivateKey)
        case p384(P384.Signing.PrivateKey)
        case p521(P521.Signing.PrivateKey)
        case rsa(MacSSHRSAKey)

        var publicMaterial: PublicMaterial {
            switch self {
            case .ed25519(let key): .ed25519(key.publicKey.rawRepresentation)
            case .p256(let key): .ecdsa(.p256, key.publicKey.x963Representation)
            case .p384(let key): .ecdsa(.p384, key.publicKey.x963Representation)
            case .p521(let key): .ecdsa(.p521, key.publicKey.x963Representation)
            case .rsa(let key): .rsa(key.components)
            }
        }

        func signature(for data: Data, flags: UInt32) throws -> (String, Data) {
            switch self {
            case .ed25519(let key): return (ed25519Name, try key.signature(for: data))
            case .p256(let key): return try ecdsaSignature(.p256, key.signature(for: SHA256.hash(data: data)).rawRepresentation)
            case .p384(let key): return try ecdsaSignature(.p384, key.signature(for: SHA384.hash(data: data)).rawRepresentation)
            case .p521(let key): return try ecdsaSignature(.p521, key.signature(for: SHA512.hash(data: data)).rawRepresentation)
            case .rsa(let key): return try key.signature(for: data, flags: flags)
            }
        }

        private func ecdsaSignature(_ curve: Curve, _ raw: Data) throws -> (String, Data) {
            guard raw.count == curve.width * 2 else { throw Failure.signingFailed }
            return (curve.algorithm, MacSSHKeyEncoding.mpint(raw.prefix(curve.width)) + MacSSHKeyEncoding.mpint(raw.suffix(curve.width)))
        }
    }
}
