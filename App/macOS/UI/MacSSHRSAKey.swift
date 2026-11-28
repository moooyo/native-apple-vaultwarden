import Foundation
import Security

struct MacSSHRSAKey {
    static let maximumModulusSize = 1024
    static let maximumExponentSize = 8

    struct Components: Equatable {
        let modulus: Data
        let exponent: Data

        init(modulus: Data, exponent: Data) throws {
            guard (128...MacSSHRSAKey.maximumModulusSize).contains(modulus.count),
                  modulus.count != 128 || (modulus.first ?? 0) >= 128,
                  modulus.last.map({ $0 & 1 == 1 }) == true,
                  exponent.count <= MacSSHRSAKey.maximumExponentSize,
                  exponent != Data([1]), exponent.last.map({ $0 & 1 == 1 }) == true else {
                throw MacSSHSigningKey.Failure.invalidKey
            }
            self.modulus = modulus
            self.exponent = exponent
        }

        var der: Data {
            MacSSHKeyEncoding.derValue(tag: 0x30, body: MacSSHKeyEncoding.derInteger(modulus) + MacSSHKeyEncoding.derInteger(exponent))
        }
    }

    let components: Components
    private let key: SecKey
    private let verificationKey: SecKey

    init(components: Components, privateExponent: Data, prime1: Data, prime2: Data, coefficient: Data,
         encodedDER: Data? = nil, encodedExponent1: Data? = nil, encodedExponent2: Data? = nil) throws {
        let modulus = MacSSHKeyMagnitude(components.modulus)
        let privateValue = MacSSHKeyMagnitude(privateExponent)
        let firstPrime = MacSSHKeyMagnitude(prime1)
        let secondPrime = MacSSHKeyMagnitude(prime2)
        let inverse = MacSSHKeyMagnitude(coefficient)
        let one = MacSSHKeyMagnitude(Data([1]))
        guard privateValue > one, privateValue < modulus, firstPrime > one, secondPrime > one,
              prime1.last.map({ $0 & 1 == 1 }) == true, prime2.last.map({ $0 & 1 == 1 }) == true,
              firstPrime != secondPrime, abs(prime1.count - prime2.count) <= 1,
              inverse < firstPrime, firstPrime * secondPrime == modulus else {
            throw MacSSHSigningKey.Failure.invalidKey
        }

        let firstOrder = firstPrime.subtractingOne()
        let secondOrder = secondPrime.subtractingOne()
        let firstExponent = privateValue.divided(by: firstOrder).remainder
        let secondExponent = privateValue.divided(by: secondOrder).remainder
        let publicValue = MacSSHKeyMagnitude(components.exponent)
        let inverseRelation = (inverse * secondPrime).divided(by: firstPrime)
        guard (firstExponent * publicValue).divided(by: firstOrder).remainder == one,
              (secondExponent * publicValue).divided(by: secondOrder).remainder == one,
              inverseRelation.remainder == one,
              encodedExponent1.map({ firstExponent.bytes == $0 }) ?? true,
              encodedExponent2.map({ secondExponent.bytes == $0 }) ?? true else {
            throw MacSSHSigningKey.Failure.invalidKey
        }

        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
            kSecAttrIsPermanent: false
        ]
        let key: SecKey?
        if let encodedDER {
            key = SecKeyCreateWithData(encodedDER as CFData, attributes as CFDictionary, nil)
        } else {
            key = nil
        }
        guard let key = key ?? Self.importCanonicalKey(
            components: components, privateExponent: privateExponent, prime1: prime1, prime2: prime2,
            exponent1: firstExponent, exponent2: secondExponent, coefficient: coefficient, reverseInverse: secondPrime - inverseRelation.quotient,
            swap: firstPrime.bitWidth < secondPrime.bitWidth, attributes: attributes as CFDictionary
        ),
              let verificationKey = SecKeyCopyPublicKey(key),
              SecKeyCopyExternalRepresentation(verificationKey, nil) as Data? == components.der else {
            throw MacSSHSigningKey.Failure.invalidKey
        }
        self.components = components
        self.key = key
        self.verificationKey = verificationKey
    }

    private static func importCanonicalKey(components: Components, privateExponent: Data, prime1: Data, prime2: Data,
                                           exponent1: MacSSHKeyMagnitude, exponent2: MacSSHKeyMagnitude, coefficient: Data,
                                           reverseInverse: MacSSHKeyMagnitude, swap: Bool, attributes: CFDictionary) -> SecKey? {
        var orderedCoefficient = swap ? reverseInverse.bytes : coefficient
        var exponentForFirstPrime = (swap ? exponent2 : exponent1).bytes
        var exponentForSecondPrime = (swap ? exponent1 : exponent2).bytes
        var body = Data([0x02, 0x01, 0x00])
        defer {
            if swap { orderedCoefficient.resetBytes(in: orderedCoefficient.indices) }
            exponentForFirstPrime.resetBytes(in: exponentForFirstPrime.indices)
            exponentForSecondPrime.resetBytes(in: exponentForSecondPrime.indices)
            body.resetBytes(in: body.indices)
        }
        for field in [components.modulus, components.exponent, privateExponent, swap ? prime2 : prime1, swap ? prime1 : prime2,
                      exponentForFirstPrime, exponentForSecondPrime, orderedCoefficient] {
            var encoded = MacSSHKeyEncoding.derInteger(field)
            body.append(encoded)
            encoded.resetBytes(in: encoded.indices)
        }
        var der = MacSSHKeyEncoding.derValue(tag: 0x30, body: body)
        defer { der.resetBytes(in: der.indices) }
        return SecKeyCreateWithData(der as CFData, attributes, nil)
    }

    static func verifyHostSignature(_ signature: Data, for data: Data, algorithm: String, components: Components) -> Bool {
        let method: SecKeyAlgorithm
        switch algorithm {
        case "rsa-sha2-256": method = .rsaSignatureMessagePKCS1v15SHA256
        case "rsa-sha2-512": method = .rsaSignatureMessagePKCS1v15SHA512
        default: return false
        }
        guard !signature.isEmpty, signature.count <= components.modulus.count else { return false }
        let attributes: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeyClass: kSecAttrKeyClassPublic]
        guard let key = SecKeyCreateWithData(components.der as CFData, attributes as CFDictionary, nil) else { return false }
        let padded = Data(count: components.modulus.count - signature.count) + signature
        return SecKeyVerifySignature(key, method, data as CFData, padded as CFData, nil)
    }

    func signature(for data: Data, flags: UInt32) throws -> (String, Data) {
        let format: String
        let algorithm: SecKeyAlgorithm
        switch flags {
        case 2, 6:
            format = "rsa-sha2-256"
            algorithm = .rsaSignatureMessagePKCS1v15SHA256
        case 4:
            format = "rsa-sha2-512"
            algorithm = .rsaSignatureMessagePKCS1v15SHA512
        default: throw MacSSHSigningKey.Failure.unsupportedFlags
        }
        guard let signature = SecKeyCreateSignature(key, algorithm, data as CFData, nil) as Data?,
              signature.count == components.modulus.count,
              SecKeyVerifySignature(verificationKey, algorithm, data as CFData, signature as CFData, nil) else {
            throw MacSSHSigningKey.Failure.signingFailed
        }
        return (format, signature)
    }
}

private final class MacSSHKeyMagnitude: Comparable {
    private var words: [UInt32]

    init(_ bytes: Data) {
        var words = [UInt32](repeating: 0, count: (bytes.count + 3) / 4)
        for (index, byte) in bytes.reversed().enumerated() {
            words[index / 4] |= UInt32(byte) << ((index % 4) * 8)
        }
        self.words = Self.normalized(words)
    }

    private init(words: [UInt32]) { self.words = Self.normalized(words) }

    deinit { Self.erase(&words) }

    var bitWidth: Int {
        guard let highWord = words.last else { return 0 }
        return words.count * 32 - highWord.leadingZeroBitCount
    }

    var bytes: Data {
        var bytes = Data(capacity: words.count * 4)
        for word in words.reversed() {
            var bigEndian = word.bigEndian
            withUnsafeBytes(of: &bigEndian) { bytes.append(contentsOf: $0) }
        }
        return bytes.drop(while: { $0 == 0 })
    }

    static func == (left: MacSSHKeyMagnitude, right: MacSSHKeyMagnitude) -> Bool { left.words == right.words }

    static func < (left: MacSSHKeyMagnitude, right: MacSSHKeyMagnitude) -> Bool {
        if left.words.count != right.words.count { return left.words.count < right.words.count }
        return left.words.reversed().lexicographicallyPrecedes(right.words.reversed())
    }

    static func * (left: MacSSHKeyMagnitude, right: MacSSHKeyMagnitude) -> MacSSHKeyMagnitude {
        var result = [UInt32](repeating: 0, count: left.words.count + right.words.count)
        for (leftIndex, leftWord) in left.words.enumerated() {
            var carry: UInt64 = 0
            for (rightIndex, rightWord) in right.words.enumerated() {
                let resultIndex = leftIndex + rightIndex
                let sum = UInt64(leftWord) * UInt64(rightWord) + UInt64(result[resultIndex]) + carry
                result[resultIndex] = UInt32(truncatingIfNeeded: sum)
                carry = sum >> 32
            }
            result[leftIndex + right.words.count] = UInt32(carry)
        }
        return Self(words: result)
    }

    static func - (left: MacSSHKeyMagnitude, right: MacSSHKeyMagnitude) -> MacSSHKeyMagnitude {
        var result = left.words
        var borrow: UInt64 = 0
        for index in result.indices {
            let word = index < right.words.count ? right.words[index] : 0
            let difference = UInt64(result[index]) &- UInt64(word) &- borrow
            result[index] = UInt32(truncatingIfNeeded: difference)
            borrow = difference >> 63
        }
        return Self(words: result)
    }

    func subtractingOne() -> MacSSHKeyMagnitude { self - Self(words: [1]) }

    func divided(by divisor: MacSSHKeyMagnitude) -> (quotient: MacSSHKeyMagnitude, remainder: MacSSHKeyMagnitude) {
        var quotient = [UInt32](repeating: 0, count: words.count)
        var remainder = [UInt32](repeating: 0, count: divisor.words.count)
        var difference = remainder
        defer { Self.erase(&difference) }
        for wordIndex in words.indices.reversed() {
            for bitIndex in (0..<32).reversed() {
                var carry = words[wordIndex] >> bitIndex & 1
                var borrow: UInt64 = 0
                for index in remainder.indices {
                    let limb = remainder[index]
                    let shifted = (limb << 1) | carry
                    carry = limb >> 31
                    remainder[index] = shifted
                    let delta = UInt64(shifted) &- UInt64(divisor.words[index]) &- borrow
                    difference[index] = UInt32(truncatingIfNeeded: delta)
                    borrow = delta >> 63
                }
                let subtract = 1 ^ UInt32((UInt64(carry) &- borrow) >> 63)
                let mask = UInt32.zero &- subtract
                for index in remainder.indices {
                    remainder[index] = (difference[index] & mask) | (remainder[index] & ~mask)
                }
                quotient[wordIndex] |= subtract << bitIndex
            }
        }
        return (Self(words: quotient), Self(words: remainder))
    }

    private static func erase(_ words: inout [UInt32]) {
        words.withUnsafeMutableBytes { bytes in
            if let baseAddress = bytes.baseAddress, !bytes.isEmpty {
                _ = memset_s(baseAddress, bytes.count, 0, bytes.count)
            }
        }
    }

    private static func normalized(_ incoming: consuming [UInt32]) -> [UInt32] {
        var words = incoming
        let length = words.lastIndex(where: { $0 != 0 }).map { $0 + 1 } ?? 0
        words.removeLast(words.count - length)
        return words
    }
}
