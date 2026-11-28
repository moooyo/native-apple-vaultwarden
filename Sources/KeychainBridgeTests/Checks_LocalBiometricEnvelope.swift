#if os(macOS)
import CryptoCore
import CryptoKit
import Foundation
import KeychainBridge

func checkLocalBiometricEnvelope(_ runner: inout TestRunner) async {
    do {
        let wrappingPeer = P256.KeyAgreement.PrivateKey()
        let simulatedEnclave = P256.KeyAgreement.PrivateKey()
        let wrappingSecret = try wrappingPeer.sharedSecretFromKeyAgreement(with: simulatedEnclave.publicKey)
        let hardwareBlob = Data(repeating: 0xA5, count: 600)
        let salt = Data(repeating: 0x5A, count: LocalBiometricEnvelope.saltLength)
        let binding = Data("fixture account and session".utf8)
        let userKey = try SymmetricCryptoKey(combined: Data(0..<64))
        let encoded = try LocalBiometricEnvelope.seal(userKey, hardwareKey: hardwareBlob,
                                                      peerPublicKey: wrappingPeer.publicKey, secret: wrappingSecret,
                                                      salt: salt, binding: binding)
        let decoded = try LocalBiometricEnvelope(encoded: encoded)
        let openingSecret = try simulatedEnclave.sharedSecretFromKeyAgreement(with: decoded.peerPublicKey)
        let recovered = try decoded.open(secret: openingSecret, binding: binding)
        runner.expect(recovered, userKey, "local biometric envelope recovers the enrolled key")
        runner.expect(decoded.hardwareKey, hardwareBlob, "local biometric envelope preserves the opaque hardware key")
        let repeated = try LocalBiometricEnvelope.seal(userKey, hardwareKey: hardwareBlob,
                                                      peerPublicKey: wrappingPeer.publicKey, secret: wrappingSecret,
                                                      salt: salt, binding: binding)
        runner.expectTrue(repeated != encoded, "local biometric envelopes use fresh AES-GCM nonces")
        runner.expectThrowsError(KeychainError.invalidUserKey, "local biometric envelope rejects a different session binding") {
            _ = try decoded.open(secret: openingSecret, binding: Data("a different session".utf8))
        }
        let otherEnclave = P256.KeyAgreement.PrivateKey()
        let unrelatedSecret = try otherEnclave.sharedSecretFromKeyAgreement(with: decoded.peerPublicKey)
        runner.expectThrowsError(KeychainError.invalidUserKey, "local biometric envelope rejects an unrelated key") {
            _ = try decoded.open(secret: unrelatedSecret, binding: binding)
        }

        var wrongVersion = encoded
        wrongVersion[wrongVersion.startIndex] = 0
        runner.expectThrowsError(KeychainError.invalidUserKey, "local biometric envelope rejects an unknown version") {
            _ = try LocalBiometricEnvelope(encoded: wrongVersion)
        }
        runner.expectThrowsError(KeychainError.invalidUserKey, "local biometric envelope rejects oversized input") {
            _ = try LocalBiometricEnvelope(encoded: encoded + Data(count: 4096))
        }
        runner.expectThrowsError(KeychainError.invalidUserKey, "local biometric envelope rejects truncated input") {
            _ = try LocalBiometricEnvelope(encoded: encoded.prefix(1 + LocalBiometricEnvelope.saltLength))
        }
        var invalidPeer = encoded
        invalidPeer[1 + LocalBiometricEnvelope.saltLength] = 0
        runner.expectThrowsError(KeychainError.invalidUserKey, "local biometric envelope rejects an invalid peer public key") {
            _ = try LocalBiometricEnvelope(encoded: invalidPeer)
        }
        var tamperedHardwareBlob = encoded
        tamperedHardwareBlob[1 + LocalBiometricEnvelope.saltLength + wrappingPeer.publicKey.x963Representation.count] ^= 1
        runner.expectThrowsError(KeychainError.invalidUserKey, "local biometric envelope authenticates the hardware-key representation") {
            _ = try LocalBiometricEnvelope(encoded: tamperedHardwareBlob).open(secret: openingSecret, binding: binding)
        }
        var tamperedCiphertext = encoded
        tamperedCiphertext[tamperedCiphertext.index(before: tamperedCiphertext.endIndex)] ^= 1
        runner.expectThrowsError(KeychainError.invalidUserKey, "local biometric envelope rejects altered ciphertext") {
            _ = try LocalBiometricEnvelope(encoded: tamperedCiphertext).open(secret: openingSecret, binding: binding)
        }

        let cancelled = Task<Bool, Never> {
            withUnsafeCurrentTask { $0?.cancel() }
            do {
                _ = try await SystemLocalBiometricKeyWrapper().unwrap(encoded, binding: binding, reason: "Isolated fixture", fallbackTitle: "")
                return false
            } catch let error as KeychainError {
                return error == .userCanceled
            } catch {
                return false
            }
        }
        runner.expectTrue(await cancelled.value, "cancellation returns before starting any Touch ID operation")
    } catch {
        runner.expectTrue(false, "local biometric envelope setup threw: \(error)")
    }
}
#endif
