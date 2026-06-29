import Foundation
import CryptoCore
import KeychainBridge

private let testAccessGroup = "TESTTEAM.dev.moooyo.tessera.shared"
private let testService = "dev.moooyo.tessera"

private func makeUserKey() throws -> SymmetricCryptoKey {
    // 64 distinct bytes: enc = 0..31, mac = 32..63.
    let combined = Data((0..<64).map { UInt8($0) })
    return try SymmetricCryptoKey(combined: combined)
}

func checkBiometricUnlock(_ r: inout TestRunner) async {
    // enable -> unlock returns the SAME key.
    do {
        let se = InMemorySecureEnclaveKeyStore()
        let items = InMemoryKeychainItemStore()
        let bridge = KeychainBridge(accessGroup: testAccessGroup, service: testService,
                                    secureEnclave: se, itemStore: items)
        let userKey = try makeUserKey()
        try await bridge.enableBiometricUnlock(userKey: userKey)
        let recovered = try await bridge.unlockWithBiometrics(reason: "Unlock Tessera")
        r.expect(recovered, userKey, "enable then unlock returns the same SymmetricCryptoKey")
    } catch {
        r.expectTrue(false, "enable/unlock round-trip threw: \(error)")
    }

    // isBiometricUnlockEnabled reflects enable.
    do {
        let se = InMemorySecureEnclaveKeyStore()
        let items = InMemoryKeychainItemStore()
        let bridge = KeychainBridge(accessGroup: testAccessGroup, service: testService,
                                    secureEnclave: se, itemStore: items)
        let before = await bridge.isBiometricUnlockEnabled()
        r.expect(before, false, "isBiometricUnlockEnabled false before enable")
        try await bridge.enableBiometricUnlock(userKey: makeUserKey())
        let after = await bridge.isBiometricUnlockEnabled()
        r.expect(after, true, "isBiometricUnlockEnabled true after enable")
    } catch {
        r.expectTrue(false, "isBiometricUnlockEnabled setup threw: \(error)")
    }

    // disable removes both the SE key and the ciphertext; unlock then throws notFound.
    do {
        let se = InMemorySecureEnclaveKeyStore()
        let items = InMemoryKeychainItemStore()
        let bridge = KeychainBridge(accessGroup: testAccessGroup, service: testService,
                                    secureEnclave: se, itemStore: items)
        try await bridge.enableBiometricUnlock(userKey: makeUserKey())
        await bridge.disableBiometricUnlock()

        let enabled = await bridge.isBiometricUnlockEnabled()
        r.expect(enabled, false, "isBiometricUnlockEnabled false after disable")
        r.expect(se.hasKey(tag: "\(testService).biometric-sekey", accessGroup: testAccessGroup), false,
                 "disable removes the SE key")
        await r.expectThrowsErrorAsync(KeychainError.notFound, "unlock after disable throws notFound") {
            _ = try await bridge.unlockWithBiometrics(reason: "x")
        }
    } catch {
        r.expectTrue(false, "disable setup threw: \(error)")
    }

    // unlock when never enabled -> notFound.
    do {
        let bridge = KeychainBridge(accessGroup: testAccessGroup, service: testService,
                                    secureEnclave: InMemorySecureEnclaveKeyStore(),
                                    itemStore: InMemoryKeychainItemStore())
        await r.expectThrowsErrorAsync(KeychainError.notFound, "unlock when not enabled throws notFound") {
            _ = try await bridge.unlockWithBiometrics(reason: "x")
        }
    }

    // ciphertext that unwraps to != 64 bytes -> invalidUserKey.
    do {
        let se = InMemorySecureEnclaveKeyStore()
        let items = InMemoryKeychainItemStore()
        let bridge = KeychainBridge(accessGroup: testAccessGroup, service: testService,
                                    secureEnclave: se, itemStore: items)
        // Create the SE key, then store a wrapped 32-byte payload directly via the seam so
        // unwrap yields 32 bytes (a "valid SE round-trip" but an invalid user key).
        try se.createBiometricKey(tag: "\(testService).biometric-sekey", accessGroup: testAccessGroup)
        let shortPayload = Data((0..<32).map { UInt8($0) })
        let wrapped = try se.wrap(shortPayload, tag: "\(testService).biometric-sekey", accessGroup: testAccessGroup)
        try await bridge.setSecret(wrapped, account: "\(testService).biometric-userkey", biometryGated: false)

        await r.expectThrowsErrorAsync(KeychainError.invalidUserKey, "unwrap to != 64 bytes throws invalidUserKey") {
            _ = try await bridge.unlockWithBiometrics(reason: "x")
        }
    } catch {
        r.expectTrue(false, "invalidUserKey setup threw: \(error)")
    }

    // biometric cancellation propagates as userCanceled.
    do {
        let se = InMemorySecureEnclaveKeyStore()
        let items = InMemoryKeychainItemStore()
        let bridge = KeychainBridge(accessGroup: testAccessGroup, service: testService,
                                    secureEnclave: se, itemStore: items)
        try await bridge.enableBiometricUnlock(userKey: makeUserKey())
        se.unwrapError = .userCanceled
        await r.expectThrowsErrorAsync(KeychainError.userCanceled, "biometric cancel propagates as userCanceled") {
            _ = try await bridge.unlockWithBiometrics(reason: "x")
        }
    } catch {
        r.expectTrue(false, "userCanceled setup threw: \(error)")
    }
}
