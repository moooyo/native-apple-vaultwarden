import Foundation
import KeychainBridge

private let testAccessGroup = "TESTTEAM.dev.moooyo.tessera.shared"
private let testService = "dev.moooyo.tessera"

func checkSecrets(_ r: inout TestRunner) async {
    // setSecret / getSecret / deleteSecret round-trip via the fake item store.
    do {
        let bridge = KeychainBridge(accessGroup: testAccessGroup, service: testService,
                                    secureEnclave: InMemorySecureEnclaveKeyStore(),
                                    itemStore: InMemoryKeychainItemStore())

        let absent = try await bridge.getSecret(account: "refresh-token")
        r.expect(absent, nil, "getSecret returns nil before set")

        let token = Data("eyJhbGciOi.refresh".utf8)
        try await bridge.setSecret(token, account: "refresh-token", biometryGated: false)
        let fetched = try await bridge.getSecret(account: "refresh-token")
        r.expect(fetched, token, "getSecret returns the stored value")

        // Overwrite.
        let token2 = Data("rotated-token".utf8)
        try await bridge.setSecret(token2, account: "refresh-token", biometryGated: false)
        let fetched2 = try await bridge.getSecret(account: "refresh-token")
        r.expect(fetched2, token2, "setSecret overwrites the previous value")

        await bridge.deleteSecret(account: "refresh-token")
        let afterDelete = try await bridge.getSecret(account: "refresh-token")
        r.expect(afterDelete, nil, "getSecret returns nil after delete")
    } catch {
        r.expectTrue(false, "setSecret/getSecret round-trip threw: \(error)")
    }

    // biometryGated flag is accepted (fake ignores gating but the path must work).
    do {
        let bridge = KeychainBridge(accessGroup: testAccessGroup, service: testService,
                                    secureEnclave: InMemorySecureEnclaveKeyStore(),
                                    itemStore: InMemoryKeychainItemStore())
        let hash = Data("local-auth-hash".utf8)
        try await bridge.setSecret(hash, account: "local-auth-hash", biometryGated: true)
        let fetched = try await bridge.getSecret(account: "local-auth-hash")
        r.expect(fetched, hash, "biometry-gated secret round-trips")
    } catch {
        r.expectTrue(false, "biometry-gated secret threw: \(error)")
    }
}
