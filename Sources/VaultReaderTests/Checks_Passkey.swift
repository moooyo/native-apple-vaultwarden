import Foundation
import CryptoKit
import CryptoCore
import VaultModels
import VaultStore
import KeyVault
import Fido2
import VaultReader

/// `passkeyAssertion` round-trip: seed a passkey cipher whose `keyValue` is a real P-256
/// PKCS#8 key, build an assertion, and verify the ES256 signature against the public key.
func checkPasskeyAssertion(_ r: inout TestRunner) async {
    let (store, dir): (VaultStore, URL)
    do { (store, dir) = try await Fixtures.freshStore() }
    catch { r.expectTrue(false, "freshStore threw: \(error)"); return }
    defer { Fixtures.cleanup(dir) }

    // Generate a real credential keypair; store the PKCS#8 (encrypted) in the cipher blob.
    let credentialKey = CredentialKey()
    let pkcs8 = credentialKey.exportPKCS8()
    let publicKey = try! P256.Signing.PublicKey(x963Representation: credentialKey.publicKeyX963)

    let rpId = "webauthn.io"
    do {
        try await store.upsertCiphers([
            Fixtures.passkeyRow(id: "pk-1", name: "WebAuthn Demo", rpId: rpId,
                                userName: "alice", pkcs8: pkcs8, counter: 0),
            Fixtures.loginRow(id: "login-1", name: "Plain login", username: "u", password: "p"),
        ])
    } catch {
        r.expectTrue(false, "seed upsert threw: \(error)"); return
    }

    let keyVault = await Fixtures.unlockedVault()
    let reader = VaultReader(store: store, keyVault: keyVault, keychain: makeFakeKeychain())

    let clientDataHash = Data(SHA256.hash(data: Data("client-data".utf8)))

    do {
        let (authData, signature) = try await reader.passkeyAssertion(
            recordID: "pk-1", rpId: rpId, clientDataHash: clientDataHash, userVerified: true)

        // authenticatorData starts with SHA-256(rpId).
        let expectedRpHash = Data(SHA256.hash(data: Data(rpId.utf8)))
        r.expect(authData.prefix(32), expectedRpHash, "passkey authData rpIdHash")
        // UP (0x01) + UV (0x04) flags set (byte 32).
        r.expect(authData.count >= 37, true, "passkey authData length >= 37")
        if authData.count >= 33 {
            r.expect(authData[32] & 0x01, 0x01, "passkey UP flag set")
            r.expect(authData[32] & 0x04, 0x04, "passkey UV flag set")
        }

        // Verify the ES256 signature over (authData || clientDataHash) against the pubkey.
        let signed = authData + clientDataHash
        let ecdsa = try P256.Signing.ECDSASignature(derRepresentation: signature)
        r.expectTrue(publicKey.isValidSignature(ecdsa, for: signed),
                     "passkey signature verifies against stored public key")
    } catch {
        r.expectTrue(false, "passkeyAssertion threw: \(error)")
    }

    // A login with no fido2 credential → .noPasskey.
    await r.expectThrowsErrorAsync(VaultReaderError.noPasskey,
                                   "passkeyAssertion on non-passkey login → noPasskey") {
        _ = try await reader.passkeyAssertion(recordID: "login-1", rpId: rpId,
                                              clientDataHash: clientDataHash, userVerified: false)
    }

    // Missing record → .notFound.
    await r.expectThrowsErrorAsync(VaultReaderError.notFound,
                                   "passkeyAssertion missing → notFound") {
        _ = try await reader.passkeyAssertion(recordID: "nope", rpId: rpId,
                                              clientDataHash: clientDataHash, userVerified: false)
    }
}

/// A locked vault rejects passkey assertion with `.locked`.
func checkPasskeyLocked(_ r: inout TestRunner) async {
    let (store, dir): (VaultStore, URL)
    do { (store, dir) = try await Fixtures.freshStore() }
    catch { r.expectTrue(false, "freshStore threw: \(error)"); return }
    defer { Fixtures.cleanup(dir) }

    let pkcs8 = CredentialKey().exportPKCS8()
    do {
        try await store.upsertCiphers([
            Fixtures.passkeyRow(id: "pk-1", name: "WebAuthn Demo", rpId: "webauthn.io",
                                userName: "alice", pkcs8: pkcs8),
        ])
    } catch {
        r.expectTrue(false, "seed upsert threw: \(error)"); return
    }

    let reader = VaultReader(store: store, keyVault: Fixtures.lockedVault(),
                             keychain: makeFakeKeychain())
    let clientDataHash = Data(repeating: 0xAB, count: 32)
    await r.expectThrowsErrorAsync(VaultReaderError.locked, "passkeyAssertion locked → locked") {
        _ = try await reader.passkeyAssertion(recordID: "pk-1", rpId: "webauthn.io",
                                              clientDataHash: clientDataHash, userVerified: true)
    }
}
