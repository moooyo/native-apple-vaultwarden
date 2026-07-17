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
            recordID: "pk-1", rpId: rpId,
            credentialID: Fixtures.passkeyCredentialID(for: "pk-1"),
            clientDataHash: clientDataHash, userVerified: true)

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
                                              credentialID: Data([0x01]),
                                              clientDataHash: clientDataHash, userVerified: false)
    }

    // Missing record → .notFound.
    await r.expectThrowsErrorAsync(VaultReaderError.notFound,
                                   "passkeyAssertion missing → notFound") {
        _ = try await reader.passkeyAssertion(recordID: "nope", rpId: rpId,
                                              credentialID: Data([0x01]),
                                              clientDataHash: clientDataHash, userVerified: false)
    }
}

/// Multiple credentials may share one cipher and RP. The assertion must select by the
/// raw credential id, including both official UUID and `b64.` plaintext forms. This also
/// covers Bitwarden's base64url `keyValue` and legacy raw-DER compatibility.
func checkPasskeyExactCredentialSelection(_ r: inout TestRunner) async {
    let (store, dir): (VaultStore, URL)
    do { (store, dir) = try await Fixtures.freshStore() }
    catch { r.expectTrue(false, "exact credential freshStore threw: \(error)"); return }
    defer { Fixtures.cleanup(dir) }

    let rpId = "login.example.com"
    let uuid = UUID(uuidString: "00112233-4455-6677-8899-aabbccddeeff")!
    let uuidBytes = Data([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ])
    let b64CredentialID = Data([0xfb, 0xff, 0x00, 0x10, 0x20, 0x30])
    let legacyCredentialID = Data("legacy-id".utf8)
    let uuidKey = CredentialKey()
    let b64Key = CredentialKey()
    let legacyKey = CredentialKey()

    let row = Fixtures.passkeyRow(
        id: "multi-passkey",
        name: "Multiple Passkeys",
        credentials: [
            Fixtures.PasskeyRecord(
                credentialIDValue: uuid.uuidString.lowercased(),
                rpId: rpId,
                userName: "uuid-user",
                userHandle: Data("uuid-handle".utf8),
                pkcs8: uuidKey.exportPKCS8()
            ),
            Fixtures.PasskeyRecord(
                credentialIDValue: "b64.\(Fixtures.base64URL(b64CredentialID))",
                rpId: rpId,
                userName: "b64-user",
                userHandle: Data("b64-handle".utf8),
                pkcs8: b64Key.exportPKCS8()
            ),
            Fixtures.PasskeyRecord(
                credentialIDValue: "b64.\(Fixtures.base64URL(legacyCredentialID))",
                rpId: rpId,
                userName: "legacy-user",
                userHandle: Data("legacy-handle".utf8),
                pkcs8: legacyKey.exportPKCS8(),
                storesLegacyRawKeyValue: true
            ),
        ]
    )
    do { try await store.upsertCiphers([row]) }
    catch { r.expectTrue(false, "exact credential seed threw: \(error)"); return }

    let reader = VaultReader(
        store: store,
        keyVault: await Fixtures.unlockedVault(),
        keychain: makeFakeKeychain()
    )
    let clientDataHash = Data(SHA256.hash(data: Data("exact-selection".utf8)))

    do {
        let (authData, signature) = try await reader.passkeyAssertion(
            recordID: row.id,
            rpId: rpId,
            credentialID: b64CredentialID,
            clientDataHash: clientDataHash,
            userVerified: true
        )
        let signed = authData + clientDataHash
        let parsed = try P256.Signing.ECDSASignature(derRepresentation: signature)
        let selectedPublicKey = try P256.Signing.PublicKey(
            x963Representation: b64Key.publicKeyX963
        )
        let otherPublicKey = try P256.Signing.PublicKey(
            x963Representation: uuidKey.publicKeyX963
        )
        r.expectTrue(selectedPublicKey.isValidSignature(parsed, for: signed),
                     "same-RP assertion selects requested b64 credential key")
        r.expectTrue(!otherPublicKey.isValidSignature(parsed, for: signed),
                     "same-RP assertion does not fall back to first key")
    } catch {
        r.expectTrue(false, "b64 credential assertion threw: \(error)")
    }

    do {
        let (authData, signature) = try await reader.passkeyAssertion(
            recordID: row.id,
            rpId: rpId,
            credentialID: uuidBytes,
            clientDataHash: clientDataHash,
            userVerified: false
        )
        let parsed = try P256.Signing.ECDSASignature(derRepresentation: signature)
        let publicKey = try P256.Signing.PublicKey(x963Representation: uuidKey.publicKeyX963)
        r.expectTrue(publicKey.isValidSignature(parsed, for: authData + clientDataHash),
                     "UUID credential id decodes to RFC-4122 bytes")
    } catch {
        r.expectTrue(false, "UUID credential assertion threw: \(error)")
    }

    do {
        let (authData, signature) = try await reader.passkeyAssertion(
            recordID: row.id,
            rpId: rpId,
            credentialID: legacyCredentialID,
            clientDataHash: clientDataHash,
            userVerified: true
        )
        let parsed = try P256.Signing.ECDSASignature(derRepresentation: signature)
        let publicKey = try P256.Signing.PublicKey(x963Representation: legacyKey.publicKeyX963)
        r.expectTrue(publicKey.isValidSignature(parsed, for: authData + clientDataHash),
                     "legacy encrypted raw PKCS#8 remains readable")
    } catch {
        r.expectTrue(false, "legacy keyValue assertion threw: \(error)")
    }

    await r.expectThrowsErrorAsync(
        VaultReaderError.noPasskey,
        "unknown credential id does not fall back within same RP"
    ) {
        _ = try await reader.passkeyAssertion(
            recordID: row.id,
            rpId: rpId,
            credentialID: Data([0xde, 0xad, 0xbe, 0xef]),
            clientDataHash: clientDataHash,
            userVerified: true
        )
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
                                              credentialID: Fixtures.passkeyCredentialID(for: "pk-1"),
                                              clientDataHash: clientDataHash, userVerified: true)
    }
}
