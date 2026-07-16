import Foundation
import CryptoCore
import VaultModels
import VaultStore
import KeyVault
import SyncEngine

/// Identities: after sync the fake store receives one identity per login URI, with the
/// decrypted serviceIdentifier + username. Rebuild is always an authoritative replace so
/// credentials from a previously active account cannot remain published.
func checkIdentitiesReplaceAll(_ r: inout TestRunner) async {
    guard let (store, dir) = try? Fixtures.freshStore() else {
        r.expectTrue(false, "identities replaceAll: fresh store"); return
    }
    defer { Fixtures.cleanup(dir) }

    let keyVault = await Fixtures.unlockedVault()
    let identity = FakeIdentityStore(enabled: true, incrementalSupported: false)
    let base = Date(timeIntervalSince1970: 1_750_000_000)

    let cipherJSON = Fixtures.loginCipherJSON(
        id: "cipher-1", name: "GitHub", username: "octocat",
        uri: "https://github.com", revision: base)
    let api = FakeVaultAPI(syncResponse: Fixtures.decodeSync(Fixtures.syncJSON(ciphers: [cipherJSON])))
    let engine = SyncEngine(api: api, store: store, keyVault: keyVault, identityStore: identity)

    do {
        let outcome = try await engine.fullSync(accountID: Fixtures.accountID)
        r.expect(outcome.identitiesWritten, 1, "one identity written (one login with one URI)")

        let calls = await identity.replaceAllCalls
        let incCalls = await identity.incrementalCalls
        r.expect(calls, 1, "replaceAll used when supportsIncremental=false")
        r.expect(incCalls, 0, "incremental NOT used when supportsIncremental=false")

        let written = await identity.lastReplaceAll
        r.expect(written.count, 1, "replaceAll received 1 identity")
        r.expect(written.first?.recordID, "cipher-1", "identity recordID is the cipher id")
        r.expect(written.first?.serviceIdentifier, "https://github.com",
                 "identity serviceIdentifier is the decrypted URI")
        r.expect(written.first?.user, "octocat", "identity user is the decrypted username")
        r.expect(written.first?.kind, CredentialIdentity.Kind.password, "identity kind is password")
    } catch {
        r.expectTrue(false, "identities replaceAll threw: \(error)")
    }
}

func checkIdentitiesIncremental(_ r: inout TestRunner) async {
    guard let (store, dir) = try? Fixtures.freshStore() else {
        r.expectTrue(false, "identities incremental: fresh store"); return
    }
    defer { Fixtures.cleanup(dir) }

    let keyVault = await Fixtures.unlockedVault()
    let identity = FakeIdentityStore(enabled: true, incrementalSupported: true)
    let base = Date(timeIntervalSince1970: 1_750_000_000)

    let cipherJSON = Fixtures.loginCipherJSON(
        id: "cipher-1", name: "GitHub", username: "octocat",
        uri: "https://github.com", revision: base)
    let api = FakeVaultAPI(syncResponse: Fixtures.decodeSync(Fixtures.syncJSON(ciphers: [cipherJSON])))
    let engine = SyncEngine(api: api, store: store, keyVault: keyVault, identityStore: identity)

    do {
        _ = try await engine.fullSync(accountID: Fixtures.accountID)
        let calls = await identity.replaceAllCalls
        let incCalls = await identity.incrementalCalls
        r.expect(incCalls, 0, "add-only incremental path is not used across accounts")
        r.expect(calls, 1, "replaceAll used even when incremental updates are supported")

        let replaced = await identity.lastReplaceAll
        r.expect(replaced.count, 1, "authoritative replace received 1 identity")
        r.expect(replaced.first?.serviceIdentifier, "https://github.com",
                 "replacement identity serviceIdentifier decrypted")
    } catch {
        r.expectTrue(false, "identities incremental threw: \(error)")
    }
}

/// AutoFill disabled → no identities written, neither path called.
func checkIdentitiesDisabledSkips(_ r: inout TestRunner) async {
    guard let (store, dir) = try? Fixtures.freshStore() else {
        r.expectTrue(false, "identities disabled: fresh store"); return
    }
    defer { Fixtures.cleanup(dir) }

    let keyVault = await Fixtures.unlockedVault()
    let identity = FakeIdentityStore(enabled: false)
    let base = Date(timeIntervalSince1970: 1_750_000_000)
    let cipherJSON = Fixtures.loginCipherJSON(
        id: "cipher-1", name: "GitHub", username: "octocat",
        uri: "https://github.com", revision: base)
    let api = FakeVaultAPI(syncResponse: Fixtures.decodeSync(Fixtures.syncJSON(ciphers: [cipherJSON])))
    let engine = SyncEngine(api: api, store: store, keyVault: keyVault, identityStore: identity)

    do {
        let outcome = try await engine.fullSync(accountID: Fixtures.accountID)
        r.expect(outcome.identitiesWritten, 0, "no identities written when AutoFill disabled")
        let calls = await identity.replaceAllCalls
        let incCalls = await identity.incrementalCalls
        r.expect(calls + incCalls, 0, "no identity-store calls when disabled")
    } catch {
        r.expectTrue(false, "identities disabled threw: \(error)")
    }
}

/// An account transition may occur while `/sync` is suspended. Its revocation generation
/// must prevent the old response from republishing identities after the app cleared them.
func checkAccountTransitionRevokesStaleIdentityWrite(_ r: inout TestRunner) async {
    guard let (store, dir) = try? Fixtures.freshStore() else {
        r.expectTrue(false, "identities revoke: fresh store"); return
    }
    defer { Fixtures.cleanup(dir) }

    let identity = FakeIdentityStore(enabled: true)
    let cipherJSON = Fixtures.loginCipherJSON(
        id: "stale-a", name: "Account A", username: "alice",
        uri: "https://a.example", revision: Date(timeIntervalSince1970: 1_750_000_000)
    )
    let api = FakeVaultAPI(
        syncResponse: Fixtures.decodeSync(Fixtures.syncJSON(ciphers: [cipherJSON]))
    )
    await api.pauseNextSync()
    let engine = SyncEngine(
        api: api,
        store: store,
        keyVault: await Fixtures.unlockedVault(),
        identityStore: identity
    )
    let sync = Task { try await engine.fullSync(accountID: Fixtures.accountID) }
    await api.waitUntilSyncIsPaused()
    await engine.invalidateIdentityWrites()
    await api.resumePausedSync()

    do {
        let outcome = try await sync.value
        r.expect(outcome.identitiesWritten, 0,
                 "identities revoke: stale sync publishes no identities")
        r.expect(await identity.replaceAllCalls, 0,
                 "identities revoke: authoritative clear cannot be overwritten")
    } catch {
        r.expectTrue(false, "identities revoke: sync threw: \(error)")
    }
}

/// A login with a TOTP secret yields an extra OTP identity for the same URI.
func checkIdentitiesIncludesOTP(_ r: inout TestRunner) async {
    guard let (store, dir) = try? Fixtures.freshStore() else {
        r.expectTrue(false, "identities otp: fresh store"); return
    }
    defer { Fixtures.cleanup(dir) }

    let keyVault = await Fixtures.unlockedVault()
    let identity = FakeIdentityStore(enabled: true, incrementalSupported: false)
    let base = Date(timeIntervalSince1970: 1_750_000_000)
    let cipherJSON = Fixtures.loginCipherJSON(
        id: "cipher-1", name: "GitHub", username: "octocat",
        uri: "https://github.com", revision: base, totp: "JBSWY3DPEHPK3PXP")
    let api = FakeVaultAPI(syncResponse: Fixtures.decodeSync(Fixtures.syncJSON(ciphers: [cipherJSON])))
    let engine = SyncEngine(api: api, store: store, keyVault: keyVault, identityStore: identity)

    do {
        _ = try await engine.fullSync(accountID: Fixtures.accountID)
        let written = await identity.lastReplaceAll
        r.expect(written.count, 2, "login with TOTP yields password + otp identities")
        let kinds = Set(written.map(\.kind))
        r.expectTrue(kinds.contains(.password), "otp case has a password identity")
        r.expectTrue(kinds.contains(.otp), "otp case has an otp identity")
    } catch {
        r.expectTrue(false, "identities otp threw: \(error)")
    }
}

/// Passkeys are indexed once per FIDO2 credential with decrypted RP/user fields and
/// decoded binary ids. They must not be multiplied by the login's URI count.
func checkIdentitiesIncludePasskeys(_ r: inout TestRunner) async {
    guard let (store, dir) = try? Fixtures.freshStore() else {
        r.expectTrue(false, "identities passkey: fresh store"); return
    }
    defer { Fixtures.cleanup(dir) }

    let keyVault = await Fixtures.unlockedVault()
    let identity = FakeIdentityStore(enabled: true, incrementalSupported: false)
    let base = Date(timeIntervalSince1970: 1_750_000_000)
    let uuidText = "00112233-4455-6677-8899-aabbccddeeff"
    let uuidCredentialID = Data([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ])
    let b64CredentialID = Data([0xfb, 0xff, 0x00, 0x10])
    let uuidHandle = Data("uuid-handle".utf8)
    let b64Handle = Data("b64-handle".utf8)
    let cipherJSON = Fixtures.loginCipherWithPasskeysJSON(
        id: "cipher-passkeys",
        name: "Passkey Login",
        username: "login-user",
        uris: ["https://one.example", "https://two.example"],
        revision: base,
        totp: "JBSWY3DPEHPK3PXP",
        passkeys: [
            Fixtures.PasskeyRecord(
                credentialIDValue: uuidText,
                rpId: "uuid.example",
                userHandle: uuidHandle,
                userName: "uuid-user"
            ),
            Fixtures.PasskeyRecord(
                credentialIDValue: "b64.\(Fixtures.base64URL(b64CredentialID))",
                rpId: "b64.example",
                userHandle: b64Handle,
                userName: "b64-user"
            ),
        ]
    )
    let api = FakeVaultAPI(
        syncResponse: Fixtures.decodeSync(Fixtures.syncJSON(ciphers: [cipherJSON]))
    )
    let engine = SyncEngine(api: api, store: store, keyVault: keyVault, identityStore: identity)

    do {
        let outcome = try await engine.fullSync(accountID: Fixtures.accountID)
        // Two URIs produce two password + two OTP identities. The two passkeys add only
        // two more identities, not two passkeys per URI.
        r.expect(outcome.identitiesWritten, 6,
                 "passkeys are independent of URI count")
        let written = await identity.lastReplaceAll
        r.expect(written.filter { $0.kind == .password }.count, 2,
                 "password remains per URI")
        r.expect(written.filter { $0.kind == .otp }.count, 2,
                 "OTP remains per URI")
        let passkeys = written.filter { $0.kind == .passkey }
        r.expect(passkeys.count, 2, "one identity emitted per FIDO2 credential")

        let uuidIdentity = passkeys.first { $0.serviceIdentifier == "uuid.example" }
        r.expect(uuidIdentity?.recordID, "cipher-passkeys",
                 "UUID passkey points to cipher")
        r.expect(uuidIdentity?.user, "uuid-user",
                 "passkey uses decrypted FIDO2 userName")
        r.expect(uuidIdentity?.credentialID, uuidCredentialID,
                 "UUID passkey credential id decoded")
        r.expect(uuidIdentity?.userHandle, uuidHandle,
                 "UUID passkey user handle decoded")

        let b64Identity = passkeys.first { $0.serviceIdentifier == "b64.example" }
        r.expect(b64Identity?.user, "b64-user",
                 "b64 passkey uses its own userName")
        r.expect(b64Identity?.credentialID, b64CredentialID,
                 "b64 passkey credential id decoded")
        r.expect(b64Identity?.userHandle, b64Handle,
                 "b64 passkey user handle decoded")
    } catch {
        r.expectTrue(false, "identities passkey threw: \(error)")
    }
}

/// A system identity is a promise that the extension can fulfill it. Corrupt password
/// ciphertext and a decryptable-but-invalid passkey private key must therefore be omitted,
/// while a healthy row in the same rebuild still publishes normally.
func checkUnfulfillableIdentitiesAreOmitted(_ r: inout TestRunner) async {
    guard let (store, dir) = try? Fixtures.freshStore() else {
        r.expectTrue(false, "identities fulfillability: fresh store"); return
    }
    defer { Fixtures.cleanup(dir) }

    let foreignKey = try! SymmetricCryptoKey(combined: Data((0..<64).map {
        UInt8(($0 * 13 + 19) & 0xff)
    }))
    let foreignPassword = try! SymmetricCrypto.encrypt(
        Data("cannot decrypt with active key".utf8),
        using: foreignKey
    ).stringValue
    let base = Date(timeIntervalSince1970: 1_750_000_000)
    let good = Fixtures.loginCipherJSON(
        id: "good-password", name: "Good", username: "alice",
        uri: "https://good.example", revision: base
    )
    let badPassword = Fixtures.loginCipherJSON(
        id: "bad-password", name: "Bad Password", username: "mallory",
        uri: "https://bad-password.example", revision: base,
        passwordWire: foreignPassword
    )
    let badItemKey = Fixtures.loginCipherJSON(
        id: "bad-item-key", name: "Bad Item Key", username: "eve",
        uri: "https://bad-item-key.example", revision: base,
        cipherKeyWire: foreignPassword
    )
    let badPasskey = Fixtures.loginCipherWithPasskeysJSON(
        id: "bad-passkey", name: "Bad Passkey", username: "bob", uris: [],
        revision: base,
        passkeys: [Fixtures.PasskeyRecord(
            credentialIDValue: "b64.AQI",
            rpId: "bad-passkey.example",
            userHandle: Data([3, 4]),
            userName: "bob"
        )],
        keyValuePlaintext: "not-a-p256-pkcs8-key"
    )
    let identity = FakeIdentityStore(enabled: true)
    let engine = SyncEngine(
        api: FakeVaultAPI(syncResponse: Fixtures.decodeSync(
            Fixtures.syncJSON(ciphers: [badPassword, good, badPasskey, badItemKey])
        )),
        store: store,
        keyVault: await Fixtures.unlockedVault(),
        identityStore: identity
    )

    do {
        let outcome = try await engine.fullSync(accountID: Fixtures.accountID)
        let written = await identity.lastReplaceAll
        r.expect(outcome.identitiesWritten, 1,
                 "identities fulfillability: only healthy identity is published")
        r.expect(written.map(\.recordID), ["good-password"],
                 "identities fulfillability: bad rows do not stop healthy batch")
        r.expectTrue(!written.contains { $0.recordID == "bad-password" },
                     "identities fulfillability: undecryptable password is omitted")
        r.expectTrue(!written.contains { $0.recordID == "bad-passkey" },
                     "identities fulfillability: invalid private key is omitted")
        r.expectTrue(!written.contains { $0.recordID == "bad-item-key" },
                     "identities fulfillability: unwrappable item key is omitted")
    } catch {
        r.expectTrue(false, "identities fulfillability threw: \(error)")
    }
}

/// Even if a soft-deleted row remains physically present for reconciliation, every live
/// query feeding AutoFill must exclude it and authoritatively withdraw prior identities.
func checkSoftDeletedRowsAreNotPublished(_ r: inout TestRunner) async {
    guard let (store, dir) = try? Fixtures.freshStore() else {
        r.expectTrue(false, "identities soft delete: fresh store"); return
    }
    defer { Fixtures.cleanup(dir) }

    let cipher = Fixtures.loginCipherJSON(
        id: "soft-deleted", name: "Deleted", username: "alice",
        uri: "https://deleted.example",
        revision: Date(timeIntervalSince1970: 1_750_000_000)
    )
    let identity = FakeIdentityStore(enabled: true)
    let engine = SyncEngine(
        api: FakeVaultAPI(syncResponse: Fixtures.decodeSync(
            Fixtures.syncJSON(ciphers: [cipher])
        )),
        store: store,
        keyVault: await Fixtures.unlockedVault(),
        identityStore: identity
    )

    do {
        _ = try await engine.fullSync(accountID: Fixtures.accountID)
        guard let row = try await store.cipher(
            id: "soft-deleted", accountID: Fixtures.accountID
        ) else {
            r.expectTrue(false, "identities soft delete: live row exists"); return
        }
        try await store.upsertCiphers([CipherRow(
            id: row.id,
            accountID: row.accountID,
            type: row.type,
            folderID: row.folderID,
            organizationID: row.organizationID,
            favorite: row.favorite,
            reprompt: row.reprompt,
            edit: row.edit,
            viewPassword: row.viewPassword,
            revisionDate: row.revisionDate,
            creationDate: row.creationDate,
            deletedDate: "2026-07-16T00:00:00.000Z",
            encName: row.encName,
            encNotes: row.encNotes,
            encBlob: row.encBlob,
            encCipherKey: row.encCipherKey,
            searchText: row.searchText
        )])

        let count = await engine.refreshCredentialIdentities(
            accountID: Fixtures.accountID,
            expectedGeneration: await engine.identityGenerationLease()
        )
        r.expect(count, 0, "identities soft delete: no identity is republished")
        r.expect(try await store.allCiphers(accountID: Fixtures.accountID).count, 0,
                 "identities soft delete: excluded from live store query")
        r.expect(await identity.lastReplaceAll.count, 0,
                 "identities soft delete: prior system identity is withdrawn")
        r.expect((try await store.cipher(
            id: "soft-deleted", accountID: Fixtures.accountID
        ))?.deletedDate, "2026-07-16T00:00:00.000Z",
                 "identities soft delete: test row is physically soft-deleted")
    } catch {
        r.expectTrue(false, "identities soft delete threw: \(error)")
    }
}
