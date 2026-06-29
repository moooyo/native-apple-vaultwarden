import Foundation
import VaultModels
import VaultStore
import KeyVault
import SyncEngine

/// Identities: after sync the fake store receives one identity per login URI, with the
/// decrypted serviceIdentifier + username; `supportsIncremental=false` → replaceAll;
/// `=true` → incremental.
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
        r.expect(incCalls, 1, "incremental used when supportsIncremental=true")
        r.expect(calls, 0, "replaceAll NOT used when supportsIncremental=true")

        let added = await identity.lastIncrementalAdd
        r.expect(added.count, 1, "incremental add received 1 identity")
        r.expect(added.first?.serviceIdentifier, "https://github.com",
                 "incremental identity serviceIdentifier decrypted")
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
