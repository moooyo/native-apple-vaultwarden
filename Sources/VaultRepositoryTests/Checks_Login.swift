import Foundation
import CryptoCore
import VaultModels
import VaultStore
import KeyVault
import Networking
import VaultRepository

/// Login happy path (PBKDF2, kdf == 0): prelogin returns kdf=0; the token grant returns a
/// protected user key that really decrypts under the stretched master key → `login` returns
/// `.success`, the vault unlocks, and a subsequently-seeded cipher decrypts back to plaintext.
func checkLoginHappyPath(_ r: inout TestRunner) async {
    let h: Fixtures.Harness
    do { h = try await Fixtures.makeHarness(tokenResults: [.success(Fixtures.tokenResponse())]) }
    catch { r.expectTrue(false, "makeHarness threw: \(error)"); return }
    defer { Fixtures.cleanup(h.dir) }

    // Pre-login: vault is locked.
    let lockedBefore = await h.keyVault.isUnlocked
    r.expectTrue(!lockedBefore, "login: vault locked before login")

    do {
        let result = try await h.auth.login(email: Fixtures.email, password: Fixtures.password,
                                            server: Fixtures.server)
        r.expect(result, LoginResult.success, "login: returns .success")
    } catch {
        r.expectTrue(false, "login threw: \(error)"); return
    }

    // The vault is now unlocked.
    let unlocked = await h.keyVault.isUnlocked
    r.expectTrue(unlocked, "login: vault unlocked after success")
    let isUnlockedViaAuth = await h.auth.isUnlocked()
    r.expectTrue(isUnlockedViaAuth, "login: auth.isUnlocked() true")

    // A session was established with the right email + iterations.
    let session = await h.auth.session
    r.expect(session?.email, Fixtures.email, "login: session email")
    r.expect(session?.kdfIterations, Fixtures.iterations, "login: session iterations")

    // The bearer token was set on the API client.
    let tokens = await h.api.accessTokensSet
    r.expectTrue(tokens.contains("access-1"), "login: bearer token set")

    // The token grant carried the SERVER-auth hash (not the local hash), and the email
    // was normalized + forwarded.
    let preloginCalls = await h.api.preloginCalls
    r.expect(preloginCalls, [Fixtures.email], "login: prelogin called once with email")
    let tokenCalls = await h.api.tokenCalls
    r.expect(tokenCalls.count, 1, "login: token called once")
    r.expectTrue(tokenCalls.first?.twoFactor == nil, "login: no 2FA payload on first token call")

    // Seed an encrypted cipher row (encrypted under the real user key the protected key
    // wraps) and confirm the unlocked vault decrypts it back to plaintext.
    guard let accountID = session?.accountID else {
        r.expectTrue(false, "login: missing accountID"); return
    }
    do {
        let row = CipherRow(
            id: "seeded-1", accountID: accountID, type: CipherType.login.rawValue,
            revisionDate: Fixtures.iso(Date()), creationDate: Fixtures.iso(Date()),
            encName: Fixtures.enc("Seeded Item"),
            encBlob: blobJSON(username: Fixtures.enc("alice"), password: Fixtures.enc("pw123")),
            searchText: "seeded item"
        )
        try await h.store.upsertCiphers([row])

        let cipher = try await h.vault.cipher(id: "seeded-1")
        r.expect(cipher.name, "Seeded Item", "login: seeded cipher name decrypts")
        r.expect(cipher.login?.username, "alice", "login: seeded cipher username decrypts")
        r.expect(cipher.login?.password, "pw123", "login: seeded cipher password decrypts")
    } catch {
        r.expectTrue(false, "login: seeded cipher decrypt threw: \(error)")
    }
}

/// Argon2id rejected (decision D6): prelogin kdf == 1 → `login` THROWS
/// `RepositoryError.unsupportedKDF(1)` BEFORE any key derivation, no token call is made,
/// and the vault stays locked.
func checkArgon2idRejected(_ r: inout TestRunner) async {
    let h: Fixtures.Harness
    // No token result queued — proves the guard fires before the token grant.
    do { h = try await Fixtures.makeHarness(tokenResults: [], kdf: 1) }
    catch { r.expectTrue(false, "makeHarness threw: \(error)"); return }
    defer { Fixtures.cleanup(h.dir) }

    await r.expectThrowsErrorAsync(RepositoryError.unsupportedKDF(1), "argon2id: login throws .unsupportedKDF(1)") {
        _ = try await h.auth.login(email: Fixtures.email, password: Fixtures.password,
                                   server: Fixtures.server)
    }

    // Guard fired BEFORE the token grant.
    let tokenCalls = await h.api.tokenCalls
    r.expect(tokenCalls.count, 0, "argon2id: token grant NOT attempted")
    // Vault stays locked.
    let unlocked = await h.keyVault.isUnlocked
    r.expectTrue(!unlocked, "argon2id: vault stays locked")
    let session = await h.auth.session
    r.expectTrue(session == nil, "argon2id: no session established")
}

/// 2FA required: the first token grant returns a TwoFactorProviders challenge → `login`
/// returns `.twoFactorRequired([.authenticator])`; `submitTwoFactor` then succeeds and
/// unlocks the vault.
func checkTwoFactorRequired(_ r: inout TestRunner) async {
    let h: Fixtures.Harness
    do {
        h = try await Fixtures.makeHarness(tokenResults: [
            Fixtures.twoFactorResult([TwoFactorProvider.authenticator.rawValue]),
            .success(Fixtures.tokenResponse()),
        ])
    } catch { r.expectTrue(false, "makeHarness threw: \(error)"); return }
    defer { Fixtures.cleanup(h.dir) }

    do {
        let result = try await h.auth.login(email: Fixtures.email, password: Fixtures.password,
                                            server: Fixtures.server)
        r.expect(result, LoginResult.twoFactorRequired([.authenticator]), "2fa: login returns .twoFactorRequired")
    } catch {
        r.expectTrue(false, "2fa: login threw: \(error)"); return
    }

    // Still locked until the second factor is answered.
    let lockedMid = await h.keyVault.isUnlocked
    r.expectTrue(!lockedMid, "2fa: vault locked while challenge pending")

    do {
        let result = try await h.auth.submitTwoFactor(provider: .authenticator, token: "123456",
                                                      remember: false, server: Fixtures.server)
        r.expect(result, LoginResult.success, "2fa: submitTwoFactor returns .success")
    } catch {
        r.expectTrue(false, "2fa: submitTwoFactor threw: \(error)"); return
    }

    let unlocked = await h.keyVault.isUnlocked
    r.expectTrue(unlocked, "2fa: vault unlocked after submitTwoFactor")

    // The retry carried the 2FA payload; the second token call used the same server hash
    // (the KDF was not re-run wrongly — same hash both times).
    let tokenCalls = await h.api.tokenCalls
    r.expect(tokenCalls.count, 2, "2fa: token called twice")
    r.expectTrue(tokenCalls.last?.twoFactor?.provider == .authenticator, "2fa: retry carries provider")
    r.expectTrue(tokenCalls.last?.twoFactor?.token == "123456", "2fa: retry carries token")
    if tokenCalls.count == 2 {
        r.expect(tokenCalls[0].hash, tokenCalls[1].hash, "2fa: same server hash on retry (KDF reused)")
    }
}

/// `submitTwoFactor` without a prior `login` (no pending state) throws `.notAuthenticated`.
func checkTwoFactorWithoutPending(_ r: inout TestRunner) async {
    let h: Fixtures.Harness
    do { h = try await Fixtures.makeHarness(tokenResults: [.success(Fixtures.tokenResponse())]) }
    catch { r.expectTrue(false, "makeHarness threw: \(error)"); return }
    defer { Fixtures.cleanup(h.dir) }

    await r.expectThrowsErrorAsync(RepositoryError.notAuthenticated, "2fa: submit without pending throws .notAuthenticated") {
        _ = try await h.auth.submitTwoFactor(provider: .authenticator, token: "000000",
                                             server: Fixtures.server)
    }
}

// MARK: - Local helper

/// Build the `enc_blob` JSON the repository reads on decrypt: a login sub-object of
/// EncString wire strings. Mirrors `BlobRoot`/`BlobLogin` in the source.
func blobJSON(username: String? = nil, password: String? = nil,
              totp: String? = nil, uris: [(uri: String, match: Int?)] = []) -> String {
    var login: [String: Any] = [:]
    if let username { login["username"] = username }
    if let password { login["password"] = password }
    if let totp { login["totp"] = totp }
    if !uris.isEmpty {
        login["uris"] = uris.map { u -> [String: Any] in
            var d: [String: Any] = ["uri": u.uri]
            if let m = u.match { d["match"] = m }
            return d
        }
    }
    let root: [String: Any] = ["login": login]
    let data = try! JSONSerialization.data(withJSONObject: root)
    return String(decoding: data, as: UTF8.self)
}
