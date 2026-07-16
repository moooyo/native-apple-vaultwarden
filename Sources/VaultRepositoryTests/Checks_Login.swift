import Foundation
import AppShared
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
    let environments = await h.api.environmentsSet
    r.expect(environments, [Fixtures.server, Fixtures.server],
             "login: revokes then commits the selected server")
    let preloginEnvironments = await h.api.environmentsAtPrelogin
    r.expect(preloginEnvironments.first ?? nil, Fixtures.server,
             "login: user server is active before prelogin")
    let tokenCalls = await h.api.tokenCalls
    r.expect(tokenCalls.count, 1, "login: token called once")
    r.expectTrue(tokenCalls.first?.twoFactor == nil, "login: no 2FA payload on first token call")
    r.expect(tokenCalls.first?.server, Fixtures.server,
             "login: token grant is explicitly server-bound")

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

/// Actor reentrancy permits a second login while the first request is suspended. The newer
/// attempt must win, while the older one fails as superseded and cannot overwrite the API
/// server, bearer, session, or unlocked key after it eventually resumes.
func checkConcurrentLoginSupersession(_ r: inout TestRunner) async {
    let h: Fixtures.Harness
    do {
        h = try await Fixtures.makeHarness(tokenResults: [
            .success(Fixtures.tokenResponse(accessToken: "access-new")),
        ])
    } catch { r.expectTrue(false, "concurrent login: makeHarness threw: \(error)"); return }
    defer { Fixtures.cleanup(h.dir) }

    let firstServer = ServerEnvironment(string: "https://old.example.test")!
    let secondServer = ServerEnvironment(string: "https://new.example.test/team")!
    await h.api.pauseNextPrelogin()

    let first = Task { () -> RepositoryError? in
        do {
            _ = try await h.auth.login(email: Fixtures.email, password: Fixtures.password,
                                       server: firstServer)
            return nil
        } catch let error as RepositoryError {
            return error
        } catch {
            return .underlying(kind: .network, description: String(describing: error))
        }
    }
    await h.api.waitUntilPreloginIsPaused()

    do {
        let result = try await h.auth.login(email: Fixtures.email, password: Fixtures.password,
                                            server: secondServer)
        r.expect(result, .success, "concurrent login: newer attempt succeeds")
    } catch {
        r.expectTrue(false, "concurrent login: newer attempt threw: \(error)")
    }

    await h.api.resumePausedPrelogin()
    let firstError = await first.value
    r.expect(
        firstError,
        RepositoryError.underlying(kind: .network,
                                   description: "Login attempt was superseded"),
        "concurrent login: suspended older attempt is rejected"
    )

    let session = await h.auth.session
    r.expect(session?.accountID,
             "https://new.example.test/team|user@example.test",
             "concurrent login: session belongs to newer server")
    r.expect(await h.api.environmentsSet.last, secondServer,
             "concurrent login: final API environment belongs to newer attempt")
    r.expect(await h.api.accessTokensSet.last ?? nil, "access-new",
             "concurrent login: older attempt cannot replace newer bearer")
    let preloginServers = await h.api.environmentsAtPrelogin.compactMap { $0 }
    r.expect(preloginServers, [firstServer, secondServer],
             "concurrent login: each prelogin stays bound to its own server")
    let tokenCalls = await h.api.tokenCalls
    r.expect(tokenCalls.count, 1, "concurrent login: superseded attempt makes no token grant")
    r.expect(tokenCalls.first?.server, secondServer,
             "concurrent login: winning token grant uses newer server")
}

/// Entering a new login transition immediately withdraws the previous account marker so
/// the extension cannot keep vending account A while account B's network request is paused.
func checkLoginTransitionWithdrawsActiveMarker(_ r: inout TestRunner) async {
    let h: Fixtures.Harness
    do {
        h = try await Fixtures.makeHarness(tokenResults: [
            .success(Fixtures.tokenResponse(accessToken: "access-a")),
            .success(Fixtures.tokenResponse(accessToken: "access-b")),
        ])
    } catch { r.expectTrue(false, "login transition: makeHarness threw: \(error)"); return }
    defer { Fixtures.cleanup(h.dir) }

    do {
        _ = try await h.auth.login(email: Fixtures.email, password: Fixtures.password,
                                   server: Fixtures.server)
    } catch {
        r.expectTrue(false, "login transition: initial login threw: \(error)")
        return
    }
    await h.api.pauseNextPrelogin()
    let nextServer = ServerEnvironment(string: "https://next.example.test/vault")!
    let transition = Task { () -> Error? in
        do {
            _ = try await h.auth.login(email: Fixtures.email, password: Fixtures.password,
                                       server: nextServer)
            return nil
        } catch { return error }
    }
    await h.api.waitUntilPreloginIsPaused()

    do {
        let marker = try await h.keychain.getSecret(
            account: AppShared.KeychainAccount.activeAccountID
        )
        r.expectTrue(marker == nil,
                     "login transition: old active marker is withdrawn before network wait")
        r.expectTrue(await h.auth.session == nil,
                     "login transition: old in-memory session is withdrawn")
    } catch {
        r.expectTrue(false, "login transition: marker read threw: \(error)")
    }

    await h.api.resumePausedPrelogin()
    if let error = await transition.value {
        r.expectTrue(false, "login transition: replacement login threw: \(error)")
    }
}

/// Logout can reenter while a successful token grant is being durably committed. It must
/// revoke ownership before awaiting cleanup, remove any pre-session account secrets, and keep
/// the suspended commit from republishing a session/bearer after logout returns.
func checkLogoutSupersedesLoginCommit(_ r: inout TestRunner) async {
    let h: Fixtures.Harness
    do {
        h = try await Fixtures.makeHarness(tokenResults: [
            .success(Fixtures.tokenResponse(accessToken: "access-cancelled")),
            .success(Fixtures.tokenResponse(accessToken: "access-retry")),
        ])
    } catch { r.expectTrue(false, "logout race: makeHarness threw: \(error)"); return }
    defer { Fixtures.cleanup(h.dir) }

    // Login applies its environment once to revoke the old context, then again immediately
    // before publishing its new account. Pause that second (commit) application.
    await h.api.pauseEnvironmentCall(2)
    let login = Task { () -> RepositoryError? in
        do {
            _ = try await h.auth.login(email: Fixtures.email, password: Fixtures.password,
                                       server: Fixtures.server)
            return nil
        } catch let error as RepositoryError {
            return error
        } catch {
            return .underlying(kind: .network, description: String(describing: error))
        }
    }
    await h.api.waitUntilEnvironmentCallIsPaused()

    let logout = Task { await h.auth.logout() }
    // Queue an actor read behind the logout task so its synchronous intent/session
    // revocation has run before the suspended login commit resumes.
    await Task.yield()
    _ = await h.auth.hasSession()
    await h.api.resumePausedEnvironmentCall()
    await logout.value
    r.expect(
        await login.value,
        RepositoryError.underlying(kind: .network,
                                   description: "Login attempt was superseded"),
        "logout race: suspended commit is rejected"
    )

    let accountID = "https://vault.example.test|user@example.test"
    r.expectTrue(await h.auth.session == nil, "logout race: session stays cleared")
    r.expectTrue(!(await h.keyVault.isUnlocked), "logout race: vault stays locked")
    let activeMarker = try? await h.keychain.getSecret(
        account: AppShared.KeychainAccount.activeAccountID
    )
    let refresh = try? await h.keychain.getSecret(
        account: AppShared.KeychainAccount.refreshToken(accountID: accountID)
    )
    let localHash = try? await h.keychain.getSecret(
        account: AppShared.KeychainAccount.localAuthHash(accountID: accountID)
    )
    r.expectTrue(activeMarker == nil, "logout race: active marker stays deleted")
    r.expectTrue(refresh == nil, "logout race: pre-session refresh secret is deleted")
    r.expectTrue(localHash == nil, "logout race: pre-session local hash is deleted")
    await r.expectThrowsErrorAsync(
        NetworkingError.accountContextChanged,
        "logout race: API account lease stays revoked"
    ) {
        _ = try await h.api.sync(accountID: accountID, excludeDomains: true)
    }

    do {
        let result = try await h.auth.login(email: Fixtures.email, password: Fixtures.password,
                                            server: Fixtures.server)
        r.expect(result, .success, "logout race: completion guard resets for a retry")
    } catch {
        r.expectTrue(false, "logout race: retry login threw: \(error)")
    }
}

/// A logout may suspend in its API cleanup while the user starts a newer login. When the
/// old logout resumes, its account-scoped revocation must be a no-op for account B and its
/// remaining cleanup must stop before deleting B's newly published markers.
func checkNewLoginSupersedesSuspendedLogout(_ r: inout TestRunner) async {
    let h: Fixtures.Harness
    do {
        h = try await Fixtures.makeHarness(tokenResults: [
            .success(Fixtures.tokenResponse(accessToken: "access-a", refreshToken: "refresh-a")),
            .success(Fixtures.tokenResponse(accessToken: "access-b", refreshToken: "refresh-b")),
        ])
    } catch { r.expectTrue(false, "reverse logout race: makeHarness threw: \(error)"); return }
    defer { Fixtures.cleanup(h.dir) }

    let serverB = ServerEnvironment(string: "https://b.example.test/vault")!
    do {
        _ = try await h.auth.login(email: Fixtures.email, password: Fixtures.password,
                                   server: Fixtures.server)
        await h.api.pauseNextAccountClear()
        let oldLogout = Task { await h.auth.logout() }
        await h.api.waitUntilAccountClearIsPaused()

        await h.api.pauseNextToken()
        let newerLogin = Task {
            try await h.auth.login(email: Fixtures.email, password: Fixtures.password,
                                   server: serverB)
        }
        await h.api.waitUntilTokenIsPaused()
        r.expect(await h.api.tokenCalls.count, 2,
                     "reverse logout race: B grant reaches serialized commit")
        await h.api.resumePausedToken()
        await Task.yield()
        r.expectTrue(await h.auth.session == nil,
                     "reverse logout race: B commit waits for older cleanup")
        await h.api.resumePausedAccountClear()
        let result = try await newerLogin.value
        r.expect(result, .success, "reverse logout race: newer B login succeeds")
        await oldLogout.value

        let accountB = "https://b.example.test/vault|user@example.test"
        r.expect(await h.auth.session?.accountID, accountB,
                 "reverse logout race: B session remains published")
        r.expect(await h.api.accessTokensSet.last ?? nil, "access-b",
                 "reverse logout race: stale logout cannot clear B bearer")
        let marker = try await h.keychain.getSecret(
            account: AppShared.KeychainAccount.activeAccountID
        )
        r.expect(String(data: marker ?? Data(), encoding: .utf8), accountB,
                 "reverse logout race: stale logout cannot delete B marker")
        let refreshB = try await h.keychain.getSecret(
            account: AppShared.KeychainAccount.refreshToken(accountID: accountB)
        )
        r.expect(String(data: refreshB ?? Data(), encoding: .utf8), "refresh-b",
                 "reverse logout race: B refresh token remains durable")
    } catch {
        await h.api.resumePausedToken()
        await h.api.resumePausedAccountClear()
        r.expectTrue(false, "reverse logout race threw: \(error)")
    }
}

/// The persistence coordinator is also the same-account ABA barrier. Even after the newer
/// password grant returns, it cannot write A-new's refresh/local-auth secrets until A-old's
/// logout cleanup has left the critical section.
func checkSameAccountLoginWaitsForLogoutCleanup(_ r: inout TestRunner) async {
    let h: Fixtures.Harness
    do {
        h = try await Fixtures.makeHarness(tokenResults: [
            .success(Fixtures.tokenResponse(
                accessToken: "same-account-old-access",
                refreshToken: "same-account-old-refresh"
            )),
            .success(Fixtures.tokenResponse(
                accessToken: "same-account-new-access",
                refreshToken: "same-account-new-refresh"
            )),
        ])
    } catch { r.expectTrue(false, "same-account logout race: harness threw: \(error)"); return }
    defer { Fixtures.cleanup(h.dir) }

    do {
        _ = try await h.auth.login(email: Fixtures.email, password: Fixtures.password,
                                   server: Fixtures.server)
        let accountID = "https://vault.example.test|user@example.test"
        await h.api.pauseNextAccountClear()
        let oldLogout = Task { await h.auth.logout() }
        await h.api.waitUntilAccountClearIsPaused()

        await h.api.pauseNextToken()
        let replacement = Task {
            try await h.auth.login(email: Fixtures.email, password: Fixtures.password,
                                   server: Fixtures.server)
        }
        await h.api.waitUntilTokenIsPaused()
        r.expect(await h.api.tokenCalls.count, 2,
                     "same-account logout race: replacement grant completes")
        await h.api.resumePausedToken()
        await Task.yield()
        r.expectTrue(await h.auth.session == nil,
                     "same-account logout race: replacement commit waits for cleanup lock")
        let whilePaused = try await h.keychain.getSecret(
            account: AppShared.KeychainAccount.refreshToken(accountID: accountID)
        )
        r.expect(String(data: whilePaused ?? Data(), encoding: .utf8),
                 "same-account-old-refresh",
                 "same-account logout race: replacement has not written while cleanup paused")

        await h.api.resumePausedAccountClear()
        r.expect(try await replacement.value, .success,
                 "same-account logout race: replacement succeeds after cleanup exits")
        await oldLogout.value
        let finalRefresh = try await h.keychain.getSecret(
            account: AppShared.KeychainAccount.refreshToken(accountID: accountID)
        )
        r.expect(String(data: finalRefresh ?? Data(), encoding: .utf8),
                 "same-account-new-refresh",
                 "same-account logout race: stale cleanup cannot delete replacement token")
        r.expect(await h.api.accessTokensSet.last ?? nil, "same-account-new-access",
                 "same-account logout race: replacement bearer remains installed")
    } catch {
        await h.api.resumePausedToken()
        await h.api.resumePausedAccountClear()
        r.expectTrue(false, "same-account logout race threw: \(error)")
    }
}

/// Once logout withdraws `session`, a concurrent duplicate logout must inherit the original
/// account/context cleanup lease. Otherwise it supersedes the first intent with no account
/// to revoke, leaving both the bearer and account-scoped Keychain secrets behind.
func checkConcurrentLogoutTakesOverCleanup(_ r: inout TestRunner) async {
    let h: Fixtures.Harness
    do {
        h = try await Fixtures.makeHarness(tokenResults: [
            .success(Fixtures.tokenResponse(
                accessToken: "logout-race-access",
                refreshToken: "logout-race-refresh"
            )),
        ])
    } catch { r.expectTrue(false, "concurrent logout: makeHarness threw: \(error)"); return }
    defer { Fixtures.cleanup(h.dir) }

    do {
        _ = try await h.auth.login(email: Fixtures.email, password: Fixtures.password,
                                   server: Fixtures.server)
        let accountID = "https://vault.example.test|user@example.test"
        await h.api.pauseNextAccountClear()
        let firstLogout = Task { await h.auth.logout() }
        await h.api.waitUntilAccountClearIsPaused()
        r.expectTrue(await h.auth.session == nil,
                     "concurrent logout: first logout withdrew session before pausing")

        // This increments the authentication intent after `session` is already nil. It must
        // take over the first logout's cleanup lease rather than abandoning that cleanup.
        let takeoverIntent = await h.auth.reserveAuthenticationIntent()
        let secondLogout = Task {
            await h.auth.logout(reservedIntent: takeoverIntent)
        }
        await Task.yield()
        _ = await h.auth.hasSession()
        await h.api.resumePausedAccountClear()
        await secondLogout.value
        await firstLogout.value

        r.expect(await h.api.accessTokensSet.last ?? nil, nil,
                 "concurrent logout: takeover clears API bearer")
        let refresh = try await h.keychain.getSecret(
            account: AppShared.KeychainAccount.refreshToken(accountID: accountID)
        )
        let localHash = try await h.keychain.getSecret(
            account: AppShared.KeychainAccount.localAuthHash(accountID: accountID)
        )
        let activeAccount = try await h.keychain.getSecret(
            account: AppShared.KeychainAccount.activeAccountID
        )
        r.expectTrue(refresh == nil,
                     "concurrent logout: takeover deletes account refresh token")
        r.expectTrue(localHash == nil,
                     "concurrent logout: takeover deletes account local-auth hash")
        r.expectTrue(activeAccount == nil,
                     "concurrent logout: active account marker remains revoked")
    } catch {
        await h.api.resumePausedAccountClear()
        r.expectTrue(false, "concurrent logout race threw: \(error)")
    }
}

/// If a token is issued but binding its bearer fails, the half-committed user key and
/// account secrets are rolled back and the terminal login transition is released.
func checkFailedLoginCommitRollsBackTransition(_ r: inout TestRunner) async {
    let h: Fixtures.Harness
    do {
        h = try await Fixtures.makeHarness(tokenResults: [
            .success(Fixtures.tokenResponse(accessToken: "unbound-access")),
        ])
    } catch { r.expectTrue(false, "failed login commit: makeHarness threw: \(error)"); return }
    defer { Fixtures.cleanup(h.dir) }
    await h.api.setScopedAccessTokenError(NetworkingError.accountContextChanged)

    await r.expectThrowsErrorAsync(
        RepositoryError.underlying(
            kind: .network,
            description: String(describing: NetworkingError.accountContextChanged)
        ),
        "failed login commit: bearer binding error is surfaced"
    ) {
        _ = try await h.auth.login(email: Fixtures.email, password: Fixtures.password,
                                   server: Fixtures.server)
    }

    r.expectTrue(!(await h.keyVault.isUnlocked),
                 "failed login commit: partially unlocked key is rolled back")
    let accountID = "https://vault.example.test|user@example.test"
    let activeMarker = try? await h.keychain.getSecret(
        account: AppShared.KeychainAccount.activeAccountID
    )
    let refresh = try? await h.keychain.getSecret(
        account: AppShared.KeychainAccount.refreshToken(accountID: accountID)
    )
    r.expectTrue(activeMarker == nil, "failed login commit: active marker is rolled back")
    r.expectTrue(refresh == nil, "failed login commit: refresh token is rolled back")
    do {
        r.expect(try await h.auth.restoreSession(), nil,
                 "failed login commit: terminal transition is released")
    } catch {
        r.expectTrue(false, "failed login commit: restore remains blocked: \(error)")
    }
}

/// A 2FA challenge is bound to the server that supplied its prelogin parameters. A changed
/// server must be rejected before another token request is made; the original challenge stays
/// usable with the original server.
func checkTwoFactorRejectsServerSwitch(_ r: inout TestRunner) async {
    let h: Fixtures.Harness
    do {
        h = try await Fixtures.makeHarness(tokenResults: [
            Fixtures.twoFactorResult([TwoFactorProvider.authenticator.rawValue]),
            .success(Fixtures.tokenResponse()),
        ])
    } catch { r.expectTrue(false, "makeHarness threw: \(error)"); return }
    defer { Fixtures.cleanup(h.dir) }

    do {
        _ = try await h.auth.login(email: Fixtures.email, password: Fixtures.password,
                                   server: Fixtures.server)
    } catch {
        r.expectTrue(false, "2fa server binding: login threw: \(error)"); return
    }

    let changedServer = ServerEnvironment(base: URL(string: "https://other.example.test")!)
    await r.expectThrowsErrorAsync(
        RepositoryError.underlying(
            kind: .network,
            description: "Server changed during two-factor authentication"
        ),
        "2fa: changed server is rejected"
    ) {
        _ = try await h.auth.submitTwoFactor(provider: .authenticator, token: "123456",
                                             server: changedServer)
    }

    let callsAfterRejectedSwitch = await h.api.tokenCalls
    r.expect(callsAfterRejectedSwitch.count, 1,
             "2fa: rejected server switch makes no retry request")
    let environments = await h.api.environmentsSet
    r.expect(environments, [Fixtures.server],
             "2fa: rejected switch does not reconfigure shared API")

    do {
        let result = try await h.auth.submitTwoFactor(provider: .authenticator, token: "123456",
                                                      server: Fixtures.server)
        r.expect(result, .success, "2fa: original server challenge remains usable")
    } catch {
        r.expectTrue(false, "2fa original-server retry threw: \(error)")
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
    do {
        r.expect(try await h.auth.restoreSession(), nil,
                 "argon2id: terminal failure releases authentication transition")
    } catch {
        r.expectTrue(false, "argon2id: restore remains blocked after failure: \(error)")
    }
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

func checkMultiProviderEmailCodeRequest(_ r: inout TestRunner) async {
    let h: Fixtures.Harness
    do {
        h = try await Fixtures.makeHarness(tokenResults: [
            Fixtures.twoFactorResult([
                TwoFactorProvider.authenticator.rawValue,
                TwoFactorProvider.email.rawValue,
            ])
        ])
    } catch { r.expectTrue(false, "email 2FA: harness threw: \(error)"); return }
    defer { Fixtures.cleanup(h.dir) }
    do {
        let result = try await h.auth.login(
            email: Fixtures.email,
            password: Fixtures.password,
            server: Fixtures.server
        )
        r.expect(result, .twoFactorRequired([.authenticator, .email]),
                 "email 2FA: multi-provider challenge returned")
        r.expect(await h.api.emailCodeRequests.count, 1,
                 "email 2FA: multi-provider challenge sends initial code")
        try await h.auth.sendTwoFactorEmail(server: Fixtures.server)
        r.expect(await h.api.emailCodeRequests.count, 2,
                 "email 2FA: resend endpoint available")
        r.expect(await h.api.emailCodeRequests.last?.email, Fixtures.email,
                 "email 2FA: pending email forwarded")
    } catch {
        r.expectTrue(false, "email 2FA flow threw: \(error)")
    }
}

func checkConcurrentTwoFactorSubmissionIsRejected(_ r: inout TestRunner) async {
    let h: Fixtures.Harness
    do {
        h = try await Fixtures.makeHarness(tokenResults: [
            Fixtures.twoFactorResult([TwoFactorProvider.authenticator.rawValue]),
            .success(Fixtures.tokenResponse(accessToken: "2fa-winner")),
            .success(Fixtures.tokenResponse(accessToken: "2fa-duplicate")),
        ])
    } catch { r.expectTrue(false, "2FA concurrency: harness threw: \(error)"); return }
    defer { Fixtures.cleanup(h.dir) }
    do {
        _ = try await h.auth.login(
            email: Fixtures.email, password: Fixtures.password, server: Fixtures.server
        )
        await h.api.pauseNextToken()
        let first = Task {
            try await h.auth.submitTwoFactor(
                provider: .authenticator, token: "111111", server: Fixtures.server
            )
        }
        await h.api.waitUntilTokenIsPaused()
        await r.expectThrowsErrorAsync(
            RepositoryError.underlying(
                kind: .network,
                description: "Another two-factor submission is in progress"
            ),
            "2FA concurrency: duplicate submission is rejected"
        ) {
            _ = try await h.auth.submitTwoFactor(
                provider: .authenticator, token: "222222", server: Fixtures.server
            )
        }
        await h.api.resumePausedToken()
        r.expect(try await first.value, .success,
                 "2FA concurrency: claimed submission succeeds")
        r.expect(await h.api.tokenCalls.count, 2,
                 "2FA concurrency: only initial + one 2FA grant sent")
    } catch {
        await h.api.resumePausedToken()
        r.expectTrue(false, "2FA concurrency flow threw: \(error)")
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

/// Account cache identities include scheme, non-default port, and deployment path while
/// canonicalizing host case, trailing slash, and explicit default ports.
func checkAccountIDUsesCanonicalFullServerBase(_ r: inout TestRunner) async {
    let tokenResults = Array(repeating: TokenResult.success(Fixtures.tokenResponse()), count: 5)
    let h: Fixtures.Harness
    do { h = try await Fixtures.makeHarness(tokenResults: tokenResults) }
    catch { r.expectTrue(false, "accountID: makeHarness threw: \(error)"); return }
    defer { Fixtures.cleanup(h.dir) }

    let servers = [
        ServerEnvironment(base: URL(string: "https://Vault.Example.test/team/")!),
        ServerEnvironment(base: URL(string: "https://vault.example.test:443/team")!),
        ServerEnvironment(base: URL(string: "https://vault.example.test:8443/team")!),
        ServerEnvironment(base: URL(string: "https://vault.example.test/other")!),
        ServerEnvironment(base: URL(string: "http://vault.example.test/team")!),
    ]
    var ids: [String] = []
    for server in servers {
        do {
            _ = try await h.auth.login(email: Fixtures.email, password: Fixtures.password,
                                       server: server)
            if let id = await h.auth.session?.accountID { ids.append(id) }
        } catch {
            r.expectTrue(false, "accountID: login threw: \(error)"); return
        }
    }

    guard ids.count == servers.count else {
        r.expectTrue(false, "accountID: every login produced an id"); return
    }
    r.expect(ids[0], "https://vault.example.test/team|user@example.test",
             "accountID: canonical full base + email")
    r.expect(ids[0], ids[1], "accountID: default port and trailing slash normalize")
    r.expectTrue(ids[0] != ids[2], "accountID: non-default port distinguishes instance")
    r.expectTrue(ids[0] != ids[3], "accountID: reverse-proxy path distinguishes instance")
    r.expectTrue(ids[0] != ids[4], "accountID: scheme distinguishes instance")
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
