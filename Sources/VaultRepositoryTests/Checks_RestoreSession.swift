import Foundation
import KeyVault
import Networking
import VaultRepository
import VaultStore
import AppShared

/// A successful login persists only an active-account marker in the Keychain. A fresh
/// repository process must rebuild a locked session from that marker + the encrypted row,
/// restore the API environment, and remain unlockable offline with the master password.
func checkColdSessionRestoration(_ r: inout TestRunner) async {
    let h: Fixtures.Harness
    do { h = try await Fixtures.makeHarness(tokenResults: [.success(Fixtures.tokenResponse())]) }
    catch { r.expectTrue(false, "restore: makeHarness threw: \(error)"); return }
    defer { Fixtures.cleanup(h.dir) }

    do {
        _ = try await h.auth.login(
            email: Fixtures.email,
            password: Fixtures.password,
            server: Fixtures.server
        )
    } catch {
        r.expectTrue(false, "restore: initial login threw: \(error)")
        return
    }

    let originalSession = await h.auth.session
    let marker = try? await h.keychain.getSecret(
        account: AppShared.KeychainAccount.activeAccountID
    )
    let sessionMarkerBeforeRestore = try? await h.keychain.getSecret(
        account: AppShared.KeychainAccount.activeSessionID
    )
    r.expect(String(data: marker ?? Data(), encoding: .utf8), originalSession?.accountID,
             "restore: login persists active account marker")
    r.expectTrue(sessionMarkerBeforeRestore != nil,
                 "restore: login publishes an extension session nonce")

    let restoredKeyVault = KeyVault()
    let restored = AuthRepository(
        api: h.api,
        keyVault: restoredKeyVault,
        keychain: h.keychain,
        store: h.store,
        encryptor: UserKeyEncryptor()
    )

    do {
        let serverURL = try await restored.restoreSession()
        r.expect(serverURL, Fixtures.server.base.absoluteString,
                 "restore: returns persisted server URL")
        let sessionMarkerAfterRestore = try await h.keychain.getSecret(
            account: AppShared.KeychainAccount.activeSessionID
        )
        r.expectTrue(sessionMarkerAfterRestore != nil
                     && sessionMarkerAfterRestore != sessionMarkerBeforeRestore,
                     "restore: cold process rotates extension session nonce")
    } catch {
        r.expectTrue(false, "restore: cold restoration threw: \(error)")
        return
    }

    r.expect(await restored.session, originalSession,
             "restore: recreates the account session")
    r.expectTrue(!(await restoredKeyVault.isUnlocked),
                 "restore: does not load user key on cold start")
    let environments = await h.api.environmentsSet
    r.expect(environments.last, Fixtures.server,
             "restore: applies persisted API environment")

    do {
        try await restored.unlockWithMasterPassword(Fixtures.password)
        r.expectTrue(await restoredKeyVault.isUnlocked,
                     "restore: restored session unlocks with master password")
    } catch {
        r.expectTrue(false, "restore: master-password unlock threw: \(error)")
    }

    // Logout must remove the marker so a third process cannot resurrect the session.
    await restored.logout()
    let afterLogout = AuthRepository(
        api: h.api,
        keyVault: KeyVault(),
        keychain: h.keychain,
        store: h.store,
        encryptor: UserKeyEncryptor()
    )
    do {
        r.expectTrue(try await afterLogout.restoreSession() == nil,
                     "restore: logout prevents cold restoration")
    } catch {
        r.expectTrue(false, "restore: post-logout restoration threw: \(error)")
    }
}

/// A corrupt/stale marker is cleared instead of trapping every launch on an unusable
/// unlock screen.
func checkStaleSessionMarkerIsCleared(_ r: inout TestRunner) async {
    let h: Fixtures.Harness
    do { h = try await Fixtures.makeHarness(tokenResults: []) }
    catch { r.expectTrue(false, "restore stale: makeHarness threw: \(error)"); return }
    defer { Fixtures.cleanup(h.dir) }

    try? await h.keychain.setSecret(
        Data("missing-account".utf8),
        account: AppShared.KeychainAccount.activeAccountID,
        biometryGated: false
    )
    do {
        r.expectTrue(try await h.auth.restoreSession() == nil,
                     "restore stale: missing account is rejected")
        let marker = try await h.keychain.getSecret(
            account: AppShared.KeychainAccount.activeAccountID
        )
        r.expectTrue(marker == nil, "restore stale: invalid marker is removed")
    } catch {
        r.expectTrue(false, "restore stale: restoration threw: \(error)")
    }
}

/// Legacy `host|email` rows are ambiguous across HTTP/HTTPS, ports, and reverse-proxy
/// paths. Restoration must quarantine the row instead of silently claiming it for the
/// stored URL; a new canonical login/full sync is the only safe migration.
func checkLegacyAccountMarkerIsQuarantined(_ r: inout TestRunner) async {
    let h: Fixtures.Harness
    do { h = try await Fixtures.makeHarness(tokenResults: []) }
    catch { r.expectTrue(false, "restore legacy: makeHarness threw: \(error)"); return }
    defer { Fixtures.cleanup(h.dir) }

    let legacyID = "vault.example.test|\(Fixtures.email.lowercased())"
    let protectedKey = Fixtures.tokenResponse().key?.stringValue
    do {
        try await h.store.upsertAccounts([
            AccountRow(
                id: legacyID,
                email: Fixtures.email,
                serverURL: Fixtures.server.base.absoluteString,
                kdfType: 0,
                kdfIters: Fixtures.iterations,
                encUserKey: protectedKey
            )
        ])
        try await h.keychain.setSecret(
            Data(legacyID.utf8),
            account: AppShared.KeychainAccount.activeAccountID,
            biometryGated: false
        )

        r.expectTrue(try await h.auth.restoreSession() == nil,
                     "restore legacy: ambiguous marker is rejected")
        r.expectTrue(await h.auth.session == nil,
                     "restore legacy: ambiguous row cannot publish a session")
        let marker = try await h.keychain.getSecret(
            account: AppShared.KeychainAccount.activeAccountID
        )
        r.expectTrue(marker == nil,
                     "restore legacy: ambiguous active marker is cleared")
        r.expectTrue(try await h.store.account(id: legacyID) != nil,
                     "restore legacy: encrypted row remains quarantined for recovery")
    } catch {
        r.expectTrue(false, "restore legacy flow threw: \(error)")
    }
}

/// `restoreSession` suspends while configuring the shared API actor. Logout during that
/// suspension must revoke the restore lease so the old session cannot be published later.
func checkLogoutSupersedesSessionRestore(_ r: inout TestRunner) async {
    let h: Fixtures.Harness
    do { h = try await Fixtures.makeHarness(tokenResults: [.success(Fixtures.tokenResponse())]) }
    catch { r.expectTrue(false, "restore race: makeHarness threw: \(error)"); return }
    defer { Fixtures.cleanup(h.dir) }

    do {
        _ = try await h.auth.login(email: Fixtures.email, password: Fixtures.password,
                                   server: Fixtures.server)
    } catch {
        r.expectTrue(false, "restore race: initial login threw: \(error)")
        return
    }

    let restored = AuthRepository(
        api: h.api,
        keyVault: KeyVault(),
        keychain: h.keychain,
        store: h.store,
        encryptor: UserKeyEncryptor()
    )
    // Initial login used environment calls 1 and 2; pause restore's third call.
    await h.api.pauseEnvironmentCall(3)
    let restore = Task { () -> RepositoryError? in
        do {
            _ = try await restored.restoreSession()
            return nil
        } catch let error as RepositoryError {
            return error
        } catch {
            return .underlying(kind: .network, description: String(describing: error))
        }
    }
    await h.api.waitUntilEnvironmentCallIsPaused()
    await restored.logout()
    await h.api.resumePausedEnvironmentCall()

    r.expect(
        await restore.value,
        RepositoryError.underlying(
            kind: .network,
            description: "Session restoration was superseded"
        ),
        "restore race: suspended restoration is rejected"
    )
    r.expectTrue(await restored.session == nil,
                 "restore race: logout cannot be undone by stale restore")
    let marker = try? await h.keychain.getSecret(
        account: AppShared.KeychainAccount.activeAccountID
    )
    r.expectTrue(marker == nil,
                 "restore race: active marker stays deleted")
}

/// The Secure-Enclave wrapped key is explicitly bound to the active account. A stale key
/// from another server must be rejected before it can unlock the in-memory vault.
func checkBiometricKeyIsAccountBound(_ r: inout TestRunner) async {
    let h: Fixtures.Harness
    do {
        h = try await Fixtures.makeHarness(tokenResults: [
            .success(Fixtures.tokenResponse(accessToken: "access-a")),
            .success(Fixtures.tokenResponse(accessToken: "access-b")),
        ])
    } catch { r.expectTrue(false, "biometric binding: makeHarness threw: \(error)"); return }
    defer { Fixtures.cleanup(h.dir) }

    do {
        _ = try await h.auth.login(
            email: Fixtures.email,
            password: Fixtures.password,
            server: Fixtures.server,
            enableBiometrics: true
        )
        await h.auth.lock()
        try await h.auth.unlockWithBiometrics(reason: "test")
        r.expectTrue(await h.keyVault.isUnlocked,
                     "biometric binding: matching account unlocks")

        await h.auth.lock()
        try await h.keychain.setSecret(
            Data("different-account".utf8),
            account: AppShared.KeychainAccount.biometricAccountID,
            biometryGated: false
        )
        await r.expectThrowsErrorAsync(
            RepositoryError.authenticationFailed,
            "biometric binding: mismatched account is rejected"
        ) {
            try await h.auth.unlockWithBiometrics(reason: "test")
        }
        r.expectTrue(!(await h.keyVault.isUnlocked),
                     "biometric binding: mismatch leaves vault locked")

        _ = try await h.auth.login(
            email: Fixtures.email,
            password: Fixtures.password,
            server: ServerEnvironment(string: "https://other.example.test")!,
            enableBiometrics: false
        )
        let binding = try await h.keychain.getSecret(
            account: AppShared.KeychainAccount.biometricAccountID
        )
        r.expectTrue(binding == nil,
                     "biometric binding: login with policy off clears previous binding")

        try await h.auth.setBiometricUnlockEnabled(true)
        let enabledBinding = try await h.keychain.getSecret(
            account: AppShared.KeychainAccount.biometricAccountID
        )
        r.expect(String(data: enabledBinding ?? Data(), encoding: .utf8),
                 (await h.auth.session)?.accountID,
                 "biometric binding: settings toggle enables current unlocked session")
        try await h.auth.setBiometricUnlockEnabled(false)
        r.expectTrue(try await h.keychain.getSecret(
            account: AppShared.KeychainAccount.biometricAccountID
        ) == nil, "biometric binding: settings toggle disables immediately")
    } catch {
        r.expectTrue(false, "biometric binding flow threw: \(error)")
    }
}

/// Sync profile upserts carry only server-side profile fields. They must not erase the local
/// server/KDF metadata required to reconstruct a session on the next process launch.
func checkSessionRestoresAfterSync(_ r: inout TestRunner) async {
    let h: Fixtures.Harness
    do { h = try await Fixtures.makeHarness(tokenResults: [.success(Fixtures.tokenResponse())]) }
    catch { r.expectTrue(false, "restore after sync: makeHarness threw: \(error)"); return }
    defer { Fixtures.cleanup(h.dir) }

    do {
        _ = try await h.auth.login(
            email: Fixtures.email,
            password: Fixtures.password,
            server: Fixtures.server
        )
        let accountID = await h.auth.session!.accountID
        let protectedBeforeSync = try await h.store.account(id: accountID)?.encUserKey
        await h.api.setSyncResponse(Fixtures.syncResponse(
            cipherID: "synced-restore",
            name: "Synced",
            username: "alice",
            uri: "https://example.test"
        ))
        _ = try await h.vault.sync()

        let row = try await h.store.account(id: accountID)
        r.expect(row?.serverURL, Fixtures.server.base.absoluteString,
                 "restore after sync: server URL preserved")
        r.expect(row?.kdfIters, Fixtures.iterations,
                 "restore after sync: KDF iterations preserved")
        r.expect(row?.encUserKey, protectedBeforeSync,
                 "restore after sync: protected user key preserved")

        let restored = AuthRepository(
            api: h.api,
            keyVault: KeyVault(),
            keychain: h.keychain,
            store: h.store,
            encryptor: UserKeyEncryptor()
        )
        r.expect(try await restored.restoreSession(), Fixtures.server.base.absoluteString,
                 "restore after sync: cold session restoration succeeds")
        r.expect((await restored.session)?.accountID, accountID,
                 "restore after sync: correct account restored")
    } catch {
        r.expectTrue(false, "restore after sync flow threw: \(error)")
    }
}
