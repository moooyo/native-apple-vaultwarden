import CryptoCore
import Foundation
import Networking
import VaultRepository
import VaultStore

func checkVaultTransferAuthorization(_ runner: inout TestRunner) async {
    do {
        let harness = try await Fixtures.makeHarness(tokenResults: [.success(Fixtures.tokenResponse())])
        defer { Fixtures.cleanup(harness.dir) }
        _ = try await harness.auth.login(email: Fixtures.email, password: Fixtures.password, server: Fixtures.server)
        guard let lease = await harness.auth.currentSessionLease() else {
            runner.expectTrue(false, "transfer: authenticated session required"); return
        }
        try await harness.auth.verifyMasterPassword(Fixtures.password, for: lease)
        do {
            try await harness.auth.verifyMasterPassword("not-the-password", for: lease)
            runner.expectTrue(false, "transfer: wrong master password rejected even while unlocked")
        } catch RepositoryError.authenticationFailed { runner.expectTrue(true, "transfer: rejected wrong password") }
        let malformed = CipherRow(id: "damaged", accountID: lease.accountID, type: 1,
                                  revisionDate: Fixtures.iso(.now), creationDate: Fixtures.iso(.now),
                                  encName: Fixtures.enc("Item"), encBlob: #"{"login":{"password":"damaged"}}"#)
        try await harness.store.upsertCiphers([malformed])
        do {
            _ = try await harness.vault.exportableCiphers(expectedSession: lease)
            runner.expectTrue(false, "transfer: damaged password must not silently export as empty")
        } catch { runner.expectTrue(true, "transfer: abort export on field decryption failure") }
        await harness.auth.lock()
        do {
            try await harness.auth.verifyMasterPassword(Fixtures.password, for: lease)
            runner.expectTrue(false, "transfer: a stale operation must not re-unlock the vault")
        } catch { runner.expectTrue(true, "transfer: lock revokes export") }
        let stillLocked = await harness.auth.isUnlocked() == false
        runner.expectTrue(stillLocked, "transfer: reauthentication never installs a key")
    } catch { runner.expectTrue(false, "transfer: authorization fixture failed") }
}

func checkVaultTransferIdentityBatching(_ runner: inout TestRunner) async {
    do {
        let identities = FakeIdentityStore(enabled: true)
        let harness = try await Fixtures.makeHarness(tokenResults: [.success(Fixtures.tokenResponse())], identityStore: identities)
        defer { Fixtures.cleanup(harness.dir) }
        _ = try await harness.auth.login(email: Fixtures.email, password: Fixtures.password, server: Fixtures.server)
        guard let lease = await harness.auth.currentSessionLease() else {
            runner.expectTrue(false, "batch import: session required"); return
        }
        let items = (1...3).map { index in
            PlaintextCipher(name: "Login \(index)", login: .init(username: "user", password: "secret",
                                                               uris: [.init(uri: "https://site\(index).example")]))
        }
        let baseline = await identities.replaceAllCalls
        try await harness.vault.importCiphers(items, expectedSession: lease)
        runner.expect(await identities.replaceAllCalls, baseline + 1, "batch import: three creates rebuild identities once")
        let requests = await harness.api.createdRequests.count
        await harness.api.failCreate(onCall: requests + 2)
        do {
            try await harness.vault.importCiphers(items, expectedSession: lease)
            runner.expectTrue(false, "batch import: partial server rejection reported")
        } catch let partial as PartialCipherImport {
            runner.expect(partial.savedCount, 1, "batch import: exact committed prefix on server failure")
        }
        runner.expect(await identities.replaceAllCalls, baseline + 2, "batch import: partial failure rebuilds once")
        await harness.api.pauseNextCreate()
        let operation = Task { try await harness.vault.importCiphers(items, expectedSession: lease) }
        await harness.api.waitUntilCreateIsPaused()
        operation.cancel()
        await harness.api.resumePausedCreate()
        do {
            try await operation.value
            runner.expectTrue(false, "batch import: cancellation reported")
        } catch let partial as PartialCipherImport {
            runner.expect(partial.savedCount, 1, "batch import: cancellation does not recreate acknowledged items")
        }
        runner.expect(await identities.replaceAllCalls, baseline + 3, "batch import: cancelled batch rebuilds once")
        await harness.api.setCreateError(NetworkingError.serverUnreachable)
        try await harness.vault.importCiphers(items, expectedSession: lease)
        runner.expect(await identities.replaceAllCalls, baseline + 4, "batch import: offline creates rebuild once")
        let outbox = try await harness.store.outboxForFlush(accountID: lease.accountID)
        runner.expect(outbox.count, 3, "batch import: all offline items retained in the account outbox")
    } catch { runner.expectTrue(false, "batch import: unexpected error") }
}
