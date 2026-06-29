import Foundation
import CryptoCore
import VaultModels
import VaultStore
import KeyVault
import KeychainBridge
import VaultRepository

/// ServiceContainer resolves the repositories + shared services through the `Has*`
/// protocols, and the wiring is identity-correct: the container's `keyVault` is the same
/// instance the repositories were built with (so a login through the resolved
/// `authRepository` unlocks the `keyVault` the resolved `vaultRepository` reads through).
func checkServiceContainer(_ r: inout TestRunner) async {
    let h: Fixtures.Harness
    do { h = try await Fixtures.makeHarness(tokenResults: [.success(Fixtures.tokenResponse())]) }
    catch { r.expectTrue(false, "makeHarness threw: \(error)"); return }
    defer { Fixtures.cleanup(h.dir) }

    let container = ServiceContainer(
        authRepository: h.auth, vaultRepository: h.vault,
        store: h.store, keyVault: h.keyVault, keychain: h.keychain
    )

    // Resolve each service via its `Has*` protocol (generic functions force the protocol
    // path rather than touching the concrete properties directly).
    let resolvedAuth = resolveAuth(container)
    let resolvedVault = resolveVault(container)
    let resolvedKeyVault = resolveKeyVault(container)
    let resolvedStore = resolveStore(container)
    let resolvedKeychain = resolveKeychain(container)

    r.expectTrue(resolvedAuth === h.auth, "container: HasAuthRepository resolves the auth actor")
    r.expectTrue(resolvedVault === h.vault, "container: HasVaultRepository resolves the vault actor")
    r.expectTrue(resolvedKeyVault === h.keyVault, "container: HasKeyVault resolves the shared KeyVault")
    r.expectTrue(resolvedStore === h.store, "container: HasVaultStore resolves the store")
    r.expectTrue(resolvedKeychain === h.keychain, "container: HasKeychain resolves the keychain")

    // End-to-end through the resolved services: login via the resolved auth repo, then read
    // a seeded cipher via the resolved vault repo — proving they share one KeyVault.
    do {
        _ = try await resolvedAuth.login(email: Fixtures.email, password: Fixtures.password,
                                         server: Fixtures.server)
        let unlocked = await resolvedKeyVault.isUnlocked
        r.expectTrue(unlocked, "container: login via resolved auth unlocks shared keyVault")

        let session = await resolvedAuth.session
        guard let accountID = session?.accountID else {
            r.expectTrue(false, "container: missing accountID"); return
        }
        try await resolvedStore.upsertCiphers([
            CipherRow(id: "ct-1", accountID: accountID, type: CipherType.login.rawValue,
                      revisionDate: Fixtures.iso(Date()), creationDate: Fixtures.iso(Date()),
                      encName: Fixtures.enc("Container Item"), searchText: "container item")
        ])
        let cipher = try await resolvedVault.cipher(id: "ct-1")
        r.expect(cipher.name, "Container Item", "container: resolved vault reads through shared keyVault")
    } catch {
        r.expectTrue(false, "container: end-to-end threw: \(error)")
    }
}

// Generic resolvers that exercise the `Has*` protocol conformances.
private func resolveAuth(_ c: some HasAuthRepository) -> AuthRepository { c.authRepository }
private func resolveVault(_ c: some HasVaultRepository) -> VaultRepository { c.vaultRepository }
private func resolveKeyVault(_ c: some HasKeyVault) -> KeyVault { c.keyVault }
private func resolveStore(_ c: some HasVaultStore) -> VaultStore { c.store }
private func resolveKeychain(_ c: some HasKeychain) -> KeychainBridge { c.keychain }
