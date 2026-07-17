// Xcode-only target. Not part of the SPM build.
//
// ExtensionEnvironment — the AutoFill extension's minimal dependency graph.
//
// It builds ONLY the read stack (VaultReader over a VaultStore opened on the SAME SQLCipher
// file the app uses, in the App Group container, keyed by the same Keychain passphrase, plus a
// KeychainBridge in the shared access group and a fresh KeyVault). NO Networking, NO SyncEngine.
//
// This is the concrete embodiment of the 120MB red line: nothing here imports a heavy module.

import Foundation
import VaultReader
import VaultStore
import KeyVault
import KeychainBridge
import AppShared

actor ExtensionEnvironment {
    let reader: VaultReader
    private let keyVault: KeyVault
    private let keychain: KeychainBridge

    /// Reason string shown in the biometric prompt.
    private let unlockReason = "使用 OpenVault 解锁并安全填充凭据"

    init() {
        let keychain = KeychainBridge(accessGroup: AppShared.keychainAccessGroup,
                                      service: "dev.moooyo.tessera")
        let keyVault = KeyVault()
        let store = ExtensionEnvironment.makeStore(keychain: keychain)
        self.keychain = keychain
        self.keyVault = keyVault
        self.reader = VaultReader(store: store, keyVault: keyVault, keychain: keychain)
    }

    /// Whether the vault key is already in memory (it won't be on a cold extension launch — the
    /// extension is a separate process from the app, so the fast path almost always needs unlock).
    var isUnlocked: Bool {
        get async { await keyVault.isUnlocked }
    }

    /// Biometric unlock for this process: unwrap the SE-wrapped UserKey from the shared Keychain.
    func unlock() async throws {
        try await reader.unlockWithBiometrics(reason: unlockReason)
    }

    /// Passkey registration must not complete until an encrypted, acknowledged write-back
    /// path exists. Failing closed avoids creating an unusable server credential or writing
    /// a private key into a plaintext App Group hand-off file.
    func stagePasskeyRegistration(rpId: String, userHandle: Data, credentialID: Data,
                                  privateKeyPKCS8: Data) async throws {
        _ = (rpId, userHandle, credentialID, privateKeyPKCS8)
        throw NSError(domain: "OpenVaultPasskeyRegistration", code: 1,
                      userInfo: [NSLocalizedDescriptionKey: "Passkey write-back is unavailable"])
    }

    // MARK: - Builders

    private static func databaseURL() -> URL {
        let fm = FileManager.default
        if let group = fm.containerURL(forSecurityApplicationGroupIdentifier: AppShared.appGroupID) {
            do {
                try fm.createDirectory(at: group, withIntermediateDirectories: true)
                return group.appendingPathComponent("tessera-vault.sqlite")
            } catch {
                #if !DEBUG
                fatalError("OpenVault App Group is not writable: \(error)")
                #endif
            }
        }
        #if !DEBUG
        fatalError("OpenVault App Group is unavailable")
        #else
        let fallback = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        try? fm.createDirectory(at: fallback, withIntermediateDirectories: true)
        return fallback.appendingPathComponent("tessera-vault.sqlite")
        #endif
    }

    private static func makeStore(keychain: KeychainBridge) -> VaultStore {
        let url = databaseURL()
        let passphrase: Data
        do {
            passphrase = try loadPassphrase(keychain: keychain)
        } catch {
            #if DEBUG
            passphrase = Data(repeating: 0, count: 32)
            #else
            fatalError("OpenVault shared Keychain unavailable: \(error)")
            #endif
        }
        do {
            return try VaultStore(databaseURL: url, passphrase: passphrase)
        } catch {
            fatalError("AutoFill: failed to open the vault store at \(url): \(error)")
        }
    }

    /// Load the random DB passphrase the app wrote to the shared Keychain. The extension never
    /// generates it — if it's absent the user must open the app once to seed the vault.
    private static func loadPassphrase(keychain: KeychainBridge) throws -> Data {
        let account = "tessera.db-passphrase"
        // Box holds the cross-task result so the detached closure captures only Sendable
        // values (the box, the actor, and the String) — satisfies Swift 6 strict concurrency.
        // Access is safe: the closure writes exactly once before signal(), the caller reads
        // only after wait().
        final class Box: @unchecked Sendable { var value: Data? }
        let box = Box()
        let semaphore = DispatchSemaphore(value: 0)
        Task.detached(priority: .userInitiated) {
            box.value = try? await keychain.getSecret(account: account)
            semaphore.signal()
        }
        semaphore.wait()
        guard let result = box.value else { throw NSError(domain: "OpenVaultAutoFill", code: -1) }
        return result
    }
}
