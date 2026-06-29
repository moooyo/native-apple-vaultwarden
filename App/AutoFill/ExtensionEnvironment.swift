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
    private let unlockReason = "Unlock Tessera to fill your credential"

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

    /// Stage a newly-registered passkey for the main app to persist on its next sync.
    ///
    /// The extension cannot write to the network (no Networking link). We write the new
    /// credential to a small App Group hand-off file the app drains on launch/sync; this keeps
    /// the write-back path out of the extension's link graph while still making the passkey
    /// durable. Best-effort — AutoFill registration succeeds even if staging fails.
    func stagePasskeyRegistration(rpId: String, userHandle: Data, credentialID: Data,
                                  privateKeyPKCS8: Data) async {
        let record: [String: String] = [
            "rpId": rpId,
            "userHandle": userHandle.base64EncodedString(),
            "credentialID": credentialID.base64EncodedString(),
            "privateKeyPKCS8": privateKeyPKCS8.base64EncodedString(),
        ]
        guard let dir = ExtensionEnvironment.handoffDirectory() else { return }
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let url = dir.appendingPathComponent("\(UUID().uuidString).json")
        if let data = try? JSONSerialization.data(withJSONObject: record) {
            try? data.write(to: url, options: .completeFileProtection)
        }
    }

    // MARK: - Builders

    private static func handoffDirectory() -> URL? {
        FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: AppShared.appGroupID)?
            .appendingPathComponent("passkey-handoff", isDirectory: true)
    }

    private static func databaseURL() -> URL {
        let fm = FileManager.default
        let container = fm.containerURL(forSecurityApplicationGroupIdentifier: AppShared.appGroupID)
            ?? fm.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return container.appendingPathComponent("tessera-vault.sqlite")
    }

    private static func makeStore(keychain: KeychainBridge) -> VaultStore {
        let url = databaseURL()
        let passphrase = (try? loadPassphrase(keychain: keychain)) ?? Data(repeating: 0, count: 32)
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
        guard let result = box.value else { throw NSError(domain: "TesseraAutoFill", code: -1) }
        return result
    }
}
