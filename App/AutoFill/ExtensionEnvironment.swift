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
import Security
import VaultReader
import VaultStore
import KeyVault
import KeychainBridge
import AppShared
import PasskeyHandoff
import Fido2

private enum ExtensionEnvironmentError: Error {
    case unavailable
}

actor ExtensionEnvironment {
    private var storedReader: VaultReader?
    private let keyVault: KeyVault
    private let keychain: KeychainBridge
    private let passkeyHandoff: PasskeyRegistrationHandoff?

    /// Reason string shown in the biometric prompt.
    private let unlockReason = "使用 OpenVault 解锁并安全填充凭据"

    init() {
        let keychain = KeychainBridge(accessGroup: AppShared.keychainAccessGroup,
                                      service: "dev.moooyo.tessera")
        let keyVault = KeyVault()
        self.keychain = keychain
        self.keyVault = keyVault
        if let store = try? ExtensionEnvironment.makeStore() {
            self.storedReader = VaultReader(
                store: store,
                keyVault: keyVault,
                keychain: keychain
            )
        } else {
            // The user may enable the provider before opening the app, or entitlements
            // may be misconfigured. Keep the extension alive so it can show configuration
            // UI / a recoverable error instead of crashing during controller construction.
            self.storedReader = nil
        }
        self.passkeyHandoff = FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: AppShared.appGroupID)
            .map {
                PasskeyRegistrationHandoff(
                    directoryURL: $0.appendingPathComponent(
                        "passkey-handoff",
                        isDirectory: true
                    ),
                    keychain: keychain
                )
            }
    }

    /// Whether the vault key is already in memory (it won't be on a cold extension launch — the
    /// extension is a separate process from the app, so the fast path almost always needs unlock).
    var isUnlocked: Bool {
        get async {
            guard let storedReader, await keyVault.isUnlocked else { return false }
            return (try? await storedReader.currentSessionLease()) != nil
        }
    }

    func vaultReader() throws -> VaultReader {
        if let storedReader { return storedReader }
        do {
            let reader = VaultReader(
                store: try ExtensionEnvironment.makeStore(),
                keyVault: keyVault,
                keychain: keychain
            )
            storedReader = reader
            return reader
        } catch {
            throw ExtensionEnvironmentError.unavailable
        }
    }

    /// Biometric unlock for this process: unwrap the SE-wrapped UserKey from the shared Keychain.
    func unlock() async throws {
        let reader = try vaultReader()
        try await reader.unlockWithBiometrics(reason: unlockReason)
    }

    /// Unlock once per extension process. The manual picker loads metadata immediately after
    /// authentication and must not display a second biometric sheet when the user taps a row.
    func unlockIfNeeded() async throws {
        guard !(await isUnlocked) else { return }
        try await unlock()
    }

    /// Durably stage a newly registered passkey. PKCS#8 bytes live only in the shared
    /// Keychain; the App Group receives a UUID-only atomic marker. Failure is propagated so
    /// the system registration can be cancelled instead of returning a credential we lost.
    func stagePasskeyRegistration(
        cipherID: String?,
        rpId: String,
        userName: String,
        userHandle: Data,
        credentialID: Data,
        privateKeyPKCS8: Data
    ) async throws -> String {
        guard let passkeyHandoff else { throw PasskeyHandoffError.storageUnavailable }
        let reader = try vaultReader()
        let lease = try await reader.currentSessionLease()
        let registration = try await passkeyHandoff.stage(
            expectedAccountID: lease.accountID,
            expectedSessionID: lease.sessionID,
            cipherID: cipherID,
            relyingPartyID: rpId,
            userName: userName,
            userDisplayName: userName,
            userHandle: userHandle,
            credentialID: credentialID,
            privateKeyPKCS8: privateKeyPKCS8
        )
        // Handoff.stage's final pre-rename nonce check authorizes the ready rename. Once that
        // marker is visible, ownership belongs to the main app's finalize/quarantine path;
        // a later lock must not make the extension roll back its only private key.
        return registration.id
    }

    /// Immediate assertion fallback for a registration that the system has captured but the
    /// main app has not imported into SQLCipher yet.
    func stagedPasskeyAssertion(
        relyingPartyIdentifier: String,
        credentialID: Data,
        userHandle: Data,
        clientDataHash: Data,
        userVerified: Bool
    ) async throws -> (authenticatorData: Data, signature: Data) {
        guard let passkeyHandoff else { throw VaultReaderError.noPasskey }
        let reader = try vaultReader()
        let lease = try await reader.currentSessionLease()
        let expectedRP = Self.normalizedRP(relyingPartyIdentifier)
        let registrations = try await passkeyHandoff.pendingRegistrations()
        guard let registration = registrations.first(where: {
            $0.accountID == lease.accountID
                && Self.normalizedRP($0.relyingPartyID) == expectedRP
                && $0.credentialID == credentialID
                && $0.userHandle == userHandle
        }) else {
            throw VaultReaderError.noPasskey
        }
        let key: CredentialKey
        do { key = try CredentialKey(pkcs8: registration.privateKeyPKCS8) }
        catch { throw VaultReaderError.malformed }
        let result: (authenticatorData: Data, signature: Data)
        do {
            result = try Fido2Authenticator.assert(
                rpId: relyingPartyIdentifier,
                clientDataHash: clientDataHash,
                signCount: 0,
                userVerified: userVerified,
                key: key
            )
        } catch {
            throw VaultReaderError.malformed
        }
        try await reader.validateSessionLease(lease)
        return result
    }

    func containsExcludedPasskey(
        relyingPartyIdentifier: String,
        credentialIDs: Set<Data>
    ) async throws -> Bool {
        guard !credentialIDs.isEmpty else { return false }
        let reader = try vaultReader()
        let lease = try await reader.currentSessionLease()
        let candidates = try await reader.credentialCandidates(
            kind: .passkey,
            relyingPartyIdentifier: relyingPartyIdentifier,
            limit: 50
        )
        if candidates.contains(where: {
            $0.credentialID.map(credentialIDs.contains) == true
        }) { return true }
        if let passkeyHandoff {
            let rp = Self.normalizedRP(relyingPartyIdentifier)
            let pending = try await passkeyHandoff.pendingRegistrations()
            if pending.contains(where: {
                $0.accountID == lease.accountID
                    && Self.normalizedRP($0.relyingPartyID) == rp
                    && credentialIDs.contains($0.credentialID)
            }) { return true }
        }
        try await reader.validateSessionLease(lease)
        return false
    }

    private static func normalizedRP(_ value: String) -> String {
        var result = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        while result.hasSuffix(".") { result.removeLast() }
        return result
    }

    // MARK: - Builders

    private static func databaseURL() throws -> URL {
        let fm = FileManager.default
        guard let container = fm.containerURL(
            forSecurityApplicationGroupIdentifier: AppShared.appGroupID
        ) else {
            throw ExtensionEnvironmentError.unavailable
        }
        return container.appendingPathComponent("tessera-vault.sqlite")
    }

    private static func makeStore() throws -> VaultStore {
        let url = try databaseURL()
        let passphrase = try loadPassphrase()
        return try VaultStore(databaseURL: url, passphrase: passphrase)
    }

    /// Load the random DB passphrase the app wrote to the shared Keychain. The extension never
    /// generates it — if it's absent the user must open the app once to seed the vault.
    private static func loadPassphrase() throws -> Data {
        let account = AppShared.KeychainAccount.databasePassphrase
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: AppShared.keychainAccessGroup,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let result = item as? Data, result.count == 32 else {
            throw NSError(domain: "TesseraAutoFill", code: -1,
                          userInfo: [NSLocalizedDescriptionKey:
                            "The shared vault database passphrase is missing or invalid."])
        }
        return result
    }
}
