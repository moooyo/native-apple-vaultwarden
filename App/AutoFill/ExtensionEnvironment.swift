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
import os
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
    private static let handoffLog = Logger(subsystem: "dev.moooyo.tessera", category: "PasskeyHandoff")
    private var storedReader: VaultReader?
    private let keyVault: KeyVault
    private let keychain: KeychainBridge
    private let container: URL?
    private let ownerGate: AutoFillAccessGate?
    private let passkeyHandoff: PasskeyRegistrationHandoff?

    /// Reason string shown in the biometric prompt.
    private let unlockReason = "使用 OpenVault 解锁并安全填充凭据"

    init() {
        let keychain = KeychainBridge(accessGroup: AppShared.keychainAccessGroup,
                                      service: "dev.moooyo.tessera")
        self.keychain = keychain
        self.keyVault = KeyVault()
        let container = FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: AppShared.appGroupID)
        self.container = container
        self.ownerGate = container.map { AutoFillAccessGate(url: $0.appendingPathComponent("autofill-owner")) }
        self.passkeyHandoff = container.map {
            PasskeyRegistrationHandoff(
                directoryURL: $0.appendingPathComponent("passkey-handoff", isDirectory: true),
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
        guard let container, let ownerGate else { throw ExtensionEnvironmentError.unavailable }
        do {
            let reader = VaultReader(
                store: try ExtensionEnvironment.makeStore(container: container),
                keyVault: keyVault,
                keychain: keychain,
                activePermit: ownerGate
            )
            storedReader = reader
            return reader
        } catch {
            // The provider can be enabled before the app has seeded the shared database.
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

    /// The App Group receives an opaque marker and the Keychain receives only ciphertext.
    /// Do not complete the website registration until the queue has committed the marker.
    func stagePasskeyRegistration(
        cipherID: String?,
        rpId: String,
        userName: String,
        userHandle: Data,
        credentialID: Data,
        privateKeyPKCS8: Data,
        for lease: VaultReader.SessionLease
    ) async throws {
        guard let passkeyHandoff, let ownerGate else { throw PasskeyHandoffError.storageUnavailable }
        let reader = try vaultReader()
        let registration = StagedPasskeyRegistration(
            accountID: lease.accountID,
            cipherID: cipherID,
            relyingPartyID: rpId,
            userName: userName,
            userDisplayName: userName,
            userHandle: userHandle,
            credentialID: credentialID,
            privateKeyPKCS8: privateKeyPKCS8
        )
        let envelope = try await registration.seal { try await reader.sealPasskeyHandoff($0, for: lease) }
        try await passkeyHandoff.stage(id: registration.id, envelope: envelope, sessionID: lease.sessionID,
                                       ownerGate: ownerGate) {
            try await reader.validateSessionLease(lease)
        }
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
        guard let registration = try await matchingPendingPasskey(
            in: passkeyHandoff, reader: reader, lease: lease, relyingPartyIdentifier: relyingPartyIdentifier,
            credentialIDs: [credentialID], userHandle: userHandle
        ) else { throw VaultReaderError.noPasskey }
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
        credentialIDs: Set<Data>,
        for lease: VaultReader.SessionLease
    ) async throws -> Bool {
        guard !credentialIDs.isEmpty else { return false }
        let reader = try vaultReader()
        guard let passkeyHandoff else { throw PasskeyHandoffError.storageUnavailable }
        try await reader.validateSessionLease(lease)
        let queueError: Error?
        do {
            // Import makes the DB row durable before removing the queue entry. Query the
            // queue first, so we cannot miss an excluded credential during that transition.
            if try await matchingPendingPasskey(
                in: passkeyHandoff, reader: reader, lease: lease, relyingPartyIdentifier: relyingPartyIdentifier,
                credentialIDs: credentialIDs, userHandle: nil
            ) != nil { return true }
            queueError = nil
        } catch { queueError = error }
        let candidates = try await reader.credentialCandidates(
            kind: .passkey,
            relyingPartyIdentifier: relyingPartyIdentifier,
            allowedCredentialIDs: credentialIDs,
            limit: 1
        )
        try await reader.validateSessionLease(lease)
        if !candidates.isEmpty { return true }
        if let queueError { throw queueError }
        return false
    }

    private func matchingPendingPasskey(
        in handoff: PasskeyRegistrationHandoff,
        reader: VaultReader,
        lease: VaultReader.SessionLease,
        relyingPartyIdentifier: String,
        credentialIDs: Set<Data>,
        userHandle: Data?
    ) async throws -> StagedPasskeyRegistration? {
        let expectedRP = Self.normalizedRP(relyingPartyIdentifier)
        let pending = try await handoff.pendingRegistrations()
        for entry in pending.registrations {
            try Task.checkCancellation()
            // A shared queue can contain ciphertext for a different account. It must stay
            // queued for its owner; a failed open never falls back to unwrapped bytes.
            guard let registration = try? await entry.open(for: lease.accountID, using: {
                try await reader.openPasskeyHandoff($0, for: lease)
            }), Self.normalizedRP(registration.relyingPartyID) == expectedRP,
               credentialIDs.contains(registration.credentialID),
               userHandle == nil || registration.userHandle == userHandle else { continue }
            try await reader.validateSessionLease(lease)
            return registration
        }
        try await reader.validateSessionLease(lease)
        if pending.requiresLegacyMigration {
            Self.handoffLog.notice("Legacy passkey handoff data must be migrated by the unlocked app.")
            throw PasskeyHandoffError.legacyMigrationPending
        }
        // An unavailable encrypted item cannot be safely treated as a negative match.
        if pending.hasUnreadableEntries { throw PasskeyHandoffError.storageUnavailable }
        return nil
    }

    private static func normalizedRP(_ value: String) -> String {
        var result = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        while result.hasSuffix(".") { result.removeLast() }
        return result
    }

    // MARK: - Builders

    private static func makeStore(container: URL) throws -> VaultStore {
        let url = container.appendingPathComponent("tessera-vault.sqlite")
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
