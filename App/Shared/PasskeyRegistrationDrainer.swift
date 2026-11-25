import CryptoCore
import Foundation
import os
import PasskeyHandoff
import VaultRepository

/// Main-app side of the extension registration queue. Import is replay-safe in the
/// repository; acknowledgement happens only after the encrypted local row/API-or-outbox path
/// succeeds, so a crash leaves either a retryable marker or an already-imported no-op.
actor PasskeyRegistrationDrainer {
    private static let log = Logger(subsystem: "dev.moooyo.tessera", category: "PasskeyHandoff")
    private let handoff: PasskeyRegistrationHandoff
    private let auth: AuthRepository
    private let vault: VaultRepository

    init(
        handoff: PasskeyRegistrationHandoff,
        auth: AuthRepository,
        vault: VaultRepository
    ) {
        self.handoff = handoff
        self.auth = auth
        self.vault = vault
    }

    @discardableResult
    func drain() async -> Bool {
        guard let lease = await auth.unlockedSessionLease() else { return false }
        let open: @Sendable (EncString) async throws -> Data = { [auth] envelope in
            try await auth.openPasskeyHandoff(envelope, for: lease)
        }
        let migration = PasskeyRegistrationHandoff.LegacyMigration(
            accountID: lease.accountID,
            validate: { [auth] in
                guard await auth.unlockedSessionLease() == lease else { throw PasskeyHandoffError.sessionChanged }
            },
            seal: { [auth] in try await auth.sealPasskeyHandoff($0, for: lease) },
            open: open
        )
        let pending: PendingPasskeyRegistrations
        do { pending = try await handoff.pendingRegistrations(migrating: migration) }
        catch { return false }
        if pending.requiresLegacyMigration {
            Self.log.notice("Legacy passkey handoff data remains queued for its owner or a Keychain retry.")
        }
        if pending.hasUnreadableEntries {
            Self.log.error("Unreadable passkey handoff entries remain queued for retry.")
        }

        var importedAny = false
        for entry in pending.registrations {
            guard !Task.isCancelled, await auth.unlockedSessionLease() == lease else { break }
            // A shared queue can contain other accounts' ciphertext. Leave failures intact;
            // only a successful authenticated open may proceed to import or acknowledgment.
            guard let registration = try? await entry.open(for: lease.accountID, using: open) else { continue }
            do {
                try await vault.importPasskeyRegistration(
                    registrationID: registration.id,
                    expectedAccountID: lease.accountID,
                    cipherID: registration.cipherID,
                    relyingPartyID: registration.relyingPartyID,
                    userName: registration.userName,
                    userDisplayName: registration.userDisplayName,
                    userHandle: registration.userHandle,
                    credentialID: registration.credentialID,
                    privateKeyPKCS8: registration.privateKeyPKCS8,
                    creationDate: registration.creationDate,
                    expectedSession: lease
                )
            } catch { continue }
            importedAny = true
            do { try await handoff.acknowledge(id: registration.id) }
            catch {
                Self.log.notice("Passkey handoff cleanup will retry after durable import.")
            }
        }
        return importedAny
    }
}
