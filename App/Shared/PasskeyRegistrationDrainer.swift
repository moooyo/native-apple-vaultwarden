import Foundation
import PasskeyHandoff
import VaultRepository

/// Main-app side of the extension registration queue. Import is replay-safe in the
/// repository; acknowledgement happens only after the encrypted local row/API-or-outbox path
/// succeeds, so a crash leaves either a retryable marker or an already-imported no-op.
actor PasskeyRegistrationDrainer {
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
        guard await auth.isUnlocked(),
              let activeAccountID = await auth.session?.accountID,
              let registrations = try? await handoff.pendingRegistrations() else {
            return false
        }
        let matching = registrations.filter { $0.accountID == activeAccountID }
        guard !matching.isEmpty else { return false }

        // Cold-restored sessions have no bearer yet. Refresh once before importing; if the
        // network is offline, repository writes still fall back to the durable outbox.
        _ = try? await auth.refresh()

        var importedAny = false
        for registration in matching {
            guard await auth.session?.accountID == activeAccountID,
                  await auth.isUnlocked() else { return importedAny }
            do {
                try await vault.importPasskeyRegistration(
                    registrationID: registration.id,
                    expectedAccountID: activeAccountID,
                    cipherID: registration.cipherID,
                    relyingPartyID: registration.relyingPartyID,
                    userName: registration.userName,
                    userDisplayName: registration.userDisplayName,
                    userHandle: registration.userHandle,
                    credentialID: registration.credentialID,
                    privateKeyPKCS8: registration.privateKeyPKCS8,
                    creationDate: registration.creationDate
                )
                try await handoff.acknowledge(id: registration.id)
                importedAny = true
            } catch {
                // Leave both marker and secret for a later unlock/network retry.
                continue
            }
        }
        return importedAny
    }
}
