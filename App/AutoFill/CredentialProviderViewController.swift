// Xcode-only target. Not part of the SPM build.
//
// CredentialProviderViewController — the AutoFill credential-provider extension principal
// class (design spec §5.7 / blueprint §F).
//
// THE 120MB RED LINE: this target links ONLY the least-privilege read stack —
// VaultReader, KeychainBridge, VaultModels, Fido2, DesignSystem, AppShared (+ their
// transitive CryptoCore / KeyVault / VaultStore / lightweight Generators). It does NOT link
// Networking, SyncEngine, VaultRepository, UIShared, or any UI-* package. The credential
// identities the picker shows are written by the MAIN APP after each sync (via
// `ASCredentialIdentityStore`);
// the extension only reads a bounded set of display metadata from the local SQLCipher cache;
// credential secrets are decrypted only for the ONE selected item.
//
// Lifecycle contract:
//   * provideCredentialWithoutUserInteraction(for:) — if the vault is locked, FAIL FAST with
//     `ASExtensionError.userInteractionRequired` (NEVER block on biometrics here).
//   * prepareInterfaceToProvideCredential(for:) — biometric unlock → decrypt the one item →
//     completeRequest / completeAssertionRequest.
//   * prepareCredentialList(for:) — show the picker (identities come from the system store).
//   * prepareInterface(forPasskeyRegistration:) — Fido2 register → completeRegistrationRequest.
//   * prepareInterfaceForExtensionConfiguration() — onboarding/config UI.

import Foundation
import AuthenticationServices
import SwiftUI
import VaultReader
import KeychainBridge
import KeyVault
import VaultStore
import VaultModels
import Fido2
import DesignSystem
import AppShared

final class CredentialProviderViewController: ASCredentialProviderViewController {

    private struct PasskeyListRequest: Sendable {
        let relyingPartyIdentifier: String
        let clientDataHash: Data
        let allowedCredentials: Set<Data>
    }

    private enum CredentialListMode: Sendable {
        case password
        case oneTimeCode
        case passkey(PasskeyListRequest)
    }

    /// The extension's minimal vault graph (VaultReader over the shared App Group store).
    private let environment = ExtensionEnvironment()

    // MARK: - Password: without user interaction (fast path)

    /// Called when the system wants a credential with NO UI. If the vault is locked we MUST
    /// fail immediately with `.userInteractionRequired` — never prompt biometrics here.
    override func provideCredentialWithoutUserInteraction(for credentialRequest: ASCredentialRequest) {
        Task {
            guard await environment.isUnlocked else {
                cancel(.userInteractionRequired)
                return
            }
            let recordIdentifier = credentialRequest.credentialIdentity.recordIdentifier ?? ""
            await fulfill(credentialRequest, recordIdentifier: recordIdentifier)
        }
    }

    // MARK: - Password: with UI (unlock then vend)

    /// Called after `provideCredentialWithoutUserInteraction` asked for interaction. Drives
    /// the biometric unlock, decrypts the one selected credential, and completes the request.
    override func prepareInterfaceToProvideCredential(for credentialRequest: ASCredentialRequest) {
        let recordIdentifier = credentialRequest.credentialIdentity.recordIdentifier ?? ""
        presentUnlock { [weak self] in
            guard let self else { return }
            do {
                try await self.environment.unlock()
            } catch {
                self.cancel(.failed)
                return
            }

            await self.fulfill(credentialRequest, recordIdentifier: recordIdentifier)
        }
    }

    // MARK: - Credential list (picker)

    /// Show the picker for the given service identifiers. The identities themselves were
    /// populated by the main app into `ASCredentialIdentityStore`; here we render a lightweight
    /// list backed by the local store so the user can pick + unlock in one place.
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        presentCredentialList(serviceIdentifiers: serviceIdentifiers, mode: .password)
    }

    /// Passkey-aware variant (iOS 17+/macOS 14+): a request for passkeys + passwords.
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier],
                                        requestParameters: ASPasskeyCredentialRequestParameters) {
        presentCredentialList(
            serviceIdentifiers: serviceIdentifiers,
            mode: .passkey(
                PasskeyListRequest(
                    relyingPartyIdentifier: requestParameters.relyingPartyIdentifier,
                    clientDataHash: requestParameters.clientDataHash,
                    allowedCredentials: Set(requestParameters.allowedCredentials)
                )
            )
        )
    }

    /// OTP-specific list entry point (iOS 18+/macOS 15+). If a fallback picker selection
    /// is returned, vend a one-time code rather than treating the record as a password.
    override func prepareOneTimeCodeCredentialList(
        for serviceIdentifiers: [ASCredentialServiceIdentifier]
    ) {
        presentCredentialList(
            serviceIdentifiers: serviceIdentifiers,
            mode: .oneTimeCode
        )
    }

    // MARK: - Passkey registration

    /// Register a new passkey: generate a fresh credential key via Fido2, build the attestation
    /// object, and complete the registration. The new credential is handed to the main app to
    /// persist (write-back path); see `ExtensionEnvironment.stagePasskeyRegistration`.
    override func prepareInterface(forPasskeyRegistration registrationRequest: ASCredentialRequest) {
        guard let request = registrationRequest as? ASPasskeyCredentialRequest,
              let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity else {
            cancel(.failed)
            return
        }
        guard request.supportedAlgorithms.contains(.ES256) else {
            cancel(.failed)
            return
        }

        presentUnlock { [weak self] in
            guard let self else { return }
            do { try await self.environment.unlock() } catch { self.cancel(.failed); return }

            do {
                let reader = try await self.environment.vaultReader()
                let excluded = Set(
                    request.excludedCredentials?.map(\.credentialID) ?? []
                )
                guard try await self.environment.containsExcludedPasskey(
                    relyingPartyIdentifier: identity.relyingPartyIdentifier,
                    credentialIDs: excluded
                ) == false else {
                    self.cancel(.matchedExcludedCredential)
                    return
                }
                let cipherID: String?
                if let recordIdentifier = identity.recordIdentifier {
                    // A present identifier must validate full v3 provenance. Treating an
                    // invalid/stale A identity as nil would silently create the credential
                    // under the currently active B account.
                    cipherID = try await reader.cipherID(
                        forRecordIdentifier: recordIdentifier,
                        kind: .passkey,
                        serviceIdentifier: identity.relyingPartyIdentifier,
                        user: identity.userName
                    )
                } else {
                    cipherID = nil
                }
                let credentialID = try Self.newCredentialID()
                let (attestationObject, credentialKey) = try Fido2Authenticator.register(
                    rpId: identity.relyingPartyIdentifier,
                    clientDataHash: request.clientDataHash,
                    credentialId: credentialID,
                    userVerified: true
                )
                // Do not complete the WebAuthn registration until the private key and its
                // non-secret discovery marker are both durably staged for the main app.
                _ = try await self.environment.stagePasskeyRegistration(
                    cipherID: cipherID,
                    rpId: identity.relyingPartyIdentifier,
                    userName: identity.userName,
                    userHandle: identity.userHandle,
                    credentialID: credentialID,
                    privateKeyPKCS8: credentialKey.exportPKCS8()
                )

                let registration = ASPasskeyRegistrationCredential(
                    relyingParty: identity.relyingPartyIdentifier,
                    clientDataHash: request.clientDataHash,
                    credentialID: credentialID,
                    attestationObject: attestationObject
                )
                await self.complete(passkeyRegistration: registration)
            } catch {
                self.cancel(.failed)
            }
        }
    }

    // MARK: - Configuration UI

    /// Onboarding / configuration shown when the user enables the provider in Settings.
    override func prepareInterfaceForExtensionConfiguration() {
        let view = ConfigurationView {
            self.extensionContext.completeExtensionConfigurationRequest()
        }
        embed(view)
    }

    // MARK: - Passkey assertion helper

    /// Fulfill the concrete request kind. AuthenticationServices uses distinct completion
    /// APIs for password, passkey assertion, and one-time-code credentials.
    private func fulfill(
        _ request: ASCredentialRequest,
        recordIdentifier: String
    ) async {
        switch request.type {
        case .password:
            do {
                guard let identity = request.credentialIdentity
                    as? ASPasswordCredentialIdentity else {
                    cancel(.credentialIdentityNotFound)
                    return
                }
                let reader = try await environment.vaultReader()
                let (user, password) = try await reader.passwordCredential(
                    forRecordIdentifier: recordIdentifier,
                    serviceIdentifier: identity.serviceIdentifier.identifier,
                    user: identity.user
                )
                await complete(
                    passwordCredential: ASPasswordCredential(user: user, password: password)
                )
            } catch {
                cancel(.credentialIdentityNotFound)
            }
        case .passkeyAssertion:
            guard let assertionRequest = request as? ASPasskeyCredentialRequest else {
                cancel(.credentialIdentityNotFound)
                return
            }
            await completePasskeyAssertion(
                for: assertionRequest,
                recordIdentifier: recordIdentifier
            )
        case .oneTimeCode:
            do {
                guard let identity = request.credentialIdentity
                    as? ASOneTimeCodeCredentialIdentity else {
                    cancel(.credentialIdentityNotFound)
                    return
                }
                let reader = try await environment.vaultReader()
                let code = try await reader.oneTimeCode(
                    forRecordIdentifier: recordIdentifier,
                    serviceIdentifier: identity.serviceIdentifier.identifier,
                    user: identity.label
                )
                await complete(oneTimeCodeCredential: ASOneTimeCodeCredential(code: code))
            } catch {
                cancel(.credentialIdentityNotFound)
            }
        case .passkeyRegistration:
            // Registration is handled by prepareInterface(forPasskeyRegistration:).
            cancel(.failed)
        @unknown default:
            cancel(.failed)
        }
    }

    private func completePasskeyAssertion(
        for request: ASPasskeyCredentialRequest,
        recordIdentifier: String
    ) async {
        guard let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity else {
            cancel(.credentialIdentityNotFound)
            return
        }
        let databaseAssertion: (authenticatorData: Data, signature: Data)?
        if recordIdentifier.isEmpty {
            databaseAssertion = nil
        } else {
            let reader = try? await environment.vaultReader()
            databaseAssertion = try? await reader?.passkeyAssertion(
                forRecordIdentifier: recordIdentifier,
                serviceIdentifier: identity.relyingPartyIdentifier,
                user: identity.userName,
                credentialID: identity.credentialID,
                userHandle: identity.userHandle,
                clientDataHash: request.clientDataHash,
                userVerified: true
            )
        }
        let assertion: (authenticatorData: Data, signature: Data)?
        if let databaseAssertion {
            assertion = databaseAssertion
        } else {
            assertion = try? await environment.stagedPasskeyAssertion(
                relyingPartyIdentifier: identity.relyingPartyIdentifier,
                credentialID: identity.credentialID,
                userHandle: identity.userHandle,
                clientDataHash: request.clientDataHash,
                userVerified: true
            )
        }
        guard let assertion else {
            cancel(.credentialIdentityNotFound)
            return
        }
        do {
            let credential = ASPasskeyAssertionCredential(
                userHandle: identity.userHandle,
                relyingParty: identity.relyingPartyIdentifier,
                signature: assertion.signature,
                clientDataHash: request.clientDataHash,
                authenticatorData: assertion.authenticatorData,
                credentialID: identity.credentialID
            )
            await complete(passkeyAssertion: credential)
        }
    }

    private func completeOneTimeCode(recordID: String) async {
        do {
            let reader = try await environment.vaultReader()
            let code = try await reader.oneTimeCode(for: recordID)
            await complete(oneTimeCodeCredential: ASOneTimeCodeCredential(code: code))
        } catch {
            cancel(.credentialIdentityNotFound)
        }
    }

    // MARK: - UI embedding + completion plumbing

    /// Present the SwiftUI unlock screen; `onUnlock` runs after the user taps "Unlock".
    private func presentUnlock(onUnlock: @escaping () async -> Void) {
        let view = ExtensionUnlockView(
            onUnlock: { Task { await onUnlock() } },
            onCancel: { [weak self] in self?.cancel(.userCanceled) }
        )
        embed(view)
    }

    private func presentCredentialList(
        serviceIdentifiers: [ASCredentialServiceIdentifier],
        mode: CredentialListMode
    ) {
        let services = serviceIdentifiers.map(\.identifier)
        let view = ExtensionCredentialListView(
            serviceIdentifiers: services,
            loadCandidates: { [weak self] in
                guard let self else { return [] }
                try await self.environment.unlockIfNeeded()
                return try await self.credentialCandidates(
                    for: mode,
                    serviceIdentifiers: services
                )
            },
            onSelect: { [weak self] candidate in
                guard let self else { return }
                Task {
                    do {
                        try await self.environment.unlockIfNeeded()
                        await self.fulfill(candidate, for: mode)
                    } catch {
                        self.cancel(.failed)
                    }
                }
            },
            onCancel: { [weak self] in self?.cancel(.userCanceled) }
        )
        embed(view)
    }

    private func credentialCandidates(
        for mode: CredentialListMode,
        serviceIdentifiers: [String]
    ) async throws -> [CredentialCandidate] {
        let reader = try await environment.vaultReader()
        switch mode {
        case .password:
            return try await reader.credentialCandidates(
                kind: .password,
                serviceIdentifiers: serviceIdentifiers
            )
        case .oneTimeCode:
            return try await reader.credentialCandidates(
                kind: .oneTimeCode,
                serviceIdentifiers: serviceIdentifiers
            )
        case .passkey(let request):
            let passkeys = try await reader.credentialCandidates(
                kind: .passkey,
                serviceIdentifiers: serviceIdentifiers,
                relyingPartyIdentifier: request.relyingPartyIdentifier
            ).filter {
                guard let credentialID = $0.credentialID else { return false }
                return request.allowedCredentials.isEmpty
                    || request.allowedCredentials.contains(credentialID)
            }
            let passwords = try await reader.credentialCandidates(
                kind: .password,
                serviceIdentifiers: serviceIdentifiers
            )
            return Array((passkeys + passwords).prefix(50))
        }
    }

    private func fulfill(
        _ candidate: CredentialCandidate,
        for mode: CredentialListMode
    ) async {
        switch (candidate.kind, mode) {
        case (.password, .password), (.password, .passkey):
            do {
                let reader = try await environment.vaultReader()
                let (user, password) = try await reader.passwordCredential(for: candidate)
                await complete(
                    passwordCredential: ASPasswordCredential(user: user, password: password)
                )
            } catch {
                cancel(.credentialIdentityNotFound)
            }
        case (.oneTimeCode, .oneTimeCode):
            do {
                let reader = try await environment.vaultReader()
                let code = try await reader.oneTimeCode(for: candidate)
                await complete(oneTimeCodeCredential: ASOneTimeCodeCredential(code: code))
            } catch {
                cancel(.credentialIdentityNotFound)
            }
        case (.passkey, .passkey(let request)):
            await completePasskeyAssertion(candidate: candidate, request: request)
        default:
            cancel(.credentialIdentityNotFound)
        }
    }

    private func completePasskeyAssertion(
        candidate: CredentialCandidate,
        request: PasskeyListRequest
    ) async {
        guard let credentialID = candidate.credentialID,
              let userHandle = candidate.userHandle,
              request.allowedCredentials.isEmpty
                || request.allowedCredentials.contains(credentialID) else {
            cancel(.credentialIdentityNotFound)
            return
        }
        do {
            let reader = try await environment.vaultReader()
            let (authenticatorData, signature) = try await reader.passkeyAssertion(
                for: candidate,
                relyingPartyIdentifier: request.relyingPartyIdentifier,
                clientDataHash: request.clientDataHash,
                userVerified: true
            )
            await complete(
                passkeyAssertion: ASPasskeyAssertionCredential(
                    userHandle: userHandle,
                    relyingParty: request.relyingPartyIdentifier,
                    signature: signature,
                    clientDataHash: request.clientDataHash,
                    authenticatorData: authenticatorData,
                    credentialID: credentialID
                )
            )
        } catch {
            cancel(.credentialIdentityNotFound)
        }
    }

    private func embed<V: View>(_ view: V) {
        let host = UIHostingControllerCompat(rootView: view)
        addChildController(host)
    }

    @MainActor
    private func complete(passwordCredential: ASPasswordCredential) async {
        extensionContext.completeRequest(withSelectedCredential: passwordCredential)
    }

    @MainActor
    private func complete(oneTimeCodeCredential: ASOneTimeCodeCredential) async {
        await extensionContext.completeOneTimeCodeRequest(using: oneTimeCodeCredential)
    }

    @MainActor
    private func complete(passkeyAssertion: ASPasskeyAssertionCredential) async {
        await extensionContext.completeAssertionRequest(using: passkeyAssertion)
    }

    @MainActor
    private func complete(passkeyRegistration: ASPasskeyRegistrationCredential) async {
        // The async bridge returns the completion-handler's `expired` flag. That flag
        // describes cleanup time after the system captured the credential; it must never
        // be interpreted as registration failure or used to delete the staged private key.
        _ = await extensionContext.completeRegistrationRequest(using: passkeyRegistration)
    }

    private func cancel(_ code: ASExtensionError.Code) {
        let error = NSError(domain: ASExtensionErrorDomain, code: code.rawValue)
        extensionContext.cancelRequest(withError: error)
    }

    /// 16 random bytes for a fresh WebAuthn credential id.
    private static func newCredentialID() throws -> Data {
        var bytes = Data(count: 16)
        let status = bytes.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!)
        }
        guard status == errSecSuccess else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
        return bytes
    }
}
