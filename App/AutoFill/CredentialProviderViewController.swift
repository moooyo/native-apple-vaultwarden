// Xcode-only target. Not part of the SPM build.
//
// CredentialProviderViewController — the AutoFill credential-provider extension principal
// class (design spec §5.7 / blueprint §F).
//
// THE 120MB RED LINE: this target links ONLY the least-privilege read stack —
// VaultReader, KeychainBridge, VaultModels, Fido2, DesignSystem, AppShared (+ their
// transitive CryptoCore / KeyVault / VaultStore). It does NOT link Networking, SyncEngine,
// Generators, VaultRepository, UIShared, or any UI-* package. The credential identities the
// picker shows are written by the MAIN APP after each sync (via `ASCredentialIdentityStore`);
// the extension only reads the local SQLCipher cache in the App Group container and decrypts
// the ONE selected item.
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
            do {
                let recordID = credentialRequest.credentialIdentity.recordIdentifier ?? ""
                let (user, password) = try await environment.reader.passwordCredential(for: recordID)
                let credential = ASPasswordCredential(user: user, password: password)
                await complete(passwordCredential: credential)
            } catch {
                cancel(.userInteractionRequired)
            }
        }
    }

    // MARK: - Password: with UI (unlock then vend)

    /// Called after `provideCredentialWithoutUserInteraction` asked for interaction. Drives
    /// the biometric unlock, decrypts the one selected credential, and completes the request.
    override func prepareInterfaceToProvideCredential(for credentialRequest: ASCredentialRequest) {
        let recordID = credentialRequest.credentialIdentity.recordIdentifier ?? ""
        let isPasskey = (credentialRequest.type == .passkeyAssertion)

        presentUnlock { [weak self] in
            guard let self else { return }
            do {
                try await self.environment.unlock()
            } catch {
                self.cancel(.failed)
                return
            }

            if isPasskey, let assertionRequest = credentialRequest as? ASPasskeyCredentialRequest {
                await self.completePasskeyAssertion(for: assertionRequest, recordID: recordID)
            } else {
                do {
                    let (user, password) = try await self.environment.reader.passwordCredential(for: recordID)
                    await self.complete(passwordCredential: ASPasswordCredential(user: user, password: password))
                } catch {
                    self.cancel(.credentialIdentityNotFound)
                }
            }
        }
    }

    // MARK: - Credential list (picker)

    /// Show the picker for the given service identifiers. The identities themselves were
    /// populated by the main app into `ASCredentialIdentityStore`; here we render a lightweight
    /// list backed by the local store so the user can pick + unlock in one place.
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        presentCredentialList(serviceIdentifiers: serviceIdentifiers, passkeyRequest: nil)
    }

    /// Passkey-aware variant (iOS 17+/macOS 14+): a request for passkeys + passwords.
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier],
                                        requestParameters: ASPasskeyCredentialRequestParameters) {
        presentCredentialList(serviceIdentifiers: serviceIdentifiers, passkeyRequest: requestParameters)
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

        presentUnlock { [weak self] in
            guard let self else { return }
            do { try await self.environment.unlock() } catch { self.cancel(.failed); return }

            do {
                let credentialID = try Self.newCredentialID()
                let (attestationObject, credentialKey) = try Fido2Authenticator.register(
                    rpId: identity.relyingPartyIdentifier,
                    clientDataHash: request.clientDataHash,
                    credentialId: credentialID,
                    userVerified: true
                )
                // Registration completes only after durable write-back succeeds.
                try await self.environment.stagePasskeyRegistration(
                    rpId: identity.relyingPartyIdentifier,
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

    private func completePasskeyAssertion(for request: ASPasskeyCredentialRequest, recordID: String) async {
        guard let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity else {
            cancel(.credentialIdentityNotFound)
            return
        }
        do {
            let (authenticatorData, signature) = try await environment.reader.passkeyAssertion(
                recordID: recordID,
                rpId: identity.relyingPartyIdentifier,
                clientDataHash: request.clientDataHash,
                userVerified: true
            )
            let credential = ASPasskeyAssertionCredential(
                userHandle: identity.userHandle,
                relyingParty: identity.relyingPartyIdentifier,
                signature: signature,
                clientDataHash: request.clientDataHash,
                authenticatorData: authenticatorData,
                credentialID: identity.credentialID
            )
            await complete(passkeyAssertion: credential)
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

    private func presentCredentialList(serviceIdentifiers: [ASCredentialServiceIdentifier],
                                       passkeyRequest: ASPasskeyCredentialRequestParameters?) {
        let view = ExtensionCredentialListView(
            serviceIdentifiers: serviceIdentifiers.map(\.identifier),
            onSelect: { [weak self] recordID in
                guard let self else { return }
                Task {
                    do { try await self.environment.unlock() } catch { self.cancel(.failed); return }
                    do {
                        let (user, password) = try await self.environment.reader.passwordCredential(for: recordID)
                        await self.complete(passwordCredential: ASPasswordCredential(user: user, password: password))
                    } catch {
                        self.cancel(.credentialIdentityNotFound)
                    }
                }
            },
            onCancel: { [weak self] in self?.cancel(.userCanceled) }
        )
        embed(view)
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
    private func complete(passkeyAssertion: ASPasskeyAssertionCredential) async {
        await extensionContext.completeAssertionRequest(using: passkeyAssertion)
    }

    @MainActor
    private func complete(passkeyRegistration: ASPasskeyRegistrationCredential) async {
        await extensionContext.completeRegistrationRequest(using: passkeyRegistration)
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
