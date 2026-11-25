import AuthenticationServices
import Foundation
import Networking
#if os(macOS)
import AppKit
#elseif os(iOS)
import UIKit
#endif

/// Native registration for the same explicit webcredentials policy as second-factor login.
/// AuthenticationServices constructs the client data; no browser origin is injected.
@MainActor
final class WebAuthnSecurityKeyRegistration: NSObject, ASAuthorizationControllerDelegate,
                                              ASAuthorizationControllerPresentationContextProviding {
    private static var active: WebAuthnSecurityKeyRegistration?
    private let anchor: ASPresentationAnchor
    private let controller: ASAuthorizationController
    private var continuation: CheckedContinuation<TwoFactorSecurityKeyAttestation, any Error>?

    static func isAvailable(for environment: ServerEnvironment) -> Bool {
        (try? TwoFactorSecurityKeyRegistrationChallenge.relyingPartyIdentifier(for: environment)) != nil &&
            WebAuthnSecurityKey.isAvailable(for: environment)
    }

    static func authorize(_ challenge: TwoFactorSecurityKeyRegistrationChallenge, environment: ServerEnvironment) async throws
        -> TwoFactorSecurityKeyAttestation {
        try Task.checkCancellation()
        guard isAvailable(for: environment),
              try TwoFactorSecurityKeyRegistrationChallenge.relyingPartyIdentifier(for: environment) == challenge.relyingPartyIdentifier else {
            throw WebAuthnSecondFactorError.unsupported
        }
        guard active == nil, let anchor = presentationAnchor else { throw WebAuthnSecondFactorError.authorizationFailed }
        let provider = ASAuthorizationSecurityKeyPublicKeyCredentialProvider(relyingPartyIdentifier: challenge.relyingPartyIdentifier)
        let request = provider.createCredentialRegistrationRequest(challenge: challenge.challenge, displayName: challenge.displayName,
                                                                  name: challenge.userName, userID: challenge.userID)
        request.credentialParameters = [ASAuthorizationPublicKeyCredentialParameters(algorithm: .ES256)]
        request.attestationPreference = .none
        request.residentKeyPreference = .discouraged
        request.userVerificationPreference = .discouraged
        let transports = ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.Transport.allSupported
        guard !transports.isEmpty else { throw WebAuthnSecondFactorError.unsupported }
        request.excludedCredentials = challenge.excludedCredentialIDs.map {
            ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor(credentialID: $0, transports: transports)
        }

        let registration = WebAuthnSecurityKeyRegistration(request: request, anchor: anchor)
        active = registration
        defer { active = nil }
        return try await registration.perform(timeout: .milliseconds(challenge.timeoutMilliseconds))
    }

    private static var presentationAnchor: ASPresentationAnchor? {
        #if os(macOS)
        NSApplication.shared.keyWindow
        #elseif os(iOS)
        let keyWindows = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
            .filter { $0.activationState == .foregroundActive }.compactMap(\.keyWindow)
        return keyWindows.count == 1 ? keyWindows.first : nil
        #endif
    }

    private init(request: ASAuthorizationSecurityKeyPublicKeyCredentialRegistrationRequest, anchor: ASPresentationAnchor) {
        controller = ASAuthorizationController(authorizationRequests: [request])
        self.anchor = anchor
        super.init()
        controller.delegate = self
        controller.presentationContextProvider = self
    }

    private func perform(timeout: Duration) async throws -> TwoFactorSecurityKeyAttestation {
        let deadline = Task { [weak self] in
            do { try await Task.sleep(for: timeout) } catch { return }
            self?.finish(.failure(WebAuthnSecondFactorError.authorizationFailed), cancel: true)
        }
        defer { deadline.cancel() }
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                guard !Task.isCancelled else { continuation.resume(throwing: CancellationError()); return }
                self.continuation = continuation
                controller.performRequests()
            }
        } onCancel: {
            Task { @MainActor in self.finish(.failure(CancellationError()), cancel: true) }
        }
    }

    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor { anchor }

    func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        guard controller === self.controller,
              let key = authorization.credential as? ASAuthorizationSecurityKeyPublicKeyCredentialRegistration,
              let object = key.rawAttestationObject else {
            finish(.failure(WebAuthnSecondFactorError.invalidAssertion))
            return
        }
        finish(.success(.init(credentialID: key.credentialID, clientDataJSON: key.rawClientDataJSON, attestationObject: object)))
    }

    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: any Error) {
        guard controller === self.controller else { return }
        if (error as? ASAuthorizationError)?.code == .canceled { finish(.failure(CancellationError())) }
        else { finish(.failure(WebAuthnSecondFactorError.authorizationFailed)) }
    }

    private func finish(_ result: Result<TwoFactorSecurityKeyAttestation, any Error>, cancel: Bool = false) {
        guard let continuation else { return }
        self.continuation = nil
        if cancel { controller.cancel() }
        continuation.resume(with: result)
    }
}
