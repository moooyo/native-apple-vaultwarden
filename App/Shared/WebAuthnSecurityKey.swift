import AuthenticationServices
import Foundation
import Networking
import UIKit

/// Native login assertions for an explicitly configured and associated Vaultwarden host.
/// AuthenticationServices verifies the signed webcredentials entitlement and the site's
/// apple-app-site-association; the app cannot substitute a browser origin.
@MainActor
enum WebAuthnSecurityKey {
    private static var activeRequest: SecurityKeyAssertionRequest?

    static func isAvailable(for environment: ServerEnvironment) -> Bool {
        guard let host = try? WebAuthnSecondFactorChallenge.relyingPartyIdentifier(for: environment),
              let hosts = Bundle.main.object(forInfoDictionaryKey: "OpenVaultWebAuthnRelyingParties") as? [String] else {
            return false
        }
        // AuthenticationServices checks the signed association before granting an assertion.
        return hosts.contains(host)
    }

    static func authorize(challenge: WebAuthnSecondFactorChallenge, environment: ServerEnvironment) async throws -> String {
        try Task.checkCancellation()
        guard isAvailable(for: environment) else { throw WebAuthnSecondFactorError.unsupported }
        try challenge.validate(environment: environment)
        guard activeRequest == nil, let anchor = presentationAnchor else {
            throw WebAuthnSecondFactorError.authorizationFailed
        }

        let provider = ASAuthorizationSecurityKeyPublicKeyCredentialProvider(
            relyingPartyIdentifier: challenge.relyingPartyIdentifier
        )
        let request = provider.createCredentialAssertionRequest(challenge: challenge.challenge)
        let transports = ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.Transport.allSupported
        guard !transports.isEmpty else { throw WebAuthnSecondFactorError.unsupported }
        request.allowedCredentials = challenge.allowedCredentialIDs.map {
            ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor(credentialID: $0, transports: transports)
        }
        switch challenge.userVerification {
        case .discouraged: request.userVerificationPreference = .discouraged
        case .preferred: request.userVerificationPreference = .preferred
        case .required: request.userVerificationPreference = .required
        }

        let operation = SecurityKeyAssertionRequest(request: request, anchor: anchor)
        activeRequest = operation
        defer { activeRequest = nil }
        let assertion = try await operation.perform(timeout: .milliseconds(challenge.timeoutMilliseconds))
        try Task.checkCancellation()
        return try challenge.token(for: assertion, environment: environment)
    }

    private static var presentationAnchor: ASPresentationAnchor? {
        let keyWindows = UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .filter { $0.activationState == .foregroundActive }
            .compactMap(\.keyWindow)
        // Do not present over an arbitrary scene if multiple scenes are active.
        return keyWindows.count == 1 ? keyWindows.first : nil
    }
}

@MainActor
private final class SecurityKeyAssertionRequest: NSObject, ASAuthorizationControllerDelegate,
                                                ASAuthorizationControllerPresentationContextProviding {
    private let controller: ASAuthorizationController
    private let anchor: ASPresentationAnchor
    private var continuation: CheckedContinuation<WebAuthnSecondFactorAssertion, any Error>?

    init(request: ASAuthorizationSecurityKeyPublicKeyCredentialAssertionRequest, anchor: ASPresentationAnchor) {
        self.controller = ASAuthorizationController(authorizationRequests: [request])
        self.anchor = anchor
        super.init()
        controller.delegate = self
        controller.presentationContextProvider = self
    }

    func perform(timeout: Duration) async throws -> WebAuthnSecondFactorAssertion {
        let timeoutTask = Task { [weak self] in
            do { try await Task.sleep(for: timeout) } catch { return }
            self?.finish(.failure(WebAuthnSecondFactorError.authorizationFailed), cancelController: true)
        }
        defer { timeoutTask.cancel() }
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                guard !Task.isCancelled else {
                    continuation.resume(throwing: CancellationError())
                    return
                }
                self.continuation = continuation
                controller.performRequests()
            }
        } onCancel: {
            Task { @MainActor in self.finish(.failure(CancellationError()), cancelController: true) }
        }
    }

    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor { anchor }

    func authorizationController(controller: ASAuthorizationController,
                                 didCompleteWithAuthorization authorization: ASAuthorization) {
        guard let credential = authorization.credential as? ASAuthorizationSecurityKeyPublicKeyCredentialAssertion else {
            finish(.failure(WebAuthnSecondFactorError.invalidAssertion))
            return
        }
        finish(.success(.init(
            credentialID: credential.credentialID,
            authenticatorData: credential.rawAuthenticatorData,
            clientDataJSON: credential.rawClientDataJSON,
            signature: credential.signature,
            userHandle: credential.userID.isEmpty ? nil : credential.userID
        )))
    }

    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: any Error) {
        if (error as? ASAuthorizationError)?.code == .canceled {
            finish(.failure(CancellationError()))
        } else {
            finish(.failure(WebAuthnSecondFactorError.authorizationFailed))
        }
    }

    private func finish(_ result: Result<WebAuthnSecondFactorAssertion, any Error>, cancelController: Bool = false) {
        guard let continuation else { return }
        self.continuation = nil
        if cancelController { controller.cancel() }
        continuation.resume(with: result)
    }
}
