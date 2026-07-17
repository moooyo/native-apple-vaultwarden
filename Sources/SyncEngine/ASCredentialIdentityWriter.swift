import Foundation

// The real, system-backed `CredentialIdentityWriting` conformer. It is gated behind
// `canImport(AuthenticationServices)` so this file compiles on a host that has the
// framework headers, but it only RUNS inside a signed app/extension with the AutoFill
// credential-provider entitlement. The unit tests use an in-memory fake instead.
#if canImport(AuthenticationServices)
import AuthenticationServices
import AppShared

/// Maps `CredentialIdentity` values onto the system `ASCredentialIdentityStore`.
///
/// This is a thin wrapper: each `SyncEngine` identity becomes an
/// `ASPasswordCredentialIdentity` / `ASPasskeyCredentialIdentity` /
/// `ASOneTimeCodeCredentialIdentity`, keyed by `recordIdentifier == recordID` so the
/// extension can map the user's pick back to a single cipher.
///
/// Availability: `ASOneTimeCodeCredentialIdentity` and the passkey identities require
/// iOS 18 / macOS 15+; OTP/passkey entries are added only where the API is present.
public struct ASCredentialIdentityWriter: CredentialIdentityWriting {
    /// The system store is a non-Sendable singleton; reference `.shared` inside each
    /// method rather than storing it, so this conformer stays `Sendable`.
    public init() {}

    public func isEnabled() async -> Bool {
        await withCheckedContinuation { cont in
            ASCredentialIdentityStore.shared.getState { state in
                cont.resume(returning: state.isEnabled)
            }
        }
    }

    public func supportsIncremental() async -> Bool {
        await withCheckedContinuation { cont in
            ASCredentialIdentityStore.shared.getState { state in
                cont.resume(returning: state.supportsIncrementalUpdates)
            }
        }
    }

    public func replaceAll(_ identities: [CredentialIdentity]) async {
        let systemIdentities = identities.compactMap(Self.systemIdentity)
        try? await ASCredentialIdentityStore.shared.replaceCredentialIdentities(systemIdentities)
    }

    public func incremental(add: [CredentialIdentity], remove: [CredentialIdentity]) async {
        let removals = remove.compactMap(Self.systemIdentity)
        if !removals.isEmpty {
            try? await ASCredentialIdentityStore.shared.removeCredentialIdentities(removals)
        }
        let additions = add.compactMap(Self.systemIdentity)
        if !additions.isEmpty {
            try? await ASCredentialIdentityStore.shared.saveCredentialIdentities(additions)
        }
    }

    // MARK: - Mapping

    private static func serviceIdentifier(_ id: CredentialIdentity) -> ASCredentialServiceIdentifier {
        ASCredentialServiceIdentifier(identifier: id.serviceIdentifier, type: .URL)
    }

    /// Build the concrete AuthenticationServices identity. Passkeys without their two
    /// required binary fields are omitted rather than publishing an unusable identity.
    private static func systemIdentity(_ id: CredentialIdentity) -> (any ASCredentialIdentity)? {
        let recordIdentifier = CredentialRecordIdentifier.encode(
            accountID: id.accountID,
            cipherID: id.recordID,
            kind: id.kind.recordIdentifierKind,
            serviceIdentifier: id.serviceIdentifier,
            user: id.user
        )
        switch id.kind {
        case .password:
            return ASPasswordCredentialIdentity(
                serviceIdentifier: serviceIdentifier(id),
                user: id.user,
                recordIdentifier: recordIdentifier
            )
        case .passkey:
            guard let credentialID = id.credentialID, let userHandle = id.userHandle else {
                return nil
            }
            return ASPasskeyCredentialIdentity(
                relyingPartyIdentifier: id.serviceIdentifier,
                userName: id.user,
                credentialID: credentialID,
                userHandle: userHandle,
                recordIdentifier: recordIdentifier
            )
        case .otp:
            return ASOneTimeCodeCredentialIdentity(
                serviceIdentifier: serviceIdentifier(id),
                label: id.user,
                recordIdentifier: recordIdentifier
            )
        }
    }

}

private extension CredentialIdentity.Kind {
    var recordIdentifierKind: CredentialRecordIdentifier.Kind {
        switch self {
        case .password: .password
        case .passkey: .passkey
        case .otp: .oneTimeCode
        }
    }
}
#endif
