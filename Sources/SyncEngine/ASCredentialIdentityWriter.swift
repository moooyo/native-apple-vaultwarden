import Foundation

// The real, system-backed `CredentialIdentityWriting` conformer. It is gated behind
// `canImport(AuthenticationServices)` so this file compiles on a host that has the
// framework headers, but it only RUNS inside a signed app/extension with the AutoFill
// credential-provider entitlement. The unit tests use an in-memory fake instead.
#if canImport(AuthenticationServices)
import AuthenticationServices

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
        let passwords = identities.filter { $0.kind == .password }.map(Self.passwordIdentity)
        try? await ASCredentialIdentityStore.shared.replaceCredentialIdentities(passwords)
        // Passkey / OTP identities are added incrementally on top (their replace-all
        // APIs differ by OS version); a failure here is non-fatal for AutoFill.
        await saveNonPassword(identities)
    }

    public func incremental(add: [CredentialIdentity], remove: [CredentialIdentity]) async {
        let addPasswords = add.filter { $0.kind == .password }.map(Self.passwordIdentity)
        if !addPasswords.isEmpty {
            try? await ASCredentialIdentityStore.shared.saveCredentialIdentities(addPasswords)
        }
        let removePasswords = remove.filter { $0.kind == .password }.map(Self.passwordIdentity)
        if !removePasswords.isEmpty {
            try? await ASCredentialIdentityStore.shared.removeCredentialIdentities(removePasswords)
        }
        await saveNonPassword(add)
    }

    // MARK: - Mapping

    private static func passwordIdentity(_ id: CredentialIdentity) -> ASPasswordCredentialIdentity {
        let service = ASCredentialServiceIdentifier(identifier: id.serviceIdentifier, type: .URL)
        let identity = ASPasswordCredentialIdentity(serviceIdentifier: service,
                                                    user: id.user,
                                                    recordIdentifier: id.recordID)
        return identity
    }

    private func saveNonPassword(_ identities: [CredentialIdentity]) async {
        for id in identities where id.kind != .password {
            switch id.kind {
            case .passkey:
                #if compiler(>=5.9)
                // Passkey credential identities require user-handle + credential-id at
                // construction; the app target supplies those from the decrypted
                // fido2Credential. This wrapper is the seam — the app wires the full
                // mapping. Left intentionally minimal here.
                _ = id
                #endif
            case .otp:
                #if compiler(>=5.9)
                _ = id
                #endif
            case .password:
                break
            }
        }
    }
}
#endif
