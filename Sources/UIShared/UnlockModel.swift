import Foundation
import Observation

/// Drives the unlock screen: master-password or biometric unlock of an already-logged-in
/// account. Logic only — no SwiftUI. The view binds `password` and observes `state`.
@MainActor
@Observable
public final class UnlockModel {
    /// The unlock lifecycle the view renders from.
    public enum State: Equatable, Sendable {
        case locked
        case unlocking
        case unlocked
        case error(String)
    }

    /// The master-password field bound by the view.
    public var password: String = ""
    public private(set) var state: State = .locked

    private let auth: AuthService

    public init(auth: AuthService) {
        self.auth = auth
    }

    /// Unlock with the entered master password. On success → `.unlocked`; on failure the
    /// vault stays locked and `state` becomes `.error(message)`.
    public func unlockWithPassword() async {
        guard state != .unlocking else { return }
        state = .unlocking
        do {
            try await auth.unlockWithMasterPassword(password)
            password = ""
            state = .unlocked
        } catch {
            state = .error(Self.message(for: error))
        }
    }

    /// Unlock via biometrics (Face ID / Touch ID / Optic ID). Same success/failure handling.
    public func unlockWithBiometrics(reason: String = "Unlock Tessera") async {
        guard state != .unlocking else { return }
        state = .unlocking
        do {
            try await auth.unlockWithBiometrics(reason: reason)
            state = .unlocked
        } catch {
            state = .error(Self.message(for: error))
        }
    }

    /// Whether an error is currently being shown (a convenience for the view).
    public var errorMessage: String? {
        if case .error(let message) = state { return message }
        return nil
    }
}
