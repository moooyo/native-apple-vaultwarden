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
    public private(set) var email: String?
    public private(set) var state: State = .locked

    private let auth: AuthService

    public init(auth: AuthService) {
        self.auth = auth
    }

    public func loadAccount() async { email = await auth.accountEmail() }

    @discardableResult
    public func logout() async -> Bool {
        guard state != .unlocking else { return false }
        state = .unlocking
        password = ""
        guard await auth.logout() else {
            state = .error(String(localized: "OpenVault could not remove the local session. Try again."))
            return false
        }
        email = nil
        state = .locked
        return true
    }

    /// Unlock with the entered master password. On success → `.unlocked`; on failure the
    /// vault stays locked and `state` becomes `.error(message)`.
    public func unlockWithPassword() async {
        guard state != .unlocking, !password.isEmpty else { return }
        // Consume the submitted credential before suspending; completion must not clear later input.
        let submittedPassword = password
        password = ""
        await attemptUnlock { try await auth.unlockWithMasterPassword(submittedPassword) }
    }

    /// Unlock via biometrics (Face ID / Touch ID / Optic ID). Drop any unused input.
    public func unlockWithBiometrics(reason: String = "Unlock OpenVault") async {
        guard state != .unlocking else { return }
        password = ""
        await attemptUnlock { try await auth.unlockWithBiometrics(reason: reason) }
    }

    private func attemptUnlock(_ operation: () async throws -> Void) async {
        state = .unlocking
        do {
            try Task.checkCancellation()
            try await operation()
            state = .unlocked
        } catch {
            state = Task.isCancelled || error is CancellationError ? .locked : .error(Self.message(for: error))
        }
    }

    /// Whether an error is currently being shown (a convenience for the view).
    public var errorMessage: String? {
        if case .error(let message) = state { return message }
        return nil
    }
}
