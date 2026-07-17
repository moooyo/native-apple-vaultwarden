import Foundation
import Observation
import VaultRepository
import Generators

/// Drives the item-detail screen for one decrypted cipher: tap-to-reveal password, live TOTP
/// code + countdown, and "what to copy" accessors. Logic only — no SwiftUI and NO clipboard
/// (the copy methods RETURN the string; writing to the pasteboard is the view's job).
@MainActor
@Observable
public final class ItemDetailModel {
    public private(set) var cipher: PlaintextCipher
    /// Whether the password is currently shown in plaintext.
    public var revealPassword = false

    /// A clock seam so tests can pin "now" for deterministic TOTP. Defaults to the system clock.
    private let now: @Sendable () -> Date

    public init(cipher: PlaintextCipher, now: @escaping @Sendable () -> Date = { Date() }) {
        self.cipher = cipher
        self.now = now
    }

    /// Toggle plaintext password visibility.
    public func toggleReveal() {
        revealPassword.toggle()
    }

    /// Replace the decrypted snapshot after list reload/edit while keeping the detail view
    /// instance alive. Secret reveal state is reset for the new snapshot.
    public func replaceCipher(_ cipher: PlaintextCipher) {
        self.cipher = cipher
        revealPassword = false
    }

    // MARK: - Copy accessors (return the value; the view owns the pasteboard)

    public var username: String? { cipher.login?.username }
    public var password: String? { cipher.login?.password }

    /// The username to place on the clipboard, or `nil` if there is none.
    public func copyUsername() -> String? { cipher.login?.username }
    /// The password to place on the clipboard, or `nil` if there is none.
    public func copyPassword() -> String? { cipher.login?.password }

    // MARK: - TOTP

    /// The parsed TOTP configuration, if the login carries a non-empty `totp` secret. `nil`
    /// (rather than throwing) when there is no secret or it fails to parse, so the view can
    /// simply hide the TOTP row.
    public var totpConfiguration: TOTPConfiguration? {
        guard let raw = cipher.login?.totp, !raw.isEmpty else { return nil }
        return try? TOTP.configuration(from: raw)
    }

    /// Whether this item exposes a TOTP code.
    public var hasTOTP: Bool { totpConfiguration != nil }

    /// The current TOTP code, or `nil` if there is no (valid) secret. Recomputed each read
    /// from `now()`; the view drives a timer and re-reads.
    public var totpCode: String? {
        guard let config = totpConfiguration else { return nil }
        return TOTP.code(for: config, at: now())
    }

    /// Seconds remaining in the current TOTP period, or `nil` if there is no TOTP.
    public var totpSecondsRemaining: Int? {
        guard let config = totpConfiguration else { return nil }
        return TOTP.secondsRemaining(for: config, at: now())
    }

    /// The TOTP code to place on the clipboard, or `nil`.
    public func copyTOTP() -> String? { totpCode }
}
