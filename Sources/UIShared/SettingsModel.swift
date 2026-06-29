import Foundation
import Observation
import AppShared

/// Holds user-facing settings: server URL, auto-lock timeout, and the biometric-unlock
/// toggle. Logic only — no SwiftUI and no persistence (the app layer persists these to App
/// Group `UserDefaults`; this model is the editable in-memory view the UI binds).
@MainActor
@Observable
public final class SettingsModel {
    /// The self-hosted Vaultwarden server URL.
    public var serverURL: String
    /// Auto-lock timeout (see `AppShared.AutoLockTimeout`).
    public var autoLockTimeout: AutoLockTimeout
    /// Whether biometric unlock is enabled.
    public var biometricUnlockEnabled: Bool

    public init(serverURL: String = AppShared.defaultServerURL,
                autoLockTimeout: AutoLockTimeout = .fiveMinutes,
                biometricUnlockEnabled: Bool = false) {
        self.serverURL = serverURL
        self.autoLockTimeout = autoLockTimeout
        self.biometricUnlockEnabled = biometricUnlockEnabled
    }

    /// All selectable timeout options (for a picker).
    public var availableTimeouts: [AutoLockTimeout] { AutoLockTimeout.allCases }

    /// Whether the entered server URL is well-formed enough to use.
    public var isServerURLValid: Bool {
        let trimmed = serverURL.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, let url = URL(string: trimmed) else { return false }
        // Require an http(s) scheme + a host so we don't accept bare strings.
        guard let scheme = url.scheme?.lowercased(), scheme == "http" || scheme == "https" else {
            return false
        }
        return (url.host?.isEmpty == false)
    }
}
