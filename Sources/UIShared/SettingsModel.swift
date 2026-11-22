import Foundation
import Observation
import AppShared

public enum SettingsPreference {
    public static let showsMenuBar = "openvault.mac.showMenuBarExtra"
    public static let locksOnSleep = "openvault.mac.lockOnSleep"
    public static let signsOutOnTimeout = "openvault.security.signOutOnTimeout"
    public static let showsItemIcons = "openvault.appearance.showsItemIcons"
    public static let showsUsernames = "openvault.appearance.showsUsernames"
}

public extension AutoLockTimeout {
    var settingsLabel: String {
        switch self {
        case .immediately: "立即"
        case .oneMinute: "1 分钟后"
        case .fiveMinutes: "5 分钟后"
        case .fifteenMinutes: "15 分钟后"
        case .oneHour: "1 小时后"
        case .onSleep: "睡眠时"
        }
    }
}

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

    public var availableTimeouts: [AutoLockTimeout] {
        [.immediately, .oneMinute, .fiveMinutes, .fifteenMinutes, .oneHour]
    }

    public var serverHost: String? {
        guard isServerURLValid, let url = URL(string: serverURL) else { return nil }
        return url.host(percentEncoded: false)
    }

    /// Whether the entered server URL is well-formed enough to use.
    public var isServerURLValid: Bool {
        let trimmed = serverURL.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, let url = URL(string: trimmed) else { return false }
        // Require an http(s) scheme + a host so we don't accept bare strings.
        guard let scheme = url.scheme?.lowercased(), scheme == "http" || scheme == "https" else {
            return false
        }
        return url.host?.isEmpty == false
            && url.user == nil
            && url.password == nil
            && url.query == nil
            && url.fragment == nil
    }
}
