#if os(macOS)
import CryptoKit
import Foundation
import Observation
import VaultRepository

public enum MacSessionTimeoutMode: String, CaseIterable, Codable, Sendable {
    case oneMinute, fiveMinutes, fifteenMinutes, thirtyMinutes, oneHour, fourHours
    case onSystemIdle, onSystemSleep, onSystemLock, onRestart, never, custom

    public var presetMinutes: Int? {
        switch self {
        case .oneMinute: 1
        case .fiveMinutes: 5
        case .fifteenMinutes: 15
        case .thirtyMinutes: 30
        case .oneHour: 60
        case .fourHours: 240
        default: nil
        }
    }

    public var allowsSupplementalLock: Bool {
        presetMinutes != nil || self == .custom || self == .onSystemIdle
    }
}

public enum MacSessionTimeoutAction: String, CaseIterable, Codable, Sendable {
    case lock, logOut
}

public enum MacSessionTimeoutTrigger: Sendable {
    case appInactivity, systemIdle, systemSleep, userSwitch, coldLaunch
    case systemLock(confirmed: Bool)
}

public struct MacSessionTimeoutPolicy: Codable, Equatable, Sendable {
    public static let maxCustomHours = Int(Int32.max) / 3600 - 1
    public static let systemIdleSeconds: TimeInterval = 5 * 60
    public static let secureDefault = Self()

    public private(set) var mode: MacSessionTimeoutMode
    public private(set) var action: MacSessionTimeoutAction
    public private(set) var customMinutes: Int
    public private(set) var alsoLocksOnSleepOrUserSwitch: Bool

    public init(mode: MacSessionTimeoutMode = .fiveMinutes, action: MacSessionTimeoutAction = .lock,
                customMinutes: Int = 5, alsoLocksOnSleepOrUserSwitch: Bool = true) {
        self.mode = mode
        self.action = action
        self.customMinutes = Self.validCustomMinutes(customMinutes)
        self.alsoLocksOnSleepOrUserSwitch = alsoLocksOnSleepOrUserSwitch
    }

    public var appInactivityDuration: Duration? {
        let minutes = mode == .custom ? Self.validCustomMinutes(customMinutes) : mode.presetMinutes
        return minutes.map { .seconds($0 * 60) }
    }

    public var customHoursPart: Int { customMinutes / 60 }
    public var customMinutesPart: Int { customMinutes % 60 }

    public func action(for trigger: MacSessionTimeoutTrigger) -> MacSessionTimeoutAction? {
        switch trigger {
        case .appInactivity:
            return appInactivityDuration == nil ? nil : action
        case .systemIdle:
            return mode == .onSystemIdle ? action : nil
        case .systemSleep:
            if mode == .onSystemSleep { return action }
            return mode.allowsSupplementalLock && alsoLocksOnSleepOrUserSwitch ? .lock : nil
        case .userSwitch:
            return mode.allowsSupplementalLock && alsoLocksOnSleepOrUserSwitch ? .lock : nil
        case .systemLock(let confirmed):
            return mode == .onSystemLock ? (confirmed ? action : .lock) : nil
        case .coldLaunch:
            return mode != .never && action == .logOut ? .logOut : nil
        }
    }

    fileprivate static func validCustomMinutes(_ minutes: Int) -> Int {
        min(max(minutes, 1), maxCustomHours * 60 + 59)
    }
}

@MainActor
@Observable
public final class MacSessionTimeoutModel {
    private let defaults: UserDefaults?
    private var selectedAccountID: String?
    public private(set) var policy = MacSessionTimeoutPolicy.secureDefault
    @ObservationIgnored public var onPolicyChanged: (@MainActor () -> Void)?

    public init(defaults: UserDefaults? = nil) {
        self.defaults = defaults
    }

    public func selectAccount(_ accountID: String?) {
        guard accountID != selectedAccountID else { return }
        policy = accountID.map { policy(for: $0) } ?? .secureDefault
        selectedAccountID = accountID
    }

    public func policy(for accountID: String) -> MacSessionTimeoutPolicy {
        if selectedAccountID == accountID { return policy }
        guard let data = defaults?.data(forKey: Self.storageKey(for: accountID)),
              let saved = try? PropertyListDecoder().decode(MacSessionTimeoutPolicy.self, from: data),
              saved.customMinutes == MacSessionTimeoutPolicy.validCustomMinutes(saved.customMinutes) else {
            return .secureDefault
        }
        return saved
    }

    public func setMode(_ mode: MacSessionTimeoutMode) {
        guard mode != policy.mode else { return }
        change(mode: mode, customMinutes: mode == .custom ? policy.mode.presetMinutes ?? 480 : nil)
    }

    public func setAction(_ action: MacSessionTimeoutAction) {
        change(action: action)
    }

    public func setCustomHours(_ hours: Int) {
        setCustomDuration(hours: hours, minutes: policy.customMinutesPart)
    }

    public func setCustomMinutes(_ minutes: Int) {
        setCustomDuration(hours: policy.customHoursPart, minutes: minutes)
    }

    public func setSupplementalLock(_ enabled: Bool) {
        change(supplementalLock: enabled)
    }

    private func setCustomDuration(hours: Int, minutes: Int) {
        let hours = min(max(hours, 0), MacSessionTimeoutPolicy.maxCustomHours)
        let minutes = min(max(minutes, 0), 59)
        change(customMinutes: hours * 60 + minutes)
    }

    private func change(mode: MacSessionTimeoutMode? = nil, action: MacSessionTimeoutAction? = nil,
                        customMinutes: Int? = nil, supplementalLock: Bool? = nil) {
        let updated = MacSessionTimeoutPolicy(mode: mode ?? policy.mode, action: action ?? policy.action,
                                              customMinutes: customMinutes ?? policy.customMinutes,
                                              alsoLocksOnSleepOrUserSwitch: supplementalLock ?? policy.alsoLocksOnSleepOrUserSwitch)
        guard updated != policy else { return }
        if let defaults, let selectedAccountID, let data = try? PropertyListEncoder().encode(updated) {
            defaults.set(data, forKey: Self.storageKey(for: selectedAccountID))
        }
        policy = updated
        onPolicyChanged?()
    }

    private static func storageKey(for accountID: String) -> String {
        "openvault.mac.sessionTimeout." + Data(SHA256.hash(data: Data(accountID.utf8))).base64EncodedString()
    }
}

public struct MacSessionInactivity: Sendable {
    public private(set) var lease: AccountSessionLease?
    private var lastInput: ContinuousClock.Instant?

    public init() {}

    @discardableResult
    public mutating func observe(_ lease: AccountSessionLease?, at now: ContinuousClock.Instant) -> Bool {
        guard lease != self.lease else { return false }
        self.lease = lease
        lastInput = lease == nil ? nil : now
        return true
    }

    public mutating func recordInput(at now: ContinuousClock.Instant) {
        if lease != nil { lastInput = now }
    }

    public func timeRemaining(for policy: MacSessionTimeoutPolicy, at now: ContinuousClock.Instant) -> Duration? {
        guard let lastInput, let duration = policy.appInactivityDuration else { return nil }
        return now.duration(to: lastInput.advanced(by: duration))
    }
}
#endif
