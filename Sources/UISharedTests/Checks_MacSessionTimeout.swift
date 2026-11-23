#if os(macOS)
import Foundation
import UIShared
import VaultRepository

@MainActor
func checkMacSessionTimeoutPolicy(_ runner: inout TestRunner) {
    let presets = MacSessionTimeoutMode.allCases.compactMap(\.presetMinutes)
    runner.expect(presets, [1, 5, 15, 30, 60, 240], "Mac timeout lists the official desktop presets")
    runner.expect(MacSessionTimeoutPolicy.systemIdleSeconds, 300, "Mac timeout system idle checks use a five-minute threshold")
    runner.expect(MacSessionTimeoutPolicy.secureDefault.mode, .fiveMinutes, "Mac timeout keeps the secure five-minute default")
    runner.expect(MacSessionTimeoutPolicy.secureDefault.action, .lock, "Mac timeout keeps the lock default")
    runner.expect(MacSessionTimeoutPolicy.secureDefault.action(for: .systemSleep), .lock, "Mac timeout retains the supplemental sleep lock by default")
    runner.expect(MacSessionTimeoutPolicy(mode: .custom, customMinutes: 0).appInactivityDuration, .seconds(60), "Mac timeout clamps a zero custom duration to one minute")
    runner.expectTrue(MacSessionTimeoutPolicy(mode: .custom, customMinutes: Int.max).customHoursPart <= MacSessionTimeoutPolicy.maxCustomHours,
                      "Mac timeout clamps overflow-sized custom settings")

    for mode in MacSessionTimeoutMode.allCases {
        let policy = MacSessionTimeoutPolicy(mode: mode, action: .logOut)
        runner.expect(policy.action(for: .systemSleep), mode == .onSystemSleep ? .logOut : mode.allowsSupplementalLock ? .lock : nil,
                      "Mac timeout sleep action for \(mode)")
        runner.expect(policy.action(for: .userSwitch), mode.allowsSupplementalLock ? .lock : nil,
                      "Mac timeout user switch action for \(mode)")
        runner.expect(policy.action(for: .systemIdle), mode == .onSystemIdle ? .logOut : nil,
                      "Mac timeout idle action for \(mode)")
        runner.expect(policy.action(for: .systemLock(confirmed: false)), mode == .onSystemLock ? .lock : nil,
                      "Mac timeout does not log out on an unconfirmed lock hint for \(mode)")
        runner.expect(policy.action(for: .systemLock(confirmed: true)), mode == .onSystemLock ? .logOut : nil,
                      "Mac timeout confirmed lock action for \(mode)")
        runner.expect(policy.action(for: .coldLaunch), mode == .never ? nil : .logOut,
                      "Mac timeout cold launch action for \(mode)")
    }

    let suite = "org.openvault.test-timeout.\(UUID().uuidString)"
    guard let defaults = UserDefaults(suiteName: suite) else {
        runner.expectTrue(false, "Mac timeout defaults test suite opens")
        return
    }
    defer { defaults.removePersistentDomain(forName: suite) }
    let settings = MacSessionTimeoutModel(defaults: defaults)
    let firstAccount = "https://vault.example.test/first|test@example.test"
    let secondAccount = "https://vault.example.test/second|test@example.test"
    settings.selectAccount(firstAccount)
    settings.setMode(.thirtyMinutes)
    settings.setMode(.custom)
    runner.expect(settings.policy.customMinutes, 30, "Mac timeout custom entry starts from the last preset")
    settings.setCustomHours(3)
    settings.setCustomMinutes(17)
    settings.setAction(.logOut)
    settings.setSupplementalLock(false)
    let firstPolicy = settings.policy
    let reopened = MacSessionTimeoutModel(defaults: defaults)
    runner.expect(reopened.policy(for: firstAccount), firstPolicy, "Mac timeout account policy is available before selecting the account on launch")
    settings.selectAccount(secondAccount)
    runner.expect(settings.policy, .secureDefault, "Mac timeout keeps identical emails on different deployments isolated")
    settings.setMode(.never)
    settings.setMode(.custom)
    runner.expect(settings.policy.customMinutes, 480, "Mac timeout custom entry defaults to eight hours from a non-numeric mode")
    settings.selectAccount(firstAccount)
    runner.expect(settings.policy, firstPolicy, "Mac timeout switching away and back restores the original settings")
}

func checkMacSessionInactivity(_ runner: inout TestRunner) {
    let initial = ContinuousClock.now
    let original = AccountSessionLease(accountID: "fixture", generation: 1)
    let replacement = AccountSessionLease(accountID: "fixture", generation: 2)
    let policy = MacSessionTimeoutPolicy(mode: .oneMinute)
    var inactivity = MacSessionInactivity()
    runner.expectTrue(inactivity.observe(original, at: initial), "Mac timeout starts observing the unlocked lease")
    runner.expect(inactivity.timeRemaining(for: policy, at: initial), .seconds(60), "Mac timeout starts at a full interval")
    runner.expectFalse(inactivity.observe(original, at: initial.advanced(by: .seconds(50))), "Mac timeout polling cannot extend the user's deadline")
    runner.expect(inactivity.timeRemaining(for: policy, at: initial.advanced(by: .seconds(60))), .zero, "Mac timeout expires at the interval boundary")
    inactivity.recordInput(at: initial.advanced(by: .seconds(33)))
    runner.expect(inactivity.timeRemaining(for: policy, at: initial.advanced(by: .seconds(60))), .seconds(33), "Mac timeout applies the last actual local input")
    runner.expectTrue(inactivity.observe(replacement, at: initial.advanced(by: .seconds(61))), "Mac timeout treats a replaced session of the same account as new")
    runner.expect(inactivity.timeRemaining(for: policy, at: initial.advanced(by: .seconds(62))), .seconds(59), "Mac timeout does not inherit a superseded lease's deadline")
    inactivity.observe(nil, at: initial.advanced(by: .seconds(70)))
    runner.expectNil(inactivity.timeRemaining(for: policy, at: initial.advanced(by: .seconds(72))), "Mac timeout has no local deadline while locked")
}
#endif
