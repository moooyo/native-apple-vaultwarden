import Foundation
import AppShared

func runAllTests() -> Int {
    var r = TestRunner()

    // Constants
    r.expect(AppShared.appGroupID, "group.dev.moooyo.tessera", "appGroupID constant")
    r.expectTrue(AppShared.keychainAccessGroup.hasSuffix("dev.moooyo.tessera.shared"),
                 "keychainAccessGroup suffix")
    r.expect(AppShared.defaultServerURL, "", "defaultServerURL empty by default")

    // DeviceMetadata
    let dev = DeviceMetadata(type: DeviceMetadata.DeviceType.iOS,
                             identifier: "AAAA-BBBB", name: "Test iPhone")
    r.expect(dev.type, 1, "DeviceMetadata iOS type")
    r.expect(dev.identifier, "AAAA-BBBB", "DeviceMetadata identifier")
    r.expect(dev.name, "Test iPhone", "DeviceMetadata name")
    r.expect(DeviceMetadata.DeviceType.macOSDesktop, 7, "macOS DeviceType raw")
    r.expect(dev, DeviceMetadata(type: 1, identifier: "AAAA-BBBB", name: "Test iPhone"),
             "DeviceMetadata Equatable")

    // AutoLockTimeout
    r.expect(AutoLockTimeout.immediately.rawValue, 0, "AutoLockTimeout immediately")
    r.expect(AutoLockTimeout.fiveMinutes.rawValue, 300, "AutoLockTimeout fiveMinutes")
    r.expect(AutoLockTimeout.never.rawValue, -1, "AutoLockTimeout never")
    r.expect(AutoLockTimeout.allCases.count, 6, "AutoLockTimeout case count")
    r.expect(AutoLockTimeout(rawValue: 3600), .oneHour, "AutoLockTimeout from rawValue")

    // LogRedaction
    let enc = "2.aBcDeFgHiJkLmNoPqRsT123456789+/abc=|ZZZZZZZZZZZZZZZZ==|MmMmMmMmMmMmMmMmMmMmMm=="
    let redactedEnc = LogRedaction.redact("token=\(enc) done")
    r.expectTrue(!redactedEnc.contains(enc), "LogRedaction hides EncString")
    r.expectTrue(redactedEnc.contains("<redacted>"), "LogRedaction emits placeholder")
    r.expectTrue(redactedEnc.contains("done"), "LogRedaction keeps surrounding text")

    let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    let redactedJwt = LogRedaction.redact("Authorization: Bearer \(jwt)")
    r.expectTrue(!redactedJwt.contains(jwt), "LogRedaction hides JWT/bearer")

    let plain = "user opened the vault list"
    r.expect(LogRedaction.redact(plain), plain, "LogRedaction leaves plain text untouched")

    return r.summary()
}

let failures = runAllTests()
if failures != 0 { exit(1) }
