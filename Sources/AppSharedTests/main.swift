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

    let record = CredentialRecordIdentifier.encode(
        accountID: "https://a.example|alice@example.test",
        cipherID: "same-server-uuid",
        kind: .password,
        serviceIdentifier: "https://login.example",
        user: "alice"
    )
    r.expect(CredentialRecordIdentifier.decode(
        record,
        expectedAccountID: "https://a.example|alice@example.test",
        expectedKind: .password,
        expectedServiceIdentifier: "https://login.example",
        expectedUser: "alice"
    ), "same-server-uuid", "credential record id round-trips for owning account")
    r.expectTrue(CredentialRecordIdentifier.decode(
        record,
        expectedAccountID: "https://b.example|alice@example.test",
        expectedKind: .password,
        expectedServiceIdentifier: "https://login.example",
        expectedUser: "alice"
    ) == nil, "credential record id rejects cloned-server account")
    r.expectTrue(CredentialRecordIdentifier.decode(
        record,
        expectedAccountID: "https://a.example|alice@example.test",
        expectedKind: .password,
        expectedServiceIdentifier: "https://changed.example",
        expectedUser: "alice"
    ) == nil, "credential record id rejects stale service identity")
    r.expectTrue(CredentialRecordIdentifier.decode(
        record,
        expectedAccountID: "https://a.example|alice@example.test",
        expectedKind: .oneTimeCode,
        expectedServiceIdentifier: "https://login.example",
        expectedUser: "alice"
    ) == nil, "credential record id rejects wrong credential kind")
    r.expectTrue(CredentialRecordIdentifier.decode(
        record,
        expectedAccountID: "https://a.example|alice@example.test",
        expectedKind: .password,
        expectedServiceIdentifier: "https://login.example",
        expectedUser: "bob"
    ) == nil, "credential record id rejects stale displayed user")
    r.expectTrue(CredentialRecordIdentifier.decode(
        "same-server-uuid",
        expectedAccountID: "https://a.example|alice@example.test",
        expectedKind: .password,
        expectedServiceIdentifier: "https://login.example",
        expectedUser: "alice"
    ) == nil, "legacy raw record id fails closed")

    return r.summary()
}

let failures = runAllTests()
if failures != 0 { exit(1) }
