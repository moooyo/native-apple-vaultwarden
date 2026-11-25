import AppShared
import CryptoCore
import Foundation
import KeychainBridge
import PasskeyHandoff

private let ownerID = "https://vault.example.test|alice@example.test"
private let anotherID = "https://vault.example.test|bob@example.test"
private let fixedID = "01234567-89ab-4def-8123-456789abcdef"
private let copyID = "11111111-2222-4333-8444-555555555555"
private let testKey = try! SymmetricCryptoKey(combined: Data(repeating: 0xA1, count: 64))
private let anotherKey = try! SymmetricCryptoKey(combined: Data(repeating: 0xB2, count: 64))

private final class HandoffItemStore: KeychainItemStore, @unchecked Sendable {
    enum Fault {
        case none, writeThenThrow, retainOnDelete, throwOnRead
    }

    private let lock = NSLock()
    private var items: [String: Data] = [:]
    private var faults: [String: Fault] = [:]
    private var reads: [String: Int] = [:]

    func addFault(_ fault: Fault, for account: String) {
        lock.withLock { faults[account] = fault }
    }

    func readsOf(_ account: String) -> Int {
        lock.withLock { reads[account, default: 0] }
    }

    func set(_ data: Data, account: String, accessGroup: String, biometryGated: Bool) throws {
        try lock.withLock {
            items[account] = data
            if faults[account] == .writeThenThrow { throw KeychainError.unexpected(-777) }
        }
    }

    func get(account: String, accessGroup: String) async throws -> Data? {
        try lock.withLock {
            reads[account, default: 0] += 1
            if faults[account] == .throwOnRead { throw KeychainError.unexpected(-777) }
            return items[account]
        }
    }

    func delete(account: String, accessGroup: String) {
        lock.withLock {
            if faults[account] != .retainOnDelete { items[account] = nil }
        }
    }
}

private final class CommitPermission: @unchecked Sendable {
    private let lock = NSLock()
    private var permitted = true

    func revoke() { lock.withLock { permitted = false } }
    func permits() -> Bool { lock.withLock { permitted } }
}

private struct HandoffFixture {
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent("passkey-handoff-tests-\(UUID().uuidString)", isDirectory: true)
    let store = HandoffItemStore()
    let keychain: KeychainBridge

    init() {
        keychain = KeychainBridge(accessGroup: "TESTTEAM.dev.moooyo.tessera.shared", service: "dev.moooyo.tessera",
                                  secureEnclave: InMemorySecureEnclaveKeyStore(), itemStore: store)
    }

    func remove() { try? FileManager.default.removeItem(at: directory) }
    func queue() -> PasskeyRegistrationHandoff { PasskeyRegistrationHandoff(directoryURL: directory, keychain: keychain) }
    func marker(_ id: String = fixedID, ready: Bool = true) -> URL {
        directory.appendingPathComponent(id).appendingPathExtension(ready ? "pending" : "staging")
    }
    func writeMarker(_ id: String = fixedID, version: Int, ready: Bool = true) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try Data("{\"version\":\(version),\"id\":\"\(id)\"}".utf8).write(to: marker(id, ready: ready))
    }
}

private func sealedAccount(_ id: String = fixedID) -> String { AppShared.KeychainAccount.passkeyRegistrationPrefix + "v2." + id }
private func legacyAccount(_ id: String = fixedID) -> String { AppShared.KeychainAccount.passkeyRegistrationPrefix + id }

private func payload(id: String = fixedID, accountID: String = ownerID) -> StagedPasskeyRegistration {
    StagedPasskeyRegistration(id: id, accountID: accountID, cipherID: "cipher-1", relyingPartyID: "example.test",
                              userName: "alice@example.test", userDisplayName: "Alice", userHandle: Data([1, 2, 3]),
                              credentialID: Data([4, 5, 6]), privateKeyPKCS8: Data((0..<96).map { UInt8($0) }),
                              creationDate: Date(timeIntervalSince1970: 1_700_000_000))
}

private func sealForTest(_ bytes: Data) throws -> EncString { try SymmetricCrypto.encrypt(bytes, using: testKey) }
private func openForTest(_ envelope: EncString) throws -> Data { try SymmetricCrypto.decrypt(envelope, using: testKey) }

private func stage(_ value: StagedPasskeyRegistration, in queue: PasskeyRegistrationHandoff) async throws {
    try await queue.stage(id: value.id, envelope: sealForTest(value.encoded()), validate: {}, permitsCommit: { true })
}

func checkPasskeyHandoff(_ r: inout TestRunner) async {
    let fixture = HandoffFixture()
    defer { fixture.remove() }
    let value = payload()
    do {
        try await stage(value, in: fixture.queue())
        let marker = try Data(contentsOf: fixture.marker())
        let markerFields = try JSONSerialization.jsonObject(with: marker) as? [String: Any]
        r.expect(Set(markerFields?.keys.map { $0 } ?? []), Set(["id", "version"]),
                 "passkey handoff: App Group marker contains only id and version")
        r.expect(markerFields?["id"] as? String, value.id, "passkey handoff: canonical opaque id")
        let secret = try await fixture.keychain.getSecret(account: sealedAccount()) ?? Data()
        let envelope = try EncString(parsing: String(decoding: secret, as: UTF8.self))
        r.expect(envelope.type, .aesCbc256_HmacSha256_B64, "passkey handoff: Keychain holds an authenticated envelope")
        r.expectTrue(secret.range(of: Data(value.relyingPartyID.utf8)) == nil
            && secret.range(of: Data(value.accountID.utf8)) == nil
            && secret.range(of: Data(value.userName.utf8)) == nil
            && secret.range(of: Data(value.userDisplayName!.utf8)) == nil
            && secret.range(of: Data(value.credentialID.base64EncodedString().utf8)) == nil
            && secret.range(of: Data(value.privateKeyPKCS8.base64EncodedString().utf8)) == nil,
                     "passkey handoff: Keychain wire contains no unwrapped metadata or credential private key")
        r.expectTrue(try await fixture.keychain.getSecret(account: legacyAccount()) == nil,
                     "passkey handoff: new stage never writes legacy plaintext")

        // Simulate extension exit: instantiate a fresh queue and open with the account key.
        let restarted = fixture.queue()
        let pending = try await restarted.pendingRegistrations()
        r.expect(pending.registrations.map(\.id), [value.id], "passkey handoff: restart finds committed marker")
        guard let entry = pending.registrations.first else { return }
        r.expect(try await entry.open(for: ownerID, using: openForTest), value,
                 "passkey handoff: same account can open with a fresh session")
        await r.expectThrowsErrorAsync(CryptoError.macMismatch, "passkey handoff: wrong key cannot open envelope") {
            _ = try await entry.open(for: anotherID) { try SymmetricCrypto.decrypt($0, using: anotherKey) }
        }
        await r.expectThrowsErrorAsync(PasskeyHandoffError.invalidRegistration,
                                       "passkey handoff: reuse of key bytes does not bypass owner check") {
            _ = try await entry.open(for: anotherID, using: openForTest)
        }
        try await restarted.acknowledge(id: value.id)
        try await restarted.acknowledge(id: value.id)
        r.expectTrue(!FileManager.default.fileExists(atPath: fixture.marker().path),
                     "passkey handoff: idempotent acknowledgement removes ready marker")
        r.expectTrue(try await fixture.keychain.getSecret(account: sealedAccount()) == nil,
                     "passkey handoff: idempotent acknowledgement removes ciphertext")
    } catch {
        r.expectTrue(false, "passkey handoff round-trip threw: \(error)")
    }
}

func checkPasskeyHandoffRejectsTampering(_ r: inout TestRunner) async {
    let fixture = HandoffFixture()
    defer { fixture.remove() }
    let value = payload()
    let queue = fixture.queue()
    do {
        let original = try sealForTest(value.encoded())
        let unauthenticated = EncString(type: .aesCbc256_B64, iv: original.iv,
                                        ciphertext: original.ciphertext, mac: nil)
        await r.expectThrowsErrorAsync(PasskeyHandoffError.invalidRegistration,
                                       "passkey handoff: rejects envelopes without authentication") {
            try await queue.stage(id: value.id, envelope: unauthenticated, validate: {}, permitsCommit: { true })
        }
        try await stage(value, in: queue)
        try fixture.writeMarker(copyID, version: 2)
        try await fixture.keychain.setSecret(Data(original.stringValue.utf8), account: sealedAccount(copyID), biometryGated: false)
        var ciphertext = original.ciphertext
        ciphertext[0] ^= 1
        let corrupted = EncString(type: original.type, iv: original.iv, ciphertext: ciphertext, mac: original.mac)
        try await fixture.keychain.setSecret(Data(corrupted.stringValue.utf8), account: sealedAccount(), biometryGated: false)
        let pending = try await queue.pendingRegistrations()
        r.expect(pending.registrations.count, 2, "passkey handoff: opaque envelopes loaded without trusting data")
        for entry in pending.registrations {
            if entry.id == fixedID {
                await r.expectThrowsErrorAsync(CryptoError.macMismatch, "passkey handoff: altered ciphertext fails authentication") {
                    _ = try await entry.open(for: ownerID, using: openForTest)
                }
            } else {
                await r.expectThrowsErrorAsync(PasskeyHandoffError.invalidRegistration,
                                               "passkey handoff: valid ciphertext cannot be moved to a different marker UUID") {
                    _ = try await entry.open(for: ownerID, using: openForTest)
                }
            }
        }
    } catch {
        r.expectTrue(false, "passkey handoff tamper fixture threw: \(error)")
    }
}

func checkPasskeyHandoffRollsBackSecret(_ r: inout TestRunner) async {
    let fixture = HandoffFixture()
    defer { fixture.remove() }
    let queue = fixture.queue()
    let value = payload()
    do {
        try fixture.writeMarker(version: 2)
        let existing = try sealForTest(value.encoded())
        try await fixture.keychain.setSecret(Data(existing.stringValue.utf8), account: sealedAccount(), biometryGated: false)
        await r.expectThrowsErrorAsync(PasskeyHandoffError.storageUnavailable,
                                       "passkey handoff: never replaces an occupied ready identifier") {
            try await stage(payload(accountID: anotherID), in: queue)
        }
        r.expect(try await fixture.keychain.getSecret(account: sealedAccount()), Data(existing.stringValue.utf8),
                 "passkey handoff: a collision does not overwrite the original secret")
        try await queue.acknowledge(id: fixedID)

        fixture.store.addFault(.writeThenThrow, for: sealedAccount())
        await r.expectThrowsErrorAsync(PasskeyHandoffError.keychainUnavailable,
                                       "passkey handoff: partial Keychain write propagates failure") {
            try await stage(value, in: queue)
        }
        r.expectTrue(try await fixture.keychain.getSecret(account: sealedAccount()) == nil,
                     "passkey handoff: partial write rolls back secret")
        r.expectTrue(!FileManager.default.fileExists(atPath: fixture.marker(ready: false).path),
                     "passkey handoff: partial write removes staging marker after confirmed rollback")
    } catch {
        r.expectTrue(false, "passkey handoff rollback fixture threw: \(error)")
    }
}

func checkPasskeyHandoffRejectsSessionSwitch(_ r: inout TestRunner) async {
    let fixture = HandoffFixture()
    defer { fixture.remove() }
    let permission = CommitPermission()
    let queue = PasskeyRegistrationHandoff(directoryURL: fixture.directory, keychain: fixture.keychain,
                                           beforeReadyPromotion: { permission.revoke() })
    fixture.store.addFault(.retainOnDelete, for: sealedAccount())
    await r.expectThrowsErrorAsync(PasskeyHandoffError.sessionChanged,
                                   "passkey handoff: revocation before rename rejects registration") {
        try await queue.stage(id: fixedID, envelope: sealForTest(payload().encoded()), validate: {}, permitsCommit: permission.permits)
    }
    do {
        r.expectTrue(!FileManager.default.fileExists(atPath: fixture.marker().path),
                     "passkey handoff: rejected session leaves no ready marker")
        r.expectTrue(FileManager.default.fileExists(atPath: fixture.marker(ready: false).path),
                     "passkey handoff: failed rollback retains staging cleanup marker")
        let restarted = fixture.queue()
        let blocked = try await restarted.pendingRegistrations()
        r.expectTrue(blocked.registrations.isEmpty && blocked.hasUnreadableEntries,
                     "passkey handoff: restart does not promote a rejected stale staging entry")
        fixture.store.addFault(.none, for: sealedAccount())
        r.expect(try await restarted.pendingRegistrations().registrations, [],
                 "passkey handoff: partial stage is only retried for cleanup")
        r.expectTrue(try await fixture.keychain.getSecret(account: sealedAccount()) == nil,
                     "passkey handoff: restart finishes cleanup of an uncommitted envelope")
    } catch {
        r.expectTrue(false, "passkey handoff switch fixture threw: \(error)")
    }
}

func checkPasskeyHandoffKeepsCommittedRegistrationAfterSessionSwitch(_ r: inout TestRunner) async {
    let fixture = HandoffFixture()
    defer { fixture.remove() }
    let permission = CommitPermission()
    let queue = PasskeyRegistrationHandoff(directoryURL: fixture.directory, keychain: fixture.keychain,
                                           afterReadyPromotion: { permission.revoke() })
    do {
        try await queue.stage(id: fixedID, envelope: sealForTest(payload().encoded()), validate: {}, permitsCommit: permission.permits)
        r.expectTrue(!permission.permits(), "passkey handoff: post-rename session was revoked")
        let pending = try await fixture.queue().pendingRegistrations()
        r.expect(pending.registrations.map(\.id), [fixedID], "passkey handoff: post-rename revocation keeps committed marker")
        r.expectTrue(try await fixture.keychain.getSecret(account: sealedAccount()) != nil,
                     "passkey handoff: post-rename revocation keeps ciphertext for a later session")
    } catch {
        r.expectTrue(false, "passkey handoff post-commit fixture threw: \(error)")
    }
}

func checkPasskeyHandoffAcknowledgementReadback(_ r: inout TestRunner) async {
    let fixture = HandoffFixture()
    defer { fixture.remove() }
    let queue = fixture.queue()
    do {
        try await stage(payload(), in: queue)
        fixture.store.addFault(.retainOnDelete, for: sealedAccount())
        await r.expectThrowsErrorAsync(PasskeyHandoffError.keychainUnavailable,
                                       "passkey handoff: a silent delete failure is surfaced") {
            try await queue.acknowledge(id: fixedID)
        }
        r.expect(try await queue.pendingRegistrations().registrations.map(\.id), [fixedID],
                 "passkey handoff: failed delete keeps a retryable marker and its ciphertext")
        fixture.store.addFault(.throwOnRead, for: sealedAccount())
        await r.expectThrowsErrorAsync(PasskeyHandoffError.keychainUnavailable,
                                       "passkey handoff: failed absence readback blocks acknowledgement") {
            try await queue.acknowledge(id: fixedID)
        }
        r.expectTrue(FileManager.default.fileExists(atPath: fixture.marker().path),
                     "passkey handoff: no readback leaves marker even when the deletion worked")
        fixture.store.addFault(.none, for: sealedAccount())
        try await fixture.queue().acknowledge(id: fixedID)
        r.expectTrue(!FileManager.default.fileExists(atPath: fixture.marker().path),
                     "passkey handoff: later confirmed absence completes cleanup")
    } catch {
        r.expectTrue(false, "passkey handoff acknowledgement fixture threw: \(error)")
    }
}

func checkPasskeyHandoffLegacyMigration(_ r: inout TestRunner) async {
    let fixture = HandoffFixture()
    defer { fixture.remove() }
    let queue = fixture.queue()
    let original = payload()
    let owner = PasskeyRegistrationHandoff.LegacyMigration(accountID: ownerID, validate: {}, seal: sealForTest, open: openForTest)
    let another = PasskeyRegistrationHandoff.LegacyMigration(accountID: anotherID, validate: {}, seal: sealForTest, open: openForTest)
    do {
        try fixture.writeMarker(version: 1)
        var unwrapped = try JSONSerialization.jsonObject(with: original.encoded()) as? [String: Any] ?? [:]
        unwrapped["version"] = 1
        let plaintext = try JSONSerialization.data(withJSONObject: unwrapped)
        try await fixture.keychain.setSecret(plaintext, account: legacyAccount(), biometryGated: false)
        let extensionView = try await queue.pendingRegistrations()
        r.expectTrue(extensionView.requiresLegacyMigration && extensionView.registrations.isEmpty,
                     "passkey handoff: extension fails closed for old unwrapped entries")
        r.expect(fixture.store.readsOf(legacyAccount()), 0, "passkey handoff: extension never reads the legacy raw item")
        let expired = PasskeyRegistrationHandoff.LegacyMigration(
            accountID: ownerID, validate: { throw PasskeyHandoffError.sessionChanged }, seal: sealForTest, open: openForTest
        )
        let expiredView = try await queue.pendingRegistrations(migrating: expired)
        r.expectTrue(expiredView.requiresLegacyMigration && expiredView.registrations.isEmpty,
                     "passkey handoff: migration fails closed after lease expiry")
        r.expect(fixture.store.readsOf(legacyAccount()), 0, "passkey handoff: expired lease cannot read the legacy raw item")
        let foreignView = try await queue.pendingRegistrations(migrating: another)
        r.expectTrue(foreignView.requiresLegacyMigration && foreignView.registrations.isEmpty,
                     "passkey handoff: wrong account cannot migrate someone else's legacy item")
        r.expect(try await fixture.keychain.getSecret(account: legacyAccount()), plaintext,
                 "passkey handoff: wrong account does not destroy a website-accepted legacy credential")
        r.expectTrue(try await fixture.keychain.getSecret(account: sealedAccount()) == nil,
                     "passkey handoff: wrong account did not publish a replacement")
        await r.expectThrowsErrorAsync(PasskeyHandoffError.legacyMigrationPending,
                                       "passkey handoff: no acknowledgement of unmigrated registration") {
            try await queue.acknowledge(id: fixedID)
        }

        fixture.store.addFault(.retainOnDelete, for: legacyAccount())
        let failedMigration = try await queue.pendingRegistrations(migrating: owner)
        r.expectTrue(failedMigration.requiresLegacyMigration && failedMigration.registrations.isEmpty,
                     "passkey handoff: failed deletion of raw item keeps migration pending")
        r.expect(try await fixture.keychain.getSecret(account: legacyAccount()), plaintext,
                 "passkey handoff: failed legacy deletion leaves the credential discoverable")
        let replacement = try await fixture.keychain.getSecret(account: sealedAccount())
        r.expectTrue(replacement != nil, "passkey handoff: verifies a separate encrypted replacement before deleting raw item")
        fixture.store.addFault(.none, for: legacyAccount())
        let migrated = try await fixture.queue().pendingRegistrations(migrating: owner)
        r.expectTrue(!migrated.requiresLegacyMigration && migrated.registrations.count == 1,
                     "passkey handoff: completes interrupted owner migration after process restart")
        r.expect(try await fixture.keychain.getSecret(account: sealedAccount()), replacement,
                 "passkey handoff: restart reuses the authenticated replacement")
        r.expectTrue(try await fixture.keychain.getSecret(account: legacyAccount()) == nil,
                     "passkey handoff: no raw item remains after owner migration")

        // Restore the old marker to simulate a crash after deleting plaintext but before
        // atomically replacing the marker. The replacement must still be available.
        try fixture.writeMarker(version: 1)
        let resumed = try await fixture.queue().pendingRegistrations(migrating: owner)
        r.expectTrue(!resumed.requiresLegacyMigration && resumed.registrations.count == 1,
                     "passkey handoff: v1 marker locates a replacement after raw bytes are gone")
        let reopened = try await fixture.queue().pendingRegistrations()
        if let entry = reopened.registrations.first {
            r.expect(try await entry.open(for: ownerID, using: openForTest), original,
                     "passkey handoff: migrated credentials preserve all fields and are now readable by the extension")
        } else {
            r.expectTrue(false, "passkey handoff: migrated marker remained hidden from extension")
        }
    } catch {
        r.expectTrue(false, "passkey handoff migration fixture threw: \(error)")
    }
}

func checkPasskeyHandoffFilesystemHardening(_ r: inout TestRunner) async {
    let fixture = HandoffFixture()
    defer { fixture.remove() }
    let external = HandoffFixture()
    defer { external.remove() }
    let fm = FileManager.default
    do {
        try fixture.writeMarker(version: 2)
        try external.writeMarker(copyID, version: 2)
        try fm.removeItem(at: fixture.marker())
        try fm.createSymbolicLink(at: fixture.marker(), withDestinationURL: external.marker(copyID))
        let pending = try await fixture.queue().pendingRegistrations()
        r.expectTrue(pending.registrations.isEmpty && pending.hasUnreadableEntries,
                     "passkey handoff: does not follow marker symlinks")
        r.expectTrue(fm.fileExists(atPath: external.marker(copyID).path),
                     "passkey handoff: does not change marker symlink target")
        try fm.removeItem(at: fixture.directory)
        try fm.createSymbolicLink(at: fixture.directory, withDestinationURL: external.directory)
        await r.expectThrowsErrorAsync(PasskeyHandoffError.storageUnavailable,
                                       "passkey handoff: rejects a symlinked queue directory") {
            try await stage(payload(), in: fixture.queue())
        }
        r.expectTrue(try await fixture.keychain.getSecret(account: sealedAccount()) == nil,
                     "passkey handoff: bad filesystem path does not leave ciphertext")
    } catch {
        r.expectTrue(false, "passkey handoff filesystem fixture threw: \(error)")
    }
}
