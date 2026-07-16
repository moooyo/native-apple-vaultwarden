import Foundation
import AppShared
import KeychainBridge
import PasskeyHandoff

private let handoffAccessGroup = "TESTTEAM.dev.moooyo.tessera.shared"
private let handoffService = "dev.moooyo.tessera"

/// Simulates a Keychain backend that commits the passkey item and only then reports an
/// error. Handoff cleanup must not assume a throwing write left no secret behind.
private final class WriteThenThrowPasskeyStore: KeychainItemStore, @unchecked Sendable {
    private let lock = NSLock()
    private var items: [String: Data] = [:]

    private func key(account: String, accessGroup: String) -> String {
        "\(accessGroup)::\(account)"
    }

    func set(
        _ data: Data,
        account: String,
        accessGroup: String,
        biometryGated: Bool
    ) throws {
        lock.withLock { items[key(account: account, accessGroup: accessGroup)] = data }
        if account.hasPrefix(AppShared.KeychainAccount.passkeyRegistrationPrefix) {
            throw KeychainError.unexpected(-777)
        }
    }

    func get(account: String, accessGroup: String) async throws -> Data? {
        lock.withLock { items[key(account: account, accessGroup: accessGroup)] }
    }

    func delete(account: String, accessGroup: String) {
        lock.withLock { items[key(account: account, accessGroup: accessGroup)] = nil }
    }
}

private func handoffBridge() -> KeychainBridge {
    KeychainBridge(
        accessGroup: handoffAccessGroup,
        service: handoffService,
        secureEnclave: InMemorySecureEnclaveKeyStore(),
        itemStore: InMemoryKeychainItemStore()
    )
}

func checkPasskeyHandoff(_ r: inout TestRunner) async {
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent("passkey-handoff-tests-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: directory) }

    let keychain = handoffBridge()
    let fixedID = UUID(uuidString: "01234567-89AB-CDEF-8123-456789ABCDEF")!
    let handoff = PasskeyRegistrationHandoff(
        directoryURL: directory,
        keychain: keychain,
        makeID: { fixedID }
    )

    await r.expectThrowsErrorAsync(
        PasskeyHandoffError.noActiveAccount,
        "passkey handoff: registration requires an active account"
    ) {
        _ = try await handoff.stage(
            expectedAccountID: "missing-account",
            expectedSessionID: "missing-session",
            cipherID: "cipher-1",
            relyingPartyID: "example.test",
            userName: "alice@example.test",
            userHandle: Data([1, 2, 3]),
            credentialID: Data([4, 5, 6]),
            privateKeyPKCS8: Data([7, 8, 9])
        )
    }

    var phase = "active marker"
    do {
        try await keychain.setSecret(
            Data("https://vault.example.test|alice@example.test".utf8),
            account: AppShared.KeychainAccount.activeAccountID,
            biometryGated: false
        )
        try await keychain.setSecret(
            Data("session-1".utf8),
            account: AppShared.KeychainAccount.activeSessionID,
            biometryGated: false
        )
        try await keychain.setSecret(
            Data("https://vault.example.test|alice@example.test".utf8),
            account: AppShared.KeychainAccount.biometricAccountID,
            biometryGated: false
        )
        phase = "stage"
        let privateKey = Data((0..<96).map { UInt8($0) })
        let staged = try await handoff.stage(
            expectedAccountID: "https://vault.example.test|alice@example.test",
            expectedSessionID: "session-1",
            cipherID: "cipher-1",
            relyingPartyID: "example.test",
            userName: "alice@example.test",
            userDisplayName: "Alice",
            userHandle: Data([1, 2, 3]),
            credentialID: Data([4, 5, 6]),
            privateKeyPKCS8: privateKey,
            creationDate: Date(timeIntervalSince1970: 1_700_000_000)
        )

        r.expect(staged.id, fixedID.uuidString.lowercased(),
                 "passkey handoff: stable marker id")
        phase = "inspect marker"
        let files = try FileManager.default.contentsOfDirectory(
            at: directory,
            includingPropertiesForKeys: nil
        )
        r.expect(files.count, 1, "passkey handoff: writes one marker")
        let markerData = try Data(contentsOf: files[0])
        let markerText = String(decoding: markerData, as: UTF8.self)
        r.expectTrue(!markerText.contains("example.test"),
                     "passkey handoff: marker excludes RP/account metadata")
        r.expectTrue(markerData.range(of: privateKey) == nil,
                     "passkey handoff: marker excludes private key bytes")

        // Simulate a crash after the Keychain write but before the staging -> ready rename.
        let recoveredStaging = files[0].deletingPathExtension()
            .appendingPathExtension("staging")
        phase = "simulate crash"
        try FileManager.default.moveItem(at: files[0], to: recoveredStaging)
        try FileManager.default.setAttributes(
            [.modificationDate: Date(timeIntervalSince1970: 1)],
            ofItemAtPath: recoveredStaging.path
        )

        phase = "recover staging"
        let pending = try await handoff.pendingRegistrations()
        r.expect(pending, [staged],
                 "passkey handoff: stale secret-bearing staging marker recovers")

        let secretAccount = AppShared.KeychainAccount.passkeyRegistrationPrefix + staged.id
        r.expectTrue(try await keychain.getSecret(account: secretAccount) != nil,
                     "passkey handoff: secret exists only in Keychain")

        phase = "acknowledge"
        try await handoff.acknowledge(id: staged.id)
        r.expect(try await handoff.pendingRegistrations(), [],
                 "passkey handoff: acknowledge removes marker")
        r.expectTrue(try await keychain.getSecret(account: secretAccount) == nil,
                     "passkey handoff: acknowledge removes Keychain secret")
    } catch {
        r.expectTrue(false, "passkey handoff round-trip threw during \(phase): \(error)")
    }
}

func checkPasskeyHandoffRollsBackSecret(_ r: inout TestRunner) async {
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent("passkey-handoff-promotion-failure-\(UUID().uuidString)")
    defer { try? FileManager.default.removeItem(at: directory) }
    let fixedID = UUID(uuidString: "11111111-2222-4333-8444-555555555555")!
    let readyCollision = directory
        .appendingPathComponent(fixedID.uuidString.lowercased())
        .appendingPathExtension("pending")
    do {
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        try Data("occupied".utf8).write(to: readyCollision)
    } catch {
        r.expectTrue(false, "passkey rollback fixture threw: \(error)")
        return
    }

    let keychain = handoffBridge()
    let handoff = PasskeyRegistrationHandoff(
        directoryURL: directory,
        keychain: keychain,
        makeID: { fixedID }
    )
    do {
        try await keychain.setSecret(
            Data("account-1".utf8),
            account: AppShared.KeychainAccount.activeAccountID,
            biometryGated: false
        )
        try await keychain.setSecret(
            Data("session-1".utf8),
            account: AppShared.KeychainAccount.activeSessionID,
            biometryGated: false
        )
        try await keychain.setSecret(
            Data("account-1".utf8),
            account: AppShared.KeychainAccount.biometricAccountID,
            biometryGated: false
        )
    } catch {
        r.expectTrue(false, "passkey rollback marker setup threw: \(error)")
        return
    }

    await r.expectThrowsErrorAsync(
        PasskeyHandoffError.storageUnavailable,
        "passkey handoff: marker failure is surfaced"
    ) {
        _ = try await handoff.stage(
            expectedAccountID: "account-1",
            expectedSessionID: "session-1",
            cipherID: nil,
            relyingPartyID: "example.test",
            userName: "alice",
            userHandle: Data([1]),
            credentialID: Data([2]),
            privateKeyPKCS8: Data([3]),
            creationDate: Date(timeIntervalSince1970: 1_700_000_000)
        )
    }

    let secretAccount = AppShared.KeychainAccount.passkeyRegistrationPrefix
        + fixedID.uuidString.lowercased()
    do {
        r.expectTrue(try await keychain.getSecret(account: secretAccount) == nil,
                     "passkey handoff: failed ready promotion rolls back secret")
        let staging = directory
            .appendingPathComponent(fixedID.uuidString.lowercased())
            .appendingPathExtension("staging")
        r.expectTrue(!FileManager.default.fileExists(atPath: staging.path),
                     "passkey handoff: failed ready promotion removes staging marker")
    } catch {
        r.expectTrue(false, "passkey rollback verification threw: \(error)")
    }
}

func checkPasskeyHandoffCleansPartialKeychainWrite(_ r: inout TestRunner) async {
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent("passkey-handoff-keychain-error-\(UUID().uuidString)",
                                isDirectory: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let keychain = KeychainBridge(
        accessGroup: handoffAccessGroup,
        service: handoffService,
        secureEnclave: InMemorySecureEnclaveKeyStore(),
        itemStore: WriteThenThrowPasskeyStore()
    )
    do {
        try await keychain.setSecret(
            Data("account-1".utf8),
            account: AppShared.KeychainAccount.activeAccountID,
            biometryGated: false
        )
        try await keychain.setSecret(
            Data("session-1".utf8),
            account: AppShared.KeychainAccount.activeSessionID,
            biometryGated: false
        )
        try await keychain.setSecret(
            Data("account-1".utf8),
            account: AppShared.KeychainAccount.biometricAccountID,
            biometryGated: false
        )
    } catch {
        r.expectTrue(false, "passkey partial-write setup threw: \(error)")
        return
    }

    let id = UUID(uuidString: "22222222-3333-4444-8555-666666666666")!
    let handoff = PasskeyRegistrationHandoff(
        directoryURL: directory,
        keychain: keychain,
        makeID: { id }
    )
    await r.expectThrowsErrorAsync(
        PasskeyHandoffError.keychainUnavailable,
        "passkey handoff: partial Keychain write surfaces failure"
    ) {
        _ = try await handoff.stage(
            expectedAccountID: "account-1",
            expectedSessionID: "session-1",
            cipherID: nil,
            relyingPartyID: "example.test",
            userName: "alice",
            userHandle: Data([1]),
            credentialID: Data([2]),
            privateKeyPKCS8: Data([3])
        )
    }

    do {
        let secretAccount = AppShared.KeychainAccount.passkeyRegistrationPrefix
            + id.uuidString.lowercased()
        r.expectTrue(try await keychain.getSecret(account: secretAccount) == nil,
                     "passkey handoff: partial Keychain write deletes secret")
        let files = try FileManager.default.contentsOfDirectory(
            at: directory,
            includingPropertiesForKeys: nil
        )
        r.expect(files, [],
                 "passkey handoff: partial Keychain write removes discovery marker")
    } catch {
        r.expectTrue(false, "passkey partial-write verification threw: \(error)")
    }
}

func checkPasskeyHandoffRejectsSessionSwitch(_ r: inout TestRunner) async {
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent("passkey-handoff-switch-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let keychain = handoffBridge()
    do {
        try await keychain.setSecret(
            Data("account-a".utf8),
            account: AppShared.KeychainAccount.activeAccountID,
            biometryGated: false
        )
        try await keychain.setSecret(
            Data("session-a".utf8),
            account: AppShared.KeychainAccount.activeSessionID,
            biometryGated: false
        )
        try await keychain.setSecret(
            Data("account-a".utf8),
            account: AppShared.KeychainAccount.biometricAccountID,
            biometryGated: false
        )
    } catch {
        r.expectTrue(false, "passkey switch setup threw: \(error)")
        return
    }
    let id = UUID(uuidString: "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE")!
    let handoff = PasskeyRegistrationHandoff(
        directoryURL: directory,
        keychain: keychain,
        makeID: { id },
        beforeReadyPromotion: {
            try? await keychain.setSecret(
                Data("session-b".utf8),
                account: AppShared.KeychainAccount.activeSessionID,
                biometryGated: false
            )
        }
    )
    await r.expectThrowsErrorAsync(
        PasskeyHandoffError.sessionChanged,
        "passkey handoff: session switch before ready is rejected"
    ) {
        _ = try await handoff.stage(
            expectedAccountID: "account-a",
            expectedSessionID: "session-a",
            cipherID: nil,
            relyingPartyID: "example.test",
            userName: "alice",
            userHandle: Data([1]),
            credentialID: Data([2]),
            privateKeyPKCS8: Data([3])
        )
    }
    do {
        r.expect(try await handoff.pendingRegistrations(), [],
                 "passkey handoff: rejected switch leaves no ready marker")
        let secret = try await keychain.getSecret(
            account: AppShared.KeychainAccount.passkeyRegistrationPrefix
                + id.uuidString.lowercased()
        )
        r.expectTrue(secret == nil,
                     "passkey handoff: rejected switch removes staged private key")
    } catch {
        r.expectTrue(false, "passkey switch verification threw: \(error)")
    }
}

/// The ready rename is the handoff commit point. A lock racing after that point must not
/// delete the only private key and turn a durable WebAuthn registration into a failure.
func checkPasskeyHandoffKeepsCommittedRegistrationAfterSessionSwitch(
    _ r: inout TestRunner
) async {
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent("passkey-handoff-committed-switch-\(UUID().uuidString)",
                                isDirectory: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let keychain = handoffBridge()
    do {
        try await keychain.setSecret(
            Data("account-a".utf8),
            account: AppShared.KeychainAccount.activeAccountID,
            biometryGated: false
        )
        try await keychain.setSecret(
            Data("session-a".utf8),
            account: AppShared.KeychainAccount.activeSessionID,
            biometryGated: false
        )
        try await keychain.setSecret(
            Data("account-a".utf8),
            account: AppShared.KeychainAccount.biometricAccountID,
            biometryGated: false
        )
    } catch {
        r.expectTrue(false, "passkey committed-switch setup threw: \(error)")
        return
    }

    let id = UUID(uuidString: "BBBBBBBB-CCCC-4DDD-8EEE-FFFFFFFFFFFF")!
    let handoff = PasskeyRegistrationHandoff(
        directoryURL: directory,
        keychain: keychain,
        makeID: { id },
        afterReadyPromotion: {
            try? await keychain.setSecret(
                Data("session-b".utf8),
                account: AppShared.KeychainAccount.activeSessionID,
                biometryGated: false
            )
        }
    )

    do {
        let staged = try await handoff.stage(
            expectedAccountID: "account-a",
            expectedSessionID: "session-a",
            cipherID: nil,
            relyingPartyID: "example.test",
            userName: "alice",
            userHandle: Data([1]),
            credentialID: Data([2]),
            privateKeyPKCS8: Data([3]),
            creationDate: Date(timeIntervalSince1970: 1_700_000_000)
        )
        r.expect(staged.id, id.uuidString.lowercased(),
                 "passkey handoff: ready registration survives later session switch")
        r.expect(try await handoff.pendingRegistrations(), [staged],
                 "passkey handoff: later session switch keeps ready marker")
        let secret = try await keychain.getSecret(
            account: AppShared.KeychainAccount.passkeyRegistrationPrefix + staged.id
        )
        r.expectTrue(secret != nil,
                     "passkey handoff: later session switch keeps committed private key")
    } catch {
        r.expectTrue(false, "passkey committed-switch flow threw: \(error)")
    }
}
