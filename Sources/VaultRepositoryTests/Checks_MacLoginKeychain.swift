#if os(macOS)
import Foundation
import Security
import KeychainBridge
import VaultStore

func checkMacLoginKeychain(_ runner: inout TestRunner) async {
    let service = "org.openvault.tests.\(UUID().uuidString)"
    let otherService = service + ".other"
    let bridge = KeychainBridge(localMacService: service)
    let query = MacLoginKeychain.itemQuery(account: "test-record", service: service)
    runner.expect(query[kSecAttrService as String] as? String, service, "local Keychain service")
    runner.expectTrue(query[kSecAttrAccessGroup as String] == nil, "local Keychain never requests a shared group")
    runner.expectTrue(!(await bridge.isBiometricUnlockEnabled()), "local mode does not offer biometric unlock")
    do {
        try await bridge.setSecret(Data(), account: "test-record", biometryGated: true)
        runner.expectTrue(false, "local mode must reject biometric storage")
    } catch {
        runner.expect(error as? KeychainError, .unavailable, "local mode never downgrades biometric protection")
    }

    guard ProcessInfo.processInfo.environment["OPENVAULT_TEST_LOGIN_KEYCHAIN"] == "1" else { return }
    defer {
        for namespace in [service, otherService] {
            let items: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: namespace]
            let status = SecItemDelete(items as CFDictionary)
            runner.expectTrue(status == errSecSuccess || status == errSecItemNotFound, "removed temporary Keychain items")
        }
    }
    let other = KeychainBridge(localMacService: otherService)
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(service, isDirectory: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    do {
        try await bridge.setSecret(Data([1]), account: "test-record", biometryGated: false)
        try await bridge.setSecret(Data([2]), account: "test-record", biometryGated: false)
        runner.expect(try await bridge.getSecret(account: "test-record"), Data([2]), "local Keychain update")
        runner.expect(try await other.getSecret(account: "test-record"), nil, "separate services do not share secrets")
        await bridge.deleteSecret(account: "test-record")
        runner.expect(try await bridge.getSecret(account: "test-record"), nil, "local Keychain deletion")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        let database = directory.appendingPathComponent("vault.sqlite")
        let keys = DatabaseKeyStore.macLogin(service: service)
        let first = try keys.loadOrCreate(account: "db-key", for: database)
        runner.expect(first.count, 32, "local database key length")
        _ = try VaultStore(databaseURL: database, passphrase: first)
        let next = try keys.loadOrCreate(account: "db-key", for: database)
        runner.expectTrue(first == next, "local database reuses its Keychain key")
        _ = try VaultStore(databaseURL: database, passphrase: next)
        try await bridge.setSecret(Data([1]), account: "db-key", biometryGated: false)
        await runner.expectThrowsAsync("invalid database keys are not replaced") {
            _ = try keys.loadOrCreate(account: "db-key", for: database)
        }
        runner.expect(try await bridge.getSecret(account: "db-key"), Data([1]), "invalid key is left untouched")
        await bridge.deleteSecret(account: "db-key")
        await runner.expectThrowsAsync("missing key for an existing database fails closed") {
            _ = try keys.loadOrCreate(account: "db-key", for: database)
        }
        runner.expect(try await bridge.getSecret(account: "db-key"), nil, "no replacement key was created")
        _ = try VaultStore(databaseURL: database, passphrase: first)
    } catch {
        runner.expectTrue(false, "local Keychain or database test failed: \(error)")
    }
    await checkColdSessionRestoration(&runner, keychain: bridge)
}
#endif
