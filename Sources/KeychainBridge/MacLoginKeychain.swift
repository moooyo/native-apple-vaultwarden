#if os(macOS)
import Foundation
import Security

public struct MacLoginKeychain: KeychainItemStore {
    public init() {}

    package static func itemQuery(account: String, service: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }

    public func set(_ data: Data, account: String, accessGroup service: String, biometryGated: Bool) throws {
        guard !biometryGated else { throw KeychainError.unavailable }
        let query = Self.itemQuery(account: account, service: service)
        let value = [kSecValueData as String: data]
        var attributes = query
        attributes[kSecValueData as String] = data
        var status = SecItemAdd(attributes as CFDictionary, nil)
        if status == errSecDuplicateItem {
            status = SecItemUpdate(query as CFDictionary, value as CFDictionary)
        }
        guard status == errSecSuccess else { throw KeychainError.unexpected(status) }
    }

    public func get(account: String, accessGroup service: String) async throws -> Data? {
        var query = Self.itemQuery(account: account, service: service)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw KeychainError.unexpected(status) }
        guard let data = item as? Data else { throw KeychainError.unexpected(errSecDecode) }
        return data
    }

    public func delete(account: String, accessGroup service: String) {
        SecItemDelete(Self.itemQuery(account: account, service: service) as CFDictionary)
    }
}
#endif
