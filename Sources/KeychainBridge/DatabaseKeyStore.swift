import Foundation
import Security

public enum DatabaseKeyStore {
    case shared(accessGroup: String)
    #if os(macOS)
    case macLogin(service: String)
    #endif

    public func loadOrCreate(account: String, for databaseURL: URL) throws -> Data {
        let query: [String: Any]
        switch self {
        case .shared(let group):
            query = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrAccount as String: account,
                kSecAttrAccessGroup as String: group,
            ]
        #if os(macOS)
        case .macLogin(let service):
            query = MacLoginKeychain.itemQuery(account: account, service: service)
        #endif
        }
        if let existing = try read(query) { return existing }
        #if os(macOS)
        if case .macLogin = self, FileManager.default.fileExists(atPath: databaseURL.path) {
            if let existing = try read(query) { return existing }
            throw NSError(domain: "OpenVault.DatabaseKey", code: 1, userInfo: [
                NSLocalizedDescriptionKey: "The existing vault's key was not found in the login Keychain. No data was changed."
            ])
        }
        #endif

        var key = Data(count: 32)
        let randomStatus = key.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }
        guard randomStatus == errSecSuccess else { throw Self.error(randomStatus) }
        var attributes = query
        attributes[kSecValueData as String] = key
        if case .shared = self {
            attributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        }
        let status = SecItemAdd(attributes as CFDictionary, nil)
        if status == errSecSuccess { return key }
        if status == errSecDuplicateItem, let existing = try read(query) { return existing }
        throw Self.error(status)
    }

    private func read(_ base: [String: Any]) throws -> Data? {
        var query = base
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw Self.error(status) }
        guard let data = item as? Data, data.count == 32 else { throw Self.error(errSecDecode) }
        return data
    }

    private static func error(_ status: OSStatus) -> NSError {
        NSError(domain: NSOSStatusErrorDomain, code: Int(status))
    }
}
