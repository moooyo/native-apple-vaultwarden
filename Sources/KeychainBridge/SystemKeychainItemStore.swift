import Foundation

#if canImport(Security)
import Security
#endif

/// Real generic-password seam. Items live in a shared Keychain access group so the app and
/// the AutoFill extension can both read them; they are `...ThisDeviceOnly` (never synced to
/// iCloud Keychain) and may optionally be biometry-gated.
///
/// ENVIRONMENT NOTE: compiles on a Command-Line-Tools host but cannot RUN here —
/// `kSecAttrAccessGroup` requires the `keychain-access-groups` entitlement on a signed app.
public struct SystemKeychainItemStore: KeychainItemStore {
    public init() {}

    public func set(_ data: Data, account: String, accessGroup: String, biometryGated: Bool) throws {
        // Replace any existing value: delete first, then add (avoids SecItemUpdate edge
        // cases when the access-control attribute changes).
        delete(account: account, accessGroup: accessGroup)

        var attributes: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: accessGroup,
            kSecValueData as String: data,
        ]

        if biometryGated {
            var acError: Unmanaged<CFError>?
            guard let access = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                [.userPresence],
                &acError
            ) else {
                acError?.release()
                throw KeychainError.unavailable
            }
            attributes[kSecAttrAccessControl as String] = access
        } else {
            attributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        }

        let status = SecItemAdd(attributes as CFDictionary, nil)
        switch status {
        case errSecSuccess:
            return
        case errSecDuplicateItem:
            throw KeychainError.duplicate
        default:
            throw KeychainError.unexpected(status)
        }
    }

    public func get(account: String, accessGroup: String) async throws -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: accessGroup,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            return item as? Data
        case errSecItemNotFound:
            return nil
        case errSecUserCanceled:
            throw KeychainError.userCanceled
        default:
            throw KeychainError.unexpected(status)
        }
    }

    public func delete(account: String, accessGroup: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: accessGroup,
        ]
        SecItemDelete(query as CFDictionary)
    }
}
