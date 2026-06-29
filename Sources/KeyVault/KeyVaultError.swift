import Foundation

/// Errors raised by `KeyVault` key operations.
public enum KeyVaultError: Error, Equatable {
    case locked          // operation requires an unlocked vault
    case unlockFailed    // protected user key could not be decrypted (wrong password / corrupt)
    case invalidUserKey  // decrypted user key was not 64 bytes
}
