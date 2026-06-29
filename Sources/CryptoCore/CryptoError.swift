import Foundation

public enum CryptoError: Error, Equatable {
    case invalidEncString
    case unsupportedEncStringType(Int)
    case macMismatch
    case decryptionFailed
    case encryptionFailed
    case kdfFailed
    case insufficientKdfParameters
    case invalidKeyLength
}
