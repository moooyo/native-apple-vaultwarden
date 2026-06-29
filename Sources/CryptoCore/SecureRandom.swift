import Foundation
import Security

public enum SecureRandom {
    /// Cryptographically secure random bytes from the system CSPRNG.
    public static func bytes(_ count: Int) throws -> Data {
        guard count > 0 else { return Data() }
        var out = Data(count: count)
        let status = out.withUnsafeMutableBytes { ptr -> Int32 in
            SecRandomCopyBytes(kSecRandomDefault, count, ptr.baseAddress!)
        }
        guard status == errSecSuccess else { throw CryptoError.randomGenerationFailed }
        return out
    }
}
