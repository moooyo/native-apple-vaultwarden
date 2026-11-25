import CryptoKit
import Foundation

/// Bitwarden's keyed login URL checksum is encoded and encrypted as a separate item field.
package enum LoginURIChecksum {
    package static func encoded(_ uri: String) -> String {
        Data(SHA256.hash(data: Data(uri.utf8))).base64EncodedString()
    }
}
