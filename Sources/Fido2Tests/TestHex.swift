import Foundation

// Test-only hex helpers. These intentionally do NOT ship in the public Fido2
// product — they exist solely so checks can compare `Data` to golden-vector hex strings.
extension Data {
    var hexString: String { map { String(format: "%02x", $0) }.joined() }

    /// Lenient test-only hex decoder: silently skips any byte pair that is not valid
    /// hex (it is for fixture/golden-vector literals, not for parsing untrusted input).
    init(hex: String) {
        var bytes = [UInt8]()
        bytes.reserveCapacity(hex.count / 2)
        var idx = hex.startIndex
        while idx < hex.endIndex {
            let next = hex.index(idx, offsetBy: 2, limitedBy: hex.endIndex) ?? hex.endIndex
            if let b = UInt8(hex[idx..<next], radix: 16) { bytes.append(b) }
            idx = next
        }
        self = Data(bytes)
    }
}
