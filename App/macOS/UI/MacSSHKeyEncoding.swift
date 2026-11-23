import Foundation

struct MacSSHKeyReader {
    private let data: Data
    private var index: Data.Index

    init(_ data: Data) {
        self.data = data
        index = data.startIndex
    }

    var isEmpty: Bool { remaining == 0 }
    var remaining: Int { data.endIndex - index }
    var nextByte: UInt8? { isEmpty ? nil : data[index] }

    mutating func bytes(_ length: Int) throws -> Data {
        guard length >= 0, length <= remaining else { throw MacSSHSigningKey.Failure.invalidKey }
        defer { index += length }
        return data[index..<(index + length)]
    }

    mutating func uint32() throws -> UInt32 {
        try bytes(4).reduce(0) { ($0 << 8) | UInt32($1) }
    }

    mutating func string(maximum: Int) throws -> Data {
        let length = Int(try uint32())
        guard length <= maximum else { throw MacSSHSigningKey.Failure.invalidKey }
        return try bytes(length)
    }

    mutating func name() throws -> String {
        guard let value = String(data: try string(maximum: 48), encoding: .ascii) else {
            throw MacSSHSigningKey.Failure.invalidKey
        }
        return value
    }

    mutating func mpint(maximum: Int) throws -> Data {
        try MacSSHKeyEncoding.positiveMagnitude(string(maximum: maximum + 1), maximum: maximum)
    }

    mutating func derValue(tag: UInt8) throws -> Data {
        guard try bytes(1).first == tag, let first = try bytes(1).first else {
            throw MacSSHSigningKey.Failure.invalidKey
        }
        if first < 128 { return try bytes(Int(first)) }
        let size = Int(first & 0x7f)
        guard (1...2).contains(size) else { throw MacSSHSigningKey.Failure.invalidKey }
        let lengthBytes = try bytes(size)
        let length = lengthBytes.reduce(0) { ($0 << 8) | Int($1) }
        guard lengthBytes.first != 0, length >= 128 else { throw MacSSHSigningKey.Failure.invalidKey }
        return try bytes(length)
    }

    mutating func derInteger(maximum: Int) throws -> Data {
        try MacSSHKeyEncoding.positiveMagnitude(derValue(tag: 0x02), maximum: maximum)
    }

    mutating func derBitString(tag: UInt8 = 0x03) throws -> Data {
        let value = try derValue(tag: tag)
        guard value.count > 1, value.first == 0 else { throw MacSSHSigningKey.Failure.invalidKey }
        return value.dropFirst()
    }
}

enum MacSSHKeyEncoding {
    static func positiveMagnitude(_ encoded: Data, maximum: Int) throws -> Data {
        guard let first = encoded.first, first < 128 else { throw MacSSHSigningKey.Failure.invalidKey }
        let magnitude = first == 0 ? encoded.dropFirst() : encoded
        guard !magnitude.isEmpty, magnitude.count <= maximum,
              first != 0 || (magnitude.first ?? 0) >= 128 else {
            throw MacSSHSigningKey.Failure.invalidKey
        }
        return magnitude
    }

    static func string(_ value: Data) -> Data {
        var length = UInt32(value.count).bigEndian
        var encoded = withUnsafeBytes(of: &length) { Data($0) }
        encoded.append(value)
        return encoded
    }

    static func string(_ value: String) -> Data { string(Data(value.utf8)) }

    static func mpint(_ bytes: Data) -> Data { string(signedMagnitude(bytes)) }

    static func derInteger(_ bytes: Data) -> Data {
        let body = signedMagnitude(bytes)
        return derValue(tag: 0x02, body: body.isEmpty ? Data([0]) : body)
    }

    static func derValue(tag: UInt8, body: Data) -> Data {
        var result = Data([tag])
        switch body.count {
        case 0..<128: result.append(UInt8(body.count))
        case 128..<256: result.append(contentsOf: [0x81, UInt8(body.count)])
        default: result.append(contentsOf: [0x82, UInt8(body.count >> 8), UInt8(truncatingIfNeeded: body.count)])
        }
        result.append(body)
        return result
    }

    private static func signedMagnitude(_ bytes: Data) -> Data {
        let value = bytes.drop(while: { $0 == 0 })
        return (value.first ?? 0) >= 128 ? Data([0]) + value : value
    }
}
