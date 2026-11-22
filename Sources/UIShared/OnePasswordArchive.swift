import Compression
import Foundation

enum OnePasswordArchive {
    static func payload(_ data: Data) throws -> Data {
        try VaultTransferCodec.checkSize(data)
        return try data.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) in
            let end = try endRecord(in: bytes)
            let count = word(bytes, end + 10)
            let directory = doubleWord(bytes, end + 16)
            guard word(bytes, end + 4) == 0, word(bytes, end + 6) == 0,
                  word(bytes, end + 8) == count,
                  directory + doubleWord(bytes, end + 12) == end else { throw VaultTransferError.invalidFile }
            guard (2...3).contains(count) else { throw VaultTransferError.unsupportedFile }
            var offset = directory
            var entries: [String: Range<Int>] = [:]
            var manifest: Data?
            var contents: Data?
            for _ in 0..<count {
                guard offset + 46 <= end, doubleWord(bytes, offset) == 0x02014b50 else {
                    throw VaultTransferError.invalidFile
                }
                let nameSize = word(bytes, offset + 28)
                let next = offset + 46 + nameSize + word(bytes, offset + 30) + word(bytes, offset + 32)
                guard next <= end, word(bytes, offset + 34) == 0,
                      let name = String(bytes: bytes[offset + 46..<offset + 46 + nameSize], encoding: .utf8) else {
                    throw VaultTransferError.invalidFile
                }
                guard ["export.attributes", "export.data", "files/"].contains(name) else {
                    throw VaultTransferError.unsupportedFile
                }
                let flags = word(bytes, offset + 8)
                let method = word(bytes, offset + 10)
                let packed = doubleWord(bytes, offset + 20)
                let unpacked = doubleWord(bytes, offset + 24)
                let local = doubleWord(bytes, offset + 42)
                guard flags & ~0x080e == 0, method == 0 || method == 8 else { throw VaultTransferError.unsupportedFile }
                guard local + 30 <= directory, doubleWord(bytes, local) == 0x04034b50,
                      word(bytes, local + 6) == flags, word(bytes, local + 8) == method,
                      word(bytes, local + 26) == nameSize else { throw VaultTransferError.invalidFile }
                let start = local + 30 + nameSize + word(bytes, local + 28)
                let entryRange = local..<start + packed
                guard entryRange.upperBound <= directory, entries[name] == nil,
                      !entries.values.contains(where: { $0.overlaps(entryRange) }),
                      bytes[local + 30..<local + 30 + nameSize].elementsEqual(name.utf8) else {
                    throw VaultTransferError.invalidFile
                }
                entries[name] = entryRange
                if name == "files/" {
                    guard unpacked == 0 else { throw VaultTransferError.unsupportedFile }
                } else {
                    let limit = name == "export.attributes" ? 65_536 : VaultTransferCodec.maximumBytes
                    guard unpacked <= limit else { throw VaultTransferError.fileTooLarge }
                    guard packed > 0, unpacked > 0, let base = bytes.baseAddress else { throw VaultTransferError.invalidFile }
                    let source = base.advanced(by: start).assumingMemoryBound(to: UInt8.self)
                    let result: Data
                    if method == 0 {
                        guard packed == unpacked else { throw VaultTransferError.invalidFile }
                        result = Data(bytes: source, count: unpacked)
                    } else {
                        var decoded = Data(count: unpacked + 1)
                        let actual = decoded.withUnsafeMutableBytes { (buffer: UnsafeMutableRawBufferPointer) in
                            compression_decode_buffer(buffer.bindMemory(to: UInt8.self).baseAddress!, buffer.count,
                                                      source, packed, nil, COMPRESSION_ZLIB)
                        }
                        guard actual == unpacked else { throw VaultTransferError.invalidFile }
                        decoded.removeLast()
                        result = decoded
                    }
                    guard checksum(result) == UInt32(doubleWord(bytes, offset + 16)) else { throw VaultTransferError.invalidFile }
                    if name == "export.attributes" { manifest = result } else { contents = result }
                }
                offset = next
            }
            guard offset == end, let manifest, let contents else { throw VaultTransferError.invalidFile }
            guard manifest.count + contents.count <= VaultTransferCodec.maximumBytes else { throw VaultTransferError.fileTooLarge }
            let header = try JSONDecoder().decode(Header.self, from: manifest)
            guard header.version == 3, header.description == "1Password Unencrypted Export" else { throw VaultTransferError.unsupportedFile }
            return contents
        }
    }

    private struct Header: Decodable { let version: Int; let description: String }

    private static func endRecord(in bytes: UnsafeRawBufferPointer) throws -> Int {
        guard bytes.count >= 22 else { throw VaultTransferError.invalidFile }
        for offset in stride(from: bytes.count - 22, through: max(0, bytes.count - 65_557), by: -1) {
            if doubleWord(bytes, offset) == 0x06054b50, offset + 22 + word(bytes, offset + 20) == bytes.count {
                return offset
            }
        }
        throw VaultTransferError.invalidFile
    }

    private static func word(_ bytes: UnsafeRawBufferPointer, _ offset: Int) -> Int {
        Int(bytes[offset]) | Int(bytes[offset + 1]) << 8
    }

    private static func doubleWord(_ bytes: UnsafeRawBufferPointer, _ offset: Int) -> Int {
        word(bytes, offset) | word(bytes, offset + 2) << 16
    }

    private static let crcTable = (0..<256).map { index in
        var value = UInt32(index)
        for _ in 0..<8 { value = value & 1 == 0 ? value >> 1 : (value >> 1) ^ 0xedb88320 }
        return value
    }

    private static func checksum(_ data: Data) -> UInt32 {
        ~data.reduce(UInt32.max) { ($0 >> 8) ^ crcTable[Int(($0 ^ UInt32($1)) & 255)] }
    }
}
