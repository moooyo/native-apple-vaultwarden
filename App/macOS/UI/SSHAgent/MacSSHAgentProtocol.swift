import Foundation

enum MacSSHAgentProtocol {
    enum Request: Equatable, Sendable {
        case list
        case sign(key: Data, data: Data, flags: UInt32)
        case unsupported
        case rejectedBinding
    }

    static let maximumPacketSize = 256 * 1024
    static let failure = Data([5])

    static func request(_ packet: Data) -> Request {
        guard !packet.isEmpty, packet.count <= maximumPacketSize else { return .unsupported }
        var reader = MacSSHKeyReader(packet)
        do {
            switch try reader.bytes(1).first {
            case 11:
                return reader.isEmpty ? .list : .unsupported
            case 13:
                let key = try reader.string(maximum: 2048)
                let data = try reader.string(maximum: maximumPacketSize)
                let flags = try reader.uint32()
                guard reader.isEmpty, !key.isEmpty, [0, 2, 4, 6].contains(flags) else { return .unsupported }
                return .sign(key: key, data: data, flags: flags)
            case 27:
                guard try reader.name() == "session-bind@openssh.com" else { return .unsupported }
                let hostKey = try reader.string(maximum: 16 * 1024)
                let session = try reader.string(maximum: 256)
                let signature = try reader.string(maximum: 16 * 1024)
                let forwarding = try reader.bytes(1).first
                guard reader.isEmpty, !hostKey.isEmpty, !session.isEmpty, !signature.isEmpty, forwarding == 0 else {
                    return .rejectedBinding
                }
                return .unsupported
            default: return .unsupported
            }
        } catch {
            return packet.first == 27 ? .rejectedBinding : .unsupported
        }
    }

    static func identities(_ keys: [(blob: Data, label: String)]) -> Data {
        var entries = Data()
        var count: UInt32 = 0
        for (blob, label) in keys {
            let comment = Data(label.utf8.prefix(256))
            let entry = MacSSHKeyEncoding.string(blob) + MacSSHKeyEncoding.string(comment)
            guard entries.count + entry.count + 5 <= maximumPacketSize else { break }
            entries.append(entry)
            count += 1
        }
        return Data([12]) + uint32(count) + entries
    }

    static func signature(_ value: Data) -> Data {
        guard !value.isEmpty, value.count <= maximumPacketSize - 5 else { return failure }
        return Data([14]) + MacSSHKeyEncoding.string(value)
    }

    static func uint32(_ value: UInt32) -> Data {
        var value = value.bigEndian
        return withUnsafeBytes(of: &value) { Data($0) }
    }

    static func safeLabel(_ raw: String) -> String {
        let clean = raw.unicodeScalars.lazy.filter { !CharacterSet.controlCharacters.contains($0) }.prefix(64)
        return String(String.UnicodeScalarView(clean))
    }
}
