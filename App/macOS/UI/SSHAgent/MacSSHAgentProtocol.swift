import CryptoKit
import Foundation

enum MacSSHAgentProtocol {
    enum Request: Equatable, Sendable {
        case list
        case sign(key: Data, data: Data, flags: UInt32)
        case bind(SessionBinding)
        case unsupported
        case rejectedBinding
    }

    enum Destination: Equatable, Sendable {
        case local
        case host(fingerprint: String, name: String?)

        var hostName: String? {
            if case let .host(_, name) = self { return name }
            return nil
        }
    }

    struct SessionBinding: Equatable, Sendable {
        let hostKey: Data
        let sessionID: Data
        let signature: Data

        var isVerified: Bool { MacSSHSigningKey.verifyHostSignature(signature, for: sessionID, hostKey: hostKey) }

        func matchesUserAuthentication(_ message: Data, userKey: Data, flags: UInt32) -> Bool {
            var reader = MacSSHKeyReader(message)
            var key = MacSSHKeyReader(userKey)
            do {
                guard try reader.string(maximum: 256) == sessionID, try reader.bytes(1).first == 50,
                      !(try reader.string(maximum: 1024)).isEmpty, try reader.name() == "ssh-connection" else { return false }
                let method = try reader.name()
                guard method == "publickey" || method == "publickey-hostbound-v00@openssh.com",
                      try reader.bytes(1).first == 1 else { return false }
                let format = try key.name()
                let algorithm = switch (format, flags) {
                case ("ssh-rsa", 2), ("ssh-rsa", 6): "rsa-sha2-256"
                case ("ssh-rsa", 4): "rsa-sha2-512"
                default: format
                }
                guard try reader.name() == algorithm, try reader.string(maximum: 2048) == userKey else { return false }
                if method != "publickey", try reader.string(maximum: 16 * 1024) != hostKey { return false }
                return reader.isEmpty
            } catch { return false }
        }
    }

    static let maximumPacketSize = 256 * 1024
    static let failure = Data([5])
    static let success = Data([6])

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
                return .bind(SessionBinding(hostKey: hostKey, sessionID: session, signature: signature))
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

    static func fingerprint(of publicKeyBlob: Data) -> String {
        "SHA256:" + Data(SHA256.hash(data: publicKeyBlob)).base64EncodedString().replacingOccurrences(of: "=", with: "")
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
