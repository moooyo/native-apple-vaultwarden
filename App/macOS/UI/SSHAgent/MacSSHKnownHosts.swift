import Darwin
import Foundation

/// A verified binding authenticates a key, not a DNS name. Only a unique, explicit
/// known_hosts pin can supply the display name. Hashed, pattern and CA entries do not.
struct MacSSHKnownHosts: Sendable {
    private static let maximumFileBytes = 1_048_576
    private let names: [Data: String]

    init(files: [String]) {
        var names: [Data: Set<String>] = [:]
        var revoked: Set<Data> = []
        var nonliteral: Set<Data> = []
        for file in files {
            for line in file.split(whereSeparator: \.isNewline) {
                let columns = line.split(maxSplits: 4, whereSeparator: \.isWhitespace)
                guard let first = columns.first, !first.hasPrefix("#") else { continue }
                let marked = first.hasPrefix("@")
                let offset = marked ? 1 : 0
                guard columns.count >= 3 + offset,
                      columns[offset + 2].utf8.count <= 4 * 1024,
                      let key = Data(base64Encoded: String(columns[offset + 2])) else { continue }
                var reader = MacSSHKeyReader(key)
                guard (try? reader.name()) == String(columns[offset + 1]) else { continue }
                if first == "@revoked" { revoked.insert(key) }
                if marked { continue }
                for field in first.split(separator: ",") {
                    guard let name = Self.literalName(field) else { nonliteral.insert(key); continue }
                    names[key, default: []].insert(name)
                }
            }
        }
        self.names = names.compactMapValues { $0.count == 1 ? $0.first : nil }.filter {
            !revoked.contains($0.key) && !nonliteral.contains($0.key)
        }
    }

    func host(for key: Data) -> String? { names[key] }

    static func systemPins() -> Self {
        // These are pre-existing, administrator-managed pins. Sandbox restrictions or an
        // unreadable file yield Unknown; no ~/.ssh entitlement or network lookup is needed.
        Self(files: ["/etc/ssh/ssh_known_hosts", "/etc/ssh/ssh_known_hosts2"].compactMap(readPins))
    }

    private static func readPins(_ path: String) -> String? {
        let descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
        guard descriptor >= 0 else { return nil }
        defer { close(descriptor) }
        var info = stat()
        guard fstat(descriptor, &info) == 0, info.st_uid == 0, info.st_mode & 0o022 == 0,
              info.st_mode & S_IFMT == S_IFREG, (1...off_t(maximumFileBytes)).contains(info.st_size) else { return nil }
        var data = Data(count: Int(info.st_size) + 1)
        let length = data.withUnsafeMutableBytes { Darwin.read(descriptor, $0.baseAddress, $0.count) }
        guard length == info.st_size else { return nil }
        return String(data: data.prefix(length), encoding: .utf8)
    }

    private static func literalName(_ field: Substring) -> String? {
        let address: Substring
        if field.hasPrefix("[") {
            guard let end = field.firstIndex(of: "]"), field[field.index(after: end)...].hasPrefix(":"),
                  let port = UInt16(field[field.index(end, offsetBy: 2)...]), port > 0 else { return nil }
            address = field[field.index(after: field.startIndex)..<end]
        } else {
            address = field
        }
        guard (1...253).contains(address.utf8.count), address.utf8.allSatisfy({ byte in
            switch byte {
            case 45, 46, 48...57, 58, 65...90, 95, 97...122: true
            default: false
            }
        }) else { return nil }
        return field.lowercased()
    }
}
