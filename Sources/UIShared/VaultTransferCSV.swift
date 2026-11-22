import Foundation
import VaultModels
import VaultRepository

public enum VaultCSVSource: Sendable { case bitwarden, apple, browser }

extension VaultTransferCodec {
    private static let exportHeader = ["folder", "favorite", "type", "name", "notes", "fields", "reprompt", "login_uri", "login_username", "login_password", "login_totp"]

    public static func encodeCSV(_ archive: VaultTransferArchive) -> Data {
        let names = Dictionary(archive.folders.map { ($0.id, $0.name) }, uniquingKeysWith: { first, _ in first })
        var lines = [exportHeader.joined(separator: ",")]
        for item in archive.items where item.organizationID == nil && item.deletedDate == nil {
            let type = CipherType(rawValue: item.type)
            guard type == .login || type == .secureNote else { continue }
            let fields = item.fields.map { "\($0.name ?? ""): \($0.value ?? "")" }.joined(separator: "\n")
            let row = [item.folderID.flatMap { names[$0] } ?? "", item.favorite ? "1" : "",
                       type == .login ? "login" : "note", item.name, item.notes ?? "", fields,
                       String(item.reprompt), item.login?.uris.map(\.uri).joined(separator: ",") ?? "",
                       item.login?.username ?? "", item.login?.password ?? "", item.login?.totp ?? ""]
            lines.append(row.map { "\"\($0.replacingOccurrences(of: "\"", with: "\"\""))\"" }.joined(separator: ","))
        }
        return Data((lines.joined(separator: "\r\n") + "\r\n").utf8)
    }

    public static func decodeCSV(_ data: Data, source: VaultCSVSource) throws -> VaultTransferArchive {
        try checkSize(data)
        let rows = try csvRows(data)
        guard let header = rows.first else { throw VaultTransferError.emptyFile }
        let keys = header.map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
        guard Set(keys).count == keys.count else { throw VaultTransferError.invalidFile }
        let required: Set<String> = switch source {
        case .bitwarden: ["type", "name", "login_username", "login_password"]
        case .apple: ["title", "url", "username", "password"]
        case .browser: ["name", "url", "username", "password"]
        }
        guard required.isSubset(of: Set(keys)), !keys.contains("collections") else { throw VaultTransferError.unsupportedFile }
        var folderIDs: [String: String] = [:]
        var items: [PlaintextCipher] = []
        for row in rows.dropFirst() {
            guard row.count == keys.count else { throw VaultTransferError.invalidFile }
            let values = Dictionary(uniqueKeysWithValues: zip(keys, row))
            func value(_ key: String) -> String? { values[key].flatMap { $0.isEmpty ? nil : $0 } }
            if source == .bitwarden {
                let folderID = value("folder").map { name -> String in
                    let id = folderIDs[name] ?? UUID().uuidString
                    folderIDs[name] = id
                    return id
                }
                let type: CipherType = switch value("type")?.lowercased() {
                case "login": .login
                case "note": .secureNote
                default: throw VaultTransferError.unsupportedItem
                }
                guard let name = value("name") else { throw VaultTransferError.invalidFile }
                let fields = try (value("fields") ?? "").split(whereSeparator: \.isNewline).map { line -> PlaintextCipher.Field in
                    guard let colon = line.firstIndex(of: ":") else { throw VaultTransferError.invalidFile }
                    var payload = line[line.index(after: colon)...]
                    if payload.first == " " { payload = payload.dropFirst() }
                    return .init(type: FieldType.text.rawValue, name: String(line[..<colon]), value: String(payload))
                }
                let login: PlaintextCipher.Login? = type == .login ? .init(username: value("login_username"), password: value("login_password"), totp: value("login_totp"), uris: (value("login_uri") ?? "").split(separator: ",").map { .init(uri: String($0)) }) : nil
                items.append(.init(type: type.rawValue, name: name, notes: value("notes"), folderID: folderID,
                                   favorite: value("favorite") == "1", reprompt: Int(value("reprompt") ?? "0") ?? 0,
                                   login: login, secureNote: type == .secureNote ? .init() : nil, fields: fields))
            } else {
                let website = value("url")
                guard let name = value(source == .apple ? "title" : "name") ?? website ?? value("username") else {
                    throw VaultTransferError.invalidFile
                }
                let login = PlaintextCipher.Login(username: value("username"), password: value("password"),
                                                  totp: source == .apple ? value("otpauth") : nil,
                                                  uris: website.map { [.init(uri: $0)] } ?? [])
                items.append(.init(name: name, notes: value("notes") ?? value("note"), login: login))
            }
        }
        return try validated(.init(folders: folderIDs.map { .init(id: $0.value, name: $0.key) }, items: items))
    }

    private static func csvRows(_ data: Data) throws -> [[String]] {
        let bytes = [UInt8](data)
        var index = bytes.starts(with: [0xEF, 0xBB, 0xBF]) ? 3 : 0
        var all: [[String]] = []
        var row: [String] = []
        var field: [UInt8] = []
        var quoted = false
        var closed = false
        func finishField() throws {
            guard row.count < 64, let string = String(bytes: field, encoding: .utf8) else { throw VaultTransferError.invalidFile }
            row.append(string)
            field.removeAll(keepingCapacity: true)
            closed = false
        }
        func finishRow() throws {
            try finishField()
            if row.count > 1 || row.first != "" { all.append(row) }
            guard all.count <= maximumRecords + 1 else { throw VaultTransferError.fileTooLarge }
            row.removeAll(keepingCapacity: true)
        }
        while index < bytes.count {
            let byte = bytes[index]
            index += 1
            if quoted {
                if byte != 34 { field.append(byte); continue }
                if index < bytes.count, bytes[index] == 34 { field.append(34); index += 1; continue }
                quoted = false
                closed = true
            } else {
                switch byte {
                case 34 where field.isEmpty && !closed: quoted = true
                case 44: try finishField()
                case 10, 13:
                    if byte == 13, index < bytes.count, bytes[index] == 10 { index += 1 }
                    try finishRow()
                default:
                    guard !closed, byte != 34 else { throw VaultTransferError.invalidFile }
                    field.append(byte)
                }
            }
        }
        guard !quoted else { throw VaultTransferError.invalidFile }
        if !row.isEmpty || !field.isEmpty || closed { try finishRow() }
        return all
    }
}
