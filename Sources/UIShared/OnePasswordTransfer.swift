import Foundation
import VaultModels
import VaultRepository

public enum OnePasswordTransfer {
    public static func decode(_ data: Data) throws -> VaultTransferArchive {
        do {
            let payload = try OnePasswordArchive.payload(data)
            let document = try JSONDecoder().decode(Document.self, from: payload)
            guard document.accounts.count == 1, let account = document.accounts.first else { throw VaultTransferError.unsupportedFile }
            var folders: [PlaintextFolder] = []
            var items: [PlaintextCipher] = []
            for vault in account.vaults {
                guard ["P", "U"].contains(vault.attrs.type) else { throw VaultTransferError.unsupportedFile }
                guard items.count + vault.items.count <= VaultTransferCodec.maximumRecords else { throw VaultTransferError.fileTooLarge }
                folders.append(.init(id: vault.attrs.uuid, name: vault.attrs.name))
                for item in vault.items { items.append(try cipher(from: item, folder: vault.attrs.uuid)) }
            }
            return try VaultTransferCodec.validated(.init(folders: folders, items: items))
        } catch let error as VaultTransferError {
            throw error
        } catch {
            throw VaultTransferError.invalidFile
        }
    }

    private static func cipher(from item: Item, folder: String) throws -> PlaintextCipher {
        guard item.state == "active", item.file == nil else { throw VaultTransferError.unsupportedItem }
        var cipher = PlaintextCipher(name: item.overview.title, notes: item.details.notesPlain, folderID: folder,
                                     favorite: (item.favIndex ?? 0) > 0)
        switch item.categoryUuid {
        case "001", "005": cipher.login = .init()
        case "002": cipher.type = CipherType.card.rawValue; cipher.card = .init()
        case "003": cipher.type = CipherType.secureNote.rawValue; cipher.secureNote = .init()
        case "004": cipher.type = CipherType.identity.rawValue; cipher.identity = .init()
        default: throw VaultTransferError.unsupportedItem
        }
        for tag in item.overview.tags ?? [] { append(tag, named: "Tag", to: &cipher) }
        var addresses: Set<String> = []
        let links = (item.overview.urls ?? []) + [Link(label: nil, url: item.overview.url ?? "")]
        for link in links where !link.url.isEmpty {
            if addresses.insert(link.url).inserted {
                if cipher.login != nil { cipher.login?.uris.append(.init(uri: link.url)) }
                else { append(link.url, named: "Website", to: &cipher) }
            }
            if let label = link.label, !label.isEmpty { append(link.url, named: label, to: &cipher) }
        }
        for field in item.details.loginFields ?? [] where !field.value.isEmpty {
            if field.designation == "username", cipher.login != nil, cipher.login?.username == nil {
                cipher.login?.username = field.value
            } else if field.designation == "password", cipher.login != nil, cipher.login?.password == nil {
                cipher.login?.password = field.value
            } else {
                let name = [field.name, field.id, field.designation].compactMap { $0 }.first { !$0.isEmpty } ?? "Form field"
                append(field.value, named: name, secret: field.fieldType == "P" || field.designation == "password", to: &cipher)
            }
        }
        if let password = item.details.password, !password.isEmpty, cipher.login?.password != password {
            if cipher.login != nil, cipher.login?.password == nil { cipher.login?.password = password }
            else { append(password, named: "Password", secret: true, to: &cipher) }
        }
        for section in item.details.sections ?? [] {
            for field in section.fields ?? [] { try apply(field, section: section.title ?? "", to: &cipher) }
        }
        for entry in item.details.passwordHistory ?? [] {
            append(entry.value, named: "Previous password (\(entry.time))", secret: true, to: &cipher)
        }
        return cipher
    }

    private static func apply(_ field: SectionField, section: String, to cipher: inout PlaintextCipher) throws {
        let name = [section, field.title?.isEmpty == false ? field.title : field.id]
            .compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: " / ")
        let label = name.isEmpty ? "Field" : name
        let secret = field.guarded == true || ["concealed", "totp", "creditCardNumber"].contains(field.value.kind)
        if let components = field.value.components {
            for (key, value) in components.sorted(by: { $0.key < $1.key }) where !value.isEmpty {
                if var identity = cipher.identity,
                   set(identityField(key, for: field.value.kind), in: &identity, to: value) {
                    cipher.identity = identity
                } else {
                    append(value, named: "\(label) / \(key)", secret: secret, to: &cipher)
                }
            }
            return
        }
        guard let value = field.value.text, !value.isEmpty else { return }
        let identifier = field.id ?? ""
        if var login = cipher.login {
            let target: WritableKeyPath<PlaintextCipher.Login, String?>?
            if field.value.kind == "totp" || identifier.hasPrefix("TOTP_") { target = \.totp }
            else if identifier == "username" { target = \.username }
            else if identifier == "password" { target = \.password }
            else { target = nil }
            if set(target, in: &login, to: value) { cipher.login = login; return }
        } else if var card = cipher.card {
            let target: WritableKeyPath<PlaintextCipher.Card, String?>? = switch identifier {
            case "ccnum": \.number
            case "cvv": \.code
            case "cardholder": \.cardholderName
            case "type": \.brand
            default: nil
            }
            if set(target, in: &card, to: value) { cipher.card = card; return }
            if identifier == "expiry", card.expMonth == nil, card.expYear == nil,
               value.count == 6, value.allSatisfy(\.isNumber), let month = Int(value.suffix(2)), (1...12).contains(month) {
                card.expMonth = String(month)
                card.expYear = String(value.prefix(4))
                cipher.card = card
                return
            }
        } else if var identity = cipher.identity, set(identityField(identifier, for: ""), in: &identity, to: value) {
            cipher.identity = identity
            return
        }
        append(value, named: label, secret: secret || ["cvv", "password"].contains(identifier), to: &cipher)
    }

    private static func set<Record>(_ key: WritableKeyPath<Record, String?>?, in record: inout Record, to value: String) -> Bool {
        guard let key, record[keyPath: key] == nil else { return false }
        record[keyPath: key] = value
        return true
    }

    private static func identityField(_ identifier: String, for kind: String) -> WritableKeyPath<PlaintextCipher.Identity, String?>? {
        switch (kind, identifier) {
        case ("address", "street"): \.address1
        case ("address", "city"): \.city
        case ("address", "state"): \.state
        case ("address", "zip"): \.postalCode
        case ("address", "country"): \.country
        case ("email", "email_address"), ("", "email"): \.email
        case ("", "firstname"): \.firstName
        case ("", "initial"): \.middleName
        case ("", "lastname"): \.lastName
        case ("", "company"): \.company
        case ("", "defphone"): \.phone
        case ("", "username"): \.username
        default: nil
        }
    }

    private static func append(_ value: String, named name: String, secret: Bool = false, to cipher: inout PlaintextCipher) {
        if !value.isEmpty { cipher.fields.append(.init(type: (secret ? FieldType.hidden : .text).rawValue, name: name, value: value)) }
    }
}

private struct Document: Decodable { let accounts: [Account] }
private struct Account: Decodable { let vaults: [Vault] }
private struct Vault: Decodable { let attrs: Attributes; let items: [Item] }
private struct Attributes: Decodable { let uuid: String; let name: String; let type: String }
private struct Item: Decodable {
    let state: String
    let categoryUuid: String
    let favIndex: Int?
    let details: Details
    let overview: Overview
    let file: FileMarker?
    struct FileMarker: Decodable {}
}
private struct Overview: Decodable { let title: String; let url: String?; let urls: [Link]?; let tags: [String]? }
private struct Link: Decodable { let label: String?; let url: String }
private struct FormField: Decodable { let name: String?; let id: String?; let designation: String?; let fieldType: String?; let value: String }
private struct ItemSection: Decodable { let title: String?; let fields: [SectionField]? }
private struct SectionField: Decodable { let title: String?; let id: String?; let guarded: Bool?; let value: FieldValue }
private struct HistoryEntry: Decodable { let value: String; let time: Int64 }

private struct AnyKey: CodingKey {
    let stringValue: String
    var intValue: Int? { nil }
    init(stringValue: String) { self.stringValue = stringValue }
    init?(intValue: Int) { return nil }
}

private struct Details: Decodable {
    let notesPlain: String?
    let loginFields: [FormField]?
    let password: String?
    let sections: [ItemSection]?
    let passwordHistory: [HistoryEntry]?

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: AnyKey.self)
        let supported = ["notesPlain", "loginFields", "password", "sections", "passwordHistory"]
        for key in container.allKeys where !supported.contains(key.stringValue) {
            if try !container.decodeNil(forKey: key) { throw VaultTransferError.unsupportedItem }
        }
        notesPlain = try container.decodeIfPresent(String.self, forKey: .init(stringValue: "notesPlain"))
        loginFields = try container.decodeIfPresent([FormField].self, forKey: .init(stringValue: "loginFields"))
        password = try container.decodeIfPresent(String.self, forKey: .init(stringValue: "password"))
        sections = try container.decodeIfPresent([ItemSection].self, forKey: .init(stringValue: "sections"))
        passwordHistory = try container.decodeIfPresent([HistoryEntry].self, forKey: .init(stringValue: "passwordHistory"))
    }
}

private struct FieldValue: Decodable {
    let kind: String
    let text: String?
    let components: [String: String]?

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: AnyKey.self)
        guard container.allKeys.count == 1, let key = container.allKeys.first else { throw VaultTransferError.unsupportedItem }
        kind = key.stringValue
        switch kind {
        case "string", "concealed", "phone", "menu", "gender", "url", "totp", "creditCardType", "creditCardNumber":
            text = try container.decodeIfPresent(String.self, forKey: key)
            components = nil
        case "monthYear", "date":
            text = try container.decodeIfPresent(Int64.self, forKey: key).map { String($0) }
            components = nil
        case "address", "email":
            text = nil
            components = try container.decodeIfPresent([String: String?].self, forKey: key)?.compactMapValues { $0 }
        default:
            throw VaultTransferError.unsupportedItem
        }
    }
}
