import Foundation

/// Proof that the writable payload of a fresh sync item is covered by the cipher update DTO.
/// Keep this allowlist tied to the writer, not just to the more permissive read models.
package struct CipherKeyUpgradeMetadata: Sendable {
    package let revisionDate: String
    package let passwordRevisionDate: String?
    package let credentialCreationDates: [String?]

    private typealias Fields = KeyedDecodingContainer<AnyCodingKey>

    private static let envelope: Set<String> = [
        "id", "organizationid", "folderid", "type", "name", "notes", "favorite", "reprompt",
        "edit", "viewpassword", "login", "card", "identity", "securenote", "sshkey", "fields",
        "attachments", "collectionids", "key", "revisiondate", "creationdate", "deleteddate",
        "archiveddate", "object", "organizationusetotp", "passwordhistory", "data",
    ]
    private static let subtypeKeys = ["login", "card", "identity", "securenote", "sshkey"]
    private static let login: Set<String> = [
        "username", "password", "totp", "uris", "fido2credentials", "passwordrevisiondate",
        "autofillonpageload", "uri",
    ]
    private static let credential: Set<String> = [
        "credentialid", "keytype", "keyalgorithm", "keycurve", "keyvalue", "rpid", "rpname",
        "userhandle", "username", "userdisplayname", "counter", "discoverable", "creationdate",
    ]
    private static let card: Set<String> = ["cardholdername", "brand", "number", "expmonth", "expyear", "code"]
    private static let identity: Set<String> = [
        "title", "firstname", "middlename", "lastname", "address1", "address2", "address3",
        "city", "state", "postalcode", "country", "company", "email", "phone", "ssn", "username",
        "passportnumber", "licensenumber",
    ]

    init?(from decoder: any Decoder, cipher: CipherResponse) throws {
        guard cipher.key == nil, cipher.organizationId == nil,
              cipher.deletedDate == nil, cipher.archivedDate == nil,
              cipher.edit != false, cipher.viewPassword != false,
              (0...1).contains(cipher.reprompt),
              cipher.attachments?.isEmpty != false, cipher.collectionIds?.isEmpty != false else { return nil }

        let root = try decoder.container(keyedBy: AnyCodingKey.self)
        guard Self.hasOnly(root, Self.envelope), try Self.emptyArrayOrAbsent(root, "passwordhistory") else { return nil }
        if let object = try root.decodeIfPresent(String.self, forKey: Self.key("object")),
           !["cipher", "cipherdetails", "cipherminidetails"].contains(object.lowercased()) { return nil }
        // Server-owned organizational capability, not a personal cipher field.
        _ = try root.decodeIfPresent(Bool.self, forKey: Self.key("organizationusetotp"))

        let subtype: String
        let allowed: Set<String>
        switch cipher.type {
        case .login: (subtype, allowed) = ("login", Self.login)
        case .card: (subtype, allowed) = ("card", Self.card)
        case .identity: (subtype, allowed) = ("identity", Self.identity)
        case .secureNote:
            guard cipher.secureNote?.type == .generic else { return nil }
            (subtype, allowed) = ("securenote", ["type"])
        case .sshKey: (subtype, allowed) = ("sshkey", ["privatekey", "publickey", "keyfingerprint"])
        case .unknown: return nil
        }
        for other in Self.subtypeKeys where other != subtype {
            guard try Self.isAbsent(root, other) else { return nil }
        }
        let payload = try root.nestedContainer(keyedBy: AnyCodingKey.self, forKey: Self.key(subtype))
        guard Self.hasOnly(payload, allowed) else { return nil }

        for fields in try Self.objects(root, "fields") {
            guard Self.hasOnly(fields, ["type", "name", "value", "linkedid"]) else { return nil }
        }
        for field in cipher.fields ?? [] {
            if case .unknown = field.type { return nil }
        }

        var passwordRevisionDate: String?
        var credentialDates: [String?] = []
        var primaryURI: String?
        if subtype == "login" {
            guard try Self.isAbsent(payload, "autofillonpageload") else { return nil }
            for uri in try Self.objects(payload, "uris") {
                guard Self.hasOnly(uri, ["uri", "match", "urichecksum"]),
                      try Self.isAbsent(uri, "urichecksum") else { return nil }
                let wire = try uri.decode(String.self, forKey: Self.key("uri"))
                if primaryURI == nil { primaryURI = wire }
            }
            for uri in cipher.login?.uris ?? [] {
                if case .unknown? = uri.match { return nil }
            }
            if let singular = try payload.decodeIfPresent(String.self, forKey: Self.key("uri")),
               singular != primaryURI { return nil }
            for credential in try Self.objects(payload, "fido2credentials") {
                guard Self.hasOnly(credential, Self.credential) else { return nil }
                credentialDates.append(try credential.decodeIfPresent(String.self, forKey: Self.key("creationdate")))
            }
            passwordRevisionDate = try payload.decodeIfPresent(String.self, forKey: Self.key("passwordrevisiondate"))
        }

        // Some servers include a deprecated Data projection alongside the typed payload.
        // Do not assume it is redundant; prove that every value is already represented.
        if try !Self.isAbsent(root, "data") {
            let data = try root.nestedContainer(keyedBy: AnyCodingKey.self, forKey: Self.key("data"))
            for field in data.allKeys {
                switch field.stringValue {
                case "passwordhistory":
                    guard try Self.emptyArrayOrAbsent(data, "passwordhistory") else { return nil }
                case "uri" where subtype == "login":
                    if let uri = try data.decodeIfPresent(String.self, forKey: field), uri != primaryURI { return nil }
                case "autofillonpageload" where subtype == "login":
                    guard try Self.isAbsent(data, "autofillonpageload") else { return nil }
                case "name", "notes", "fields":
                    guard try Self.mirrors(field, from: data, in: root) else { return nil }
                default:
                    guard allowed.contains(field.stringValue),
                          try Self.mirrors(field, from: data, in: payload) else { return nil }
                }
            }
        }

        self.revisionDate = try root.decode(String.self, forKey: Self.key("revisiondate"))
        self.passwordRevisionDate = passwordRevisionDate
        self.credentialCreationDates = credentialDates
    }

    private static func key(_ value: String) -> AnyCodingKey { AnyCodingKey(stringValue: value) }

    private static func hasOnly(_ fields: Fields, _ allowed: Set<String>) -> Bool {
        fields.allKeys.allSatisfy { allowed.contains($0.stringValue) }
    }

    private static func isAbsent(_ fields: Fields, _ name: String) throws -> Bool {
        let key = Self.key(name)
        return try !fields.contains(key) || fields.decodeNil(forKey: key)
    }

    private static func emptyArrayOrAbsent(_ fields: Fields, _ name: String) throws -> Bool {
        try isAbsent(fields, name) || fields.nestedUnkeyedContainer(forKey: key(name)).isAtEnd
    }

    private static func objects(_ fields: Fields, _ name: String) throws -> [Fields] {
        guard try !isAbsent(fields, name) else { return [] }
        var array = try fields.nestedUnkeyedContainer(forKey: key(name))
        var objects: [Fields] = []
        while !array.isAtEnd { objects.append(try array.nestedContainer(keyedBy: AnyCodingKey.self)) }
        return objects
    }

    private static func mirrors(_ key: AnyCodingKey, from source: Fields, in canonical: Fields) throws -> Bool {
        let value = try source.decodeIfPresent(MirrorValue.self, forKey: key)
        return try value == canonical.decodeIfPresent(MirrorValue.self, forKey: key)
    }

    private enum MirrorValue: Decodable, Equatable {
        case null, text(Data), boolean(Bool), integer(Int)
        case object([String: Self]), list([Self])

        init(from decoder: any Decoder) throws {
            if let object = try? decoder.container(keyedBy: AnyCodingKey.self) {
                var values: [String: Self] = [:]
                for key in object.allKeys {
                    guard values.updateValue(try object.decode(Self.self, forKey: key), forKey: key.stringValue) == nil else {
                        throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath,
                                                                debugDescription: "Duplicate cipher projection field"))
                    }
                }
                self = .object(values)
            } else if var list = try? decoder.unkeyedContainer() {
                var values: [Self] = []
                while !list.isAtEnd { values.append(try list.decode(Self.self)) }
                self = .list(values)
            } else {
                let value = try decoder.singleValueContainer()
                if value.decodeNil() { self = .null }
                else if let text = try? value.decode(String.self) { self = .text(Data(text.utf8)) }
                else if let boolean = try? value.decode(Bool.self) { self = .boolean(boolean) }
                else { self = .integer(try value.decode(Int.self)) }
            }
        }
    }
}
