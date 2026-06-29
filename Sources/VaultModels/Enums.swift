import Foundation

/// Cipher kind. Unknown server values decode to `.unknown(Int)` (never throw),
/// so a new server enum value can't break sync.
public enum CipherType: Codable, Sendable, Equatable {
    case login, secureNote, card, identity, sshKey
    case unknown(Int)

    public init(from decoder: any Decoder) throws {
        self.init(rawValue: try decoder.singleValueContainer().decode(Int.self))
    }
    public func encode(to encoder: any Encoder) throws {
        var c = encoder.singleValueContainer(); try c.encode(rawValue)
    }
    public init(rawValue v: Int) {
        switch v {
        case 1: self = .login
        case 2: self = .secureNote
        case 3: self = .card
        case 4: self = .identity
        case 5: self = .sshKey
        default: self = .unknown(v)
        }
    }
    public var rawValue: Int {
        switch self {
        case .login: 1
        case .secureNote: 2
        case .card: 3
        case .identity: 4
        case .sshKey: 5
        case .unknown(let v): v
        }
    }
}

/// Secure-note kind. Only `generic` (0) is currently defined.
public enum SecureNoteType: Codable, Sendable, Equatable {
    case generic
    case unknown(Int)

    public init(from decoder: any Decoder) throws {
        self.init(rawValue: try decoder.singleValueContainer().decode(Int.self))
    }
    public func encode(to encoder: any Encoder) throws {
        var c = encoder.singleValueContainer(); try c.encode(rawValue)
    }
    public init(rawValue v: Int) {
        switch v {
        case 0: self = .generic
        default: self = .unknown(v)
        }
    }
    public var rawValue: Int {
        switch self {
        case .generic: 0
        case .unknown(let v): v
        }
    }
}

/// Custom-field kind.
public enum FieldType: Codable, Sendable, Equatable {
    case text, hidden, boolean, linked
    case unknown(Int)

    public init(from decoder: any Decoder) throws {
        self.init(rawValue: try decoder.singleValueContainer().decode(Int.self))
    }
    public func encode(to encoder: any Encoder) throws {
        var c = encoder.singleValueContainer(); try c.encode(rawValue)
    }
    public init(rawValue v: Int) {
        switch v {
        case 0: self = .text
        case 1: self = .hidden
        case 2: self = .boolean
        case 3: self = .linked
        default: self = .unknown(v)
        }
    }
    public var rawValue: Int {
        switch self {
        case .text: 0
        case .hidden: 1
        case .boolean: 2
        case .linked: 3
        case .unknown(let v): v
        }
    }
}

/// Login URI match strategy.
public enum UriMatchType: Codable, Sendable, Equatable {
    case domain, host, startsWith, exact, regex, never
    case unknown(Int)

    public init(from decoder: any Decoder) throws {
        self.init(rawValue: try decoder.singleValueContainer().decode(Int.self))
    }
    public func encode(to encoder: any Encoder) throws {
        var c = encoder.singleValueContainer(); try c.encode(rawValue)
    }
    public init(rawValue v: Int) {
        switch v {
        case 0: self = .domain
        case 1: self = .host
        case 2: self = .startsWith
        case 3: self = .exact
        case 4: self = .regex
        case 5: self = .never
        default: self = .unknown(v)
        }
    }
    public var rawValue: Int {
        switch self {
        case .domain: 0
        case .host: 1
        case .startsWith: 2
        case .exact: 3
        case .regex: 4
        case .never: 5
        case .unknown(let v): v
        }
    }
}

/// Send kind (minimal — full Send handling is a later milestone).
public enum SendType: Codable, Sendable, Equatable {
    case text, file
    case unknown(Int)

    public init(from decoder: any Decoder) throws {
        self.init(rawValue: try decoder.singleValueContainer().decode(Int.self))
    }
    public func encode(to encoder: any Encoder) throws {
        var c = encoder.singleValueContainer(); try c.encode(rawValue)
    }
    public init(rawValue v: Int) {
        switch v {
        case 0: self = .text
        case 1: self = .file
        default: self = .unknown(v)
        }
    }
    public var rawValue: Int {
        switch self {
        case .text: 0
        case .file: 1
        case .unknown(let v): v
        }
    }
}

/// Linked-field identifier. Values are many and vary by cipher type, so this is
/// a thin Int wrapper rather than an enumerated set.
public struct LinkedIdType: RawRepresentable, Codable, Sendable, Equatable {
    public let rawValue: Int
    public init(rawValue: Int) { self.rawValue = rawValue }
    public init(from decoder: any Decoder) throws {
        self.rawValue = try decoder.singleValueContainer().decode(Int.self)
    }
    public func encode(to encoder: any Encoder) throws {
        var c = encoder.singleValueContainer(); try c.encode(rawValue)
    }
}
