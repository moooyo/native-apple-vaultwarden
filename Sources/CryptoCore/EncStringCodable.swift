import Foundation

extension EncString: Codable {
    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        let raw = try container.decode(String.self)
        do { self = try EncString(parsing: raw) }
        catch {
            throw DecodingError.dataCorruptedError(in: container,
                debugDescription: "Invalid EncString: \(raw.prefix(8))…")
        }
    }
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(stringValue)
    }
}
