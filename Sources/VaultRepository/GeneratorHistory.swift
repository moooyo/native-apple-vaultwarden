import Foundation

public struct GeneratorHistoryEntry: Identifiable, Codable, Equatable, Sendable {
    public enum Kind: String, Codable, CaseIterable, Hashable, Sendable {
        case password, passphrase, username
    }

    public static let limit = 100
    public let id: UUID
    public let kind: Kind
    public let value: String
    public let date: Date

    public init(kind: Kind, value: String, date: Date = .now) {
        self.id = UUID()
        self.kind = kind
        self.value = value
        self.date = date
    }
}

public struct GeneratorHistorySnapshot: Sendable {
    public let session: AccountSessionLease
    public let entries: [GeneratorHistoryEntry]

    public init(session: AccountSessionLease, entries: [GeneratorHistoryEntry]) {
        self.session = session
        self.entries = entries
    }
}

public protocol GeneratorHistoryService: Sendable {
    func generatorHistory() async throws -> GeneratorHistorySnapshot
    func addGeneration(_ entry: GeneratorHistoryEntry, session: AccountSessionLease) async throws
    func clearGeneratorHistory(session: AccountSessionLease) async throws
}

extension VaultRepository: GeneratorHistoryService {}
