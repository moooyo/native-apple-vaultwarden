import Foundation
import VaultRepository

actor FixtureSendService: VaultSendService {
    enum ExternalChange: String {
        case offline = "--fixture-send-offline"
        case removeHandoff = "--fixture-send-remove-handoff"
        case revokeAccessThenRecover = "--fixture-send-revoke-then-recover"
    }

    private enum Failure: Error { case missing, unsupportedKind, invalidURL }
    private var records: [String: VaultSend] = [:]
    private(set) var listReadCount = 0
    private var readError: RepositoryError?
    private var nextReadErrors: [RepositoryError] = []
    private static let offline = RepositoryError.underlying(kind: .network, description: "Simulated offline Send refresh")
    var metadataCount: Int { records.count }

    init() {
        let now = Date.now
        let entries: [(String, String, VaultSendKind)] = [
            ("handoff", "Design handoff", .text), ("preview", "Prototype preview", .file), ("notes", "Studio notes", .text)
        ]
        for (index, entry) in entries.enumerated() {
            let (id, name, kind) = entry
            guard let url = URL(string: "https://vault.example.com/#/send/\(id)") else { continue }
            records[id] = VaultSend(id: id, kind: kind, name: name, text: kind == .text ? "Review information for the studio." : nil,
                                    fileName: kind == .file ? "Preview.pdf" : nil, deletionDate: now.addingTimeInterval(604_800),
                                    expirationDate: index == 2 ? now.addingTimeInterval(-3_600) : nil,
                                    accessCount: index + 1, maxAccessCount: 5, hasPassword: index == 0,
                                    shareURL: url, revisionDate: now.addingTimeInterval(-Double(index + 1) * 86_400))
        }
    }

    func listSends() async throws -> [VaultSend] {
        listReadCount += 1
        if !nextReadErrors.isEmpty { throw nextReadErrors.removeFirst() }
        if let readError { throw readError }
        return records.values.sorted { $0.revisionDate > $1.revisionDate }
    }

    func setReadError(_ error: RepositoryError?) { readError = error }

    func apply(_ change: ExternalChange) {
        switch change {
        case .offline:
            readError = Self.offline
        case .removeHandoff:
            records.removeValue(forKey: "handoff")
            readError = nil
        case .revokeAccessThenRecover:
            records.removeValue(forKey: "notes")
            readError = nil
            nextReadErrors = [.notAuthenticated, Self.offline]
        }
    }

    func createSend(_ draft: VaultSendDraft) async throws -> VaultSend {
        try save(id: UUID().uuidString, draft: draft)
    }

    func updateSend(id: String, draft: VaultSendDraft) async throws -> VaultSend {
        guard records[id] != nil else { throw Failure.missing }
        return try save(id: id, draft: draft)
    }

    func deleteSend(id: String) async throws {
        guard records.removeValue(forKey: id) != nil else { throw Failure.missing }
    }

    private func save(id: String, draft: VaultSendDraft) throws -> VaultSend {
        guard draft.kind == .text else { throw Failure.unsupportedKind }
        guard let url = URL(string: "https://fixture.invalid/#/send/\(id)") else { throw Failure.invalidURL }
        let hasPassword = !draft.removePassword && (draft.password?.isEmpty == false || records[id]?.hasPassword == true)
        let record = VaultSend(id: id, kind: draft.kind, name: draft.name, text: draft.text,
                               hideText: draft.hideText, deletionDate: draft.deletionDate,
                               expirationDate: draft.expirationDate, maxAccessCount: draft.maxAccessCount,
                               hasPassword: hasPassword, hideEmail: draft.hideEmail, disabled: draft.disabled,
                               shareURL: url, revisionDate: .now, notes: draft.notes)
        records[id] = record
        return record
    }
}
