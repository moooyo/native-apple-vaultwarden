import Foundation
import VaultRepository

actor FixtureSendService: VaultSendService {
    private enum Failure: Error { case missing, unsupportedKind, invalidURL }
    private var records: [String: VaultSend] = [:]

    func listSends() async throws -> [VaultSend] {
        records.values.sorted { $0.revisionDate > $1.revisionDate }
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
