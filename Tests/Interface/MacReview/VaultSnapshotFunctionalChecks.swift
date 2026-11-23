import AppKit
import SwiftUI
import UIShared
import VaultModels
import VaultRepository

extension ReviewBoards {
    func checkVaultSnapshots(using renderer: WindowRenderer) async throws {
        let initial = PlaintextCipher(id: "kept", type: CipherType.secureNote.rawValue,
                                      name: "Zebra review note", notes: "Original review details", secureNote: .init())
        var updated = initial
        updated.notes = "Confirmed review details"
        let inserted = PlaintextCipher(id: "inserted", type: CipherType.secureNote.rawValue,
                                       name: "Aardvark review note", notes: "New first item details", secureNote: .init())
        let service = FakeVaultService(stored: [initial])
        let revision = ReviewVaultRevision()
        let sync = SyncStatusModel(vault: service, onSuccess: { await revision.advance() })
        let firstOutbox = ReviewVaultReadGate()
        let syncedListing = ReviewVaultReadGate()
        await service.beforeNextOutboxRead { await firstOutbox.suspend() }
        defer { Task { await firstOutbox.release(); await syncedListing.release() } }

        try await renderer.inspect(width: 1280, height: 800, title: "Vault") {
            ReviewVaultWindow(auth: auth, vault: service, sync: sync, revision: revision)
        } perform: { window in
            try await firstOutbox.waitUntilSuspended("The first vault outbox read did not start")
            _ = try await reviewAX(.staticText, named: "1 个条目", in: window)
            _ = try await reviewAX(.staticText, named: initial.notes, in: window)
            try require(sync.syncAttempt == 0, "the first item is selected before outbox status and sync complete")

            await service.setStored([inserted, updated])
            await service.beforeNextListing { await syncedListing.suspend() }
            await firstOutbox.release()
            try await syncedListing.waitUntilSuspended("The read following initial sync did not start")
            try require(sync.syncAttempt == 1, "initial sync requests a new local snapshot")
            _ = try await reviewAX(.staticText, named: "1 个条目", in: window)
            _ = try await reviewAX(.staticText, named: initial.notes, in: window)
            try require(reviewNode(.button, named: "mac.vault.retry", in: window) == nil,
                        "a pending refresh keeps the last successful snapshot without a retry prompt")

            await syncedListing.release()
            _ = try await reviewAX(.staticText, named: "2 个条目", in: window)
            _ = try await reviewAX(.staticText, named: updated.notes, in: window)
            try require(reviewNode(.staticText, named: inserted.notes, in: window) == nil,
                        "refresh keeps the selected ID when an earlier item arrives")

            await service.setCiphersError(RepositoryError.locked)
            revision.advance()
            let retry = try await reviewAX(.button, named: "mac.vault.retry", in: window)
            try require(reviewNode(.staticText, named: updated.notes, in: window) == nil
                        && reviewNode(.staticText, named: "2 个条目", in: window) == nil,
                        "a rejected read clears the prior detail and exact count")
            await service.setCiphersError(nil)
            try require(retry.accessibilityPerformPress?() == true, "retry the rejected refresh")
            _ = try await reviewAX(.staticText, named: "2 个条目", in: window)
            _ = try await reviewAX(.staticText, named: inserted.notes, in: window)
        }
        print("Vault snapshots: initial selection, stable pending sync refresh, retained selection and read failure recovery passed.")
    }
}

@MainActor @Observable private final class ReviewVaultRevision {
    private(set) var value: UInt64 = 0
    func advance() { value &+= 1 }
}

private struct ReviewVaultWindow: View {
    let auth: FakeAuthService
    let vault: FakeVaultService
    let sync: SyncStatusModel
    let revision: ReviewVaultRevision

    var body: some View {
        MacMainView(auth: auth, vault: vault, syncModel: sync, dataRevision: revision.value) {}
    }
}

actor ReviewVaultReadGate {
    private var continuation: CheckedContinuation<Void, Never>?
    private var released = false

    func suspend() async {
        guard !released else { return }
        await withCheckedContinuation { continuation = $0 }
    }

    func waitUntilSuspended(_ failure: String) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(3))
        while continuation == nil {
            guard ContinuousClock.now < deadline else { throw CheckFailure(message: failure) }
            try await Task.sleep(for: .milliseconds(40))
        }
    }

    func release() {
        released = true
        continuation?.resume()
        continuation = nil
    }
}
