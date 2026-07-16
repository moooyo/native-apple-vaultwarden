import Foundation

/// Process-wide async mutex shared by sync/outbox work and repository mutations.
///
/// Swift actors are reentrant at every network/store `await`; separate SyncEngine and
/// VaultRepository actors therefore do not prevent an outbox row from being changed while its
/// POST is in flight. This coordinator serializes those state machines without blocking a thread.
public actor VaultMutationCoordinator {
    private var isHeld = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    public init() {}

    public func withLock<T: Sendable>(
        _ operation: @Sendable () async throws -> T
    ) async rethrows -> T {
        await acquire()
        defer { release() }
        return try await operation()
    }

    private func acquire() async {
        guard isHeld else {
            isHeld = true
            return
        }
        await withCheckedContinuation { continuation in
            waiters.append(continuation)
        }
    }

    private func release() {
        if waiters.isEmpty {
            isHeld = false
        } else {
            waiters.removeFirst().resume()
        }
    }
}
