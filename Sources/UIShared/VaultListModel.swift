import Foundation
import Observation
import VaultRepository

/// Drives the vault list: load all items, run a (debounce-friendly) search, and pull-to-
/// refresh via sync. Logic only — no SwiftUI. The view binds `query` and observes `items`.
@MainActor
@Observable
public final class VaultListModel {
    public private(set) var items: [PlaintextCipher] = []
    public private(set) var folders: [PlaintextFolder] = []
    public private(set) var archivedItems: [PlaintextCipher] = []
    public private(set) var trashedItems: [PlaintextCipher] = []
    /// The search field bound by the view. Changing it does NOT auto-search — the view
    /// debounces then calls `search()` so this model stays free of timers.
    public var query: String = ""
    public private(set) var isLoading = false
    public private(set) var errorMessage: String?
    public private(set) var hasLoadedContent = false

    public var canPresentCounts: Bool { hasLoadedContent && !isLoading && errorMessage == nil }

    private let vault: VaultService
    private var requestID: UInt64 = 0

    public init(vault: VaultService) {
        self.vault = vault
    }

    /// Load all ciphers for the active account.
    public func load(onResolved: (@MainActor () -> Void)? = nil) async {
        let request = beginRequest()
        let result: Result<VaultListing, Error>
        do {
            result = .success(try await vault.listing())
        } catch {
            result = .failure(error)
        }
        guard request == requestID else { return }
        isLoading = false
        guard !Task.isCancelled else { return }
        switch result {
        case .success(let listing):
            install(listing)
        case .failure(let error):
            clearDecryptedItems()
            errorMessage = Self.message(for: error)
        }
        onResolved?()
    }

    /// Run a search using the current `query`. An empty query reloads the full list. The
    /// view typically debounces keystrokes then calls this.
    public func search() async {
        let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { await load(); return }
        let request = beginRequest()
        defer { if request == requestID { isLoading = false } }
        do {
            let results = try await vault.search(trimmed)
            guard request == requestID, !Task.isCancelled else { return }
            items = results
            hasLoadedContent = true
        } catch {
            guard request == requestID, !Task.isCancelled else { return }
            clearDecryptedItems()
            errorMessage = Self.message(for: error)
        }
    }

    /// Convenience for the view: set the query then search in one call.
    public func search(_ text: String) async {
        query = text
        await search()
    }

    /// Reload while preserving the visible search filter.
    public func reloadCurrentView() async {
        if query.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            await load()
        } else {
            await search()
        }
    }

    public func clearDecryptedItems() {
        requestID &+= 1
        items = []
        archivedItems = []
        trashedItems = []
        folders = []
        hasLoadedContent = false
        isLoading = false
        errorMessage = nil
    }

    private func beginRequest() -> UInt64 {
        requestID &+= 1
        errorMessage = nil
        isLoading = true
        return requestID
    }

    private func install(_ listing: VaultListing) {
        items = listing.active
        archivedItems = listing.archived
        trashedItems = listing.trash
        folders = listing.folders
        hasLoadedContent = true
    }

    /// Pull-to-refresh: sync with the server, then reload the (now-updated) local list.
    /// A sync failure surfaces `errorMessage` but still reloads what we have locally.
    public func refresh() async {
        let request = beginRequest()
        defer { if request == requestID { isLoading = false } }
        var syncError: String?
        do {
            _ = try await vault.synchronize()
        } catch {
            syncError = Self.message(for: error)
        }
        guard request == requestID, !Task.isCancelled else { return }
        await reloadCurrentView()
        if requestID == (request &+ 1), errorMessage == nil { errorMessage = syncError }
    }
}
