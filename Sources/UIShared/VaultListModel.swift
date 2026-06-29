import Foundation
import Observation
import VaultRepository

/// Drives the vault list: load all items, run a (debounce-friendly) search, and pull-to-
/// refresh via sync. Logic only — no SwiftUI. The view binds `query` and observes `items`.
@MainActor
@Observable
public final class VaultListModel {
    public private(set) var items: [PlaintextCipher] = []
    /// The search field bound by the view. Changing it does NOT auto-search — the view
    /// debounces then calls `search()` so this model stays free of timers.
    public var query: String = ""
    public private(set) var isLoading = false
    public private(set) var errorMessage: String?

    private let vault: VaultService

    public init(vault: VaultService) {
        self.vault = vault
    }

    /// Load all ciphers for the active account.
    public func load() async {
        isLoading = true
        errorMessage = nil
        do {
            items = try await vault.ciphers()
        } catch {
            errorMessage = Self.message(for: error)
        }
        isLoading = false
    }

    /// Run a search using the current `query`. An empty query reloads the full list. The
    /// view typically debounces keystrokes then calls this.
    public func search() async {
        let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { await load(); return }
        isLoading = true
        errorMessage = nil
        do {
            items = try await vault.search(trimmed)
        } catch {
            errorMessage = Self.message(for: error)
        }
        isLoading = false
    }

    /// Convenience for the view: set the query then search in one call.
    public func search(_ text: String) async {
        query = text
        await search()
    }

    /// Pull-to-refresh: sync with the server, then reload the (now-updated) local list.
    /// A sync failure surfaces `errorMessage` but still reloads what we have locally.
    public func refresh() async {
        isLoading = true
        errorMessage = nil
        do {
            _ = try await vault.sync()
        } catch {
            errorMessage = Self.message(for: error)
        }
        // Reload regardless of sync outcome so the list reflects local state.
        do {
            items = try await vault.ciphers()
        } catch {
            errorMessage = Self.message(for: error)
        }
        isLoading = false
    }
}
