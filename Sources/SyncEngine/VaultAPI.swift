import Foundation
import VaultModels
import Networking

/// The subset of the network API that `SyncEngine` depends on.
///
/// Declaring a protocol (rather than taking `Networking.APIClient` directly)
/// gives the sync logic a test seam: the unit tests inject an in-memory fake
/// that records calls and returns canned responses / throws canned errors,
/// without any URLSession or live server.
///
/// `Networking.APIClient` is made to conform via an extension in this module
/// (see `APIClient+VaultAPI.swift`) so `Networking` itself stays untouched.
public protocol VaultAPI: Sendable {
    /// `GET /api/sync`.
    func sync(accountID: String, excludeDomains: Bool) async throws -> SyncResponse
    /// `POST /api/ciphers`.
    func createCipher(accountID: String, _ req: CipherRequest) async throws -> CipherResponse
    /// `PUT /api/ciphers/{id}`.
    func updateCipher(accountID: String, id: String, _ req: CipherRequest) async throws -> CipherResponse
    /// `DELETE /api/ciphers/{id}`.
    func deleteCipher(accountID: String, id: String) async throws
    /// `GET /api/folders`.
    func folders(accountID: String) async throws -> [FolderResponse]
}
