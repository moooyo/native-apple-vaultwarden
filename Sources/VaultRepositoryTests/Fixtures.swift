import Foundation
import CryptoCore
import VaultModels
import VaultStore
import KeyVault
import KeychainBridge
import Networking
import SyncEngine
import VaultRepository

/// Test fixtures for the repository layer: a deterministic master-password account whose
/// protected user key really decrypts under the derived stretched master key (so login
/// genuinely unlocks the vault), plus temp-DB stores and a fake API wiring.
enum Fixtures {
    static let email = "user@example.test"
    static let password = "correct horse battery staple"
    static let iterations = 600_000
    static let server = ServerEnvironment(string: "https://vault.example.test")!

    /// The synthetic 64-byte user key the protected key wraps.
    static func userKeyData() -> Data { Data((0..<64).map { UInt8(($0 * 7 + 3) & 0xff) }) }
    static func userKey() -> SymmetricCryptoKey { try! SymmetricCryptoKey(combined: userKeyData()) }

    /// A deterministic personal per-item key plus its user-key-protected wire form.
    static func cipherKeyData() -> Data { Data((0..<64).map { UInt8(($0 * 11 + 5) & 0xff) }) }
    static func cipherKey() -> SymmetricCryptoKey {
        try! SymmetricCryptoKey(combined: cipherKeyData())
    }
    static func protectedCipherKey() -> EncString {
        try! SymmetricCrypto.encrypt(cipherKeyData(), using: userKey())
    }

    /// The stretched master key derived from (password, email, iterations) — the key the
    /// protected user key is encrypted under in a real Bitwarden account.
    static func stretchedMasterKey() -> SymmetricCryptoKey {
        let mk = try! KDF.deriveMasterKey(password: password, email: email, iterations: iterations)
        return KeyStretch.stretchMasterKey(mk)
    }

    /// The protected user key wire string: type-2 EncString of the 64-byte user key,
    /// encrypted under the stretched master key. `KeyVault.unlock(password:…)` decrypts this.
    static func protectedUserKeyWire() -> String {
        let e = try! SymmetricCrypto.encrypt(userKeyData(), using: stretchedMasterKey())
        return e.stringValue
    }

    /// Encrypt a string under the user key, returning the wire string (for seeding store rows).
    static func enc(_ s: String) -> String {
        try! SymmetricCrypto.encrypt(Data(s.utf8), using: userKey()).stringValue
    }

    /// Encrypt a string under the deterministic personal per-item key.
    static func cipherEnc(_ s: String) -> String {
        try! SymmetricCrypto.encrypt(Data(s.utf8), using: cipherKey()).stringValue
    }

    static func iso(_ date: Date) -> String {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f.string(from: date)
    }

    // MARK: - Stores / keychain

    static func freshStore() async throws -> (VaultStore, URL) {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("vaultrepo-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let url = dir.appendingPathComponent("vault.sqlite")
        let store = try VaultStore(databaseURL: url, passphrase: Data("test-passphrase".utf8))
        return (store, dir)
    }

    static func cleanup(_ dir: URL) { try? FileManager.default.removeItem(at: dir) }

    // MARK: - Responses

    /// A `PreloginResponse` for a PBKDF2 (`kdf == 0`) account.
    static func prelogin(kdf: Int = 0) -> PreloginResponse {
        PreloginResponse(kdf: kdf, kdfIterations: iterations, kdfMemory: nil, kdfParallelism: nil)
    }

    /// A successful `TokenResponse` carrying the protected user key.
    static func tokenResponse(accessToken: String = "access-1",
                              refreshToken: String? = "refresh-1") -> TokenResponse {
        let key = try! EncString(parsing: protectedUserKeyWire())
        return TokenResponse(accessToken: accessToken, expiresIn: 3600, refreshToken: refreshToken,
                             tokenType: "Bearer", key: key, privateKey: nil, kdf: 0,
                             kdfIterations: iterations)
    }

    /// A 2FA-required token result with the given providers.
    static func twoFactorResult(_ providerIDs: [Int]) -> TokenResult {
        let providers = TwoFactorProviders(providerIDs: providerIDs, raw: [:])
        return .twoFactorRequired(providers)
    }

    /// A `SyncResponse` JSON with one login cipher, decodable via the case-insensitive decoder.
    static func syncResponse(cipherID: String, name: String, username: String, uri: String) -> SyncResponse {
        let json = """
        {"profile":{"id":"profile-1","email":"\(email)","name":"Test",
          "key":"\(enc("k"))","privateKey":"\(enc("pk"))","securityStamp":"stamp","organizations":[]},
         "folders":[],
         "ciphers":[{"id":"\(cipherID)","organizationId":null,"folderId":null,"type":1,
           "name":"\(enc(name))","notes":null,"favorite":false,"reprompt":0,"edit":true,"viewPassword":true,
           "login":{"username":"\(enc(username))","password":"\(enc("pw"))","totp":null,
             "uris":[{"uri":"\(enc(uri))","match":null}],"fido2Credentials":null,"passwordRevisionDate":null},
           "card":null,"identity":null,"secureNote":null,"sshKey":null,"fields":null,
           "attachments":null,"collectionIds":null,"key":null,
           "revisionDate":"\(iso(Date()))","creationDate":"2026-01-01T00:00:00.000Z","deletedDate":null}],
         "collections":[],"sends":[],"policies":[],"domains":null}
        """
        return try! VaultJSON.decoder().decode(SyncResponse.self, from: Data(json.utf8))
    }

    // MARK: - Wiring

    /// Build a fully-wired repository set sharing one KeyVault + encryptor + store + API.
    struct Harness {
        let api: FakeAPI
        let auth: AuthRepository
        let vault: VaultRepository
        let syncEngine: SyncEngine
        let keyVault: KeyVault
        let store: VaultStore
        let keychain: KeychainBridge
        let dir: URL
    }

    static func makeHarness(tokenResults: [TokenResult],
                            kdf: Int = 0) async throws -> Harness {
        let (store, dir) = try await freshStore()
        let api = FakeAPI(preloginResponse: prelogin(kdf: kdf), tokenResults: tokenResults)
        let keyVault = KeyVault()
        let encryptor = UserKeyEncryptor()
        let keychain = makeFakeKeychain()
        let auth = AuthRepository(api: api, keyVault: keyVault, keychain: keychain,
                                  store: store, encryptor: encryptor)
        let mutationCoordinator = VaultMutationCoordinator()
        let syncEngine = SyncEngine(
            api: api,
            store: store,
            keyVault: keyVault,
            identityStore: FakeIdentityStore(),
            mutationCoordinator: mutationCoordinator
        )
        let vault = VaultRepository(api: api, store: store, keyVault: keyVault, encryptor: encryptor,
                                    syncEngine: syncEngine,
                                    mutationCoordinator: mutationCoordinator,
                                    accountLease: { await auth.currentSessionLease() },
                                    lockHandler: { await auth.lock() })
        return Harness(api: api, auth: auth, vault: vault, syncEngine: syncEngine,
                       keyVault: keyVault,
                       store: store, keychain: keychain, dir: dir)
    }
}
