# VaultModels Implementation Plan (M1 · Plan 2/N)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Build `VaultModels` — the Sendable, Codable wire/domain models for the Bitwarden/Vaultwarden API (prelogin, token, sync, ciphers + sub-objects, folders), with **case-insensitive key decoding** so the same models decode both Vaultwarden (camelCase) and official Bitwarden (PascalCase) JSON. EncString-typed fields decode straight into `CryptoCore.EncString`.

**Architecture:** A SwiftPM library target `VaultModels` depending on `CryptoCore`. Pure value types, no UIKit/AppKit/networking. A small `CaseInsensitiveCodingKey` + custom decoder strategy handles the casing split. EncString fields use `CryptoCore.EncString` (which gains `Codable` in Task 1). Tests follow the **same CLT-only executable-test convention as the CryptoCore plan** (no XCTest; `swift run VaultModelsTests`; `TestRunner` harness; `swift-tools-version: 6.2`).

**Tech Stack:** Swift 6 (`swift-tools-version: 6.2`), Foundation `Codable`, CryptoCore. Baseline iOS/macOS 26. Same toolchain as Plan 1.

> **⚠️ TESTING CONVENTION (identical to the CryptoCore plan — read its "ENVIRONMENT & TESTING CONVENTIONS" section).** No XCTest / no swift-testing on this CLT-only host. Add an `.executableTarget` `VaultModelsTests` and a copy of the `TestRunner` harness (or factor a shared one). Each task: add `checkXxx(_ r: inout TestRunner)` functions, register in `main.swift`, verify with `swift run VaultModelsTests` (exit 0 = pass). TDD: add check → watch fail → implement → watch pass → commit.

---

## File Structure

```
Package.swift                      # add VaultModels lib + VaultModelsTests executable targets
Sources/CryptoCore/EncStringCodable.swift   # NEW: EncString: Codable (string <-> wire)
Sources/VaultModels/
  Casing.swift            # CaseInsensitiveCodingKey + JSONDecoder/Encoder factory
  Enums.swift             # CipherType, FieldType, UriMatchType, SecureNoteType, SendType, LinkedIdType
  KdfConfig.swift         # Kdf config (PBKDF2-only domain note) + PreloginResponse
  TokenResponse.swift     # connect/token response
  Cipher.swift            # CipherResponse + nested Login/Card/Identity/SecureNote/SshKey
  LoginModels.swift       # LoginModel, LoginUriModel, Fido2CredentialModel
  Field.swift             # FieldModel
  Attachment.swift        # AttachmentModel
  Folder.swift            # FolderResponse
  Profile.swift           # ProfileResponse (+ minimal OrganizationModel for later)
  SyncResponse.swift      # SyncResponse (profile, folders, ciphers; collections/sends/policies optional)
Sources/VaultModelsTests/
  TestRunner.swift        # harness (copy of Plan 1's)
  main.swift              # runAllTests()
  TestJSON.swift          # synthetic JSON fixtures (camelCase + PascalCase)
  Checks_Casing.swift
  Checks_EncStringCodable.swift
  Checks_Cipher.swift
  Checks_Sync.swift
  Checks_Auth.swift
  Fixtures/README.md      # real-Vaultwarden /api/sync capture procedure
```

**Design decisions (locked):**
- **EncString fields** are typed `CryptoCore.EncString` (non-optional where always present, e.g. `name`; optional where nullable, e.g. `notes`). Decoding a malformed/unknown EncString must NOT crash the whole sync — see Task 6 soft-fail.
- **Casing**: decode with a custom `KeyDecodingStrategy` that lowercases keys, and models declare lowercased `CodingKeys` raw values. This accepts `camelCase`, `PascalCase`, and is robust to either server.
- **PBKDF2-only (D6)**: `KdfConfig` still models `kdfType/kdfIterations/kdfMemory/kdfParallelism` for fidelity, but the auth layer (later plan) rejects `kdfType != 0`. VaultModels itself does not enforce — it just models.
- **Unknown enum values** decode to a `.unknown(Int)`-style fallback (never throw) so a new server enum value doesn't break sync.

---

### Task 1: EncString gains Codable (in CryptoCore)

**Files:**
- Create: `Sources/CryptoCore/EncStringCodable.swift`
- Add checks: `Sources/CryptoCoreTests/Checks_EncStringCodable.swift` (register in CryptoCore's `main.swift`)

EncString is the natural Codable boundary: it encodes to its wire `stringValue` and decodes from a wire string via `init(parsing:)`.

- [ ] **Step 1: Add failing checks** (CryptoCore test target): decode `"2.<iv>|<ct>|<mac>"` from a JSON string value into a struct field of type `EncString`, assert round-trip equals; decoding an invalid string throws a decoding error.

- [ ] **Step 2: Run** `swift run CryptoCoreTests` → new checks FAIL.

- [ ] **Step 3: Implement**

```swift
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
```

- [ ] **Step 4: Run** `swift run CryptoCoreTests` → all pass.

- [ ] **Step 5: Commit**
```bash
git add Sources/CryptoCore/EncStringCodable.swift Sources/CryptoCoreTests/Checks_EncStringCodable.swift Sources/CryptoCoreTests/main.swift
git commit -m "feat(cryptocore): make EncString Codable (wire string <-> value)"
```

---

### Task 2: Package targets + casing infrastructure + test harness

**Files:**
- Modify: `Package.swift` (add `VaultModels` library target dep on `CryptoCore`; add `VaultModelsTests` executable target dep on `VaultModels` + `CryptoCore`, with `exclude: ["Fixtures"]`)
- Create: `Sources/VaultModels/Casing.swift`
- Create: `Sources/VaultModelsTests/TestRunner.swift` (copy Plan 1 harness), `Sources/VaultModelsTests/main.swift`, `Sources/VaultModelsTests/TestJSON.swift`
- Create: `Sources/VaultModelsTests/Checks_Casing.swift`

- [ ] **Step 1: Add failing check** — decode `{"Foo":1,"barBaz":2}` AND `{"foo":1,"BarBaz":2}` into a `struct S: Codable { let foo: Int; let barBaz: Int }` using the factory; both yield `foo==1, barBaz==2`.

- [ ] **Step 2: Run** `swift run VaultModelsTests` → FAIL (target/symbols missing).

- [ ] **Step 3: Implement** `Casing.swift`:

```swift
import Foundation

/// A coding key whose lookups are case-insensitive (matched by lowercased name),
/// so the same models decode Vaultwarden (camelCase) and Bitwarden (PascalCase) JSON.
public enum VaultJSON {
    public static func decoder() -> JSONDecoder {
        let d = JSONDecoder()
        d.keyDecodingStrategy = .custom { keys in
            let last = keys.last!
            return AnyCodingKey(stringValue: last.stringValue.lowercasedFirstScalarFold())
        }
        d.dateDecodingStrategy = .iso8601WithFractionalSeconds
        return d
    }
    public static func encoder() -> JSONEncoder {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .iso8601
        return e
    }
}

public struct AnyCodingKey: CodingKey {
    public let stringValue: String
    public let intValue: Int?
    public init(stringValue: String) { self.stringValue = stringValue; self.intValue = nil }
    public init(intValue: Int) { self.stringValue = String(intValue); self.intValue = intValue }
}

extension String {
    /// Fold a JSON key to a canonical lowercased form for case-insensitive matching.
    func lowercasedFirstScalarFold() -> String { lowercased() }
}

extension JSONDecoder.DateDecodingStrategy {
    /// Bitwarden/Vaultwarden emit ISO-8601 with fractional seconds; tolerate both.
    static var iso8601WithFractionalSeconds: JSONDecoder.DateDecodingStrategy {
        .custom { decoder in
            let s = try decoder.singleValueContainer().decode(String.self)
            let withFrac = ISO8601DateFormatter()
            withFrac.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            if let d = withFrac.date(from: s) { return d }
            let plain = ISO8601DateFormatter()
            plain.formatOptions = [.withInternetDateTime]
            if let d = plain.date(from: s) { return d }
            throw DecodingError.dataCorruptedError(in: try decoder.singleValueContainer(),
                debugDescription: "Bad ISO-8601 date: \(s)")
        }
    }
}
```
And models MUST declare lowercased `CodingKeys` raw values (e.g. `case revisionDate = "revisiondate"`). The harness `TestRunner.swift` and `main.swift` mirror Plan 1.

- [ ] **Step 4: Run** `swift run VaultModelsTests` → casing check passes.

- [ ] **Step 5: Commit**
```bash
git add Package.swift Sources/VaultModels/Casing.swift Sources/VaultModelsTests
git commit -m "feat(vaultmodels): add target + case-insensitive JSON decoding infra"
```

---

### Task 3: Enums (with unknown-value fallback)

**Files:** Create `Sources/VaultModels/Enums.swift`; add `Sources/VaultModelsTests/Checks_Enums.swift`.

- [ ] **Step 1: Failing checks** — `CipherType(rawValue:1) == .login`; decoding `99` yields `.unknown(99)` (no throw); `SecureNoteType`, `FieldType`, `UriMatchType`, `SendType`, `LinkedIdType` decode known values and fall back on unknown.

- [ ] **Step 2: Run** → FAIL.

- [ ] **Step 3: Implement** — model each as a Codable enum backed by Int with an `.unknown(Int)` case. Pattern:

```swift
public enum CipherType: Codable, Sendable, Equatable {
    case login, secureNote, card, identity, sshKey
    case unknown(Int)
    public init(from decoder: any Decoder) throws {
        let v = try decoder.singleValueContainer().decode(Int.self)
        switch v {
        case 1: self = .login
        case 2: self = .secureNote
        case 3: self = .card
        case 4: self = .identity
        case 5: self = .sshKey
        default: self = .unknown(v)
        }
    }
    public func encode(to encoder: any Encoder) throws {
        var c = encoder.singleValueContainer(); try c.encode(rawValue)
    }
    public var rawValue: Int {
        switch self {
        case .login: 1; case .secureNote: 2; case .card: 3
        case .identity: 4; case .sshKey: 5; case .unknown(let v): v
        }
    }
}
```
Apply the same shape to `SecureNoteType` (0 generic), `FieldType` (0 text,1 hidden,2 boolean,3 linked), `UriMatchType` (0 domain,1 host,2 startsWith,3 exact,4 regex,5 never), `SendType` (0 text,1 file), `LinkedIdType` (keep as Int wrapper — values are many; model as `struct LinkedId: RawRepresentable Codable`).

- [ ] **Step 4: Run** → pass. **Step 5: Commit** `feat(vaultmodels): add domain enums with unknown-value fallback`.

---

### Task 4: Auth models (prelogin, token, KdfConfig)

**Files:** Create `Sources/VaultModels/KdfConfig.swift`, `Sources/VaultModels/TokenResponse.swift`; add `Sources/VaultModelsTests/Checks_Auth.swift` + fixtures in `TestJSON.swift`.

- [ ] **Step 1: Failing checks** — decode a prelogin JSON (`{"kdf":0,"kdfIterations":600000,"kdfMemory":null,"kdfParallelism":null}`) into `PreloginResponse`; decode a token JSON with `access_token/expires_in/refresh_token/token_type/Key/PrivateKey/Kdf/KdfIterations` into `TokenResponse` (note: token uses snake_case for OAuth fields AND PascalCase for vault fields — casing strategy handles it; but `access_token` → `accesstoken` after fold, so CodingKey raw = `"access_token"` lowercased = `"access_token"`; ensure keys map). Verify `key` decodes to `EncString`.

- [ ] **Step 2: Run** → FAIL.

- [ ] **Step 3: Implement**:
```swift
public struct PreloginResponse: Codable, Sendable, Equatable {
    public let kdf: Int
    public let kdfIterations: Int
    public let kdfMemory: Int?
    public let kdfParallelism: Int?
    enum CodingKeys: String, CodingKey {
        case kdf, kdfIterations = "kdfiterations", kdfMemory = "kdfmemory", kdfParallelism = "kdfparallelism"
    }
}

public struct TokenResponse: Codable, Sendable {
    public let accessToken: String
    public let expiresIn: Int
    public let refreshToken: String?
    public let tokenType: String
    public let key: EncString?          // protected user key
    public let privateKey: EncString?   // RSA private key (type-2 wrapped)
    public let kdf: Int?
    public let kdfIterations: Int?
    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token", expiresIn = "expires_in"
        case refreshToken = "refresh_token", tokenType = "token_type"
        case key, privateKey = "privatekey", kdf, kdfIterations = "kdfiterations"
    }
}
```
> NOTE for implementer: the case-insensitive strategy lowercases incoming keys; CodingKeys raw values MUST therefore be the lowercased form of the wire key. Verify each against the fixtures; if the OAuth snake_case keys don't fold to your CodingKeys, adjust the CodingKeys raw value to the exact lowercased incoming string. Add a check that proves both a camelCase and PascalCase variant of the vault fields decode.

- [ ] **Step 4: Run** → pass. **Step 5: Commit** `feat(vaultmodels): add prelogin + token + kdf config models`.

---

### Task 5: Cipher + nested models + folder

**Files:** Create `Sources/VaultModels/Cipher.swift`, `LoginModels.swift`, `Field.swift`, `Attachment.swift`, `Folder.swift`; add `Checks_Cipher.swift` + fixtures.

- [ ] **Step 1: Failing checks** — decode a representative cipher JSON (a Login with uris[], totp, fido2Credentials[]) in BOTH camelCase and PascalCase; assert `type == .login`, `name` is an `EncString`, `login.username`/`login.password` are `EncString?`, `login.uris[0].uri` is `EncString`, `login.uris[0].match` is `UriMatchType?`, `revisionDate` is a `Date`, optional `notes`/`folderId` handled. Decode a `FolderResponse`.

- [ ] **Step 2: Run** → FAIL.

- [ ] **Step 3: Implement** the models. Field inventory (all EncString fields lowercased CodingKeys; all optionals where server may send null):
  - `CipherResponse`: id(String), organizationId(String?), folderId(String?), type(CipherType), name(EncString), notes(EncString?), favorite(Bool), reprompt(Int), edit(Bool?), viewPassword(Bool?), login(LoginModel?), card(CardModel?), identity(IdentityModel?), secureNote(SecureNoteModel?), sshKey(SshKeyModel?), fields([FieldModel]?), attachments([AttachmentModel]?), collectionIds([String]?), key(EncString?), revisionDate(Date), creationDate(Date?), deletedDate(Date?).
  - `LoginModel`: username(EncString?), password(EncString?), totp(EncString?), uris([LoginUriModel]?), fido2Credentials([Fido2CredentialModel]?), passwordRevisionDate(Date?).
  - `LoginUriModel`: uri(EncString?), match(UriMatchType?).
  - `Fido2CredentialModel`: credentialId(EncString?), keyType(EncString?), keyAlgorithm(EncString?), keyCurve(EncString?), keyValue(EncString?), rpId(EncString?), rpName(EncString?), userHandle(EncString?), userName(EncString?), userDisplayName(EncString?), counter(EncString?), discoverable(EncString?), creationDate(Date?). (All fields are EncString on the wire EXCEPT creationDate which is plaintext ISO-8601.)
  - `CardModel`: cardholderName, brand, number, expMonth, expYear, code — all `EncString?`.
  - `IdentityModel`: title, firstName, middleName, lastName, address1-3, city, state, postalCode, country, company, email, phone, ssn, username, passportNumber, licenseNumber — all `EncString?`.
  - `SecureNoteModel`: type(SecureNoteType).
  - `SshKeyModel`: privateKey(EncString?), publicKey(EncString?), keyFingerprint(EncString?).
  - `FieldModel`: type(FieldType), name(EncString?), value(EncString?), linkedId(Int?).
  - `AttachmentModel`: id(String?), url(String?), fileName(EncString?), key(EncString?), size(String?), sizeName(String?).
  - `FolderResponse`: id(String), name(EncString), revisionDate(Date).

- [ ] **Step 4: Run** → pass. **Step 5: Commit** `feat(vaultmodels): add cipher, login/card/identity/securenote/sshkey, folder models`.

---

### Task 6: SyncResponse + Profile + soft-fail decode wrapper

**Files:** Create `Sources/VaultModels/Profile.swift`, `Sources/VaultModels/SyncResponse.swift`; add `Checks_Sync.swift` + a full `/api/sync` fixture (camelCase) in `TestJSON.swift` and `Fixtures/README.md`.

- [ ] **Step 1: Failing checks** —
  (a) decode a full sync JSON (`{"profile":{...},"folders":[...],"ciphers":[...],"collections":[],"sends":[],"object":"sync"}`) into `SyncResponse`; assert counts.
  (b) **soft-fail**: a sync JSON where ONE cipher has an invalid EncString `name` (e.g. `"60.garbage"`) must still decode the OTHER ciphers — the bad one is dropped/flagged, sync does not throw. (Implement via a `FailableDecodable<T>` wrapper used for the `ciphers` array: decode each element independently; collect failures.)

- [ ] **Step 2: Run** → FAIL.

- [ ] **Step 3: Implement**:
```swift
/// Decodes T but never throws: on failure stores nil + the error, so one bad
/// element can't abort decoding an entire array (2026 protocol-split defense).
public struct Failable<T: Decodable & Sendable>: Decodable, Sendable {
    public let value: T?
    public let error: String?
    public init(from decoder: any Decoder) throws {
        do { value = try T(from: decoder); error = nil }
        catch { value = nil; self.error = String(describing: error) }
    }
}

public struct SyncResponse: Decodable, Sendable {
    public let profile: ProfileResponse
    public let folders: [FolderResponse]
    private let cipherSlots: [Failable<CipherResponse>]
    public let collections: [CollectionResponse]?
    public var ciphers: [CipherResponse] { cipherSlots.compactMap(\.value) }
    public var droppedCipherErrors: [String] { cipherSlots.compactMap(\.error) }
    enum CodingKeys: String, CodingKey {
        case profile, folders, cipherSlots = "ciphers", collections
    }
}
```
`ProfileResponse`: id(String), email(String), name(String?), key(EncString?), privateKey(EncString?), organizations([OrganizationModel]?), securityStamp(String?). `OrganizationModel` minimal: id, name(String?), key(EncString?) (full org handling is M2). `CollectionResponse` minimal: id, organizationId, name(EncString?).

- [ ] **Step 4: Run** → pass (including the soft-fail check: good ciphers survive, bad one in `droppedCipherErrors`).

- [ ] **Step 5: Commit** `feat(vaultmodels): add sync response + profile + soft-fail cipher decode`.

---

### Task 7: Real-Vaultwarden fixture procedure

**Files:** Create `Sources/VaultModelsTests/Fixtures/README.md`.

- [ ] **Step 1:** Document capturing a real `/api/sync` from a throwaway Vaultwarden (docker), saving as `Fixtures/sync-vaultwarden.json`, and a gated check (env `TESSERA_FIXTURES=1`) that decodes it and asserts no `droppedCipherErrors`. Same throwaway-account caution as the CryptoCore Fixtures README. Commit `test(vaultmodels): document real /api/sync fixture procedure`.

---

## Self-Review (author)
- Spec coverage (§5.1 VaultModels): models for Cipher+nested, Folder, Profile, Sync, prelogin/token, KdfConfig ✔; casing tolerance ✔; EncString fields → EncString ✔; soft-fail unknown EncString/cipher ✔ (Task 6); unknown enum fallback ✔ (Task 3). Org/Collection/Send modeled minimally (full handling M2/M3) — documented, not a gap.
- Placeholders: none; field inventories are explicit.
- Type consistency: `EncString` (CryptoCore, now Codable), `CipherType`/`UriMatchType`/`SecureNoteType`/`FieldType`, `Failable<T>`, `VaultJSON.decoder()` used consistently.

## Execution note
After VaultModels: per build order the next *fully CLT-testable* package is the logic of **KeyVault** (key hierarchy assembly, lock/zeroize) and **Generators** (TOTP/password) and **Fido2** (assertion/registration signing). **KeychainBridge, VaultStore(SQLCipher), AutoFillExtension, UI, App targets** need Xcode/entitlements → those get written plans, not executed here.
