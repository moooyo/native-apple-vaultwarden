# M1 Remaining (Xcode-gated) Implementation Plans

> **Status:** blueprint for the modules that require full Xcode + entitlements + a device/simulator and therefore **cannot be built or tested on this Command-Line-Tools-only host**. The pure-Swift core (CryptoCore, VaultModels, KeyVault, Generators, Fido2 — 315 passing checks) is already implemented, reviewed, and committed.
>
> **How to use:** each module below is its own subagent-driven task set when you're on a machine with Xcode. They are ordered by dependency. Each gives: target type, dependencies, public API, the load-bearing implementation details (with code for the tricky parts), required entitlements/Info.plist, and a verification recipe (XCTest/swift-testing become available with Xcode; UI verified in Simulator).
>
> **Cross-cutting conventions that change once Xcode is present:**
> - Tests can use **XCTest or swift-testing** (`import Testing`) instead of the executable `swift run` harness used for the core packages. Keep the golden-vector style.
> - Add an `.xcodeproj`/`.xcworkspace` (or keep SwiftPM for the libraries and an Xcode project for the App + Extension targets that need entitlements/signing). Recommended: libraries stay in `Package.swift`; the iOS App, macOS App, and AutoFill extension live in an Xcode project that depends on the local package.
> - Set the App Group `group.<bundleid>` and a shared Keychain access group on the main app AND the extension.

---

## Dependency order

```
AppShared ─┐
KeychainBridge ─┤ (need CryptoCore)
VaultStore ─────┤ (need CryptoCore, VaultModels)
Networking ─────┤ (need VaultModels)
SyncEngine ─────┤ (need CryptoCore, KeyVault, VaultStore, VaultModels, Networking)
VaultReader ────┤ (need CryptoCore, KeyVault, KeychainBridge, VaultStore, VaultModels, Fido2)
VaultRepository ┘ (need everything in L1/L2)
DesignSystem → UIShared → {UI-iOS, UI-mac} → {App-iOS, App-macOS, AutoFillExtension}
```

---

## A. AppShared (library, no deps)

**Purpose:** cross-target constants + small value types so app and extension agree on identifiers.
**Public API:**
```swift
public enum AppShared {
    public static let appGroupID = "group.dev.moooyo.tessera"          // set to your real group
    public static let keychainAccessGroup = "<TEAMID>.dev.moooyo.tessera.shared"
    public static let defaultServerURL = ""                            // empty → user must enter
}
public struct DeviceMetadata: Sendable {
    public let type: Int      // Bitwarden DeviceType: iOS=1, MacOsDesktop=7
    public let identifier: String   // stable UUID persisted in App Group UserDefaults
    public let name: String
}
public enum AutoLockTimeout: Int, Sendable, CaseIterable { case immediately = 0, oneMinute = 60, fiveMinutes = 300, fifteenMinutes = 900, oneHour = 3600, never = -1 }
public enum LogRedaction { public static func redact(_ s: String) -> String } // never log secrets
```
**Verification:** trivial unit tests; this can actually be built/tested headless too (no entitlements needed to read constants), so it can move earlier if convenient.

---

## B. KeychainBridge (library; needs CryptoCore; needs entitlements at runtime)

**Purpose:** the ONLY cross-process key channel — store the 64-byte UserKey wrapped by a Secure-Enclave key behind biometrics, in a shared Keychain access group, so both the app and the AutoFill extension can recover it with Face ID/Touch ID/Optic ID without the master password.

**Public API:**
```swift
public actor KeychainBridge {
    public init(accessGroup: String, service: String)
    /// Generates (once) an SE P-256 key gated by .biometryCurrentSet, ECIES-wraps the userKey,
    /// stores the ciphertext in the shared access group. Call after a successful master-password unlock.
    public func enableBiometricUnlock(userKey: SymmetricCryptoKey) throws
    /// Prompts biometrics (LAContext) and returns the unwrapped userKey, or throws if unavailable/denied.
    public func unlockWithBiometrics(reason: String) async throws -> SymmetricCryptoKey
    public func isBiometricUnlockEnabled() -> Bool
    public func disableBiometricUnlock()
    // Plain Keychain helpers (shared access group) for refresh token + local-auth hash + DB key:
    public func setSecret(_ data: Data, account: String, biometryGated: Bool) throws
    public func getSecret(account: String, context: LAContext?) throws -> Data?
    public func deleteSecret(account: String)
}
public enum KeychainError: Error, Equatable { case unavailable, userCanceled, notFound, duplicate, unexpected(OSStatus) }
```

**Load-bearing implementation details:**
- **SE key creation** (P-256, non-exportable, biometric + this-device-only):
```swift
var error: Unmanaged<CFError>?
let access = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
    kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
    [.privateKeyUsage, .biometryCurrentSet], &error)!   // .biometryCurrentSet invalidates on enrollment change
let attrs: [String: Any] = [
    kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
    kSecAttrKeySizeInBits as String: 256,
    kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
    kSecPrivateKeyAttrs as String: [
        kSecAttrIsPermanent as String: true,
        kSecAttrApplicationTag as String: tag.data(using: .utf8)!,
        kSecAttrAccessControl as String: access,
        kSecAttrAccessGroup as String: accessGroup,
    ],
]
let privKey = SecKeyCreateRandomKey(attrs as CFDictionary, &error)!  // private key STAYS in SE
```
- **ECIES wrap/unwrap** of the 64-byte userKey using the SE public key:
  `SecKeyCreateEncryptedData(pubKey, .eciesEncryptionStandardVariableIVX963SHA256AESGCM, userKeyData, &err)` and `SecKeyCreateDecryptedData(privKey, sameAlgo, ciphertext, &err)`. Decrypt triggers the biometric prompt because the private key is access-controlled.
- **Unlock**: build an `LAContext` (set `localizedReason`, optionally `touchIDAuthenticationAllowableReuseDuration`), pass via `kSecUseAuthenticationContext` when fetching/using the SE key. Map `errSecUserCanceled`/`LAError` to `.userCanceled`, `errSecItemNotFound` to `.notFound`.
- **Store the wrapped key** as a generic-password item with `kSecAttrAccessGroup = accessGroup`, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (the ciphertext itself doesn't need biometric gating — the SE key does).
- The DB passphrase (random 32 bytes) and refresh token are plain shared-access-group items; the local-auth hash (PBKDF2 iters=2 from `KDF.masterPasswordHash`) is stored for offline master-password verification.

**Entitlements:** `keychain-access-groups` = [`$(AppIdentifierPrefix)dev.moooyo.tessera.shared`]; App Groups; on both app + extension targets. Requires running on device/simulator with a provisioning profile.

**Verification (Xcode, on device/simulator):** enable → lock → `unlockWithBiometrics` returns the same key (use a simulator with enrolled biometrics, or gate behind `#if targetEnvironment(simulator)` test seams); wrong/absent biometrics → `.userCanceled`/`.unavailable`. Note: SE is unavailable on the iOS Simulator pre-A-series mac? On Apple-Silicon Macs the Simulator supports SE-backed keys; verify on the target.

**⚠️ Open item from research:** macOS Intel vs Apple-Silicon SE/Touch ID consistency — verify and provide a master-password fallback path.

---

## C. VaultStore (library; needs CryptoCore, VaultModels; SQLCipher via SPM)

**Purpose:** encrypted offline cache (GRDB + SQLCipher) in the App Group container. Stores E2E-encrypted cipher blobs + plaintext metadata + a local search index.

**Dependency setup (the fiddly part):** SQLCipher-over-SPM still needs care (research: GRDB 7.10+ makes it "possible but not easy"). Options:
1. Use **GRDB.swift** + the **SQLCipher** SPM product (`groue/GRDB.swift` with the `SQLCipher` trait), or
2. Vendor SQLCipher via a binary target / `groue/GRDBSQLCipher`.
Pin exact versions. Document the chosen approach in `Package.swift` comments.

**Public API:**
```swift
public actor VaultStore {
    public init(databaseURL: URL, passphrase: Data) throws   // passphrase from Keychain (random)
    public func upsertCiphers(_ rows: [CipherRow]) throws
    public func allCiphers(accountID: String) throws -> [CipherRow]
    public func cipher(id: String) throws -> CipherRow?
    public func deleteCipher(id: String) throws
    public func upsertFolders(_ rows: [FolderRow]) throws
    public func search(_ query: String, accountID: String) throws -> [CipherRow]   // over plaintext search_text
    public func setSyncState(_ s: SyncStateRow) throws ; public func syncState(accountID: String) throws -> SyncStateRow?
    public func enqueueOutbox(_ op: OutboxRow) throws ; public func outbox() throws -> [OutboxRow] ; public func clearOutbox(id: Int64) throws
}
```
`CipherRow`/`FolderRow`/etc. mirror the schema in the design spec §7.3 (enc_ columns = EncString wire strings; plaintext metadata columns for query/sort/sync).

**Load-bearing details:**
- `var config = Configuration(); config.prepareDatabase { db in try db.usePassphrase(passphrase) ; try db.execute(sql: "PRAGMA cipher_plaintext_header_size = 32") }` — the plaintext-header pragma + self-managed salt are required for the App Group shared container so app+extension can both open it.
- Use **WAL** mode + `NSFileCoordinator` around opens, and handle `0xDEAD10CC` (file-lock on suspend) by closing connections on `applicationWillResignActive`.
- Store the **search_text** column as plaintext-decrypted searchable text (names/usernames/uris) — it lives only inside the SQLCipher-encrypted DB. Build it when upserting (the repository decrypts then writes it).
- Store EncString fields as their wire `stringValue` (TEXT) — decryption happens in the repository/KeyVault, not here.

**Verification (Xcode):** open with a passphrase, upsert/read round-trip; reopen with wrong passphrase fails; concurrent app+extension access (two `DatabaseQueue`s) doesn't corrupt under WAL; search returns expected rows.

---

## D. Networking (library; needs VaultModels)

**Purpose:** URLSession async/await client for the Bitwarden/Vaultwarden REST API. Logic is unit-testable with a mocked `URLProtocol`; integration needs a running Vaultwarden (docker).

**Public API:**
```swift
public actor APIClient {
    public init(environment: ServerEnvironment, session: URLSession = .shared)
    public func prelogin(email: String) async throws -> PreloginResponse
    public func token(email: String, passwordHash: String, device: DeviceMetadata,
                      twoFactor: TwoFactorPayload?) async throws -> TokenResult   // .success(TokenResponse) | .twoFactorRequired(providers)
    public func refresh(refreshToken: String, device: DeviceMetadata) async throws -> TokenResponse
    public func sync(excludeDomains: Bool) async throws -> SyncResponse
    public func createCipher(_ req: CipherRequest) async throws -> CipherResponse
    public func updateCipher(id: String, _ req: CipherRequest) async throws -> CipherResponse
    public func deleteCipher(id: String) async throws
    public func folders() async throws -> [FolderResponse] /* + create/update/delete */
    public func attachmentUploadURL(cipherID: String, _ req: AttachmentRequest) async throws -> AttachmentUploadResponse
    public func uploadAttachment(to url: URL, cipherID: String, attachmentID: String, encryptedData: Data) async throws
    public func config() async throws -> ServerConfig ; public func alive() async throws -> Bool
}
public struct ServerEnvironment: Sendable { public var base: URL; public var identityURL: URL?; public var apiURL: URL? }  // allow split URLs + custom self-hosted
```

**Load-bearing details:**
- Two base paths: `/identity/*` (auth) and `/api/*` (vault). Allow user-entered self-hosted base URL; derive identity/api unless explicitly overridden.
- `token` is `application/x-www-form-urlencoded`: `grant_type=password`, `username`, `password=<server-auth hash>`, `scope=api offline_access`, `client_id=mobile`, `deviceType`, `deviceIdentifier`, `deviceName`. 2FA retry adds `twoFactorToken/twoFactorProvider/twoFactorRemember`. A first 400 with `TwoFactorProviders2` → `.twoFactorRequired`.
- Inject headers: `Device-Type`, `Bitwarden-Client-Name: mobile`, `Bitwarden-Client-Version: <semver>` (Vaultwarden's `ClientVersion` guard needs a realistic value), `Authorization: Bearer` for `/api/*`.
- Attachment v2: POST request body `{key,fileName,fileSize}` → response `{attachmentId,url,fileUploadType}` → upload encrypted blob to `url` (direct or Azure).
- Decode with `VaultJSON.decoder()` (case-insensitive) from VaultModels.
- `devicePushToken` registration is a **no-op** for self-hosted (no APNs).

**Verification:** unit tests with a stub `URLProtocol` returning canned JSON (assert request shape + response decode); an integration suite gated on `TESSERA_VW_URL` hitting a docker Vaultwarden.

---

## E. SyncEngine (library/actor; needs CryptoCore, KeyVault, VaultStore, VaultModels, Networking)

**Purpose:** revision-token incremental sync, no-push polling, conflict handling, and `ASCredentialIdentityStore` rebuild after each sync.

**Public API:**
```swift
public actor SyncEngine {
    public init(api: APIClient, store: VaultStore, keyVault: KeyVault, identityStore: CredentialIdentityWriting)
    public func fullSync(accountID: String) async throws -> SyncOutcome
    public func flushOutbox(accountID: String) async throws
    public func registerBackgroundRefresh()   // BGAppRefreshTask (iOS) / NSBackgroundActivityScheduler (macOS)
}
public protocol CredentialIdentityWriting: Sendable { func replace(_ identities: [CredentialIdentity]) async ; func incremental(add: [CredentialIdentity], remove: [CredentialIdentity]) async }
```

**Load-bearing details:**
- Algorithm: GET `/api/sync` → for each cipher compare server `revisionDate` vs stored; **skip-write-when-server-newer** is inverted here (write when server newer; protect local edits that are newer/pending in outbox). Flush outbox FIRST (`lastKnownRevisionDate` optimistic concurrency; on 400-stale, re-pull then re-apply).
- **soft-fail**: `SyncResponse` already drops bad EncString ciphers into `droppedCipherErrors`; log + surface a non-fatal warning, never abort the sync.
- After upserting decrypted rows, rebuild AutoFill identities: `getState` → if `supportsIncrementalUpdates` use incremental, else `replace`. Do this on a background task from the main app (more memory than the extension).
- Triggers: foreground, manual pull-to-refresh, timer while active, `BGAppRefreshTask` (register identifier in Info.plist `BGTaskSchedulerPermittedIdentifiers`), `NSBackgroundActivityScheduler` on macOS. `/alive` as a reachability probe.

**Verification:** unit-test the merge/conflict logic with in-memory fakes of APIClient + VaultStore; integration against docker VW: create on server → sync → row appears; edit locally offline → flush → server updated.

---

## F. VaultReader (library; extension's least-privilege facade) + AutoFillExtension

### VaultReader (needs CryptoCore, KeyVault, KeychainBridge, VaultStore, VaultModels, Fido2)
**Purpose:** the ONLY vault API the extension links — query credential identities, decrypt a SINGLE selected item, build a passkey assertion. No sync, no network, no bulk decrypt.
```swift
public actor VaultReader {
    public init(store: VaultStore, keyVault: KeyVault, keychain: KeychainBridge)
    public func unlockWithBiometrics(reason: String) async throws    // -> keyVault.unlock(userKey:)
    public func passwordCredential(for recordID: String) async throws -> (user: String, password: String)
    public func passkeyAssertion(recordID: String, rpId: String, clientDataHash: Data,
                                 userVerified: Bool) async throws -> ASPasskeyAssertionResult  // uses Fido2
    public func decryptOneCipher(id: String) async throws -> DecryptedCipher
}
```

### AutoFillExtension (App Extension target; needs VaultReader, KeychainBridge, VaultModels, Fido2, DesignSystem, AppShared)
**Purpose:** `ASCredentialProviderViewController` subclass. **Do NOT link** Networking/SyncEngine/Generators/VaultRepository/UIShared/UI-* (the ~120MB budget red line).

**Load-bearing lifecycle:**
- `provideCredentialWithoutUserInteraction(for:)` — if locked, immediately `extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: ASExtensionError.userInteractionRequired.rawValue))`. NEVER block on biometrics here.
- `prepareInterfaceToProvideCredential(for:)` — show unlock UI → `VaultReader.unlockWithBiometrics` → decrypt the ONE selected credential → `completeRequest(withSelectedCredential:)` (password) or `completeAssertionRequest(using: ASPasskeyAssertionCredential(...))` (passkey).
- `prepareCredentialList(for:)` / `prepareCredentialList(for:requestParameters:)` — show the picker; identities come from `ASCredentialIdentityStore` (populated by SyncEngine in the app).
- `prepareInterface(forPasskeyRegistration:)` — `Fido2Authenticator.register` → persist the new `fido2Credentials` entry (write-back path: enqueue to outbox via a minimal shared write, or require the app to sync — document the chosen approach) → `completeRegistrationRequest(using: ASPasskeyRegistrationCredential(...))`.
- Memory: decrypt only the selected item; release buffers after `completeRequest`.

**Entitlements/Info.plist:** capability "AutoFill Credential Provider" (`com.apple.developer.authentication-services.autofill-credential-provider`) on app + extension; `NSExtensionPointIdentifier = com.apple.authentication-services-credential-provider-ui`; `ASCredentialProviderExtensionCapabilities` = `{ProvidesPasswords:true, ProvidesPasskeys:true, ProvidesOneTimeCodes:true, ShowsConfigurationUI:true}`; App Group + shared Keychain group.

**Verification (device/simulator):** register the provider in Settings → Passwords; AutoFill into Safari/a test app; passkey create + assert against webauthn.io. Profile memory with Instruments to confirm < ~120MB.

---

## G. UI & App targets

### DesignSystem (library; SwiftUI; iOS/macOS 26)
Liquid Glass tokens + reusable views: `GlassScrim`, `ConcentricRectangleCard`, `OTPRingView` (uses `TOTP.secondsRemaining`), `SecureRevealView` (tap-to-reveal; renders password/TOTP/card on `.regular` material or solid scrim — **never clear glass**), and accessibility fallbacks reading `@Environment(\.accessibilityReduceTransparency)` / `differentiateWithoutColor` / `reduceMotion` to drop `.glassEffect` to `.identity`/opaque. Verify in Simulator under all three accessibility settings.

### UIShared (library; @Observable VMs; needs VaultRepository, Generators, DesignSystem)
`@Observable` models: `UnlockModel`, `VaultListModel`, `ItemDetailModel`, `GeneratorModel`, `SyncStatusModel`, `SettingsModel`. Logic only — no layout. Hide repositories behind protocols for testability (XCTest with mocks).

### UI-iOS (library; needs UIShared)
`TabView` (Vault/Generator/Send/Settings) + `Tab(role:.search)` + bottom `searchable`; opaque `List` rows + `ConcentricRectangle` cards; floating `.buttonStyle(.glassProminent)` "+"; `.tabBarMinimizeBehavior(.onScrollDown)` + `.tabViewBottomAccessory` unlock/sync pill; `.scrollEdgeEffectStyle`. M1: full iOS polish.

### UI-mac (library; needs UIShared)
Three-column `NavigationSplitView` (categories | list | detail) + `.inspector` (metadata/password history) + detail hero `.backgroundExtensionEffect()` + `ToolbarSpacer` glass capsules + `MenuBarExtra` quick-unlock/search/copy. M1: minimal usable three-column; deepen in M2.

### App-iOS / App-macOS (App targets; need UI-*, VaultRepository, AppShared)
Thin `@main` shells: scene lifecycle, background/timeout auto-lock observers, `BGAppRefreshTask` (iOS) / `NSBackgroundActivityScheduler` (macOS) registration, entitlements (App Group / Keychain group / AutoFill / Passkeys), and `ServiceContainer` wiring. Verify end-to-end in Simulator: add a self-hosted server URL → login (PBKDF2 account) → 2FA → sync → browse/search → view item (reveal password + TOTP) → create/edit → AutoFill into Safari → create+use a passkey.

---

## Milestone close-out checklist (when the above are done)
- [ ] End-to-end against a real docker Vaultwarden (PBKDF2 account): login, 2FA (Authenticator+Email), sync, CRUD all 5 item types, TOTP copy, attachment download (M2), AutoFill password + passkey.
- [ ] AutoFill extension memory < ~120MB on device (Instruments).
- [ ] Accessibility: Reduce Transparency / Increased Contrast / Reduce Motion verified on sensitive screens.
- [ ] Golden-vector CI green on a machine with the package tests; add the real-Vaultwarden fixture suites (CryptoCore + VaultModels Fixtures READMEs) gated by env vars.
- [ ] Trademark/naming review (product name "Tessera"; nominative "compatible with Bitwarden®" only).
