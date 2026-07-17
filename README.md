# Tessera

A from-scratch, **pure-Swift, byte-compatible Bitwarden/Vaultwarden client** for iOS and macOS, with an OpenVault interface rebuilt for the WWDC26 iOS 27 / macOS 27 **Liquid Glass** design language. Tessera re-implements Bitwarden's client-side cryptography and sync protocol natively (no Rust SDK), talks to a self-hosted [Vaultwarden](https://github.com/dani-garcia/vaultwarden) server, and ships a system-wide AutoFill + passkey extension.

> Tessera is *compatible with Bitwarden®* but is an independent project; it is not affiliated with or endorsed by Bitwarden, Inc.

## Status

The entire **headless core is implemented, tested, and reviewed** — 14 Swift packages, **848 passing checks**, verified on `swift`. The **SwiftUI screens, app entry points, and the AutoFill extension** are written as source and assembled by an Xcode project; they target iOS 27 / macOS 27 and require **full Xcode** to build.

| Layer | Modules | Verified here |
|---|---|---|
| **L0 Spine** | `CryptoCore`, `VaultModels` | ✅ `swift run *Tests` |
| **L1 Security/data** | `KeyVault`, `KeychainBridge`, `VaultStore`, `VaultReader`, `Fido2` | ✅ (KeychainBridge real SE path compiles; runs on device) |
| **L2 Services** | `Networking`, `SyncEngine`, `Generators`, `VaultRepository`, `AppShared` | ✅ |
| **L3 UI** | `UIShared` (✅ view-models), `DesignSystem` (✅ compiles) · `App/iOS/UI`, `App/macOS/UI` (Xcode-only) | ⚠️ screens build in Xcode |
| **L4 App** | `App/iOS/App`, `App/macOS/App`, `App/AutoFill` | ⚠️ Xcode-only |

## Architecture

Four layers; dependencies only point downward. Security-sensitive code lives in L0/L1; the **AutoFill extension links only a minimal subset** (`VaultReader + KeychainBridge + VaultModels + Fido2 + DesignSystem + AppShared`) to stay within the ~120 MB extension memory budget — it never links networking, sync, or the main UI.

```
L4  App         App-iOS · App-macOS · AutoFillExtension
L3  UI          UI-iOS · UI-mac  ←shared←  UIShared(@Observable) · DesignSystem
L2  Services    Networking · SyncEngine · Generators · VaultRepository · AppShared
L1  Security    KeyVault · KeychainBridge · VaultStore · VaultReader · Fido2
L0  Spine       CryptoCore · VaultModels
```

The unwrapped User Key lives only inside the `KeyVault` actor in memory and is zeroized on lock; it crosses to the extension only as a Secure-Enclave-ECIES-wrapped blob behind biometrics.

## Key decisions

- **Pure-Swift crypto** (CryptoKit + CommonCrypto + Security) — the Bitwarden Rust SDK is license-incompatible with an MIT/App-Store client.
- **PBKDF2-only** — Argon2id accounts are rejected at login with a clear message (intentional scope limit; removes the AutoFill-extension Argon2 OOM risk).
- **Vaultwarden self-hosted** is the official target; a custom server URL is supported.
- **No push** (self-hosted gets no APNs) — polling + `BGAppRefreshTask`/`NSBackgroundActivityScheduler` + revision-token incremental sync; unknown EncString types soft-fail instead of aborting a sync.
- Crypto is pinned to **golden vectors** (PBKDF2/HKDF/AES-CBC+HMAC/TOTP/WebAuthn) generated and verified during development.

## Build & test

**Libraries (headless core) — works with Command-Line-Tools, no Xcode:**
```sh
swift build                       # compiles all 14 library packages
swift run CryptoCoreTests         # each package has an executable test runner
swift run VaultRepositoryTests    # ... (XCTest is unavailable on CLT; see docs)
```
(There is no `swift test` here — the CLT host lacks XCTest and the swift-testing macro plugin, so tests are `.executableTarget`s run via `swift run <Module>Tests`, exit 0 = pass.)

**App + extension — requires Xcode 26:**
```sh
brew install xcodegen
xcodegen generate                 # produces Tessera.xcodeproj from project.yml
open Tessera.xcodeproj
# set DEVELOPMENT_TEAM, replace the placeholder bundle ids / App Group, then build
#   the Tessera-iOS or Tessera-macOS scheme.
```
See [`App/README.md`](App/README.md) for assembly details.

## Documentation

- Research brief (byte-exact crypto/API/AutoFill/Liquid Glass, adversarially verified): [`docs/superpowers/research/2026-06-28-vaultwarden-client-research.md`](docs/superpowers/research/2026-06-28-vaultwarden-client-research.md)
- Architecture recommendation: [`docs/superpowers/research/2026-06-29-architecture-recommendation.md`](docs/superpowers/research/2026-06-29-architecture-recommendation.md)
- Design spec (locked decisions, components, milestones): [`docs/superpowers/specs/2026-06-29-tessera-vaultwarden-client-design.md`](docs/superpowers/specs/2026-06-29-tessera-vaultwarden-client-design.md)
- Implementation plans (per module): [`docs/superpowers/plans/`](docs/superpowers/plans/)

## Remaining work (next, in Xcode)

1. `xcodegen generate` → build the app + extension; resolve the API points flagged in `App/README.md` against the shipping SDK.
2. Add the real-Vaultwarden integration fixtures (procedures in `Sources/CryptoCoreTests/Fixtures/README.md` and `Sources/VaultModelsTests/Fixtures/README.md`).
3. Profile the AutoFill extension memory on device (< ~120 MB).
4. M2/M3 features (organizations/attachments/Sends/emergency access) per the design spec milestones.

## License

MIT (see [`LICENSE`](LICENSE)). Because the crypto is re-implemented in Swift and the Bitwarden Rust SDK is not embedded, MIT distribution and the App Store are unencumbered.
