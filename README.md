# OpenVault

OpenVault is a native Swift client for self-hosted [Vaultwarden](https://github.com/dani-garcia/vaultwarden).
It implements the Bitwarden client protocol without embedding the Bitwarden SDK. The Xcode project
and Swift package are named `Tessera`. This project is independent of Bitwarden, Inc.

| Edition | Runs on | Setup |
| --- | --- | --- |
| Standalone Mac | macOS 26+ | [Build and install on your Mac](App/README.md#local-mac-without-a-developer-account). No developer account needed. Uses master-password unlock and manual copy. |
| Full app with AutoFill | iOS/iPadOS 27+ or macOS 27+ | [Configure the app and extension](App/README.md#full-edition-with-autofill). Requires a signing team and shared entitlements for system AutoFill and biometric unlock. |

Both editions support personal vaults, TOTP codes, password and passphrase generation, and
offline edits to logins, secure notes, cards, identities, and SSH keys. Sign-in requires a
**PBKDF2** account; Argon2id is not supported. Organizations, attachments, Sends and emergency
access are outside the current feature set.

## Architecture

The code is grouped into five responsibility bands with deliberately narrow SwiftPM target
dependencies. Security-sensitive code lives in L0/L1. The **AutoFill extension directly depends
only on a minimal subset** (`VaultReader + KeychainBridge + VaultModels + Fido2 + DesignSystem +
AppShared + PasskeyHandoff`); their transitive read/crypto stack includes `CryptoCore`, `KeyVault`,
`VaultStore`, and lightweight `Generators`. It never links networking, sync, the repository, or
the main UI, which keeps it suitable for the system's roughly 120 MB extension memory budget.

```
L4  App         App-iOS · App-macOS · AutoFillExtension
L3  UI          UI-iOS · UI-mac  ←shared←  UIShared(@Observable) · DesignSystem
L2  Services    Networking · SyncEngine · Generators · VaultRepository · AppShared
L1  Security    KeyVault · KeychainBridge · VaultStore · VaultReader · Fido2 · PasskeyHandoff
L0  Spine       CryptoCore · VaultModels
```

The unwrapped User Key lives only inside the `KeyVault` actor in memory and is zeroized on lock; it crosses to the extension only as a Secure-Enclave-ECIES-wrapped blob behind biometrics.

The offline cache uses [SQLCipher](https://github.com/sqlcipher/SQLCipher.swift) with a random
database key stored in the Keychain. Sync uses revision polling and an account-scoped outbox,
not push notifications. If the server accepts a create request but its response is lost,
the protocol has no idempotency key to guarantee both eventual delivery and no duplicates.

## Build & test

The [app guide](App/README.md) covers Xcode setup, simulator UI tests, and checks that require
a signed device. To build the libraries and run individual test runners from the repository root:

```sh
swift build
swift run CryptoCoreTests
swift run VaultRepositoryTests
```

The `<Module>Tests` executables are declared in [Package.swift](Package.swift); use `swift run`,
not `swift test`. For real-server compatibility checks, see the [crypto fixture guide](Sources/CryptoCoreTests/Fixtures/README.md)
and [sync fixture guide](Sources/VaultModelsTests/Fixtures/README.md). Use a throwaway vault, never personal credentials.

## License

[MIT](LICENSE). The bundled EFF passphrase wordlist has [separate attribution](Sources/UIShared/Resources/README.md).
