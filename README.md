# OpenVault

OpenVault is a native Swift client for self-hosted [Vaultwarden](https://github.com/dani-garcia/vaultwarden).
It implements the Bitwarden client protocol without embedding the Bitwarden SDK. The Xcode project
and Swift package are named `Tessera`. This project is independent of Bitwarden, Inc.

| Edition | Runs on | Setup |
| --- | --- | --- |
| Standalone Mac | macOS 26+ | [Build and install on your Mac](App/README.md#local-mac-without-a-developer-account). No developer account needed. Uses master-password or optional Touch ID unlock and manual copy. |
| Full app with AutoFill | iOS/iPadOS 27+ or macOS 27+ | [Configure the app and extension](App/README.md#full-edition-with-autofill). Requires a signing team and shared entitlements for system AutoFill and biometric unlock. |

Both editions support personal vaults, verification codes, generators, folders, archive and trash,
and offline edits to logins, secure notes, cards, identities and SSH keys. Vaultwarden Send supports
encrypted text and direct file uploads. Import and export are available from Settings on iPhone and
iPad, and from the File menu on Mac; export requires the active account's master password.
Sign-in requires a **PBKDF2** account. Argon2id accounts, organizations, vault item attachments
and emergency access are not supported.

The [Apple UI handoff](Design/openvault-ui-handoff/HANDOFF.md) includes the original boards and
the product corrections. The [implementation walkthrough](Design/openvault-ui-handoff/REVIEW.md)
maps them to the native views, records the simulator and Mac visual review, and separates that
evidence from checks requiring a signed device or disposable server account.

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
not push notifications. Settings show pending uploads separately from changes that need a
decision. For a conflicting edit, use the current server version or keep the local edit as an
independent item without overwriting the original. Recovering an unconfirmed deletion cancels
the queued deletion without deleting anything on the server.

The protocol does not provide an idempotency key for item creation. If a create response is lost,
OpenVault never automatically repeats that request. A later complete listing can confirm a unique
match for the encrypted data and item metadata. If it cannot, check the server before choosing
to keep and upload another copy; that explicit choice can create a duplicate.

SSH key items require a private key, public key, and fingerprint. Import rejects an incomplete
SSH key before writing any items or folders. Existing incomplete items can be inspected, repaired,
or removed; exporting them to JSON preserves what is readable but does not repair them.

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
