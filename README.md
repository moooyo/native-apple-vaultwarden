# OpenVault

OpenVault is a native Swift client for self-hosted [Vaultwarden](https://github.com/dani-garcia/vaultwarden).
It implements the Bitwarden client protocol without embedding the Bitwarden SDK. The Xcode project
and Swift package are named `Tessera`. This project is independent of Bitwarden, Inc.

[Build and install OpenVault](App/README.md#mac-without-a-developer-account) on macOS 26 or later.
There is a single Mac build; no Apple Developer account is needed for local use. It supports
master-password or optional Touch ID unlock and manual copy, not Apple system AutoFill.
The [iPhone and iPad targets](App/README.md#ios-and-ipados-with-autofill) remain in the repository
and require an Apple Developer team for device builds with AutoFill.

OpenVault supports personal vaults, verification codes, generators, folders, archive and trash,
and offline edits to logins, secure notes, cards, identities and SSH keys. Vaultwarden Send supports
encrypted text and direct file uploads. Import and export are available from Settings on iPhone and
iPad, and from the File menu on Mac; export requires the active account's master password.
Use an HTTPS Vaultwarden deployment and a **PBKDF2** account. Account creation, password
changes, and account-key rotation remain in the Web Vault. OpenVault adds local password
health reports, device approval for known installations, and read-only personal emergency
access. Account takeover still requires the Web Vault. See the [account feature requirements](App/README.md#server-and-account-feature-requirements)
before relying on a new sign-in method. Argon2id accounts, organization vaults, and vault item
attachments are not supported.

The [Apple UI handoff](Design/openvault-ui-handoff/HANDOFF.md) includes the original boards and
the product corrections. The [implementation walkthrough](Design/openvault-ui-handoff/REVIEW.md)
maps them to the native views, records the simulator and Mac visual review, and separates that
evidence from checks requiring a signed device or disposable server account.

## Architecture

The code is grouped into five responsibility bands with deliberately narrow SwiftPM target
dependencies. Security-sensitive code lives in L0/L1. The **iOS AutoFill extension directly depends
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

While unlocked, the read and write actors hold separate, explicitly erasable copies of the account
key. Locking wipes those buffers and revokes previously issued access leases; it cannot guarantee
that every temporary OS or Swift runtime copy has been wiped. AutoFill requires a live unlock in
the main app as well as its own biometric check. Lock revokes credential access and requests that
the system withdraw suggestions; a stale system suggestion does not authorize filling.

The offline cache uses [SQLCipher](https://github.com/sqlcipher/SQLCipher.swift) with a random
database key stored in the Keychain. Decrypted search fields are processed in memory, not persisted.
New personal items use separate random keys wrapped by the account key. A manual upgrade in
Security settings can migrate eligible older items. Sync uses revision polling and an account-scoped outbox,
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
not `swift test`. To measure the first local search over 5,000 separately keyed synthetic logins,
run `swift build`, then `OPENVAULT_CHECK_LARGE_SEARCH=1 /usr/bin/time -l .build/debug/VaultRepositoryTests`
on macOS. The runner times the first query; process memory includes fixture setup and the SQLCipher cache.
For real-server compatibility checks, see the [crypto fixture guide](Sources/CryptoCoreTests/Fixtures/README.md)
and [sync fixture guide](Sources/VaultModelsTests/Fixtures/README.md). Use a throwaway vault, never personal credentials.

## License

[MIT](LICENSE). The bundled EFF passphrase wordlist has [separate attribution](Sources/UIShared/Resources/README.md).
