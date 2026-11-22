# Building and testing OpenVault

The app and AutoFill extension are Xcode targets defined in [project.yml](../project.yml).
Use full Xcode with the iOS/macOS 27 SDKs and [XcodeGen](https://github.com/yonaskolb/XcodeGen).
Run the commands below from the repository root.

```sh
brew install xcodegen
```

## Local Mac without a developer account

Use the `OpenVault-Local` scheme for your own Mac on macOS 26 or later. It is sandboxed and signed
locally by Xcode. No team, provisioning profile, notarization, iPhone, or App Store submission is
needed. To build and install it for the first time, run from the repository root:

```sh
export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
xcodegen generate
xcodebuild -project Tessera.xcodeproj -scheme OpenVault-Local -configuration Release \
  -destination 'platform=macOS' -derivedDataPath build/local build
mkdir -p "$HOME/Applications"
ditto build/local/Build/Products/Release/OpenVault.app "$HOME/Applications/OpenVault.app"
open "$HOME/Applications/OpenVault.app"
```

Sign in to your Vaultwarden server with a PBKDF2 account on first use. Manual copy, TOTP, sync
and master-password unlock use the regular app code. This edition does not install a system
AutoFill provider, publish credentials to macOS, or offer Touch ID unlock.

The local executable has no signing team. It keeps Hardened Runtime and embeds SQLCipher with
its original vendor signature. Its [library load constraint](macOS/Local/Libraries.coderequirement)
permits Apple platform code and Zetetic's `net.zetetic.SQLCipher` framework. No system-wide
security setting changes are required.

The SQLCipher database lives in the app's private sandbox. Its random key and session secrets
use the Mac's login Keychain under `dev.moooyo.tessera.local`, separate from the full edition.
On updates, quit and replace the app at the same path; keep its Keychain items and container.
Ad hoc signing identifies a specific build, so a replacement can require authorization again
even if an earlier build was allowed. If access fails, the app offers a retry instead of opening
an unencrypted database or resetting the vault. Use the dedicated fixture below for repeated tests.

The separate `OPENVAULT_TEST_LOGIN_KEYCHAIN=1 swift run VaultRepositoryTests` check explicitly opts
into the real login Keychain using disposable service names. The test disables authorization
dialogs in its own process, fails if required access is unavailable, and attempts to remove only
its own records. With the flag unset the runner does not access the login Keychain.

## Standalone Mac fixture

Use `OpenVault-Local-Fixture` to exercise the real standalone app scenes without login Keychain
requests. It has a different sandbox and executable, disables Keychain authorization dialogs in
its own process, and keeps session secrets and the random database key in memory. Normal quit
removes the temporary encrypted database; after a crash any remaining database has no saved key.
Relaunch starts a new test session. This does not test real Keychain access or session restoration.
Use only a disposable account served via plain HTTP at `127.0.0.1`. Pass its local port to the fixture;
without it the API client makes no requests. The client rejects other origins and redirects.

```sh
export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
work=$(mktemp -d)
xcodegen generate
xcodebuild -project Tessera.xcodeproj -scheme OpenVault-Local-Fixture -configuration Release \
  -destination 'platform=macOS' -derivedDataPath "$work/build" build
open "$work/build/Build/Products/Release/OpenVault-Fixture.app" --args --fixture-port 39821
```

Quit the fixture and remove its temporary build when finished. For board captures and offline
interaction checks without an active window, use the [Mac review host](../Tests/Interface/MacReview.md).

## Full edition with AutoFill

For `Tessera-iOS` or `Tessera-macOS`, configure both the app and its matching
`TesseraAutoFill` extension. These steps do not apply to `OpenVault-Local`.

1. Set `DEVELOPMENT_TEAM` and your app and extension bundle identifiers in [project.yml](../project.yml).
   The extension's identifier must start with the app's identifier followed by a period.
2. Set the same App Group in the full app and extension entitlements and in
   [AppShared.appGroupID](../Sources/AppShared/AppShared.swift). Keep the shared Keychain group in
   their entitlements aligned with `OpenVaultKeychainAccessGroup` in their Info.plists, including
   the `$(AppIdentifierPrefix)` prefix.
3. Enable App Groups, Keychain Sharing and AutoFill Credential Provider for both targets.
   Generate the project, choose the scheme for your platform and run it on a signed device.

```sh
xcodegen generate
open Tessera.xcodeproj
```

## Simulator UI tests

The [interface test project](../Tests/Interface/project.yml) uses an in-memory vault, not a real
account or the system credential provider. The tests drive the production mobile views, attach
screenshots named after the boards, and skip tests meant for the other device family. Use a
disposable simulator of each family; the accessibility checks exercise the keyboard and VoiceOver.

```sh
export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
xcodegen generate --spec Tests/Interface/project.yml
xcrun simctl list devices available
review=$(mktemp -d)
# Set PHONE_UDID and PAD_UDID to the two simulator identifiers.
for id in "$PHONE_UDID" "$PAD_UDID"; do
  xcodebuild -project Tests/Interface/InterfaceChecks.xcodeproj -scheme InterfaceChecks \
    -destination "platform=iOS Simulator,id=$id" -derivedDataPath "$review/build" \
    -parallel-testing-enabled NO -resultBundlePath "$review/$id.xcresult" test || break
done
python3 Tests/Interface/export_review.py --output "$review/screens" \
  "$review/$PHONE_UDID.xcresult" "$review/$PAD_UDID.xcresult"
```

The exporter reports missing boards instead of treating absent screenshots as passes. Compare
the images with the [board index](../Design/openvault-ui-handoff/design/README.md), applying the
[three product corrections](../Design/openvault-ui-handoff/HANDOFF.md#product-corrections).
The primary iPad boards use the collapsed sidebar; separate Vault and Send attachments preserve
the expanded layout so the narrower list can be checked without comparing unlike states.
Primary boards use light appearance regardless of the time of day. The AX5 verification and
Codes checks explicitly use dark appearance; each test restores the simulator appearance it found.
The expiring-code regression uses a five-second synthetic account and recognizes only the row's
status area to check the receipt and seconds in the same frame. It does not store recognized text.
For the Mac, the [offscreen review host](../Tests/Interface/MacReview.md) captures the real
views in light and dark appearance without opening the user's vault or taking over the desktop.
The [functional review matrix](../Tests/Interface/FunctionalReview.md) distinguishes completed
native interactions from shared logic checks and workflows that still need a signed device or
disposable Vaultwarden server.

On a fresh disposable iPhone or iPad simulator, add
`-only-testing:InterfaceTests/BackupTransferTests` to the `xcodebuild test` command to check
saving and reopening a synthetic JSON backup through system Files. This test leaves the
fixture export in the simulator's local Documents provider; delete the disposable simulator
after the run.

Keep the screenshots needed for review and remove the temporary builds and result bundles afterwards.

## Checks that need a device or server

- On a signed full build, inspect both the `.app` and its embedded `.appex` with
  `codesign --display --entitlements - --xml "$BUNDLE"`. Verify matching App Group and Keychain
  access and the AutoFill entitlement. An unsigned build cannot validate these permissions.
- Test successful, cancelled and unavailable biometric unlock, including master-password fallback
  in the main window and Mac menu bar.
- Enable OpenVault in system AutoFill settings. Fill a password and a one-time code, then register
  and use a passkey. Check the registration survives an extension restart, two same-named accounts
  can be distinguished by domain, and cancelling a scrolled picker does not fill anything.
- Listen with VoiceOver to navigation, password reveal/hide and copy feedback; check contrast,
  reduced transparency and reduced motion. Profile memory in the actual extension, not the UI fixture.
- With a disposable Vaultwarden account, test real authenticator and email delivery, native
  cold-start offline unlock, and browser file Send and expiration. Recheck proxy-path and
  refresh behavior when changing the server setup.
