# Building and testing OpenVault

The app and AutoFill extension are Xcode targets defined in [project.yml](../project.yml).
Use full Xcode with the iOS/macOS 27 SDKs and [XcodeGen](https://github.com/yonaskolb/XcodeGen).
Run the commands below from the repository root.

```sh
brew install xcodegen
```

## Mac without a developer account

Use the `OpenVault` scheme on macOS 26 or later. It is the only Mac app build and uses ad hoc
signing. No team, provisioning profile, notarization, iPhone, or App Store submission is needed
when building for your own Mac. To build and install it for the first time, run from the
repository root:

```sh
export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
xcodegen generate
xcodebuild -project Tessera.xcodeproj -scheme OpenVault -configuration Release \
  -destination 'platform=macOS' -derivedDataPath build/mac build
mkdir -p "$HOME/Applications"
ditto build/mac/Build/Products/Release/OpenVault.app "$HOME/Applications/OpenVault.app"
open "$HOME/Applications/OpenVault.app"
```

Sign in to your Vaultwarden server with a PBKDF2 account on first use. The Mac app supports manual
copy, TOTP, sync and offline vault access. It does not publish credentials to Apple system AutoFill
or create or use website passkeys. Existing passkeys are preserved when editing login items.

The Mac app has no signing team. It keeps Hardened Runtime and embeds SQLCipher with its original
vendor signature. Its [library load constraint](macOS/Local/Libraries.coderequirement) permits
Apple platform code and Zetetic's `net.zetetic.SQLCipher` framework. No system-wide security
setting changes are required.

The SQLCipher database lives in the app's private sandbox. OpenVault stores only its random database
key in the Mac's login Keychain under `dev.moooyo.tessera.local`. The session and refresh credentials
are stored in the encrypted database, not in separate Keychain entries. The vault starts locked, and
you can unlock the cached vault without waiting for the server. Sync renews a missing or expiring
access token before sending vault requests. On a Mac with Touch ID set up, unlock with the master
password and turn on **Unlock with Touch ID** in **Settings → Security**.
This lets you unlock from the window or menu bar, including after restarting OpenVault. The
setting applies to the current saved session, not to future sign-ins.

Touch ID uses a Secure Enclave key restricted to the current fingerprint enrollment. Only the
wrapped vault key and the hardware key's opaque representation are saved in the encrypted database;
neither the master password nor an unwrapped vault key is saved. No Apple Developer account or
extra Keychain entry is required. If Touch ID becomes unavailable or you change the enrolled
fingerprints, unlock with the master password and set up Touch ID again.

If upgrading from a build that stored the session in separate Keychain entries, sign in online
once using the same account and server URL. The database key, existing vault cache and pending
uploads are preserved. The new build does not read, migrate or remove the old session entries;
replacing it with the old build can still expose that build's saved session on this Mac.

On updates, quit and replace the app at the same path; keep its Keychain entry and container.
Ad hoc signing identifies a specific build, so macOS may ask to authorize the database-key entry
after a replacement. If access fails, the app offers a retry rather than opening an unencrypted
database or resetting the vault. Use the dedicated fixture below for repeated tests.

**Load website icons** is on by default in Mac Settings → Preferences. It asks your configured
Vaultwarden server for icons for public-looking login domains. The request includes the domain,
not the full website URL or vault credentials. You can turn the setting off, and updates respect
that choice. The app does not follow redirects or contact external icon services directly. Use
Vaultwarden's `ICON_SERVICE=internal` with icon downloading enabled. Unsupported or unavailable
icons keep the local badge; Vaultwarden can also return its own fallback image.

## Mac desktop settings

- **General:** Choose whether closing the last window quits OpenVault or leaves it running.
  Menu bar visibility is independent. Launch at login uses the macOS Login Items service;
  enable it from the final installation and approve it in System Settings if requested.
  Appearance can follow the system, use Light, or use Dark. The interface can follow the
  system or use English or Simplified Chinese after restarting OpenVault.
- **Preferences:** Clear copied values after 10, 20, or 30 seconds, 1, 2, or 5 minutes, or never.
  Minimize the originating vault window after a successful item copy if desired. The global
  quick-copy preference in General shows separate controls for applicable personal logins,
  cards, and secure notes. Fields that require master-password re-prompt and organizational
  entries do not get a new direct path. Identity and SSH item fields remain in the detail view.
- **Security:** Choose a preset app-inactivity timeout, a custom duration, system idle, sleep,
  screen lock, restart, or no timeout. The timeout action is Lock or Sign Out. The default is
  five minutes and Lock, with the additional sleep/user-switch lock enabled for timed modes.
  Screen lock confirmation is best-effort; an unconfirmed lock signal only locks the vault.
  Never does not retain an unlocked vault across an app restart. Sign-out policy is kept per
  account and a failed local sign-out leaves the vault locked.
- **Integrations:** The SSH agent is off by default and serves a same-user Unix socket while
  the vault is unlocked. Under **SSH Agent Socket Path**, choose **OpenVault (Default)** for
  the app's own path or **Bitwarden DMG** to reuse `~/.bitwarden-ssh-agent.sock`. The latter
  creates a symbolic link to the private OpenVault socket without disabling App Sandbox.
  Disable the Bitwarden DMG agent before using this mode; OpenVault will not replace another
  app's socket, file, or link. Locking the vault, disabling the agent, or switching back removes
  the link OpenVault created. Use the copied path as `IdentityAgent` in your SSH configuration.
  OpenVault does not change that configuration or `SSH_AUTH_SOCK`. Use Always, Never, or remember
  approval for the requesting local process and key until the vault locks. No automatic unlock
  or agent forwarding is supported.

The native app has no Electron hardware-acceleration switch. macOS does not provide a public
per-window switch that reliably prevents system screenshots, ScreenCaptureKit recordings and
screen sharing together. The [legacy AppKit setting](https://developer.apple.com/documentation/appkit/nswindow/sharingtype-swift.enum/none)
does not provide that guarantee. Lock the vault with Shift-Command-L or share only the intended
window before presenting your screen.

The separate `OPENVAULT_TEST_LOGIN_KEYCHAIN=1 swift run VaultRepositoryTests` check explicitly opts
into the real login Keychain using disposable service names. The test disables authorization
dialogs in its own process, fails if required access is unavailable, and attempts to remove only
its own records. With the flag unset the runner does not access the login Keychain.

## Mac test fixture

Use `OpenVault-Mac-Fixture` to exercise the real Mac app scenes without login Keychain
requests. It has a different sandbox and executable, disables Keychain authorization dialogs in
its own process, and stores the test session only in the temporary encrypted database. Its random
database key is kept in memory. Normal quit removes the temporary encrypted database; after a crash
any remaining database has no saved key.
Relaunch starts a new test session. This does not test real Keychain access, Touch ID, or session
restoration.
Use only a disposable account served via plain HTTP at `127.0.0.1`. Pass its local port to the fixture;
without it the API client makes no requests. The client rejects other origins and redirects.

```sh
export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
work=$(mktemp -d)
xcodegen generate
xcodebuild -project Tessera.xcodeproj -scheme OpenVault-Mac-Fixture -configuration Release \
  -destination 'platform=macOS' -derivedDataPath "$work/build" build
open "$work/build/Build/Products/Release/OpenVault-Fixture.app" --args --fixture-port 39821
```

Quit the fixture and remove its temporary build when finished. For board captures and offline
interaction checks without an active window, use the [Mac review host](../Tests/Interface/MacReview.md).

## iOS and iPadOS with AutoFill

The existing `Tessera-iOS` scheme and `TesseraAutoFill-iOS` extension target iOS and iPadOS 27 or
later. These targets require an Apple Developer team for device builds with AutoFill and are not
part of the Mac build.

1. Set `DEVELOPMENT_TEAM` and the iOS app and extension bundle identifiers in [project.yml](../project.yml).
   The extension's identifier must start with the app's identifier followed by a period.
2. Set the same App Group in the iOS app and extension entitlements and in
   [AppShared.appGroupID](../Sources/AppShared/AppShared.swift). Keep the shared Keychain group in
   their entitlements aligned with `OpenVaultKeychainAccessGroup` in their Info.plists, including
   the `$(AppIdentifierPrefix)` prefix.
3. Enable App Groups, Keychain Sharing and AutoFill Credential Provider for both targets.
   Generate the project, choose `Tessera-iOS` and run it on a signed device.

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

## Server and account feature requirements

- Production networking requires HTTPS with normal system certificate validation. Configure the final
  URL, including a reverse-proxy subpath if applicable; OpenVault does not follow API redirects. The
  isolated fixture is the only cleartext exception and accepts one explicitly selected loopback port.
- OpenVault accepts PBKDF2 iteration counts from 5,000 to 2,000,000 and warns in Account settings
  below 600,000. Change account settings in the Web Vault; OpenVault will not substitute a different
  iteration count. Once the app detects different unlock material, it requires a new sign-in.
  Saved edits encrypted under a different or uncertain key are parked instead of uploaded.
- Security settings can check active personal logins for weak and reused passwords without a network
  connection. They also expose a manual item-key upgrade. The upgrade skips archived, deleted,
  conflicting, pending, or otherwise unsafe-to-rewrite entries, and stops if a write cannot be
  confirmed. Synchronize and check the affected entries before trying the upgrade again.
- The account two-step login pane supports TOTP, six-digit email verification, FIDO2 key management,
  and recovery codes on compatible servers. A recovery code is single-use and removes the other
  second factors. It is not a regular sign-in code.
- The Mac app does not register FIDO2 hardware security keys or use them to verify a sign-in.
  Register or use hardware keys in the Web Vault. For Mac sign-in, enable authenticator app or
  email verification on the account if a hardware key is currently the only second factor.
  Existing hardware key entries can still be viewed or removed from the Mac account settings.
- Native FIDO2 second-factor authentication on iOS requires a signed build with
  `webcredentials:<host>` in its Associated Domains entitlement, a valid site association authorizing
  that team and bundle ID, and `OpenVaultWebAuthnRelyingParties` listing the host in the app's
  Info.plist. Use the final HTTPS origin as Vaultwarden's configured domain. Native registration
  supports nonresident ES256 hardware keys on the default HTTPS port. Stock builds do not claim
  arbitrary self-hosted domains.
- Device approval is separate from passkey account login. Vaultwarden 1.37.5 requires the requesting
  installation to have signed in previously, still enforces its two-step login policy, and expires a
  request after approximately five minutes. On the other device verify the full fingerprint before
  approval. Do not log the query string for the device approval response endpoint in a reverse proxy.
- Vaultwarden 1.37.5 does not implement the PRF account-login protocol OpenVault would need for
  passkey-only sign-in. Website passkeys and FIDO2 second factors are separate features.
- Personal emergency access supports read-only grants and review of supported personal items. The
  server controls waiting periods. Account takeover remains in the Web Vault; it can change account
  access, two-factor configuration, and organization membership.
- On Mac, an explicitly locked or timed-out vault can relaunch the app after two minutes if the
  same session remains locked. Credential interaction cancels a pending relaunch. This does not
  override a policy that signs out on a cold launch. It is not an operating-system restart.

## Checks that need a device or server

- On a signed iOS build, inspect both the `.app` and its embedded `.appex` with
  `codesign --display --entitlements - --xml "$BUNDLE"`. Verify matching App Group and Keychain
  access and the AutoFill entitlement. An unsigned build cannot validate these permissions.
- Test successful, cancelled and unavailable biometric unlock, including master-password fallback
  in the main window and Mac menu bar.
- On iOS, enable OpenVault in system AutoFill settings. Fill a password and a one-time code, then register
  and use a website passkey. Check that manual lock, timeout, sign-out, and account changes revoke
  credential access and withdraw system suggestions; unlock should rebuild eligible suggestions.
  Verify that an encrypted registration survives extension restart and sign-out, and imports once
  after its owner signs in and unlocks again. A registration sealed under a previous account key
  may be unreadable after rotation; it remains queued, not available to another account.
- On Mac, check that a manual lock starts the two-minute relaunch countdown, that the old process
  exits before the new one opens locked, and that entering a credential or quitting cancels the
  relaunch. Repeat across sleep and wake and with a pending local edit.
- Listen with VoiceOver to navigation, password reveal/hide and copy feedback; check contrast,
  reduced transparency and reduced motion. Profile memory in the iOS extension, not the UI fixture.
- With disposable Vaultwarden accounts, test HTTPS behind the final proxy path, cold-start offline
  unlock, token renewal after unlock, TOTP, email delivery, and one-time recovery codes. Test native
  FIDO2 registration and verification on a signed iOS build with the proper domain association.
- Use two installations to test device approval, including rejection and expiry, and two accounts
  to test the emergency access waiting period, approval, read-only grant, and revocation.
- Check new and manually upgraded item keys in another compatible client. Exercise conflicting
  changes and an interrupted upgrade. Test external password and account-key changes separately,
  with a pending edit, to verify reauthentication and outbox handling. Use only fixture data.
