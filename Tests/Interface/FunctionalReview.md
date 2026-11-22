# OpenVault functional review

The [UI handoff](../../Design/openvault-ui-handoff/HANDOFF.md#screen-behavior) defines what each
flow should do. The [visual review](../../Design/openvault-ui-handoff/REVIEW.md#iterative-fidelity-review)
records board fidelity separately. A build, a rendered board, a fixture interaction, and a live
integration test establish different things.

## Run record

| Surface | Executed evidence |
| --- | --- |
| iPhone 17, iOS 27.2 simulator | 19 baseline and 11 additional cases passed, with zero failures or skips. The four pinned tiles opened their own records. Cancelled single-item removal kept the item visible; the confirmed empty-trash action removed it. |
| 11-inch iPad Pro (M5), iPadOS 27.2 simulator | 6 baseline and 5 additional cases passed in one run, with zero failures or skips. The focused Send regression also passed twice with the software keyboard present when saving both a new text and an edit. A separate Files probe verified an actual export on disk, but did not complete import selection. |
| Mac, macOS 26.7.3 | The offscreen native host passed all nine reported check groups in two complete runs. An isolated AppKit process also exercised actual normal termination with a named pasteboard, including a later write owned by a separate process. Neither test opened the production app or touched the general pasteboard. |
| Shared Swift packages on Mac | 14 test executables passed, 1,700 assertions and zero failures. Tests used disposable data, real temporary SQLCipher files where appropriate, and injected services or in-process HTTP responses. Optional real-Keychain and captured-server fixtures were not used. |
| Isolated Vaultwarden 1.37.5 | 36 functional assertions and one isolation check passed on the final source. Three independent clients used production networking, authentication, repository, encryption and temporary SQLCipher stores with an in-memory Keychain adapter. Anonymous-recipient HTTP traffic used the real server and no owner credential. |
| Official Web Vault recipient | Four text Send checks passed in a nonpersistent, offscreen WebKit instance serving Web Vault 2026.10.1. This is separate from the HTTP file download test. |
| Production builds | All four targets built: generic iOS simulator, generic iOS device, Mac Full and Mac Local. The three complete targets embedded their expected AutoFill provider. The simulator app/provider and published Mac Local package passed strict signature verification. Generic iOS device and Mac Full were unsigned; neither proves signed system authorization. |
| Post-fix visual review | Two successive reviews of the affected states on the same UI source found zero new actionable visual changes. Reruns are not counted as new functional cases. |

## Native interaction evidence

Mobile XCTest cases drive the production views in a fixture app. The Mac host exercises
production views through in-process AppKit controls and injected actions without owning the active
window, system menus or physical keyboard. A view or enabled control is not evidence of an
operation unless the action and outcome were both checked.

| Flow | iPhone fixture | iPad fixture | Mac offscreen fixture |
| --- | --- | --- | --- |
| Sign-in, verification, and unlock | Gated credential form, six-digit challenge, and master-password unlock. Settings lock/unlock and confirmed sign-out after cancellation. | Email-provider switch, resend request receipt, five-digit submit disabled, six-digit completion, settings lock and password unlock. The receipt acknowledges the request, not delivery. | Invalid credentials and retry, challenge cancellation, rejected and accepted email codes, and failed then successful password unlock. |
| Vault navigation and search | Settings gear, bottom search and return to each tool, matching result to detail, pinned/type filtering and failed-read retry. Each of the four tiles opens its own record. | Expanded/collapsed sidebar and counted filters, pinned-first ordering, bottom search, zero results and clear, cancellation back to Codes, and matching result selected beside its detail. | Native workspace selection and retry, scoped Codes search and hidden-item predicates; menu-panel recent items and site search with secrets excluded. System Command-K was not sent. |
| Five item types and passkey preservation | New item opens its saved detail in the correct parent. Create, rename and reopen representative fields for login, card, identity, note and SSH; editing an existing login retains its passkey, password and code controls. | Form switches types; saving a note from the card filter makes the new note visible and selected. Cloning a pinned login shows an unpinned copy without the source passkey. No five-type round trip on iPad. | Native login edits and cancelled edits preserve its passkey, URI settings and other stored fields. Native forms create a card, identity, secure note and SSH record with representative fields. |
| Folders, pinning, archive and trash | Create in a folder; move to trash, undo and restore. Folder rename and confirmed deletion keep the contained item unfiled; pin toggle, unarchive, cancelled single removal and confirmed empty-trash. | Pinned filtering and a clone appearing outside that filter; folder mutations and permanent deletion were not driven here. | Archive/trash with undo; batch removal checks the confirmation snapshot, order, cancellation and partial failure in the batch logic. No system folder context menu action. |
| Sync, failures and account access | Read failures offer Retry rather than fake empty data. On reactivation, synthetic disconnection retains the open Send; denied full sync closes it and requires fresh authorized data. | The Sync action is visible in the settings detail; live sync was not performed. | Native Sync button invokes the fixture service; workspace and menu read failures can retry. Two Send windows retain detail on disconnection, drop selection and counts on denial, and recover after retry. |
| Codes and inline copy | Native row activation, inline password copy receipt, dark AX5 wrapping and visible receipt plus remaining seconds at expiry. | Activates a Codes card and verifies that the grid becomes usable again after closing search. | Selection-dependent warning rules at rollover, explicit row activation rather than selection-only copy, ungrouped current values and row-local receipt, result counts, and seed validation when adding a code. Codes copy goes to an injected sink. |
| Send | Text validation and creation, detail presentation, unavailable service without a link, remote fixture edits/removal and revocation during foreground refresh. | File/text filters and counts, text create/edit with the keyboard still visible, detail remains in the right column, and cancellation then confirmation of deletion. File rows are fixture metadata, not uploads. | Native editor save/cancel, list selection, sidebar badge, search and delayed mutations/reads. Synthetic creation, missing complete snapshot, retry and two-window revocation; no public recipient link or file upload from this host. |
| Generator and history | Native entry and result; passphrase option preserved across modes, username/passphrase regeneration and populated history clear. | Generate all three modes, retain independent options, validate an alias result, activate history copy and clear/reopen the history popover. | Select all three modes, validate alias input, show/hide the history inspector and clear in-memory history without removing the current result. |
| Preferences, clipboard, and session | Settings entry; timeout choice retained across navigation, manual lock and sign-out confirmation. No timed device lock test. | The username visibility switch immediately changes Vault rows, survives a process relaunch and can be restored. Manual lock and password unlock also exercised. | Native Settings pane changes and isolated menu/sleep preferences. Named pasteboard tests cover expiry, replacement, later foreign ownership, never-clear and normal termination. Sleep and actual session-lock notifications were not sent. |
| Import and export | Settings entry, import chooser action available, export disabled before password, and wrong-password refusal with no success notice. | The system Files exporter wrote a cleartext personal JSON archive to a disposable local provider; the host independently checked eight items and two folders. The import chooser opened, but automation did not select the file or verify a write. | Native guards require an import file and reject a wrong export password before showing a save panel. No production files were opened, written or imported. |
| AutoFill and passkeys | Fixture picker limits displayed metadata to the requesting domain, expands and searches alternatives, closes after scrolling and avoids speaking secrets in simulator VoiceOver. | No system or standalone fixture picker session was driven on iPad in this pass. | No system credential-provider session. Vault editing checks retention of an existing passkey, not its use for authentication. |
| Mac menu bar and commands | Not applicable. | Not applicable. | Hosted panel shows recents, searches by site, excludes secret values, clears search, locks and returns after password unlock. No system menu item or keyboard shortcut was used. |

## Live server evidence

The final run used the [official Vaultwarden 1.37.5 release](https://github.com/dani-garcia/vaultwarden/releases/tag/1.37.5)
on Linux, in a fresh data directory under a non-root account. It listened only on loopback and
was reached over a loopback SSH forward. The server, temporary account and databases were
removed afterwards; no existing vault or Keychain was used.

- Three independent clients obtained PBKDF2 sessions and decrypted vault data. They exercised
  personal item creation and update across databases, folder create/rename/unfile, archive and
  unarchive, trash and restore, permanent deletion, and personal JSON export and live import.
  One client created a cipher before its first vault sync, using the authorized profile endpoint.
- A transport interruption on one client queued a real offline create/edit in SQLCipher. The
  second client stayed online and did not see it until reconnect. After replay it saw exactly
  one item with the final values, and the outbox was empty.
- Independent Send HTTP sessions verified absent/wrong passwords, a successful decrypt, access
  counts and limits, password removal, and link invalidation after deletion. A recipient used a
  signed download URL and decrypted 93,415 bytes identical to the source. The file download was
  not driven through a browser.
- The [official Web Vault 2026.10.1](https://github.com/dani-garcia/bw_web_builds/releases/tag/v2026.10.1)
  rendered a protected OpenVault text link through a loopback-only TLS bridge. Offscreen WebKit
  checked the password gate, rejection without a count increment, correct-password decryption
  rendering the original text with one counted access, and a fresh session refusing the deleted
  link. Neither system trust nor a personal browser session was changed.

The live server rejected create, update and import with HTTP 422 before the fix because the
[cipher schema](https://github.com/dani-garcia/vaultwarden/blob/1.37.5/src/api/core/ciphers.rs#L260-L274)
requires `encryptedFor`. The final client sends the server user ID under the active account lease,
not the locally composed account key. The live acceptance run includes the account-lease fix.

## Shared logic and remaining integration checks

| Area | What the automated checks establish | What still needs an independent environment |
| --- | --- | --- |
| Identity, locking, and sync | Prelogin PBKDF2 and key unwrap, identity/2FA/refresh request handling, online/offline reconciliation, encrypted store reopen and migration, and account-isolated outbox and session paths with synthetic services. | Verify real authenticator challenge and email delivery, production token refresh, a cold-start offline unlock in the native app, and a deployment behind TLS and a reverse-proxy subpath. |
| Vault items, folders, archive and trash | Encrypted CRUD and preservation of other fields, folder removal/unfiling, hidden-item filtering, undo/restore, confirmation snapshots, and account isolation. | Compare capabilities across other supported deployments and exercise every item type with production clients. An offline removal receipt from the UI does not itself prove remote deletion. |
| Codes, generators and clipboard | TOTP/generation vectors, copy feedback policy, encrypted device-local history and its cap. Expiring Mac copies now clear at normal termination only if the app still owns them; forced termination, crashes and power loss are not covered. | Verify timing and paste expiry on signed iPhone/iPad and the normal Mac app. Check hardware keyboard and VoiceOver behavior in the active app, rather than treating accessibility labels as device certification. |
| Text and file Send | The [owner-protocol test](../../Sources/VaultRepositoryTests/Checks_FunctionalSend.swift) uses production networking, encryption, repository and a temporary SQLCipher database with an in-process HTTP responder. It checks text create/update/password removal, file reserve/upload/publish, and rollback on 503. Decrypting the upload payload with the share-link key reproduces the original 93,415-byte fixture file. | Use the browser to download a file Send. Exercise live expiration and disabled links, live upstream upload failures, additional reverse-proxy layouts, and the native system share sheet. |
| Import/export | Supported parser round trips, encryption and repository write/password/session checks, including partial and offline imports. | Complete an import using the iPad system chooser and file round trips on iPhone and Mac; round-trip the other supported formats with independent clients. Inspect exclusion warnings and confirm cancellation writes no file. |
| Signed AutoFill, biometrics and Mac runtime | Metadata-only picker evidence, credential reader, software FIDO2 signatures, passkey handoff, credential-index logic and biometric policy checks with fake stores. | On signed devices verify App Group and Keychain access, password and TOTP filling, passkey registration and assertion across extension restart, cancellation, extension memory, and successful/cancelled/unavailable biometric unlock. On a live Mac verify menu commands and window focus, sleep and wake, local-edition Keychain after app replacement, and full-edition runtime on macOS 27. |

The review does not extend the supported scope: personal PBKDF2 vaults, the supported personal
transfer formats, and direct file Send uploads. Argon2id accounts, organization/collection
management, vault item attachments, Azure Send uploads and system AutoFill or Touch ID in the
standalone Mac edition are not treated as untested supported features.

## Follow-up: Sync recovery and backups

These checks cover the follow-up work only; they do not repeat the 38-board review or certify
the full app on signed devices. The new sync issue and pending states use the existing Settings
layout and native confirmation controls. They are not separate handoff boards.

| Surface | Follow-up evidence |
| --- | --- |
| iPhone 17 and 11-inch iPad Pro (M5), iOS/iPadOS 27.2 | The production views opened the queue from the vault, showed the duplicate-risk warning, discarded an unconfirmed local item, cancelled a resolution, and kept a conflicting edit as a pending copy. Each device family passed the focused fixture test twice. Each also passed the separate system Files round trip: save a synthetic JSON export, select it from Recents and import nine items. Opening the disposable output independently confirmed nine items and two folders. |
| Mac, macOS 26.7.3 | The full offscreen check passed twice. It rendered the native Sync pane in both queue states and verified the model transitions. The host did not drive the Mac system confirmation dialog or a native file round trip. |
| Swift packages and production builds | 14 executables passed 1,913 assertions with no failures. This includes durable issue storage, stale and account-scoped recovery, copy and discard rollback, and personal JSON, password-protected JSON and Bitwarden CSV files restored into an independent SQLCipher vault. All four app builds passed; the Mac Local app also passed strict signature verification. |
| Isolated Vaultwarden 1.37.5 | 26 assertions covered two real clients with separate caches, conflict parking and both recovery choices, lost create acknowledgement without a duplicate, and SSH key visibility at client version `2024.12.0`. A second pass through an HTTPS reverse-proxy subpath passed 12 assertions, including two refresh grants and subsequent authenticated sync and creation. |

For the live checks, run a non-root server on Linux loopback and use a disposable PBKDF2 account.
Point two production service containers with separate temporary SQLCipher stores and in-memory
Keychains at the server. At a loopback proxy, drop a `PUT` before forwarding and later disconnect
a `POST` response after receiving its upstream 2xx. Edit the first item from the peer after the
server's revision tolerance, exercise both recovery choices, and check that the next pull confirms
the created item without a second `POST`. For the TLS run, use the server's configured subpath
through the proxy and scope the temporary trust anchor to the harness session; the system trust
store is unchanged. Check login, two distinct renewed grants, a write and a subsequent pull.

Two fresh visual rounds checked the new queue, unconfirmed-create warning and pending-copy
states against the existing Settings layouts. Both rounds found zero new changes. Signed AutoFill,
biometrics, native Mac focus and sleep/wake, real two-factor delivery, and a browser file Send
remain separate acceptance work.

## Local Mac release acceptance

On November 23, 2026, the locally signed standalone Release ran on macOS 26.7.3 with
its own bundle identifier, sandbox, login Keychain items, and disposable Vaultwarden 1.37.5
account. This was separate from the offscreen review host. Three findings changed the
candidate before the visual recheck:

- A cold launch could spin in SwiftUI's scene and menu updates without reaching sign-in.
  The menu-bar extra now ignores identical insertion-state writes instead of repeatedly updating
  the preference. The independently launched Release reached its native login window.
- The visible login frame was 560 × 532 points, including native chrome. The app now derives its
  content size from the designed 560 × 500-point outer frame. A fresh capture measured 560 × 500
  with the native window controls and unchanged form spacing.
- Vaultwarden returned an empty SSH payload after accepting an incomplete key. Saving now
  requires the private key, public key and fingerprint. Import rejects an incomplete key before
  writing any folder or item. The real server independently confirmed all three fields on a
  complete key and no write for an incomplete one. The iPhone SSH fixture, the Mac offscreen
  interaction checks, and the shared repository and transfer tests also passed.

## Affected-state visual loop

The earlier [board-by-board review](../../Design/openvault-ui-handoff/REVIEW.md#iterative-fidelity-review)
closed after two clean rounds across all 38 product boards. This subsequent loop rechecked only
the screens affected by the functional fixes. It compared fresh native captures with the boards
and the previously accepted gallery, accounting for sample data, the three product corrections
and native system controls rather than requiring pixel identity with the drawings.

| Round | Checked on the same UI source | New changes |
| --- | --- | --- |
| 1 | iPhone dark Vault tiles and Trash swipe, confirmation and cancellation, plus light Send form; iPad horizontal Send form with the keyboard, with selection and detail after save and expanded sidebar; Mac Vault and Codes in both appearances and at the five-second copy receipt. | 0 |
| 2 | Fresh iPhone light captures and four targeted tests, including every pinned hit target, confirmed and cancelled Trash actions and Send; separate iPad create/edit keyboard and settled split-view frames; a new Mac capture of the same vault, Codes and expiry states. | 0 |

iPhone kept four independently labeled tiles and at least 44-point targets at the checked text
size. The native red Trash action still opens a confirmation and the row stays visible on cancel.
On iPad the keyboard does not cover the save action and the saved item stays selected. On Mac the
remaining seconds and copy receipt appear together without covering the progress track. The two
clean rounds meet the stop condition. A small set of synthetic frames and summarized logs is
retained in the local, ignored `build/functional-review` directory; it does not replace the earlier
full design gallery.

## Reproduce the checks

- Run the [disposable simulator host](../../App/README.md#simulator-ui-tests) on both families.
  [NavigationTests](UITests/NavigationTests.swift) contains baseline and board capture cases;
  [PhoneFunctionalTests](UITests/PhoneFunctionalTests.swift) and
  [PadFunctionalTests](UITests/PadFunctionalTests.swift) contain workflow cases. The other device
  family's cases are skipped intentionally; count successes only for the matching family.
- Run the [Mac review host](MacReview.md#functional-checks) with `--check-interactions`.
- Run the [Swift package test executables](../../README.md#build--test) from the repository root.
  `swift run VaultRepositoryTests` includes the synthetic Send owner-protocol test.
- Use the [device and server checks](../../App/README.md#checks-that-need-a-device-or-server) only
  with dedicated signed installs and a disposable vault. Use synthetic credentials and files,
  never a personal vault, and remove temporary apps, exports, and accounts after verification.
