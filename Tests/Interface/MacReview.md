# Mac interface capture

The independent `MacReview` target hosts the production Mac views with an in-memory account, vault and Send service. It does not instantiate `AppEnvironment`, access a real vault or Keychain, fill a credential, touch the general pasteboard or send network requests. The supplied account, websites and generated examples are disposable.

Run from the repository root on a Mac with a logged-in graphical session, full Xcode with the macOS 27 SDK, XcodeGen and macOS 26 or later:

```sh
export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
work=$(mktemp -d)
xcodegen generate --spec Tests/Interface/macOS.yml
xcodebuild -project Tests/Interface/MacReview.xcodeproj -scheme MacReview -configuration Debug \
  -destination 'platform=macOS' -derivedDataPath "$work/build" build
fixture="$work/build/Build/Products/Debug/MacReview.app/Contents/MacOS/MacReview"
"$fixture" "$work/light"
"$fixture" "$work/dark" --dark
"$fixture" --check-interactions
```

## Functional checks

Run `"$fixture" --check-interactions` without rendering the board set to exercise native controls. The host exits nonzero on a failed check. To check repeatability, invoke the command again after the first invocation has completed. This is an interaction rerun, not a new visual comparison round.

The [functional flows](MacReview/FunctionalFlows.swift) exercise sign-in validation and rejection, cancelling a verification challenge, rejected and accepted email codes, and password unlock and retry. They also drive the native Settings toolbar and preference controls, generator modes and history inspector, vault CRUD forms for representative fields and passkey preservation, workspace sync and archive/trash undo, the hosted menu panel and session lock, and import/export guards. The panel runs outside the real menu bar, and the transfer guard checks do not open or save files.

The [clipboard check](MacReview/ClipboardFunctionalChecks.swift) gives the production ownership logic a uniquely named AppKit pasteboard and a controlled timer. It checks expiry, replacement, a later owner writing the same text, the never-clear option and the delegate's synchronous cleanup on normal termination. It does not touch the general pasteboard or test forced termination.

The interaction check exercises the production Hidden Items and Send search predicates with synthetic metadata, then uses the editor's in-process AppKit accessibility controls to submit a valid authenticator login and reject a missing or malformed seed. It also injects vault and recent-item read failures, checks the workspace and menu panel do not claim the vault is empty, and activates their real retry buttons. It does not post system events or test the system menu, global keyboard routing or a signed app.

The vault snapshot check holds the initial sync queue read and later local refresh in the fixture. It verifies that the first selection appears without the queue status, that the prior list and detail remain visible during a refresh, and that the refreshed snapshot preserves selection by ID. A rejected read clears the old detail before the native retry button restores the list.

The website icon check toggles the native preference in an isolated defaults suite. A separate hosted badge uses an injected image and verifies that loading and invalidating it replaces and restores the built-in badge without changing its 30-point frame. Neither check makes a network request.

The Codes check passes up/down events directly to the hosted native list and verifies selection alone does not copy. An injected in-memory sink records explicit row activations across fixed TOTP periods, including reactivation of the selected row, ungrouped values and row-local receipt renewal and expiry. It checks the last-five-seconds warning rule for selected and unselected rows and the account, filtered and zero-result count labels. No verification code is written to the system clipboard.

To inspect the first warning frame, run `"$fixture" --check-interactions "$work/expiry"`. This also captures the real Codes list and Vault inspector row at six seconds, five seconds and immediately after copying at five seconds. Compare the receipt, seconds and progress track in the same frame. To recapture just the ordinary Vault and Codes windows, run `"$fixture" "$work/light" --code-boards` or add `--dark` for the other appearance.

The trash batch check uses empty and populated confirmation snapshots, cancels before the first deletion, and injects an unconfirmed deletion at each possible position. It checks counts, order, failure wording and that an item arriving after confirmation is not deleted. A successful repository request can be an offline local removal; this fixture does not establish that a server deleted the item.

The Send check reads the native sidebar badge before opening Send: the existing vault sync supplies the count without fetching the Send list, a failed sync suppresses the badge, and a missing service does not masquerade as zero. It also verifies the signed, one-unit countdown at fixed dates, edits and cancels real forms, exercises the production selection and per-window search bindings, and removes an editor while an update is pending. Creating a record is exercised below the clipboard-writing UI; the test does not copy a link, switch real accounts or send network traffic.

The hosted Send workspace also starts with a failing list read. A confirmed synthetic creation remains selectable without publishing partial totals or showing false search results. The real retry button restores the full snapshot. The check covers confirmed changes, failed refreshes and retries, and delayed reads racing a mutation, cancellation or loss of service.

The two-window check mounts separate production workspaces with a shared session. A disconnected full sync keeps both selected details. A forbidden full sync removes their selections, share links and exact counts even if an earlier list request later succeeds. Retrying from each window checks recovery against the new authorized list.

See the [functional review matrix](FunctionalReview.md) for the executed results and the Mac actions that still need a live app or server.

## Board captures

Each run writes one 1× PNG per Mac board, at the reference window dimensions, plus the two-factor sign-in and General and Account settings states. The General capture shows the website icon preference in its default off state using isolated preferences. The item editor sheet takes its natural content size within the workspace. Compare these with the [board index](../../Design/openvault-ui-handoff/design/README.md). Dates, current codes and generator results may change. After inspection, remove the generated build and any screenshots no longer needed.

The host cannot activate or receive mouse input. Its windows stay underneath the desktop background. ScreenCaptureKit captures only windows owned by this process, including the native title bar, navigation columns, toolbars and sheet. This is deliberately not a display capture: it does not require permission to record the user's screen. System window controls look inactive. The unlock image covers the password fallback; actual Touch ID, application activation, menu ownership, keyboard operation and signed system integration require a live app review.
