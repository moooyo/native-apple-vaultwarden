# OpenVault UI handoff

This is the design reference for the native iPhone, iPad and Mac clients. The [board index](design/README.md) links all 39 original boards and lists their reference sizes. The [upstream notes](upstream-notes.zip) preserve the complete original `HANDOFF.md` and `design/README.md` in Chinese at their original paths. The boards, shared stylesheet and canvas manifest are original, not rewritten to match the implementation.

## Product corrections

Three decisions supersede the drawings and any conflicting text in the upstream notes:

1. **Search belongs at the bottom on iPhone and iPad.** Put the search entry and active search field there, not in the top toolbar. Reserve the system search role for real search. Mac retains toolbar search and Command-K.
2. **Settings uses a gear button.** Give the button a Settings accessibility label. Do not disguise Settings as search, an account avatar or the user's initials. Account information may still be displayed on the settings page.
3. **Use the supplied blue and violet folded-key artwork** for the app icon and in-app OpenVault mark, including authentication and the credential picker. Vault, password and lock actions can still use their own system symbols.

## Navigation and layout

| Platform | Navigation | Reference measurements (points) |
| --- | --- | --- |
| iPhone | Vault, Codes, Send and Generator are the four primary destinations. Use filled symbols, native bottom search and a separate Settings gear. Keep the tab bar when pushing details, folders, hidden items or transfer. Present creation, Send detail and generator history modally. | 34-point bold large title; 16-point group margins; 26-point card corners; rows at least 52 high. Use touch targets at least 44 square. |
| iPad | Use the same destinations in an adaptive tab/sidebar layout. A visible sidebar takes space rather than covering the detail. Types, folders, Archive and Trash filter the vault list. When the sidebar is hidden, show the type filters in the list. Search remains at the bottom. | About 300 for the sidebar and 340–380 for the list, 62 for a row; center detail content within 540. Center sign-in and unlock in columns of about 420 and 400 respectively. |
| Mac | Use the system split view with sidebar, list and detail; do not cover it with custom material or an account footer. Group All Items, Pinned and Codes, then Types, Folders, Tools and Hidden Items. Use native selection, count badges and a folder context menu. Settings is a separate scene (Command-comma); the optional menu-bar panel uses a window-style extra. | Sidebar rows 28; list width about 316; 12-point detail card corners and 38-point form rows. Body and sidebar 13, section captions 11, toolbar title 15 and main detail heading 26. Sign-in has its own 560 × 500 window. |

## Screen behavior

| Flow | What to look for |
| --- | --- |
| Sign in and unlock | Collect email and master password on one page; offer a recent-server selector, an alternate server and a password hint. Only a server challenge opens verification: authenticator or email, six digits, resend and remember-device where supported. In the locked state show the logo, account email and biometric/password choices, not server or timeout details. Confirm sign-out. Mac keeps an explicit password field and a prominent Touch ID action. |
| Vault and search | Show type/count chips, a four-column pinned overview on the phone, folders with counts and a plus button, then the item list and hidden-item counts. Sort by localized name, modification date or type; do not show dashboard statistics above the list. Search names, usernames and sites, with optional type filters, result counts and a no-match state. |
| Item and editor | Show the icon, title, type/date, grouped fields, sites, passkeys and notes. Keep Pin and More by Edit. Edit the current item in place on iPhone/iPad; create in an empty form sheet and edit in a sheet on Mac. Offer login, card, identity, secure note and SSH key; show only the appropriate fields. Allow multiple login sites, password generation, folder selection, notes and pinning. Do not drop fields the editor does not expose. |
| Codes | Show a name, account, monospaced code grouped in threes and a three-point countdown along the bottom. The bar shrinks and turns orange with five seconds or less remaining. Tap the row/card to copy. Use a list on iPhone, an adaptive card grid on iPad, and a searchable list plus a large selected code on Mac. |
| Folders and hidden items | Create, rename and delete folders and create items in a folder. Confirm folder deletion and state that the contained items become unfiled. Archive and trash are distinct states with real counts. Offer undo after archive/trash and restore/unarchive where appropriate; confirm permanent deletion and emptying the trash. Use an empty state for each filter. |
| Send | Filter All/Text/File, show the name, access count, deletion time and password/expiration state. Create or edit text or file content with deletion/expiration, access limits, access password and email visibility. Detail presents a real share link, copy/share and a confirmed delete. Use a detail sheet on iPhone, a list/detail arrangement on larger screens, and a centered creation form. |
| Generator | Offer passwords, passphrases and usernames, with independent options. Display a monospaced result, a labeled four-segment strength scale where relevant, regenerate and copy. History can be copied or cleared; use a sheet on iPhone, a popover on iPad and a right-hand pane on Mac. |
| Settings | Show the actual account and sync state plus manual sync, biometrics, automatic locking, clipboard expiration, AutoFill settings, folder management, transfer, lock, confirmed sign-out and version. iPad uses a category list beside detail. Mac has General, Account, Security, Sync and AutoFill panes, including the menu-bar preference and sleep/lock settings. Follow the relevant platform board for appearance controls; the upstream specification also describes following system appearance. |
| Import and export | Open from Settings on iOS/iPadOS or File on Mac. Import specifies a source, a file and optional destination folder. The reference shows Bitwarden JSON, Apple Passwords CSV, browser CSV and 1Password 1PUX. Export specifies JSON, password-protected encrypted JSON or CSV and requires master-password confirmation. Explain cleartext exposure and exclusions (attachments, Sends and trashed items) before writing. |
| AutoFill | A compact sheet identifies the requesting domain and OpenVault, supports closing and selecting a credential, distinguishes passkeys and permits searching for other credentials. A recency badge must refer to actual usage. Show only the appropriate domain/credential metadata, not secrets or full private URLs. |
| Mac menu bar and commands | The unlocked panel offers search, recent items, per-item copy actions, generate-and-copy, open and lock. Provide menu equivalents for available toolbar actions, including new item/folder/Send, transfer, sync, edit, trash, info, search and credential copy. Scope commands to the active window and selection. |

## Components and accessibility

- Prefer native `TabView`, `NavigationSplitView`, `List`, `Form`, `Section`, toolbars, pickers, menus, alerts and sheets. Glass is navigation or control chrome, not a card fill. Do not stack custom materials, draw a fake system status bar or copy the canvas's fixed coordinates.
- Use semantic fonts and system label, grouped-background, separator, fill, selection and status colors. Item tiles are rounded squares, not account avatars. The large-title, title, headline, body, subheadline and footnote roles scale with Dynamic Type. Keep content legible in both light and dark appearance.
- A username, password or one-time code copies on tapping its row; show “Copied” in that row for **1.6 seconds**, never the copied value in an announcement or global toast. Respect the clipboard timeout. On iOS use a separate eye control; on Mac reveal on hover or keyboard focus and conceal again on exit.
- Reserve bottom operation feedback for state changes. Archive and move-to-trash offer undo for about four seconds. Destructive confirmation text describes the consequence; required fields gate the default action. Keep focus rings on the focused input, icon actions labeled, and destructive actions reachable without a swipe.
- During a device review inspect Increase Contrast, Reduce Transparency, both glass appearances, Reduce Motion, VoiceOver, keyboard navigation and Dynamic Type through AX5. Test grouped or multiline codes at large sizes, and do not rely on color alone for strength or expiry. The contrast values in the original notes describe the **prototype**, not measurements of the app.

## Data and capability boundaries

The workflow above is a design target, not a list of verified server capabilities. Use actual account data, not prototype names, counts, timestamps or share links.

- Authenticate using the server's prelogin KDF parameters before requesting a token. Persist favorites and encrypted folder names and maintain folder relationships when a folder is removed.
- Move to trash and restore are reversible operations. Only confirmed permanent deletion or emptying trash may destroy data. Track archive separately; ordinary lists, search and the AutoFill index must exclude hidden items. The original handoff calls out server-version support for archive.
- A Send requires a locally generated key, local encryption and a server-issued access ID; file Sends also need the encrypted file upload flow. Do not report a create, save or share as successful without the corresponding operation.
- Import must encrypt data before upload. Export requires master-password verification; password-protected JSON must be compatible with the selected format. CSV can represent only a subset of the vault. A format or capability that is unavailable should not present a working-looking action.
- If generator history is persisted, use device-local encrypted storage, cap it at 100 entries and do not sync it. Multi-account switching, organizations/collections and attachment or custom-field editing are outside the upstream scope.

## Review

Start with tokens and navigation, then trace each board through its entry point, empty and populated states, actions, error handling and return path. Check the three product corrections separately from board fidelity. The current delivery is **code and static review only**: do not treat source inspection as an Apple build, simulator run, visual comparison or accessibility test on a device. Those runtime checks remain separate from this reference.
