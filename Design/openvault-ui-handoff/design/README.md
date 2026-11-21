# Design source index

The [canvas manifest](canvas.json) contains the original board order, titles, dimensions and canvas positions. The [shared stylesheet](ov-kit.css) defines the prototype's semantic color, spacing, type, glass and control treatments, including `.dark`, `.hc` and `.mac` variants. These are source references; the SwiftUI app does not load them at runtime. See the [handoff](../HANDOFF.md#product-corrections) for approved differences from the drawings.

Each board's `<x-dc>` markup describes its visual hierarchy and labels. `{{name}}` values, `<sc-if>` conditions, `<sc-for>` lists and interaction handlers are supplied by `renderVals()` in the embedded `text/x-dc` script. The interactive renderer is not included in this export; opening a board directly in a browser is not an app preview. All sample content and identities in these files are illustrative.

## iPhone (16 boards, 402 × 874)

| Flow | Boards |
| --- | --- |
| Account access | [Sign in and two-factor verification](boards/iPhone-Login.dc.html), [Unlock](boards/iPhone-Unlock.dc.html) |
| Browse and edit | [Vault home](boards/Main.dc.html), [Search](boards/iPhone-Search.dc.html), [Item details](boards/iPhone-Item.dc.html), [New item](boards/iPhone-NewItem.dc.html) |
| Organization | [Folder contents](boards/iPhone-Folder.dc.html), [Manage folders](boards/iPhone-Folders.dc.html), [Trash and archive](boards/iPhone-Trash.dc.html) |
| Tools | [Codes](boards/iPhone-Codes.dc.html), [Generator](boards/iPhone-Generator.dc.html), [Send](boards/iPhone-Send.dc.html), [New Send](boards/iPhone-SendNew.dc.html) |
| Settings and system integration | [Settings](boards/iPhone-Settings.dc.html), [Import and export](boards/iPhone-ImportExport.dc.html), [AutoFill](boards/iPhone-AutoFill.dc.html) |

## iPad (9 boards, 1194 × 834)

| Flow | Boards |
| --- | --- |
| Account access | [Sign in and two-factor verification](boards/iPad-Login.dc.html), [Unlock](boards/iPad-Unlock.dc.html) |
| Adaptive workspace | [Vault](boards/iPad-Vault.dc.html), [Search](boards/iPad-Search.dc.html), [New item](boards/iPad-NewItem.dc.html) |
| Tools and settings | [Codes](boards/iPad-Codes.dc.html), [Send](boards/iPad-Send.dc.html), [Generator](boards/iPad-Generator.dc.html), [Settings](boards/iPad-Settings.dc.html) |

## Mac (13 boards)

| Reference size | Boards |
| --- | --- |
| 1280 × 800 | [Unlock](boards/Mac-Unlock.dc.html), [Vault](boards/Mac-Vault.dc.html), [Codes](boards/Mac-Codes.dc.html), [Generator](boards/Mac-Generator.dc.html), [Item form in context](boards/Mac-Edit.dc.html), [Send](boards/Mac-Send.dc.html), [Trash and archive](boards/Mac-Trash.dc.html) |
| 560 × 500 | [Sign in and two-factor verification](boards/Mac-Login.dc.html), [Export](boards/Mac-Export.dc.html) |
| 600 × 600 | [New Send](boards/Mac-SendNew.dc.html) |
| 560 × 340 | [Import](boards/Mac-Import.dc.html) |
| 720 × 330 | [Settings](boards/Mac-Settings.dc.html) |
| 380 × 560 | [Menu-bar panel](boards/Mac-MenuBar.dc.html) |

## Shared specification (1 board, 1600 × 5000)

[Design system and SwiftUI mapping](boards/Spec.dc.html): component treatments, color roles, contrast notes, interaction policies and feature coverage.
