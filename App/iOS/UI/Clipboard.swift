// Xcode-only target (UI-iOS / UI-mac). Not part of the SPM build.
//
// Clipboard — the iOS pasteboard seam. UIShared view models deliberately RETURN the
// string to copy (they never touch the pasteboard), so the platform copy + clear-after
// policy lives here in an iOS-only file. `UIPasteboard` is fine here per the plan.

import UIKit
import UniformTypeIdentifiers

enum Clipboard {
    /// Copy `value` to the general pasteboard. When `expiresAfter` is set, the item is
    /// marked to auto-expire (so a copied password doesn't linger indefinitely).
    static func copy(_ value: String, expiresAfter seconds: TimeInterval? = 90) {
        let pasteboard = UIPasteboard.general
        if let seconds {
            pasteboard.setItems(
                [[UTType.utf8PlainText.identifier: value]],
                options: [.expirationDate: Date().addingTimeInterval(seconds)]
            )
        } else {
            pasteboard.string = value
        }
    }
}
