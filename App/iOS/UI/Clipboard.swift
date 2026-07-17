import UIKit
import UniformTypeIdentifiers
import DesignSystem

enum Clipboard {
    static func copy(_ value: String) {
        copy(value, expiresAfter: preferredExpiration)
    }

    static func copy(_ value: String, expiresAfter seconds: TimeInterval?) {
        let pasteboard = UIPasteboard.general
        if let seconds, seconds > 0 {
            pasteboard.setItems(
                [[UTType.utf8PlainText.identifier: value]],
                options: [.expirationDate: Date().addingTimeInterval(seconds)]
            )
        } else {
            pasteboard.string = value
        }
    }

    private static var preferredExpiration: TimeInterval? {
        let defaults = UserDefaults.standard
        guard defaults.object(forKey: OpenVaultPreferenceKey.clipboardTimeout) != nil else {
            return 30
        }
        let seconds = defaults.double(forKey: OpenVaultPreferenceKey.clipboardTimeout)
        return seconds > 0 ? seconds : nil
    }
}
