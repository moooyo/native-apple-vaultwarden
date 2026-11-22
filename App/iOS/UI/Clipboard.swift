import UIKit
import UniformTypeIdentifiers
import AppShared

@MainActor
enum Clipboard {
    static func copy(_ value: String) {
        copy(value, expiresAfter: AppShared.Preference.clipboardLifetime(in: AppShared.Preference.defaults))
    }

    static func copy(_ value: String, expiresAfter seconds: TimeInterval?) {
        var options: [UIPasteboard.OptionsKey: Any] = [.localOnly: true]
        if let seconds, seconds > 0 {
            options[.expirationDate] = Date().addingTimeInterval(seconds)
        }
        UIPasteboard.general.setItems([[UTType.utf8PlainText.identifier: value]], options: options)
    }
}
