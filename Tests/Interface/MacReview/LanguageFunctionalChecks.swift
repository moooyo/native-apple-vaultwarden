import AppKit
import Generators
import SwiftUI
import UIShared
import VaultModels
import VaultRepository

extension ReviewBoards {
    func checkInterfaceLanguage() async throws {
        let (preferences, suite) = try isolatedPreferences()
        defer { preferences.removePersistentDomain(forName: suite) }
        try require(preferences.persistentDomain(forName: suite)?[MacLanguagePreference.defaultsKey] == nil,
                    "the new profile has no explicit language override")
        preferences.set("unsupported", forKey: MacLanguagePreference.defaultsKey)
        try require(MacLanguagePreference(defaults: preferences) == .system, "unknown preference follows the system")
        let regionalLocale = Locale(identifier: "en-CA")
        let renderer = WindowRenderer(directory: FileManager.default.temporaryDirectory, dark: false)
        let item = PlaintextCipher(id: "review-login", name: "Language fixture", notes: "回收站",
                                   login: .init(username: "review@example.invalid"))
        let card = PlaintextCipher(type: CipherType.card.rawValue, name: "Review card", card: .init(number: "0000 4242"))
        let configuration = TOTPConfiguration(secret: Data(repeating: 23, count: 20), algorithm: .sha1, digits: 6, period: 30, isSteam: false)
        for (preference, emailPrompt, loginError, pickerTitle, restartNote) in [
            (MacLanguagePreference.english, "Email address", "Authentication failed. Check your input and try again.",
             "Language", "Language changes apply after restarting OpenVault."),
            (.simplifiedChinese, "邮箱地址", "验证失败，请检查输入后重试。", "语言", "语言更改将在重新启动 OpenVault 后生效。")
        ] {
            preferences.set(preference.rawValue, forKey: MacLanguagePreference.defaultsKey)
            let persisted = MacLanguagePreference(defaults: preferences)
            try require(persisted == preference, "a new launch reads the selected language")
            let locale = persisted.locale(regionalLocale: regionalLocale)
            try require(locale.region == regionalLocale.region, "the interface language does not change the system region")
            try require(MacLocalization.text("验证失败，请检查输入后重试。", locale: locale) == loginError,
                        "dynamic authentication messages use the selected language")
            try require(card.macSubtitle(in: locale) == (preference == .english ? "Ending in 4242" : "尾号 4242")
                        && MacLocalization.text(MacDestination.all.titleKey, locale: locale) == (preference == .english ? "All items" : "全部条目"),
                        "workspace titles and derived summaries use the view language")
            try await renderer.inspect(width: 560, height: 640) {
                VStack(spacing: 0) {
                    MacLoginView(model: LoginModel(auth: FakeAuthService(), defaults: preferences)) { _ in }
                    MacLanguageSetting(activePreference: persisted).padding()
                }
                .defaultAppStorage(preferences)
                .macInterfaceLanguage(persisted)
            } perform: { window in
                _ = try await reviewAX(.textField, named: emailPrompt, in: window)
                _ = try await reviewAX(.staticText, named: restartNote, in: window)
                _ = try await reviewAX(.staticText, named: pickerTitle, in: window)
                _ = try await reviewAX(.popUpButton, named: "settings.language", in: window)
                preferences.set(MacLanguagePreference.system.rawValue, forKey: MacLanguagePreference.defaultsKey)
                let pendingNote = preference == .english ? "Restart OpenVault to apply the selected language." : "重新启动 OpenVault 以应用所选语言。"
                _ = try await reviewAX(.staticText, named: pendingNote, in: window)
                _ = try await reviewAX(.textField, named: emailPrompt, in: window)
            }
            try await renderer.inspect(width: 780, height: 500) {
                MacItemDetailView(cipher: item, vault: FakeVaultService(), onEdit: {}, onChanged: {})
                    .macInterfaceLanguage(persisted)
            } perform: { window in
                _ = try await reviewAX(.staticText, named: "回收站", in: window)
            }
            try await renderer.inspect(width: 780, height: 500) {
                VStack {
                    MacDetailRow("备注") { Text("synthetic field value") }
                    MacCodeCopyRow(configuration: configuration, date: .now, copied: false, action: {})
                }
                .macInterfaceLanguage(persisted)
            } perform: { window in
                _ = try await reviewAX(.staticText, named: preference == .english ? "Notes" : "备注", in: window)
                _ = try await reviewAX(.button, named: preference == .english ? "Copy verification code" : "拷贝验证码", in: window)
            }
        }
        preferences.set(MacLanguagePreference.system.rawValue, forKey: MacLanguagePreference.defaultsKey)
        let reset = MacLanguagePreference(defaults: preferences)
        try require(reset == .system && reset.locale().language.isEquivalent(to: Locale.Language(identifier: Bundle.main.preferredLocalizations.first ?? "zh-Hans")),
                    "restoring System uses the bundle's preferred localization")
        try require(preferences.persistentDomain(forName: suite)?["AppleLanguages"] == nil
                    && preferences.persistentDomain(forName: suite)?["AppleLocale"] == nil, "the setting does not write Apple locale preferences")
        print("Language: isolated preference, System reset, English and Simplified Chinese sign-in, detail, and verification codes passed.")
    }
}
