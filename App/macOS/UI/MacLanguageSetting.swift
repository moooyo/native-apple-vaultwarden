import SwiftUI

enum MacLanguagePreference: String, CaseIterable {
    case system
    case english = "en"
    case simplifiedChinese = "zh-Hans"

    static let defaultsKey = "openvault.mac.interfaceLanguage"

    init(defaults: UserDefaults) {
        self = defaults.string(forKey: Self.defaultsKey).flatMap(Self.init(rawValue:)) ?? .system
    }

    func locale(in bundle: Bundle = .main, regionalLocale: Locale = .current) -> Locale {
        let language: String
        switch self {
        case .system:
            language = bundle.preferredLocalizations.first ?? Self.simplifiedChinese.rawValue
            if Locale.Language(identifier: language).isEquivalent(to: regionalLocale.language) { return regionalLocale }
        case .english, .simplifiedChinese:
            language = rawValue
        }
        var components = Locale.Components(identifier: language)
        components.region = regionalLocale.region
        return Locale(components: components)
    }

    var label: Text {
        switch self {
        case .system: Text("System")
        case .english: Text(verbatim: "English")
        case .simplifiedChinese: Text(verbatim: Locale(identifier: Self.simplifiedChinese.rawValue)
            .localizedString(forIdentifier: Self.simplifiedChinese.rawValue) ?? "Simplified Chinese")
        }
    }
}

enum MacLocalization {
    static let startupPreference = MacLanguagePreference(defaults: .standard)
    static let interfaceLocale = startupPreference.locale()

    static func text(_ key: String, table: String? = nil, locale: Locale = interfaceLocale) -> String {
        Bundle.main.localizedString(forKey: key, value: key, table: table, localizations: [locale.language])
    }

    static func format(_ key: String, _ arguments: CVarArg..., locale: Locale = interfaceLocale) -> String {
        String(format: text(key, locale: locale), locale: locale, arguments: arguments)
    }

    static func formattedDate(_ date: Date, dateStyle: Date.FormatStyle.DateStyle = .abbreviated,
                              timeStyle: Date.FormatStyle.TimeStyle = .omitted, locale: Locale = interfaceLocale) -> String {
        date.formatted(Date.FormatStyle(date: dateStyle, time: timeStyle, locale: locale))
    }
}

extension View {
    func macInterfaceLanguage(_ preference: MacLanguagePreference = MacLocalization.startupPreference) -> some View {
        environment(\.locale, preference.locale())
    }
}

struct MacLanguageSetting: View {
    let activePreference: MacLanguagePreference
    @AppStorage(MacLanguagePreference.defaultsKey) private var preference = MacLanguagePreference.system
    @Environment(\.locale) private var locale

    init(activePreference: MacLanguagePreference = MacLocalization.startupPreference) {
        self.activePreference = activePreference
    }

    var body: some View {
        Picker(MacLocalization.text("Language", locale: locale), selection: $preference) {
            ForEach(MacLanguagePreference.allCases, id: \.self) { option in
                option.label.tag(option)
            }
        }
        .accessibilityIdentifier("settings.language")
        Text(preference == activePreference ? "Language changes apply after restarting OpenVault." : "Restart OpenVault to apply the selected language.")
            .foregroundStyle(.secondary)
            .font(.footnote)
    }
}
