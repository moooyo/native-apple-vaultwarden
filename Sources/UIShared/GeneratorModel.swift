import Foundation
import Observation
import Generators

/// Drives password, passphrase and enhanced-alias generation. Holds option bindings,
/// generation history and the latest value. A `RandomSource` is injected so tests are
/// deterministic; production uses the CSPRNG-backed default.
@MainActor
@Observable
public final class GeneratorModel {
    public enum Mode: Equatable, Sendable {
        case password
        case passphrase
        case username
    }

    public var mode: Mode = .password {
        didSet { if mode != oldValue { regenerate() } }
    }

    /// Password options bound by the view.
    public var passwordOptions = PasswordGeneratorOptions(
        length: 20,
        useLowercase: true,
        useUppercase: true,
        useNumbers: true,
        useSpecial: true
    )
    /// Passphrase options bound by the view.
    public var passphraseOptions = PassphraseGeneratorOptions()

    /// Enhanced alias settings used by the username mode.
    public var usernameBase = "openvault"
    public var usernameDomain = "icloud.com"
    public var usernameSuffixLength = 4

    public private(set) var generated: String = ""
    public private(set) var history: [String] = []
    /// A non-fatal message when the current options can't produce a value (e.g. no character
    /// set selected). `nil` when the last generation succeeded.
    public private(set) var errorMessage: String?

    private let source: RandomSource
    private let wordList: [String]

    /// - Parameters:
    ///   - source: random source (inject a deterministic mock in tests).
    ///   - wordList: an optional passphrase word list. `nil` selects the bundled compact list;
    ///     an explicitly empty list remains useful for testing the error state.
    public init(source: RandomSource = SystemRandomSource(), wordList: [String]? = nil) {
        self.source = source
        self.wordList = wordList ?? Self.productionWordList
    }

    /// (Re)generate using the current mode + options. Result lands in `generated`; on invalid
    /// options `generated` is cleared and `errorMessage` is set.
    public func regenerate(recordInHistory: Bool = false) {
        do {
            let value: String
            switch mode {
            case .password:
                value = try PasswordGenerator.generate(passwordOptions, using: source)
            case .passphrase:
                value = try PassphraseGenerator.generate(passphraseOptions,
                                                         wordList: wordList, using: source)
            case .username:
                value = try generateUsername()
            }
            generated = value
            if recordInHistory { record(value) }
            errorMessage = nil
        } catch {
            generated = ""
            if error is UsernameValidationError {
                errorMessage = "Enter a valid alias name and email domain."
            } else {
                errorMessage = Self.message(for: error)
            }
        }
    }

    /// The value to place on the clipboard, or `nil` if nothing was generated.
    public func copyGenerated() -> String? {
        guard !generated.isEmpty else { return nil }
        record(generated)
        return generated
    }

    private func record(_ value: String) {
        guard history.first != value else { return }
        history.insert(value, at: 0)
        if history.count > 20 { history.removeLast(history.count - 20) }
    }

    private enum UsernameValidationError: Error { case invalidAlias }

    private func generateUsername() throws -> String {
        let alphabet = Array("abcdefghjkmnpqrstuvwxyz23456789")
        let suffix = String((0..<max(2, min(usernameSuffixLength, 12))).map { _ in
            alphabet[source.int(upperBound: alphabet.count)]
        })
        let base = usernameBase.trimmingCharacters(in: .whitespacesAndNewlines)
        let domain = usernameDomain.trimmingCharacters(in: .whitespacesAndNewlines)
        let localAllowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "._-"))
        let domainAllowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-")
        let labels = domain.split(separator: ".", omittingEmptySubsequences: false)
        guard !base.isEmpty,
              base.unicodeScalars.allSatisfy(localAllowed.contains),
              !domain.isEmpty,
              domain.unicodeScalars.allSatisfy(domainAllowed.contains),
              labels.count >= 2,
              labels.allSatisfy({ !$0.isEmpty && !$0.hasPrefix("-") && !$0.hasSuffix("-") }) else {
            throw UsernameValidationError.invalidAlias
        }
        return "\(base)+\(suffix)@\(domain)"
    }

    private static let productionWordList: [String] = {
        guard let url = Bundle.module.url(forResource: "eff_large_wordlist", withExtension: "txt"),
              let contents = try? String(contentsOf: url, encoding: .utf8) else {
            return []
        }
        return contents.split(whereSeparator: \.isNewline).compactMap { line in
            line.split(whereSeparator: \.isWhitespace).last.map(String.init)
        }
    }()

    static func message(for error: Error) -> String {
        guard let gen = error as? GeneratorError else { return "Could not generate a value." }
        switch gen {
        case .noCharacterSetSelected: return "Select at least one character set."
        case .lengthTooShort: return "Length must be at least 5."
        case .invalidOptions: return "These options can't produce a value."
        }
    }
}
