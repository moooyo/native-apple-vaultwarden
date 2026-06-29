import Foundation
import Observation
import Generators

/// Drives the password/passphrase generator screen. Holds the options bindings, switches
/// between modes, and produces `generated`. A `RandomSource` is injected so tests are
/// deterministic; production uses the CSPRNG-backed default.
@MainActor
@Observable
public final class GeneratorModel {
    public enum Mode: Equatable, Sendable {
        case password
        case passphrase
    }

    public var mode: Mode = .password {
        didSet { if mode != oldValue { regenerate() } }
    }

    /// Password options bound by the view.
    public var passwordOptions = PasswordGeneratorOptions()
    /// Passphrase options bound by the view.
    public var passphraseOptions = PassphraseGeneratorOptions()

    public private(set) var generated: String = ""
    /// A non-fatal message when the current options can't produce a value (e.g. no character
    /// set selected). `nil` when the last generation succeeded.
    public private(set) var errorMessage: String?

    private let source: RandomSource
    private let wordList: [String]

    /// - Parameters:
    ///   - source: random source (inject a deterministic mock in tests).
    ///   - wordList: the passphrase word list. The production EFF list is supplied by the app;
    ///     defaults to empty (passphrase mode then surfaces a clear error until a list is set).
    public init(source: RandomSource = SystemRandomSource(), wordList: [String] = []) {
        self.source = source
        self.wordList = wordList
    }

    /// (Re)generate using the current mode + options. Result lands in `generated`; on invalid
    /// options `generated` is cleared and `errorMessage` is set.
    public func regenerate() {
        do {
            switch mode {
            case .password:
                generated = try PasswordGenerator.generate(passwordOptions, using: source)
            case .passphrase:
                generated = try PassphraseGenerator.generate(passphraseOptions,
                                                             wordList: wordList, using: source)
            }
            errorMessage = nil
        } catch {
            generated = ""
            errorMessage = Self.message(for: error)
        }
    }

    /// The value to place on the clipboard, or `nil` if nothing was generated.
    public func copyGenerated() -> String? {
        generated.isEmpty ? nil : generated
    }

    static func message(for error: Error) -> String {
        guard let gen = error as? GeneratorError else { return "Could not generate a value." }
        switch gen {
        case .noCharacterSetSelected: return "Select at least one character set."
        case .lengthTooShort: return "Length must be at least 5."
        case .invalidOptions: return "These options can't produce a value."
        }
    }
}
