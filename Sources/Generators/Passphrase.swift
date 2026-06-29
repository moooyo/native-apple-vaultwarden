import Foundation

/// Options controlling passphrase generation (mirrors Bitwarden's generator).
public struct PassphraseGeneratorOptions: Sendable, Equatable {
    public var wordCount: Int         // >= 3
    public var separator: String      // default "-"
    public var capitalize: Bool
    public var includeNumber: Bool

    public init(wordCount: Int = 3, separator: String = "-", capitalize: Bool = false, includeNumber: Bool = false) {
        self.wordCount = wordCount
        self.separator = separator
        self.capitalize = capitalize
        self.includeNumber = includeNumber
    }
}

public enum PassphraseGenerator {
    /// Generate a passphrase from an injected `wordList`.
    ///
    /// The production EFF/Bitwarden word list (7776 words) ships as a SwiftPM
    /// resource in a later milestone; for now the caller injects the list so this
    /// generator stays pure and deterministically testable.
    public static func generate(_ options: PassphraseGeneratorOptions,
                                wordList: [String],
                                using source: RandomSource = SystemRandomSource()) throws -> String {
        guard options.wordCount >= 3 else { throw GeneratorError.invalidOptions }
        guard !wordList.isEmpty else { throw GeneratorError.invalidOptions }

        // Pick the words.
        var words: [String] = []
        for _ in 0..<options.wordCount {
            var word = wordList[source.int(upperBound: wordList.count)]
            if options.capitalize {
                word = word.prefix(1).uppercased() + word.dropFirst()
            }
            words.append(word)
        }

        // Append a single digit to one chosen word, if requested.
        if options.includeNumber {
            let idx = source.int(upperBound: words.count)
            let digit = source.int(upperBound: 10)
            words[idx] += String(digit)
        }

        return words.joined(separator: options.separator)
    }
}
