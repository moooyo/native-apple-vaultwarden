import Foundation

/// Options controlling password generation (mirrors Bitwarden's generator).
public struct PasswordGeneratorOptions: Sendable, Equatable {
    public var length: Int            // >= 5
    public var useLowercase: Bool
    public var useUppercase: Bool
    public var useNumbers: Bool
    public var useSpecial: Bool
    public var minNumbers: Int        // >= 0
    public var minSpecial: Int        // >= 0
    public var avoidAmbiguous: Bool   // exclude I l 1 O 0 o etc.

    public init(length: Int = 14, useLowercase: Bool = true, useUppercase: Bool = true,
                useNumbers: Bool = true, useSpecial: Bool = false,
                minNumbers: Int = 1, minSpecial: Int = 0, avoidAmbiguous: Bool = false) {
        self.length = length
        self.useLowercase = useLowercase
        self.useUppercase = useUppercase
        self.useNumbers = useNumbers
        self.useSpecial = useSpecial
        self.minNumbers = minNumbers
        self.minSpecial = minSpecial
        self.avoidAmbiguous = avoidAmbiguous
    }
}

/// Errors raised by the password/passphrase generators.
public enum GeneratorError: Error, Equatable {
    case noCharacterSetSelected
    case lengthTooShort
    case invalidOptions
}

public enum PasswordGenerator {
    // Full character sets.
    static let lowercaseFull = Array("abcdefghijklmnopqrstuvwxyz")
    static let uppercaseFull = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    static let numbersFull = Array("0123456789")
    static let specialFull = Array("!@#$%^&*")

    // Ambiguous-excluded variants drop I, l, 1, O, 0, o. (special has no ambiguous chars)
    static let lowercaseSafe = Array("abcdefghijkmnpqrstuvwxyz")    // no l, o
    static let uppercaseSafe = Array("ABCDEFGHJKLMNPQRSTUVWXYZ")    // no I, O
    static let numbersSafe = Array("23456789")                      // no 0, 1

    public static func estimatedEntropy(for options: PasswordGeneratorOptions) -> Double? {
        let groups = characterGroups(options)
        let required = groups.reduce(0) { $0 + $1.minimum }
        guard !groups.isEmpty, options.length >= max(5, required) else { return nil }
        let pool = groups.reduce(0) { $0 + $1.characters.count }
        let fixedDraws = groups.reduce(0.0) { $0 + Double($1.minimum) * log2(Double($1.characters.count)) }
        return fixedDraws + Double(options.length - required) * log2(Double(pool))
    }

    private static func characterGroups(_ options: PasswordGeneratorOptions) -> [(characters: [Character], minimum: Int)] {
        var groups: [(characters: [Character], minimum: Int)] = []
        if options.useLowercase { groups.append((options.avoidAmbiguous ? lowercaseSafe : lowercaseFull, 1)) }
        if options.useUppercase { groups.append((options.avoidAmbiguous ? uppercaseSafe : uppercaseFull, 1)) }
        if options.useNumbers { groups.append((options.avoidAmbiguous ? numbersSafe : numbersFull, max(options.minNumbers, 1))) }
        if options.useSpecial { groups.append((specialFull, max(options.minSpecial, 1))) }
        return groups
    }

    /// Generate a password meeting the options' constraints.
    public static func generate(_ options: PasswordGeneratorOptions,
                                using source: RandomSource = SystemRandomSource()) throws -> String {
        // Validation
        guard options.useLowercase || options.useUppercase || options.useNumbers || options.useSpecial else {
            throw GeneratorError.noCharacterSetSelected
        }
        guard options.length >= 5 else { throw GeneratorError.lengthTooShort }
        guard options.minNumbers >= 0, options.minSpecial >= 0 else { throw GeneratorError.invalidOptions }

        let groups = characterGroups(options)
        guard groups.reduce(0, { $0 + $1.minimum }) <= options.length else {
            throw GeneratorError.invalidOptions
        }

        let union = groups.flatMap { $0.characters }

        func pick(_ set: [Character]) -> Character {
            set[source.int(upperBound: set.count)]
        }

        // Place the required minimums first.
        var chars: [Character] = []
        for group in groups {
            for _ in 0..<group.minimum { chars.append(pick(group.characters)) }
        }

        // Fill the remainder from the union.
        while chars.count < options.length {
            chars.append(pick(union))
        }

        // Fisher–Yates shuffle so the required chars aren't always in fixed positions.
        if chars.count > 1 {
            for i in stride(from: chars.count - 1, to: 0, by: -1) {
                let j = source.int(upperBound: i + 1)
                chars.swapAt(i, j)
            }
        }

        return String(chars)
    }
}
