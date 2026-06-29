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

    /// Generate a password meeting the options' constraints.
    public static func generate(_ options: PasswordGeneratorOptions,
                                using source: RandomSource = SystemRandomSource()) throws -> String {
        // Validation
        guard options.useLowercase || options.useUppercase || options.useNumbers || options.useSpecial else {
            throw GeneratorError.noCharacterSetSelected
        }
        guard options.length >= 5 else { throw GeneratorError.lengthTooShort }
        guard options.minNumbers >= 0, options.minSpecial >= 0 else { throw GeneratorError.invalidOptions }

        let lower = options.avoidAmbiguous ? lowercaseSafe : lowercaseFull
        let upper = options.avoidAmbiguous ? uppercaseSafe : uppercaseFull
        let numbers = options.avoidAmbiguous ? numbersSafe : numbersFull
        let special = specialFull

        // Effective per-set minimums: enabled sets contribute >= 1; numbers/special honor explicit minimums.
        let minLower = options.useLowercase ? 1 : 0
        let minUpper = options.useUppercase ? 1 : 0
        let minNum = options.useNumbers ? max(options.minNumbers, 1) : 0
        let minSpec = options.useSpecial ? max(options.minSpecial, 1) : 0

        guard minLower + minUpper + minNum + minSpec <= options.length else {
            throw GeneratorError.invalidOptions
        }

        // Union of all enabled sets (used to fill the remainder).
        var union: [Character] = []
        if options.useLowercase { union += lower }
        if options.useUppercase { union += upper }
        if options.useNumbers { union += numbers }
        if options.useSpecial { union += special }

        func pick(_ set: [Character]) -> Character {
            set[source.int(upperBound: set.count)]
        }

        // Place the required minimums first.
        var chars: [Character] = []
        for _ in 0..<minLower { chars.append(pick(lower)) }
        for _ in 0..<minUpper { chars.append(pick(upper)) }
        for _ in 0..<minNum { chars.append(pick(numbers)) }
        for _ in 0..<minSpec { chars.append(pick(special)) }

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
