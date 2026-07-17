import Foundation
import Generators
import UIShared

@MainActor
func checkGeneratorPasswordDeterministic(_ r: inout TestRunner) async {
    // Two models with identically-seeded mock sources must yield the same password (proving
    // the RandomSource injection makes generation deterministic).
    let seq = [3, 7, 1, 9, 5, 2, 8, 0, 4, 6, 11, 13, 17, 19, 23]
    let m1 = GeneratorModel(source: MockRandomSource(seq))
    let m2 = GeneratorModel(source: MockRandomSource(seq))
    m1.passwordOptions = PasswordGeneratorOptions(length: 12)
    m2.passwordOptions = PasswordGeneratorOptions(length: 12)

    m1.regenerate()
    m2.regenerate()

    r.expect(m1.generated.count, 12, "Generator: password honors length")
    r.expect(m1.generated, m2.generated, "Generator: deterministic for identical sources")
    r.expectNil(m1.errorMessage, "Generator: no error on valid options")
    r.expect(m1.copyGenerated(), m1.generated, "Generator: copyGenerated returns the password")
}

@MainActor
func checkGeneratorPassphraseGoldenVector(_ r: inout TestRunner) async {
    // wordList + sequence chosen so the output is fully predictable:
    // sequence [0,1,2] → picks alpha, bravo, charlie → "alpha-bravo-charlie".
    let words = ["alpha", "bravo", "charlie", "delta"]
    let model = GeneratorModel(source: MockRandomSource([0, 1, 2]), wordList: words)
    model.passphraseOptions = PassphraseGeneratorOptions(wordCount: 3, separator: "-",
                                                         capitalize: false, includeNumber: false)
    model.mode = .passphrase  // didSet triggers regenerate()

    r.expect(model.generated, "alpha-bravo-charlie", "Generator: passphrase golden vector")
    r.expectNil(model.errorMessage, "Generator: no error on valid passphrase options")
}

@MainActor
func checkGeneratorModeSwitch(_ r: inout TestRunner) async {
    let words = ["alpha", "bravo", "charlie", "delta"]
    let model = GeneratorModel(source: MockRandomSource([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]),
                               wordList: words)
    model.passwordOptions = PasswordGeneratorOptions(length: 8)

    model.regenerate()  // password mode
    r.expect(model.mode, .password, "Generator: starts in password mode")
    let pw = model.generated
    r.expect(pw.count, 8, "Generator: password length 8")
    r.expectFalse(pw.contains("-"), "Generator: password has no separator")

    model.mode = .passphrase  // didSet regenerates as a passphrase
    r.expectTrue(model.generated.contains("-"), "Generator: passphrase contains separator after switch")
}

@MainActor
func checkGeneratorInvalidOptions(_ r: inout TestRunner) async {
    let model = GeneratorModel(source: MockRandomSource([0]))
    // No character set selected → GeneratorError.noCharacterSetSelected.
    model.passwordOptions = PasswordGeneratorOptions(length: 10, useLowercase: false,
                                                     useUppercase: false, useNumbers: false,
                                                     useSpecial: false)
    model.regenerate()

    r.expect(model.generated, "", "Generator: invalid options clear generated")
    r.expectNotNil(model.errorMessage, "Generator: invalid options set errorMessage")
}

@MainActor
func checkGeneratorPassphraseNoWordList(_ r: inout TestRunner) async {
    // Passphrase mode with an empty word list → clear error, no crash.
    let model = GeneratorModel(source: MockRandomSource([0, 1, 2]), wordList: [])
    model.mode = .passphrase

    r.expect(model.generated, "", "Generator: empty word list → no passphrase")
    r.expectNotNil(model.errorMessage, "Generator: empty word list sets errorMessage")
}

@MainActor
func checkGeneratorUsernameAndHistory(_ r: inout TestRunner) async {
    let model = GeneratorModel(source: MockRandomSource([0, 1, 2, 3, 4, 5, 6, 7]))
    model.usernameBase = "li.wei"
    model.usernameDomain = "icloud.com"
    model.usernameSuffixLength = 4
    model.mode = .username

    r.expect(model.generated, "li.wei+abcd@icloud.com", "Generator: username alias golden vector")
    r.expect(model.history.count, 0, "Generator: live previews do not enter history")

    let first = model.generated
    model.regenerate(recordInHistory: true)
    r.expectFalse(model.generated == first, "Generator: username regeneration advances random suffix")
    r.expect(model.history.first, Optional(model.generated), "Generator: explicit generation enters history")
    _ = model.copyGenerated()
    r.expect(model.history.count, 1, "Generator: duplicate copy does not duplicate history")
}

@MainActor
func checkGeneratorBundledWordList(_ r: inout TestRunner) async {
    let model = GeneratorModel(source: MockRandomSource([0, 1, 2]))
    model.passphraseOptions = PassphraseGeneratorOptions(
        wordCount: 3,
        separator: "-",
        capitalize: false,
        includeNumber: false
    )
    model.mode = .passphrase

    r.expect(model.generated.split(separator: "-").count, 3,
             "Generator: bundled EFF list produces a three-word passphrase")
    r.expectNil(model.errorMessage, "Generator: bundled EFF list loads without error")
}

@MainActor
func checkGeneratorRejectsInvalidUsername(_ r: inout TestRunner) async {
    let model = GeneratorModel(source: MockRandomSource([0, 1, 2, 3]))
    model.usernameBase = "bad@alias"
    model.usernameDomain = "not a domain"
    model.mode = .username

    r.expect(model.generated, "", "Generator: invalid username options clear preview")
    r.expectNotNil(model.errorMessage, "Generator: invalid username options surface an error")
}
