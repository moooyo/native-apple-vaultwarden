import Foundation
@testable import Generators

func checkPassphrase(_ r: inout TestRunner) {
    let words = ["alpha", "bravo", "charlie", "delta"]

    // --- Validation ---
    r.expectThrowsError(GeneratorError.invalidOptions, "wordCount<3 -> invalidOptions") {
        let o = PassphraseGeneratorOptions(wordCount: 2)
        _ = try PassphraseGenerator.generate(o, wordList: words, using: MockRandomSource(sequence: [0]))
    }
    r.expectThrowsError(GeneratorError.invalidOptions, "empty wordList -> invalidOptions") {
        let o = PassphraseGeneratorOptions(wordCount: 3)
        _ = try PassphraseGenerator.generate(o, wordList: [], using: MockRandomSource(sequence: [0]))
    }

    // --- Exact output (deterministic MockRandomSource) ---
    // wordCount=3, separator="-", capitalize=true, includeNumber=true; wordList count 4.
    // Trace: pick 0->alpha, 1->bravo, 2->charlie -> capitalized Alpha,Bravo,Charlie
    //        includeNumber idx 0 -> word[0]; digit 7 -> "Alpha7"
    //        join "-" => "Alpha7-Bravo-Charlie"
    do {
        let o = PassphraseGeneratorOptions(wordCount: 3, separator: "-", capitalize: true, includeNumber: true)
        let phrase = try PassphraseGenerator.generate(o, wordList: words, using: MockRandomSource(sequence: [0, 1, 2, 0, 7]))
        r.expect(phrase, "Alpha7-Bravo-Charlie", "passphrase exact output")
    } catch {
        r.expectTrue(false, "passphrase exact output threw \(error)")
    }

    // --- Property tests over 500 iterations (real SystemRandomSource) ---
    let sys = SystemRandomSource()
    var allOK = true
    for _ in 0..<500 {
        let o = PassphraseGeneratorOptions(wordCount: 4, separator: ".", capitalize: true, includeNumber: true)
        guard let phrase = try? PassphraseGenerator.generate(o, wordList: words, using: sys) else { allOK = false; break }
        let parts = phrase.components(separatedBy: ".")
        if parts.count != 4 { allOK = false; break }
        // Each word starts uppercase (capitalize)
        for part in parts where !(part.first?.isUppercase ?? false) { allOK = false }
        if !allOK { break }
        // Exactly one digit appears (includeNumber appends one digit to one word)
        let digits = phrase.filter { $0.isNumber }
        if digits.count != 1 { allOK = false; break }
        if !(digits.first.map { ("0"..."9").contains($0) } ?? false) { allOK = false; break }
    }
    r.expectTrue(allOK, "passphrase properties hold over 500 iterations")

    // Separator + no-capitalize + no-number property
    var plainOK = true
    for _ in 0..<200 {
        let o = PassphraseGeneratorOptions(wordCount: 3, separator: " ", capitalize: false, includeNumber: false)
        guard let phrase = try? PassphraseGenerator.generate(o, wordList: words, using: sys) else { plainOK = false; break }
        let parts = phrase.components(separatedBy: " ")
        if parts.count != 3 { plainOK = false; break }
        if phrase.contains(where: { $0.isNumber }) { plainOK = false; break }
    }
    r.expectTrue(plainOK, "passphrase plain (no cap/no number) properties hold")
}
