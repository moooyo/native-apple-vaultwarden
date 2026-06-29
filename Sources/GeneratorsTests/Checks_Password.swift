import Foundation
@testable import Generators

func checkPassword(_ r: inout TestRunner) {
    // --- Validation ---
    r.expectThrowsError(GeneratorError.noCharacterSetSelected, "no sets -> noCharacterSetSelected") {
        var o = PasswordGeneratorOptions(length: 10)
        o.useLowercase = false; o.useUppercase = false; o.useNumbers = false; o.useSpecial = false
        _ = try PasswordGenerator.generate(o, using: MockRandomSource(sequence: [0]))
    }
    r.expectThrowsError(GeneratorError.lengthTooShort, "length<5 -> lengthTooShort") {
        let o = PasswordGeneratorOptions(length: 4)
        _ = try PasswordGenerator.generate(o, using: MockRandomSource(sequence: [0]))
    }
    r.expectThrowsError(GeneratorError.invalidOptions, "minNumbers+minSpecial>length -> invalidOptions") {
        var o = PasswordGeneratorOptions(length: 5)
        o.useLowercase = true; o.useUppercase = true; o.useNumbers = true; o.useSpecial = true
        o.minNumbers = 3; o.minSpecial = 3
        _ = try PasswordGenerator.generate(o, using: MockRandomSource(sequence: [0]))
    }

    // --- Exact output (deterministic MockRandomSource) ---
    // Options: length=5, lower+numbers only, minNumbers=2.
    // Trace:
    //   minLower(1): pick lower(26) seq 0 -> 'a'
    //   minNum(2):   pick numbers(10) seq 1 -> '1', seq 2 -> '2'
    //   fill(2):     pick union(36) seq 26 -> '0', seq 3 -> 'd'   (union = lower+numbers)
    //   chars = a 1 2 0 d
    //   FY: i=4 j=0 swap -> d 1 2 0 a ; i=3 j=1 swap -> d 0 2 1 a ;
    //       i=2 j=2 noop  -> d 0 2 1 a ; i=1 j=0 swap -> 0 d 2 1 a
    //   => "0d21a"
    do {
        var o = PasswordGeneratorOptions(length: 5)
        o.useLowercase = true; o.useUppercase = false; o.useNumbers = true; o.useSpecial = false
        o.minNumbers = 2; o.minSpecial = 0; o.avoidAmbiguous = false
        let seq = [0, 1, 2, 26, 3, 0, 1, 2, 0]
        let pw = try PasswordGenerator.generate(o, using: MockRandomSource(sequence: seq))
        r.expect(pw, "0d21a", "password exact output")
    } catch {
        r.expectTrue(false, "password exact output threw \(error)")
    }

    // --- Property tests over 500 iterations (real SystemRandomSource) ---
    let sys = SystemRandomSource()
    let lowerSet = Set("abcdefghijklmnopqrstuvwxyz")
    let upperSet = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    let numberSet = Set("0123456789")
    let specialSet = Set("!@#$%^&*")
    let ambiguous = Set("Il1O0o")

    var allOK = true
    for _ in 0..<500 {
        var o = PasswordGeneratorOptions(length: 16)
        o.useLowercase = true; o.useUppercase = true; o.useNumbers = true; o.useSpecial = true
        o.minNumbers = 3; o.minSpecial = 2; o.avoidAmbiguous = true
        guard let pw = try? PasswordGenerator.generate(o, using: sys) else { allOK = false; break }
        let chars = Array(pw)
        if chars.count != 16 { allOK = false; break }
        let allowed = lowerSet.union(upperSet).union(numberSet).union(specialSet)
        if !chars.allSatisfy({ allowed.contains($0) }) { allOK = false; break }
        if chars.filter({ numberSet.contains($0) }).count < 3 { allOK = false; break }
        if chars.filter({ specialSet.contains($0) }).count < 2 { allOK = false; break }
        if !chars.contains(where: { lowerSet.contains($0) }) { allOK = false; break }
        if !chars.contains(where: { upperSet.contains($0) }) { allOK = false; break }
        if chars.contains(where: { ambiguous.contains($0) }) { allOK = false; break }
    }
    r.expectTrue(allOK, "password properties hold over 500 iterations")
}
