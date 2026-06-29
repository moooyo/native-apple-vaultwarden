# Generators (Password + Passphrase) Implementation Plan (M1+ · Plan 5/N)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Checkbox steps.
> Pulled forward from M2 at user request — extends the existing `Generators` package (which already has TOTP).

**Goal:** Add **password** and **passphrase** generation to the `Generators` package, matching Bitwarden's generator semantics: character-class password generation (upper/lower/number/special, minimums, avoid-ambiguous) and word-based passphrases (word count, separator, capitalize, include-number), all using an **injectable, unbiased random source** so output is deterministic in tests and CSPRNG-backed in production.

**Architecture:** Add to the existing `Generators` library a `RandomSource` protocol (default `SystemRandomSource` using `CryptoCore.SecureRandom` with rejection sampling to avoid modulo bias) and two pure generators. Injecting `RandomSource` makes generation fully testable (a `MockRandomSource` yields exact strings) while production uses the CSPRNG. Tests use the CLT executable convention (`swift run GeneratorsTests`).

**Tech Stack:** Swift 6 (`swift-tools-version: 6.2`), `CryptoCore` (SecureRandom), Foundation.

> **⚠️ TESTING CONVENTION** (same as prior plans): no XCTest; extend the existing `GeneratorsTests` executable; TDD: check → fail → implement → pass → commit. Randomized logic is tested two ways: (a) **exact output** via a deterministic `MockRandomSource`; (b) **properties** (length, required classes present, minimums satisfied, only-allowed chars, ambiguous excluded) over many iterations with the real `SystemRandomSource`.

---

## File Structure

```
Sources/Generators/
  RandomSource.swift       # protocol + SystemRandomSource (unbiased) + helpers
  PasswordGenerator.swift  # PasswordGeneratorOptions + PasswordGenerator
  Passphrase.swift         # PassphraseGeneratorOptions + PassphraseGenerator
Sources/GeneratorsTests/
  MockRandomSource.swift   # deterministic source for exact-output tests
  Checks_Random.swift
  Checks_Password.swift
  Checks_Passphrase.swift
```

**Public API:**
```swift
public protocol RandomSource: Sendable {
    /// Uniform random Int in 0..<upperBound (upperBound > 0).
    func int(upperBound: Int) -> Int
}
public struct SystemRandomSource: RandomSource { public init(); public func int(upperBound: Int) -> Int }

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
                minNumbers: Int = 1, minSpecial: Int = 0, avoidAmbiguous: Bool = false)
}

public enum GeneratorError: Error, Equatable { case noCharacterSetSelected, lengthTooShort, invalidOptions }

public enum PasswordGenerator {
    public static func generate(_ options: PasswordGeneratorOptions, using source: RandomSource = SystemRandomSource()) throws -> String
}

public struct PassphraseGeneratorOptions: Sendable, Equatable {
    public var wordCount: Int         // >= 3
    public var separator: String      // default "-"
    public var capitalize: Bool
    public var includeNumber: Bool
    public init(wordCount: Int = 3, separator: String = "-", capitalize: Bool = false, includeNumber: Bool = false)
}

public enum PassphraseGenerator {
    /// `wordList` is injected (the full EFF/Bitwarden list ships as a resource in a later task/milestone).
    public static func generate(_ options: PassphraseGeneratorOptions, wordList: [String],
                                using source: RandomSource = SystemRandomSource()) throws -> String
}
```

---

### Task 1: RandomSource (unbiased) + MockRandomSource

**Files:** create `Sources/Generators/RandomSource.swift`, `Sources/GeneratorsTests/MockRandomSource.swift`, `Checks_Random.swift`.

- [ ] **Step 1: Failing checks** —
  - `MockRandomSource(sequence: [0,1,2]).int(upperBound: 10)` returns 0,1,2 in order (wrapping if exhausted), for deterministic tests.
  - `SystemRandomSource().int(upperBound: 1) == 0` always; over 5000 draws of `int(upperBound: 6)` every value 0..<6 appears and none is out of range (sanity + no bias crash). `int(upperBound:)` with a non-power-of-two bound (e.g. 10) never returns >= bound.
- [ ] **Step 2: Run** `swift run GeneratorsTests` → FAIL.
- [ ] **Step 3: Implement** `RandomSource.swift`:
```swift
import Foundation
import CryptoCore

public protocol RandomSource: Sendable {
    func int(upperBound: Int) -> Int   // uniform in 0..<upperBound
}

public struct SystemRandomSource: RandomSource {
    public init() {}
    public func int(upperBound: Int) -> Int {
        precondition(upperBound > 0)
        if upperBound == 1 { return 0 }
        // Rejection sampling over whole bytes to avoid modulo bias.
        let range = UInt64(upperBound)
        let maxUnbiased = UInt64.max - (UInt64.max % range)
        while true {
            let r = randomU64()
            if r < maxUnbiased { return Int(r % range) }
        }
    }
    private func randomU64() -> UInt64 {
        let data = (try? SecureRandom.bytes(8)) ?? Data((0..<8).map { _ in UInt8.random(in: .min ... .max) })
        return data.withUnsafeBytes { $0.load(as: UInt64.self) }
    }
}
```
`MockRandomSource.swift` (test target):
```swift
import Generators
final class MockRandomSource: RandomSource, @unchecked Sendable {
    private let seq: [Int]; private var i = 0
    init(sequence: [Int]) { seq = seq.isEmpty ? [0] : sequence }
    func int(upperBound: Int) -> Int { defer { i += 1 }; return seq[i % seq.count] % upperBound }
}
```
- [ ] **Step 4: Run** → pass. **Step 5: Commit** `feat(generators): add injectable unbiased RandomSource`.

---

### Task 2: PasswordGenerator

**Files:** create `Sources/Generators/PasswordGenerator.swift`; `Sources/GeneratorsTests/Checks_Password.swift`.

Character sets (ambiguous excluded when `avoidAmbiguous`): lowercase `abcdefghijkmnopqrstuvwxyz` (no `l`), uppercase `ABCDEFGHJKLMNPQRSTUVWXYZ` (no `I`,`O`), numbers `23456789` (no `0`,`1`), special `!@#$%^&*` ; without avoidAmbiguous, full sets `abcdefghijklmnopqrstuvwxyz`, `ABCDEFGHIJKLMNOPQRSTUVWXYZ`, `0123456789`, `!@#$%^&*`.

- [ ] **Step 1: Failing checks** —
  - **Validation**: all-sets-false → `GeneratorError.noCharacterSetSelected`; `length < 5` → `.lengthTooShort`; `minNumbers + minSpecial > length` → `.invalidOptions`.
  - **Exact output** with `MockRandomSource`: with a scripted sequence and a known options set, assert the exact produced string (compute the expected by hand-tracing the algorithm; the implementer writes the algorithm first, then derives the expected from the deterministic source — OR asserts structural properties; prefer at least one exact-output check once the algorithm is fixed).
  - **Properties** (real `SystemRandomSource`, 500 iterations): result length == `length`; only chars from the enabled sets; at least `minNumbers` digits and `minSpecial` specials; when `avoidAmbiguous`, contains none of `Il1O0o`; each enabled set contributes ≥1 char.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** — algorithm: validate; build the enabled alphabets; place `minNumbers` digits + `minSpecial` specials + one of each other enabled set (guarantee ≥1 per enabled set); fill the rest from the union; then **shuffle** the result using `source` (Fisher–Yates with `source.int(upperBound:)`). Use `source.int(upperBound: set.count)` to pick chars. Return as `String`.
- [ ] **Step 4: Run** → pass. **Step 5: Commit** `feat(generators): add password generator`.

---

### Task 3: PassphraseGenerator

**Files:** create `Sources/Generators/Passphrase.swift`; `Sources/GeneratorsTests/Checks_Passphrase.swift`.

- [ ] **Step 1: Failing checks** —
  - Validation: `wordCount < 3` → `.invalidOptions`; empty `wordList` → `.invalidOptions`.
  - Exact output with `MockRandomSource` + a small wordList `["alpha","bravo","charlie","delta"]`: assert the exact passphrase for given options (e.g. `wordCount: 3, separator: "-", capitalize: true, includeNumber: true`).
  - Properties: word count == `wordCount`; joined by `separator`; when `capitalize`, each word starts uppercase; when `includeNumber`, exactly one digit 0–9 appears appended to one word.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** — pick `wordCount` words via `source.int(upperBound: wordList.count)`; capitalize first letter if set; if `includeNumber`, pick one word index via `source` and append `String(source.int(upperBound: 10))`; join by `separator`.
- [ ] **Step 4: Run** → pass. **Step 5: Commit** `feat(generators): add passphrase generator`.

---

### Task 4: (note) full word list as a resource — DEFERRED

The production EFF/Bitwarden word list (7776 words) ships as a SwiftPM resource later (needs `resources:` in the target + `Bundle.module`). For now `PassphraseGenerator` takes an injected `wordList`; the UI layer (later plan) will load the bundled list. Document this in a one-line comment in `Passphrase.swift`. No code/commit for this task beyond the comment (added in Task 3).

---

## Self-Review (author)
- Coverage: password generator (sets, minimums, avoid-ambiguous, validation) ✔; passphrase (count, separator, capitalize, include-number) ✔; unbiased CSPRNG via rejection sampling ✔; deterministic testability via injected `RandomSource` ✔.
- No placeholders (word-list-as-resource explicitly deferred with rationale).
- Type consistency: `RandomSource`/`SystemRandomSource`/`MockRandomSource`, `PasswordGeneratorOptions`/`PasswordGenerator`, `PassphraseGeneratorOptions`/`PassphraseGenerator`, `GeneratorError`.
- Security: rejection sampling avoids modulo bias; CSPRNG via `SecureRandom`; minimums enforced then shuffled so positions aren't predictable.

## Execution note
After this, `Generators` covers TOTP + password + passphrase. Remaining M1-testable: **Fido2** (P-256 WebAuthn signing). Then written-only plans for the Xcode-gated modules.
