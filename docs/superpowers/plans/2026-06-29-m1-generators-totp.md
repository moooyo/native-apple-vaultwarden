# Generators (TOTP) Implementation Plan (M1 · Plan 4/N)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Checkbox steps.

**Goal:** Build the M1 slice of the `Generators` package — **TOTP** (RFC 6238): Base32 decoding, parsing of raw secrets / `otpauth://totp` URIs / Steam (`steam://`) secrets, and time-based code generation (SHA-1/256/512, configurable digits & period, plus Steam's 5-char alphabet). Password/passphrase/username/passkey generation are M2 and NOT in this plan.

**Architecture:** SwiftPM library `Generators` depending on `CryptoCore` (for HMAC via CryptoKit it can also import CryptoKit directly; keep crypto in CryptoCore where reasonable — HOTP uses HMAC-SHA1/256/512 which CryptoKit provides, so `Generators` may `import CryptoKit` directly for the HMAC, since CryptoCore doesn't expose a generic HMAC API). Pure value types; deterministic given (secret, time). Tests use the CLT executable-target convention (`swift run GeneratorsTests`).

**Tech Stack:** Swift 6 (`swift-tools-version: 6.2`), CryptoKit (HMAC), Foundation. Baseline iOS/macOS 26.

> **⚠️ TESTING CONVENTION** (same as Plans 1–3): no XCTest; `.executableTarget` `GeneratorsTests` via `swift run GeneratorsTests`; copy `TestRunner`. TDD: check → fail → implement → pass → commit. To make TOTP deterministic, generate codes at a fixed `Date(timeIntervalSince1970:)` — never use the real clock in tests.

**Verified RFC 6238 golden vectors (SHA-1, seed = ASCII `"12345678901234567890"`, base32 `GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ`):**
| unix time | 8-digit | 6-digit |
|---|---|---|
| 59 | 94287082 | 287082 |
| 1111111109 | 07081804 | 081804 |
| 1234567890 | 89005924 | 005924 |
| 2000000000 | 69279037 | 279037 |

(Reproduce with `python3` hmac/struct as during planning.)

---

## File Structure

```
Package.swift                      # add Generators lib + GeneratorsTests executable
Sources/Generators/
  Base32.swift            # RFC 4648 base32 decode (case-insensitive, padding-tolerant)
  TOTP.swift              # TOTPConfiguration, TOTPAlgorithm, parse(...), code(for:at:)
Sources/GeneratorsTests/
  TestRunner.swift
  main.swift
  Checks_Base32.swift
  Checks_TOTP.swift
```

**Public API:**
```swift
public enum TOTPAlgorithm: String, Sendable { case sha1 = "SHA1", sha256 = "SHA256", sha512 = "SHA512" }

public struct TOTPConfiguration: Sendable, Equatable {
    public var secret: Data          // decoded key bytes
    public var algorithm: TOTPAlgorithm
    public var digits: Int           // 6 (or 8); Steam uses 5 chars
    public var period: Int           // seconds, default 30
    public var isSteam: Bool         // Steam Guard alphabet
}

public enum TOTP {
    /// Parse a raw base32 secret, an otpauth://totp/...?secret=...&algorithm=...&digits=...&period=... URI,
    /// or a steam://<base32> secret (Bitwarden stores any of these in login.totp).
    public static func configuration(from string: String) throws -> TOTPConfiguration
    /// The code at a given instant (use a fixed Date in tests).
    public static func code(for config: TOTPConfiguration, at date: Date) -> String
    /// Seconds remaining in the current period at `date`.
    public static func secondsRemaining(for config: TOTPConfiguration, at date: Date) -> Int
}

public enum TOTPError: Error, Equatable { case invalidSecret, invalidURI }
```

---

### Task 1: Package target + Base32 + harness

**Files:** modify `Package.swift` (add `Generators` lib dep `CryptoCore`; `GeneratorsTests` executable dep `Generators`); create `Sources/Generators/Base32.swift`, `Sources/GeneratorsTests/{TestRunner,main}.swift`, `Checks_Base32.swift`.

- [ ] **Step 1: Failing checks** — `Base32.decode("JBSWY3DPEHPK3PXP")` returns the bytes `Hello!\xde\xad\xbe\xef`; lowercase input works; spaces/padding `=` tolerated; invalid chars → nil/throws. Use the known pair: base32 `GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ` decodes to ASCII `12345678901234567890`.
- [ ] **Step 2: Run** `swift run GeneratorsTests` → FAIL.
- [ ] **Step 3: Implement** `Base32.swift` — RFC 4648 alphabet `ABCDEFGHIJKLMNOPQRSTUVWXYZ234567`, uppercase+strip spaces/`=`, 8-char→5-byte groups, reject invalid:
```swift
import Foundation
public enum Base32 {
    private static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    public static func decode(_ input: String) -> Data? {
        let cleaned = input.uppercased().filter { $0 != " " && $0 != "=" && $0 != "-" }
        var lookup = [Character: UInt8]()
        for (i, c) in alphabet.enumerated() { lookup[c] = UInt8(i) }
        var bits = 0, value = 0
        var out = [UInt8]()
        for ch in cleaned {
            guard let v = lookup[ch] else { return nil }
            value = (value << 5) | Int(v); bits += 5
            if bits >= 8 { bits -= 8; out.append(UInt8((value >> bits) & 0xff)) }
        }
        return Data(out)
    }
}
```
- [ ] **Step 4: Run** → pass. **Step 5: Commit** `feat(generators): add base32 decode + target/harness`.

---

### Task 2: TOTP code generation (RFC 6238) with golden vectors

**Files:** create `Sources/Generators/TOTP.swift`; `Sources/GeneratorsTests/Checks_TOTP.swift`.

- [ ] **Step 1: Failing checks** — build `TOTPConfiguration(secret: Base32.decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")!, algorithm: .sha1, digits: 8, period: 30, isSteam: false)`; assert `TOTP.code(for:at: Date(timeIntervalSince1970: 59)) == "94287082"`, and the other 3 vectors; with `digits: 6` assert `287082`, `081804`, `005924`, `279037`. Assert `secondsRemaining(at: Date(timeIntervalSince1970: 59)) == 1` (30 - 59%30 = 30-29 = 1).
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** the HOTP/TOTP core (HMAC via CryptoKit, switch on algorithm), dynamic truncation, zero-padded modulo `10^digits`:
```swift
import Foundation
import CryptoKit

public enum TOTP {
    public static func code(for config: TOTPConfiguration, at date: Date) -> String {
        let counter = UInt64(max(0, Int(date.timeIntervalSince1970) / config.period))
        let digest = hmac(counter: counter, key: config.secret, algorithm: config.algorithm)
        let offset = Int(digest[digest.count - 1] & 0x0f)
        let binary = (UInt32(digest[offset] & 0x7f) << 24)
            | (UInt32(digest[offset + 1]) << 16)
            | (UInt32(digest[offset + 2]) << 8)
            | UInt32(digest[offset + 3])
        if config.isSteam { return steamEncode(binary) }
        let mod = UInt32(pow(10.0, Double(config.digits)))
        return String(binary % mod).leftPadded(to: config.digits, with: "0")
    }

    public static func secondsRemaining(for config: TOTPConfiguration, at date: Date) -> Int {
        config.period - (Int(date.timeIntervalSince1970) % config.period)
    }

    private static func hmac(counter: UInt64, key: Data, algorithm: TOTPAlgorithm) -> [UInt8] {
        var c = counter.bigEndian
        let msg = withUnsafeBytes(of: &c) { Data($0) }
        let k = SymmetricKey(data: key)
        switch algorithm {
        case .sha1:   return Array(HMAC<Insecure.SHA1>.authenticationCode(for: msg, using: k))
        case .sha256: return Array(HMAC<SHA256>.authenticationCode(for: msg, using: k))
        case .sha512: return Array(HMAC<SHA512>.authenticationCode(for: msg, using: k))
        }
    }

    private static let steamAlphabet = Array("23456789BCDFGHJKMNPQRTVWXY")
    private static func steamEncode(_ binary: UInt32) -> String {
        var v = binary; var s = ""
        for _ in 0..<5 { s.append(steamAlphabet[Int(v % UInt32(steamAlphabet.count))]); v /= UInt32(steamAlphabet.count) }
        return s
    }
}

private extension String {
    func leftPadded(to n: Int, with c: Character) -> String {
        count >= n ? self : String(repeating: c, count: n - count) + self
    }
}
```
> Note: `Insecure.SHA1` is the correct CryptoKit type for TOTP's SHA-1 (TOTP requires SHA-1; the "Insecure" label is about collision resistance, irrelevant to HMAC-OTP). Add a code comment to that effect.

- [ ] **Step 4: Run** → all RFC vectors pass. **Step 5: Commit** `feat(generators): add RFC 6238 TOTP code generation + steam`.

---

### Task 3: Parsing (raw secret / otpauth URI / steam)

**Files:** extend `Sources/Generators/TOTP.swift`; extend `Checks_TOTP.swift`.

- [ ] **Step 1: Failing checks** —
  - `TOTP.configuration(from: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")` → sha1/6/30/non-steam, secret decodes; `code(at: 59)` == `287082`.
  - otpauth: `"otpauth://totp/Example:alice@x.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA256&digits=8&period=60"` → algorithm sha256, digits 8, period 60.
  - steam: `"steam://GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"` → isSteam true, digits 5.
  - garbage → `TOTPError.invalidSecret` / `.invalidURI`.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** `configuration(from:)` using `URLComponents` for the `otpauth`/`steam` schemes and `Base32.decode` for raw/secret; defaults sha1/6/30; map bad input to the errors. (Handle the `algorithm` query case-insensitively.)
- [ ] **Step 4: Run** → pass. **Step 5: Commit** `feat(generators): parse raw/otpauth/steam totp secrets`.

---

## Self-Review (author)
- Spec coverage: TOTP (RFC 6238) for M1 ✔ — generation (sha1/256/512, digits, period), Base32, otpauth + steam parsing. Password/passphrase/username/passkey generation correctly deferred to M2 (documented, not a gap).
- Placeholders: none; golden vectors verified.
- Type consistency: `TOTPConfiguration`, `TOTPAlgorithm`, `TOTP.code/configuration/secondsRemaining`, `Base32.decode`, `TOTPError` consistent.
- Determinism: all tests pass a fixed `Date(timeIntervalSince1970:)`.

## Execution note
After Generators(TOTP): the last clearly CLT-testable M1 package is **Fido2** (P-256 WebAuthn assertion/registration signing — CryptoKit P256 works in CLI). Then write plans (not executed here) for **KeychainBridge, VaultStore(SQLCipher), Networking, SyncEngine, VaultRepository, AutoFillExtension, DesignSystem, UIShared, UI-iOS, UI-mac, App-iOS, App-macOS**.
