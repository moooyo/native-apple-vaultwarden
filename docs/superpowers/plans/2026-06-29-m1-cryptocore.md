# CryptoCore Implementation Plan (M1 · Plan 1/N)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `CryptoCore` — the byte-exact, dependency-free Swift crypto spine (EncString, PBKDF2 KDF, master-password hashes, HKDF key-stretching, AES-256-CBC+HMAC encrypt-then-MAC) that every other Tessera module depends on, with a golden-vector test suite proving Bitwarden/Vaultwarden compatibility.

**Architecture:** A standalone SwiftPM library target with **zero third-party dependencies** — only system frameworks (`CommonCrypto` for AES-CBC + PBKDF2, `CryptoKit` for HKDF + HMAC, `Security` for CSPRNG). Caseless-enum namespaces (`KDF`, `KeyStretch`, `SymmetricCrypto`, `SecureRandom`) expose static functions; value types (`EncString`, `SymmetricCryptoKey`) carry data. **PBKDF2 only — no Argon2id** (locked decision D6). RSA-OAEP and type-7 decryption are out of scope for this plan (RSA → M2 org keys; type-7 → soft-fail only).

**Tech Stack:** Swift 6 (`swift-tools-version: 6.2`), SwiftPM, CommonCrypto, CryptoKit, Security. Baseline iOS 26 / macOS 26. Verified against the toolchain `Apple Swift 6.4 (target arm64-apple-macosx27)`.

> **⚠️ ENVIRONMENT & TESTING CONVENTIONS (READ FIRST — overrides the per-task XCTest snippets below).**
> The build host has **Command Line Tools only (no full Xcode)**. Verified consequences:
> 1. **`swift-tools-version: 6.2`** is required for `.macOS(.v26)`/`.iOS(.v26)` (the `.v26` enum is unavailable in 6.0).
> 2. **XCTest is unavailable** (no Xcode) and **swift-testing's `TestingMacros` plugin is also unavailable** under CLT — so `swift test` cannot build any test target. Tests are therefore an **`.executableTarget` named `CryptoCoreTests`** run with **`swift run CryptoCoreTests`** (exit code 0 = pass, non-zero = fail).
> 3. Swift 6 strict concurrency: top-level `main.swift` is `@MainActor`, so keep mutable test state **local to a function** (not file-global).
>
> **How to realize the tests:** Each task below shows assertions in XCTest style **for readability only**. Implement them instead as plain functions using the `TestRunner` harness from Task 1 (`expect`, `expectTrue`, `expectThrows`, `expectThrowsError`), registered in `runAllTests()` in `main.swift`. **The inputs, golden vectors, and pass/fail conditions are unchanged — only the mechanism differs.** "Run: `swift test --filter X`" in each task means "add the checks to the runner and run `swift run CryptoCoreTests`". TDD still holds: add the check, run and watch it fail, implement, run and watch it pass, commit.

---

## File Structure

```
Package.swift                              # SwiftPM manifest, CryptoCore + tests
Sources/CryptoCore/
  CryptoError.swift        # error enum
  EncryptionType.swift     # EncString type enum (0..7)
  SecureBytes.swift        # zeroizing byte buffer
  SecureRandom.swift       # CSPRNG via SecRandomCopyBytes
  EncString.swift          # parse/serialize "type.iv|ct|mac"
  PBKDF2.swift             # internal CommonCrypto PBKDF2-SHA256
  KDF.swift                # deriveMasterKey + masterPasswordHash (public)
  KeyStretch.swift         # HKDF-Expand stretch + SymmetricCryptoKey
  SymmetricCrypto.swift    # AES-256-CBC + HMAC-SHA256 encrypt/decrypt
Sources/CryptoCoreTests/        # executable target (no XCTest — see conventions)
  TestRunner.swift         # expect/expectThrows harness
  main.swift               # runAllTests() — registers & runs every check
  Checks_SecureBytes.swift
  Checks_EncString.swift
  Checks_PBKDF2.swift
  Checks_KDF.swift
  Checks_KeyStretch.swift
  Checks_SymmetricCrypto.swift
  Checks_GoldenVector.swift
  Fixtures/README.md       # real-Vaultwarden fixture capture procedure
```

**Responsibility split:** one file per primitive so each stays small and independently testable. `EncString` is pure parsing (no crypto). `KDF`/`KeyStretch`/`SymmetricCrypto` each wrap exactly one operation. Tests mirror sources 1:1 plus a cross-cutting `GoldenVectorTests`.

**Golden vectors (verified with `python3` hashlib/hmac during planning — reproduce with the commands shown in each task):**
- PBKDF2-HMAC-SHA256(`"password"`, `"salt"`, 1, 32) = `120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b`
- PBKDF2-HMAC-SHA256(`"password"`, `"salt"`, 2, 32) = `ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43`
- HKDF-Expand-SHA256(PRK=`00010203…1f`, info=`"enc"`, 32) = `9c5639fac602366b486253191cb7900d7d8e3a1514676b118d5803a11dd97213`
- HKDF-Expand-SHA256(PRK=`00010203…1f`, info=`"mac"`, 32) = `cce388b4ac0f05edee78d40dcbe78a7715640de75ed9ba06942fb42398d6b1f1`
- End-to-end (email `user@example.com`, password `Password123!`, iters 5000):
  - masterKey = `b86c2ee9e33113c09c31c92d5f288a989a56d2485e76cc81f5607dea299a5da4`
  - serverAuthHash (purpose=1) = `5XhkzlRm282dCTYHuni4Qw6J4PYChL0z7Cx+kKqE50w=`
  - localAuthHash (purpose=2) = `TX2MDMqyhAyYAET/GN1etxjUsD/22fWXWT9YOkktUA4=`
  - stretch enc = `8ec8d572bdc1df1e915f60f45e76a1535c3ad1db52ddd6a6542eb3e6cf8636a4`
  - stretch mac = `194a0f057a41373f7e74b8639f66bf4925b1cfb65186addde6a9b6bb92096432`

A tiny hex helper is added in Task 2 so every test can compare `Data` to a hex string.

---

### Task 1: Package scaffold + test harness + smoke check

**Files:**
- Create: `Package.swift`
- Create: `Sources/CryptoCore/CryptoCore.swift`
- Create: `Sources/CryptoCoreTests/TestRunner.swift`
- Create: `Sources/CryptoCoreTests/main.swift`

- [ ] **Step 1: Write `Package.swift`** (note: `swift-tools-version: 6.2`, tests are an **executable** target)

```swift
// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "Tessera",
    platforms: [.iOS(.v26), .macOS(.v26)],
    products: [
        .library(name: "CryptoCore", targets: ["CryptoCore"]),
    ],
    targets: [
        .target(name: "CryptoCore"),
        .executableTarget(name: "CryptoCoreTests", dependencies: ["CryptoCore"]),
    ]
)
```

- [ ] **Step 2: Add the library entry source**

`Sources/CryptoCore/CryptoCore.swift`:
```swift
/// CryptoCore — byte-exact Bitwarden/Vaultwarden-compatible crypto primitives.
/// PBKDF2-only (no Argon2id). See docs/superpowers/specs for the design.
public enum CryptoCore {
    public static let version = "0.1.0"
}
```

- [ ] **Step 3: Write the test harness**

`Sources/CryptoCoreTests/TestRunner.swift`:
```swift
import Foundation

/// Minimal test harness (XCTest is unavailable on this CLT-only host).
/// Keep an instance local to a function so Swift 6 MainActor isolation is satisfied.
struct TestRunner {
    private(set) var passed = 0
    private(set) var failed = 0

    mutating func expect<T: Equatable>(_ actual: T, _ expected: T, _ name: String) {
        if actual == expected { passed += 1 }
        else { failed += 1; print("FAIL  \(name)\n   got: \(String(describing: actual))\n   exp: \(String(describing: expected))") }
    }

    mutating func expectTrue(_ condition: Bool, _ name: String) {
        if condition { passed += 1 } else { failed += 1; print("FAIL  \(name): expected true") }
    }

    mutating func expectThrows(_ name: String, _ body: () throws -> Void) {
        do { try body(); failed += 1; print("FAIL  \(name): expected an error") }
        catch { passed += 1 }
    }

    mutating func expectThrowsError<E: Error & Equatable>(_ expected: E, _ name: String, _ body: () throws -> Void) {
        do { try body(); failed += 1; print("FAIL  \(name): expected \(expected)") }
        catch let error as E where error == expected { passed += 1 }
        catch { failed += 1; print("FAIL  \(name): wrong error \(error), expected \(expected)") }
    }

    func summary() -> Int {
        print("— \(passed) passed, \(failed) failed —")
        return failed
    }
}
```

- [ ] **Step 4: Write the runner entry point with a smoke check**

`Sources/CryptoCoreTests/main.swift`:
```swift
import Foundation
import CryptoCore

func runAllTests() -> Int {
    var r = TestRunner()

    // Smoke
    r.expect(CryptoCore.version, "0.1.0", "module loads")

    // Later tasks add their registrations here, e.g.:
    // checkEncryptionType(&r)
    // checkEncString(&r)
    // ...

    return r.summary()
}

let failures = runAllTests()
if failures != 0 { exit(1) }
```

- [ ] **Step 5: Run to verify it builds and passes**

Run: `swift run CryptoCoreTests`
Expected: prints `— 1 passed, 0 failed —`, exit code 0. (A harmless `ld: warning: search path ... not found` may appear under CLT — ignore it.)

- [ ] **Step 6: Commit**

```bash
git add Package.swift Sources
git commit -m "feat(cryptocore): scaffold SwiftPM package + executable test harness"
```

> For every later task: add a `checkXxx(_ r: inout TestRunner)` function in `Sources/CryptoCoreTests/Checks_Xxx.swift`, call it from `runAllTests()`, and verify with `swift run CryptoCoreTests`.

---

### Task 2: CryptoError + EncryptionType + hex test helper

**Files:**
- Create: `Sources/CryptoCore/CryptoError.swift`
- Create: `Sources/CryptoCore/EncryptionType.swift`
- Test: `Tests/CryptoCoreTests/EncryptionTypeTests.swift`

- [ ] **Step 1: Write the failing test**

`Tests/CryptoCoreTests/EncryptionTypeTests.swift`:
```swift
import XCTest
@testable import CryptoCore

final class EncryptionTypeTests: XCTestCase {
    func test_rawValues() {
        XCTAssertEqual(EncryptionType.aesCbc256_HmacSha256_B64.rawValue, 2)
        XCTAssertEqual(EncryptionType.rsa2048_OaepSha1_B64.rawValue, 4)
        XCTAssertEqual(EncryptionType.coseEncrypt0_B64.rawValue, 7)
        XCTAssertNil(EncryptionType(rawValue: 99))
    }

    func test_hexHelper() {
        XCTAssertEqual(Data([0x00, 0xff, 0x10]).hexString, "00ff10")
        XCTAssertEqual(Data(hex: "00ff10"), Data([0x00, 0xff, 0x10]))
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `swift test --filter EncryptionTypeTests`
Expected: FAIL — `cannot find type 'EncryptionType'` / `value of type 'Data' has no member 'hexString'`.

- [ ] **Step 3: Implement**

`Sources/CryptoCore/CryptoError.swift`:
```swift
import Foundation

public enum CryptoError: Error, Equatable {
    case invalidEncString
    case unsupportedEncStringType(Int)
    case macMismatch
    case decryptionFailed
    case encryptionFailed
    case kdfFailed
    case insufficientKdfParameters
    case invalidKeyLength
}
```

`Sources/CryptoCore/EncryptionType.swift`:
```swift
import Foundation

public enum EncryptionType: Int, Sendable, CaseIterable {
    case aesCbc256_B64 = 0                       // deprecated, decryption blocked
    case aesCbc128_HmacSha256_B64 = 1
    case aesCbc256_HmacSha256_B64 = 2            // current symmetric format
    case rsa2048_OaepSha256_B64 = 3
    case rsa2048_OaepSha1_B64 = 4                // active asymmetric (org keys)
    case rsa2048_OaepSha256_HmacSha256_B64 = 5
    case rsa2048_OaepSha1_HmacSha256_B64 = 6
    case coseEncrypt0_B64 = 7                    // account crypto v2 — soft-fail only
}

// Test/utility helper kept in the module so tests can assert hex.
extension Data {
    var hexString: String { map { String(format: "%02x", $0) }.joined() }

    init(hex: String) {
        var bytes = [UInt8]()
        bytes.reserveCapacity(hex.count / 2)
        var idx = hex.startIndex
        while idx < hex.endIndex {
            let next = hex.index(idx, offsetBy: 2, limitedBy: hex.endIndex) ?? hex.endIndex
            if let b = UInt8(hex[idx..<next], radix: 16) { bytes.append(b) }
            idx = next
        }
        self = Data(bytes)
    }
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `swift test --filter EncryptionTypeTests`
Expected: PASS, 2 tests.

- [ ] **Step 5: Commit**

```bash
git add Sources/CryptoCore/CryptoError.swift Sources/CryptoCore/EncryptionType.swift Tests/CryptoCoreTests/EncryptionTypeTests.swift
git commit -m "feat(cryptocore): add CryptoError, EncryptionType, hex helpers"
```

---

### Task 3: SecureBytes (zeroizing buffer)

**Files:**
- Create: `Sources/CryptoCore/SecureBytes.swift`
- Test: `Tests/CryptoCoreTests/SecureBytesTests.swift`

- [ ] **Step 1: Write the failing test**

`Tests/CryptoCoreTests/SecureBytesTests.swift`:
```swift
import XCTest
@testable import CryptoCore

final class SecureBytesTests: XCTestCase {
    func test_storesAndReturnsBytes() {
        let sb = SecureBytes([1, 2, 3, 4])
        XCTAssertEqual(sb.count, 4)
        XCTAssertEqual(sb.bytes, [1, 2, 3, 4])
        XCTAssertEqual(sb.data, Data([1, 2, 3, 4]))
    }

    func test_zeroInit() {
        let sb = SecureBytes(count: 8)
        XCTAssertEqual(sb.bytes, [UInt8](repeating: 0, count: 8))
    }

    func test_withUnsafeBytes() {
        let sb = SecureBytes([0xAA, 0xBB])
        let first = sb.withUnsafeBytes { $0.first }
        XCTAssertEqual(first, 0xAA)
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `swift test --filter SecureBytesTests`
Expected: FAIL — `cannot find 'SecureBytes' in scope`.

- [ ] **Step 3: Implement**

`Sources/CryptoCore/SecureBytes.swift`:
```swift
import Foundation

/// A heap buffer of sensitive bytes that is best-effort zeroized on deinit.
/// NOTE: Swift `Array` may copy-on-write; callers must avoid leaking copies.
/// Long-lived keys (e.g. the UserKey in KeyVault) use this type.
public final class SecureBytes: @unchecked Sendable {
    private var storage: [UInt8]

    public init(_ bytes: [UInt8]) { storage = bytes }
    public init(count: Int) { storage = [UInt8](repeating: 0, count: count) }

    public var count: Int { storage.count }
    public var bytes: [UInt8] { storage }
    public var data: Data { Data(storage) }

    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try storage.withUnsafeBytes(body)
    }

    deinit {
        storage.withUnsafeMutableBytes { ptr in
            guard let base = ptr.baseAddress, ptr.count > 0 else { return }
            memset_s(base, ptr.count, 0, ptr.count)
        }
    }
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `swift test --filter SecureBytesTests`
Expected: PASS, 3 tests.

- [ ] **Step 5: Commit**

```bash
git add Sources/CryptoCore/SecureBytes.swift Tests/CryptoCoreTests/SecureBytesTests.swift
git commit -m "feat(cryptocore): add SecureBytes zeroizing buffer"
```

---

### Task 4: SecureRandom (CSPRNG)

**Files:**
- Create: `Sources/CryptoCore/SecureRandom.swift`
- Test: `Tests/CryptoCoreTests/SecureRandomTests.swift`

- [ ] **Step 1: Write the failing test**

`Tests/CryptoCoreTests/SecureRandomTests.swift`:
```swift
import XCTest
@testable import CryptoCore

final class SecureRandomTests: XCTestCase {
    func test_lengthAndUniqueness() throws {
        let a = try SecureRandom.bytes(16)
        let b = try SecureRandom.bytes(16)
        XCTAssertEqual(a.count, 16)
        XCTAssertEqual(b.count, 16)
        XCTAssertNotEqual(a, b)                       // astronomically unlikely to match
    }

    func test_zeroLength() throws {
        XCTAssertEqual(try SecureRandom.bytes(0), Data())
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `swift test --filter SecureRandomTests`
Expected: FAIL — `cannot find 'SecureRandom' in scope`.

- [ ] **Step 3: Implement**

`Sources/CryptoCore/SecureRandom.swift`:
```swift
import Foundation
import Security

public enum SecureRandom {
    /// Cryptographically secure random bytes from the system CSPRNG.
    public static func bytes(_ count: Int) throws -> Data {
        guard count > 0 else { return Data() }
        var out = Data(count: count)
        let status = out.withUnsafeMutableBytes { ptr -> Int32 in
            SecRandomCopyBytes(kSecRandomDefault, count, ptr.baseAddress!)
        }
        guard status == errSecSuccess else { throw CryptoError.encryptionFailed }
        return out
    }
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `swift test --filter SecureRandomTests`
Expected: PASS, 2 tests.

- [ ] **Step 5: Commit**

```bash
git add Sources/CryptoCore/SecureRandom.swift Tests/CryptoCoreTests/SecureRandomTests.swift
git commit -m "feat(cryptocore): add SecureRandom CSPRNG"
```

---

### Task 5: EncString parse + serialize

**Files:**
- Create: `Sources/CryptoCore/EncString.swift`
- Test: `Tests/CryptoCoreTests/EncStringTests.swift`

Format: `type.b64iv|b64ct|b64mac` (type 1/2), `type.b64iv|b64ct` (type 0), `type.b64data` (type 3/4), `type.b64data|b64mac` (type 5/6), `type.b64data` (type 7 raw COSE bytes).

- [ ] **Step 1: Write the failing test**

`Tests/CryptoCoreTests/EncStringTests.swift`:
```swift
import XCTest
@testable import CryptoCore

final class EncStringTests: XCTestCase {
    // iv=16 bytes, ct=16 bytes, mac=32 bytes (lengths typical for type 2)
    private let iv = Data((0..<16).map { UInt8($0) })
    private let ct = Data((16..<32).map { UInt8($0) })
    private let mac = Data((32..<64).map { UInt8($0) })

    func test_roundTripType2() throws {
        let original = EncString(type: .aesCbc256_HmacSha256_B64, iv: iv, ciphertext: ct, mac: mac)
        let string = original.stringValue
        XCTAssertTrue(string.hasPrefix("2."))
        XCTAssertEqual(string.split(separator: ".")[1].split(separator: "|").count, 3)

        let parsed = try EncString(parsing: string)
        XCTAssertEqual(parsed, original)
    }

    func test_parseType4SinglePart() throws {
        let data = Data((0..<256).map { UInt8($0 & 0xff) })
        let s = "4.\(data.base64EncodedString())"
        let parsed = try EncString(parsing: s)
        XCTAssertEqual(parsed.type, .rsa2048_OaepSha1_B64)
        XCTAssertNil(parsed.iv)
        XCTAssertNil(parsed.mac)
        XCTAssertEqual(parsed.ciphertext, data)
    }

    func test_rejectsMissingDot() {
        XCTAssertThrowsError(try EncString(parsing: "2"))
    }

    func test_rejectsWrongPartCountForType2() {
        XCTAssertThrowsError(try EncString(parsing: "2.\(iv.base64EncodedString())|\(ct.base64EncodedString())"))
    }

    func test_unsupportedTypeThrows() {
        // type 7 parses structurally but is flagged unsupported on decrypt elsewhere;
        // here an out-of-range type integer must throw invalidEncString.
        XCTAssertThrowsError(try EncString(parsing: "42.\(ct.base64EncodedString())"))
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `swift test --filter EncStringTests`
Expected: FAIL — `cannot find 'EncString' in scope`.

- [ ] **Step 3: Implement**

`Sources/CryptoCore/EncString.swift`:
```swift
import Foundation

public struct EncString: Equatable, Sendable {
    public let type: EncryptionType
    public let iv: Data?
    public let ciphertext: Data
    public let mac: Data?

    public init(type: EncryptionType, iv: Data?, ciphertext: Data, mac: Data?) {
        self.type = type
        self.iv = iv
        self.ciphertext = ciphertext
        self.mac = mac
    }

    public init(parsing string: String) throws {
        guard let dot = string.firstIndex(of: ".") else { throw CryptoError.invalidEncString }
        guard let rawType = Int(string[string.startIndex..<dot]),
              let type = EncryptionType(rawValue: rawType) else { throw CryptoError.invalidEncString }
        let body = String(string[string.index(after: dot)...])
        let parts = body.split(separator: "|", omittingEmptySubsequences: false).map(String.init)

        func b64(_ s: String) throws -> Data {
            guard let d = Data(base64Encoded: s) else { throw CryptoError.invalidEncString }
            return d
        }

        switch type {
        case .aesCbc256_B64: // iv|ct, no mac
            guard parts.count == 2 else { throw CryptoError.invalidEncString }
            self.init(type: type, iv: try b64(parts[0]), ciphertext: try b64(parts[1]), mac: nil)
        case .aesCbc128_HmacSha256_B64, .aesCbc256_HmacSha256_B64: // iv|ct|mac
            guard parts.count == 3 else { throw CryptoError.invalidEncString }
            self.init(type: type, iv: try b64(parts[0]), ciphertext: try b64(parts[1]), mac: try b64(parts[2]))
        case .rsa2048_OaepSha256_B64, .rsa2048_OaepSha1_B64, .coseEncrypt0_B64: // single part
            guard parts.count == 1 else { throw CryptoError.invalidEncString }
            self.init(type: type, iv: nil, ciphertext: try b64(parts[0]), mac: nil)
        case .rsa2048_OaepSha256_HmacSha256_B64, .rsa2048_OaepSha1_HmacSha256_B64: // data|mac
            guard parts.count == 2 else { throw CryptoError.invalidEncString }
            self.init(type: type, iv: nil, ciphertext: try b64(parts[0]), mac: try b64(parts[1]))
        }
    }

    public var stringValue: String {
        let b = ciphertext.base64EncodedString()
        switch type {
        case .aesCbc256_B64:
            return "\(type.rawValue).\(iv?.base64EncodedString() ?? "")|\(b)"
        case .aesCbc128_HmacSha256_B64, .aesCbc256_HmacSha256_B64:
            return "\(type.rawValue).\(iv?.base64EncodedString() ?? "")|\(b)|\(mac?.base64EncodedString() ?? "")"
        case .rsa2048_OaepSha256_B64, .rsa2048_OaepSha1_B64, .coseEncrypt0_B64:
            return "\(type.rawValue).\(b)"
        case .rsa2048_OaepSha256_HmacSha256_B64, .rsa2048_OaepSha1_HmacSha256_B64:
            return "\(type.rawValue).\(b)|\(mac?.base64EncodedString() ?? "")"
        }
    }
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `swift test --filter EncStringTests`
Expected: PASS, 5 tests.

- [ ] **Step 5: Commit**

```bash
git add Sources/CryptoCore/EncString.swift Tests/CryptoCoreTests/EncStringTests.swift
git commit -m "feat(cryptocore): add EncString parse/serialize"
```

---

### Task 6: PBKDF2 primitive (CommonCrypto) — golden vectors

**Files:**
- Create: `Sources/CryptoCore/PBKDF2.swift`
- Test: `Tests/CryptoCoreTests/PBKDF2Tests.swift`

> Reproduce the expected values:
> `python3 -c "import hashlib,binascii; print(binascii.hexlify(hashlib.pbkdf2_hmac('sha256',b'password',b'salt',1,32)).decode())"`

- [ ] **Step 1: Write the failing test**

`Tests/CryptoCoreTests/PBKDF2Tests.swift`:
```swift
import XCTest
@testable import CryptoCore

final class PBKDF2Tests: XCTestCase {
    func test_goldenVector_iters1() throws {
        let out = try PBKDF2.deriveSHA256(password: Data("password".utf8),
                                          salt: Data("salt".utf8),
                                          iterations: 1, keyLength: 32)
        XCTAssertEqual(Data(out).hexString,
                       "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")
    }

    func test_goldenVector_iters2() throws {
        let out = try PBKDF2.deriveSHA256(password: Data("password".utf8),
                                          salt: Data("salt".utf8),
                                          iterations: 2, keyLength: 32)
        XCTAssertEqual(Data(out).hexString,
                       "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43")
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `swift test --filter PBKDF2Tests`
Expected: FAIL — `cannot find 'PBKDF2' in scope`.

- [ ] **Step 3: Implement**

`Sources/CryptoCore/PBKDF2.swift`:
```swift
import Foundation
import CommonCrypto

enum PBKDF2 {
    /// PBKDF2-HMAC-SHA256. `password` and `salt` are used as raw bytes.
    static func deriveSHA256(password: Data, salt: Data, iterations: Int, keyLength: Int) throws -> [UInt8] {
        var derived = [UInt8](repeating: 0, count: keyLength)
        // Empty salt/password need a valid (non-nil) pointer; use a 1-byte scratch.
        let status: Int32 = password.withUnsafeBytesOrEmpty { pwPtr, pwLen in
            salt.withUnsafeBytesOrEmpty { saltPtr, saltLen in
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    pwPtr.assumingMemoryBound(to: Int8.self), pwLen,
                    saltPtr.assumingMemoryBound(to: UInt8.self), saltLen,
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                    UInt32(iterations),
                    &derived, keyLength
                )
            }
        }
        guard status == kCCSuccess else { throw CryptoError.kdfFailed }
        return derived
    }
}

private extension Data {
    /// Calls `body` with a guaranteed non-nil base pointer (uses a scratch byte when empty).
    func withUnsafeBytesOrEmpty<R>(_ body: (UnsafeRawPointer, Int) -> R) -> R {
        if isEmpty {
            var scratch: UInt8 = 0
            return withUnsafePointer(to: &scratch) { body(UnsafeRawPointer($0), 0) }
        }
        return withUnsafeBytes { body($0.baseAddress!, count) }
    }
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `swift test --filter PBKDF2Tests`
Expected: PASS, 2 tests.

- [ ] **Step 5: Commit**

```bash
git add Sources/CryptoCore/PBKDF2.swift Tests/CryptoCoreTests/PBKDF2Tests.swift
git commit -m "feat(cryptocore): add PBKDF2-SHA256 primitive with golden vectors"
```

---

### Task 7: KDF — master key + master-password hash (PBKDF2-only)

**Files:**
- Create: `Sources/CryptoCore/KDF.swift`
- Test: `Tests/CryptoCoreTests/KDFTests.swift`

> Reproduce: run the planning `python3` snippet in the plan header (email `user@example.com`, password `Password123!`, iters 5000).

- [ ] **Step 1: Write the failing test**

`Tests/CryptoCoreTests/KDFTests.swift`:
```swift
import XCTest
@testable import CryptoCore

final class KDFTests: XCTestCase {
    let email = "user@example.com"
    let password = "Password123!"
    let iters = 5000

    func test_deriveMasterKey_goldenVector() throws {
        let mk = try KDF.deriveMasterKey(password: password, email: email, iterations: iters)
        XCTAssertEqual(Data(mk).hexString,
                       "b86c2ee9e33113c09c31c92d5f288a989a56d2485e76cc81f5607dea299a5da4")
    }

    func test_emailIsTrimmedAndLowercased() throws {
        let mk1 = try KDF.deriveMasterKey(password: password, email: "  USER@Example.com ", iterations: iters)
        let mk2 = try KDF.deriveMasterKey(password: password, email: email, iterations: iters)
        XCTAssertEqual(mk1, mk2)
    }

    func test_serverAuthHash_goldenVector() throws {
        let mk = try KDF.deriveMasterKey(password: password, email: email, iterations: iters)
        let hash = try KDF.masterPasswordHash(masterKey: mk, password: password, purpose: .serverAuthorization)
        XCTAssertEqual(hash, "5XhkzlRm282dCTYHuni4Qw6J4PYChL0z7Cx+kKqE50w=")
    }

    func test_localAuthHash_goldenVector() throws {
        let mk = try KDF.deriveMasterKey(password: password, email: email, iterations: iters)
        let hash = try KDF.masterPasswordHash(masterKey: mk, password: password, purpose: .localAuthorization)
        XCTAssertEqual(hash, "TX2MDMqyhAyYAET/GN1etxjUsD/22fWXWT9YOkktUA4=")
    }

    func test_belowMinIterationsThrows() {
        XCTAssertThrowsError(try KDF.deriveMasterKey(password: password, email: email, iterations: 4999)) {
            XCTAssertEqual($0 as? CryptoError, .insufficientKdfParameters)
        }
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `swift test --filter KDFTests`
Expected: FAIL — `cannot find 'KDF' in scope`.

- [ ] **Step 3: Implement**

`Sources/CryptoCore/KDF.swift`:
```swift
import Foundation

public enum KDF {
    /// Minimum PBKDF2 iterations accepted (matches Bitwarden's PBKDF2_MIN_ITERATIONS).
    public static let minimumPBKDF2Iterations = 5000

    /// Master Key = PBKDF2-HMAC-SHA256(password, salt = trimmed+lowercased email, iterations).
    /// PBKDF2 only — Argon2id is intentionally unsupported (decision D6).
    public static func deriveMasterKey(password: String, email: String, iterations: Int) throws -> [UInt8] {
        guard iterations >= minimumPBKDF2Iterations else { throw CryptoError.insufficientKdfParameters }
        let normalized = email.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return try PBKDF2.deriveSHA256(password: Data(password.utf8),
                                       salt: Data(normalized.utf8),
                                       iterations: iterations, keyLength: 32)
    }

    public enum HashPurpose: Int {
        case serverAuthorization = 1   // sent to server (OAuth `password` field)
        case localAuthorization = 2    // persisted for offline unlock verification
    }

    /// base64(PBKDF2-HMAC-SHA256(payload = masterKey, salt = password, iterations = purpose.rawValue)).
    public static func masterPasswordHash(masterKey: [UInt8], password: String, purpose: HashPurpose) throws -> String {
        let out = try PBKDF2.deriveSHA256(password: Data(masterKey),
                                          salt: Data(password.utf8),
                                          iterations: purpose.rawValue, keyLength: 32)
        return Data(out).base64EncodedString()
    }
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `swift test --filter KDFTests`
Expected: PASS, 5 tests.

- [ ] **Step 5: Commit**

```bash
git add Sources/CryptoCore/KDF.swift Tests/CryptoCoreTests/KDFTests.swift
git commit -m "feat(cryptocore): add PBKDF2 master key + master-password hash"
```

---

### Task 8: KeyStretch — HKDF-Expand + SymmetricCryptoKey

**Files:**
- Create: `Sources/CryptoCore/KeyStretch.swift`
- Test: `Tests/CryptoCoreTests/KeyStretchTests.swift`

- [ ] **Step 1: Write the failing test**

`Tests/CryptoCoreTests/KeyStretchTests.swift`:
```swift
import XCTest
@testable import CryptoCore

final class KeyStretchTests: XCTestCase {
    func test_hkdfExpand_goldenVectors() {
        let prk = Array<UInt8>(0...31)                       // 00..1f
        let enc = KeyStretch.hkdfExpand(prk: prk, info: "enc", length: 32)
        let mac = KeyStretch.hkdfExpand(prk: prk, info: "mac", length: 32)
        XCTAssertEqual(Data(enc).hexString,
                       "9c5639fac602366b486253191cb7900d7d8e3a1514676b118d5803a11dd97213")
        XCTAssertEqual(Data(mac).hexString,
                       "cce388b4ac0f05edee78d40dcbe78a7715640de75ed9ba06942fb42398d6b1f1")
    }

    func test_stretchMasterKey_goldenVectors() {
        let mk = Array(Data(hex: "b86c2ee9e33113c09c31c92d5f288a989a56d2485e76cc81f5607dea299a5da4"))
        let key = KeyStretch.stretchMasterKey(mk)
        XCTAssertEqual(key.encKey.hexString, "8ec8d572bdc1df1e915f60f45e76a1535c3ad1db52ddd6a6542eb3e6cf8636a4")
        XCTAssertEqual(key.macKey.hexString, "194a0f057a41373f7e74b8639f66bf4925b1cfb65186addde6a9b6bb92096432")
    }

    func test_symmetricKeyFrom64Bytes() throws {
        let combined = Data((0..<64).map { UInt8($0) })
        let key = try SymmetricCryptoKey(combined: combined)
        XCTAssertEqual(key.encKey, combined.prefix(32))
        XCTAssertEqual(key.macKey, combined.suffix(32))
    }

    func test_symmetricKeyWrongLengthThrows() {
        XCTAssertThrowsError(try SymmetricCryptoKey(combined: Data(count: 50))) {
            XCTAssertEqual($0 as? CryptoError, .invalidKeyLength)
        }
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `swift test --filter KeyStretchTests`
Expected: FAIL — `cannot find 'KeyStretch' in scope`.

- [ ] **Step 3: Implement**

`Sources/CryptoCore/KeyStretch.swift`:
```swift
import Foundation
import CryptoKit

/// A 64-byte symmetric key split into a 32-byte AES key and a 32-byte HMAC key.
public struct SymmetricCryptoKey: Sendable, Equatable {
    public let encKey: Data   // 32 bytes
    public let macKey: Data   // 32 bytes

    public init(encKey: Data, macKey: Data) throws {
        guard encKey.count == 32, macKey.count == 32 else { throw CryptoError.invalidKeyLength }
        self.encKey = encKey
        self.macKey = macKey
    }

    /// Split a 64-byte combined key (first 32 = enc, last 32 = mac).
    public init(combined: Data) throws {
        guard combined.count == 64 else { throw CryptoError.invalidKeyLength }
        self.encKey = combined.prefix(32)
        self.macKey = combined.suffix(32)
    }
}

public enum KeyStretch {
    /// HKDF-Expand (RFC 5869, no extract step) with SHA-256. PRK is used directly.
    public static func hkdfExpand(prk: [UInt8], info: String, length: Int) -> [UInt8] {
        let key = SymmetricKey(data: prk)
        let okm = HKDF<SHA256>.expand(pseudoRandomKey: key,
                                      info: Data(info.utf8),
                                      outputByteCount: length)
        return okm.withUnsafeBytes { Array($0) }
    }

    /// Bitwarden stretched master key: HKDF-Expand("enc") || HKDF-Expand("mac").
    public static func stretchMasterKey(_ masterKey: [UInt8]) -> SymmetricCryptoKey {
        let enc = hkdfExpand(prk: masterKey, info: "enc", length: 32)
        let mac = hkdfExpand(prk: masterKey, info: "mac", length: 32)
        // 32-byte halves are guaranteed valid, so `try!` is safe here.
        return try! SymmetricCryptoKey(encKey: Data(enc), macKey: Data(mac))
    }
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `swift test --filter KeyStretchTests`
Expected: PASS, 4 tests.

- [ ] **Step 5: Commit**

```bash
git add Sources/CryptoCore/KeyStretch.swift Tests/CryptoCoreTests/KeyStretchTests.swift
git commit -m "feat(cryptocore): add HKDF-Expand key stretching + SymmetricCryptoKey"
```

---

### Task 9: SymmetricCrypto — AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC)

**Files:**
- Create: `Sources/CryptoCore/SymmetricCrypto.swift`
- Test: `Tests/CryptoCoreTests/SymmetricCryptoTests.swift`

- [ ] **Step 1: Write the failing test**

`Tests/CryptoCoreTests/SymmetricCryptoTests.swift`:
```swift
import XCTest
import CryptoKit
@testable import CryptoCore

final class SymmetricCryptoTests: XCTestCase {
    private func makeKey() throws -> SymmetricCryptoKey {
        try SymmetricCryptoKey(combined: Data((0..<64).map { UInt8($0) }))
    }

    func test_roundTrip() throws {
        let key = try makeKey()
        let plaintext = Data("the quick brown fox jumps over the lazy dog".utf8)
        let enc = try SymmetricCrypto.encrypt(plaintext, using: key)
        XCTAssertEqual(enc.type, .aesCbc256_HmacSha256_B64)
        XCTAssertEqual(enc.iv?.count, 16)
        XCTAssertEqual(enc.mac?.count, 32)
        let decrypted = try SymmetricCrypto.decrypt(enc, using: key)
        XCTAssertEqual(decrypted, plaintext)
    }

    func test_roundTripViaStringSerialization() throws {
        let key = try makeKey()
        let plaintext = Data("secret".utf8)
        let enc = try SymmetricCrypto.encrypt(plaintext, using: key)
        let reparsed = try EncString(parsing: enc.stringValue)
        XCTAssertEqual(try SymmetricCrypto.decrypt(reparsed, using: key), plaintext)
    }

    func test_macTamperRejected() throws {
        let key = try makeKey()
        let enc = try SymmetricCrypto.encrypt(Data("secret".utf8), using: key)
        var badMac = enc.mac!
        badMac[0] ^= 0xFF
        let tampered = EncString(type: .aesCbc256_HmacSha256_B64, iv: enc.iv, ciphertext: enc.ciphertext, mac: badMac)
        XCTAssertThrowsError(try SymmetricCrypto.decrypt(tampered, using: key)) {
            XCTAssertEqual($0 as? CryptoError, .macMismatch)
        }
    }

    func test_ciphertextTamperRejectedByMAC() throws {
        let key = try makeKey()
        let enc = try SymmetricCrypto.encrypt(Data("secret".utf8), using: key)
        var badCt = enc.ciphertext
        badCt[0] ^= 0xFF
        let tampered = EncString(type: .aesCbc256_HmacSha256_B64, iv: enc.iv, ciphertext: badCt, mac: enc.mac)
        XCTAssertThrowsError(try SymmetricCrypto.decrypt(tampered, using: key)) {
            XCTAssertEqual($0 as? CryptoError, .macMismatch)
        }
    }

    func test_decrypt64ByteCipherKey_pkcs7Unpadded() throws {
        // A 64-byte payload (e.g. a per-cipher key) must round-trip with PKCS#7
        // padding added on encrypt and stripped on decrypt — yielding exactly 64 bytes.
        let key = try makeKey()
        let cipherKey = Data((0..<64).map { UInt8(($0 * 7) & 0xff) })
        let enc = try SymmetricCrypto.encrypt(cipherKey, using: key)
        let out = try SymmetricCrypto.decrypt(enc, using: key)
        XCTAssertEqual(out.count, 64)
        XCTAssertEqual(out, cipherKey)
    }

    func test_type0DecryptionBlocked() throws {
        let key = try makeKey()
        let enc = EncString(type: .aesCbc256_B64, iv: Data(count: 16), ciphertext: Data(count: 16), mac: nil)
        XCTAssertThrowsError(try SymmetricCrypto.decrypt(enc, using: key)) {
            XCTAssertEqual($0 as? CryptoError, .unsupportedEncStringType(0))
        }
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `swift test --filter SymmetricCryptoTests`
Expected: FAIL — `cannot find 'SymmetricCrypto' in scope`.

- [ ] **Step 3: Implement**

`Sources/CryptoCore/SymmetricCrypto.swift`:
```swift
import Foundation
import CommonCrypto
import CryptoKit

public enum SymmetricCrypto {
    /// Encrypt with AES-256-CBC (PKCS#7) then HMAC-SHA256 over (iv || ciphertext).
    public static func encrypt(_ plaintext: Data, using key: SymmetricCryptoKey) throws -> EncString {
        let iv = try SecureRandom.bytes(16)
        let ciphertext = try aesCBC(.encrypt, data: plaintext, key: key.encKey, iv: iv)
        let mac = hmac(iv + ciphertext, key: key.macKey)
        return EncString(type: .aesCbc256_HmacSha256_B64, iv: iv, ciphertext: ciphertext, mac: mac)
    }

    /// Verify HMAC (constant-time) BEFORE decrypting; only type 2 is supported here.
    public static func decrypt(_ encString: EncString, using key: SymmetricCryptoKey) throws -> Data {
        guard encString.type == .aesCbc256_HmacSha256_B64 else {
            throw CryptoError.unsupportedEncStringType(encString.type.rawValue)
        }
        guard let iv = encString.iv, let mac = encString.mac else { throw CryptoError.invalidEncString }
        let macKey = SymmetricKey(data: key.macKey)
        let authenticated = iv + encString.ciphertext
        guard HMAC<SHA256>.isValidAuthenticationCode(mac, authenticating: authenticated, using: macKey) else {
            throw CryptoError.macMismatch
        }
        return try aesCBC(.decrypt, data: encString.ciphertext, key: key.encKey, iv: iv)
    }

    // MARK: - Private

    private static func hmac(_ data: Data, key: Data) -> Data {
        let code = HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: key))
        return Data(code)
    }

    private enum Operation { case encrypt, decrypt }

    private static func aesCBC(_ op: Operation, data: Data, key: Data, iv: Data) throws -> Data {
        guard key.count == kCCKeySizeAES256, iv.count == kCCBlockSizeAES128 else {
            throw CryptoError.invalidKeyLength
        }
        let ccOp = (op == .encrypt) ? CCOperation(kCCEncrypt) : CCOperation(kCCDecrypt)
        var out = Data(count: data.count + kCCBlockSizeAES128)
        var moved = 0
        let status: Int32 = out.withUnsafeMutableBytes { outPtr in
            data.withUnsafeBytesOrEmpty { dataPtr, dataLen in
                iv.withUnsafeBytes { ivPtr in
                    key.withUnsafeBytes { keyPtr in
                        CCCrypt(ccOp,
                                CCAlgorithm(kCCAlgorithmAES),
                                CCOptions(kCCOptionPKCS7Padding),
                                keyPtr.baseAddress, key.count,
                                ivPtr.baseAddress,
                                dataPtr, dataLen,
                                outPtr.baseAddress, out.count,
                                &moved)
                    }
                }
            }
        }
        guard status == kCCSuccess else {
            throw op == .encrypt ? CryptoError.encryptionFailed : CryptoError.decryptionFailed
        }
        return out.prefix(moved)
    }
}

private extension Data {
    func withUnsafeBytesOrEmpty<R>(_ body: (UnsafeRawPointer, Int) -> R) -> R {
        if isEmpty {
            var scratch: UInt8 = 0
            return withUnsafePointer(to: &scratch) { body(UnsafeRawPointer($0), 0) }
        }
        return withUnsafeBytes { body($0.baseAddress!, count) }
    }
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `swift test --filter SymmetricCryptoTests`
Expected: PASS, 6 tests.

- [ ] **Step 5: Commit**

```bash
git add Sources/CryptoCore/SymmetricCrypto.swift Tests/CryptoCoreTests/SymmetricCryptoTests.swift
git commit -m "feat(cryptocore): add AES-256-CBC + HMAC-SHA256 encrypt-then-MAC"
```

---

### Task 10: End-to-end golden chain + real-account fixture procedure

**Files:**
- Create: `Tests/CryptoCoreTests/GoldenVectorTests.swift`
- Create: `Tests/CryptoCoreTests/Fixtures/README.md`

This proves the full unlock decryption path: derive master key → stretch → encrypt a synthetic 64-byte "UserKey" under the stretched key → parse the EncString → decrypt back. It also documents how to capture a **real Vaultwarden** fixture so a later CI step can assert byte-compatibility against an actual server.

- [ ] **Step 1: Write the failing test**

`Tests/CryptoCoreTests/GoldenVectorTests.swift`:
```swift
import XCTest
@testable import CryptoCore

final class GoldenVectorTests: XCTestCase {
    func test_fullUnlockChain_synthetic() throws {
        // 1. derive master key (PBKDF2) from the planning golden vector
        let mk = try KDF.deriveMasterKey(password: "Password123!",
                                         email: "user@example.com",
                                         iterations: 5000)
        XCTAssertEqual(Data(mk).hexString,
                       "b86c2ee9e33113c09c31c92d5f288a989a56d2485e76cc81f5607dea299a5da4")

        // 2. stretch into a SymmetricCryptoKey
        let stretched = KeyStretch.stretchMasterKey(mk)

        // 3. a synthetic 64-byte UserKey, "protected" under the stretched key
        let userKey = Data((0..<64).map { UInt8(($0 &* 3 &+ 1) & 0xff) })
        let protectedUserKey = try SymmetricCrypto.encrypt(userKey, using: stretched)

        // 4. simulate the wire round-trip and decrypt the protected user key
        let wire = protectedUserKey.stringValue
        let recovered = try SymmetricCrypto.decrypt(try EncString(parsing: wire), using: stretched)
        XCTAssertEqual(recovered, userKey)

        // 5. and the recovered 64 bytes form a usable SymmetricCryptoKey
        let userSymKey = try SymmetricCryptoKey(combined: recovered)
        let secret = Data("a vault item field".utf8)
        let enc = try SymmetricCrypto.encrypt(secret, using: userSymKey)
        XCTAssertEqual(try SymmetricCrypto.decrypt(enc, using: userSymKey), secret)
    }
}
```

- [ ] **Step 2: Run to verify it fails, then passes**

Run: `swift test --filter GoldenVectorTests`
Expected: PASS immediately (it only uses APIs from Tasks 6–9). If it fails, a prior primitive is wrong — fix that task, do not weaken this test.

- [ ] **Step 3: Document the real-account fixture capture procedure**

`Tests/CryptoCoreTests/Fixtures/README.md`:
```markdown
# Real Vaultwarden compatibility fixtures

To assert byte-compatibility against a real server (run before merging crypto changes):

1. Start a throwaway Vaultwarden in Docker:
   `docker run --rm -p 8080:80 -e ADMIN_TOKEN=dev vaultwarden/server:latest`
2. Create an account with a KNOWN PBKDF2 KDF (Settings → Security → set KDF = PBKDF2,
   iterations = 600000). Record email, password, iterations.
3. Capture from `POST /identity/connect/token` the `Key` (protected user key EncString)
   and from `GET /api/sync` one cipher's `name` EncString.
4. Save them as `Fixtures/vaultwarden-pbkdf2.json`:
   `{ "email": "...", "password": "...", "iterations": 600000,
      "protectedUserKey": "2.<iv>|<ct>|<mac>", "cipherName": "2.<iv>|<ct>|<mac>",
      "expectedCipherName": "<plaintext>" }`
5. Add a test that derives the master key, stretches, decrypts `protectedUserKey` to the
   UserKey, then decrypts `cipherName` and asserts it equals `expectedCipherName`.

NOTE: fixtures contain a real password for a THROWAWAY account only. Never commit a
fixture for a real user. Gate the fixture test behind an env var (e.g. `TESSERA_FIXTURES=1`)
so CI without the file still passes.
```

- [ ] **Step 4: Run the full suite**

Run: `swift test`
Expected: ALL tests pass (Tasks 1–10).

- [ ] **Step 5: Commit**

```bash
git add Tests/CryptoCoreTests/GoldenVectorTests.swift Tests/CryptoCoreTests/Fixtures/README.md
git commit -m "test(cryptocore): add end-to-end golden chain + fixture procedure"
```

---

## Self-Review (run by the author after writing)

**1. Spec coverage** — maps to spec §5.1 (CryptoCore):
- SecureBytes ✔ Task 3 · EncString parser (type 0/1/2/3-6/7) ✔ Task 5 · PBKDF2-only KDF ✔ Tasks 6–7 · server/local hash (iters 1/2) ✔ Task 7 · HKDF-Expand stretch ✔ Task 8 · AES-256-CBC+HMAC encrypt-then-MAC, constant-time compare ✔ Task 9 · PKCS#7 unpad of 64-byte cipher key ✔ Task 9 · golden-vector regression ✔ Tasks 6–10.
- Deliberately deferred (documented, not gaps): RSA-2048-OAEP (type 3/4) → M2 org keys; type-7 (COSE) decryption → soft-fail only; libsodium/Argon2id → excluded by D6.

**2. Placeholder scan** — every step has runnable code or an exact command; no TBD/TODO. The Fixtures README describes a procedure (intentional, for real-server capture), not a code placeholder.

**3. Type consistency** — checked across tasks: `PBKDF2.deriveSHA256`, `KDF.deriveMasterKey`/`masterPasswordHash`/`HashPurpose`, `KeyStretch.hkdfExpand`/`stretchMasterKey`, `SymmetricCryptoKey(combined:)`/`encKey`/`macKey`, `SymmetricCrypto.encrypt`/`decrypt`, `EncString(parsing:)`/`stringValue`, `Data.hexString`/`Data(hex:)`, `SecureRandom.bytes` — all names used in tests match their definitions. `withUnsafeBytesOrEmpty` is defined privately in both PBKDF2.swift and SymmetricCrypto.swift (file-private, no conflict).

---

## Execution Handoff

After this plan, the next M1 plans (separate files) are: **Plan 2 VaultModels**, **Plan 3 KeyVault+KeychainBridge**, **Plan 4 VaultStore**, **Plan 5 Networking**, **Plan 6 SyncEngine+VaultRepository**, **Plan 7 VaultReader+Fido2+AutoFillExtension**, **Plan 8 DesignSystem+UIShared+UI-iOS+App-iOS**, **Plan 9 minimal UI-mac+App-macOS** (per spec §9 build order).
