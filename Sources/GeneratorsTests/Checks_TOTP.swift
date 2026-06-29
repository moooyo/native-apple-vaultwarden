import Foundation
@testable import Generators

func checkTOTP(_ r: inout TestRunner) {
    let secret = Base32.decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")!

    // RFC 6238 golden vectors (SHA-1, seed "12345678901234567890")
    // 8-digit
    let cfg8 = TOTPConfiguration(secret: secret, algorithm: .sha1, digits: 8, period: 30, isSteam: false)
    r.expect(TOTP.code(for: cfg8, at: Date(timeIntervalSince1970: 59)), "94287082", "TOTP sha1/8 t=59")
    r.expect(TOTP.code(for: cfg8, at: Date(timeIntervalSince1970: 1111111109)), "07081804", "TOTP sha1/8 t=1111111109")
    r.expect(TOTP.code(for: cfg8, at: Date(timeIntervalSince1970: 1234567890)), "89005924", "TOTP sha1/8 t=1234567890")
    r.expect(TOTP.code(for: cfg8, at: Date(timeIntervalSince1970: 2000000000)), "69279037", "TOTP sha1/8 t=2000000000")

    // 6-digit
    let cfg6 = TOTPConfiguration(secret: secret, algorithm: .sha1, digits: 6, period: 30, isSteam: false)
    r.expect(TOTP.code(for: cfg6, at: Date(timeIntervalSince1970: 59)), "287082", "TOTP sha1/6 t=59")
    r.expect(TOTP.code(for: cfg6, at: Date(timeIntervalSince1970: 1111111109)), "081804", "TOTP sha1/6 t=1111111109")
    r.expect(TOTP.code(for: cfg6, at: Date(timeIntervalSince1970: 1234567890)), "005924", "TOTP sha1/6 t=1234567890")
    r.expect(TOTP.code(for: cfg6, at: Date(timeIntervalSince1970: 2000000000)), "279037", "TOTP sha1/6 t=2000000000")

    // secondsRemaining: 30 - 59 % 30 = 30 - 29 = 1
    r.expect(TOTP.secondsRemaining(for: cfg6, at: Date(timeIntervalSince1970: 59)), 1, "TOTP secondsRemaining t=59 == 1")
}

func checkTOTPParsing(_ r: inout TestRunner) {
    let seed = Base32.decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")!

    // Raw base32 secret -> sha1/6/30/non-steam
    do {
        let cfg = try TOTP.configuration(from: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        r.expect(cfg.secret, seed, "raw: secret decodes")
        r.expect(cfg.algorithm, .sha1, "raw: algorithm sha1")
        r.expect(cfg.digits, 6, "raw: digits 6")
        r.expect(cfg.period, 30, "raw: period 30")
        r.expectTrue(!cfg.isSteam, "raw: not steam")
        r.expect(TOTP.code(for: cfg, at: Date(timeIntervalSince1970: 59)), "287082", "raw: code(at:59) == 287082")
    } catch {
        r.expectTrue(false, "raw: threw \(error)")
    }

    // otpauth URI with params (algorithm case-insensitive)
    do {
        let uri = "otpauth://totp/Example:alice@x.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA256&digits=8&period=60"
        let cfg = try TOTP.configuration(from: uri)
        r.expect(cfg.secret, seed, "otpauth: secret decodes")
        r.expect(cfg.algorithm, .sha256, "otpauth: algorithm sha256")
        r.expect(cfg.digits, 8, "otpauth: digits 8")
        r.expect(cfg.period, 60, "otpauth: period 60")
        r.expectTrue(!cfg.isSteam, "otpauth: not steam")
    } catch {
        r.expectTrue(false, "otpauth: threw \(error)")
    }

    // otpauth with defaults (no algorithm/digits/period)
    do {
        let uri = "otpauth://totp/Example:alice@x.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        let cfg = try TOTP.configuration(from: uri)
        r.expect(cfg.algorithm, .sha1, "otpauth defaults: algorithm sha1")
        r.expect(cfg.digits, 6, "otpauth defaults: digits 6")
        r.expect(cfg.period, 30, "otpauth defaults: period 30")
    } catch {
        r.expectTrue(false, "otpauth defaults: threw \(error)")
    }

    // steam:// -> isSteam true, digits 5
    do {
        let cfg = try TOTP.configuration(from: "steam://GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        r.expect(cfg.secret, seed, "steam: secret decodes")
        r.expectTrue(cfg.isSteam, "steam: isSteam true")
        r.expect(cfg.digits, 5, "steam: digits 5")
    } catch {
        r.expectTrue(false, "steam: threw \(error)")
    }

    // garbage raw secret -> invalidSecret
    r.expectThrowsError(TOTPError.invalidSecret, "garbage raw -> invalidSecret") {
        _ = try TOTP.configuration(from: "0189!@#$")
    }

    // otpauth missing secret -> invalidURI
    r.expectThrowsError(TOTPError.invalidURI, "otpauth missing secret -> invalidURI") {
        _ = try TOTP.configuration(from: "otpauth://totp/Example:alice@x.com?digits=6")
    }

    // empty input -> invalidSecret
    r.expectThrowsError(TOTPError.invalidSecret, "empty -> invalidSecret") {
        _ = try TOTP.configuration(from: "")
    }
}

func checkTOTPRanges(_ r: inout TestRunner) {
    let secret = Base32.decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")!

    // DoS guard at parse time: period=0 -> invalidURI (would div-by-zero)
    r.expectThrowsError(TOTPError.invalidURI, "otpauth period=0 -> invalidURI") {
        _ = try TOTP.configuration(from: "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=0")
    }

    // DoS guard at parse time: digits=10 -> invalidURI (would overflow UInt32 pow)
    r.expectThrowsError(TOTPError.invalidURI, "otpauth digits=10 -> invalidURI") {
        _ = try TOTP.configuration(from: "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=10")
    }

    // Defensive totality: a directly-constructed bad config must NOT crash.
    let bad = TOTPConfiguration(secret: secret, algorithm: .sha1, digits: 100, period: 0, isSteam: false)
    let code = TOTP.code(for: bad, at: Date(timeIntervalSince1970: 59))
    r.expectTrue(!code.isEmpty, "code(for: bad config) does not crash, returns non-empty")
    let remaining = TOTP.secondsRemaining(for: bad, at: Date(timeIntervalSince1970: 59))
    r.expectTrue(remaining >= 0, "secondsRemaining(for: bad config) does not crash")

    // secondsRemaining boundary: 30 - 60 % 30 = 30 - 0 = 30
    let cfg6 = TOTPConfiguration(secret: secret, algorithm: .sha1, digits: 6, period: 30, isSteam: false)
    r.expect(TOTP.secondsRemaining(for: cfg6, at: Date(timeIntervalSince1970: 60)), 30, "TOTP secondsRemaining t=60 == 30")
}
