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
