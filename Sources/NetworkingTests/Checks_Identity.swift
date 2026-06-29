import Foundation
import Networking
import VaultModels

func checkPrelogin(_ r: inout TestRunner) async {
    let box = StubBox(response: .json(Fixtures.prelogin))
    let client = Fixtures.client(box: box)

    do {
        let resp = try await client.prelogin(email: "user@example.test")
        r.expect(resp.kdf, 0, "prelogin decodes kdf")
        r.expect(resp.kdfIterations, 600000, "prelogin decodes kdfIterations")
    } catch {
        r.expectTrue(false, "prelogin threw: \(error)")
    }

    guard let cap = box.captured else {
        r.expectTrue(false, "prelogin captured a request"); return
    }
    r.expect(cap.method, "POST", "prelogin is POST")
    r.expect(cap.path, "/identity/accounts/prelogin", "prelogin path")
    r.expectTrue(cap.header("Content-Type")?.contains("application/json") ?? false,
                 "prelogin Content-Type JSON")
    // Body is JSON {"email": ...}
    if let obj = try? JSONSerialization.jsonObject(with: cap.body ?? Data()) as? [String: String] {
        r.expect(obj["email"], "user@example.test", "prelogin body email")
    } else {
        r.expectTrue(false, "prelogin body is JSON object with email")
    }
}

func checkTokenSuccess(_ r: inout TestRunner) async {
    let box = StubBox(response: .json(Fixtures.token()))
    let client = Fixtures.client(box: box)

    do {
        let result = try await client.token(email: "user@example.test",
                                            passwordHash: "SERVER-AUTH-HASH==",
                                            twoFactor: nil)
        switch result {
        case .success(let token):
            r.expect(token.accessToken, "AT-123", "token success accessToken")
            r.expect(token.refreshToken, "RT-456", "token success refreshToken")
            r.expectTrue(token.key != nil, "token success Key → EncString")
            r.expectTrue(token.privateKey != nil, "token success PrivateKey → EncString")
        case .twoFactorRequired:
            r.expectTrue(false, "token success should not be 2FA")
        }
    } catch {
        r.expectTrue(false, "token success threw: \(error)")
    }

    guard let cap = box.captured else {
        r.expectTrue(false, "token captured a request"); return
    }
    r.expect(cap.method, "POST", "token is POST")
    r.expect(cap.path, "/identity/connect/token", "token path")
    r.expectTrue(cap.header("Content-Type")?.contains("application/x-www-form-urlencoded") ?? false,
                 "token Content-Type is form-urlencoded")

    let form = parseForm(cap.bodyString)
    r.expect(form["grant_type"], "password", "token form grant_type")
    r.expect(form["username"], "user@example.test", "token form username")
    r.expect(form["password"], "SERVER-AUTH-HASH==", "token form password (server-auth hash)")
    r.expect(form["scope"], "api offline_access", "token form scope")
    r.expect(form["client_id"], "mobile", "token form client_id")
    r.expect(form["deviceType"], "1", "token form deviceType")
    r.expect(form["deviceIdentifier"], "DEV-IDENT-UUID", "token form deviceIdentifier")
    r.expect(form["deviceName"], "Test iPhone", "token form deviceName")
}

/// CRITICAL: a base64 PBKDF2 server-auth hash can contain `+`, `/`, and `=`. In an
/// `application/x-www-form-urlencoded` body these are all reserved: `+` means space,
/// `/` and `=` are delimiters. They MUST be percent-encoded (`%2B`/`%2F`/`%3D`) on the
/// wire or the server sees a corrupted hash and login silently fails. This guards
/// against a regression to the naive `.urlQueryAllowed` encoding (which leaves `+`/`/`/`=`
/// untouched). We assert both the raw wire bytes and the round-tripped value.
func checkTokenPasswordHashSpecialChars(_ r: inout TestRunner) async {
    let box = StubBox(response: .json(Fixtures.token()))
    let client = Fixtures.client(box: box)
    // Realistic shape: base64 with +, /, trailing == padding.
    let hash = "ab+cd/ef+gh/ij=="

    do {
        _ = try await client.token(email: "user+tag@example.test",
                                   passwordHash: hash,
                                   twoFactor: nil)
    } catch {
        r.expectTrue(false, "token special-char hash threw: \(error)")
    }

    let raw = box.captured?.bodyString ?? ""
    // The literal special chars must NOT appear unencoded in the password field.
    r.expectTrue(raw.contains("password=ab%2Bcd%2Fef%2Bgh%2Fij%3D%3D"),
                 "password hash +,/,= are percent-encoded on the wire (%2B/%2F/%3D)")
    r.expectTrue(!raw.contains("ab+cd"),
                 "password hash '+' is NOT left as a raw '+' (would decode to space)")
    // And it round-trips back to the exact hash a server would reconstruct.
    let form = parseForm(raw)
    r.expect(form["password"], hash, "password hash round-trips through form decode")
    // The '+' in the username/email must also survive (encoded, not turned to space).
    r.expect(form["username"], "user+tag@example.test", "username '+' round-trips")
}

func checkTokenTwoFactor(_ r: inout TestRunner) async {
    let box = StubBox(response: .json(Fixtures.twoFactorChallenge, status: 400))
    let client = Fixtures.client(box: box)

    do {
        let result = try await client.token(email: "user@example.test",
                                            passwordHash: "HASH",
                                            twoFactor: nil)
        switch result {
        case .success:
            r.expectTrue(false, "token 2FA should not be success")
        case .twoFactorRequired(let providers):
            r.expect(providers.providerIDs, [0, 1], "2FA provider IDs (Authenticator, Email)")
            r.expectTrue(providers.providers.contains(.authenticator), "2FA includes Authenticator")
            r.expectTrue(providers.providers.contains(.email), "2FA includes Email")
            // Email metadata masked address is surfaced.
            r.expect(providers.raw[1]?["Email"], .string("j***@example.test"),
                     "2FA email metadata surfaced")
        }
    } catch {
        r.expectTrue(false, "token 2FA threw instead of returning .twoFactorRequired: \(error)")
    }
}

func checkTokenTwoFactorRetry(_ r: inout TestRunner) async {
    // After a challenge, the retry includes the twoFactor* fields and succeeds.
    let box = StubBox(response: .json(Fixtures.token()))
    let client = Fixtures.client(box: box)
    let payload = TwoFactorPayload(provider: .authenticator, token: "123456", remember: true)

    do {
        let result = try await client.token(email: "user@example.test",
                                            passwordHash: "HASH",
                                            twoFactor: payload)
        if case .success = result {
            r.expectTrue(true, "token 2FA retry succeeds")
        } else {
            r.expectTrue(false, "token 2FA retry should succeed")
        }
    } catch {
        r.expectTrue(false, "token 2FA retry threw: \(error)")
    }

    let form = parseForm(box.captured?.bodyString ?? "")
    r.expect(form["twoFactorToken"], "123456", "retry form twoFactorToken")
    r.expect(form["twoFactorProvider"], "0", "retry form twoFactorProvider")
    r.expect(form["twoFactorRemember"], "1", "retry form twoFactorRemember")
}

func checkTokenBadCredentials(_ r: inout TestRunner) async {
    // A 400 WITHOUT TwoFactorProviders2 must re-throw as .http, not be swallowed.
    let box = StubBox(response: .json(Fixtures.badCredentials, status: 400))
    let client = Fixtures.client(box: box)
    await r.expectThrowsAsync("token bad credentials throws .http(400)") {
        _ = try await client.token(email: "u@x.test", passwordHash: "wrong", twoFactor: nil)
    }
}

func checkRefresh(_ r: inout TestRunner) async {
    let box = StubBox(response: .json(Fixtures.token()))
    let client = Fixtures.client(box: box)

    do {
        let token = try await client.refresh(refreshToken: "RT-OLD")
        r.expect(token.accessToken, "AT-123", "refresh decodes accessToken")
    } catch {
        r.expectTrue(false, "refresh threw: \(error)")
    }

    let form = parseForm(box.captured?.bodyString ?? "")
    r.expect(box.captured?.path, "/identity/connect/token", "refresh path")
    r.expect(form["grant_type"], "refresh_token", "refresh form grant_type")
    r.expect(form["refresh_token"], "RT-OLD", "refresh form refresh_token")
    r.expect(form["client_id"], "mobile", "refresh form client_id")
}

/// Parses an application/x-www-form-urlencoded body into a dictionary, decoding
/// `+` → space and percent-escapes so assertions compare against plain values.
func parseForm(_ s: String) -> [String: String] {
    var out: [String: String] = [:]
    for pair in s.split(separator: "&") {
        let kv = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
        guard kv.count == 2 else { continue }
        let k = formDecode(String(kv[0]))
        let v = formDecode(String(kv[1]))
        out[k] = v
    }
    return out
}

private func formDecode(_ s: String) -> String {
    s.replacingOccurrences(of: "+", with: " ").removingPercentEncoding ?? s
}
