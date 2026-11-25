import Foundation
import Networking

func checkWebAuthnSecondFactor(_ r: inout TestRunner) {
    let encodedChallenge = "AAECAwQFBgcICQoLDA0ODw"
    let id = Data([0xfb, 0xff])
    let encodedID = "-_8"
    let host = "vault.example.test"
    let response = """
    {"TwoFactorProviders":["0","7"],"TwoFactorProviders2":{"0":{},"7":{
      "rpId":"\(host)","challenge":"\(encodedChallenge)","timeout":60000,
      "allowCredentials":[{"type":"public-key","id":"\(encodedID)","transports":["usb","nfc"]}],
      "userVerification":"discouraged","extensions":{"appid":"https://\(host)/app-id.json"}
    }}}
    """
    func providers(_ response: String) -> TwoFactorProviders? {
        TwoFactorProviders(errorResponseData: Data(response.utf8))
    }
    guard let twoFactor = providers(response), let challenge = twoFactor.webAuthnChallenge else {
        r.expectTrue(false, "Vaultwarden provider-7 flat request options decode")
        return
    }
    r.expect(twoFactor.providers, [.authenticator, .webAuthn], "provider 7 coexists with authenticator codes")
    r.expect(challenge.challenge, Data(0..<16), "challenge bytes are decoded")
    r.expect(challenge.allowedCredentialIDs, [id], "nested credential allowlist is preserved")
    r.expect(challenge.relyingPartyIdentifier, host, "RP ID is decoded")
    r.expect(challenge.userVerification, .discouraged, "server's user verification preference is retained")
    r.expect(challenge.timeoutMilliseconds, 60_000, "server's timeout is retained")

    for (original, invalid) in [
        (encodedChallenge, "AA"), (encodedChallenge, "\(encodedChallenge)=="),
        (encodedChallenge, "\(encodedChallenge.dropLast())x"),
        (encodedChallenge, String(repeating: "A", count: 1_368)),
        (encodedID, "+/8"), (encodedID, "-_9"), (encodedID, ""),
        (host, "https://\(host)"), (host, "127.0.0.1"),
        ("\"public-key\"", "\"unknown\""), ("60000", "true"), ("60000", "1.5"),
        ("\"discouraged\"", "\"unknown\""),
    ] {
        let modified = providers(response.replacingOccurrences(of: original, with: invalid))
        r.expect(modified?.webAuthnChallenge, nil, "malformed provider 7 options are not usable")
        r.expect(modified?.providers, [.authenticator, .webAuthn], "malformed provider 7 does not discard TOTP")
    }
    let descriptor = "{\"type\":\"public-key\",\"id\":\"\(encodedID)\",\"transports\":[\"usb\",\"nfc\"]}"
    r.expect(providers(response.replacingOccurrences(of: descriptor, with: ""))?.webAuthnChallenge,
             nil, "an empty allowlist cannot invoke a discoverable-credential request")
    r.expect(providers(response.replacingOccurrences(of: descriptor, with: "\(descriptor),\(descriptor)"))?.webAuthnChallenge,
             nil, "duplicate allowlist IDs are rejected")
    let tooMany = (0..<65).map { value in
        "{\"type\":\"public-key\",\"id\":\"\(Data([UInt8(value)]).base64EncodedString().prefix(2))\"}"
    }.joined(separator: ",")
    r.expect(providers(response.replacingOccurrences(of: descriptor, with: tooMany))?.webAuthnChallenge,
             nil, "oversized allowlists are rejected")
    r.expect(providers(response.replacingOccurrences(of: "60000", with: "600000"))?.webAuthnChallenge?.timeoutMilliseconds,
             120_000, "server timeout is capped")
    r.expect(providers(#"{"TwoFactorProviders":["7"]}"#)?.webAuthnChallenge,
             nil, "a legacy provider ID without request options is not usable")

    let server = ServerEnvironment(string: "https://\(host)/prefix")!
    let authenticatorData = Data(repeating: 0x42, count: 37)
    func clientData(origin: String = "https://VAULT.example.test:443", type: String = "webauthn.get",
                    challenge: String = encodedChallenge, extra: String = "") -> Data {
        // Deliberate whitespace and explicit default port: preserve the exact signed input.
        Data("{ \"type\":\"\(type)\", \"challenge\":\"\(challenge)\", \"origin\":\"\(origin)\"\(extra) }".utf8)
    }
    func assertion(clientData: Data, credentialID: Data = id, authenticator: Data = authenticatorData,
                   signature: Data = Data([0xff]), handle: Data? = nil) -> WebAuthnSecondFactorAssertion {
        .init(credentialID: credentialID, authenticatorData: authenticator,
              clientDataJSON: clientData, signature: signature, userHandle: handle)
    }
    let signedClientData = clientData()
    let valid = assertion(clientData: signedClientData, handle: Data([0xff]))
    do {
        let token = try challenge.token(for: valid, environment: server)
        let receivedEnvelope = String(token.dropLast()) + #", "ignored": true}"#
        let validatedToken = try challenge.validate(token: receivedEnvelope, environment: server)
        r.expectTrue(!validatedToken.contains("ignored"), "only recognized wire fields are eligible for submission")
        let object = try JSONSerialization.jsonObject(with: Data(validatedToken.utf8)) as? [String: Any]
        let wireResponse = object?["response"] as? [String: String]
        r.expect(Set(object?.keys.map { $0 } ?? []), Set(["id", "rawId", "type", "extensions", "response"]),
                 "provider-7 wire JSON uses Vaultwarden's exact field names")
        r.expect(object?["id"] as? String, encodedID, "id is canonical unpadded base64url")
        r.expect(object?["rawId"] as? String, encodedID, "rawId matches id")
        r.expect(object?["type"] as? String, "public-key", "wire credential type")
        r.expect(object?["extensions"] as? [String: String], [:], "wire extensions are empty")
        r.expect(wireResponse?["signature"], "_w", "signature uses unpadded base64url")
        r.expect(wireResponse?["userHandle"], "_w", "optional user handle uses unpadded base64url")
        r.expect(wireResponse?["authenticatorData"], authenticatorData.base64EncodedString().replacingOccurrences(of: "=", with: ""),
                 "authenticator data bytes are preserved")
        let decodedClientData = wireResponse?["clientDataJson"].flatMap { encoded in
            let padded = encoded.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
                + String(repeating: "=", count: (4 - encoded.utf8.count % 4) % 4)
            return Data(base64Encoded: padded)
        }
        r.expect(decodedClientData, signedClientData, "signed client data bytes are not normalized")
        let baseToken = try challenge.token(for: assertion(clientData: signedClientData), environment: server)
        r.expectTrue(!baseToken.contains("userHandle"), "unavailable user handle is omitted")

        for tamperedToken in [
            token.replacingOccurrences(of: "\"rawId\":\"-_8\"", with: "\"rawId\":\"_w\""),
            token.replacingOccurrences(of: "\"extensions\":{}", with: "\"extensions\":{\"appid\":true}"),
            token.replacingOccurrences(of: "\"clientDataJson\"", with: "\"clientDataJSON\""),
            token.replacingOccurrences(of: "\"signature\":\"_w\"", with: "\"signature\":\"_w==\""),
            String(repeating: " ", count: 65_537) + token,
        ] {
            r.expectThrows("arbitrary retry token must have canonical wire shape") {
                try challenge.validate(token: tamperedToken, environment: server)
            }
        }
        let anotherChallenge = providers(response.replacingOccurrences(of: encodedChallenge,
                                  with: "BAECAwQFBgcICQoLDA0ODw"))?.webAuthnChallenge
        r.expectTrue(anotherChallenge != nil, "second challenge fixture is valid")
        r.expectThrows("a prior assertion is not accepted for a replacement challenge") {
            try anotherChallenge?.validate(token: token, environment: server)
        }
    } catch {
        r.expectTrue(false, "valid assertion did not round-trip: \(error)")
    }

    for origin in ["https://example.test", "https://other.\(host)", "https://\(host).",
                   "http://\(host)", "https://\(host):444", "https://\(host):",
                   "https://\(host)/", "https://\(host)/prefix", "https://\(host)?",
                   "https://\(host)#", "https://user@\(host)", "https://%76ault.example.test",
                   "ios:bundle-id:dev.moooyo.tessera"] {
        r.expectThrows("reject assertion origin \(origin)") {
            _ = try challenge.token(for: assertion(clientData: clientData(origin: origin)), environment: server)
        }
    }
    for invalidClientData in [
        clientData(type: "webauthn.create"), clientData(challenge: "BAECAwQFBgcICQoLDA0ODw"),
        clientData(extra: ", \"crossOrigin\":true"), clientData(extra: ", \"topOrigin\":\"https://\(host)\""),
        Data(), Data(repeating: 0x20, count: 16_385),
    ] {
        r.expectThrows("reject invalid callback client data") {
            _ = try challenge.token(for: assertion(clientData: invalidClientData), environment: server)
        }
    }
    for invalid in [
        assertion(clientData: signedClientData, credentialID: Data([0xff])),
        assertion(clientData: signedClientData, authenticator: Data(repeating: 0, count: 36)),
        assertion(clientData: signedClientData, signature: Data()),
        assertion(clientData: signedClientData, handle: Data(repeating: 0, count: 65)),
    ] {
        r.expectThrows("reject invalid callback credential fields") { _ = try challenge.token(for: invalid, environment: server) }
    }

    for unsupported in [ServerEnvironment(string: "http://\(host)")!,
                        ServerEnvironment(string: "https://other.\(host)")!,
                        ServerEnvironment(base: server.base, identityURL: URL(string: "https://identity.\(host)/identity")),
                        ServerEnvironment(base: server.base, identityURL: URL(string: "https://\(host):8443/identity"))] {
        r.expectThrows("request refuses a mismatched configured deployment") { try challenge.validate(environment: unsupported) }
    }
    let customPort = ServerEnvironment(string: "https://\(host):8443/prefix")!
    let customAssertion = assertion(clientData: clientData(origin: "https://\(host):8443", extra: ", \"crossOrigin\":false"))
    r.expectTrue((try? challenge.token(for: customAssertion, environment: customPort)) != nil,
                 "nondefault configured origin port must match exactly")
}
