import CoreFoundation
import Foundation

public enum WebAuthnSecondFactorError: Error, Sendable, Equatable {
    case unsupported
    case invalidChallenge
    case invalidAssertion
    case authorizationFailed
}

/// Password-grant provider 7 of Vaultwarden 1.37.5, not the separate passkey login flow.
public struct WebAuthnSecondFactorChallenge: Sendable, Equatable {
    public enum UserVerification: String, Sendable {
        case discouraged, preferred, required
    }

    public let relyingPartyIdentifier: String
    public let challenge: Data
    public let allowedCredentialIDs: [Data]
    public let userVerification: UserVerification
    public let timeoutMilliseconds: Int

    init?(metadata: [String: Any]) {
        guard let rpID = metadata["rpId"] as? String,
              let host = HTTPSOrigin.dnsHost(rpID),
              let encodedChallenge = metadata["challenge"] as? String,
              let challenge = Base64URL.decode(encodedChallenge, size: Size.challenge),
              let descriptors = metadata["allowCredentials"] as? [[String: Any]],
              (1...64).contains(descriptors.count) else { return nil }

        var credentialIDs: [Data] = []
        var seen: Set<Data> = []
        for descriptor in descriptors {
            guard descriptor["type"] as? String == "public-key",
                  let encodedID = descriptor["id"] as? String,
                  let id = Base64URL.decode(encodedID, size: Size.credentialID),
                  seen.insert(id).inserted else { return nil }
            credentialIDs.append(id)
        }

        let verification: UserVerification
        if let option = metadata["userVerification"] {
            guard let raw = option as? String, let value = UserVerification(rawValue: raw) else { return nil }
            verification = value
        } else {
            verification = .preferred
        }

        let timeout: Int
        if let option = metadata["timeout"] {
            guard let number = option as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
                  let milliseconds = number as? Int,
                  (1...Int(UInt32.max)).contains(milliseconds) else { return nil }
            timeout = min(milliseconds, 120_000)
        } else {
            timeout = 60_000
        }

        // Transport hints are advisory. Vaultwarden also asks for the legacy appid
        // extension, which Apple's native (non-browser) requests cannot supply.
        self.relyingPartyIdentifier = host
        self.challenge = challenge
        self.allowedCredentialIDs = credentialIDs
        self.userVerification = verification
        self.timeoutMilliseconds = timeout
    }

    /// Native assertions are only sent to a configured HTTPS Vaultwarden origin. A
    /// split identity origin is outside this flow, even if both hosts are trusted.
    public static func relyingPartyIdentifier(for environment: ServerEnvironment) throws -> String {
        try configuredOrigin(for: environment).host
    }

    /// Checks that the server's RP ID is exactly the configured deployment host.
    public func validate(environment: ServerEnvironment) throws {
        _ = try expectedOrigin(for: environment)
    }

    /// Returns the JSON string that is form-encoded as `twoFactorToken`. Signed
    /// client/authenticator data is preserved byte-for-byte instead of rewritten.
    public func token(for assertion: WebAuthnSecondFactorAssertion, environment: ServerEnvironment) throws -> String {
        try validate(assertion, expectedOrigin: expectedOrigin(for: environment))
        let id = Base64URL.encode(assertion.credentialID)
        let wire = WireAssertion(id: id, rawId: id, type: "public-key", extensions: [:], response: .init(
            authenticatorData: Base64URL.encode(assertion.authenticatorData),
            clientDataJson: Base64URL.encode(assertion.clientDataJSON),
            signature: Base64URL.encode(assertion.signature),
            userHandle: assertion.userHandle.map(Base64URL.encode)
        ))
        return String(decoding: try JSONEncoder().encode(wire), as: UTF8.self)
    }

    /// Rechecks a wire token against the pending login before transmission. This
    /// validates local binding and shape, not the signature (Vaultwarden verifies it).
    @discardableResult
    public func validate(token: String, environment: ServerEnvironment) throws -> String {
        guard token.utf8.count <= Size.token,
              let wire = try? JSONDecoder().decode(WireAssertion.self, from: Data(token.utf8)),
              wire.type == "public-key", wire.extensions.isEmpty, wire.id == wire.rawId,
              let id = Base64URL.decode(wire.rawId, size: Size.credentialID),
              let authenticatorData = Base64URL.decode(wire.response.authenticatorData, size: Size.authenticatorData),
              let clientData = Base64URL.decode(wire.response.clientDataJson, size: Size.clientDataJSON),
              let signature = Base64URL.decode(wire.response.signature, size: Size.signature) else {
            throw WebAuthnSecondFactorError.invalidAssertion
        }
        let userHandle: Data?
        if let encoded = wire.response.userHandle {
            guard let decoded = Base64URL.decode(encoded, size: Size.userHandle) else {
                throw WebAuthnSecondFactorError.invalidAssertion
            }
            userHandle = decoded
        } else {
            userHandle = nil
        }
        // Reserialize the outer envelope so ignored or ambiguous JSON fields never
        // reach the server. The signed binary fields are not changed.
        return try self.token(for: .init(credentialID: id, authenticatorData: authenticatorData,
                                         clientDataJSON: clientData, signature: signature, userHandle: userHandle),
                              environment: environment)
    }

    private static func configuredOrigin(for environment: ServerEnvironment) throws -> HTTPSOrigin {
        guard let origin = HTTPSOrigin(url: environment.base),
              origin == HTTPSOrigin(url: environment.identityBase) else {
            throw WebAuthnSecondFactorError.unsupported
        }
        return origin
    }

    private func expectedOrigin(for environment: ServerEnvironment) throws -> HTTPSOrigin {
        let origin = try Self.configuredOrigin(for: environment)
        guard origin.host == relyingPartyIdentifier else { throw WebAuthnSecondFactorError.invalidChallenge }
        return origin
    }

    private func validate(_ assertion: WebAuthnSecondFactorAssertion, expectedOrigin: HTTPSOrigin) throws {
        guard Size.credentialID.contains(assertion.credentialID.count),
              allowedCredentialIDs.contains(assertion.credentialID),
              Size.authenticatorData.contains(assertion.authenticatorData.count),
              Size.clientDataJSON.contains(assertion.clientDataJSON.count),
              Size.signature.contains(assertion.signature.count),
              assertion.userHandle.map({ Size.userHandle.contains($0.count) }) ?? true,
              let clientData = try? JSONDecoder().decode(ClientData.self, from: assertion.clientDataJSON),
              clientData.type == "webauthn.get", clientData.crossOrigin != true, clientData.topOrigin == nil,
              Base64URL.decode(clientData.challenge, size: Size.challenge) == challenge,
              HTTPSOrigin(serialized: clientData.origin) == expectedOrigin else {
            throw WebAuthnSecondFactorError.invalidAssertion
        }
    }

    private struct ClientData: Decodable {
        let type: String
        let challenge: String
        let origin: String
        let crossOrigin: Bool?
        let topOrigin: String?
    }

    private struct WireAssertion: Codable {
        struct Response: Codable {
            let authenticatorData: String
            let clientDataJson: String
            let signature: String
            let userHandle: String?
        }

        let id: String
        let rawId: String
        let type: String
        let extensions: [String: Bool]
        let response: Response
    }

    private enum Size {
        static let challenge = 16...1_024
        static let credentialID = 1...1_023
        static let authenticatorData = 37...16_384 // RP ID hash, flags, counter, optional extensions
        static let clientDataJSON = 1...16_384
        static let signature = 1...8_192
        static let userHandle = 1...64
        static let token = 65_536
    }
}

/// The raw fields returned by the operating system's security-key assertion.
public struct WebAuthnSecondFactorAssertion: Sendable, Equatable {
    public let credentialID: Data
    public let authenticatorData: Data
    public let clientDataJSON: Data
    public let signature: Data
    public let userHandle: Data?

    public init(credentialID: Data, authenticatorData: Data, clientDataJSON: Data,
                signature: Data, userHandle: Data? = nil) {
        self.credentialID = credentialID
        self.authenticatorData = authenticatorData
        self.clientDataJSON = clientDataJSON
        self.signature = signature
        self.userHandle = userHandle
    }
}

private struct HTTPSOrigin: Equatable {
    let host: String
    let port: Int

    init?(url: URL) {
        self.init(url: url, originOnly: false)
    }

    init?(serialized: String) {
        guard serialized.utf8.count <= 267,
              let url = URL(string: serialized, encodingInvalidCharacters: false) else { return nil }
        self.init(url: url, originOnly: true)
    }

    private init?(url: URL, originOnly: Bool) {
        guard url.baseURL == nil, url.absoluteString.prefix(8).lowercased() == "https://",
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              components.user == nil, components.password == nil,
              components.query == nil, components.fragment == nil,
              !originOnly || components.percentEncodedPath.isEmpty,
              let encodedHost = components.encodedHost, let host = Self.dnsHost(encodedHost) else { return nil }
        let port = components.port ?? 443
        let authority = url.absoluteString.dropFirst(8).prefix(while: { $0 != "/" }).lowercased()
        guard (1...65_535).contains(port), authority == host || authority == "\(host):\(port)" else { return nil }
        self.host = host
        self.port = port
    }

    static func dnsHost(_ host: String) -> String? {
        guard (1...253).contains(host.utf8.count) else { return nil }
        let labels = host.split(separator: ".", omittingEmptySubsequences: false)
        // Associated domains use DNS names (ASCII/IDNA A-labels), not IP addresses.
        guard labels.count >= 2, labels.last?.utf8.contains(where: isLetter) == true,
              labels.allSatisfy({ label in
                  (1...63).contains(label.utf8.count) && label.first != "-" && label.last != "-"
                      && label.utf8.allSatisfy { isLetter($0) || (48...57).contains($0) || $0 == 45 }
              }) else { return nil }
        return host.lowercased()
    }

    private static func isLetter(_ byte: UInt8) -> Bool {
        (65...90).contains(byte) || (97...122).contains(byte)
    }
}

private enum Base64URL {
    static func encode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    static func decode(_ value: String, size: ClosedRange<Int>) -> Data? {
        let count = value.utf8.count
        guard (1...(size.upperBound * 4 + 2) / 3).contains(count), count % 4 != 1,
              value.utf8.allSatisfy({ byte in
                  switch byte {
                  case 45, 48...57, 65...90, 95, 97...122: true
                  default: false
                  }
              }) else { return nil }
        let base64 = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        let padded = base64 + String(repeating: "=", count: (4 - count % 4) % 4)
        guard let decoded = Data(base64Encoded: padded), size.contains(decoded.count),
              encode(decoded) == value else { return nil }
        return decoded
    }
}
