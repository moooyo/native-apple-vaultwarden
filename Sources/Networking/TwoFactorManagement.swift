import CryptoKit
import Foundation

/// A provider returned by the server's account-level two-step login list.
public struct TwoFactorMethodStatus: Decodable, Sendable, Equatable, Identifiable {
    public let type: Int
    public let enabled: Bool
    public var id: Int { type }
    public var provider: TwoFactorProvider? { TwoFactorProvider(rawValue: type) }
}

/// Vaultwarden's management ID, not a credential ID or an account passkey.
public struct TwoFactorSecurityKey: Decodable, Sendable, Equatable, Identifiable {
    public let id: Int32
    public let name: String
    public let migrated: Bool
}

package struct TwoFactorRequestContext: Sendable {
    package let accountID: String
    package let contextID: UUID

    package init(accountID: String, contextID: UUID) {
        self.accountID = accountID
        self.contextID = contextID
    }
}

package struct VerifiedTwoFactorAuthenticator: Decodable, Sendable {
    struct Authenticator: Decodable, Sendable {
        let enabled: Bool
        let key: String
    }

    let authenticator: Authenticator
    package let userVerificationToken: String
    package var enabled: Bool { authenticator.enabled }
    package var key: String { authenticator.key }

    private enum CodingKeys: String, CodingKey {
        case authenticator
        case userVerificationToken = "userverificationtoken"
    }
}

package struct VerifiedTwoFactorEmail: Decodable, Sendable {
    struct Email: Decodable, Sendable {
        let enabled: Bool
        let email: String?
    }

    let email: Email
    package let userVerificationToken: String
    package var enabled: Bool { email.enabled }
    package var address: String? { email.email }

    private enum CodingKeys: String, CodingKey {
        case email
        case userVerificationToken = "userverificationtoken"
    }
}

package struct VerifiedTwoFactorSecurityKeys: Decodable, Sendable {
    let webAuthn: TwoFactorKeyState
    package let userVerificationToken: String
    package var enabled: Bool { webAuthn.enabled }
    package var keys: [TwoFactorSecurityKey] { webAuthn.keys }

    private enum CodingKeys: String, CodingKey {
        case webAuthn = "webauthn"
        case userVerificationToken = "userverificationtoken"
    }
}

struct TwoFactorKeyState: Decodable, Sendable {
    let enabled: Bool
    let keys: [TwoFactorSecurityKey]

    var isConsistent: Bool {
        enabled == !keys.isEmpty && Set(keys.map(\.id)).count == keys.count
    }
}

/// The ES256-only native registration subset of Vaultwarden's password-grant second factor.
public struct TwoFactorSecurityKeyRegistrationChallenge: Sendable {
    public let relyingPartyIdentifier: String
    public let challenge: Data
    public let userID: Data
    public let userName: String
    public let displayName: String
    public let excludedCredentialIDs: [Data]
    public let timeoutMilliseconds: Int

    public static func relyingPartyIdentifier(for environment: ServerEnvironment) throws -> String {
        let host = try WebAuthnSecondFactorChallenge.relyingPartyIdentifier(for: environment)
        // The native request takes the RP ID, not a browser origin or port.
        guard environment.base.port == nil || environment.base.port == 443 else {
            throw WebAuthnSecondFactorError.unsupported
        }
        return host
    }

    fileprivate init(_ options: SecurityKeyCreationOptions, environment: ServerEnvironment, email: String,
                     existingKeyCount: Int) throws {
        let host = try Self.relyingPartyIdentifier(for: environment)
        let excluded = options.excludeCredentials ?? []
        guard options.status == "ok", options.errorMessage.isEmpty, options.rp.id == host,
              options.attestation == "none", options.attestationFormats == nil, options.extensions == nil,
              options.hints?.isEmpty != false,
              options.authenticatorSelection.authenticatorAttachment == nil ||
                options.authenticatorSelection.authenticatorAttachment == "cross-platform",
              options.authenticatorSelection.residentKey == "discouraged", !options.authenticatorSelection.requireResidentKey,
              options.authenticatorSelection.userVerification == "discouraged",
              (1...32).contains(options.pubKeyCredParams.count),
              options.pubKeyCredParams.contains(where: { $0.type == "public-key" && $0.alg == -7 }),
              (1...120_000).contains(options.timeout),
              options.user.name.caseInsensitiveCompare(email) == .orderedSame,
              Self.isDisplayText(options.user.name, limit: 254), Self.isDisplayText(options.user.displayName, limit: 512),
              let userID = RegistrationBase64URL.decode(options.user.id, size: 16...16),
              let challenge = RegistrationBase64URL.decode(options.challenge, size: 16...1_024),
              excluded.count == existingKeyCount, excluded.count <= 64 else {
            throw NetworkingError.decoding("Unsupported security key creation options")
        }
        let ids = excluded.compactMap { descriptor in
            descriptor.type == "public-key" ? RegistrationBase64URL.decode(descriptor.id, size: 1...1_023) : nil
        }
        guard ids.count == excluded.count, Set(ids).count == ids.count else {
            throw NetworkingError.decoding("Invalid security key exclusion list")
        }
        self.relyingPartyIdentifier = host
        self.challenge = challenge
        self.userID = userID
        self.userName = options.user.name
        self.displayName = options.user.displayName
        self.excludedCredentialIDs = ids
        self.timeoutMilliseconds = options.timeout
    }

    package func validate(_ attestation: TwoFactorSecurityKeyAttestation) throws {
        guard (1...1_023).contains(attestation.credentialID.count),
              !excludedCredentialIDs.contains(attestation.credentialID),
              (1...16_384).contains(attestation.clientDataJSON.count),
              (1...32_768).contains(attestation.attestationObject.count),
              let client = try? JSONDecoder().decode(RegistrationClientData.self, from: attestation.clientDataJSON),
              client.type == "webauthn.create", client.crossOrigin != true, client.topOrigin == nil,
              client.origin == "https://\(relyingPartyIdentifier)",
              RegistrationBase64URL.decode(client.challenge, size: 16...1_024) == challenge else {
            throw WebAuthnSecondFactorError.invalidAssertion
        }
        // CBOR is bounded before reading it. WebAuthn attestation was requested as none;
        // the credential must still prove presence and carry an ES256 P-256 public key.
        var object = RegistrationCBOR(attestation.attestationObject)
        guard object.length(major: 5, max: 3) == 3 else { throw WebAuthnSecondFactorError.invalidAssertion }
        var fields: Set<String> = []
        var authenticatorData: Data?
        for _ in 0..<3 {
            guard let field = object.text(max: 8), fields.insert(field).inserted else {
                throw WebAuthnSecondFactorError.invalidAssertion
            }
            switch field {
            case "fmt": guard object.text(max: 4) == "none" else { throw WebAuthnSecondFactorError.invalidAssertion }
            case "attStmt": guard object.length(major: 5, max: 0) == 0 else { throw WebAuthnSecondFactorError.invalidAssertion }
            case "authData": authenticatorData = object.bytes(max: 4_096)
            default: throw WebAuthnSecondFactorError.invalidAssertion
            }
        }
        guard object.atEnd, let authenticatorData, authenticatorData.count >= 56,
              authenticatorData.prefix(32) == Data(SHA256.hash(data: Data(relyingPartyIdentifier.utf8))),
              // Require user presence and attested credential data, without extension or backup bits.
              authenticatorData[32] & 0xfb == 0x41 else { throw WebAuthnSecondFactorError.invalidAssertion }
        // 32-byte RP hash, flags, counter, 16-byte AAGUID, and 2-byte credential ID length.
        let idLength = Int(authenticatorData[53]) * 256 + Int(authenticatorData[54])
        let idEnd = 55 + idLength
        guard idLength == attestation.credentialID.count, idEnd < authenticatorData.count,
              authenticatorData[55..<idEnd] == attestation.credentialID else {
            throw WebAuthnSecondFactorError.invalidAssertion
        }
        var cose = RegistrationCBOR(Data(authenticatorData.dropFirst(idEnd)))
        guard cose.length(major: 5, max: 5) == 5 else { throw WebAuthnSecondFactorError.invalidAssertion }
        var parameters: Set<Int> = []
        var x: Data?
        var y: Data?
        for _ in 0..<5 {
            guard let key = cose.integer(), parameters.insert(key).inserted else {
                throw WebAuthnSecondFactorError.invalidAssertion
            }
            switch key {
            case 1: guard cose.integer() == 2 else { throw WebAuthnSecondFactorError.invalidAssertion }
            case 3: guard cose.integer() == -7 else { throw WebAuthnSecondFactorError.invalidAssertion }
            case -1: guard cose.integer() == 1 else { throw WebAuthnSecondFactorError.invalidAssertion }
            case -2: x = cose.bytes(max: 32)
            case -3: y = cose.bytes(max: 32)
            default: throw WebAuthnSecondFactorError.invalidAssertion
            }
        }
        guard cose.atEnd, let x, x.count == 32, let y, y.count == 32,
              (try? P256.Signing.PublicKey(x963Representation: Data([4]) + x + y)) != nil else {
            throw WebAuthnSecondFactorError.invalidAssertion
        }
    }

    fileprivate func deviceResponse(for attestation: TwoFactorSecurityKeyAttestation) throws -> SecurityKeyEnrollment.Credential {
        try validate(attestation)
        let id = RegistrationBase64URL.encode(attestation.credentialID)
        return .init(id: id, rawId: id, response: .init(attestationObject: RegistrationBase64URL.encode(attestation.attestationObject),
                                                     clientDataJson: RegistrationBase64URL.encode(attestation.clientDataJSON)))
    }

    private static func isDisplayText(_ text: String, limit: Int) -> Bool {
        (1...limit).contains(text.utf8.count) && text.rangeOfCharacter(from: .controlCharacters) == nil
    }
}

/// The unmodified credential fields returned by AuthenticationServices, not a private key.
public struct TwoFactorSecurityKeyAttestation: Sendable {
    let credentialID: Data
    let clientDataJSON: Data
    let attestationObject: Data

    public init(credentialID: Data, clientDataJSON: Data, attestationObject: Data) {
        self.credentialID = credentialID
        self.clientDataJSON = clientDataJSON
        self.attestationObject = attestationObject
    }
}

private struct TwoFactorMethodList: Decodable, Sendable {
    let object: String
    let data: [TwoFactorMethodStatus]
    let continuationToken: String?

    private enum CodingKeys: String, CodingKey {
        case object, data
        case continuationToken = "continuationtoken"
    }
}

private struct TwoFactorPasswordProof: Encodable {
    let masterPasswordHash: String
}

private struct TwoFactorVerification: Encodable {
    let userVerificationToken: String
}

private struct TwoFactorAuthenticatorActivation: Encodable {
    let key: String
    let token: String
    let userVerificationToken: String
}

private struct TwoFactorAuthenticatorRemoval: Encodable {
    let key: String
    let userVerificationToken: String
}

private struct TwoFactorEmailSend: Encodable {
    let email: String
    let userVerificationToken: String
}

private struct TwoFactorEmailActivation: Encodable {
    let email: String
    let token: String
    let userVerificationToken: String
}

private struct TwoFactorKeyRemoval: Encodable {
    let id: Int32
    let userVerificationToken: String
}

private struct RegistrationClientData: Decodable {
    let type: String
    let challenge: String
    let origin: String
    let crossOrigin: Bool?
    let topOrigin: String?
}

private enum RegistrationBase64URL {
    static func encode(_ bytes: Data) -> String {
        bytes.base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    static func decode(_ text: String, size: ClosedRange<Int>) -> Data? {
        let count = text.utf8.count
        guard (1...(size.upperBound * 4 + 2) / 3).contains(count), count % 4 != 1,
              text.utf8.allSatisfy({ byte in
                  switch byte {
                  case 45, 48...57, 65...90, 95, 97...122: true
                  default: false
                  }
              }) else { return nil }
        let encoded = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
            + String(repeating: "=", count: (4 - count % 4) % 4)
        guard let data = Data(base64Encoded: encoded), size.contains(data.count), encode(data) == text else { return nil }
        return data
    }
}

/// Reads only the definite-length, bounded primitives used by a none-attested ES256 key.
private struct RegistrationCBOR {
    private let data: Data
    private var index = 0
    var atEnd: Bool { index == data.count }

    init(_ data: Data) { self.data = Data(data) }

    mutating func length(major: UInt8, max: Int) -> Int? {
        guard let type = readByte(), type >> 5 == major else { return nil }
        return argument(type & 31, max: max)
    }

    mutating func integer() -> Int? {
        guard let type = readByte(), type >> 5 <= 1, let value = argument(type & 31, max: 7) else { return nil }
        return type >> 5 == 0 ? value : -1 - value
    }

    mutating func bytes(max: Int) -> Data? { item(major: 2, max: max) }
    mutating func text(max: Int) -> String? { item(major: 3, max: max).flatMap { String(data: $0, encoding: .utf8) } }

    private mutating func item(major: UInt8, max: Int) -> Data? {
        guard let count = length(major: major, max: max), count <= data.count - index else { return nil }
        defer { index += count }
        return data.subdata(in: index..<(index + count))
    }

    private mutating func readByte() -> UInt8? {
        guard !atEnd else { return nil }
        defer { index += 1 }
        return data[index]
    }

    private mutating func argument(_ extra: UInt8, max: Int) -> Int? {
        let value: Int
        switch extra {
        case 0...23: value = Int(extra)
        case 24: guard let byte = readByte(), byte >= 24 else { return nil }; value = Int(byte)
        case 25:
            guard let high = readByte(), high > 0, let low = readByte() else { return nil }
            value = Int(high) * 256 + Int(low)
        default: return nil
        }
        return value <= max ? value : nil
    }
}

private struct SecurityKeyCreationOptions: Decodable, Sendable {
    struct RP: Decodable, Sendable { let id: String }
    struct User: Decodable, Sendable {
        let id: String
        let name: String
        let displayName: String
        private enum CodingKeys: String, CodingKey { case id, name; case displayName = "displayname" }
    }
    struct Parameter: Decodable, Sendable { let type: String; let alg: Int }
    struct Descriptor: Decodable, Sendable { let type: String; let id: String }
    struct Selection: Decodable, Sendable {
        let authenticatorAttachment: String?
        let residentKey: String
        let requireResidentKey: Bool
        let userVerification: String
        private enum CodingKeys: String, CodingKey {
            case authenticatorAttachment = "authenticatorattachment", residentKey = "residentkey"
            case requireResidentKey = "requireresidentkey", userVerification = "userverification"
        }
    }
    // Extensions are intentionally absent. Decoding an object rather than null as this
    // placeholder fails closed instead of ignoring requirements the native API cannot meet.
    let extensions: Bool?
    let attestationFormats: [String]?
    let hints: [String]?
    let rp: RP
    let user: User
    let challenge: String
    let timeout: Int
    let attestation: String
    let status: String
    let errorMessage: String
    let authenticatorSelection: Selection
    let excludeCredentials: [Descriptor]?
    let pubKeyCredParams: [Parameter]

    private enum CodingKeys: String, CodingKey {
        case extensions, hints, rp, user, challenge, timeout, attestation, status
        case attestationFormats = "attestationformats", errorMessage = "errormessage"
        case authenticatorSelection = "authenticatorselection", excludeCredentials = "excludecredentials"
        case pubKeyCredParams = "pubkeycredparams"
    }
}

private struct SecurityKeyCreationResponse: Decodable, Sendable { let options: SecurityKeyCreationOptions }

private struct SecurityKeyEnrollment: Encodable {
    struct Credential: Encodable {
        struct Response: Encodable {
            let attestationObject: String
            let clientDataJson: String
        }
        let id: String
        let rawId: String
        let type = "public-key"
        let response: Response
    }
    let id: Int32
    let name: String
    let deviceResponse: Credential
    let userVerificationToken: String
}

private struct TwoFactorAuthenticatorResult: Decodable, Sendable {
    let authenticator: VerifiedTwoFactorAuthenticator.Authenticator
}

private struct TwoFactorKeysResult: Decodable, Sendable {
    let webAuthn: TwoFactorKeyState

    private enum CodingKeys: String, CodingKey { case webAuthn = "webauthn" }
}

private struct TwoFactorRecoveryResult: Decodable, Sendable {
    let code: String?
    let object: String

    private enum CodingKeys: String, CodingKey { case code, object }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        code = try container.decode(String?.self, forKey: .code)
        object = try container.decode(String.self, forKey: .object)
    }
}

// Vaultwarden 1.37.5's nested provider-specific state and short-lived verification-token
// protocol. Do not fall back to legacy disable or registration endpoints.
extension APIClient {
    package func listTwoFactorMethods(_ context: TwoFactorRequestContext) async throws -> [TwoFactorMethodStatus] {
        let result: TwoFactorMethodList = try await twoFactorJSON(context, "GET", [])
        guard result.object == "list", result.continuationToken == nil,
              Set(result.data.map(\.type)).count == result.data.count else {
            throw Self.invalidTwoFactorResponse
        }
        return result.data
    }

    package func getTwoFactorAuthenticator(_ context: TwoFactorRequestContext, proof: String) async throws
        -> VerifiedTwoFactorAuthenticator {
        let result: VerifiedTwoFactorAuthenticator = try await twoFactorJSON(
            context, "POST", ["get-authenticator"], body: TwoFactorPasswordProof(masterPasswordHash: proof)
        )
        guard Self.isTwoFactorSecret(result.key), !result.userVerificationToken.isEmpty else {
            throw Self.invalidTwoFactorResponse
        }
        return result
    }

    package func enableTwoFactorAuthenticator(_ context: TwoFactorRequestContext, key: String, code: String,
                                               verificationToken: String) async throws {
        let result: TwoFactorAuthenticatorResult = try await twoFactorJSON(
            context, "PUT", ["authenticator"],
            body: TwoFactorAuthenticatorActivation(key: key, token: code, userVerificationToken: verificationToken)
        )
        guard result.authenticator.enabled, result.authenticator.key == key else { throw Self.invalidTwoFactorResponse }
    }

    package func removeTwoFactorAuthenticator(_ context: TwoFactorRequestContext,
                                               verified: VerifiedTwoFactorAuthenticator) async throws {
        try await twoFactorEmpty(context, "DELETE", ["authenticator"], body: TwoFactorAuthenticatorRemoval(
            key: verified.key, userVerificationToken: verified.userVerificationToken
        ))
    }

    package func getTwoFactorEmail(_ context: TwoFactorRequestContext, proof: String) async throws -> VerifiedTwoFactorEmail {
        let result: VerifiedTwoFactorEmail = try await twoFactorJSON(
            context, "POST", ["get-email"], body: TwoFactorPasswordProof(masterPasswordHash: proof)
        )
        guard !result.userVerificationToken.isEmpty,
              result.enabled ? result.address?.isEmpty == false : result.address == nil else {
            throw Self.invalidTwoFactorResponse
        }
        return result
    }

    package func sendTwoFactorSetupEmail(_ context: TwoFactorRequestContext, address: String,
                                         verified: VerifiedTwoFactorEmail) async throws {
        let result: [String: String] = try await twoFactorJSON(
            context, "POST", ["send-email"],
            body: TwoFactorEmailSend(email: address, userVerificationToken: verified.userVerificationToken)
        )
        guard result.isEmpty else { throw Self.invalidTwoFactorResponse }
    }

    package func enableTwoFactorEmail(_ context: TwoFactorRequestContext, address: String, code: String,
                                      verified: VerifiedTwoFactorEmail) async throws {
        let result: [String: String] = try await twoFactorJSON(
            context, "PUT", ["email"],
            body: TwoFactorEmailActivation(email: address, token: code, userVerificationToken: verified.userVerificationToken)
        )
        guard result.isEmpty else { throw Self.invalidTwoFactorResponse }
    }

    package func removeTwoFactorEmail(_ context: TwoFactorRequestContext, verified: VerifiedTwoFactorEmail) async throws {
        try await twoFactorEmpty(context, "DELETE", ["email"], body: TwoFactorVerification(
            userVerificationToken: verified.userVerificationToken
        ))
    }

    package func getTwoFactorSecurityKeys(_ context: TwoFactorRequestContext, proof: String) async throws
        -> VerifiedTwoFactorSecurityKeys {
        let result: VerifiedTwoFactorSecurityKeys = try await twoFactorJSON(
            context, "POST", ["get-webauthn"], body: TwoFactorPasswordProof(masterPasswordHash: proof)
        )
        guard !result.userVerificationToken.isEmpty, result.webAuthn.isConsistent else { throw Self.invalidTwoFactorResponse }
        return result
    }

    package func removeTwoFactorSecurityKey(_ context: TwoFactorRequestContext, id: Int32,
                                             verified: VerifiedTwoFactorSecurityKeys) async throws -> [TwoFactorSecurityKey] {
        let result: TwoFactorKeysResult = try await twoFactorJSON(
            context, "DELETE", ["webauthn"],
            body: TwoFactorKeyRemoval(id: id, userVerificationToken: verified.userVerificationToken)
        )
        guard result.webAuthn.isConsistent, !result.webAuthn.keys.contains(where: { $0.id == id }) else {
            throw Self.invalidTwoFactorResponse
        }
        return result.webAuthn.keys
    }

    package func getTwoFactorSecurityKeyChallenge(_ context: TwoFactorRequestContext, environment: ServerEnvironment,
                                                 email: String, verified: VerifiedTwoFactorSecurityKeys) async throws
        -> TwoFactorSecurityKeyRegistrationChallenge {
        let result: SecurityKeyCreationResponse = try await twoFactorJSON(
            context, "POST", ["get-webauthn-challenge"],
            body: TwoFactorVerification(userVerificationToken: verified.userVerificationToken)
        )
        return try TwoFactorSecurityKeyRegistrationChallenge(result.options, environment: environment, email: email,
                                                             existingKeyCount: verified.keys.count)
    }

    package func registerTwoFactorSecurityKey(_ context: TwoFactorRequestContext, id: Int32, name: String,
                                              challenge: TwoFactorSecurityKeyRegistrationChallenge,
                                              attestation: TwoFactorSecurityKeyAttestation,
                                              verified: VerifiedTwoFactorSecurityKeys) async throws -> [TwoFactorSecurityKey] {
        let credential = try challenge.deviceResponse(for: attestation)
        let result: TwoFactorKeysResult = try await twoFactorJSON(
            context, "PUT", ["webauthn"], body: SecurityKeyEnrollment(
                id: id, name: name, deviceResponse: credential, userVerificationToken: verified.userVerificationToken
            )
        )
        guard result.webAuthn.isConsistent, result.webAuthn.enabled,
              let added = result.webAuthn.keys.first(where: { $0.id == id }), added.name == name, !added.migrated,
              Set(result.webAuthn.keys.map(\.id)) == Set(verified.keys.map(\.id) + [id]) else {
            throw Self.invalidTwoFactorResponse
        }
        return result.webAuthn.keys
    }

    package func getTwoFactorRecoveryCode(_ context: TwoFactorRequestContext, proof: String) async throws -> String? {
        let result: TwoFactorRecoveryResult = try await twoFactorJSON(
            context, "POST", ["get-recover"], body: TwoFactorPasswordProof(masterPasswordHash: proof)
        )
        guard result.object == "twoFactorRecover", result.code.map(Self.isTwoFactorSecret) != false else {
            throw Self.invalidTwoFactorResponse
        }
        return result.code
    }

    private func twoFactorJSON<Response: Decodable & Sendable>(_ context: TwoFactorRequestContext, _ method: String,
                                                              _ path: [String], body: (any Encodable)? = nil) async throws
        -> Response {
        try await authenticatedJSON(accountID: context.accountID, contextID: context.contextID, method: method,
                                    path: ["two-factor"] + path, body: try body.map { try JSONEncoder().encode($0) })
    }

    private func twoFactorEmpty(_ context: TwoFactorRequestContext, _ method: String,
                                _ path: [String], body: any Encodable) async throws {
        try await authenticatedEmpty(accountID: context.accountID, contextID: context.contextID, method: method,
                                     path: ["two-factor"] + path, body: try JSONEncoder().encode(body))
    }

    private static let invalidTwoFactorResponse = NetworkingError.decoding("Unexpected two-step login response")

    private static func isTwoFactorSecret(_ value: String) -> Bool {
        value.utf8.count == 32 && value.utf8.allSatisfy { (65...90).contains($0) || (50...55).contains($0) }
    }
}
