import CryptoCore
import Foundation

public enum DeviceLoginError: Error, Equatable, Sendable {
    case invalidEmail
    case invalidDeviceIdentifier
    case invalidPublicKey
    case invalidWrappedKey
    case invalidResponse
    /// Vaultwarden does not distinguish rejection, expiration, and a failed IP/device/code check here.
    case requestUnavailable
}

/// A one-attempt credential. The owned random bytes are wiped on release; only the transport
/// can derive the transient string required by Vaultwarden. Do not persist it or log requests.
public struct DeviceLoginAccessCode: Sendable, CustomStringConvertible, CustomReflectable {
    private let bytes: SecureBytes

    public static func generate() throws -> Self {
        var random = try SecureRandom.bytes(32)
        defer { random.withUnsafeMutableBytes(SecureBytes.erase) }
        let bytes = SecureBytes(count: random.count)
        bytes.withUnsafeMutableBytes { target in random.withUnsafeBytes { target.copyMemory(from: $0) } }
        return Self(bytes: bytes)
    }

    package var wireValue: String {
        bytes.withUnsafeBytes { source in
            let borrowed = Data(bytesNoCopy: UnsafeMutableRawPointer(mutating: source.baseAddress!),
                                count: source.count, deallocator: .none)
            return DeviceLoginWire.base64URL(borrowed)
        }
    }

    public var description: String { "DeviceLoginAccessCode(redacted)" }
    public var customMirror: Mirror { Mirror(self, children: [:]) }
}

/// The device approval protocol uses the request ID, not a caller-supplied path or URL.
/// `origin` is informational: the caller must keep using the originally selected server.
public struct DeviceLoginRequest: Decodable, Equatable, Identifiable, Sendable, CustomStringConvertible, CustomReflectable {
    public let id: UUID
    public let publicKey: String
    public let requestDeviceType: String
    public let requestIPAddress: String
    public let creationDate: Date
    public let responseDate: Date?
    public let requestApproved: Bool?
    public let key: EncString?
    /// Legacy responses can include a wrapped master-password hash. Such responses are not a user-key grant.
    public let masterPasswordHash: String?
    public let origin: String

    public var isPending: Bool { requestApproved != true && responseDate == nil }
    public var description: String { "DeviceLoginRequest(redacted)" }
    public var customMirror: Mirror { Mirror(self, children: [:]) }

    private enum CodingKeys: String, CodingKey {
        case id, key, origin, object
        case publicKey = "publickey"
        case requestDeviceType = "requestdevicetype"
        case requestIPAddress = "requestipaddress"
        case creationDate = "creationdate"
        case responseDate = "responsedate"
        case requestApproved = "requestapproved"
        case masterPasswordHash = "masterpasswordhash"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let id = try container.decode(String.self, forKey: .id)
        guard try container.decode(String.self, forKey: .object) == "auth-request",
              id.utf8.count == 36, let uuid = UUID(uuidString: id) else { throw DeviceLoginError.invalidResponse }
        self.id = uuid
        publicKey = try container.decode(String.self, forKey: .publicKey)
        requestDeviceType = try container.decode(String.self, forKey: .requestDeviceType)
        requestIPAddress = try container.decode(String.self, forKey: .requestIPAddress)
        origin = try container.decode(String.self, forKey: .origin)
        creationDate = try container.decode(Date.self, forKey: .creationDate)
        responseDate = try container.decodeIfPresent(Date.self, forKey: .responseDate)
        requestApproved = try container.decodeIfPresent(Bool.self, forKey: .requestApproved)
        masterPasswordHash = try container.decodeIfPresent(String.self, forKey: .masterPasswordHash)
        let wrappedKey = try container.decodeIfPresent(String.self, forKey: .key)
        guard DeviceLoginWire.publicKeyBytes(publicKey) != nil,
              DeviceLoginWire.isDisplayText(requestDeviceType, maxBytes: 64),
              DeviceLoginWire.isDisplayText(requestIPAddress, maxBytes: 64),
              DeviceLoginWire.isDisplayText(origin, maxBytes: 2_048),
              masterPasswordHash.map({ DeviceLoginWire.isDisplayText($0, maxBytes: 1_024) }) ?? true else {
            throw DeviceLoginError.invalidResponse
        }
        if requestApproved == true {
            guard responseDate != nil, let wrappedKey, wrappedKey.utf8.count == 346,
                  let parsed = try? EncString(parsing: wrappedKey), DeviceLoginWire.isWrappedKey(parsed),
                  parsed.stringValue == wrappedKey else { throw DeviceLoginError.invalidResponse }
            key = parsed
        } else {
            guard wrappedKey == nil, masterPasswordHash == nil else { throw DeviceLoginError.invalidResponse }
            key = nil
        }
    }
}

public enum DeviceLoginDecision: Sendable {
    case approve(EncString)
    case deny
}

private struct DeviceLoginCreateBody: Encodable {
    let email: String
    let deviceIdentifier: String
    let publicKey: String
    let accessCode: String
}

private struct DeviceLoginResponseBody: Encodable {
    let deviceIdentifier: String
    let key: String
    let requestApproved: Bool
}

private struct DeviceLoginPendingList: Decodable, Sendable {
    let object: String
    let data: [DeviceLoginRequest]
    let continuationToken: String?

    private enum CodingKeys: String, CodingKey {
        case object, data
        case continuationToken = "continuationtoken"
    }
}

package enum DeviceLoginWire {
    package static func normalizedEmail(_ value: String) throws -> String {
        let email = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let parts = email.split(separator: "@", maxSplits: 2, omittingEmptySubsequences: false)
        guard (1...254).contains(email.utf8.count), parts.count == 2, parts.allSatisfy({ !$0.isEmpty }),
              !email.unicodeScalars.contains(where: CharacterSet.whitespacesAndNewlines.union(.controlCharacters).contains) else {
            throw DeviceLoginError.invalidEmail
        }
        return email
    }

    fileprivate static func base64URL(_ bytes: Data) -> String {
        bytes.base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    fileprivate static func isDisplayText(_ value: String, maxBytes: Int) -> Bool {
        (1...maxBytes).contains(value.utf8.count) &&
            !value.unicodeScalars.contains(where: CharacterSet.controlCharacters.union(.newlines).contains)
    }

    package static func publicKeyBytes(_ value: String) -> Data? {
        guard (1...1_024).contains(value.utf8.count), let bytes = Data(base64Encoded: value),
              bytes.base64EncodedString() == value else { return nil }
        return bytes
    }

    package static func isWrappedKey(_ key: EncString) -> Bool {
        key.type == .rsa2048_OaepSha1_B64 && key.ciphertext.count == 256 && key.iv == nil && key.mac == nil
    }

    fileprivate static func path(_ id: UUID) -> [String] { ["auth-requests", id.uuidString.lowercased()] }
}

extension APIClient {
    /// This checks the persisted identifier, not the device type; creation checks both on Vaultwarden.
    public func isKnownDeviceForLogin(email: String, server: ServerEnvironment) async throws -> Bool {
        let email = try DeviceLoginWire.normalizedEmail(email)
        let identifier = try validatedDeviceLoginIdentifier()
        return try await anonymousJSON(server: server, method: "GET", path: ["devices", "knowndevice"],
                                       headers: ["X-Request-Email": DeviceLoginWire.base64URL(Data(email.utf8)),
                                                 "X-Device-Identifier": identifier])
    }

    public func createDeviceLoginRequest(email: String, accessCode: DeviceLoginAccessCode, publicKey: String,
                                         server: ServerEnvironment) async throws -> DeviceLoginRequest {
        let email = try DeviceLoginWire.normalizedEmail(email)
        let identifier = try validatedDeviceLoginIdentifier()
        guard DeviceLoginWire.publicKeyBytes(publicKey) != nil else { throw DeviceLoginError.invalidPublicKey }
        let body = try JSONEncoder().encode(DeviceLoginCreateBody(email: email, deviceIdentifier: identifier,
                                                                  publicKey: publicKey, accessCode: accessCode.wireValue))
        let request: DeviceLoginRequest = try await anonymousJSON(server: server, method: "POST", path: ["auth-requests"], body: body)
        guard request.publicKey == publicKey, request.isPending else { throw DeviceLoginError.invalidResponse }
        return request
    }

    public func pollDeviceLoginRequest(id: UUID, accessCode: DeviceLoginAccessCode,
                                       server: ServerEnvironment) async throws -> DeviceLoginRequest {
        let response: DeviceLoginRequest
        do {
            response = try await anonymousJSON(server: server, method: "GET", path: DeviceLoginWire.path(id) + ["response"],
                                               query: [URLQueryItem(name: "code", value: accessCode.wireValue)])
        } catch NetworkingError.http(let status, _) where status == 400 || status == 404 {
            throw DeviceLoginError.requestUnavailable
        }
        guard response.id == id else { throw DeviceLoginError.invalidResponse }
        return response
    }

    public func pendingDeviceLoginRequests(accountID: String, contextID: UUID) async throws -> [DeviceLoginRequest] {
        let response: DeviceLoginPendingList = try await authenticatedJSON(accountID: accountID, contextID: contextID,
                                                                           method: "GET", path: ["auth-requests", "pending"])
        guard response.object == "list", response.continuationToken == nil, response.data.count <= 128,
              response.data.allSatisfy(\.isPending), Set(response.data.map(\.id)).count == response.data.count else {
            throw DeviceLoginError.invalidResponse
        }
        return response.data
    }

    public func deviceLoginRequest(id: UUID, accountID: String, contextID: UUID) async throws -> DeviceLoginRequest {
        let response: DeviceLoginRequest = try await authenticatedJSON(accountID: accountID, contextID: contextID,
                                                                      method: "GET", path: DeviceLoginWire.path(id))
        guard response.id == id else { throw DeviceLoginError.invalidResponse }
        return response
    }

    @discardableResult
    public func respondToDeviceLoginRequest(id: UUID, accountID: String, contextID: UUID,
                                           decision: DeviceLoginDecision) async throws -> DeviceLoginRequest {
        let identifier = try validatedDeviceLoginIdentifier()
        let wrapped: EncString?
        switch decision {
        case .approve(let key):
            guard DeviceLoginWire.isWrappedKey(key) else { throw DeviceLoginError.invalidWrappedKey }
            wrapped = key
        case .deny:
            wrapped = nil
        }
        // Vaultwarden requires a string key even for a denial, which deletes the record.
        let body = try JSONEncoder().encode(DeviceLoginResponseBody(deviceIdentifier: identifier,
                                                                    key: wrapped?.stringValue ?? "",
                                                                    requestApproved: wrapped != nil))
        let response: DeviceLoginRequest = try await authenticatedJSON(accountID: accountID, contextID: contextID,
                                                                      method: "PUT", path: DeviceLoginWire.path(id), body: body)
        guard response.id == id, response.responseDate != nil, (response.requestApproved == true) == (wrapped != nil),
              response.key == wrapped, response.masterPasswordHash == nil else { throw DeviceLoginError.invalidResponse }
        return response
    }

    private func validatedDeviceLoginIdentifier() throws -> String {
        let identifier = deviceIdentifier
        // Preserve the registered value and casing. Vaultwarden uses CHAR(36) for this on MySQL.
        guard (1...36).contains(identifier.utf8.count), identifier.utf8.allSatisfy({
            (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 45 || $0 == 95
        }) else { throw DeviceLoginError.invalidDeviceIdentifier }
        return identifier
    }
}
