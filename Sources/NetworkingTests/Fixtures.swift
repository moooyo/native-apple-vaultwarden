import Foundation
import CryptoCore
import AppShared
import Networking

/// Synthetic JSON fixtures + shared helpers for the Networking checks.
enum Fixtures {
    /// A valid type-2 (AES-CBC-256 + HMAC-SHA256) EncString wire string.
    static func validEnc(seed: UInt8 = 0) -> String {
        let iv = Data((0..<16).map { UInt8(($0 &+ Int(seed)) & 0xff) })
        let ct = Data((16..<48).map { UInt8(($0 &+ Int(seed)) & 0xff) })
        let mac = Data((48..<80).map { UInt8(($0 &+ Int(seed)) & 0xff) })
        return EncString(type: .aesCbc256_HmacSha256_B64, iv: iv, ciphertext: ct, mac: mac).stringValue
    }

    static func enc(seed: UInt8 = 0) -> EncString {
        try! EncString(parsing: validEnc(seed: seed))
    }

    static let device = DeviceMetadata(type: DeviceMetadata.DeviceType.iOS,
                                       identifier: "DEV-IDENT-UUID",
                                       name: "Test iPhone")

    static let clientVersion = "2024.10.0"

    static func environment() -> ServerEnvironment {
        ServerEnvironment(string: "https://vault.example.test")!
    }

    /// Builds an `APIClient` wired to a stubbed session for `box`.
    static func client(box: StubBox) -> APIClient {
        APIClient(environment: environment(),
                  session: makeStubbedSession(box: box),
                  device: device,
                  clientVersion: clientVersion)
    }

    // MARK: JSON fixtures

    static let prelogin = """
    {"kdf":0,"kdfIterations":600000,"kdfMemory":null,"kdfParallelism":null}
    """

    static func token() -> String {
        """
        {"access_token":"AT-123","expires_in":3600,"refresh_token":"RT-456",
         "token_type":"Bearer","Key":"\(validEnc(seed: 1))","PrivateKey":"\(validEnc(seed: 2))",
         "Kdf":0,"KdfIterations":600000}
        """
    }

    /// A 2FA-challenge 400 body with `TwoFactorProviders2` (Authenticator + Email).
    static let twoFactorChallenge = """
    {"error":"invalid_grant","error_description":"Two factor required.",
     "TwoFactorProviders":["0","1"],
     "TwoFactorProviders2":{"0":{},"1":{"Email":"j***@example.test"}}}
    """

    /// A plain bad-credentials 400 (no 2FA fields).
    static let badCredentials = """
    {"error":"invalid_grant","error_description":"username or password is incorrect"}
    """

    static func sync() -> String {
        """
        {"profile":{"id":"user-1","email":"throwaway@example.test","name":"Test User",
          "key":"\(validEnc(seed: 1))","privateKey":"\(validEnc(seed: 2))",
          "securityStamp":"stamp-1","organizations":[]},
         "folders":[{"id":"folder-1","name":"\(validEnc(seed: 5))","revisionDate":"2026-01-02T03:04:05.123Z"}],
         "ciphers":[{"id":"cipher-1","organizationId":null,"folderId":null,"type":1,
            "name":"\(validEnc(seed: 10))","notes":null,"favorite":false,"reprompt":0,
            "edit":true,"viewPassword":true,"login":null,"card":null,"identity":null,
            "secureNote":null,"sshKey":null,"fields":null,"attachments":null,
            "collectionIds":null,"key":null,"revisionDate":"2026-01-02T03:04:05.123Z",
            "creationDate":"2026-01-01T00:00:00.000Z","deletedDate":null}],
         "collections":[],"sends":[],"policies":[],"domains":null}
        """
    }

    static func cipher() -> String {
        """
        {"id":"cipher-99","organizationId":null,"folderId":null,"type":1,
         "name":"\(validEnc(seed: 10))","notes":null,"favorite":false,"reprompt":0,
         "edit":true,"viewPassword":true,"login":null,"card":null,"identity":null,
         "secureNote":null,"sshKey":null,"fields":null,"attachments":null,
         "collectionIds":null,"key":null,"revisionDate":"2026-01-02T03:04:05.123Z",
         "creationDate":"2026-01-01T00:00:00.000Z","deletedDate":null}
        """
    }

    static func folder() -> String {
        """
        {"id":"folder-99","name":"\(validEnc(seed: 5))","revisionDate":"2026-01-02T03:04:05.123Z"}
        """
    }

    static func folderListJSON() -> String {
        """
        {"object":"list","data":[
          {"id":"folder-1","name":"\(validEnc(seed: 5))","revisionDate":"2026-01-02T03:04:05.123Z"},
          {"id":"folder-2","name":"\(validEnc(seed: 6))","revisionDate":"2026-01-03T03:04:05.123Z"}
        ],"continuationToken":null}
        """
    }

    static func attachmentUpload() -> String {
        """
        {"attachmentId":"att-1","url":"https://vault.example.test/api/ciphers/cipher-1/attachment/att-1",
         "fileUploadType":0,"cipherResponse":null}
        """
    }

    static let config = """
    {"version":"1.32.0","gitHash":"abc1234","server":null,
     "environment":null,"push":{"pushTechnology":0},"featureStates":{}}
    """
}
