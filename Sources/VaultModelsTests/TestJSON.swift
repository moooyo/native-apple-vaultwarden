import Foundation
import CryptoCore

/// Synthetic JSON fixtures used by the VaultModels checks.
/// Each model is verified against BOTH a camelCase (Vaultwarden) and a
/// PascalCase (official Bitwarden) variant to prove case-insensitive decoding.
enum TestJSON {

    /// A valid type-2 (AES-CBC-256 + HMAC-SHA256) EncString wire string,
    /// used wherever a fixture needs a decodable EncString-typed field.
    static func validEnc(seed: UInt8 = 0) -> String {
        let iv = Data((0..<16).map { UInt8(($0 &+ Int(seed)) & 0xff) })
        let ct = Data((16..<48).map { UInt8(($0 &+ Int(seed)) & 0xff) })
        let mac = Data((48..<80).map { UInt8(($0 &+ Int(seed)) & 0xff) })
        return EncString(type: .aesCbc256_HmacSha256_B64, iv: iv, ciphertext: ct, mac: mac).stringValue
    }

    // MARK: Auth (Task 4)

    static let preloginCamel = """
    {"kdf":0,"kdfIterations":600000,"kdfMemory":null,"kdfParallelism":null}
    """

    static let preloginPascal = """
    {"Kdf":0,"KdfIterations":600000,"KdfMemory":null,"KdfParallelism":null}
    """

    static func tokenCamel() -> String {
        """
        {"access_token":"AT-123","expires_in":3600,"refresh_token":"RT-456",
         "token_type":"Bearer","Key":"\(validEnc(seed: 1))","PrivateKey":"\(validEnc(seed: 2))",
         "Kdf":0,"KdfIterations":600000}
        """
    }

    static func tokenPascal() -> String {
        """
        {"access_token":"AT-789","expires_in":7200,"refresh_token":"RT-000",
         "token_type":"Bearer","key":"\(validEnc(seed: 3))","privateKey":"\(validEnc(seed: 4))",
         "kdf":0,"kdfIterations":650000}
        """
    }

    // MARK: Cipher + Folder (Task 5)

    static func cipherLoginCamel() -> String {
        """
        {
          "id":"cipher-1","organizationId":null,"folderId":"folder-9",
          "type":1,"name":"\(validEnc(seed: 10))","notes":"\(validEnc(seed: 11))",
          "favorite":true,"reprompt":0,"edit":true,"viewPassword":true,
          "login":{
            "username":"\(validEnc(seed: 12))","password":"\(validEnc(seed: 13))",
            "totp":"\(validEnc(seed: 14))","passwordRevisionDate":"2026-01-02T03:04:05.123Z",
            "uris":[{"uri":"\(validEnc(seed: 15))","match":1}],
            "fido2Credentials":[{
              "credentialId":"\(validEnc(seed: 16))","keyType":"\(validEnc(seed: 17))",
              "keyAlgorithm":"\(validEnc(seed: 18))","keyCurve":"\(validEnc(seed: 19))",
              "keyValue":"\(validEnc(seed: 20))","rpId":"\(validEnc(seed: 21))",
              "rpName":"\(validEnc(seed: 22))","userHandle":"\(validEnc(seed: 23))",
              "userName":"\(validEnc(seed: 24))","userDisplayName":"\(validEnc(seed: 25))",
              "counter":"\(validEnc(seed: 26))","discoverable":"\(validEnc(seed: 27))",
              "creationDate":"2026-01-03T04:05:06.000Z"
            }]
          },
          "fields":[{"type":1,"name":"\(validEnc(seed: 28))","value":"\(validEnc(seed: 29))","linkedId":null}],
          "attachments":null,"collectionIds":null,"key":"\(validEnc(seed: 30))",
          "revisionDate":"2026-01-01T00:00:00.000Z","creationDate":"2025-12-31T00:00:00.000Z","deletedDate":null
        }
        """
    }

    static func cipherLoginPascal() -> String {
        """
        {
          "Id":"cipher-2","OrganizationId":null,"FolderId":"folder-7",
          "Type":1,"Name":"\(validEnc(seed: 40))","Notes":"\(validEnc(seed: 41))",
          "Favorite":false,"Reprompt":0,"Edit":true,"ViewPassword":false,
          "Login":{
            "Username":"\(validEnc(seed: 42))","Password":"\(validEnc(seed: 43))",
            "Totp":null,"PasswordRevisionDate":null,
            "Uris":[{"Uri":"\(validEnc(seed: 45))","Match":3}],
            "Fido2Credentials":[]
          },
          "Fields":null,"Attachments":null,"CollectionIds":null,"Key":null,
          "RevisionDate":"2026-02-02T12:00:00Z","CreationDate":null,"DeletedDate":null
        }
        """
    }

    static func folderCamel() -> String {
        """
        {"id":"folder-1","name":"\(validEnc(seed: 50))","revisionDate":"2026-01-01T00:00:00.000Z"}
        """
    }

    static func folderPascal() -> String {
        """
        {"Id":"folder-2","Name":"\(validEnc(seed: 51))","RevisionDate":"2026-01-01T00:00:00Z"}
        """
    }

    // MARK: Sync (Task 6)

    static func syncCamel() -> String {
        """
        {
          "profile":{
            "id":"user-1","email":"throwaway@example.test","name":"Test User",
            "key":"\(validEnc(seed: 60))","privateKey":"\(validEnc(seed: 61))",
            "securityStamp":"stamp-1",
            "organizations":[{"id":"org-1","name":"Org One","key":"\(validEnc(seed: 62))"}]
          },
          "folders":[
            {"id":"folder-1","name":"\(validEnc(seed: 63))","revisionDate":"2026-01-01T00:00:00.000Z"},
            {"id":"folder-2","name":"\(validEnc(seed: 64))","revisionDate":"2026-01-01T00:00:00.000Z"}
          ],
          "ciphers":[
            \(cipherLoginCamel()),
            \(cipherLoginCamel())
          ],
          "collections":[{"id":"coll-1","organizationId":"org-1","name":"\(validEnc(seed: 65))"}],
          "sends":[],
          "object":"sync"
        }
        """
    }

    /// A sync where exactly ONE cipher has an invalid EncString `name`.
    /// The good ciphers must survive; the bad one lands in `droppedCipherErrors`.
    static func syncWithOneBadCipher() -> String {
        """
        {
          "profile":{"id":"user-1","email":"throwaway@example.test","name":null,
            "key":null,"privateKey":null,"securityStamp":null,"organizations":null},
          "folders":[],
          "ciphers":[
            \(cipherLoginCamel()),
            {"id":"bad-cipher","type":1,"name":"60.garbage","favorite":false,"reprompt":0,
             "revisionDate":"2026-01-01T00:00:00.000Z"},
            \(cipherLoginCamel())
          ],
          "collections":[],
          "sends":[],
          "object":"sync"
        }
        """
    }

    /// A sync where exactly ONE folder has an invalid EncString `name`.
    /// The good folders must survive; the bad one lands in `droppedFolderErrors`.
    static func syncWithOneBadFolder() -> String {
        """
        {
          "profile":{"id":"user-1","email":"throwaway@example.test","name":null,
            "key":null,"privateKey":null,"securityStamp":null,"organizations":null},
          "folders":[
            {"id":"folder-good-1","name":"\(validEnc(seed: 70))","revisionDate":"2026-01-01T00:00:00.000Z"},
            {"id":"folder-bad","name":"60.garbage","revisionDate":"2026-01-01T00:00:00.000Z"},
            {"id":"folder-good-2","name":"\(validEnc(seed: 71))","revisionDate":"2026-01-01T00:00:00.000Z"}
          ],
          "ciphers":[],
          "collections":[],
          "sends":[],
          "object":"sync"
        }
        """
    }

    /// A sync where exactly ONE collection has an invalid EncString `name`.
    /// The good collections must survive; the bad one lands in `droppedCollectionErrors`.
    static func syncWithOneBadCollection() -> String {
        """
        {
          "profile":{"id":"user-1","email":"throwaway@example.test","name":null,
            "key":null,"privateKey":null,"securityStamp":null,"organizations":null},
          "folders":[],
          "ciphers":[],
          "collections":[
            {"id":"coll-good","organizationId":"org-1","name":"\(validEnc(seed: 72))"},
            {"id":"coll-bad","organizationId":"org-1","name":"60.garbage"}
          ],
          "sends":[],
          "object":"sync"
        }
        """
    }
}
