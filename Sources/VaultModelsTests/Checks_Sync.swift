import Foundation
import VaultModels
import CryptoCore

func checkSync(_ r: inout TestRunner) {
    let decoder = VaultJSON.decoder()

    // (a) full sync decode — assert counts and nested decode
    do {
        let s = try decoder.decode(SyncResponse.self, from: TestJSON.syncCamel().data(using: .utf8)!)
        r.expect(s.profile.id, "user-1", "sync profile id")
        r.expect(s.profile.email, "throwaway@example.test", "sync profile email")
        r.expect(s.profile.name, "Test User", "sync profile name")
        r.expectTrue(s.profile.key != nil, "sync profile key EncString?")
        r.expectTrue(s.profile.privateKey != nil, "sync profile privateKey EncString?")
        r.expect(s.profile.securityStamp, "stamp-1", "sync profile securityStamp")
        r.expect(s.profile.organizations?.count, 1, "sync profile organizations count")
        r.expect(s.profile.organizations?[0].id, "org-1", "sync org id")
        r.expect(s.profile.organizations?[0].name, "Org One", "sync org name")
        r.expectTrue(s.profile.organizations?[0].key != nil, "sync org key EncString?")
        r.expect(s.folders.count, 2, "sync folders count")
        r.expect(s.ciphers.count, 2, "sync ciphers count")
        r.expect(s.droppedCipherErrors.count, 0, "sync no dropped ciphers")
        r.expect(s.collections?.count, 1, "sync collections count")
        r.expect(s.collections?[0].organizationId, "org-1", "sync collection organizationId")
        r.expectTrue(s.collections?[0].name != nil, "sync collection name EncString?")
    } catch { r.expectTrue(false, "sync full decode threw: \(error)") }

    // (b) soft-fail: one cipher has an invalid EncString name; the rest survive
    do {
        let s = try decoder.decode(SyncResponse.self, from: TestJSON.syncWithOneBadCipher().data(using: .utf8)!)
        r.expect(s.ciphers.count, 2, "soft-fail: good ciphers survive")
        r.expect(s.droppedCipherErrors.count, 1, "soft-fail: exactly one dropped cipher error")
        // the good ciphers are the valid ones (id cipher-1), not the bad one
        r.expectTrue(s.ciphers.allSatisfy { $0.id == "cipher-1" }, "soft-fail: dropped cipher is the bad one")
    } catch { r.expectTrue(false, "sync soft-fail decode threw (must NOT throw): \(error)") }

    // (c) soft-fail folders: one folder has an invalid EncString name; the rest survive
    do {
        let s = try decoder.decode(SyncResponse.self, from: TestJSON.syncWithOneBadFolder().data(using: .utf8)!)
        r.expect(s.folders.count, 2, "soft-fail folders: good folders survive")
        r.expect(s.droppedFolderErrors.count, 1, "soft-fail folders: exactly one dropped folder error")
        r.expectTrue(s.folders.allSatisfy { $0.id.hasPrefix("folder-good") }, "soft-fail folders: dropped folder is the bad one")
    } catch { r.expectTrue(false, "sync bad-folder decode threw (must NOT throw): \(error)") }

    // (d) soft-fail collections: one collection has an invalid EncString name; the rest survive
    do {
        let s = try decoder.decode(SyncResponse.self, from: TestJSON.syncWithOneBadCollection().data(using: .utf8)!)
        r.expect(s.collections?.count, 1, "soft-fail collections: good collections survive")
        r.expect(s.droppedCollectionErrors.count, 1, "soft-fail collections: exactly one dropped collection error")
        r.expect(s.collections?.first?.id, "coll-good", "soft-fail collections: dropped collection is the bad one")
    } catch { r.expectTrue(false, "sync bad-collection decode threw (must NOT throw): \(error)") }

    // Profile decodes with all-null optionals (no organizations, no keys)
    do {
        let json = #"{"id":"u","email":"e@x.test","name":null,"key":null,"privateKey":null,"securityStamp":null,"organizations":null}"#
        let p = try decoder.decode(ProfileResponse.self, from: json.data(using: .utf8)!)
        r.expect(p.id, "u", "profile minimal id")
        r.expectTrue(p.name == nil, "profile minimal name nil")
        r.expectTrue(p.organizations == nil, "profile minimal organizations nil")
    } catch { r.expectTrue(false, "profile minimal decode threw: \(error)") }
}
