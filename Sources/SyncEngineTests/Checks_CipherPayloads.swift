import Foundation
import VaultModels
import VaultStore
import Networking
import SyncEngine

/// The Codable outbox mirror must rebuild every request sub-payload, including fields that
/// used to be silently absent (full identity, SSH key, FIDO2, and linked custom fields).
func checkCompleteOutboxCipherPayload(_ r: inout TestRunner) {
    let date = Date(timeIntervalSinceReferenceDate: 456_789)
    func wire(_ value: String) -> String { Fixtures.enc(value) }

    let payload = OutboxCipherPayload(
        type: CipherType.login.rawValue,
        name: wire("Complete payload"),
        notes: wire("notes"),
        folderID: "folder-1",
        favorite: true,
        login: .init(
            username: wire("alice"), password: wire("password"), totp: wire("totp"),
            uris: [.init(uri: wire("https://example.test"), match: 3)],
            fido2Credentials: [.init(
                credentialId: wire("credential"), keyType: wire("public-key"),
                keyAlgorithm: wire("ECDSA"), keyCurve: wire("P-256"),
                keyValue: wire("pkcs8"), rpId: wire("example.test"),
                rpName: wire("Example"), userHandle: wire("handle"),
                userName: wire("alice"), userDisplayName: wire("Alice"),
                counter: wire("9"), discoverable: wire("true"), creationDate: date
            )],
            passwordRevisionDate: date
        ),
        card: .init(cardholderName: wire("Ada"), brand: wire("Visa"),
                    number: wire("4111"), expMonth: wire("12"), expYear: wire("2030"),
                    code: wire("123")),
        identity: .init(
            title: wire("Dr"), firstName: wire("Grace"), middleName: wire("B"),
            lastName: wire("Hopper"), address1: wire("A1"), address2: wire("A2"),
            address3: wire("A3"), city: wire("City"), state: wire("State"),
            postalCode: wire("Postal"), country: wire("Country"), company: wire("Company"),
            email: wire("email"), phone: wire("phone"), ssn: wire("ssn"),
            username: wire("username"), passportNumber: wire("passport"),
            licenseNumber: wire("license")
        ),
        secureNote: .init(type: SecureNoteType.generic.rawValue),
        sshKey: .init(privateKey: wire("private"), publicKey: wire("public"),
                      keyFingerprint: wire("fingerprint")),
        fields: [.init(type: FieldType.linked.rawValue, name: wire("field-name"),
                       value: wire("field-value"), linkedId: 42)]
    )

    do {
        let decoded = try OutboxCipherPayload.decode(payload.encodedJSON())
        r.expect(decoded, payload, "complete outbox payload JSON round-trip")
        let request = try decoded.cipherRequest(lastKnownRevisionDate: date)
        r.expectTrue(request.login?.fido2Credentials?.first?.keyValue != nil,
                     "complete outbox rebuilds FIDO2 key value")
        r.expectTrue(request.card?.code != nil, "complete outbox rebuilds card")
        r.expectTrue(request.identity?.title != nil && request.identity?.licenseNumber != nil,
                     "complete outbox rebuilds full identity")
        r.expectTrue(request.sshKey?.privateKey != nil && request.sshKey?.keyFingerprint != nil,
                     "complete outbox rebuilds SSH key")
        r.expect(request.fields?.first?.linkedId, 42,
                 "complete outbox rebuilds linked custom field")
        r.expect(request.login?.passwordRevisionDate, date,
                 "complete outbox rebuilds login revision date")
    } catch {
        r.expectTrue(false, "complete outbox payload threw: \(error)")
    }
}

/// A server sync must retain every identity and SSH field in `enc_blob`; search indexing
/// includes useful labels/fingerprints but excludes card/key secrets.
func checkSyncPreservesIdentityAndSSH(_ r: inout TestRunner) async {
    guard let (store, dir) = try? Fixtures.freshStore() else {
        r.expectTrue(false, "complete blob: fresh store")
        return
    }
    defer { Fixtures.cleanup(dir) }

    let revision = Date(timeIntervalSince1970: 1_760_000_000)
    let title = Fixtures.enc("Admiral")
    let first = Fixtures.enc("Grace")
    let middle = Fixtures.enc("B")
    let last = Fixtures.enc("Hopper")
    let address1 = Fixtures.enc("1 Compiler Way")
    let address2 = Fixtures.enc("Suite 2")
    let address3 = Fixtures.enc("Floor 3")
    let city = Fixtures.enc("Arlington")
    let state = Fixtures.enc("VA")
    let postal = Fixtures.enc("22201")
    let country = Fixtures.enc("US")
    let company = Fixtures.enc("Navy")
    let email = Fixtures.enc("grace@example.test")
    let phone = Fixtures.enc("+1 555")
    let ssn = Fixtures.enc("000-00-0000")
    let username = Fixtures.enc("ghopper")
    let passport = Fixtures.enc("P123")
    let license = Fixtures.enc("L456")
    let fieldName = Fixtures.enc("Identity custom")
    let fieldValue = Fixtures.enc("custom value")

    let identityJSON = """
    {"id":"identity-1","organizationId":null,"folderId":null,"type":4,
     "name":"\(Fixtures.enc("Complete Identity"))","notes":null,"favorite":false,"reprompt":0,
     "edit":true,"viewPassword":true,"login":null,"card":null,
     "identity":{"title":"\(title)","firstName":"\(first)","middleName":"\(middle)",
       "lastName":"\(last)","address1":"\(address1)","address2":"\(address2)",
       "address3":"\(address3)","city":"\(city)","state":"\(state)",
       "postalCode":"\(postal)","country":"\(country)","company":"\(company)",
       "email":"\(email)","phone":"\(phone)","ssn":"\(ssn)",
       "username":"\(username)","passportNumber":"\(passport)",
       "licenseNumber":"\(license)"},
     "secureNote":null,"sshKey":null,
     "fields":[{"type":3,"name":"\(fieldName)","value":"\(fieldValue)","linkedId":42}],
     "attachments":null,"collectionIds":null,"key":null,
     "revisionDate":"\(Fixtures.iso(revision))","creationDate":"2026-01-01T00:00:00.000Z",
     "deletedDate":null}
    """

    let privateKey = Fixtures.enc("PRIVATE-KEY-MUST-NOT-BE-INDEXED")
    let publicKey = Fixtures.enc("ssh-ed25519 PUBLIC-MUST-NOT-BE-INDEXED")
    let fingerprint = Fixtures.enc("SHA256:searchable-fingerprint")
    let sshJSON = """
    {"id":"ssh-1","organizationId":null,"folderId":null,"type":5,
     "name":"\(Fixtures.enc("Complete SSH"))","notes":null,"favorite":false,"reprompt":0,
     "edit":true,"viewPassword":true,"login":null,"card":null,"identity":null,
     "secureNote":null,"sshKey":{"privateKey":"\(privateKey)","publicKey":"\(publicKey)",
       "keyFingerprint":"\(fingerprint)"},"fields":null,"attachments":null,
     "collectionIds":null,"key":null,"revisionDate":"\(Fixtures.iso(revision))",
     "creationDate":"2026-01-01T00:00:00.000Z","deletedDate":null}
    """

    let response = Fixtures.decodeSync(Fixtures.syncJSON(ciphers: [identityJSON, sshJSON]))
    let api = FakeVaultAPI(syncResponse: response)
    let engine = SyncEngine(api: api, store: store, keyVault: await Fixtures.unlockedVault(),
                            identityStore: FakeIdentityStore(enabled: false))

    do {
        let outcome = try await engine.fullSync(accountID: Fixtures.accountID)
        r.expect(outcome.upserted, 2, "complete blob: sync upserts identity + SSH")

        guard let identityRow = try await store.cipher(
            id: "identity-1",
            accountID: Fixtures.accountID
        ),
              let identityData = identityRow.encBlob?.data(using: .utf8),
              let identityRoot = try JSONSerialization.jsonObject(with: identityData) as? [String: Any],
              let identity = identityRoot["identity"] as? [String: Any],
              let fields = identityRoot["fields"] as? [[String: Any]],
              let field = fields.first else {
            r.expectTrue(false, "complete blob: parse identity blob")
            return
        }
        r.expect(identity["title"] as? String, title, "complete blob: identity title retained")
        r.expect(identity["middleName"] as? String, middle,
                 "complete blob: identity middle name retained")
        r.expect(identity["address3"] as? String, address3,
                 "complete blob: identity address3 retained")
        r.expect(identity["licenseNumber"] as? String, license,
                 "complete blob: identity license retained")
        r.expect((field["type"] as? NSNumber)?.intValue, FieldType.linked.rawValue,
                 "complete blob: custom field type retained")
        r.expect((field["linkedId"] as? NSNumber)?.intValue, 42,
                 "complete blob: custom linked id retained")
        r.expectTrue(identityRow.searchText?.contains("grace@example.test") == true,
                     "complete blob: identity email searchable")
        r.expectTrue(identityRow.searchText?.contains("000-00-0000") == false,
                     "complete blob: identity SSN excluded from index")

        guard let sshRow = try await store.cipher(
            id: "ssh-1",
            accountID: Fixtures.accountID
        ),
              let sshData = sshRow.encBlob?.data(using: .utf8),
              let sshRoot = try JSONSerialization.jsonObject(with: sshData) as? [String: Any],
              let ssh = sshRoot["sshKey"] as? [String: Any] else {
            r.expectTrue(false, "complete blob: parse SSH blob")
            return
        }
        r.expect(ssh["privateKey"] as? String, privateKey,
                 "complete blob: SSH private key retained encrypted")
        r.expect(ssh["publicKey"] as? String, publicKey,
                 "complete blob: SSH public key retained encrypted")
        r.expect(ssh["keyFingerprint"] as? String, fingerprint,
                 "complete blob: SSH fingerprint retained encrypted")
        r.expectTrue(sshRow.searchText?.contains("searchable-fingerprint") == true,
                     "complete blob: SSH fingerprint searchable")
        r.expectTrue(sshRow.searchText?.contains("public-must-not-be-indexed") == false,
                     "complete blob: SSH public key excluded from index")
        r.expectTrue(sshRow.searchText?.contains("private-key-must-not-be-indexed") == false,
                     "complete blob: SSH private key excluded from index")
    } catch {
        r.expectTrue(false, "complete blob sync threw: \(error)")
    }
}
