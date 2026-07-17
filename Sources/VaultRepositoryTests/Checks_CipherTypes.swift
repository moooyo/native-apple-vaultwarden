import Foundation
import VaultModels
import Networking
import SyncEngine
import VaultRepository

/// All five cipher types must survive the real repository encryption -> local blob ->
/// decryption path and the offline outbox mirror without dropping untouched fields.
func checkAllCipherTypesRoundTrip(_ r: inout TestRunner) async {
    let h: Fixtures.Harness
    do {
        h = try await Fixtures.makeHarness(tokenResults: [.success(Fixtures.tokenResponse())])
        _ = try await h.auth.login(email: Fixtures.email, password: Fixtures.password,
                                   server: Fixtures.server)
    } catch {
        r.expectTrue(false, "five types: setup threw \(error)")
        return
    }
    defer { Fixtures.cleanup(h.dir) }
    guard let accountID = await h.auth.session?.accountID else {
        r.expectTrue(false, "five types: missing account id")
        return
    }

    let metadataDate = Date(timeIntervalSinceReferenceDate: 789_123)
    let ciphers: [PlaintextCipher] = [
        PlaintextCipher(
            type: CipherType.login.rawValue,
            name: "Full Login",
            notes: "login note",
            favorite: true,
            login: .init(
                username: "alice",
                password: "correct horse",
                totp: "otpauth://totp/Tessera",
                uris: [.init(uri: "https://login-roundtrip.example", match: 3)],
                fido2Credentials: [.init(
                    credentialId: "credential-id", keyType: "public-key",
                    keyAlgorithm: "ECDSA", keyCurve: "P-256", keyValue: "pkcs8-value",
                    rpId: "login-roundtrip.example", rpName: "Round Trip",
                    userHandle: "user-handle", userName: "alice",
                    userDisplayName: "Alice Example", counter: "7",
                    discoverable: "true", creationDate: metadataDate
                )],
                passwordRevisionDate: metadataDate
            ),
            fields: [.init(type: FieldType.hidden.rawValue, name: "Login custom",
                           value: "custom secret", linkedId: nil)]
        ),
        PlaintextCipher(
            type: CipherType.secureNote.rawValue,
            name: "Full Secure Note",
            notes: "the complete secure note",
            secureNote: .init(type: SecureNoteType.generic.rawValue)
        ),
        PlaintextCipher(
            type: CipherType.card.rawValue,
            name: "Full Card",
            card: .init(cardholderName: "Ada Cardholder", brand: "Visa",
                        number: "4111111111111111", expMonth: "12", expYear: "2031",
                        code: "123"),
            fields: [.init(type: FieldType.linked.rawValue, name: "Card custom",
                           value: "linked value", linkedId: 7)]
        ),
        PlaintextCipher(
            type: CipherType.identity.rawValue,
            name: "Full Identity",
            identity: .init(
                title: "Dr", firstName: "Grace", middleName: "B", lastName: "Hopper",
                address1: "1 Compiler Way", address2: "Suite 2", address3: "Floor 3",
                city: "Arlington", state: "VA", postalCode: "22201", country: "US",
                company: "Navy", email: "grace.identity@example.test", phone: "+1 555 0100",
                ssn: "000-00-0000", username: "ghopper", passportNumber: "P123",
                licenseNumber: "L456"
            )
        ),
        PlaintextCipher(
            type: CipherType.sshKey.rawValue,
            name: "Full SSH Key",
            sshKey: .init(privateKey: "-----BEGIN PRIVATE KEY-----private",
                          publicKey: "ssh-ed25519 AAAA-roundtrip",
                          keyFingerprint: "SHA256:ssh-roundtrip-fingerprint")
        ),
    ]

    await h.api.setCreateError(NetworkingError.serverUnreachable)
    var ids: [String] = []
    for original in ciphers {
        do {
            let id = try await h.vault.createCipher(original)
            ids.append(id)
            var expected = original
            expected.id = id
            let actual = try await h.vault.cipher(id: id)
            r.expect(actual, expected, "five types: \(original.name) local round-trip")
        } catch {
            r.expectTrue(false, "five types: \(original.name) create/read threw \(error)")
        }
    }

    let requests = await h.api.createdRequests
    r.expect(requests.count, 5, "five types: API saw every create")
    if requests.count == 5 {
        r.expectTrue(requests[0].login?.fido2Credentials?.first?.keyValue != nil,
                     "five types: login request preserves passkey private key")
        r.expect(requests[1].secureNote?.type, SecureNoteType.generic.rawValue,
                 "five types: secure-note payload present")
        r.expectTrue(requests[2].card?.code != nil,
                     "five types: card request preserves code")
        r.expectTrue(requests[3].identity?.licenseNumber != nil,
                     "five types: identity request preserves final field")
        r.expectTrue(requests[4].sshKey?.privateKey != nil,
                     "five types: SSH request preserves private key")
        r.expect(requests[2].fields?.first?.linkedId, 7,
                 "five types: linked custom-field id preserved")
    }

    // Repeat the matrix online. FakeAPI echoes every encrypted sub-payload as a server
    // response, exercising makeRow/encodeBlob rather than the optimistic local-row path.
    await h.api.setCreateError(nil)
    var onlineIDs: [String] = []
    for original in ciphers {
        do {
            let id = try await h.vault.createCipher(original)
            onlineIDs.append(id)
            var expected = original
            expected.id = id
            let actual = try await h.vault.cipher(id: id)
            r.expect(actual, expected, "five types online: \(original.name) round-trip")
        } catch {
            r.expectTrue(false, "five types online: \(original.name) create/read threw \(error)")
        }
    }

    do {
        let rows = try await h.store.outbox()
        r.expect(rows.count, 5, "five types: every offline create queued")
        let payloads = try rows.map { try OutboxCipherPayload.decode($0.payloadJSON) }
        let rebuilt = try payloads.map { try $0.cipherRequest(lastKnownRevisionDate: nil) }
        r.expectTrue(rebuilt.contains { $0.card?.number != nil && $0.card?.code != nil },
                     "five types: card survives outbox rebuild")
        r.expectTrue(rebuilt.contains { $0.identity?.passportNumber != nil && $0.identity?.licenseNumber != nil },
                     "five types: identity survives outbox rebuild")
        r.expectTrue(rebuilt.contains { $0.sshKey?.privateKey != nil && $0.sshKey?.keyFingerprint != nil },
                     "five types: SSH survives outbox rebuild")
        r.expectTrue(rebuilt.contains { $0.login?.fido2Credentials?.first?.userHandle != nil },
                     "five types: passkey survives outbox rebuild")
    } catch {
        r.expectTrue(false, "five types: outbox decode/rebuild threw \(error)")
    }

    do {
        r.expect((try await h.vault.search("ada cardholder")).first?.type,
                 CipherType.card.rawValue, "five types: card fields searchable")
        r.expect((try await h.vault.search("grace.identity@example.test")).first?.type,
                 CipherType.identity.rawValue, "five types: identity fields searchable")
        r.expect((try await h.vault.search("ssh-roundtrip-fingerprint")).first?.type,
                 CipherType.sshKey.rawValue, "five types: SSH fingerprint searchable")
        if ids.count > 4 {
            let cardIndex = (try await h.store.cipher(id: ids[2], accountID: accountID))?.searchText ?? ""
            let sshIndex = (try await h.store.cipher(id: ids[4], accountID: accountID))?.searchText ?? ""
            r.expectTrue(!cardIndex.contains("4111111111111111"),
                         "five types: card number excluded from plaintext search index")
            r.expectTrue(!sshIndex.contains("ssh-ed25519"),
                         "five types: SSH public key excluded from plaintext search index")
            r.expectTrue(!sshIndex.contains("begin private key"),
                         "five types: SSH private key excluded from plaintext search index")
        }
    } catch {
        r.expectTrue(false, "five types: search threw \(error)")
    }

    // Updating only the card's name must carry its full existing sub-payload forward.
    if ids.count > 2 {
        do {
            var edited = try await h.vault.cipher(id: ids[2])
            let originalCard = edited.card
            edited.name = "Renamed Card"
            await h.api.setUpdateError(NetworkingError.serverUnreachable)
            try await h.vault.updateCipher(id: ids[2], edited)
            let after = try await h.vault.cipher(id: ids[2])
            r.expect(after.card, originalCard, "five types: rename does not clear card fields")
        } catch {
            r.expectTrue(false, "five types: card-preserving update threw \(error)")
        }
    }


    if onlineIDs.count > 3 {
        do {
            var edited = try await h.vault.cipher(id: onlineIDs[3])
            let originalIdentity = edited.identity
            edited.name = "Renamed Identity"
            await h.api.setUpdateError(nil)
            try await h.vault.updateCipher(id: onlineIDs[3], edited)
            let after = try await h.vault.cipher(id: onlineIDs[3])
            r.expect(after.identity, originalIdentity,
                     "five types online: rename does not clear identity fields")
        } catch {
            r.expectTrue(false, "five types online: identity-preserving update threw \(error)")
        }
    }
}
