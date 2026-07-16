import Foundation
import Fido2
import VaultModels
import VaultReader
import VaultStore
import AppShared

/// The manual picker reads only bounded display metadata, prioritizes exact service
/// matches, separates password/OTP/passkey kinds, and never crosses the active account.
func checkCredentialCandidates(_ r: inout TestRunner) async {
    let (store, dir): (VaultStore, URL)
    do { (store, dir) = try await Fixtures.freshStore() }
    catch { r.expectTrue(false, "candidates freshStore threw: \(error)"); return }
    defer { Fixtures.cleanup(dir) }

    let otherAccount = "user-2"
    do {
        try await store.upsertAccounts([
            AccountRow(id: otherAccount, email: "other@example.test")
        ])
        let noUsernameBlob = Fixtures.loginBlobJSON(
            username: nil,
            password: "secret-without-user",
            uris: ["https://nouser.example"]
        )
        let noUsername = CipherRow(
            id: "no-user",
            accountID: Fixtures.accountID,
            type: CipherType.login.rawValue,
            revisionDate: Fixtures.iso(Date()),
            creationDate: Fixtures.iso(Date()),
            encName: Fixtures.enc("No Username"),
            encBlob: noUsernameBlob
        )
        let oversizedBase = Fixtures.loginRow(
            id: "oversized",
            name: "Oversized",
            username: "huge",
            password: "secret",
            uris: ["https://login.example/path"]
        )
        let oversized = CipherRow(
            id: oversizedBase.id,
            accountID: oversizedBase.accountID,
            type: oversizedBase.type,
            revisionDate: oversizedBase.revisionDate,
            creationDate: oversizedBase.creationDate,
            encName: oversizedBase.encName,
            encBlob: (oversizedBase.encBlob ?? "") + String(repeating: " ", count: 150_000)
        )
        let deleted = CipherRow(
            id: "deleted-login",
            accountID: Fixtures.accountID,
            type: CipherType.login.rawValue,
            revisionDate: Fixtures.iso(Date()),
            creationDate: Fixtures.iso(Date()),
            deletedDate: Fixtures.iso(Date()),
            encName: Fixtures.enc("Deleted Login"),
            encBlob: Fixtures.loginBlobJSON(
                username: "deleted-user",
                password: "deleted-secret",
                uris: ["https://login.example/path"]
            )
        )
        try await store.upsertCiphers([
            Fixtures.loginRow(
                id: "fallback", name: "Fallback", username: "bob",
                password: "fallback-secret", uris: ["https://other.example"]
            ),
            Fixtures.loginRow(
                id: "matching", name: "Matching", username: "alice",
                password: "matching-secret",
                totp: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                uris: ["https://login.example/path"]
            ),
            noUsername,
            oversized,
            deleted,
            // The same server UUID under another account must not overwrite or appear
            // in the active account's picker.
            Fixtures.loginRow(
                id: "matching", accountID: otherAccount, name: "Foreign Clone",
                username: "mallory", password: "foreign-secret",
                uris: ["https://login.example/path"]
            ),
            Fixtures.passkeyRow(
                id: "passkey-row",
                name: "Passkeys",
                credentials: [
                    Fixtures.PasskeyRecord(
                        credentialIDValue: "b64.\(Fixtures.base64URL(Data([1, 2, 3])))",
                        rpId: "Login.Example",
                        userName: "passkey-user",
                        userHandle: Data([4, 5, 6]),
                        pkcs8: CredentialKey().exportPKCS8()
                    ),
                    Fixtures.PasskeyRecord(
                        credentialIDValue: "b64.\(Fixtures.base64URL(Data([7, 8, 9])))",
                        rpId: "other-rp.example",
                        userName: "other-user",
                        userHandle: Data([10, 11]),
                        pkcs8: CredentialKey().exportPKCS8()
                    ),
                ]
            ),
        ])
    } catch {
        r.expectTrue(false, "candidates seed threw: \(error)")
        return
    }

    let reader = VaultReader(
        store: store,
        keyVault: await Fixtures.unlockedVault(),
        keychain: makeFakeKeychain()
    )

    do {
        let systemRecord = CredentialRecordIdentifier.encode(
            accountID: Fixtures.accountID,
            cipherID: "matching",
            kind: .password,
            serviceIdentifier: "https://login.example/path",
            user: "alice"
        )
        r.expect(try await reader.cipherID(
            forRecordIdentifier: systemRecord,
            kind: .password,
            serviceIdentifier: "https://login.example/path",
            user: "alice"
        ),
                 "matching", "candidates: owning system identity decodes")

        let systemPassword = try await reader.passwordCredential(
            forRecordIdentifier: systemRecord,
            serviceIdentifier: "https://login.example/path",
            user: "alice"
        )
        r.expect(systemPassword.user, "alice",
                 "candidates: v3 password identity keeps validated row user")
        r.expect(systemPassword.password, "matching-secret",
                 "candidates: v3 password identity vends validated row secret")

        let otpRecord = CredentialRecordIdentifier.encode(
            accountID: Fixtures.accountID,
            cipherID: "matching",
            kind: .oneTimeCode,
            serviceIdentifier: "https://login.example/path",
            user: "alice"
        )
        r.expect(try await reader.oneTimeCode(
            forRecordIdentifier: otpRecord,
            serviceIdentifier: "https://login.example/path",
            user: "alice",
            at: Date(timeIntervalSince1970: 59)
        ), "287082", "candidates: v3 OTP identity vends validated row code")

        let passkeyRecord = CredentialRecordIdentifier.encode(
            accountID: Fixtures.accountID,
            cipherID: "passkey-row",
            kind: .passkey,
            serviceIdentifier: "Login.Example",
            user: "passkey-user"
        )
        let passkeyAssertion = try await reader.passkeyAssertion(
            forRecordIdentifier: passkeyRecord,
            serviceIdentifier: "Login.Example",
            user: "passkey-user",
            credentialID: Data([1, 2, 3]),
            userHandle: Data([4, 5, 6]),
            clientDataHash: Data(repeating: 0xA5, count: 32),
            userVerified: true
        )
        r.expectTrue(passkeyAssertion.authenticatorData.count >= 37,
                     "candidates: v3 passkey identity vends exact credential")
        await r.expectThrowsErrorAsync(
            VaultReaderError.noPasskey,
            "candidates: v3 passkey identity rejects stale user handle"
        ) {
            _ = try await reader.passkeyAssertion(
                forRecordIdentifier: passkeyRecord,
                serviceIdentifier: "Login.Example",
                user: "passkey-user",
                credentialID: Data([1, 2, 3]),
                userHandle: Data([9, 9, 9]),
                clientDataHash: Data(repeating: 0xA5, count: 32),
                userVerified: true
            )
        }
        await r.expectThrowsErrorAsync(
            VaultReaderError.notFound,
            "candidates: cloned-account system identity is rejected"
        ) {
            _ = try await reader.cipherID(forRecordIdentifier:
                CredentialRecordIdentifier.encode(
                    accountID: otherAccount,
                    cipherID: "matching",
                    kind: .password,
                    serviceIdentifier: "https://login.example/path",
                    user: "mallory"
                ),
                kind: .password,
                serviceIdentifier: "https://login.example/path",
                user: "mallory"
            )
        }
        await r.expectThrowsErrorAsync(
            VaultReaderError.notFound,
            "candidates: legacy raw record identifier is rejected"
        ) {
            _ = try await reader.cipherID(
                forRecordIdentifier: "matching",
                kind: .password,
                serviceIdentifier: "https://login.example/path",
                user: "alice"
            )
        }
        await r.expectThrowsErrorAsync(
            VaultReaderError.notFound,
            "candidates: stale service identity cannot vend current secret"
        ) {
            _ = try await reader.cipherID(
                forRecordIdentifier: CredentialRecordIdentifier.encode(
                    accountID: Fixtures.accountID,
                    cipherID: "matching",
                    kind: .password,
                    serviceIdentifier: "https://old.example",
                    user: "alice"
                ),
                kind: .password,
                serviceIdentifier: "https://old.example",
                user: "alice"
            )
        }
        await r.expectThrowsErrorAsync(
            VaultReaderError.notFound,
            "candidates: stale displayed user cannot vend another user's secret"
        ) {
            _ = try await reader.cipherID(
                forRecordIdentifier: CredentialRecordIdentifier.encode(
                    accountID: Fixtures.accountID,
                    cipherID: "matching",
                    kind: .password,
                    serviceIdentifier: "https://login.example/path",
                    user: "bob"
                ),
                kind: .password,
                serviceIdentifier: "https://login.example/path",
                user: "bob"
            )
        }
        await r.expectThrowsErrorAsync(
            VaultReaderError.notFound,
            "candidates: deleted system identity cannot vend its old secret"
        ) {
            _ = try await reader.passwordCredential(
                forRecordIdentifier: CredentialRecordIdentifier.encode(
                    accountID: Fixtures.accountID,
                    cipherID: "deleted-login",
                    kind: .password,
                    serviceIdentifier: "https://login.example/path",
                    user: "deleted-user"
                ),
                serviceIdentifier: "https://login.example/path",
                user: "deleted-user"
            )
        }

        let passwords = try await reader.credentialCandidates(
            kind: .password,
            serviceIdentifiers: ["login.example"],
            limit: 10
        )
        r.expect(passwords.first?.recordID, "matching",
                 "candidates: exact host match is ordered first")
        r.expect(passwords.first?.name, "Matching",
                 "candidates: cloned foreign UUID cannot overwrite active row")
        r.expectTrue(!passwords.contains { $0.name == "Foreign Clone" },
                     "candidates: foreign account metadata is excluded")
        r.expectTrue(!passwords.contains { $0.name == "Oversized" },
                     "candidates: oversized encrypted blob is excluded before materialization")
        r.expectTrue(!passwords.contains { $0.recordID == "deleted-login" },
                     "candidates: deleted row is excluded from manual AutoFill")
        r.expect(passwords.first { $0.recordID == "no-user" }?.user, "",
                 "candidates: password-only entry without username remains selectable")
        r.expect(try await reader.credentialCandidates(
            kind: .password,
            serviceIdentifiers: [],
            limit: 1
        ).count, 1, "candidates: caller limit is enforced")

        let otp = try await reader.credentialCandidates(
            kind: .oneTimeCode,
            serviceIdentifiers: ["https://login.example"]
        )
        r.expect(otp.map(\.recordID), ["matching"],
                 "candidates: OTP kind returns only logins with a seed")

        let passkeys = try await reader.credentialCandidates(
            kind: .passkey,
            relyingPartyIdentifier: "login.example"
        )
        r.expect(passkeys.count, 1,
                 "candidates: passkey RP filter is strict")
        r.expect(passkeys.first?.credentialID, Data([1, 2, 3]),
                 "candidates: passkey credential id is decoded")
        r.expect(passkeys.first?.userHandle, Data([4, 5, 6]),
                 "candidates: passkey user handle is decoded")

        // The assertion lookup uses the same normalized RP comparison as the picker;
        // capitalization in stored legacy metadata cannot make a displayed row fail.
        _ = try await reader.passkeyAssertion(
            recordID: "passkey-row",
            rpId: "login.example",
            credentialID: Data([1, 2, 3]),
            clientDataHash: Data(repeating: 0xA5, count: 32),
            userVerified: true
        )
    } catch {
        r.expectTrue(false, "credentialCandidates flow threw: \(error)")
    }

    let lockedReader = VaultReader(
        store: store,
        keyVault: Fixtures.lockedVault(),
        keychain: makeFakeKeychain()
    )
    await r.expectThrowsErrorAsync(
        VaultReaderError.locked,
        "candidates: locked vault fails before metadata scan"
    ) {
        _ = try await lockedReader.credentialCandidates(kind: .password)
    }
}
