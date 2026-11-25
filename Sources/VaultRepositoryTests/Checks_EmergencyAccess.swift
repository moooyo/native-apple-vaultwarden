import AppShared
import CryptoCore
import Foundation
import Networking
import Security
import UIShared
import VaultRepository
import os

func checkEmergencyAccess(_ runner: inout TestRunner) async {
    let words = await GeneratorModel.standardDicewareWords
    do {
        // Public fixture from Bitwarden SDK `crates/bitwarden-crypto/src/fingerprint.rs`.
        let sdkSPKI = Data(base64Encoded: "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuyYs8W7NWf0Zv35Ueco93730dtRKi4Jhc6Snar+86drE+ruSfaCWMcbgsAoAj2Pm6KAzaJrTIVCqBERQ23OncpzjfcGAeyf+v3w/gSw/EjihMJ4AG5ICY4hLFYcGdgwa+7is+TVO0i6PEWjKQa3l2+mQo2XY7pg2ngHDMssV4gxSqq+qoBX3+FBhewCYdOV+3cebwsAzz7HwoFTxKViwNW8crbHonhZPhZgfIAzEkzo5MvzQg5azhLKW6vuPfaOQFC5HqPykVnh8OPzO0uzUi3+97CguAu4N2CgwVYXltZuw2fGamdVw3kjbxQPbOE1tL0j7gyTwYKkfUl2m8gMh1QIDAQAB")!
        let userID = "a09726a0-9590-49d1-a5f5-afe300b6a515"
        runner.expect(try EmergencyAccessCryptography.fingerprint(userID: userID, spki: sdkSPKI, words: words),
                      "turban-deftly-anime-chatroom-unselfish", "emergency access: fingerprint matches Bitwarden SDK vector")
        runner.expectThrowsError(.unsupportedKey, "emergency access: rejects trailing DER data") {
            _ = try EmergencyAccessCryptography.fingerprint(userID: userID, spki: sdkSPKI + Data([0]), words: words)
        }

        let rsa = try EmergencyRSAFixture()
        let accountKey = Fixtures.userKey()
        let grantorKey = Fixtures.cipherKey()
        let protectedKey = try SymmetricCrypto.encrypt(rsa.pkcs8, using: accountKey)
        let wrapped = try EmergencyAccessCryptography.wrap(grantorKey, spki: rsa.spki)
        runner.expect(wrapped.type, .rsa2048_OaepSha1_B64, "emergency access: SDK-compatible type 4 writes")
        runner.expect(wrapped.ciphertext.count, 256, "emergency access: wraps with RSA-2048")
        runner.expect(try rsa.decryptForTest(wrapped), Fixtures.cipherKeyData(), "emergency access: wire wraps the raw 64-byte key")
        runner.expect(try EmergencyAccessCryptography.unwrap(wrapped, pkcs8: rsa.pkcs8), grantorKey,
                      "emergency access: reads a type-4 wrapped key from a PKCS#8 private key")
        let sha256 = try rsa.wrapForTest(Fixtures.cipherKeyData(), type: .rsa2048_OaepSha256_B64)
        runner.expect(try EmergencyAccessCryptography.unwrap(sha256, pkcs8: rsa.pkcs8), grantorKey,
                      "emergency access: also reads the explicit OAEP-SHA256 type-3 format")
        runner.expectThrowsError(.unsupportedKey, "emergency access: no alternate format fallback") {
            _ = try EmergencyAccessCryptography.unwrap(
                EncString(type: .rsa2048_OaepSha1_HmacSha256_B64, iv: nil, ciphertext: wrapped.ciphertext, mac: Data([1])),
                pkcs8: rsa.pkcs8)
        }

        let storeAndDir = try await Fixtures.freshStore()
        defer { Fixtures.cleanup(storeAndDir.1) }
        let fixturePublicKey = rsa.spki.base64EncodedString()
        let fixtureCiphers = try EmergencyAccessTransport.cipherFixtures(grantorKey: grantorKey)
        EmergencyAccessTransport.state.withLock { state in
            state = .init()
            state.publicKey = fixturePublicKey
            state.privateKey = protectedKey.stringValue
            state.wrappedKey = wrapped.stringValue
            state.ciphers = fixtureCiphers
        }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [EmergencyAccessTransport.self]
        let network = URLSession(configuration: configuration)
        defer {
            network.invalidateAndCancel()
            EmergencyAccessTransport.state.withLock { $0 = .init() }
        }
        let api = APIClient(environment: Fixtures.server, session: network,
                            device: .init(type: DeviceMetadata.DeviceType.macOSDesktop, identifier: "emergency-fixture", name: "Fixture"),
                            clientVersion: "2026.1.0")
        let container = ServiceContainer.makeDefault(apiClient: api, store: storeAndDir.0,
                                                     keychain: makeFakeKeychain(), identityStore: FakeIdentityStore())
        let auth = container.authRepository
        let repository = EmergencyAccessRepository(auth: auth, api: api, keyVault: container.keyVault,
                                                   store: container.store, fingerprintWords: words)
        _ = try await auth.login(email: Fixtures.email, password: Fixtures.password, server: Fixtures.server)
        guard let lease = await repository.unlockedSessionLease() else { throw EmergencyFixtureError.missingLease }
        let accountItemsBefore = try await container.store.allCiphers(accountID: lease.accountID).count

        var list = try await repository.list(lease: lease)
        guard let trusted = list.trusted.first,
              let granted = list.granted.first(where: { $0.type == .view }),
              let takeover = list.granted.first(where: { $0.type == .takeover }) else { throw EmergencyFixtureError.missingContact }
        runner.expect(trusted.status, .accepted, "emergency access: camelCase trusted status is server-owned")
        runner.expect(trusted.contactID, EmergencyAccessTransport.contactID, "emergency access: decode granteeId in trusted")
        runner.expect(granted.status, .confirmed, "emergency access: PascalCase granted status decodes")
        runner.expect(granted.contactID, EmergencyAccessTransport.contactID, "emergency access: decode GrantorId in granted")
        runner.expect(granted.waitTimeDays, 9, "emergency access: wait duration comes from the server")
        runner.expect(takeover.type, .takeover, "emergency access: existing takeover remains visible")
        runner.expect(list.granted.last?.status, .unknown(99), "emergency access: unknown statuses remain visible")

        let beforeInvalid = EmergencyAccessTransport.callCount
        await runner.expectThrowsErrorAsync(EmergencyAccessError.invalidWaitTime, "emergency access: rejects wait durations above 90") {
            try await repository.invite(email: "contact@example.test", waitTimeDays: 91, lease: lease)
        }
        await runner.expectThrowsErrorAsync(EmergencyAccessError.invalidWaitTime, "emergency access: rejects zero wait duration") {
            try await repository.edit(trusted, waitTimeDays: 0, lease: lease)
        }
        await runner.expectThrowsErrorAsync(EmergencyAccessError.invalidEmail, "emergency access: does not invite the current account") {
            try await repository.invite(email: Fixtures.email.uppercased(), waitTimeDays: 7, lease: lease)
        }
        await runner.expectThrowsErrorAsync(EmergencyAccessError.invalidInvitation, "emergency access: never accepts a full token-bearing URL") {
            try await repository.accept(invitationID: trusted.id, token: "https://mail.example.test/#token=aaa.bbb.ccc", lease: lease)
        }
        await runner.expectThrowsErrorAsync(EmergencyAccessError.actionUnavailable, "emergency access: blocks initiation of takeover") {
            try await repository.perform(.request, on: takeover, lease: lease)
        }
        await runner.expectThrowsErrorAsync(EmergencyAccessError.actionUnavailable, "emergency access: grantor cannot initiate own access") {
            try await repository.perform(.request, on: trusted, lease: lease)
        }
        await runner.expectThrowsErrorAsync(EmergencyAccessError.actionUnavailable, "emergency access: grantee cannot approve") {
            try await repository.perform(.approve, on: granted, lease: lease)
        }
        await runner.expectThrowsErrorAsync(EmergencyAccessError.actionUnavailable, "emergency access: pending grant cannot read") {
            _ = try await repository.viewIndex(for: granted, lease: lease)
        }
        runner.expect(EmergencyAccessTransport.callCount, beforeInvalid, "emergency access: invalid inputs/roles never dispatch")

        try await repository.invite(email: " contact@example.test ", waitTimeDays: 1, lease: lease)
        let invite = EmergencyAccessTransport.lastMutation
        runner.expect(invite?.path, "/api/emergency-access/invite", "emergency access: invite endpoint")
        runner.expect(invite?.email, "contact@example.test", "emergency access: trim invite email")
        runner.expect(invite?.waitTime, 1, "emergency access: invite lower bound uses waitTimeDays")
        runner.expect(invite?.type, 0, "emergency access: invite specifies read-only")
        let invitationID = EmergencyAccessTransport.invitationID
        try await repository.accept(invitationID: invitationID, token: " aaa.bbb.ccc ", lease: lease)
        let accept = EmergencyAccessTransport.lastMutation
        runner.expect(accept?.path, "/api/emergency-access/\(invitationID.uuidString.lowercased())/accept",
                      "emergency access: accept URL contains only the record ID, not the token")
        runner.expect(accept?.hasQuery, false, "emergency access: no token-bearing URL query or fragment")
        runner.expect(accept?.token, "aaa.bbb.ccc", "emergency access: acceptance passes the trimmed token in JSON")
        await runner.expectThrowsErrorAsync(EmergencyAccessError.serverRejected, "emergency access: rejects invalid token without surfacing echoed body") {
            try await repository.accept(invitationID: invitationID, token: "aaa.bad.ccc", lease: lease)
        }

        try await repository.edit(trusted, waitTimeDays: 90, lease: lease)
        let edit = EmergencyAccessTransport.lastMutation
        runner.expect(edit?.method, "PUT", "emergency access: edit uses PUT")
        runner.expect(edit?.waitTime, 90, "emergency access: allows the exact upper wait-time bound")
        runner.expect(edit?.keys, ["type", "waitTimeDays"], "emergency access: edit never replaces a wrapped key")
        await runner.expectThrowsErrorAsync(EmergencyAccessError.contactChanged, "emergency access: stale contact settings block confirmation") {
            _ = try await repository.prepareConfirmation(for: trusted, lease: lease)
        }
        EmergencyAccessTransport.state.withLock { $0.trustedStatus = 0 }
        guard let invited = try await repository.list(lease: lease).trusted.first else { throw EmergencyFixtureError.missingContact }
        try await repository.perform(.reinvite, on: invited, lease: lease)
        runner.expect(EmergencyAccessTransport.lastMutation?.path.hasSuffix("/reinvite"), true,
                      "emergency access: server re-invite accepts an empty success response")

        EmergencyAccessTransport.state.withLock { $0.trustedStatus = 1; $0.mismatchedKeyID = true }
        guard let accepted = try await repository.list(lease: lease).trusted.first else { throw EmergencyFixtureError.missingContact }
        await runner.expectThrowsErrorAsync(EmergencyAccessError.unsupportedKey, "emergency access: public key must belong to the reviewed user ID") {
            _ = try await repository.prepareConfirmation(for: accepted, lease: lease)
        }
        EmergencyAccessTransport.state.withLock { $0.mismatchedKeyID = false }
        let prepared = try await repository.prepareConfirmation(for: accepted, lease: lease)
        let beforeMismatch = EmergencyAccessTransport.callCount
        await runner.expectThrowsErrorAsync(EmergencyAccessError.fingerprintMismatch, "emergency access: no confirmation without fingerprint match") {
            try await repository.confirm(prepared, verifiedFingerprint: "not-matching")
        }
        runner.expect(EmergencyAccessTransport.callCount, beforeMismatch, "emergency access: failed fingerprint never dispatches")
        // Changing the public-key endpoint after review must not substitute an unverified key.
        EmergencyAccessTransport.state.withLock { $0.publicKey = sdkSPKI.base64EncodedString() }
        await runner.expectThrowsErrorAsync(EmergencyAccessError.contactChanged, "emergency access: key rotation requires a fresh review") {
            try await repository.confirm(prepared, verifiedFingerprint: prepared.fingerprint)
        }
        runner.expect(EmergencyAccessTransport.lastMutation?.path.hasSuffix("/confirm"), false,
                      "emergency access: key rotation blocks confirmation before dispatch")
        EmergencyAccessTransport.state.withLock { $0.publicKey = fixturePublicKey }
        try await repository.confirm(prepared, verifiedFingerprint: prepared.fingerprint)
        let confirm = EmergencyAccessTransport.lastMutation
        runner.expect(confirm?.path.hasSuffix("/confirm"), true, "emergency access: confirmation uses exact endpoint")
        runner.expect(confirm?.keys, ["key"], "emergency access: confirm sends only the wrapped key")
        guard let wire = confirm?.wrappedKey else { throw EmergencyFixtureError.missingWrappedKey }
        runner.expect(try rsa.decryptForTest(EncString(parsing: wire)), Fixtures.userKeyData(),
                      "emergency access: confirmation wraps the current account key to the reviewed key only")

        try await repository.perform(.request, on: granted, lease: lease)
        runner.expect(EmergencyAccessTransport.lastMutation?.path.hasSuffix("/initiate"), true, "emergency access: initiate endpoint")
        list = try await repository.list(lease: lease)
        runner.expect(list.granted.first?.status, .recoveryInitiated, "emergency access: no local timer promotes pending status")
        EmergencyAccessTransport.state.withLock { $0.trustedStatus = 3 }
        guard let pending = try await repository.list(lease: lease).trusted.first else { throw EmergencyFixtureError.missingContact }
        try await repository.perform(.approve, on: pending, lease: lease)
        runner.expect(EmergencyAccessTransport.lastMutation?.path.hasSuffix("/approve"), true, "emergency access: approve endpoint")
        guard let approved = try await repository.list(lease: lease).trusted.first else { throw EmergencyFixtureError.missingContact }
        try await repository.perform(.reject, on: approved, lease: lease)
        runner.expect(EmergencyAccessTransport.lastMutation?.path.hasSuffix("/reject"), true, "emergency access: rejection can revert an approved request")
        guard let confirmed = try await repository.list(lease: lease).trusted.first else { throw EmergencyFixtureError.missingContact }
        try await repository.perform(.revoke, on: confirmed, lease: lease)
        runner.expect(EmergencyAccessTransport.lastMutation?.method, "DELETE", "emergency access: revoke endpoint uses DELETE")
        runner.expect(try await repository.list(lease: lease).trusted.isEmpty, true, "emergency access: revoked contact removed by server")

        EmergencyAccessTransport.state.withLock { $0.grantedStatus = 4 }
        guard let grant = try await repository.list(lease: lease).granted.first else { throw EmergencyFixtureError.missingContact }
        let index = try await repository.viewIndex(for: grant, lease: lease)
        runner.expect(index.items.map(\.name), ["Legacy note", "Protected login"],
                      "emergency access: view decrypts personal legacy fields and fields behind a per-item key")
        runner.expect(index.unsupportedItemCount, 2, "emergency access: malformed and permission-restricted items are not decrypted")
        let beforeWrongPassword = EmergencyAccessTransport.callCount
        await runner.expectThrowsErrorAsync(EmergencyAccessError.passwordIncorrect, "emergency access: incorrect local password does not reveal") {
            _ = try await repository.readItem(id: EmergencyAccessTransport.loginID, from: grant, lease: lease, masterPassword: "wrong")
        }
        runner.expect(EmergencyAccessTransport.callCount, beforeWrongPassword, "emergency access: no view API after failed password check")
        let details = try await repository.readItem(id: EmergencyAccessTransport.loginID, from: grant,
                                                   lease: lease, masterPassword: Fixtures.password)
        runner.expect(details.fields.first(where: { $0.label == "Password" })?.value, "synthetic secret",
                      "emergency access: opens only the selected field-level cipher")
        runner.expect(try await container.store.allCiphers(accountID: lease.accountID).count, accountItemsBefore,
                      "emergency access: no decrypted or grantor items are persisted in the active vault")
        let ownAccountStillOpen = try await container.keyVault.decryptString(SymmetricCrypto.encrypt(Data("own vault".utf8), using: accountKey))
        runner.expect(ownAccountStillOpen, "own vault", "emergency access: grantor key never replaces the user's KeyVault")
        EmergencyAccessTransport.state.withLock { $0.grantedStatus = 2 }
        await runner.expectThrowsErrorAsync(EmergencyAccessError.contactChanged, "emergency access: server revocation invalidates a previously opened index") {
            _ = try await repository.readItem(id: EmergencyAccessTransport.loginID, from: grant,
                                              lease: lease, masterPassword: Fixtures.password)
        }

        // Hold a list response until after AuthRepository has revoked its API context.
        let gate = DispatchSemaphore(value: 0)
        let blockedCall = AsyncStream<Void>.makeStream()
        EmergencyAccessTransport.state.withLock { $0.trustedListBarrier = .init(gate: gate, started: blockedCall.continuation) }
        let inFlight = Task { try await repository.list(lease: lease) }
        let timeout = Task {
            try? await Task.sleep(for: .seconds(5))
            blockedCall.continuation.finish()
        }
        var blockedCalls = blockedCall.stream.makeAsyncIterator()
        let didBlock = await blockedCalls.next() != nil
        timeout.cancel()
        await auth.lock()
        gate.signal()
        runner.expectTrue(didBlock, "emergency access: test held an in-flight request")
        await runner.expectThrowsErrorAsync(EmergencyAccessError.sessionChanged, "emergency access: response returned after lock is discarded") {
            _ = try await inFlight.value
        }
        try await auth.unlockWithMasterPassword(Fixtures.password)
        let beforeStaleLease = EmergencyAccessTransport.callCount
        await runner.expectThrowsErrorAsync(EmergencyAccessError.sessionChanged, "emergency access: old lease cannot survive lock and re-unlock") {
            _ = try await repository.list(lease: lease)
        }
        runner.expect(EmergencyAccessTransport.callCount, beforeStaleLease, "emergency access: stale lease does not reach the network")
        runner.expect(EmergencyAccessTransport.state.withLock { $0.unexpectedRequests }, 0,
                      "emergency access: every authenticated call uses the expected host, method and bearer")
    } catch {
        runner.expectTrue(false, "emergency access: unexpected synthetic fixture failure (\(error))")
    }
}

private extension TestRunner {
    mutating func expectThrowsError(_ expected: EmergencyAccessError, _ message: String, _ body: () throws -> Void) {
        do { try body(); expectTrue(false, message) }
        catch { expect(error as? EmergencyAccessError, expected, message) }
    }
}

private enum EmergencyFixtureError: Error {
    case rsa, missingLease, missingContact, missingWrappedKey
}

private struct EmergencyRSAFixture {
    private let privateKey: SecKey
    let spki: Data
    let pkcs8: Data

    init() throws {
        let attrs = [kSecAttrKeyType as String: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits as String: 2_048] as CFDictionary
        guard let privateKey = SecKeyCreateRandomKey(attrs, nil), let publicKey = SecKeyCopyPublicKey(privateKey),
              let publicPKCS1 = SecKeyCopyExternalRepresentation(publicKey, nil),
              let privatePKCS1 = SecKeyCopyExternalRepresentation(privateKey, nil) else { throw EmergencyFixtureError.rsa }
        let algorithm = Data([0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 1, 5, 0])
        spki = Self.der(0x30, algorithm + Self.der(0x03, Data([0]) + (publicPKCS1 as Data)))
        pkcs8 = Self.der(0x30, Data([2, 1, 0]) + algorithm + Self.der(0x04, privatePKCS1 as Data))
        self.privateKey = privateKey
    }

    func decryptForTest(_ wrapped: EncString) throws -> Data {
        guard let opened = SecKeyCreateDecryptedData(privateKey, .rsaEncryptionOAEPSHA1, wrapped.ciphertext as CFData, nil) else {
            throw EmergencyFixtureError.rsa
        }
        return opened as Data
    }

    func wrapForTest(_ key: Data, type: EncryptionType) throws -> EncString {
        guard let publicKey = SecKeyCopyPublicKey(privateKey),
              let wrapped = SecKeyCreateEncryptedData(publicKey, .rsaEncryptionOAEPSHA256, key as CFData, nil) else {
            throw EmergencyFixtureError.rsa
        }
        return EncString(type: type, iv: nil, ciphertext: wrapped as Data, mac: nil)
    }

    private static func der(_ tag: UInt8, _ data: Data) -> Data {
        Data([tag, 0x82, UInt8(data.count >> 8), UInt8(data.count & 0xff)]) + data
    }
}

private final class EmergencyAccessTransport: URLProtocol, @unchecked Sendable {
    static let trustedID = UUID(uuidString: "11111111-1111-4111-8111-111111111111")!
    static let grantedID = UUID(uuidString: "22222222-2222-4222-8222-222222222222")!
    static let contactID = UUID(uuidString: "33333333-3333-4333-8333-333333333333")!
    static let invitationID = UUID(uuidString: "44444444-4444-4444-8444-444444444444")!
    static let loginID = UUID(uuidString: "55555555-5555-4555-8555-555555555555")!

    struct Mutation: Sendable {
        let method: String
        let path: String
        let keys: [String]
        let hasQuery: Bool
        let email: String?
        let waitTime: Int?
        let type: Int?
        let token: String?
        let wrappedKey: String?
    }

    struct Barrier: Sendable {
        let gate: DispatchSemaphore
        let started: AsyncStream<Void>.Continuation
    }

    struct State: Sendable {
        var trustedStatus: Int? = 1
        var grantedStatus = 2
        var trustedWaitTime = 7
        var callCount = 0
        var unexpectedRequests = 0
        var lastMutation: Mutation?
        var publicKey = ""
        var privateKey = ""
        var wrappedKey = ""
        var ciphers = Data()
        var mismatchedKeyID = false
        var trustedListBarrier: Barrier?
    }

    static let state = OSAllocatedUnfairLock(initialState: State())
    static var lastMutation: Mutation? { state.withLock { $0.lastMutation } }
    static var callCount: Int { state.withLock { $0.callCount } }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let url = request.url else { return }
        let method = request.httpMethod ?? ""
        let body = request.httpBody ?? Self.readBody(request.httpBodyStream)
        let bearer = request.value(forHTTPHeaderField: "Authorization")
        let (result, barrier) = Self.state.withLock { state in
            let result = Self.handle(url: url, method: method, body: body, bearer: bearer, state: &state)
            let barrier = url.path == "/api/emergency-access/trusted" ? state.trustedListBarrier : nil
            if barrier != nil { state.trustedListBarrier = nil }
            return (result, barrier)
        }
        if let barrier {
            barrier.started.yield(())
            _ = barrier.gate.wait(timeout: .now() + 5)
        }
        let response = HTTPURLResponse(url: url, statusCode: result.0, httpVersion: "HTTP/1.1",
                                       headerFields: ["Content-Type": "application/json"])!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        if !result.1.isEmpty { client?.urlProtocol(self, didLoad: result.1) }
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}

    private static func handle(url: URL, method: String, body: Data, bearer: String?, state: inout State) -> (Int, Data) {
        state.callCount += 1
        guard url.host == Fixtures.server.base.host, url.scheme == "https", url.query == nil, url.fragment == nil else {
            state.unexpectedRequests += 1
            return (422, Data())
        }
        switch (method, url.path) {
        case ("POST", "/identity/accounts/prelogin"):
            return (200, try! JSONEncoder().encode(Fixtures.prelogin()))
        case ("POST", "/identity/connect/token"):
            let grant = Fixtures.tokenResponse()
            if String(decoding: body, as: UTF8.self).contains("grant_type=refresh_token") {
                return json(["access_token": grant.accessToken, "refresh_token": "refresh-1", "expires_in": 3_600, "token_type": "Bearer"])
            }
            var data = try! JSONSerialization.jsonObject(with: JSONEncoder().encode(grant)) as! [String: Any]
            data["PrivateKey"] = state.privateKey
            return json(data)
        default:
            guard bearer == "Bearer access-1" else { state.unexpectedRequests += 1; return (401, Data()) }
        }
        let root = "/api/emergency-access"
        let trusted = "\(root)/\(trustedID.uuidString.lowercased())"
        let granted = "\(root)/\(grantedID.uuidString.lowercased())"
        let invite = "\(root)/\(invitationID.uuidString.lowercased())"
        if method != "GET" {
            let object = (try? JSONSerialization.jsonObject(with: body)) as? [String: Any] ?? [:]
            state.lastMutation = .init(method: method, path: url.path, keys: object.keys.sorted(),
                                       hasQuery: url.query != nil || url.fragment != nil, email: object["email"] as? String,
                                       waitTime: object["waitTimeDays"] as? Int, type: object["type"] as? Int,
                                       token: object["token"] as? String, wrappedKey: object["key"] as? String)
        }
        switch (method, url.path) {
        case ("GET", "\(root)/trusted"):
            return json(["object": "list", "data": state.trustedStatus.map { [trustedContact($0, wait: state.trustedWaitTime)] } ?? [],
                         "continuationToken": NSNull()])
        case ("GET", "\(root)/granted"):
            return json(["Object": "list", "Data": [grantedContact(state.grantedStatus),
                                                   grantedContact(2, type: 1, id: "66666666-6666-4666-8666-666666666666"),
                                                   grantedContact(99, type: 66, id: "77777777-7777-4777-8777-777777777777")],
                         "ContinuationToken": NSNull()])
        case ("GET", trusted):
            guard let status = state.trustedStatus else { return (400, Data()) }
            return json(trustedContact(status, wait: state.trustedWaitTime))
        case ("GET", "/api/users/\(contactID.uuidString.lowercased())/public-key"):
            return json(["object": "userKey", "userId": state.mismatchedKeyID ? invitationID.uuidString : contactID.uuidString,
                         "publicKey": state.publicKey])
        case ("POST", "\(root)/invite"), ("POST", "\(trusted)/reinvite"):
            return (204, Data())
        case ("POST", "\(invite)/accept"):
            if state.lastMutation?.token == "aaa.bbb.ccc" { return (200, Data()) }
            return (400, Data("echoed token \(state.lastMutation?.token ?? "")".utf8))
        case ("PUT", trusted):
            guard let wait = state.lastMutation?.waitTime, let status = state.trustedStatus else { return (400, Data()) }
            state.trustedWaitTime = wait
            return mutation(id: trustedID, status: status, wait: wait)
        case ("POST", "\(trusted)/confirm"):
            state.trustedStatus = 2
            return mutation(id: trustedID, status: 2, wait: state.trustedWaitTime)
        case ("POST", "\(granted)/initiate"):
            state.grantedStatus = 3
            return mutation(id: grantedID, status: 3, wait: 9)
        case ("POST", "\(trusted)/approve"):
            state.trustedStatus = 4
            return mutation(id: trustedID, status: 4, wait: state.trustedWaitTime)
        case ("POST", "\(trusted)/reject"):
            state.trustedStatus = 2
            return mutation(id: trustedID, status: 2, wait: state.trustedWaitTime)
        case ("DELETE", trusted):
            state.trustedStatus = nil
            return (200, Data())
        case ("POST", "\(granted)/view") where state.grantedStatus == 4:
            let ciphers = try! JSONSerialization.jsonObject(with: state.ciphers)
            return json(["object": "emergencyAccessView", "keyEncrypted": state.wrappedKey, "ciphers": ciphers])
        default:
            state.unexpectedRequests += 1
            return (404, Data())
        }
    }

    static func cipherFixtures(grantorKey: SymmetricCryptoKey) throws -> Data {
        func enc(_ text: String, _ key: SymmetricCryptoKey) throws -> String {
            try SymmetricCrypto.encrypt(Data(text.utf8), using: key).stringValue
        }
        let itemBytes = Data(repeating: 29, count: 64)
        let itemKey = try SymmetricCryptoKey(combined: itemBytes)
        let protected = try SymmetricCrypto.encrypt(itemBytes, using: grantorKey)
        let legacy: [String: Any] = ["id": "88888888-8888-4888-8888-888888888888", "type": 2,
            "organizationId": NSNull(), "name": try enc("Legacy note", grantorKey), "notes": try enc("Synthetic note", grantorKey),
            "favorite": false, "reprompt": 0, "viewPassword": true, "revisionDate": "2026-10-01T02:03:04.000000Z"]
        let login: [String: Any] = ["id": loginID.uuidString, "type": 1, "OrganizationId": NSNull(), "key": protected.stringValue,
            "name": try enc("Protected login", itemKey), "favorite": false, "reprompt": 1, "viewPassword": true,
            "login": ["username": try enc("fixture-user", itemKey), "password": try enc("synthetic secret", itemKey)],
            "revisionDate": "2026-10-01T02:03:04Z"]
        var organization = legacy
        organization["id"] = "99999999-9999-4999-8999-999999999999"
        organization["organizationId"] = "aaaa1111-1111-4111-8111-111111111111"
        var ambiguousOwner = legacy
        ambiguousOwner["id"] = "bbbb1111-1111-4111-8111-111111111111"
        ambiguousOwner.removeValue(forKey: "organizationId")
        var denied = legacy
        denied["id"] = "cccc1111-1111-4111-8111-111111111111"
        denied["viewPassword"] = false
        var deleted = legacy
        deleted["id"] = "dddd1111-1111-4111-8111-111111111111"
        deleted["deletedDate"] = "2026-10-02T02:03:04Z"
        return try JSONSerialization.data(withJSONObject: [legacy, login, organization, ambiguousOwner, denied, deleted,
                                                           ["id": "malformed"]])
    }

    private static func trustedContact(_ status: Int, wait: Int) -> [String: Any] {
        ["object": "emergencyAccessGranteeDetails", "id": trustedID.uuidString, "granteeId": contactID.uuidString,
         "email": "trusted@example.test", "name": "Synthetic Trust", "status": status, "type": 0, "waitTimeDays": wait]
    }

    private static func grantedContact(_ status: Int, type: Int = 0, id: String = grantedID.uuidString) -> [String: Any] {
        ["Object": "emergencyAccessGrantorDetails", "Id": id, "GrantorId": contactID.uuidString,
         "Email": "grantor@example.test", "Status": status, "Type": type, "WaitTimeDays": 9]
    }

    private static func mutation(id: UUID, status: Int, wait: Int) -> (Int, Data) {
        json(["object": "emergencyAccess", "id": id.uuidString, "status": status, "type": 0, "waitTimeDays": wait])
    }

    private static func json(_ object: Any) -> (Int, Data) {
        (200, try! JSONSerialization.data(withJSONObject: object))
    }

    private static func readBody(_ stream: InputStream?) -> Data {
        guard let stream else { return Data() }
        stream.open()
        defer { stream.close() }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 4_096)
        while true {
            let count = stream.read(&buffer, maxLength: buffer.count)
            guard count > 0 else { return data }
            data.append(buffer, count: count)
        }
    }
}
