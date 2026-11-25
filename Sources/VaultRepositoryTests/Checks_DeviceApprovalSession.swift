import CryptoCore
import Foundation
import Networking
import VaultModels
@testable import VaultRepository

func checkDeviceApprovalSession(_ runner: inout TestRunner) async {
    let key = Fixtures.userKey()
    do {
        let wrappedPrivate = try SymmetricCrypto.encrypt(Data([0x30, 0x01, 0x02]), using: key)
        let token = TokenResponse(accessToken: "device-fixture-access", expiresIn: 300, refreshToken: "device-fixture-refresh",
                                  tokenType: "Bearer", key: try EncString(parsing: Fixtures.protectedUserKeyWire()),
                                  privateKey: wrappedPrivate, kdf: 0, kdfIterations: Fixtures.iterations)
        let harness = try await Fixtures.makeHarness(tokenResults: [Fixtures.twoFactorResult([0]), .success(token)])
        defer { Fixtures.cleanup(harness.dir) }
        let requestID = UUID()
        let grant = DeviceLoginGrant(requestID: requestID, accessCode: try DeviceLoginAccessCode.generate(),
                                     userKey: key, expiresAt: .now + .seconds(60))
        let challenge = try await harness.auth.acceptDeviceLogin(email: Fixtures.email, server: Fixtures.server, grant: grant)
        runner.expect(challenge, LoginResult.twoFactorRequired([.authenticator]), "Device approval does not bypass two-step login")
        runner.expectTrue(!(await harness.auth.isUnlocked()), "Pending device second factor does not unlock")
        runner.expectTrue(await harness.api.tokenCalls.isEmpty, "Device access code is not submitted as a master-password proof")
        let result = try await harness.auth.submitTwoFactor(provider: .authenticator, token: "123456", server: Fixtures.server)
        runner.expect(result, .success, "Approved device opens the personal vault after second factor")
        let calls = await harness.api.deviceTokenRequests
        runner.expect(calls.map(\.0), [requestID, requestID], "Device grant and second factor use the same request")
        runner.expect(calls.last?.1?.provider, .authenticator, "The retry sends the explicitly selected factor")
        runner.expectTrue(await harness.auth.isUnlocked(), "Verified account key is installed")
        await harness.auth.lock()
        try await harness.auth.unlockWithMasterPassword(Fixtures.password)
        runner.expectTrue(await harness.auth.isUnlocked(), "A real password can still unlock the protected account key offline")

        let expiredHarness = try await Fixtures.makeHarness(tokenResults: [.success(token)])
        defer { Fixtures.cleanup(expiredHarness.dir) }
        let expired = DeviceLoginGrant(requestID: UUID(), accessCode: try DeviceLoginAccessCode.generate(),
                                       userKey: key, expiresAt: .now - .seconds(1))
        await runner.expectThrowsAsync("An expired device grant cannot establish a session") {
            _ = try await expiredHarness.auth.acceptDeviceLogin(email: Fixtures.email, server: Fixtures.server, grant: expired)
        }
        runner.expectTrue(await expiredHarness.api.deviceTokenRequests.isEmpty, "Expired grants are never submitted")
    } catch { runner.expectTrue(false, "Device approval session fixture threw: \(error)") }
}
