import Foundation
import VaultModels
import CryptoCore

func checkAuth(_ r: inout TestRunner) {
    let decoder = VaultJSON.decoder()

    // PreloginResponse — camelCase
    do {
        let p = try decoder.decode(PreloginResponse.self, from: TestJSON.preloginCamel.data(using: .utf8)!)
        r.expect(p.kdf, 0, "prelogin camel kdf")
        r.expect(p.kdfIterations, 600000, "prelogin camel iterations")
        r.expectTrue(p.kdfMemory == nil, "prelogin camel memory nil")
        r.expectTrue(p.kdfParallelism == nil, "prelogin camel parallelism nil")
    } catch { r.expectTrue(false, "prelogin camel threw: \(error)") }

    // PreloginResponse — PascalCase
    do {
        let p = try decoder.decode(PreloginResponse.self, from: TestJSON.preloginPascal.data(using: .utf8)!)
        r.expect(p.kdf, 0, "prelogin pascal kdf")
        r.expect(p.kdfIterations, 600000, "prelogin pascal iterations")
    } catch { r.expectTrue(false, "prelogin pascal threw: \(error)") }

    // TokenResponse — camelCase variant (vault fields PascalCase here)
    do {
        let t = try decoder.decode(TokenResponse.self, from: TestJSON.tokenCamel().data(using: .utf8)!)
        r.expect(t.accessToken, "AT-123", "token camel access_token")
        r.expect(t.expiresIn, 3600, "token camel expires_in")
        r.expect(t.refreshToken, "RT-456", "token camel refresh_token")
        r.expect(t.tokenType, "Bearer", "token camel token_type")
        r.expectTrue(t.key != nil, "token camel key decodes to EncString")
        r.expectTrue(t.privateKey != nil, "token camel privateKey decodes to EncString")
        r.expect(t.kdf, 0, "token camel kdf")
        r.expect(t.kdfIterations, 600000, "token camel kdfIterations")
    } catch { r.expectTrue(false, "token camel threw: \(error)") }

    // TokenResponse — PascalCase variant (vault fields camelCase here)
    do {
        let t = try decoder.decode(TokenResponse.self, from: TestJSON.tokenPascal().data(using: .utf8)!)
        r.expect(t.accessToken, "AT-789", "token pascal access_token")
        r.expect(t.expiresIn, 7200, "token pascal expires_in")
        r.expectTrue(t.key != nil, "token pascal key decodes to EncString")
        r.expectTrue(t.privateKey != nil, "token pascal privateKey decodes to EncString")
        r.expect(t.kdfIterations, 650000, "token pascal kdfIterations")
    } catch { r.expectTrue(false, "token pascal threw: \(error)") }
}
