import Foundation
@testable import CryptoCore

func checkPBKDF2(_ r: inout TestRunner) {
    // test_goldenVector_iters1
    do {
        let out = try PBKDF2.deriveSHA256(password: Data("password".utf8),
                                          salt: Data("salt".utf8),
                                          iterations: 1, keyLength: 32)
        r.expect(Data(out).hexString,
                 "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
                 "PBKDF2 golden vector iters=1")
    } catch {
        r.expectTrue(false, "PBKDF2 iters=1 threw: \(error)")
    }

    // test_goldenVector_iters2
    do {
        let out = try PBKDF2.deriveSHA256(password: Data("password".utf8),
                                          salt: Data("salt".utf8),
                                          iterations: 2, keyLength: 32)
        r.expect(Data(out).hexString,
                 "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43",
                 "PBKDF2 golden vector iters=2")
    } catch {
        r.expectTrue(false, "PBKDF2 iters=2 threw: \(error)")
    }
}
