import Foundation
import VaultRepository

func checkSendShareLinks(_ runner: inout TestRunner) {
    let base = URL(string: "https://vault.example.test:8443/passwords/vault")!
    let accessID = "ct2APRQtJk-BLLDwAYqhRA"
    let seed = Data(base64Encoded: "Pgui0FK85cNhBGWHAlBHBw==")!
    do {
        let link = try SendRepository.shareURL(base: base, accessID: accessID, secret: seed)
        runner.expect(link.absoluteString, "https://vault.example.test:8443/passwords/vault/#/send/ct2APRQtJk-BLLDwAYqhRA/Pgui0FK85cNhBGWHAlBHBw",
                      "Send link preserves self-hosted path and contains its key only in the fragment")
        runner.expect(link.query, nil, "Send key is never included in the query")
    } catch {
        runner.expectTrue(false, "Send link fixture: \(error)")
    }
    do {
        _ = try SendRepository.shareURL(base: base, accessID: "?next=/", secret: seed)
        runner.expectTrue(false, "a malformed server access ID cannot become a share link")
    } catch VaultSendError.invalidLink {
        runner.expectTrue(true, "reject unsafe access IDs")
    } catch {
        runner.expectTrue(false, "unexpected Send URL error")
    }
}
