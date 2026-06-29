import Foundation
import VaultModels
import CryptoCore

/// Gated check: decode a real captured `/api/sync` payload and assert no ciphers
/// were dropped. Skipped unless `TESSERA_FIXTURES=1` and the fixture file exists.
/// See `Fixtures/README.md` for the capture procedure. The `Fixtures/` directory
/// is excluded from the build target, so the file is read from disk at runtime,
/// resolved relative to this source file.
func checkRealSyncFixture(_ r: inout TestRunner) {
    guard ProcessInfo.processInfo.environment["TESSERA_FIXTURES"] == "1" else {
        return // skipped: fixtures not requested
    }

    let here = URL(fileURLWithPath: #filePath)
    let fixture = here
        .deletingLastPathComponent()
        .appendingPathComponent("Fixtures/sync-vaultwarden.json")

    guard FileManager.default.fileExists(atPath: fixture.path) else {
        print("SKIP  real sync fixture not found at \(fixture.path)")
        return
    }

    do {
        let data = try Data(contentsOf: fixture)
        let s = try VaultJSON.decoder().decode(SyncResponse.self, from: data)
        r.expect(s.droppedCipherErrors.count, 0, "real sync: no dropped ciphers")
        r.expectTrue(s.ciphers.count >= 1, "real sync: at least one cipher")
        r.expectTrue(s.folders.count >= 1, "real sync: at least one folder")
    } catch {
        r.expectTrue(false, "real sync fixture decode threw: \(error)")
    }
}
