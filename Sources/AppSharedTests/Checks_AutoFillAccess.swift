import AppShared
import Foundation

func checkAutoFillAccess(_ runner: inout TestRunner) {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    do {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("owner")
        let owner = AutoFillAccessGate(url: url)
        let reader = AutoFillAccessGate(url: url)
        let first = UUID().uuidString
        let second = UUID().uuidString
        runner.expectTrue(!reader.permits(sessionID: first), "AutoFill: missing owner fails closed")
        runner.expectTrue(owner.activate(sessionID: first), "AutoFill: unlock publishes a held permit")
        runner.expectTrue(reader.permits(sessionID: first), "AutoFill: reader validates the live permit")
        runner.expectTrue(!reader.permits(sessionID: second), "AutoFill: another generation cannot use the permit")
        runner.expectTrue(!reader.activate(sessionID: second), "AutoFill: second writer cannot steal a live permit")
        owner.deactivate()
        runner.expectTrue(!reader.permits(sessionID: first), "AutoFill: old marker alone is insufficient after lock")
        runner.expectTrue(owner.activate(sessionID: second), "AutoFill: owner can activate a new generation")
        runner.expectTrue(!reader.permits(sessionID: first) && reader.permits(sessionID: second), "AutoFill: old generation stays revoked")
    } catch {
        runner.expectTrue(false, "AutoFill permit fixture could not be opened: \(error)")
    }

    runner.expect(AutoFillWebsiteIdentity.value(for: "https://example.test/path?token=private#anchor", match: nil),
                  "https://example.test", "AutoFill publishes only the origin")
    runner.expect(AutoFillWebsiteIdentity.value(for: "https://example.test/path", match: 5), nil,
                  "AutoFill respects never-match")
    runner.expect(AutoFillWebsiteIdentity.value(for: "https://example.test/path", match: 3), nil,
                  "AutoFill does not widen exact-path matching")
}
