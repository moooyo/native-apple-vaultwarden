import Foundation
import UIShared

func checkOnePasswordTransfer(_ runner: inout TestRunner) {
    let deflated = """
    UEsDBBQAAAAIAAAAIVD/mnpAOAAAADoAAAARAAAAZXhwb3J0LmF0dHJpYnV0ZXOrVipLLSrOzM9TsjLWUUpJLU4uyiwo
    AfOVDAMSi4vL84tSFELzUvOSiyoLSlJTFFwrCvKLSpRqAVBLAwQUAAAACAAAACFQNJdRlVYBAABWAgAACwAAAGV4cG9y
    dC5kYXRhZZFta8IwEMe/itxrnbq+68sxZW4wC3a4MWSE9HRhaVKSS7UUv/surd0jhZB7+P3zv2sLQkobDHlIX1uoRdCX
    qyByfGshBFVACmLSFWEMRpTIicypWhBygpqqS8B5DIqw7AU8xSqDklQd2yTHB+uap15wNptzci/qlSnwBGkyBlujqxUe
    47OkSEd8cRJlpSMfnOb4najy6XSKff6K0EdTJA7xWdha9wE7NlIgCaW7CYzlpkwLZZhfqhMFhyNrdMOctgdllgp10bu+D
    Iclw1yuhQ4x3vcURF2vDkaQslEteHQdwpNEkbxfRc6raL/gAks7qYT3//CYPFpX/MF5k7sxeJSxrfc1rGODMjhFzUD8rq
    4NTkiVOJK2iJ66RefrPHubfw/D7ZYqLtzfbLYvyW22uMsekuyZX42uB61s9TgoyODJlj8VpDUShcbuR86vE0Z3/HXH7vwJ
    UEsBAhQAFAAAAAgAAAAhUP+aekA4AAAAOgAAABEAAAAAAAAAAAAAAIABAAAAAGV4cG9ydC5hdHRyaWJ1dGVzUEsBAhQAFAAA
    AAgAAAAhUDSXUZVWAQAAVgIAAAsAAAAAAAAAAAAAAIABZwAAAGV4cG9ydC5kYXRhUEsFBgAAAAACAAIAeAAAAOYBAAAAAA==
    """
    let document = """
    UEsDBBQAAAAAAAAAIVD/mnpAOgAAADoAAAARAAAAZXhwb3J0LmF0dHJpYnV0ZXN7InZlcnNpb24iOjMsImRlc2NyaXB0aW9u
    IjoiMVBhc3N3b3JkIFVuZW5jcnlwdGVkIEV4cG9ydCJ9UEsDBBQAAAAAAAAAIVC/YcxuwAAAAMAAAAALAAAAZXhwb3J0LmRh
    dGF7ImFjY291bnRzIjpbeyJ2YXVsdHMiOlt7ImF0dHJzIjp7InV1aWQiOiJhLXZhdWx0IiwibmFtZSI6IlByaXZhdGUiLCJ0
    eXBlIjoiUCJ9LCJpdGVtcyI6W3sic3RhdGUiOiJhY3RpdmUiLCJjYXRlZ29yeVV1aWQiOiIwMDYiLCJmYXZJbmRleCI6Mywi
    b3ZlcnZpZXciOnsidGl0bGUiOiJEb2N1bWVudCJ9LCJkZXRhaWxzIjp7fX1dfV19XX1QSwECFAAUAAAAAAAAACFQ/5p6QDoA
    AAA6AAAAEQAAAAAAAAAAAAAAgAEAAAAAZXhwb3J0LmF0dHJpYnV0ZXNQSwECFAAUAAAAAAAAACFQv2HMbsAAAADAAAAACwAAAAAA
    AAAAAAAAgAFpAAAAZXhwb3J0LmRhdGFQSwUGAAAAAAIAAgB4AAAAUgEAAAAA
    """
    guard let compressed = Data(base64Encoded: deflated, options: .ignoreUnknownCharacters),
          let unsupported = Data(base64Encoded: document, options: .ignoreUnknownCharacters) else {
        runner.expectTrue(false, "1PUX fixtures decode")
        return
    }
    do {
        let archive = try OnePasswordTransfer.decode(compressed)
        let item = archive.items.first
        runner.expect(archive.folders.first?.name, "Private", "1PUX imports the vault as a folder")
        runner.expect(item?.folderID, archive.folders.first?.id, "1PUX binds the item to its original vault")
        runner.expect(item?.favorite, true, "1PUX accepts any positive favorite index")
        runner.expect(item?.login?.username, "fixture", "1PUX preserves designated form fields")
        runner.expect(item?.login?.password, "demo-pass", "1PUX imports the password")
        runner.expect(item?.login?.uris.first?.uri, "https://example.test", "1PUX imports the primary URL")
        runner.expect(item?.login?.totp, "JBSWY3DPEHPK3PXP", "1PUX preserves the OTP seed")
        runner.expect(item?.fields.first(where: { $0.name == "Security / PIN" })?.type, 1, "1PUX preserves hidden field semantics")
    } catch { runner.expectTrue(false, "1PUX imports a standard deflated archive") }
    checkRejected(unsupported, as: .unsupportedItem, runner: &runner)
    checkRejected(Data(compressed.dropLast(3)), as: .invalidFile, runner: &runner)
    var oversized = compressed
    if let central = compressed.range(of: Data([0x50, 0x4b, 0x01, 0x02])) {
        oversized.replaceSubrange(central.lowerBound + 24..<central.lowerBound + 28, with: [255, 255, 255, 127])
        checkRejected(oversized, as: .fileTooLarge, runner: &runner)
    } else { runner.expectTrue(false, "1PUX fixture has a central directory") }
}

private func checkRejected(_ data: Data, as expected: VaultTransferError, runner: inout TestRunner) {
    do {
        _ = try OnePasswordTransfer.decode(data)
        runner.expectTrue(false, "1PUX rejects unsupported or invalid input")
    } catch {
        runner.expect(error as? VaultTransferError, expected, "1PUX reports the right import failure")
    }
}
