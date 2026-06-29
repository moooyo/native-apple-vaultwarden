import Foundation
import CryptoCore
import Networking
import SyncEngine

/// Unit checks for the small pure helpers, plus the OutboxCipherPayload round-trip.
func checkHelpers(_ r: inout TestRunner) {
    // serverIsNewer: strict, parse-tolerant.
    let base = Date(timeIntervalSince1970: 1_750_000_000)
    let baseStr = Fixtures.iso(base)
    r.expectTrue(SyncEngine.serverIsNewer(serverDate: base.addingTimeInterval(1), storedDate: baseStr),
                 "serverIsNewer: +1s is newer")
    r.expectTrue(!SyncEngine.serverIsNewer(serverDate: base.addingTimeInterval(-1), storedDate: baseStr),
                 "serverIsNewer: -1s is NOT newer")
    r.expectTrue(!SyncEngine.serverIsNewer(serverDate: base, storedDate: baseStr),
                 "serverIsNewer: equal is NOT newer (strict)")
    r.expectTrue(SyncEngine.serverIsNewer(serverDate: base, storedDate: "not-a-date"),
                 "serverIsNewer: unparseable stored date → treat server as newer")

    // isConflict classification.
    r.expectTrue(SyncEngine.isConflict(400), "400 is a conflict")
    r.expectTrue(SyncEngine.isConflict(409), "409 is a conflict")
    r.expectTrue(SyncEngine.isConflict(404), "404 is a conflict")
    r.expectTrue(!SyncEngine.isConflict(500), "500 is NOT a conflict")

    // OutboxCipherPayload JSON round-trip + reconstitution into a CipherRequest.
    // `Fixtures.enc` uses a random IV per call, so capture each wire string once and
    // reuse it for both construction and assertion.
    do {
        let nameWire = Fixtures.enc("Round Trip")
        let userWire = Fixtures.enc("bob")
        let uriWire = Fixtures.enc("https://rt.test")
        let payload = OutboxCipherPayload(
            type: 1,
            name: nameWire,
            notes: Fixtures.enc("a note"),
            favorite: true,
            login: .init(username: userWire,
                         uris: [.init(uri: uriWire, match: 0)])
        )
        let json = try payload.encodedJSON()
        let back = try OutboxCipherPayload.decode(json)
        r.expect(back, payload, "OutboxCipherPayload survives JSON round-trip")

        let last = Date(timeIntervalSince1970: 1_750_000_000)
        let req = try back.cipherRequest(lastKnownRevisionDate: last)
        r.expect(req.type, 1, "reconstituted request type")
        r.expect(req.name.stringValue, nameWire, "reconstituted request name wire string")
        r.expect(req.favorite, true, "reconstituted request favorite")
        r.expect(req.login?.username?.stringValue, userWire,
                 "reconstituted request login username")
        r.expect(req.login?.uris?.first?.match, 0, "reconstituted request uri match")
        r.expectTrue(req.lastKnownRevisionDate == last, "reconstituted request carries lastKnownRevisionDate")
    } catch {
        r.expectTrue(false, "OutboxCipherPayload round-trip threw: \(error)")
    }

    // registerBackgroundRefresh is compile-only; calling it must not crash.
    // (Constructed lazily so we don't need an engine instance here.)
}
