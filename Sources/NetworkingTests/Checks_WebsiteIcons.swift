import CoreGraphics
import Foundation
import ImageIO
import Networking
import UniformTypeIdentifiers

func checkWebsiteIconLocation(_ runner: inout TestRunner) {
    let server = ServerEnvironment(base: URL(string: "https://vault.example.test:8443/proxy/a%2Fb/")!,
                                   apiURL: URL(string: "https://api.example.test/api")!)
    let rejected = [
        "ftp://site.com", "androidapp://site.com", "https://", "https://localhost",
        "https://device", "https://phone.local.", "https://router.home.arpa", "https://host.internal",
        "https://host.invalid", "https://user:password@site.com", "https://@site.com",
        "https://127.0.0.1:8443", "https://[2001:db8::1]", "https://[fe80::1%25en0]",
        "https://2130706433", "https://0x7f.0x0.0x0.0x1", "https://127.1", "https://127.0x1",
        "https://a..com", "https://_hello.com", "https://-hello.com", "https://hello-.com",
        "https://\(String(repeating: "a", count: 64)).com", "https://some%2fpath.com",
        "", "localhost", "a.local", "a.home.arpa", "127.0.0.1", "0x7f.0x1", "[2001:db8::1]",
        "site.com/", "site.com/path", "site.com\\path", "//site.com", "site.com:443", "user@site.com",
        "site.com?token=private", "site.com#account", "site%2ecom", "st%65.com", "site.com／path",
        "site.com：443", "si te.com", "site..com", "-site.com", "_user.site.com"
    ]
    for website in rejected {
        runner.expect(WebsiteIconLocation(server: server, websites: [website]), nil, "icons: rejects \(website)")
    }
    let location = WebsiteIconLocation(server: server, websites: rejected + [
        "  HTTPS://BÜCHER.DE.:9443/login?token=private#account  ", "https://later.com/"
    ])
    runner.expect(location?.url.absoluteString, "https://vault.example.test:8443/proxy/a%2Fb/icons/xn--bcher-kva.de/icon.png",
                  "icons: preserves the account origin and proxy subpath, passing only the first eligible domain")
    runner.expect(location, WebsiteIconLocation(server: server, websites: ["https://xn--bcher-kva.de/somewhere"]),
                  "icons: equivalent domains share a cache key")
    runner.expect(location, WebsiteIconLocation(server: server, websites: ["  BÜCHER。DE.  "]),
                  "icons: bare internationalized domains normalize to the same cache key as HTTP URLs")
    let bare = WebsiteIconLocation(server: server, websites: ["site.com/path", "  WWW.Site.COM. ", "https://later.com"])
    runner.expect(bare?.url.absoluteString, "https://vault.example.test:8443/proxy/a%2Fb/icons/www.site.com/icon.png",
                  "icons: first eligible bare domain wins and normalizes letters and trailing dot")
    let international = WebsiteIconLocation(server: server, websites: ["站点.公司"])
    runner.expect(international?.url.lastPathComponent, "icon.png", "icons: bare IDNA top-level domains are eligible")
    runner.expect(international?.url.deletingLastPathComponent().lastPathComponent, "xn--3pxx9s.xn--55qx5d",
                  "icons: both IDNA domain labels are sent in canonical ASCII form")
    for invalidServer in ["ftp://vault.example.test", "https://user:pass@vault.example.test",
                          "https://vault.example.test/?secret=value", "https://vault.example.test/#secret"] {
        let unsafe = ServerEnvironment(base: URL(string: invalidServer)!)
        runner.expect(WebsiteIconLocation(server: unsafe, websites: ["https://site.com"]), nil,
                      "icons: malformed server base cannot construct a request")
    }
}

func checkWebsiteIconClient(_ runner: inout TestRunner) async {
    guard let png = syntheticIcon(side: 160), let hugePNG = syntheticIcon(side: 1025),
          let ico = syntheticIcon(side: 32, type: .ico) else {
        runner.expectTrue(false, "icons: generated image fixtures")
        return
    }
    let server = ServerEnvironment(string: "https://vault.example.test:8443/proxy")!
    let valid = StubResponse(body: png, headers: ["Content-Type": "image/png", "Set-Cookie": "icon=fixture; Path=/; Secure"])
    let box = StubBox(response: valid)
    let stub = makeStubbedConfiguration(box: box)
    let cookies = HTTPCookieStorage()
    if let cookie = HTTPCookie(properties: [.name: "existing", .value: "fixture", .domain: ".vault.example.test",
                                            .path: "/", .secure: "TRUE"]) {
        cookies.setCookie(cookie)
    }
    stub.configuration.httpCookieStorage = cookies
    stub.configuration.httpShouldSetCookies = true
    let client = WebsiteIconClient(configuration: stub.configuration)
    let first = WebsiteIconLocation(server: server, websites: ["https://first.com/private?one=two"])!
    box.pauseResponses()
    let firstLookup = Task { await client.icon(for: first) }
    await waitForIconRequest(box)
    let duplicateLookup = Task { await client.icon(for: first) }
    box.resumeResponses()
    let firstImage = await firstLookup.value
    let duplicateImage = await duplicateLookup.value
    runner.expect(firstImage?.width, 128, "icons: valid PNG is downsampled")
    runner.expect(duplicateImage?.height, 128, "icons: two callers receive the thumbnail")
    runner.expect((await client.icon(for: first))?.width, 128, "icons: a later lookup uses the positive cache")
    runner.expect(box.capturedCount, 1, "icons: concurrent and cached lookups send just one request")
    runner.expect(box.captured?.path, "/proxy/icons/first.com/icon.png", "icons: request has no original website path")
    runner.expect(box.captured?.url.host, "vault.example.test", "icons: contacts only the account server")
    runner.expect(box.captured?.url.port, 8443, "icons: uses the configured reverse-proxy port")
    runner.expect(box.captured?.url.query, nil, "icons: request has no original website query")
    runner.expect(box.captured?.method, "GET", "icons: request is an unauthenticated GET")
    runner.expect(box.captured?.body, nil, "icons: request has no body")
    runner.expect(box.captured?.header("Authorization"), nil, "icons: sends no bearer")
    runner.expect(box.captured?.header("Cookie"), nil, "icons: sends no cookies")

    let alternate = WebsiteIconLocation(server: server, websites: ["https://alternate.com"])!
    box.response = StubResponse(body: ico, headers: ["Content-Type": "image/x-icon"])
    runner.expect((await client.icon(for: alternate))?.width, 32, "icons: supports the Vaultwarden ICO MIME type")
    runner.expect(box.captured?.header("Cookie"), nil, "icons: does not replay response cookies")

    let invalidResponses: [(String, StubResponse)] = [
        ("redirect", .init(statusCode: 302, body: png, headers: [
            "Content-Type": "image/png", "Location": "https://unrelated.invalid/icon.png"
        ])),
        ("declared-too-large", .init(body: png, headers: ["Content-Type": "image/png", "Content-Length": "300000"])),
        ("stream-too-large", .init(body: png + Data(repeating: 0, count: 256 * 1024), headers: ["Content-Type": "image/png"])),
        ("too-many-pixels", .init(body: hugePNG, headers: ["Content-Type": "image/png"])),
        ("mismatched-type", .init(body: png, headers: ["Content-Type": "image/jpeg"])),
        ("missing-type", .init(body: png, headers: [:])),
        ("non-raster", .init(body: Data("<svg/>".utf8), headers: ["Content-Type": "image/svg+xml"])),
        ("malformed-png", .init(body: Data("<html/>".utf8), headers: ["Content-Type": "image/png"]))
    ]
    for (label, response) in invalidResponses {
        box.response = response
        let location = WebsiteIconLocation(server: server, websites: ["https://\(label).com"])!
        let count = box.capturedCount
        runner.expectTrue(await client.icon(for: location) == nil, "icons: rejects \(label)")
        box.response = valid
        runner.expectTrue(await client.icon(for: location) == nil, "icons: negative cache retains \(label)")
        runner.expect(box.capturedCount, count + 1, "icons: no retry or onward request for \(label)")
    }

    let inactiveCount = box.capturedCount
    await client.invalidate()
    runner.expectTrue(await client.icon(for: first) == nil, "icons: invalidated clients never return cached data")
    runner.expect(box.capturedCount, inactiveCount, "icons: invalidation never restarts a request")
    StubRegistry.shared.remove(token: stub.token)
}

func checkWebsiteIconInvalidation(_ runner: inout TestRunner) async {
    guard let png = syntheticIcon(side: 4) else {
        runner.expectTrue(false, "icons: generated cancellation fixture")
        return
    }
    let server = ServerEnvironment(string: "https://vault.example.test")!
    let box = StubBox(response: StubResponse(body: png, headers: ["Content-Type": "image/png"]))
    let stub = makeStubbedConfiguration(box: box)
    defer { StubRegistry.shared.remove(token: stub.token) }
    let client = WebsiteIconClient(configuration: stub.configuration)
    let location = WebsiteIconLocation(server: server, websites: ["https://active.com"])!
    box.pauseResponses()
    let lookup = Task { await client.icon(for: location) }
    await waitForIconRequest(box)
    runner.expect(box.capturedCount, 1, "icons: there is a request in flight before invalidation")
    await client.invalidate()
    box.resumeResponses()
    runner.expectTrue(await lookup.value == nil, "icons: invalidation discards a late in-flight result")
    let other = WebsiteIconLocation(server: server, websites: ["https://after-invalidation.com"])!
    runner.expectTrue(await client.icon(for: other) == nil, "icons: invalidation rejects new requests")
    runner.expect(box.capturedCount, 1, "icons: only the original request touched the URL session")
}

func checkWebsiteIconRequestPermission(_ runner: inout TestRunner) async {
    guard let png = syntheticIcon(side: 4) else {
        runner.expectTrue(false, "icons: generated request permission fixture")
        return
    }
    let server = ServerEnvironment(string: "https://vault.example.test")!
    let first = WebsiteIconLocation(server: server, websites: ["https://first.com"])!
    let second = WebsiteIconLocation(server: server, websites: ["https://second.com"])!
    let box = StubBox(response: StubResponse(body: png, headers: ["Content-Type": "image/png"]))
    let stub = makeStubbedConfiguration(box: box)
    defer { StubRegistry.shared.remove(token: stub.token) }
    let permission = IconRequestPermission()
    let client = WebsiteIconClient(configuration: stub.configuration, requestIsAllowed: { await permission.isAllowed })

    runner.expectTrue(await client.icon(for: first) == nil, "icons: revoked permission prevents the first download")
    runner.expect(box.capturedCount, 0, "icons: denied downloads never touch URLSession")
    await permission.allow(true)
    runner.expect((await client.icon(for: first))?.width, 4, "icons: authorization denial does not cache a missing icon")
    await permission.allow(false)
    runner.expectTrue(await client.icon(for: second) == nil, "icons: each new download rechecks the lease")
    runner.expect(box.capturedCount, 1, "icons: a permission change prevents later requests")
    await client.invalidate()
}

private actor IconRequestPermission {
    private(set) var isAllowed = false
    func allow(_ allowed: Bool) { isAllowed = allowed }
}

func checkWebsiteIconQueuedPermission(_ runner: inout TestRunner) async {
    guard let png = syntheticIcon(side: 4) else {
        runner.expectTrue(false, "icons: generated queued permission fixture")
        return
    }
    let server = ServerEnvironment(string: "https://vault.example.test")!
    let box = StubBox(response: StubResponse(body: png, headers: ["Content-Type": "image/png"]))
    let stub = makeStubbedConfiguration(box: box)
    defer { StubRegistry.shared.remove(token: stub.token) }
    let gate = QueuedIconPermission()
    let client = WebsiteIconClient(configuration: stub.configuration, requestIsAllowed: { await gate.check() })
    let pending = (1...8).map { index in
        let location = WebsiteIconLocation(server: server, websites: ["https://fixture\(index).com"])!
        return Task { await client.icon(for: location) }
    }

    let deadline = ContinuousClock.now + .seconds(3)
    while await gate.started < 4, ContinuousClock.now < deadline {
        try? await Task.sleep(for: .milliseconds(5))
    }
    runner.expect(await gate.started, 4, "icons: only the active workers check authorization before dispatch")
    runner.expect(box.capturedCount, 0, "icons: no fetch starts until its authorization check returns")

    await gate.revoke()
    var images = 0
    for lookup in pending {
        if await lookup.value != nil { images += 1 }
    }
    runner.expect(images, 4, "icons: only the already-authorized workers fetch icons")
    runner.expect(box.capturedCount, 4, "icons: no queued request reaches URLSession after lease revocation")
    runner.expect(await gate.started, 8, "icons: queued workers check the revoked lease before fetching")
    await client.invalidate()
}

private actor QueuedIconPermission {
    private(set) var started = 0
    private var revoked = false
    private var waiters: [CheckedContinuation<Bool, Never>] = []

    func check() async -> Bool {
        started += 1
        if revoked { return false }
        return await withCheckedContinuation { waiters.append($0) }
    }

    func revoke() {
        revoked = true
        for waiter in waiters { waiter.resume(returning: true) }
        waiters.removeAll()
    }
}

private func waitForIconRequest(_ box: StubBox) async {
    let deadline = ContinuousClock.now + .seconds(3)
    while box.capturedCount == 0, ContinuousClock.now < deadline {
        try? await Task.sleep(for: .milliseconds(5))
    }
}

private func syntheticIcon(side: Int, type: UTType = .png) -> Data? {
    guard let context = CGContext(data: nil, width: side, height: side, bitsPerComponent: 8, bytesPerRow: 0,
                                  space: CGColorSpaceCreateDeviceRGB(), bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)
    else { return nil }
    context.setFillColor(red: 0.2, green: 0.7, blue: 1, alpha: 1)
    context.fill(CGRect(x: 0, y: 0, width: side, height: side))
    let data = NSMutableData()
    guard let image = context.makeImage(),
          let destination = CGImageDestinationCreateWithData(data as CFMutableData, type.identifier as CFString, 1, nil)
    else { return nil }
    CGImageDestinationAddImage(destination, image, nil)
    return CGImageDestinationFinalize(destination) ? data as Data : nil
}
