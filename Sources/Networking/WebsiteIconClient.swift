import CoreGraphics
import Foundation
import ImageIO
import UniformTypeIdentifiers

public struct WebsiteIconLocation: Hashable, Sendable {
    public let url: URL

    /// Resolves the first eligible website domain at the selected Vaultwarden server's icon endpoint.
    public init?(server: ServerEnvironment, websites: [String]) {
        let base = server.base.absoluteURL
        guard Self.isWebURL(base), base.query == nil, base.fragment == nil,
              let domain = websites.lazy.compactMap(Self.publicDomain).first else { return nil }

        url = base.appending(path: "icons", directoryHint: .isDirectory)
            .appending(path: domain, directoryHint: .isDirectory)
            .appending(path: "icon.png", directoryHint: .notDirectory)
    }

    private static func isWebURL(_ url: URL) -> Bool {
        guard let scheme = url.scheme?.lowercased(), scheme == "https" || scheme == "http" else { return false }
        return url.host?.isEmpty == false && url.user == nil && url.password == nil
    }

    private static let privateSuffixes: Set<Substring> = [
        "alt", "arpa", "corp", "example", "home", "internal", "intranet", "invalid", "lan",
        "local", "localdomain", "localhost", "onion", "private", "test"
    ]
    private static let bareDomainDelimiters = CharacterSet(charactersIn: ":/?#[]@%\\")
        .union(.whitespacesAndNewlines)

    private static func publicDomain(_ website: String) -> String? {
        let address = website.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let host = websiteHost(address)?.lowercased() else { return nil }

        let domain = host.hasSuffix(".") ? String(host.dropLast()) : host
        let labels = domain.split(separator: ".", omittingEmptySubsequences: false)
        guard (1...253).contains(domain.utf8.count), labels.count >= 2,
              let suffix = labels.last, !privateSuffixes.contains(suffix),
              suffix.hasPrefix("xn--") || suffix.utf8.allSatisfy(isASCIILetter),
              labels.allSatisfy({ label in
                  (1...63).contains(label.utf8.count) && !label.hasPrefix("-") && !label.hasSuffix("-") &&
                      label.utf8.allSatisfy { isASCIILetter($0) || (48...57).contains($0) || $0 == 45 }
              }) else { return nil }

        return domain
    }

    private static func websiteHost(_ address: String) -> String? {
        if let url = URL(string: address), isWebURL(url) {
            return url.host(percentEncoded: false)
        }

        guard address.rangeOfCharacter(from: bareDomainDelimiters) == nil else { return nil }
        var components = URLComponents()
        components.scheme = "https"
        components.host = address
        return components.url?.host(percentEncoded: false)
    }

    private static func isASCIILetter(_ byte: UInt8) -> Bool { (97...122).contains(byte) }
}

/// Loads bounded raster icons with an anonymous transport and a session-scoped memory cache.
public actor WebsiteIconClient {
    private struct CachedIcon {
        let image: CGImage?
        let expires: ContinuousClock.Instant
        var lastUsed: ContinuousClock.Instant
    }

    private static let maxQueued = 96
    private static let maxActive = 4
    private static let maxCached = 128
    private static let maxBytes = 256 * 1024
    private static let maxSourceSide = 1024
    private static let maxThumbnailSide = 128
    private static let cacheLifetime = Duration.seconds(3600)
    private static let missingLifetime = Duration.seconds(90)

    private let session: URLSession
    private let requestIsAllowed: (@Sendable () async -> Bool)?
    private var cached: [WebsiteIconLocation: CachedIcon] = [:]
    private var pending: [WebsiteIconLocation] = []
    private var active: [WebsiteIconLocation: Task<Void, Never>] = [:]
    private var waiters: [WebsiteIconLocation: [CheckedContinuation<CGImage?, Never>]] = [:]
    private var invalidated = false

    /// Rechecks optional session permission immediately before each new download, including queued ones.
    public init(requestIsAllowed: (@Sendable () async -> Bool)? = nil) {
        self.init(configuration: .ephemeral, requestIsAllowed: requestIsAllowed)
    }

    package init(configuration: URLSessionConfiguration, requestIsAllowed: (@Sendable () async -> Bool)? = nil) {
        configuration.httpCookieAcceptPolicy = .never
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.urlCredentialStorage = nil
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.timeoutIntervalForRequest = 8
        configuration.timeoutIntervalForResource = 12
        session = URLSession(configuration: configuration, delegate: WebsiteIconSessionDelegate(), delegateQueue: nil)
        self.requestIsAllowed = requestIsAllowed
    }

    deinit {
        session.invalidateAndCancel()
    }

    public func icon(for location: WebsiteIconLocation) async -> CGImage? {
        guard !invalidated, !Task.isCancelled else { return nil }
        let now = ContinuousClock.now
        if let entry = cached[location], now < entry.expires {
            cached[location]?.lastUsed = now
            return entry.image
        }

        cached.removeValue(forKey: location)
        let image: CGImage? = await withCheckedContinuation { continuation in
            if waiters[location] != nil {
                waiters[location]?.append(continuation)
            } else if pending.count < Self.maxQueued {
                waiters[location] = [continuation]
                pending.append(location)
                startRequests()
            } else {
                continuation.resume(returning: nil)
            }
        }
        return invalidated || Task.isCancelled ? nil : image
    }

    /// Cancels pending work and permanently retires this client.
    public func invalidate() {
        guard !invalidated else { return }
        invalidated = true
        if active.isEmpty { session.invalidateAndCancel() }
        for task in active.values { task.cancel() }
        for requests in waiters.values {
            for request in requests { request.resume(returning: nil) }
        }
        pending.removeAll()
        waiters.removeAll()
        cached.removeAll()
    }

    private func startRequests() {
        while active.count < Self.maxActive, !pending.isEmpty {
            let location = pending.removeFirst()
            active[location] = Task.detached(priority: .utility) { [session, requestIsAllowed] in
                guard !Task.isCancelled, await requestIsAllowed?() != false else {
                    await self.finish(location, image: nil, cacheResult: false)
                    return
                }
                let image = await Self.fetch(location, session: session)
                await self.finish(location, image: image)
            }
        }
    }

    private func finish(_ location: WebsiteIconLocation, image: CGImage?, cacheResult: Bool = true) {
        active.removeValue(forKey: location)
        guard !invalidated else {
            if active.isEmpty { session.invalidateAndCancel() }
            return
        }
        if cacheResult {
            let now = ContinuousClock.now
            if cached.count >= Self.maxCached,
               let oldest = cached.min(by: { $0.value.lastUsed < $1.value.lastUsed })?.key {
                cached.removeValue(forKey: oldest)
            }
            cached[location] = CachedIcon(image: image, expires: now + (image == nil ? Self.missingLifetime : Self.cacheLifetime),
                                          lastUsed: now)
        }
        if let requests = waiters.removeValue(forKey: location) {
            for request in requests { request.resume(returning: image) }
        }
        startRequests()
    }

    private static let imageTypes: [String: UTType] = [
        "image/png": .png, "image/jpeg": .jpeg, "image/gif": .gif, "image/webp": .webP,
        "image/x-icon": .ico, "image/vnd.microsoft.icon": .ico, "image/bmp": .bmp
    ]

    private static func fetch(_ location: WebsiteIconLocation, session: URLSession) async -> CGImage? {
        guard !Task.isCancelled else { return nil }
        var request = URLRequest(url: location.url)
        request.httpShouldHandleCookies = false
        request.setValue(imageTypes.keys.sorted().joined(separator: ", "), forHTTPHeaderField: "Accept")

        do {
            let (bytes, response) = try await session.bytes(for: request)
            defer { bytes.task.cancel() }
            guard let http = response as? HTTPURLResponse, http.statusCode == 200, http.url == location.url,
                  let contentType = http.value(forHTTPHeaderField: "Content-Type")?.split(separator: ";").first,
                  let type = imageTypes[contentType.trimmingCharacters(in: .whitespaces).lowercased()],
                  http.expectedContentLength <= Int64(maxBytes) else { return nil }

            var data = Data()
            for try await byte in bytes {
                guard data.count < maxBytes, !Task.isCancelled else { return nil }
                data.append(byte)
            }
            guard !Task.isCancelled else { return nil }
            return thumbnail(from: data, type: type)
        } catch {
            return nil
        }
    }

    private static func thumbnail(from data: Data, type: UTType) -> CGImage? {
        let sourceOptions = [kCGImageSourceShouldCache: false] as CFDictionary
        guard let source = CGImageSourceCreateWithData(data as CFData, sourceOptions),
              CGImageSourceGetType(source) as String? == type.identifier,
              CGImageSourceGetStatus(source) == .statusComplete else { return nil }

        let count = CGImageSourceGetCount(source)
        guard (1...16).contains(count) else { return nil }
        var selectedIndex = 0
        var selectedArea = 0
        for index in 0..<count {
            guard let info = CGImageSourceCopyPropertiesAtIndex(source, index, nil) as? [CFString: Any],
                  let width = info[kCGImagePropertyPixelWidth] as? Int, let height = info[kCGImagePropertyPixelHeight] as? Int,
                  (1...maxSourceSide).contains(width), (1...maxSourceSide).contains(height) else { return nil }
            if type == .ico, width * height > selectedArea {
                selectedIndex = index
                selectedArea = width * height
            }
        }

        let thumbnailOptions = [
            kCGImageSourceCreateThumbnailFromImageAlways: true,
            kCGImageSourceCreateThumbnailWithTransform: true,
            kCGImageSourceShouldCacheImmediately: true,
            kCGImageSourceThumbnailMaxPixelSize: maxThumbnailSide
        ] as CFDictionary
        return CGImageSourceCreateThumbnailAtIndex(source, selectedIndex, thumbnailOptions)
    }
}

private final class WebsiteIconSessionDelegate: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping @Sendable (URLRequest?) -> Void) {
        completionHandler(nil)
    }

    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        completionHandler(Self.disposition(for: challenge), nil)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        completionHandler(Self.disposition(for: challenge), nil)
    }

    private static func disposition(for challenge: URLAuthenticationChallenge) -> URLSession.AuthChallengeDisposition {
        challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust
            ? .performDefaultHandling : .cancelAuthenticationChallenge
    }
}
