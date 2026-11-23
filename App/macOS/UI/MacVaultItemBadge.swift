import CoreGraphics
import DesignSystem
import Networking
import SwiftUI
import VaultModels
import VaultRepository

@MainActor
@Observable
final class MacWebsiteIcons {
    let server: ServerEnvironment
    private let sessionIsCurrent: @Sendable () async -> Bool
    private let client: WebsiteIconClient?
    private let loadIcon: @MainActor (WebsiteIconLocation) async -> CGImage?
    private var images: [WebsiteIconLocation: CGImage] = [:]
    @ObservationIgnored private var order: [WebsiteIconLocation] = []
    @ObservationIgnored private var isActive = true

    init(server: ServerEnvironment, sessionIsCurrent: @escaping @Sendable () async -> Bool,
         loadIcon: (@MainActor (WebsiteIconLocation) async -> CGImage?)? = nil) {
        self.server = server
        self.sessionIsCurrent = sessionIsCurrent
        let client = loadIcon == nil ? WebsiteIconClient(requestIsAllowed: sessionIsCurrent) : nil
        self.client = client
        self.loadIcon = loadIcon ?? { await client?.icon(for: $0) }
    }

    func image(for location: WebsiteIconLocation) -> CGImage? { images[location] }

    func load(_ location: WebsiteIconLocation) async {
        guard isActive, images[location] == nil, await sessionIsCurrent(), isActive, !Task.isCancelled else { return }
        guard let image = await loadIcon(location), isActive, !Task.isCancelled,
              await sessionIsCurrent(), isActive, !Task.isCancelled, images[location] == nil else { return }
        if order.count == 128, let oldest = order.first {
            order.removeFirst()
            images.removeValue(forKey: oldest)
        }
        order.append(location)
        images[location] = image
    }

    func invalidate() {
        isActive = false
        order.removeAll()
        images.removeAll()
        if let client { Task { await client.invalidate() } }
    }
}

extension EnvironmentValues {
    @Entry var macWebsiteIcons: MacWebsiteIcons? = nil
}

struct MacVaultItemBadge: View {
    private struct Lookup: Hashable {
        let source: ObjectIdentifier
        let location: WebsiteIconLocation
    }

    let cipher: PlaintextCipher
    let diameter: CGFloat
    @Environment(\.macWebsiteIcons) private var icons

    init(_ cipher: PlaintextCipher, diameter: CGFloat) {
        self.cipher = cipher
        self.diameter = diameter
    }

    private var location: WebsiteIconLocation? {
        guard let icons, CipherType(rawValue: cipher.type) == .login,
              let sites = cipher.login?.uris, !sites.isEmpty else { return nil }
        return WebsiteIconLocation(server: icons.server, websites: sites.map(\.uri))
    }

    var body: some View {
        let icons = icons
        let location = location
        let lookup = icons.flatMap { source in location.map { Lookup(source: ObjectIdentifier(source), location: $0) } }
        Group {
            if let location, let image = icons?.image(for: location) {
                Image(decorative: image, scale: 1, orientation: .up)
                    .resizable()
                    .interpolation(.high)
                    .scaledToFit()
                    .padding(diameter * 0.17)
                    .frame(width: diameter, height: diameter)
                    .background(.fill.tertiary, in: RoundedRectangle(cornerRadius: diameter * 0.28))
            } else {
                BrandBadge(cipher, diameter: diameter)
            }
        }
        .frame(width: diameter, height: diameter)
        .accessibilityHidden(true)
        .task(id: lookup) {
            if let lookup { await icons?.load(lookup.location) }
        }
    }
}
