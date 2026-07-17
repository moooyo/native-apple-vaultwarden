// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "Tessera",
    platforms: [.iOS("27.0"), .macOS("27.0")],
    products: [
        .library(name: "CryptoCore", targets: ["CryptoCore"]),
        .library(name: "VaultModels", targets: ["VaultModels"]),
        .library(name: "KeyVault", targets: ["KeyVault"]),
        .library(name: "Generators", targets: ["Generators"]),
        .library(name: "Fido2", targets: ["Fido2"]),
        .library(name: "AppShared", targets: ["AppShared"]),
        // VaultStore uses the system `import SQLite3` C API on this CLT host.
        // PRODUCTION: swap the linked lib to SQLCipher (PRAGMA key) — see VaultStore.swift header.
        .library(name: "VaultStore", targets: ["VaultStore"]),
        // KeychainBridge: SE-wrapped biometric unlock via an injectable Keychain seam.
        // The real Security/LocalAuthentication impls compile here but only RUN in a
        // signed app on device/simulator (entitlements required). See KeychainBridge.swift.
        .library(name: "KeychainBridge", targets: ["KeychainBridge"]),
        // Networking: URLSession async/await Bitwarden/Vaultwarden API client.
        // Fully headless-testable via an injected URLSession + custom URLProtocol stub.
        .library(name: "Networking", targets: ["Networking"]),
        // SyncEngine: revision-token incremental sync, outbox flush, AutoFill identity
        // rebuild. Protocol-seamed (VaultAPI / CredentialIdentityWriting) so the logic
        // is headless-testable with fakes + a real VaultStore + a real KeyVault. The
        // ASCredentialIdentityStore-backed writer compiles here but only RUNS in a
        // signed app/extension (see ASCredentialIdentityWriter.swift).
        .library(name: "SyncEngine", targets: ["SyncEngine"]),
        // VaultReader: the AutoFill extension's least-privilege read facade. NO
        // networking, NO sync, NO bulk decrypt — biometric unlock + decrypt a SINGLE
        // selected cipher + build a passkey assertion. Headless-testable end-to-end
        // (real VaultStore on a temp DB + real KeyVault + real Fido2 + in-memory
        // KeychainBridge seams).
        .library(name: "VaultReader", targets: ["VaultReader"]),
        // VaultRepository: app-facing auth + vault orchestration + the ServiceContainer
        // DI graph. Headless-testable with a fake VaultAPI + real KeyVault + temp-DB
        // VaultStore + in-memory KeychainBridge seams.
        .library(name: "VaultRepository", targets: ["VaultRepository"]),
        // UIShared: @Observable view models over repository PROTOCOLS (AuthService /
        // VaultService). NO SwiftUI/UIKit/AppKit — logic only (`import Observation`), so it
        // compiles AND its logic is headless-testable. The view packages (UI-iOS/UI-mac)
        // consume these later. See docs/superpowers/plans §G.
        .library(name: "UIShared", targets: ["UIShared"]),
        // DesignSystem: SwiftUI Liquid Glass tokens + reusable components (GlassScrim,
        // ConcentricRectangleCard, OTPRingView, SecureRevealView) with accessibility
        // fallbacks (Reduce Transparency / Increased Contrast → opaque). SwiftUI library
        // code COMPILES headlessly for the macOS target here (the SDK is present) using
        // only cross-platform iOS/macOS SwiftUI APIs. Views are verified by `swift build`;
        // the pure decision logic (glass resolution, OTP ring math, strength thresholds)
        // is unit-tested via DesignSystemTests. See docs/superpowers/plans §G.
        .library(name: "DesignSystem", targets: ["DesignSystem"]),
    ],
    targets: [
        .target(name: "CryptoCore"),
        .executableTarget(
            name: "CryptoCoreTests",
            dependencies: ["CryptoCore"],
            exclude: ["Fixtures"]
        ),
        .target(
            name: "VaultModels",
            dependencies: ["CryptoCore"]
        ),
        .executableTarget(
            name: "VaultModelsTests",
            dependencies: ["VaultModels", "CryptoCore"],
            exclude: ["Fixtures"]
        ),
        .target(
            name: "KeyVault",
            dependencies: ["CryptoCore"]
        ),
        .executableTarget(
            name: "KeyVaultTests",
            dependencies: ["KeyVault", "CryptoCore"]
        ),
        .target(
            name: "Generators",
            dependencies: ["CryptoCore"]
        ),
        .executableTarget(
            name: "GeneratorsTests",
            dependencies: ["Generators"]
        ),
        .target(
            name: "Fido2"
        ),
        .executableTarget(
            name: "Fido2Tests",
            dependencies: ["Fido2"]
        ),
        // AppShared: cross-target constants + value types. No dependencies.
        .target(name: "AppShared"),
        .executableTarget(
            name: "AppSharedTests",
            dependencies: ["AppShared"]
        ),
        // VaultStore: encrypted offline cache. Uses the system SQLite3 module
        // (`import SQLite3`) which resolves on Apple platforms with no extra linker
        // config in SPM. PRODUCTION swaps in SQLCipher; see VaultStore.swift header.
        .target(
            name: "VaultStore",
            dependencies: ["CryptoCore", "VaultModels"]
        ),
        .executableTarget(
            name: "VaultStoreTests",
            dependencies: ["VaultStore", "CryptoCore", "VaultModels"]
        ),
        // KeychainBridge: the only cross-process key channel (SE-wrapped UserKey behind
        // biometrics, in a shared access group). Real Security/LocalAuthentication impls
        // compile but run only in a signed app; orchestration is tested via in-memory fakes.
        .target(
            name: "KeychainBridge",
            dependencies: ["CryptoCore"]
        ),
        .executableTarget(
            name: "KeychainBridgeTests",
            dependencies: ["KeychainBridge", "CryptoCore"]
        ),
        // Networking: URLSession async/await client for the Bitwarden/Vaultwarden
        // REST API. Depends on VaultModels (response models + case-insensitive
        // decoder), AppShared (DeviceMetadata), and CryptoCore (EncString in DTOs).
        .target(
            name: "Networking",
            dependencies: ["VaultModels", "AppShared", "CryptoCore"]
        ),
        // Tests run as an executable (CLT-only host, no XCTest). URLSession is
        // headless; a custom URLProtocol returns canned responses AND captures the
        // outgoing request so tests can assert method/path/headers/body.
        .executableTarget(
            name: "NetworkingTests",
            dependencies: ["Networking", "VaultModels", "AppShared", "CryptoCore"]
        ),
        // SyncEngine: L2 sync orchestration (incremental revision-token sync, outbox
        // flush, AutoFill identity rebuild). Depends on the full L0/L1 stack it
        // orchestrates, plus Networking for the real APIClient -> VaultAPI conformance.
        .target(
            name: "SyncEngine",
            dependencies: ["CryptoCore", "VaultModels", "VaultStore", "KeyVault", "Networking"]
        ),
        // Tests run as an executable (CLT-only host, no XCTest). Fakes for VaultAPI +
        // CredentialIdentityWriting are paired with a REAL VaultStore (temp-file DB) and
        // a REAL KeyVault (unlocked with a synthetic user key) to exercise the merge /
        // soft-fail / identity / outbox paths end-to-end.
        .executableTarget(
            name: "SyncEngineTests",
            dependencies: ["SyncEngine", "CryptoCore", "VaultModels", "VaultStore", "KeyVault", "Networking"]
        ),
        // VaultReader: L1 least-privilege facade for the AutoFill extension. Depends only
        // on the read/decrypt stack it needs (no Networking / SyncEngine), preserving the
        // extension's minimal link graph.
        .target(
            name: "VaultReader",
            dependencies: ["CryptoCore", "VaultModels", "VaultStore", "KeyVault", "KeychainBridge", "Fido2"]
        ),
        // Tests run as an executable (CLT-only host, no XCTest). A real temp-DB VaultStore
        // is seeded with ciphers encrypted under a synthetic user key; a real KeyVault is
        // unlocked with that key; the password/passkey/decrypt paths are exercised
        // end-to-end (the passkey path round-trips through real Fido2).
        .executableTarget(
            name: "VaultReaderTests",
            dependencies: ["VaultReader", "CryptoCore", "VaultModels", "VaultStore", "KeyVault", "KeychainBridge", "Fido2"]
        ),
        // VaultRepository: L2 app-facing orchestration (AuthRepository + VaultRepository)
        // plus the ServiceContainer DI graph. Depends on the full L1/L2 stack it composes.
        .target(
            name: "VaultRepository",
            dependencies: ["CryptoCore", "VaultModels", "VaultStore", "KeyVault", "KeychainBridge",
                           "Networking", "SyncEngine", "AppShared"]
        ),
        // Tests run as an executable (CLT-only host, no XCTest). A fake VaultAPI is paired
        // with a real KeyVault + temp-DB VaultStore + in-memory KeychainBridge seams to
        // exercise the login / 2FA / unlock / CRUD / lock paths end-to-end.
        .executableTarget(
            name: "VaultRepositoryTests",
            dependencies: ["VaultRepository", "CryptoCore", "VaultModels", "VaultStore", "KeyVault",
                           "KeychainBridge", "Networking", "SyncEngine", "AppShared"]
        ),
        // UIShared: L3 @Observable view models. Depends on VaultRepository (the AuthService /
        // VaultService protocols + LoginResult / PlaintextCipher / RepositoryError), Generators
        // (password/passphrase/TOTP), Networking (TwoFactorProvider / ServerEnvironment used by
        // the adapters), SyncEngine (SyncOutcome), AppShared (AutoLockTimeout), and VaultModels.
        // NO SwiftUI — `import Observation` only.
        .target(
            name: "UIShared",
            dependencies: ["VaultRepository", "Generators", "Networking", "SyncEngine",
                           "AppShared", "VaultModels"],
            resources: [.process("Resources")]
        ),
        // Tests run as an executable (CLT-only host, no XCTest). The view models are driven
        // against in-memory fakes of AuthService / VaultService; TOTP + generator paths use
        // deterministic inputs (a fixed clock, a MockRandomSource) for golden-vector checks.
        // The runner is `@MainActor async` (the view models are `@MainActor`).
        .executableTarget(
            name: "UISharedTests",
            dependencies: ["UIShared", "VaultRepository", "Generators", "Networking",
                           "SyncEngine", "AppShared", "VaultModels"]
        ),
        // DesignSystem: L3 SwiftUI Liquid Glass component kit. `import SwiftUI`. Depends
        // on Generators for `TOTPConfiguration`/`TOTP` (OTP ring). Compiles for the macOS
        // target on this host using only cross-platform iOS/macOS SwiftUI
        // APIs (the Liquid Glass primitives are available on both). iOS-only chrome
        // (tab-bar minimize, bottom accessory, UIPasteboard) lives in UI-iOS, not here.
        .target(
            name: "DesignSystem",
            dependencies: ["Generators"]
        ),
        // Tests run as an executable (CLT-only host, no XCTest). SwiftUI Views cannot be
        // exercised headlessly, so only the PURE decision logic is tested: glass-style
        // resolution under accessibility flags, OTP ring progress fraction (boundaries +
        // clamping), and password-strength color thresholds. The Views themselves are
        // verified by `swift build` compiling them.
        .executableTarget(
            name: "DesignSystemTests",
            dependencies: ["DesignSystem", "Generators"]
        ),
    ]
)
