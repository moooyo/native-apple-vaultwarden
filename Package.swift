// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "Tessera",
    platforms: [.iOS(.v26), .macOS(.v26)],
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
    ]
)
