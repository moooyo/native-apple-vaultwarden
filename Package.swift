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
    ]
)
