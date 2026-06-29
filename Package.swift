// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "Tessera",
    platforms: [.iOS(.v26), .macOS(.v26)],
    products: [
        .library(name: "CryptoCore", targets: ["CryptoCore"]),
        .library(name: "VaultModels", targets: ["VaultModels"]),
        .library(name: "KeyVault", targets: ["KeyVault"]),
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
    ]
)
