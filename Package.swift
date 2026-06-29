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
    ]
)
