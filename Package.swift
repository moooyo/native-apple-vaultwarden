// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "Tessera",
    platforms: [.iOS(.v26), .macOS(.v26)],
    products: [
        .library(name: "CryptoCore", targets: ["CryptoCore"]),
    ],
    targets: [
        .target(name: "CryptoCore"),
        .executableTarget(
            name: "CryptoCoreTests",
            dependencies: ["CryptoCore"],
            exclude: ["Fixtures"]
        ),
    ]
)
