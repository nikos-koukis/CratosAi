// swift-tools-version: 6.2
// Everything of the Jarvis apps except the thin app targets: the API client
// and session, the voice session, the approver, and the SwiftUI screens.
// Builds and tests on macOS without Xcode (see scripts/swift-test.sh).
import PackageDescription

let package = Package(
    name: "JarvisKit",
    platforms: [.iOS(.v18), .macOS(.v15)],
    products: [
        .library(name: "JarvisKit", targets: ["JarvisKit"]),
        .library(name: "JarvisUI", targets: ["JarvisUI"]),
        .executable(name: "jarvis-cli", targets: ["jarvis-cli"]),
    ],
    dependencies: [
        .package(path: "../../../gen/swift"),
        .package(url: "https://github.com/apple/swift-protobuf.git", exact: "1.38.1"),
    ],
    targets: [
        .target(
            name: "JarvisKit",
            dependencies: [
                .product(name: "JarvisProto", package: "swift"),
                .product(name: "SwiftProtobuf", package: "swift-protobuf"),
            ],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .target(
            name: "JarvisUI",
            dependencies: ["JarvisKit"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .executableTarget(
            name: "jarvis-cli",
            dependencies: ["JarvisKit"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .testTarget(
            name: "JarvisKitTests",
            dependencies: ["JarvisKit", "JarvisUI"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
    ]
)
