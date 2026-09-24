// swift-tools-version: 6.2
// Swift code generated from /proto for the apps (tools/gen-swift.sh). Do not
// edit Sources/JarvisProto by hand: run `pnpm nx run proto:generate`.
import PackageDescription

let package = Package(
    name: "JarvisProto",
    platforms: [.iOS(.v18), .macOS(.v15)],
    products: [
        .library(name: "JarvisProto", targets: ["JarvisProto"]),
    ],
    dependencies: [
        // Keep in sync with tools/swift/Package.swift (the code generator).
        .package(url: "https://github.com/apple/swift-protobuf.git", exact: "1.38.1"),
    ],
    targets: [
        .target(
            name: "JarvisProto",
            dependencies: [.product(name: "SwiftProtobuf", package: "swift-protobuf")],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
    ]
)
