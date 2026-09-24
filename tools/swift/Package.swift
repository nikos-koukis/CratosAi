// swift-tools-version: 6.2
// Pinned protoc plugin for the Swift code generated from /proto (see
// tools/gen-swift.sh). Nothing here ships; it only builds the plugin.
import PackageDescription

let package = Package(
    name: "JarvisSwiftTools",
    platforms: [.macOS(.v15)],
    dependencies: [
        // Keep in sync with gen/swift/Package.swift.
        .package(url: "https://github.com/apple/swift-protobuf.git", exact: "1.38.1"),
    ],
    targets: [
        // SwiftPM needs a target; the plugin is the dependency's product.
        .target(name: "Placeholder", path: "Placeholder"),
    ]
)
