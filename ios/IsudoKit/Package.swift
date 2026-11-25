// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "IsudoKit",
    platforms: [.iOS(.v26), .macOS(.v15)],
    products: [.library(name: "IsudoKit", targets: ["IsudoKit"])],
    targets: [
        .target(
            name: "IsudoKit",
            swiftSettings: [.treatAllWarnings(as: .error)]
        ),
        .testTarget(
            name: "IsudoKitTests",
            dependencies: ["IsudoKit"],
            swiftSettings: [.treatAllWarnings(as: .error)]
        ),
    ],
    swiftLanguageModes: [.v6]
)
