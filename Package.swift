// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "DeviceSecurityKit",
    platforms: [
        .iOS(.v15),
        .macOS(.v13)
    ],
    products: [
        .library(
            name: "DeviceSecurityKit",
            targets: ["DeviceSecurityKit"]
        ),
        .executable(
            name: "dsk-scan",
            targets: ["dsk-scan"]
        )
    ],
    targets: [
        .target(
            name: "DSKStaticAnalysis",
            dependencies: [],
            path: "Sources/DSKStaticAnalysis"
        ),
        .target(
            name: "DeviceSecurityKit",
            dependencies: ["DSKStaticAnalysis"],
            path: "Sources/DeviceSecurityKit",
            resources: [
                .process("Resources")
            ],
            linkerSettings: [
                .linkedFramework("NetworkExtension"),
                .linkedFramework("DeviceCheck"),
                .linkedFramework("BackgroundTasks")
            ]
        ),
        .executableTarget(
            name: "dsk-scan",
            dependencies: ["DSKStaticAnalysis"],
            path: "Sources/dsk-scan"
        ),
        .testTarget(
            name: "DeviceSecurityKitTests",
            dependencies: ["DeviceSecurityKit"],
            path: "Tests/DeviceSecurityKitTests"
        )
    ]
)
