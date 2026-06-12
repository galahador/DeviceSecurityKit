// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "DeviceSecurityKit",
    platforms: [
        .iOS(.v15)
    ],
    products: [
        .library(
            name: "DeviceSecurityKit",
            targets: ["DeviceSecurityKit"]
        )
    ],
    targets: [
        .target(
            name: "DeviceSecurityKit",
            dependencies: [],
            path: "Sources",
            resources: [
                .process("DeviceSecurityKit/Resources")
            ],
            linkerSettings: [
                .linkedFramework("NetworkExtension"),
                .linkedFramework("DeviceCheck"),
                .linkedFramework("BackgroundTasks")
            ]
        ),
        .testTarget(
            name: "DeviceSecurityKitTests",
            dependencies: ["DeviceSecurityKit"],
            path: "Tests/DeviceSecurityKitTests"
        )
    ]
)
