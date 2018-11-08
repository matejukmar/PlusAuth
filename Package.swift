// swift-tools-version:4.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "PlusAuth",
    products: [
        .library(
            name: "PlusAuth",
            targets: ["PlusAuth"]),
    ],
    dependencies: [
        .package(url: "https://github.com/zen-plus/Scrypt-Swift.git", from: "1.0.0"),
        .package(url: "https://github.com/SwiftORM/MySQL-StORM.git", from: "3.0.0"),
        .package(url: "https://github.com/PerfectlySoft/Perfect-Crypto.git", from: "3.0.0")
    ],
    targets: [
        .target(
            name: "PlusAuth",
            dependencies: ["Scrypt", "MySQLStORM", "PerfectCrypto"]
        ),
        .testTarget(
            name: "PlusAuthTests",
            dependencies: ["PlusAuth"]
        ),
    ]
)
