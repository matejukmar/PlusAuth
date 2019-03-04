// swift-tools-version:4.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "PlusAuth",
    products: [
        .library(
            name: "PlusAuth",
            targets: ["PlusAuth"])
    ],
    dependencies: [
        .package(url: "https://github.com/matejukmar/Scrypt-Swift.git", from: "1.0.0"),
        .package(url: "https://github.com/PerfectlySoft/Perfect-Crypto.git", from: "3.0.0"),
		.package(url: "https://github.com/PerfectlySoft/Perfect-HTTP.git", from: "3.0.0"),
		.package(url: "https://github.com/PerfectlySoft/Perfect-MySQL.git", from: "3.0.0"),
		.package(url: "https://github.com/PerfectlySoft/Perfect-SMTP.git", from: "3.0.0"),
    ],
    targets: [
        .target(
            name: "PlusAuth",
            dependencies: ["PerfectHTTP", "PerfectMySQL", "PerfectSMTP", "Scrypt", "PerfectCrypto"]
        ),
        .testTarget(
            name: "PlusAuthTests",
            dependencies: ["PlusAuth"]
        ),
    ]
)
