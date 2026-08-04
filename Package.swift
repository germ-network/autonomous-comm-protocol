// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
	name: "CommProtocol",
	platforms: [.iOS(.v17), .macOS(.v13)],
	products: [
		// Products define the executables and libraries a package produces, making them visible to other packages.
		.library(
			name: "CommProtocol",
			targets: ["CommProtocol"]),
		.library(
			name: "CommProtocolMocks",
			targets: ["CommProtocolMocks"]),
	],
	dependencies: [
		.package(
			url: "https://github.com/germ-network/AtprotoTypes.git",
			from: "0.4.5"
		),
		.package(
			url: "https://github.com/germ-network/GermConvenience.git",
			from: "0.2.2"
		),
		.package(url: "https://github.com/swift-libp2p/swift-bases.git", from: "0.2.0"),
		.package(
			// pinned by revision: `Options.deterministicCbor` (RFC 8949 §4.2.1)
			// is on main and not in any released tag. Same pin as CoreAppLogic.
			url: "https://github.com/nnabeyang/swift-cbor.git",
			revision: "8d9b9c25284c6a2f0a564f4c42c7dc3466d08472"
		),
	],
	targets: [
		// Targets are the basic building blocks of a package, defining a module or a test suite.
		// Targets can depend on other targets in this package and products from dependencies.
		.target(
			name: "CommProtocol",
			dependencies: [
				.product(name: "AtprotoTypes", package: "AtprotoTypes"),
				.product(name: "AtprotoTypesMocks", package: "AtprotoTypes"),
				.product(name: "Base64", package: "swift-bases"),
				"GermConvenience",
				.product(name: "SwiftCbor", package: "swift-cbor"),
			]
		),
		.target(
			name: "CommProtocolMocks",
			dependencies: ["CommProtocol"]
		),
		.testTarget(
			name: "CommProtocolTests",
			dependencies: ["CommProtocol", "CommProtocolMocks"]
		),
	]
)
