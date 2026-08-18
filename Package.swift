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
		//0.3.0 made Data(base64URLEncoded:) throwing rather than failable, and
		//MailboxGrant is written against that. Consumers ignore this package's
		//Package.resolved, so the floor has to be stated here.
		.package(url: "https://github.com/swift-libp2p/swift-bases.git", from: "0.3.0"),
		.package(
			// swift-cbor 0.1.0 includes `Options.deterministicCbor` (RFC 8949
			// §4.2.1) — confirmed the previously-pinned revision
			// (8d9b9c2, "feature/deterministic-cbor-option") is an ancestor of
			// 0.1.0's tagged commit. A stable-tagged package (this one, since
			// PR #46) cannot depend on a revision-pinned one — SwiftPM refuses
			// to resolve it — so this must track a real tag, not a revision.
			url: "https://github.com/nnabeyang/swift-cbor.git",
			from: "0.1.0"
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
