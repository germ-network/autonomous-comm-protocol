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
			// Temporary revision pin to AtprotoTypes' swift-crypto-5 branch
			// (germ-network/AtprotoTypes#69); replace with the released version
			// once it cuts.
			url: "https://github.com/germ-network/AtprotoTypes.git",
			revision: "8e00dd81013fef864de2b0f3dde7ad7fcbdc119b"
		),
		.package(
			// Temporary revision pin to GermConvenience main (org-wide swift-crypto
			// 5 move); released line still caps swift-crypto at ..<5.0.0.
			url: "https://github.com/germ-network/GermConvenience.git",
			revision: "f907c9018dd4c2f0110ab5f1f37c7c53fa0ae6ca"
		),
		//0.3.0 made Data(base64URLEncoded:) throwing rather than failable, and
		//MailboxGrant is written against that. Consumers ignore this package's
		//Package.resolved, so the floor has to be stated here.
		.package(url: "https://github.com/swift-libp2p/swift-bases.git", from: "0.3.0"),
		.package(
			url: "https://github.com/apple/swift-crypto.git",
			from: "5.0.0"),
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
				.product(name: "Crypto", package: "swift-crypto"),
				"GermConvenience",
				.product(name: "SwiftCbor", package: "swift-cbor"),
			]
		),
		.target(
			name: "CommProtocolMocks",
			dependencies: [
				"CommProtocol",
				.product(name: "Crypto", package: "swift-crypto"),
			]
		),
		.testTarget(
			name: "CommProtocolTests",
			dependencies: [
				"CommProtocol",
				"CommProtocolMocks",
				.product(name: "Crypto", package: "swift-crypto"),
			]
		),
	]
)
