// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
	name: "CommProtocol",
	platforms: [.iOS(.v17), .macOS(.v12)],
	products: [
		// Products define the executables and libraries a package produces, making them visible to other packages.
		.library(
			name: "CommProtocol",
			targets: ["CommProtocol"])
	],
	targets: [
		// Targets are the basic building blocks of a package, defining a module or a test suite.
		// Targets can depend on other targets in this package and products from dependencies.
		.target(
			name: "CommProtocol",
			dependencies: []
		),
		.testTarget(
			name: "CommProtocolTests",
			dependencies: ["CommProtocol"]
		),
	]
)
