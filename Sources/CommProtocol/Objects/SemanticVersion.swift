//
//  SemanticVersion.swift
//
//
//  Created by Mark @ Germ on 8/4/23.
//

import Foundation

public struct SemanticVersion: Equatable, Hashable, Sendable, Comparable {
	let major: UInt32
	let minor: UInt32
	let patch: UInt32
	let preReleaseSuffix: String?

	public init(
		major: UInt32,
		minor: UInt32,
		patch: UInt32,
		preReleaseSuffix: String? = nil
	) {
		self.major = major
		self.minor = minor
		self.patch = patch
		self.preReleaseSuffix = preReleaseSuffix
	}

	public var string: String {
		"\(major).\(minor).\(patch)" + (preReleaseSuffix ?? "")
	}

	static public func < (lhs: SemanticVersion, rhs: SemanticVersion) -> Bool {
		if lhs.major < rhs.major {
			true
		} else if lhs.major > rhs.major {
			false
		} else {
			if lhs.minor < rhs.minor {
				true
			} else if lhs.minor > rhs.minor {
				false
			} else {
				if lhs.patch < rhs.patch {
					true
				} else if lhs.patch > rhs.patch {
					false
				} else {
					false
				}
			}
		}
	}
}

///Compactly represent this as 3 UInt8 bytes and a 4th enum indicating if there is a suffix
///Overflow the UInt8 to Uint32
extension SemanticVersion: LinearEncodedQuad {
	public var first: UInt32 { major }
	public var second: UInt32 { minor }
	public var third: UInt32 { patch }
	public var fourth: OptionalString { .init(preReleaseSuffix) }

	public init(first: UInt32, second: UInt32, third: UInt32, fourth: OptionalString) throws {
		self.init(
			major: first,
			minor: second,
			patch: third,
			preReleaseSuffix: fourth.string
		)
	}
}
