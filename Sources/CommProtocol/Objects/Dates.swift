//
//  Dates.swift
//  CommProtocol
//
//  Created by Mark at Germ  on 9/19/24.
//

import Foundation

//two different formats for dates

///`Date` deliberately does not conform to LinearEncodable — wire structs carry
///`WireDate` (or the hour-quantized `RoundedDate`) instead, so a raw `Date`
///wire field is a compile error.
///
///The wire format stores `timeIntervalSince1970.bitPattern`, but `Date` equates
///on `timeIntervalSinceReferenceDate`, and converting between the two epochs in
///Double can round away low mantissa bits (it does for about half of
///current-era clock values) — so a raw Date would survive a wire round trip
///`==`-intact only by coin flip. `WireDate` pre-rounds the instant to the wire
///grid at construction (moving it by at most 2⁻²³ s, ~120 ns for current-era
///dates), which makes round trips exact by construction. DateEncodingTests
///sweeps these properties across the distinct float-grid regimes.
///
///Caveats at the edges: parse does no finiteness check (NaN/±inf bit patterns
///parse into Dates that poison comparisons); bytes from a foreign encoder may
///re-encode differently (parsed values are stable from then on); Dates within
///2⁻²⁴ s of the reference epoch collapse onto it when normalized.
public struct WireDate: Equatable, Sendable {
	///Pre-rounded to the wire grid at construction; wire round trips
	///reproduce finite dates exactly
	public let date: Date

	public init(date: Date) {
		self.date = date.wireNormalized
	}

	public static var now: WireDate { .init(date: .now) }
}

extension WireDate: LinearEncodable {
	public static func parse(_ input: Data) throws -> (WireDate, Int) {
		let (bitPattern, consumed) = try UInt64.parse(input)
		return (
			.init(
				date: .init(
					timeIntervalSince1970: .init(
						bitPattern: bitPattern
					)
				)
			),
			consumed
		)
	}

	public var wireFormat: Data {
		date.timeIntervalSince1970.bitPattern.wireFormat
	}
}

extension Date {
	///Self, pre-rounded to what the wire format can represent — the rounding
	///`WireDate` applies at construction
	public var wireNormalized: Date {
		.init(timeIntervalSince1970: timeIntervalSince1970)
	}
}

public struct RoundedDate: Equatable, Sendable {
	let hoursSinceEpoch: UInt32

	public init(date: Date) {
		hoursSinceEpoch = UInt32((date.timeIntervalSince1970 / 3600).rounded())
	}

	init(hoursSinceEpoch: UInt32) {
		self.hoursSinceEpoch = hoursSinceEpoch
	}

	public var date: Date {
		.init(timeIntervalSince1970: Double(hoursSinceEpoch) * 3600)
	}
}

extension RoundedDate: LinearEncodable {
	public static func parse(_ input: Data) throws -> (RoundedDate, Int) {
		let (hours, consumed) = try UInt32.parse(input)
		return (
			.init(hoursSinceEpoch: hours),
			consumed
		)
	}

	public var wireFormat: Data {
		hoursSinceEpoch.wireFormat
	}
}
