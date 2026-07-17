//
//  Dates.swift
//  CommProtocol
//
//  Created by Mark at Germ  on 9/19/24.
//

import Foundation

//two different formats for dates

///The wire format stores `timeIntervalSince1970.bitPattern`, but `Date` equates on
///`timeIntervalSinceReferenceDate`, and converting between the two epochs in Double
///can round away low mantissa bits (it does for about half of current-era clock
///values). So for an arbitrary in-memory Date (e.g. `.now`),
///`parse(wireFormat) == original` is a coin flip — never compare un-normalized
///Dates (or structs containing them) bit-exactly across a wire round trip.
///
///For the timestamps this library stamps, one round trip is a fixed point: the
///parsed Date re-encodes to identical bytes and stays `==` through further round
///trips. `wireNormalized` applies that rounding up front — identical wire bytes,
///moving the instant by at most 2⁻²³ s (~120 ns for current-era dates) — so a
///Date stamped `.now.wireNormalized` round-trips to exact equality. Library
///constructors stamp their wire-bound Dates this way (`NewAgentData`'s init
///normalizes its caller-supplied expiration); normalize likewise if you feed a
///Date-typed wire field directly. `RoundedDate` fields, like the
///Resource/ProtocolAddress expirations, quantize to whole hours instead —
///`wireNormalized` is inert there.
///
///Caveats at the edges: bytes from a foreign encoder can need a second parse to
///reach the fixed point, `parse` does no finiteness check (NaN/±inf bit patterns
///parse into Dates that poison comparisons), and Dates within 2⁻²⁴ s of the
///reference epoch collapse onto it. DateEncodingTests sweeps these properties
///across the distinct float-grid regimes.
extension Date: LinearEncodable {
	public static func parse(_ input: Data) throws -> (Date, Int) {
		let (bitPattern, consumed) = try UInt64.parse(input)
		return (
			.init(
				timeIntervalSince1970: .init(
					bitPattern: bitPattern
				)
			),
			consumed
		)
	}

	public var wireFormat: Data {
		timeIntervalSince1970.bitPattern.wireFormat
	}
}

extension Date {
	///Self, pre-rounded to what the wire format can represent, so that a wire
	///round trip reproduces a finite Date exactly (see the note on
	///`Date: LinearEncodable`)
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
