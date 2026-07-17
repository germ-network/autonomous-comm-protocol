//
//  DateEncodingTests.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 7/17/26.
//

import CommProtocol
import Foundation
import Testing

///Sweeps the properties documented on `Date: LinearEncodable`: the epoch
///conversion in the wire format rounds away sub-µs precision for about half
///of arbitrary clock values, but parsing is a fixed point, and a
///`wireNormalized` Date round-trips to exact equality with identical bytes.
struct DateEncodingTests {
	//deterministic sweep: base is mid-2026 in the reference epoch, stepped by
	//2^-23 s (~one ulp at this magnitude) to exercise the low mantissa bits
	//the 1970-epoch conversion rounds away
	static let sweep: [Date] = (0..<10_000).map {
		Date(timeIntervalSinceReferenceDate: 806_000_000.0 + Double($0) * 0x1p-23)
	}

	@Test func normalizedDatesRoundTripExactly() throws {
		for date in Self.sweep {
			let normalized = date.wireNormalized
			#expect(normalized.wireFormat == date.wireFormat)
			let (parsed, consumed) = try Date.parse(normalized.wireFormat)
			#expect(consumed == normalized.wireFormat.count)
			#expect(parsed == normalized)
		}
	}

	@Test func parseIsAFixedPoint() throws {
		for date in Self.sweep {
			let (once, _) = try Date.parse(date.wireFormat)
			#expect(once.wireFormat == date.wireFormat)
			let (twice, _) = try Date.parse(once.wireFormat)
			#expect(twice == once)
		}
	}

	@Test func rawDatesDoNotReliablyRoundTrip() throws {
		//canary for why wireNormalized exists: ~50% of the sweep fails
		//bit-exact equality after one round trip. If this ever reports zero
		//failures, Date's storage or the wire format changed and
		//wireNormalized can be retired.
		var failures = 0
		for date in Self.sweep {
			if try Date.parse(date.wireFormat).0 != date {
				failures += 1
			}
		}
		#expect(failures > 0)
	}
}
