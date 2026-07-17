//
//  DateEncodingTests.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 7/17/26.
//

import CommProtocol
import Foundation
import Testing

///Sweeps the properties documented on `WireDate` across the distinct
///float-grid regimes: whether the epoch conversion in the wire format
///moves a raw Date depends on the relative ulp of
///timeIntervalSinceReferenceDate vs timeIntervalSince1970 at that
///magnitude, so each regime gets a sweep.
struct DateEncodingTests {
	///(base seconds since the reference epoch, whether the epoch
	///conversion is exact there — true iff the 1970-epoch grid is at
	///least as fine as the reference-epoch grid)
	static let regimes: [(base: Double, epochConversionExact: Bool)] = [
		(1.0, false),  //at the 2001 epoch: 1970 grid vastly coarser
		(-800_000_000.0, true),  //~1975: 1970 grid finer
		(806_000_000.0, false),  //~2026: 1970 grid one binade coarser
		(1_100_000_000.0, true),  //~2035–2069: grids coincide
		(2_200_000_000.0, true),  //~2070+: grids coincide
	]

	//stepped by the base's own ulp to exercise the low mantissa bits the
	//epoch conversion can round away
	static func sweep(from base: Double) -> [Date] {
		(0..<64).map {
			Date(timeIntervalSinceReferenceDate: base + Double($0) * base.ulp)
		}
	}

	@Test func wireDatesRoundTripExactly() throws {
		for regime in Self.regimes {
			for (step, date) in Self.sweep(from: regime.base).enumerated() {
				let wireDate = WireDate(date: date)
				let once = try WireDate.finalParse(wireDate.wireFormat)
				#expect(once == wireDate, "base \(regime.base), step \(step)")
				#expect(
					once.wireFormat == wireDate.wireFormat,
					"base \(regime.base), step \(step)"
				)
				let twice = try WireDate.finalParse(once.wireFormat)
				#expect(twice == once, "base \(regime.base), step \(step)")
			}
		}
	}

	@Test func normalizationTracksTheGridRegime() throws {
		//canary for why WireDate normalizes at construction: the epoch
		//conversion moves raw Dates wherever the 1970 grid is coarser
		//(half the steps in 2026, nearly all of them at the 2001 epoch),
		//and is exact wherever it isn't. If a coarser-grid regime ever
		//reports zero moved, Date's storage or the wire format changed
		//and the normalization can be retired; zero moved in the other
		//regimes is expected grid coincidence, not a fix.
		for regime in Self.regimes {
			let moved = Self.sweep(from: regime.base).count {
				WireDate(date: $0).date != $0
			}
			if regime.epochConversionExact {
				#expect(moved == 0, "base \(regime.base)")
			} else {
				#expect(moved > 0, "base \(regime.base)")
			}
		}
	}

	//live-clock spot check on the exact contract
	@Test func liveClockRoundTrip() throws {
		let stamped = WireDate.now
		#expect(try WireDate.finalParse(stamped.wireFormat) == stamped)
	}
}
