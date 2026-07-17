//
//  DateEncodingTests.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 7/17/26.
//

import CommProtocol
import Foundation
import Testing

///Sweeps the properties documented on `Date: LinearEncodable` across the
///distinct float-grid regimes: whether a raw Date survives the epoch
///conversion depends on the relative ulp of timeIntervalSinceReferenceDate
///vs timeIntervalSince1970 at that magnitude, so each regime gets a sweep.
struct DateEncodingTests {
	///(base seconds since the reference epoch, whether raw Dates at that
	///magnitude round-trip exactly — true iff the 1970-epoch grid is at
	///least as fine as the reference-epoch grid there)
	static let regimes: [(base: Double, rawRoundTripExact: Bool)] = [
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

	@Test func normalizedDatesRoundTripExactly() throws {
		for regime in Self.regimes {
			for (step, date) in Self.sweep(from: regime.base).enumerated() {
				let normalized = date.wireNormalized
				#expect(
					normalized.wireFormat == date.wireFormat,
					"base \(regime.base), step \(step)"
				)
				let parsed = try Date.finalParse(normalized.wireFormat)
				#expect(parsed == normalized, "base \(regime.base), step \(step)")
			}
		}
	}

	@Test func parseIsAFixedPoint() throws {
		for regime in Self.regimes {
			for (step, date) in Self.sweep(from: regime.base).enumerated() {
				let once = try Date.finalParse(date.wireFormat)
				#expect(
					once.wireFormat == date.wireFormat,
					"base \(regime.base), step \(step)"
				)
				let twice = try Date.finalParse(once.wireFormat)
				#expect(twice == once, "base \(regime.base), step \(step)")
			}
		}
	}

	@Test func rawRoundTripExactnessTracksTheGridRegime() throws {
		//canary for why wireNormalized exists: raw Dates fail bit-exact
		//equality after a round trip wherever the 1970 grid is coarser
		//(half the steps in 2026, nearly all of them at the 2001 epoch),
		//and survive wherever it isn't. If a coarser-grid regime ever
		//reports zero failures, Date's storage or the wire format changed
		//and wireNormalized can be retired; zero failures in the other
		//regimes is expected grid coincidence, not a fix.
		for regime in Self.regimes {
			let failures = try Self.sweep(from: regime.base).count {
				try Date.finalParse($0.wireFormat) != $0
			}
			if regime.rawRoundTripExact {
				#expect(failures == 0, "base \(regime.base)")
			} else {
				#expect(failures > 0, "base \(regime.base)")
			}
		}
	}

	//the live-clock spot check formerly in ResourceTests, tightened to the
	//exact contract: normalize, then equality is bit-exact
	@Test func liveClockNormalizedRoundTrip() throws {
		let stamped = Date.now.wireNormalized
		#expect(try Date.finalParse(stamped.wireFormat) == stamped)
	}
}
