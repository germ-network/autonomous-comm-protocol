//
//  Dates.swift
//  CommProtocol
//
//  Created by Mark at Germ  on 9/19/24.
//

import Foundation

//two different formats for dates

//we transform the date into a
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

public struct RoundedDate: Equatable {
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
