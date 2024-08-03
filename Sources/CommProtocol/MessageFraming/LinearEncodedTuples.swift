//
//  LinearEncodedTuples.swift
//  CommProtocol
//
//  Created by Mark Xue on 8/2/24.
//

import Foundation

///let conforming types declare their types
protocol LinearEncodedPair: LinearEncodable {
    associatedtype First: LinearEncodable
    associatedtype Second: LinearEncodable

    var first: First { get }
    var second: Second { get }

    init(first: First, second: Second) throws
}

extension LinearEncodedPair {
    public static func parse(_ input: Data) throws -> (Self, Int) {
        let (first, consumed) = try First.parse(input)
        guard consumed < input.count else {
            throw LinearEncodingError.unexpectedEOF
        }
        let slice = input.suffix(from: input.startIndex + consumed)
        let (second, secondConsumed) = try Second.parse(slice)

        let result = try Self(first: first, second: second)
        return (result, consumed + secondConsumed)
    }

    public var wireFormat: Data {
        get throws {
            try first.wireFormat
                + second.wireFormat
        }
    }

}

protocol LinearEncodedTriple: LinearEncodable {
    associatedtype First: LinearEncodable
    associatedtype Second: LinearEncodable
    associatedtype Third: LinearEncodable

    var first: First { get }
    var second: Second { get }
    var third: Third { get }

    init(first: First, second: Second, third: Third) throws
}

extension LinearEncodedTriple {
    public static func parse(_ input: Data) throws -> (Self, Int) {
        let (first, consumed) = try First.parse(input)
        guard consumed < input.count else {
            throw LinearEncodingError.unexpectedEOF
        }
        let slice = input.suffix(from: input.startIndex + consumed)
        let (second, secondConsumed) = try Second.parse(slice)

        let secondSlice = slice.suffix(from: slice.startIndex + secondConsumed)
        let (third, thirdConsumed) = try Third.parse(secondSlice)

        let result = try Self(first: first, second: second, third: third)
        return (result, consumed + secondConsumed + thirdConsumed)
    }

    public var wireFormat: Data {
        get throws {
            try first.wireFormat
                + second.wireFormat
                + third.wireFormat
        }
    }

}
