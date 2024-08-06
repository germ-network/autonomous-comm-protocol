//
//  Convenience.swift
//
//
//  Created by Mark Xue on 6/23/24.
//

import CryptoKit
import Foundation

extension Digest {
    var data: Data { Data(bytes) }
    private var bytes: [UInt8] { Array(makeIterator()) }
}

// Ensure that SymmetricKey is generic password convertible.
extension SymmetricKey: RawRepresentableKey {
    public init<D>(rawRepresentation data: D) throws where D: ContiguousBytes {
        self.init(data: data)
    }

    public var rawRepresentation: Data {
        return dataRepresentation  // Contiguous bytes repackaged as a Data instance.
    }
}

extension ContiguousBytes {
    var dataRepresentation: Data {
        withUnsafeBytes {
            Data(Array($0))
        }
    }
}

/// Extension for making base64 representations of `Data` safe for
/// transmitting via URL query parameters
extension Data {
    /// Instantiates data by decoding a base64url string into base64
    ///
    /// - Parameter string: A base64url encoded string
    public init?(base64URLEncoded string: String) {
        self.init(base64Encoded: string.fromBase64URL)
    }

    /// Encodes the string into a base64url safe representation
    ///
    /// - Returns: A string that is base64 encoded but made safe for passing
    ///            in as a query parameter into a URL string
    public func base64URLEncodedString() -> String {
        base64EncodedString().toBase64URL
    }
}

extension String {
    // Make base64 string safe for passing into URL query params
    var toBase64URL: String {
        self.replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "=", with: "")
    }

    var fromBase64URL: String {
        self.replacingOccurrences(of: "_", with: "/")
            .replacingOccurrences(of: "-", with: "+")
            .base64padded
    }

    private var base64padded: String {
        let padding = 4 - count % 4
        guard (0..<4).contains(padding) else { return self }

        return self + String(repeating: "=", count: padding)
    }
}
