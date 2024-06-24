//
//  Convenience.swift
//
//
//  Created by Mark Xue on 6/23/24.
//

import Foundation
import CryptoKit

public enum TypedCodableError: Error {
    case decode(String, Error)
}

extension TypedCodableError: LocalizedError {
    public var errorDescription: String? {
        switch self{
        case .decode(let string, let error):
            "Error decoding type \(string): \(error.localizedDescription)"
        }
    }
}

extension Encodable {
    var encoded: Data {
        get throws { try JSONEncoder().encode(self) }
    }
}

///Captures type information when throwing a Json decoder error so we know what object it was trying to decode
extension Data {
    func decoded<T:Decodable>() throws -> T {
        do {
            return try JSONDecoder().decode(T.self, from: self)
        } catch {
            throw TypedCodableError.decode("\(type(of: T.self))", error)
        }
    }
}

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
