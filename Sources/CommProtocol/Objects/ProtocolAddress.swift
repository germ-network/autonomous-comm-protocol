//
//  ProtocolAddress.swift
//
//
//  Created by Mark @ Germ on 6/24/24.
//

import Foundation

public struct ProtocolAddress: Sendable, Equatable {
    public let identifier: String
    public let serviceHost: String
    public let expiration: RoundedDate

    struct Constants {
        static let validNowBuffer: TimeInterval = 3600
        static let validTodayBuffer: TimeInterval = 24 * 3600

    }

    init(identifier: String, serviceHost: String, expiration: Date) {
        self.identifier = identifier
        self.serviceHost = serviceHost
        self.expiration = .init(date: expiration)
    }

    init(identifier: String, serviceHost: String, expiration: RoundedDate) {
        self.identifier = identifier
        self.serviceHost = serviceHost
        self.expiration = expiration
    }

    public var validImmediateUse: Bool {
        expiration.date.timeIntervalSinceNow > Constants.validNowBuffer
    }

    public var validToday: Bool {
        expiration.date.timeIntervalSinceNow > Constants.validTodayBuffer
    }
}

//protocol adddress identified by combination of identifer and host, not the expiration
extension ProtocolAddress: Hashable {
    public static func == (lhs: ProtocolAddress, rhs: ProtocolAddress) -> Bool {
        lhs.identifier == rhs.identifier && lhs.serviceHost == rhs.serviceHost
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(identifier)
        hasher.combine(serviceHost)
    }
}

extension ProtocolAddress: Identifiable {
    public var id: String { serviceHost + identifier }
}

extension ProtocolAddress: LinearEncodedTriple {
    public var first: String { identifier }
    public var second: String { serviceHost }
    public var third: RoundedDate { expiration }

    public init(first: String, second: String, third: RoundedDate) throws {
        self.init(identifier: first, serviceHost: second, expiration: third)
    }
}
