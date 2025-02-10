//
//  AppWelcome.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 2/9/25.
//

import Foundation

///This is the accompanying Application-level data to an MLS welcome, issued in response
///to a KeyPackage message contained in an AppHello
///
///The AppWelcome specifies the parameters of the accompanying MLS Welcome:
/// - groupId (randomly gemerated)
/// - should comprise 2 members
///     - the introduced AgentId at index 0
///     - the recipient agentId at index 1

public struct AppWelcome {
    public let introduction: IdentityIntroduction
    public let signedContent: SignedObject<Content>

    public struct Content: Sendable {
        public let groupId: DataIdentifier
        public let agentData: AgentUpdate
        public let seqNo: UInt32  //sets the initial seqNo
        public let sentTime: Date  //just as messages assert local send time
    }

    //This gets transmitted, encrypted to the HPKE init key
    public struct Combined {
        public let appWelcome: AppWelcome
        public let mlsMessageData: Data
        
        public init(appWelcome: AppWelcome, mlsMessageData: Data) {
            self.appWelcome = appWelcome
            self.mlsMessageData = mlsMessageData
        }
    }
}

extension AppWelcome: LinearEncodedPair {
    public var first: IdentityIntroduction { introduction }
    public var second: SignedObject<Content> { signedContent }

    public init(
        first: IdentityIntroduction,
        second: SignedObject<Content>
    ) throws {
        self.init(introduction: first, signedContent: second)
    }
}

extension AppWelcome.Content: LinearEncodedQuad {
    public var first: DataIdentifier { groupId }
    public var second: AgentUpdate { agentData }
    public var third: UInt32 { seqNo }
    public var fourth: Date { sentTime }

    public init(
        first: DataIdentifier,
        second: AgentUpdate,
        third: UInt32,
        fourth: Date
    ) throws {
        self.init(
            groupId: first,
            agentData: second,
            seqNo: third,
            sentTime: fourth
        )
    }
}

extension AppWelcome.Combined: LinearEncodedPair {
    public var first: AppWelcome { appWelcome }
    public var second: Data { mlsMessageData }

    public init(first: AppWelcome, second: Data) throws {
        self.init(appWelcome: first, mlsMessageData: second)
    }
}
