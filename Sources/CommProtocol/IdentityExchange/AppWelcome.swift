//
//  AppWelcome.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 2/9/25.
//

import CryptoKit
import Foundation

///This is the accompanying Application-level data to an MLS welcome, issued in response
///to a KeyPackage message contained in an AppHello
///
///The AppWelcome specifies the parameters of the accompanying MLS Welcome:
/// - groupId (randomly gemerated)
/// - should comprise 2 members
///     - the introduced AgentId at index 0
///     - the recipient agentId at index 1

public struct AppWelcome: Equatable {
	public let introduction: IdentityIntroduction
	public let signedContent: SignedObject<Content>

	public struct Content: Equatable, Sendable {
		public let groupId: DataIdentifier
		public let agentData: AgentUpdate
		public let seqNo: UInt32  //sets the initial seqNo
		public let sentTime: Date  //just as messages assert local send time
		public let keyPackageData: Data
	}

	//This gets transmitted, encrypted to the HPKE init key
	public struct Combined: Equatable {
		public let appWelcome: AppWelcome
		public let mlsWelcomeData: Data

		public init(appWelcome: AppWelcome, mlsMessageData: Data) {
			self.appWelcome = appWelcome
			self.mlsWelcomeData = mlsMessageData
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

extension AppWelcome.Content: LinearEncodedQuintuple {
	public var first: DataIdentifier { groupId }
	public var second: AgentUpdate { agentData }
	public var third: UInt32 { seqNo }
	public var fourth: Date { sentTime }
	public var fifth: Data { keyPackageData }

	public init(
		first: DataIdentifier,
		second: AgentUpdate,
		third: UInt32,
		fourth: Date,
		fifth: Data
	) throws {
		self.init(
			groupId: first,
			agentData: second,
			seqNo: third,
			sentTime: fourth,
			keyPackageData: fifth
		)
	}
}

extension AppWelcome.Combined: LinearEncodedPair {
	public var first: AppWelcome { appWelcome }
	public var second: Data { mlsWelcomeData }

	public init(first: AppWelcome, second: Data) throws {
		self.init(appWelcome: first, mlsMessageData: second)
	}
}

//The AppWelcome is encrypted to an assumed published key in HPKE basic mode
//(we don't know the sender ahead of time)
//should presume confidentiality but not authenticity.
//We need to confirm the identity key in the AppWelcome signs
//over the remainder of the data in the AppWelcome
//some indirectly through the delegate AgentKey
extension AppWelcome {
	public struct Validated {
		public let coreIdentity: CoreIdentity
		public let introContents: IdentityIntroduction.Contents
		public let imageResource: Resource
		public let welcomeContent: AppWelcome.Content
	}

	public func validated(myAgent: AgentPublicKey) throws -> Validated {
		let agentType = AgentTypes.welcome(
			remoteAgentId: myAgent,
			groupId: signedContent.content.groupId
		)

		guard
			let context = try agentType.generateContext(
				myAgentId: introduction.signedContents.content.agentKey
			)
		else {
			throw ProtocolError.unexpected("mismatched context")
		}

		let (coreIdentity, introContents, imageResource) = try introduction.validated(
			context: context
		)

		return .init(
			coreIdentity: coreIdentity,
			introContents: introContents,
			imageResource: imageResource,
			welcomeContent: try introContents.agentKey
				.validate(signedObject: signedContent)
		)
	}
}

extension AppWelcome {
	static public func mock(
		remoteAgentKey: AgentPublicKey,
		keyPackageData: Data
	) throws -> AppWelcome {
		let (identityKey, signedIdentity) =
			try Mocks
			.mockIdentity()

		let groupId = DataIdentifier(width: .bits256)

		let (agentKey, introduction) =
			try identityKey
			.createNewDelegate(
				signedIdentity: signedIdentity,
				identityMutable: .mock(),
				agentType: .welcome(
					remoteAgentId: remoteAgentKey,
					groupId: groupId
				)
			)

		return try agentKey.createAppWelcome(
			introduction: introduction,
			agentData: .mock(),
			groupId: groupId,
			keyPackageData: keyPackageData
		)
	}
}
