//
//  AnchorAgentSource.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 4/29/25.
//

import Foundation

//PrivateAgentAnchor can save the associated proof at creation time
extension PrivateAnchorAgent {
	public enum Source: Sendable {
		//hello, unquely, allows regeneration of the source
		case hello(HelloInputs)
		case reply
		//handoff is not necessarily pre-generated
		case handoff

		public enum Archive: Codable {
			case hello(HelloInputs.Archive)
			case reply
			case handoff
		}

		public var archive: Archive {
			get throws {
				switch self {
				case .hello(let hello): .hello(try hello.archive)
				case .reply: .reply
				case .handoff: .handoff
				}
			}
		}

		public init(archive: Archive) throws {
			switch archive {
			case .hello(let archive):
				self = .hello(try .init(archive: archive))
			case .reply: self = .reply
			case .handoff: self = .handoff
			}
		}

		//data we cache to regenerate the hello
		public struct HelloInputs: Sendable {
			let anchorKey: AnchorPublicKey
			let attestation: DependentIdentity
			let proofHistory: [DatedProof]

			init(
				anchorKey: AnchorPublicKey,
				attestation: DependentIdentity,
				proofHistory: [DatedProof]
			) {
				self.anchorKey = anchorKey
				self.attestation = attestation
				self.proofHistory = proofHistory
			}

			public struct Archive: Codable {
				let anchorKey: Data
				let attestation: Data
				let proofHistory: [Data]
			}

			var archive: Archive {
				get throws {
					.init(
						anchorKey: anchorKey.wireFormat,
						attestation: try attestation.wireFormat,
						proofHistory: proofHistory.compactMap {
							try? $0.wireFormat
						}
					)
				}
			}

			init(archive: Archive) throws {
				anchorKey = try .init(wireFormat: archive.anchorKey)
				attestation = try .finalParse(archive.attestation)
				proofHistory = archive.proofHistory
					.compactMap { try? .finalParse($0) }
			}
		}
	}
}
