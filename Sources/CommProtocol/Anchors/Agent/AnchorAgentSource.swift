//
//  AnchorAgentSource.swift
//  CommProtocol
//
//  Created by Mark @ Germ on 4/29/25.
//

import Foundation

//PrivateAgentAnchor can save the associated proof at creation time
extension PrivateAnchorAgent {
	public enum Source {
		//hello, unquely, allows regeneration of the source
		case hello(HelloInputs)
		case reply(AnchorReply)
		case handoff(AnchorHandoff)

		public enum Archive: Codable {
			case hello(HelloInputs.Archive)
			case reply(Data)
			case handoff(Data)
		}

		public var archive: Archive {
			get throws {
				switch self {
				case .hello(let hello): .hello(try hello.archive)
				case .reply(let value): .reply(try value.wireFormat)
				case .handoff(let value): .handoff(try value.wireFormat)
				}
			}
		}

		public init(archive: Archive) throws {
			switch archive {
			case .hello(let archive):
				self = .hello(try .init(archive: archive))
			case .reply(let data): self = .reply(try .finalParse(data))
			case .handoff(let data): self = .handoff(try .finalParse(data))
			}
		}

		//data we cache to regenerate the hello
		public struct HelloInputs {
			let anchorKey: AnchorPublicKey
			let attestation: AnchorAttestation
			let proofHistory: [DatedProof]

			init(
				anchorKey: AnchorPublicKey,
				attestation: AnchorAttestation,
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
