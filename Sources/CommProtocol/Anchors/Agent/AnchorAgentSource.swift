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
		case hello(AnchorHello)
		case reply(AnchorReply)
		case handoff(AnchorHandoff)

		public enum Archive: Codable {
			case hello(Data)
			case reply(Data)
			case handoff(Data)
		}

		public var archive: Archive {
			get throws {
				switch self {
				case .hello(let value): .hello(try value.wireFormat)
				case .reply(let value): .reply(try value.wireFormat)
				case .handoff(let value): .handoff(try value.wireFormat)
				}
			}
		}

		public init(archive: Archive) throws {
			switch archive {
			case .hello(let data): self = .hello(try .finalParse(data))
			case .reply(let data): self = .reply(try .finalParse(data))
			case .handoff(let data): self = .handoff(try .finalParse(data))
			}
		}
	}
}
