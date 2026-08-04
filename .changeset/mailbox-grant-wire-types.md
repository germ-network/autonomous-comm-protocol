---
"@germ-network/autonomous-comm-protocol": minor
---

Add mailbox-v2 wire types (GER-1965/1966/1967): `swift-cbor` pinned at the same
revision as CoreAppLogic, a `DeterministicCbor` seam, and `MailboxGrant`
(`{authKey, serviceHost, expiration}`) with `address`/`putTag` HMAC-SHA256
derivation, cross-validated against germ-service's test vectors. A
`ProtocolAddress <-> MailboxGrant` bridge lets a grant ride the existing
`identifier` field on the wire-frozen PQ establishment surfaces (an authKey's
32 decoded bytes never collide with a legacy `crypto.randomUUID()` address's
27) with zero arity change. `AgentUpdateV2` (grants only) rides a new
`CommProposal` tag, emitted only to peers observed >= `mailboxGrantVersion`
(2.4.0) — existing proposal tags and the classical `AgentUpdate`/
`ProtocolAddress` wire format are unchanged (fixture-pinned).
