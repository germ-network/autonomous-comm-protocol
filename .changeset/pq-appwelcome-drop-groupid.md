---
"@germ-network/autonomous-comm-protocol": minor
---

Drop the shared `groupId` from the PQ card establishment reply. `PQAppWelcome.Content` no longer carries a `DataIdentifier groupId` (Quintuple → Quad), and the introduction's signature context switches from `.reply`/`.welcome(groupId:)` to a new seedless `AgentTypes.pqCardEstablishment(remoteAgentId:)` that binds only the answered peer agent (the cross-invitation anti-splice), not a per-session seed.

Rationale: a PQ card session's identity is the crate's LOCAL send-group id (each endpoint keys its own), not a shared, initiator-chosen id transmitted on the wire and used as a shared at-rest record key. The session↔welcome↔identity weld is already the born-dedicated establishment handoff over `sha256(welcome)`, so the seed==groupId cross-check the introduction used to carry is redundant (the agent-signed `Content` plus the handoff pin the establishment).

Wire-breaking for the PQ card reply only; classical `AppWelcome` is unchanged. Adopters must regenerate PQ card invitations/establishments (pre-ship). No new errors. Verified: the full CommProtocol suite passes, including the recipient-binding anti-splice test (`testWrongRecipientAgentFailsValidation`), which confirms the peer-agent binding survives the seed removal.
