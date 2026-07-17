---
"@germ-network/autonomous-comm-protocol": minor
---

Add `PQAnchorWelcome` / `PQAppWelcome`: parallel establishment-reply structs for
the PQ (TwoMLSPQ v20) path. The classical `AnchorWelcome` / `AppWelcome` stay
live unchanged — routing discriminates (the PQ reply only ever answers a PQ
hello), so there is no version field.

Both carry the new `PQEstablishmentKeyMaterial` pair inside the signed body:
the replier's CLASSICAL return key package plus a `TypedDigest` commitment
(SHA-256) to the A.4 bootstrap PQ key package, binding the deferred PQ key
material to the sender's identity root. New signature discriminators
("PQAnchorReply.*") domain-separate the anchor arm from the classical welcome;
the card arm's content layout diverges structurally at the fifth element.

New API: `PrivateActiveAnchor.createPQAnchorWelcome`,
`AnchorPublicKey.verify(pqReply:recipient:)`,
`AgentPrivateKey.createPQAppWelcome`, `PQAppWelcome.validated(myAgent:)`,
plus `PQAppWelcome.mock` / `PQEstablishmentKeyMaterial.mock` in
CommProtocolMocks.
