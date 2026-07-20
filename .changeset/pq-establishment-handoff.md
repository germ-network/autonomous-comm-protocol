---
"@germ-network/autonomous-comm-protocol": minor
---

Add the born-dedicated establishment delegation (TwoMLSPQ contract 26): `PQCardEstablishmentHandoff` and `PQAnchorEstablishmentHandoff` carry the identity-signed handoff artifact on the establishment staple, next to the unmodified spec-conformant return welcome, with every to-be-signed slot derived from the welcome bytes (`PQEstablishmentBinding`) so the delegation binds the exact group being joined and cannot cross-validate as a steady-state rotation handoff. Create via `AgentPrivateKey.completePQCardEstablishment` / `PrivateActiveAnchor.createPQAnchorEstablishmentHandoff`.
