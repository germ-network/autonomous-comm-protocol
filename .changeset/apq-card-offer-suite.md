---
"@germ-network/autonomous-comm-protocol": minor
---

Carry a post-quantum (TwoMLSPQ) key package in the card offer as a legacy shim. `MLSIntroduction.postQuantumShim(kemPublicKeyData:encodedKeyPackage:)` builds an entry that is wire-indistinguishable from a classical one — the suite and kem key stay classical and the self-contained PQ key package rides in `encodedKeyPackage` — so already-deployed parsers accept a card that offers both classical and PQ. PQ-capable consumers detect the PQ entry by parsing its key package; publishers keep the classical entry at index 0. The card wire format is unchanged (byte-identical, golden-pinned); an honest, suite-typed card format is left for a future replacement.
