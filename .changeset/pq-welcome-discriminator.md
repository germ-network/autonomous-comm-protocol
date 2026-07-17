---
"@germ-network/autonomous-comm-protocol": patch
---

Fix a cross-route parsing confusion in the PQ establishment welcomes
(`PQAppWelcome` / `PQAnchorWelcome`, shipped in 1.6.0). Their domain separation
from the classical `AppWelcome` / `AnchorWelcome` rested on the signed content's
fifth element diverging in layout, which in turn depended on the signing-key and
digest prefix enums keeping disjoint raw values. A crafted 128-byte classical
key package round-tripped byte-identically through the PQ parse, so a classical
welcome's own agent signature also validated it as a PQ welcome.

`PQEstablishmentKeyMaterial` now leads with a checked reserved `0x00` byte — the
one length prefix a classical key-package `Data` field can never carry — so both
cross-parse directions reject deterministically at decode, independent of any
enum raw values. This changes the PQ welcome wire format (the classical welcomes
are byte-for-byte unchanged); regenerate any PQ welcomes serialized under 1.6.0.
