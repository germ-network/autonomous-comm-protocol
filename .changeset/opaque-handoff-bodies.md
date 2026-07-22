---
"@germ-network/comm-protocol": minor
---

Add opaque-digest handoff bodies (v2), with corrected discriminators.

`createNewAgentHandoff` and `PublicAnchorAgent.verify(anchorHandoff:…)` gain
overloads taking `groupContext`/`mlsUpdateDigest` as `Data` instead of
`TypedDigest`. The new v2 signature bodies commit to those bytes as length-framed
values and never interpret them.

The motivation is ownership. A digest's algorithm is a facet of the MLS backend's
cipher suite, so requiring a `TypedDigest` meant the backend could not adopt a new
suite until this package shipped a matching `DigestTypes` case — a release
dependency in the wrong direction. Committing to opaque bytes removes it: the
caller's own self-describing encoding travels inside the value, so cross-era
signatures stay unambiguous without this package knowing the eras.

This is safe because a verifier never parses a digest out of a handoff — it
rebuilds the signature body from its own locally derived reference digest and
checks the signature against that. Agreement on the algorithm is enforced where
the session is established, not here.

**Nothing existing changes.** The typed overloads, the v1 bodies, and their
discriminators are untouched, so every already-issued handoff keeps verifying.
v1 and v2 are mutually unverifiable by construction (distinct discriminators),
which is pinned by tests in both directions.

**Discriminator note.** v1's `ActiveAgentBody` and `RetiredAgentBody` carry each
other's names. That is a labeling bug, not a security one — domain separation
needs the committed strings to be distinct, not correctly named, and they are —
but it is now frozen and commented as such, because renaming in place would
silently fail verification for every live relationship. The v2 bodies carry the
corrected names, `.v2`-suffixed: the plain corrected strings are unavailable
precisely because v1 has them live on the opposite structs. A test asserts all six
are pairwise distinct.
