---
"@germ-network/autonomous-comm-protocol": minor
---

Widen the `swift-crypto` dependency to `from: "5.0.0"` as part of the org-wide
swift-crypto 5 migration.

`AtprotoTypes` and `GermConvenience` are revision-pinned to their swift-crypto-5
commits (germ-network/AtprotoTypes#69, and GermConvenience main) until each
cuts a release, because both released lines still cap swift-crypto at
`..<5.0.0`.

No source changes were required.

**Secret-bytes audit (no adoption).** The package holds key material — the
identity signing key (`IdentityPrivateKey`, a `CryptoKit`/swift-crypto private
key type) and `TypedKeyMaterial.keyData`, which is either a symmetric key or an
HPKE-encapsulated (non-secret) byte string disambiguated by `algorithm`. Moving
`keyData` into `SecretBytes` would change a wire/format-level type shared across
the codec, and the private keys already live in swift-crypto's own key types
rather than a plaintext field, so swift-secret-bytes is deliberately not
adopted here.
