---
"@germ-network/autonomous-comm-protocol": minor
---

Widen the `swift-crypto` dependency to `from: "5.0.0"` as part of the org-wide
swift-crypto 5 migration.

`GermConvenience` moves to its released 0.10.0 (the swift-crypto-5 release).
`AtprotoTypes` is revision-pinned to its swift-crypto-5 commit
(germ-network/AtprotoTypes#69) until it cuts a release, because its released
line still caps swift-crypto at `..<5.0.0`.

No source changes were required.

**Secret-bytes audit (no adoption).** The package holds key material — the
identity signing key (`IdentityPrivateKey`, a `CryptoKit`/swift-crypto private
key type) and `TypedKeyMaterial.keyData`, which is either a symmetric key or an
HPKE-encapsulated (non-secret) byte string disambiguated by `algorithm`. Moving
`keyData` into `SecretBytes` would change a wire/format-level type shared across
the codec, and the private keys already live in swift-crypto's own key types
rather than a plaintext field, so swift-secret-bytes is deliberately not
adopted here.
