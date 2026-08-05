---
"@germ-network/autonomous-comm-protocol": patch
---

Re-base `DefinedWidthBinary.init(wireFormat:)` so it stores its payload as a
zero-based `Data` rather than a `suffix(from:)` view. `Data` is its own
SubSequence, so the old form handed conformers a `checkedData` whose valid range
began at the caller's `startIndex + 1` — safe for `.first`/`.count`/`for`-in, a
wrong-window read or a trap for `[0]` or `[0..<n]`. `parse(wireFormat:)` has
always re-based, so the two construction paths disagreed while nothing in the
type signalled which one produced a value; every `DataIdentifier`,
`TypedKeyMaterial`, and `TypedDigest` built via `init(wireFormat:)` carried a
non-zero `startIndex`. The framing layer's other two slice factories are
re-based the same way: `DeclaredWidthData.parse` and the `Data` field in
`OptionalData.parse`, which backs `Data: LinearEncodable`. Every `Data` the
framing layer hands out is now zero-based, so consumers that index absolutely —
including ones outside this package — cannot be handed a view they have no way
to detect. Wire format is unchanged; this only affects the indices of the
decoded value in memory.
