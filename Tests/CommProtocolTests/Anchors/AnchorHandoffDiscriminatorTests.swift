//
//  AnchorHandoffDiscriminatorTests.swift
//  CommProtocol
//
//  Pins the AnchorHandoff signature-body discriminator strings. Two of them are
//  historically swapped relative to the struct they name (ActiveAgentBody signs
//  "…RetiredAgentBody"; RetiredAgentBody signs "…ActiveAgentBody"). Those strings
//  are part of the signed bytes of every CLASSICAL anchor handoff in production,
//  so they are frozen: renaming a string to match its struct would be a breaking
//  wire change. This test fails loudly if a future edit "corrects" the labels.
//  The clean fix is a PQ variant (PQAnchorHandoff) with its own namespace and
//  correctly-matching labels — never a rename of these classical strings.
//

import Testing

@testable import CommProtocol

struct AnchorHandoffDiscriminatorTests {
	// Exact frozen values. Do not update these to "fix" the swap — see
	// AnchorHandoff.swift's "HISTORICAL LABEL SWAP" note.
	@Test func discriminatorsAreFrozen() {
		#expect(AnchorHandoff.ActiveAnchorBody.discriminator == "AnchorHandoff.ActiveAnchorBody")
		#expect(AnchorHandoff.ActiveAgentBody.discriminator == "AnchorHandoff.RetiredAgentBody")
		#expect(AnchorHandoff.RetiredAgentBody.discriminator == "AnchorHandoff.ActiveAgentBody")
	}

	// The swap is a labeling mismatch only: the three strings remain distinct, so
	// the three signer roles stay domain-separated and no signature can be
	// replayed across roles.
	@Test func discriminatorsAreDistinct() {
		let all = Set([
			AnchorHandoff.ActiveAnchorBody.discriminator,
			AnchorHandoff.ActiveAgentBody.discriminator,
			AnchorHandoff.RetiredAgentBody.discriminator,
		])
		#expect(all.count == 3)
	}
}
