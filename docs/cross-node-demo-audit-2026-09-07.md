# Cross-node disagreement demo

## Pass gates

- [x] Add two independent node-local disagreement examples to the canonical
  scenario save: an MPLS label binding and a VXLAN service VNI binding.
- [x] Reuse generated route declarations and the existing consistency-finding
  interface. Keep packet continuity valid and protocol interpretation in the
  example plug-in, not in core.
- [x] Derive findings from the persisted sender/receiver observations, with
  exact node, revision and resource provenance. Equal values produce no
  mismatch; missing/incomplete evidence is not proof of disagreement.
- [x] Prove forward disagreement and an independently consistent reverse
  observation, plus healthy, missing, incomplete and malformed-evidence tests.
- [ ] Preserve the full-scale ten-node archive, rebuild it once, and browse
  both new cases and an ordinary route on the actual server.
- [ ] Run focused regressions, the frontend suite, author smoke/conformance,
  stub checks and an independent review; update user and author documentation.

These are contradictory configuration/capture observations, not proof that a
packet was physically dropped. Different forward and reverse paths alone are
not an inconsistency. The core continues to enforce exact packet-state
continuity; an invalid before/after chain is not a valid demo fault injection.

## Review findings addressed

- A catalog-level `inconsistent` outcome marked both directions regardless of
  their observations. The new cases declare normal forwarding and derive
  disagreement from the actual directional evidence instead.
- Generic consistency aggregation ignored explicit findings outside its
  category allowlist. Explicit `affects_consistency: true` now controls the
  verdict and issue references, with a regression for an open plug-in category.
- Source identity, observation timestamp, missing values and malformed
  observation containers needed validation before comparing values. Invalid
  evidence now yields an informational unknown, not a claimed disagreement.
- The generator's source-table mapping did not admit the two new diagnostic
  resource kinds. Both use its existing generic forwarding-resource table.

Independent review found no remaining actionable defects in the focused
implementation. New evidence tests pass: 27 tests and 158 subtests; the
archive-backed generator subset passes 6 tests and 805 subtests. The generic
consistency regression and the existing cross-layer regression also pass.
