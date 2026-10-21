# SN013 — P2: invalid topology controls relabel the retained result's clock policy

Revision: `112d346447316af6ae8f5503c252d5b66d317b07`.
Status: browser-confirmed in S184 and repeated in S190, S196, S202, S208 and SX012.

Changing Clock policy while the time input is invalid changes the **Clock**
chip beside the retained topology result. That chip then describes the rejected
form controls instead of the policy used for the last successful reconstruction.
The inverse transition can label a retained Best effort result as Strict even
though no valid Strict reconstruction occurred. The validation error, retained
basis and data, and retry-button recovery remain correct.

## Browser reproduction

1. In the synthetic 1M node demo, choose **Underlay connectivity**, **Hardware
   observed forwarding**, **Absolute timestamp**, and **Strict**. Disable
   **Follow timeline selection**, use the observed capture-start timestamp
   `1759679999996000000`, and reconstruct successfully.
2. Submit another valid reconstruction. S184's `pending` records **Querying**
   and the disabled **Reconstructing...** button.
3. Fill the absolute timestamp with `not-a-time`. The saved
   `beforeInvalidPolicy` still shows Querying and the disabled button, proving
   the newer form edit overlaps the pending operation.
4. Change Clock policy to **Best effort**, triggering validation. The error is
   correctly **Absolute time must be an integer nanosecond timestamp.**, and
   **Reconstruct topology** is enabled again.
5. The retained result's chip now reads **Clock best_effort**, although its
   successful baseline was Strict. Its absolute basis, clock cards, resources
   and connectivity remain unchanged. The later `lateInvalid` observation
   retains both the error and the incorrect chip.
6. Restore the valid capture-start input and explicitly reconstruct. The error
   clears and a successful Best effort result is applied.

S190 repeats this sequence at the observed capture End,
`1759680719996000000`. Both `pending` and `invalidDraft` record Querying and
the disabled submit button before the policy change. The invalid action keeps
the prior End basis and exact validation error with retry enabled, but changes
the retained Strict result's chip to **best_effort**. The later observation
repeats the mismatch; correcting End and explicitly reconstructing applies
Best effort successfully. This is another reproduction of SN013, with pending
UI overlap observed but no assertion about server-side cancellation.

SX012 expands the same defect without requiring a pending request. Starting
from the valid Best effort absolute result, entering `not-a-time` and selecting
Strict relabels that retained result **Clock strict**. A relative-time variant
then retains a successful Strict **−5-second** capture-vector result: entering
`+1` and selecting Best effort shows **A watermark-relative time must be zero
or in the past.**, but changes the applied chip to **best_effort**. The basis,
rows and clock cards retain the −5-second result on the later read.

The relative baseline's input had been edited to `0`, while its recorded applied
basis was still −5 seconds. This report uses the applied basis as the oracle;
it does not claim a successful zero-offset baseline before invalidation.
Correcting to `0` and explicitly reconstructing subsequently applies the
zero-offset Best effort result. Restoring absolute capture start and Strict
also succeeds. These are repetitions of one attribution defect, not additional
unique findings.

S196, S202 and S208 repeat the pending-request sequence with successful Strict
relative baselines at `0`, `-5` and `-600` seconds respectively. Each records
the disabled **Reconstructing...** button both after the valid submission and
after entering `+1`, before changing policy to Best effort. The invalid action
correctly restores a usable submit button and the exact relative-time error,
but changes the retained result's Clock chip to **best_effort**. Its applied
basis, resource and connection rows, change rows, clock cards and summary
remain identical to the Strict baseline on both the immediate and later reads.
Correcting to the original offset and explicitly reconstructing succeeds in
all three cases. The `-600`-second basis is correctly displayed as **−10m 0s**;
that formatting is not a defect.

## Evidence and limits

- [S184.json](../../.runtime/audit-600-2026-10-21/single-node/S184.json)
  contains the Strict baseline, two pending observations, invalid and later
  invalid states, and successful correction.
- [S190.json](../../.runtime/audit-600-2026-10-21/single-node/S190.json)
  repeats the pending/invalid/corrected sequence at capture End, retaining the
  correct basis and error while the applied policy chip changes incorrectly.
- [SX012.json](../../.runtime/audit-600-2026-10-21/single-node/SX012.json)
  contains the inverse-policy and relative-validator repetitions, stable
  retained data, and corrected reconstructions.
- [S196.json](../../.runtime/audit-600-2026-10-21/single-node/S196.json),
  [S202.json](../../.runtime/audit-600-2026-10-21/single-node/S202.json) and
  [S208.json](../../.runtime/audit-600-2026-10-21/single-node/S208.json)
  repeat the pending/invalid/corrected sequence at relative zero, −5 and
  −600 seconds, including matching retained data on the later observations.
- [Absolute invalid-input screenshot](../../.runtime/audit-600-2026-10-21/single-node/SN013-invalid-time-changes-applied-clock.png)
  shows `not-a-time`, the exact validation error, enabled retry, the
  **best_effort** chip and the retained absolute basis together.
- [Relative invalid-input screenshot](../../.runtime/audit-600-2026-10-21/single-node/SN013-relative-invalid-clock.png)
  shows `+1`, its validation error, the **best_effort** chip and retained
  −5-second basis. The saved baseline states establish the prior Strict policy;
  either screenshot alone does not prove which policy produced the result.

The primary auditor performed the browser actions; this report's author
reviewed the records, both screenshots and source. S184 proves pending UI
overlap, not the network completion status or a late HTTP 200 response. The
unused delay-proxy helper was not started or used for these cases. No CPU,
memory, request-duration or changed topology-data claim is made. Per-node
mapping-quality labels are separate from the requested clock policy and are
not themselves evidence of this defect.

## Source cause and repair invariant

`requestTopology()` correctly aborts the preceding request, advances its request
ID and clears pending state before validating at
[app.js:8873–8886](../../frontend/assets/app.js). On validation failure it retains
`state.topologyQuery` and calls `renderTopologyQueryState()` to restore the
applied result attribution and usable submit button.

The Clock chip at app.js line 8715 uses
`payload.clock_policy || byId("topology-clock-policy").value`. The normal
topology response has no top-level `clock_policy`: its response construction at
[temporal_topology.py:778–824](../../src/router_dump_analyzer/temporal_topology.py)
includes `resolved_basis` and `basis`, whose policy is recorded in the resolved
basis at line 1131. The renderer does not read that recorded policy and falls
back to the current, rejected form value. This explains the immediate relabel
without a new successful response or changes to the retained data.

The applied Clock chip should use the retained result's recorded policy, while
the editable form continues to show the user's proposed policy. Preserve the
passing validation, request invalidation and recovery behavior. Verify both
policy directions and both time validators, including the pending-request
sequence and successful correction.

This is distinct from the older
[invalid-input response-authority finding](../other-sections-audit-2026-10-20.md)
and its [repair](../outstanding-audit-fixes-2026-10-20.md): the newer error now
remains authoritative, but the retained result's policy attribution changes.
The focused regression in
[node_view_state_regressions.test.mjs:12](../../frontend/tests/node_view_state_regressions.test.mjs)
checks error/request authority with a stubbed query-state renderer; it does not
exercise this chip's fallback. Tests were inspected, not rerun.

Only this report was changed for the reporting task. No product code, skills,
ledgers, aggregate counts or checkpoint were edited. Documentation drift check
found no public plug-in boundary, example or author-command change; no
maintained authoring update was required.
