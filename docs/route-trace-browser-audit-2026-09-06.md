# Route trace browser audit

Scope: the running full-scale demo, shared route UI, and related executable
regressions. Existing unrelated working-tree changes are retained. No archive
regeneration or protocol-policy changes are required.

## Work list

- [x] Fix absent optional identity fields matching the wrong trace start.
- [x] Prefer an exact packet-transition step reference over a shared segment;
  retain unknown explicit references instead of guessing another step.
- [x] Keep the trace-wide outcome visible without pinning an individual path
  in the All paths view. Hide obsolete outcomes while inputs change or a new
  request is pending.
- [x] Add Restore trace limits using advertised defaults only; preserve
  endpoints, scenario, direction and steering, invalidate stale results, and
  require an explicit trace to apply the restored limits.
- [x] Show packet-size bases and MTU limit/basis together in packet details,
  including explicit unknown values and the incomparable-basis case.
- [x] Recheck ordinary routing, standby selection, transit-origin return,
  loops, policy stops, nested packets, invalid/reduced limits and MTU cases in
  the browser; run focused and complete frontend regressions.
- [x] Complete independent review and documentation drift check.
- [x] Correct terminal badges and repeated-visit labels on looped paths;
  a trace ending at a router is not proof that the traffic target was reached.

## Findings and corrections

1. Optional absent start identities compared equal and selected the first
   advertised start. Matching now requires a supplied identity and uses
   start/member/node precedence, retaining an honest fallback when unmatched.
2. Packet transitions could attach to the first step on a shared segment rather
   than their explicit step. Explicit unknown references and generated display
   IDs could also collide with real steps. A separate resolved association now
   governs step linking and the inspector; ambiguous references stay unresolved.
3. All paths hid the overall outcome together with the selected-path panel.
   The shared banner now renders independently, but stays hidden while inputs
   change or a replacement request is pending.
4. Invalid or reduced limits had no one-click recovery. Restore uses only
   server-advertised bounds/defaults and requires an explicit new trace.
5. Packet details omitted the size basis and numeric MTU constraint, making a
   declared basis mismatch difficult to understand. Both before/after size
   bases, the MTU basis and limit, and incomplete/unknown states are displayed.
6. The demo README retained the obsolete 35-case/26-route-and-packet counts.
   Corrected them to the generated 39-case/30-route-and-packet catalog.
7. All-paths loop cards matched terminal status by router identity rather than
   occurrence, labeling both P1 visits as destinations. The last occurrence now
   says **Trace end** unless the path explicitly declares the traffic target
   reached. Focused paths use the same rule; successful return paths say
   **Source target**. Zero-based occurrence indexes no longer lose one when
   converted to displayed visit numbers.
8. Live recovery testing found the new restore reminder remained after a trace
   had already started. Accepted requests now clear it; rejected input retains
   the reminder and validation error.

## Live checks

- Full-scale ten-node demo reused its existing generated archive; no fixture
  regeneration or additional long-running server was needed.
- All paths retains the reachable banner while selected-path details are
  closed. Selecting the eligible P2 alternative opens P2's own resolution.
- Changing the scenario hides the obsolete verdict. A hop limit of zero is
  rejected by browser validation. Restore yields the advertised 64 hops and 16
  recursion steps, preserves the context and does not auto-submit.
- A one-hop native IPv4 trace is incomplete, not delivered; restoring limits
  and submitting produces an ordinary reachable, three-transition IPv4 trace.
- The incomparable-MTU inspector shows `demo.wire-size.v1` before and after,
  `demo.ip-size.v1` for the MTU, and a 1,500-byte limit. It preserves the
  declared uncertainty rather than presenting a proven MTU failure.
- Changing direction clears the selected path and pinned packet inspector
  while preserving the overall trace result.
- A genuine encapsulation MTU violation reports both directions dropped.
  Nested VPN return tracing retains four physical router visits while showing
  transport/VPN label push, swap, PHP, nested wrappers and final decapsulation
  in the packet rail. Split-horizon reports a policy block, not ordinary loss.
- Transit-origin tracing correctly shows P1 to PE-B for the forward observation
  and PE-B to PE-A for return, with an explicit explanation that return traffic
  need not revisit P1.
- Forwarding loops report both directions failed. Both focused and All paths
  display P1's first and second visits separately; only the final visit has a
  **Trace end** badge, with no false **Destination** badge. The restore reminder
  clears on submission, and the outcome stays hidden during that request.

## Validation and ownership

- Complete frontend suite: **306 tests passed**.
- Python frontend-contract suite: **51 tests passed**.
- Frontend distribution check: five routes, fourteen JavaScript modules, one
  source distribution; passed. `git diff --check` passed.
- Independent read-only review found no additional actionable defect in the
  changed route paths; all **51 targeted route tests** passed. These counts
  overlap the complete frontend suite and are not additional total coverage.
- Browser validation used the existing full-scale ten-node generated sample;
  these checks are not a claim that every possible plug-in or trace was tested.
- Plug-in documentation drift check completed. This task changes the generic
  renderer and exposes existing declared fields, not public hooks, schemas or
  protocol policy. The normative authoring contract and minimal example need
  no task-specific change. Updated the user-facing walkthrough, case counts
  and audit records instead. No commit was created.

The core owns identity matching, optional-state preservation, generic outcome
presentation and display of declared packet facts. Plug-ins continue to own
protocol behavior, route choices, label/SID transformations and size-basis
meaning. The UI must not infer reachability from a guessed protocol rule.
