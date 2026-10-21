# MN003 — P2: direction changes retain an incompatible scenario routing context

The advertised **PE-A / PE-C asymmetric service** scenario fails in **Return
only** with its automatically populated fields. The form retains the forward
SRv6 context instead of selecting the declared return MPLS context. Correcting
the fields manually makes the return trace work, but switching back to
**Forward only** then retains the MPLS fields and fails in the opposite
direction. Reloading the same scenario restores forward defaults even when
**Return only** remains selected.

This is one finding with repeated and inverse reproductions. It is not a
failure to resolve the declared return path: that path succeeds with a correct
request and in the **Both directions** control case.

## Browser evidence and reproduction

The primary auditor executed the browser interactions on the existing local
demo. This note's author reviewed the saved DOM observations, screenshot and
source at `112d346`; no additional browser execution or function probe is
claimed here.

- [M027: repeated Return-only failure](../../.runtime/audit-600-2026-10-21/multi-node/M027.json),
  recorded at `2026-10-21T05:57:11.182Z`. Use states 1 and 2 for the repeated
  explicit error and the populated form.
- [MX003: manual recovery and direction-switch expansion](../../.runtime/audit-600-2026-10-21/multi-node/MX003.json),
  recorded at `2026-10-21T05:57:41.981Z`. States 1 and 3 contain visible successful
  results; states 2 and 4 contain the inverse and repeated validation errors.
- [M025: successful Both-directions control](../../.runtime/audit-600-2026-10-21/multi-node/M025.json),
  visible states 1–3, including the correct return context in state 2.
- [Return-preset screenshot](../../.runtime/audit-600-2026-10-21/multi-node/MN003-return-preset.png)
  shows the IPv6/SRv6 fields and the reverse-direction MPLS requirement error.

All state indexes are zero-based. Hidden result descendants in the failed or
pending states describe previous output and are excluded from visible-result
claims. The visible validation error and form values establish the failure;
the generic loading flag alone is not used to infer request completion. No
performance, CPU or memory finding is asserted from these observations.

1. With the topology reconstructed, select scenario
   `site-a-site-c-asymmetric`, **Return only**, **Strict** policy and restored
   trace limits (`64` hops, `16` recursion).
2. The form contains `blue / ipv6_unicast / srv6_policy`. Submit, then repeat.
   Both attempts show:
   `scenario site-a-site-c-asymmetric requires route_type mpls_transport for reverse direction`.
3. Manually select `default / mpls_labeled_unicast / mpls_transport` and submit
   **Return only**. The trace resolves PE-C → P2 → P1 → PE-A. The eligible
   standby PE-C → P2 → PE-A remains a separate alternative; Forward is disabled
   because it was not requested.
4. Change only validation direction to **Forward only** and submit. The form
   retains the manual MPLS context and shows:
   `scenario site-a-site-c-asymmetric requires route_type srv6_policy for forward direction`.
5. Reload the same scenario in **Forward only** and submit. Its forward
   `blue / ipv6_unicast / srv6_policy` context resolves PE-A → P2 → PE-C.
6. Choose **Return only**, reload the same scenario and submit again. The form
   still uses forward defaults and repeats the MPLS requirement error.

Here, reloading the scenario means applying its preset through the scenario
control, not a browser page reload. Fresh-page and deep-link restoration are
additional checks proposed below, not claimed as executed by MX003.

The declared contexts are:

| Requested direction | VRF | Route family | Route type |
| --- | --- | --- | --- |
| Forward | `blue` | `ipv6_unicast` | `srv6_policy` |
| Return | `default` | `mpls_labeled_unicast` | `mpls_transport` |

M025 succeeds in **Both directions** despite the form displaying the forward
context: its return result explicitly reports the MPLS context and both
declared endpoints are reachable with different path shapes.

## Source diagnosis

The scenario already declares both contexts in
[scenario_registry.py:261–288](../../demo/rsl_demo_plugin/scenario_registry.py).
The frontend's capability normalization preserves scenario fields through
`...scenario` in
[topology.js:1013–1023](../../frontend/assets/topology.js).

The form does not use that directional information consistently:

- The scenario-change handler takes `pair.forward.route_family`,
  `pair.forward.route_type` and the scenario's top-level VRF regardless of the
  selected validation direction. It then announces that endpoints and routing
  context were updated together
  ([topology.js:9910–9936](../../frontend/assets/topology.js)).
- The validation-direction handler updates the forward-start control, clears
  route-row focus, invalidates the old result and synchronizes the URL. It
  never reapplies a directional routing context
  ([topology.js:9997–10002](../../frontend/assets/topology.js)). The correctly
  disabled forward-start input in Return-only mode does not correct the other
  fields.
- `resolveCompatibleRouteContext()` checks advertised type/family/VRF
  compatibility and uses top-level scenario fallbacks; it receives no direction
  and does not validate the fixed scenario's directional requirement
  ([topology.js:1376–1403](../../frontend/assets/topology.js)). The stale forward
  tuple is globally compatible, so this check permits submission.
- `buildRouteTraceRequest()` reads the selected validation direction but sends
  the visible VRF, family, address family and type as explicit request fields
  ([topology.js:3024–3030](../../frontend/assets/topology.js),
  [topology.js:3053–3064](../../frontend/assets/topology.js),
  [topology.js:3090–3098](../../frontend/assets/topology.js)). This is a
  source-derived request explanation; the note does not claim a separate
  captured network payload.

The server correctly resolves scenario defaults for the requested direction in
`_scenario_routing_context()`
([multi_node_route.py:5520–5535](../../src/router_dump_analyzer/multi_node_route.py))
and rejects an explicitly incompatible route type/family for a fixed scenario
([multi_node_route.py:5710–5724](../../src/router_dump_analyzer/multi_node_route.py)).
Removing that validation would conceal the form defect.

**Both directions** takes a different path: the core creates forward and
reverse child requests, removes their explicit routing fields, and substitutes
the declared per-direction contexts before tracing them
([multi_node_route.py:6041–6087](../../src/router_dump_analyzer/multi_node_route.py)).
This explains why M025 resolves the return MPLS path while M027's explicit
single-direction request fails.

There is a relevant descriptor caution: `_generated_directional_pairs()` copies
one top-level `route_context` into both `forward` and `reverse`
([multi_node_route.py:4577–4604](../../src/router_dump_analyzer/multi_node_route.py)).
Changing the form from `pair.forward` to `pair.reverse` alone is therefore not
a sufficient repair. The form should use the declared scenario
`directional_routing_contexts`, or the directional descriptor must be made
consistent with that declaration. This source observation is part of the
repair analysis, not another counted browser finding.

## Repair and validation targets

Use one direction-aware context selection rule for scenario application,
direction changes and initial form restoration. Preserve the logical traffic
source/destination pair: **Return only** reverses traversal; it should not
require swapping the user's traffic endpoints or reusing a forward observation
start. Keep the core's explicit-context checks. Any handling of intentional
manual edits or arbitrary-endpoint scenarios must remain explicit rather than
silently submitting values different from the visible controls.

Existing server tests exercise valid directional contexts and the opposite
context in a counterpart request
([test_multi_node_route.py:1651–1676](../../tests/test_multi_node_route.py),
[test_multi_node_route_regressions.py:318–348](../../tests/test_multi_node_route_regressions.py)).
Those checks do not exercise the failing form transition. The current
[route-controls harness](../../frontend/tests/route_controls.test.mjs), around
lines 39–86 and 137–170, supplies ordinary same-context scenarios and an empty
directional-pair inventory; its endpoint/default checks do not cover this
asymmetric direction switch. No tests were rerun for this report-only note.

Additional UI checks to execute after a repair, not completed claims:

1. Repeat the entire M027/MX003 sequence with actual scenario and direction
   handlers, including Return selected before the scenario and repeated
   Forward → Return → Both transitions.
2. After successful manual Return recovery, change directly to **Both
   directions**. Initial server context validation runs before the bidirectional
   substitution, so stale reverse form fields also need examination on this
   transition.
3. Reopen both a valid saved Return-only URL and a scenario/direction-only URL.
   Initial rendering currently chooses forward/top-level defaults before it
   restores the direction selector
   ([topology.js:4430–4457](../../frontend/assets/topology.js)). Verify visible
   fields and the next submitted result, including deliberate URL overrides.
4. Preserve explicit start behavior and route-row trace actions, and retain a
   same-context scenario as a control. Check that a failed submission can be
   corrected and submitted without losing endpoints, budgets or policy.

## Documentation drift check

Completed for this audit-note addition. No product, plug-in API, fixture,
example, skill or author-facing command changed. Maintained plug-in authoring
materials require no update. This file does not alter case counts, execution
ledgers or the main findings report.
