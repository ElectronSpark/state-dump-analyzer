# Demo browser audit — 2026-09-06

Scope: the expanded demo, route scenario/budget controls, packet evolution,
durable revision inspection, import selection/retry, sessions, private evidence
review, retention preview and server status. This is a bounded exploratory pass,
not a claim that every combination of core features was exercised.

## Verified defects and corrections

| Finding | Cause and correction | Ownership |
| --- | --- | --- |
| Revision inspection omitted projected relationships | Temporal observations were queried, but revision-level declarations were not. Inspection now includes both classes, with separate counts and explicit revision scope; it does not fabricate validity timestamps or merge resource identities. | Core query/presentation; plug-ins still declare correspondence |
| Hidden private-analysis panels remained visible | Component grid rules overrode the HTML `hidden` attribute. A scoped hidden rule restores the intended visibility contract. | Core frontend |
| Summary table stretched the page sideways | Shared table `nowrap` and inline materialization JSON produced an approximately 8,593-pixel cell. Summary scalars now use fixed columns; structured values have compact status/count summaries and expandable exact JSON. Management tables explicitly allow wrapping. | Core frontend |
| Revision selector repeated the same long ID twice | A revision-only member ID equals its revision ID. Equal values now appear once; distinct session member IDs and exact selection values are preserved. | Core frontend |
| Upload notice claimed processing while awaiting parser selection | An admission message assumed a later worker state. It now directs the user to the durable status without asserting that parsing is running. | Core frontend |
| A hop-limited packet prefix declared delivery at a transit node | The example packet builder treated the last available transition as the final planned action. It now requires the actual terminal action. Forced alternate SR-MPLS explicitly compresses its plan to push, PHP and egress delivery. | Demo plug-in packet semantics, not a core protocol rule |
| An unresolved trace was described as a definite failure | Directional presentation treated unresolved status and `reachable=false` as proof of failure. Incomplete results now remain incomplete; explicit drops, loops and policy stops retain their failure meanings. | Core frontend |
| Mixed outcomes and counterfactual alternatives were collapsed into failure | One terminal candidate overshadowed an unresolved sibling; a lossy `reachable=false` also hid partial active reachability and mislabeled unselected alternatives as dropped. Aggregation now uses endpoint-state metadata, preserves uncertainty and partial reachability, and retains branch-local terminal evidence. | Core frontend |
| A checked visibility checkbox announced the opposite action | Labels retained the old button wording, so a checked control said "Hide." Both states now use the stable positive name "Show ... in Resource timeline"; checked means visible. | Core frontend |

## Browser execution evidence

- Full-size archive: ten full-scale node dumps, 39 coverage cases. The loaded
  node reported **1,250,005 events and 7,504 resources**. Scale was not reduced.
- Before/after inputs went through the real process-mode ingestion pipeline.
  Inspection showed three independent resources, one correspondence and
  failing/healthy findings as expected.
- A two-member session was snapshotted, then the live session was renamed. The
  immutable snapshot retained its original vector and version.
- Both CLI admission and browser file upload exercised manual candidate
  selection. Only the primary parser was offered, not the auxiliary evidence
  provider. The browser-selected import reached published/completed state.
- The explicit retry button successfully resumed a staged import after an old
  worker was stopped. Its prior failure and later publication stayed in the
  processing journal.
- The offline scripted runner was blocked by the default disabled policy.
  Explicit client-safe/in-process permission for synthetic data allowed a run
  with two validated citations: a source record and an auxiliary-provider
  result. Reload returned the durable report. No model service, proposal or
  automatic annotation was involved. Test workspace policies were disabled
  again after validation.
- Tenant administration did not expose instance-wide diagnostics. Retention
  preview showed disabled policies, an advisory/incomplete host inventory, and
  disabled execution. No retention deletion was performed.
- Below-MTU (1440/1500), exact-MTU (1500/1500), incomparable bases and incomplete
  capture were inspected in both directions. The existing 1510/1500 drop was
  retained. Transition details showed encapsulation and provenance.
- The summary layout was rechecked at 1280 and 768 pixels, including expanded
  provenance: document width stayed within the viewport. Exact JSON remained
  available, and the selector no longer duplicated its ID.
- A one-hop IPv4 trace stopped with `Continuation Required`, not false delivery.
  Zero recursion remained incomplete; restoring the advertised budget exposed
  the recursive loop. The explicit EVPN split-horizon case remained policy
  blocked rather than being weakened to an unknown outcome.
- Native IPv4 still delivered in three transitions. Forced alternate steering
  traversed P2 with push, PHP and real egress delivery in both directions; its
  packet details stayed visibly counterfactual.
- Timeline zoom, earlier/later keyboard navigation, selecting the visible
  duration, range zoom and fit were exercised. The revised visibility checkbox
  was unchecked and checked again: its lane disappeared and returned, with the
  same positive accessible name in both states.

## Operational observations, not bypasses

Plug-in package fingerprints include `.pyi` files. Regenerating stubs after
admission changed retained provider identity, and capability execution correctly
refused the stale pin. Re-admission under finalized package bytes resolved it.
An old worker sharing the same state directory also intercepted publication and
correctly rejected an incompatible composition policy. Stop old consumers before
validating a changed deployment; do not relax either identity check.

The Windows generator completed archive writing but its path-only stdout failed
under a legacy console encoding in one test command. Re-running with Python UTF-8
mode reused and validated the completed archive. The shipped launcher already
sets UTF-8 for this reason.

## Remaining usability opportunities

1. **Revision discovery:** add a compact capture-time/count summary to catalog
   entries so before/after revisions of the same node can be distinguished
   without opening provenance. Keep full opaque IDs inspectable.
2. **Snapshot-only empty states:** explain that a disabled one-point timeline
   and zero events may mean a snapshot-only input, rather than a failed load.
   Distinguish that from a filter that happens to match no events.
3. **Traversal recovery — addressed:** “Restore trace limits” now restores
   advertised hop/recursion defaults without changing the trace context.
4. **MTU uncertainty explanation — addressed:** packet details now show
   before/after size bases alongside the MTU limit and basis. See the
   [route trace follow-up](route-trace-browser-audit-2026-09-06.md).
5. **Review-gap accuracy:** the single-node drawer still describes upload,
   persistence and authentication as globally missing. Distinguish limitations
   of this synthetic sample/runtime from the now-implemented core control-plane
   features. Do not imply that the demo proves production authentication or a
   platform-specific CTF decoder.

Unmarked items remain suggestions, not claims of implemented features.
Do not infer protocol semantics, relax authentication, enable destructive
retention or wire public model APIs merely to make a demonstration look complete.

## Validation limits

Executable frontend and focused Python regressions, plug-in author conformance,
type-stub consistency and the frontend distribution checker were run. Broad
Python/API invocations that reached their explicit 90-second deadline are not
counted as passing suites; focused replacements have separate recorded results
in the coverage walkthrough. No all-repository Python-suite claim is made.

Final checks: **265 frontend tests** and **51 frontend-contract Python tests**
passed. An independent reviewer reproduced and rechecked the outcome defects
using 33 endpoint-aware vectors plus the 22 focused route tests; no further
concrete defect was found in that scoped recheck. This is not an assertion that
the whole application is defect-free.

## VPN topology sample follow-up

The canonical scenario now authors three logical services from node-local
configuration: Blue MPLS L3VPN (three PEs), Red MPLS L3VPN (two PEs), and Blue
EVPN/VXLAN VNI 50100 (four PEs). Blue and Red deliberately reuse 10.20.0.0/24
without sharing service identity. No physical link or peer list was added for
the VPNs. The generated ten-node archive retained its full event scale and
rebuilt in 503.84 seconds.

Live browsing found and fixed two generic frontend defects missed by the
synthetic projection tests: an absent optional `separate_view` became false
and hid valid VPN domains; nested logical attachment declarations fell back to
physical-port labels. Explicit plane authority, omitted/true/false display
states, and attachment normalization now have executable regressions.

On the actual server, the VPN graph displayed five participating PEs, three
domain nodes and nine logical attachments. Keyboard-opened details correctly
identified the selected attachment and retained the plug-in/core calculation
split. At watermark offsets -420, -270 and 0 seconds, PE-E's EVPN attachment
was usable, unusable and usable respectively. During the outage the EVPN
domain was degraded with all four memberships retained, while Red L3VPN stayed
usable. The underlay still showed ten devices, four shared domains, three
compact pairs and one hidden external network; VPNs did not become route hops.

Focused Python validation passed 19 tests and 9 subtests. The documented
minimal fixture verifier and plug-in validator passed, as did the 132-module
stub check and frontend distribution checker. This is scoped validation, not a
claim that every application path was audited.
Final frontend recheck passed 277 tests, including 12 executable VPN display
and attachment regressions; the 51 Python frontend-contract tests also passed.
An independent reviewer verified the VPN/API boundary and the generic renderer
fixes. Review also retained backward compatibility for flat subinterface fields
with omitted kinds and for LAG/subinterface stacks.
