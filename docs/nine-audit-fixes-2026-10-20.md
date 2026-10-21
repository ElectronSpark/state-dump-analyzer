# Nine audit repairs — 2026-10-20

All nine findings from the [repeated-navigation](repeated-navigation-audit-2026-10-20.md),
[cross-component](cross-component-audit-2026-10-20.md), and
[surrounding-component](surrounding-components-audit-2026-10-20.md) audits are
repaired. The primary agent implemented the changes and validated the UI;
parallel reviewers performed read-only checks.

## Changes and validation

| Finding | Cause-level repair | Browser result |
| --- | --- | --- |
| Toolbar Reveal overrides newer resource selection | Capture the existing navigation intent before selection resolution and reject stale continuation/errors. | Delayed selection resolution preserves the subsequently selected ETG resource. |
| Timeline-to-log locate overrides newer row selection | Advance the existing locate token when selecting/clearing rows; guard deferred focus as well as the response. | A delayed locate leaves the newer first-row selection, focus, and scroll at row zero. |
| Source-preset toggle loses focus | Restore the same control identity after replacing the preset list, without stealing external focus. | Keyboard toggles retain checkbox focus; disabling both defaults reaches 0/8. |
| Rejected custom regex poisons later timeline queries | Stage the candidate in the ordinary timeline query, retaining/resetting only accepted, unchanged input. Resume an interrupted viewport refresh if the candidate is discarded and still owns the request. | Grouped and counted regexes remain in the form with an error and 2/8 active rules. Correcting to `warning\|error` succeeds at 3/8; subsequent zoom refreshes. Rejection during a delayed zoom also recovers the zoom. |
| Pending direct reveal overrides newer time cursor | Cursor actions advance navigation intent, including key/pointer interaction when the value is already at the endpoint. | End at the already-selected capture end remains there after an older delayed +30 s reveal resolves. |
| Subpixel keyboard ranges escape capture | Keyboard and pointer paths share the bounded range adjustment; minimum width never exceeds the existing interval. | Start ArrowRight on 0–0.01 s and End ArrowLeft on 719.986–719.996 s remain bounded without movement against the key. |
| Correlation pagination resets disclosure/focus | Preserve disclosure by direction and edge identity, scroll, and the pagination focus destination. | Repeated Enter/Space pagination through all 499 relationships preserves the collapsed source group and expanded relationship; the final page focuses the group summary. |
| Repeated source reveals exhaust lane capacity | Reuse a transient rule for the same exact source UID/type before allocating or checking capacity. | Nine overlapping Ctrl+Enter reveals settle to one jump lane, 1/8 slots, with one remove control. |
| Pending correlation preparation reopens after disconnect | Capture and recheck the existing review connection token before subject projection and dialog opening. | Disconnect during delayed selection keeps the dialog closed. Reconnect and prepare again opens two exact events successfully. |

The repairs use existing ownership tokens, controls, and request paths. No new
plug-in hook, endpoint, cache, or persistent state is introduced. Custom-lane
acceptance uses the required timeline response rather than an extra corpus scan.

## Evidence and scope

Browser checks used the 1M demo at `http://127.0.0.1:8883/node`, with
1,250,005 normalized events and 7,510 resources. Ordinary focus, range, regex,
and pagination checks ran against the real local backend.

To make overlap deterministic, a temporary loopback proxy on port 8895 delayed
selected real requests by 8–10 seconds. Those checks establish behavior under
controlled response timing; the delay is not a performance measurement.
The review-disconnect check used port 8896 with a synthetic read-only catalog
matching the active revision, because the demo has no matching writable review
revision. It forwarded the real event-selection request and refused durable
mutations. No correlation was saved. This validates frontend preparation and
disconnect behavior, not durable persistence or production authorization.

After validation, both temporary proxy servers were stopped, their browser tab
was closed, and the original 8883 page was restored to the full capture with
13 resource lanes, two default source lanes, and browser-only review.

Local evidence is retained under `.runtime/nine-audit-fixes-2026-10-20/`:

- `toolbar-new-resource-settled.txt`, `log-locate-new-selection-fixed.txt`,
  `log-locate-new-selection-state.json`, and `same-end-fixed.txt`.
- `source-preset-off.txt`, `source-repeat-fixed.txt`, and
  `source-repeat-one-allocation.txt`.
- `regex-final-group-rejected.txt`, `regex-final-counted-rejected.txt`,
  `regex-pending-viewport-recovered.txt`, and `regex-final-corrected.txt`.
- `regex-final-zoom-recovered.txt`, `range-start-fixed.txt`, `range-end-fixed.txt`,
  `correlation-final-page60.txt`, and `correlation-final-page499-state.json`.
- `correlation-disconnect-fixed.txt` and `correlation-retry-open.txt`.
- `browser-final.png` shows the recovered timeline and source-lane controls;
  `browser-console.json` contains no captured warnings or errors for that tab.

Earlier exploratory snapshots in that directory include failed intermediate
checks. The evidence filenames above identify the successful repair checks.

## Automated checks and documentation

- `npm --prefix frontend run check`: **451 passed, 0 failed, 0 skipped**,
  including syntax checks and all frontend tests. The proxy tests require
  loopback-listener permission; the final run used that permission.
- `node --test frontend/tests/cross_component_recovery.test.mjs`: **23 passed**.
  These compose production functions across delayed navigation, row selection,
  request cancellation, candidate validation/recovery, repeated reveals,
  bounded ranges, and review connection changes.
- Both maintained author/validator skills pass `quick_validate.py`.
- `scripts/check_plugin_conformance.py --list` passes with the repository's
  configured `router-dump-analyzer-demo` Python environment. This inventories
  the checks; it is not a full conformance run.
- `git diff --check` passes.

The author and validator skills, plus `docs/plugin-api-validation.md`, now
cover these state/recovery cases and distinguish browser timing from controlled
race evidence. The required plug-in documentation drift check found no public
plug-in boundary or author-facing command change, so the quickstart, normative
contract, and runnable example need no edits. This task did not rerun CPU/RSS
benchmarks or make performance claims.
