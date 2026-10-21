# MN007 — P3: stationary hover overrides the keyboard packet preview

Pressing End from the first packet-transition chip correctly focuses the last
chip, but horizontal scrolling can place a different chip under the stationary
pointer. Its hover then replaces the keyboard destination's preview and
correlated highlight. In the nested-VPN Return trace, focus reaches the fourth
delivery transition while the preview and highlight describe the third
penultimate-hop-pop transition. The primary auditor reproduced the mismatch
twice using native End without moving the pointer. MX010 later reproduced it
in Forward, including a clean click-first → Escape → End sequence: focus
reaches delivery at PE-B while the preview and highlight identify PHP at P2.

Moving the pointer outside the packet rail and repeating Home → End makes
the preview follow the focused delivery transition. This is a usability
finding: keyboard focus and the transition being explained disagree. No
incorrect route or packet-transition data is demonstrated.

## Browser evidence

The primary auditor performed the browser actions on the existing local demo.
This note's author reviewed saved DOM observations, the screenshot and source
at `112d346`. No additional browser execution or production-function probe is
claimed here.

- [MX008: mixed-input repeats and controls](../../.runtime/audit-600-2026-10-21/multi-node/MX008.json),
  recorded at `2026-10-21T07:20:53.758Z`.
- [Screenshot: PHP preview after keyboard End](../../.runtime/audit-600-2026-10-21/multi-node/MN007-keyboard-hover-overrides.png)
  shows the penultimate-hop-pop preview, P1 highlight and independently pinned
  first-transition detail. Exact keyboard focus identity is established by
  the DOM records, rather than inferred from the screenshot's styling.
- [Execution ledger](multi-node-results.jsonl), latest MX008 entry. Its pin
  assertion was corrected after reviewing the states: clicking an already
  pinned first chip legitimately toggles it off. The earlier false pin-retention
  assertion is superseded and is not another finding.
- [MX010: Forward repeat and controls](../../.runtime/audit-600-2026-10-21/multi-node/MX010.json),
  final record and latest ledger entry at `2026-10-21T09:20:54.615Z`.
- [Clean repeat screenshot: PHP preview while delivery is focused](../../.runtime/audit-600-2026-10-21/multi-node/MN007-repeat-keyboard-hover-clean.png)
  shows the PHP preview and P2 emphasis. The exact focused `step-7` identity
  comes from the saved `cleanRepeat` DOM state. The initial MX010 screenshot,
  `MN007-repeat-keyboard-hover.png`, included browser text selection from a
  neutral-margin drag and is superseded by this clean screenshot.

For MX008, the selected scenario is `packet-vpn-over-vpn`, Return, observed steering.
Its four packet chips correspond to resolution steps 1, 3, 5 and 7; these step
numbers are not chip indexes:

| Packet chip | Resolution step | Transition |
| --- | --- | --- |
| First | `step-1` | Push transport and VPN labels at PE-B |
| Third | `step-5` | Penultimate-hop pop transport label at P1 |
| Fourth | `step-7` | Remove MPLS L3VPN and nested VXLAN wrappers; deliver at PE-A |

The MX008 references belong to
`route-path:generated:packet-vpn-over-vpn:reverse:observed`; the saved packet
refs include that path identity and the full transition identity.

## Reproduction and controls

1. Resolve the nested-VPN Return path and display its packet-evolution rail.
2. Click the first transition chip. Keep the pointer at that location and
   press native End from the chip.
3. After the rail scroll settles, inspect actual active-element packet ref,
   visible preview, `.is-packet-focus` references and actual `:hover` chip.
4. Repeat the click-first → End sequence without moving the pointer between
   the click and key. Record pin toggling separately from preview behavior.
5. Move the pointer to the fixed **Route trace** navigation outside the rail,
   then keyboard-focus the first chip and perform Home → End again.

| Observation | MX008 states | Result |
| --- | --- | --- |
| Initial pinned transition | 0 | First chip focused and pinned; preview and detail both show the push transition |
| Initial mismatch | 1 | Fourth/delivery chip focused; preview shows third/PHP; first detail remains pinned |
| Pointer-outside control | 2–3 | Focus, preview and packet highlight agree on `step-7`; hover is on fixed navigation, not a packet chip |
| First controlled mixed-input repeat | 4–5 | Clicking the already pinned first chip unpins it; End focuses `step-7`, but hover, preview and highlight identify `step-5` |
| Second mixed-input repeat | 6 | First transition pinned again; focus is `step-7`, while hover, preview and highlight remain `step-5` |
| Escape control | 7 | Pin dismissed, all chips unpressed and focus restored to the first trigger |
| Repin and explicit Close control | 8–9 | First detail opens again; Close dismisses the pin and restores the first trigger |

Indexes are zero-based. In both controlled failures the rail's recorded
`scrollLeft` is approximately `436.8` pixels. The pointer-outside control also
reaches this scroll position, but its preview follows the keyboard focus.
The primary auditor's action record establishes that no pointer move was
requested between the first-chip click and End; the DOM snapshots establish
which chip is hovered after scrolling.

Pinned detail is intentionally independent of temporary preview. When pinned,
the first transition retains its complete seven-layer after-state:
`transport-label`, `vpn-label`, `outer-ipv6`, `udp`, `vxlan`,
`tenant-ethernet`, `inner-ipv4`. Its short chip summary ending in `+3 more`
does not indicate missing detail. Escape and Close may show a new first-chip
focus preview after dismissing the pin; the passing assertion is dismissal of
the pinned detail and restoration of its trigger.

An incidental header node-opening action during exploration is recorded
separately as [MX009 / MN006](multi-node-return-context.md). It is not part of
MN007's keyboard reproduction or its successful fixed-navigation control.

## MX010: clean Forward repeat

MX010 uses the same nested-VPN scenario with Both directions requested and
the **Forward** path displayed, under observed steering. Its references belong
to `route-path:generated:packet-vpn-over-vpn:forward:observed`. Here the first
chip is the PE-A push, `step-5` is PHP at P2, and `step-7` is delivery at PE-B.
This expands the existing MN007 evidence; it is not a new unique bug.

After the initial stationary-pointer End reproduction and controls, the primary
auditor clicked the first chip and pressed Escape. The saved `clickEscape`
state has focus and actual hover on `step-1`, no pressed chips, and hidden
pinned detail. Without moving the pointer, native End then focused `step-7`,
but the settled `cleanRepeat` state shows hover, preview and correlated
highlight on `step-5`. No pin was active in this clean repeat.

| Saved MX010 state | Observation |
| --- | --- |
| `stationaryEnd` | Delivery `step-7` focused; PHP `step-5` hovered, previewed and highlighted |
| `pinned` | Native Enter pins the focused delivery transition at PE-B; the independent temporary preview still describes PHP at P2 |
| `control` | After moving the pointer outside the rail and performing Home → End, focus, preview and highlights all identify delivery `step-7`; no packet chip is hovered |
| `clickEscape` | Clean-repeat setup: first chip focused and hovered, all pins cleared |
| `cleanRepeat` | End again focuses delivery `step-7`, while PHP `step-5` owns hover, preview and highlights |

The Enter control demonstrates that pinning uses the actual keyboard target;
the defect remains in temporary preview and highlight priority. The clean
screenshot was reviewed alongside these records and has no browser text
selection. Its visual emphasis alone is not used as proof of keyboard focus.
The earlier MX010 ledger entry at `09:20:16.122Z` lacks the clean-repeat step;
the later entry and final runtime record retain that additional evidence and
supersede the initial screenshot.

## Source diagnosis

[bindRoutePacketElements in topology.js](../../frontend/assets/topology.js),
lines 4148–4170, registers both `pointerenter` and `focus` to call
`showRoutePacketPreview`. Its Home/End/Arrow handler calls the destination
button's ordinary `.focus()`, allowing the browser to scroll it into view.
The packet rail is horizontally scrollable and uses inline proximity snapping
([topology.css](../../frontend/assets/topology.css), lines 4555–4574).

`showRoutePacketPreview` at line 4020 unconditionally replaces the shared
preview reference and anchor, updates the preview content, and applies route
hover/highlight state. It does not distinguish a new intentional pointer move
from a pointer-enter event caused by keyboard scrolling beneath a stationary
pointer. The handler order and the observed post-scroll hover provide the
source explanation for the mismatch; the browser event sequence itself was
not instrumented in MX008 or MX010.

`applyRoutePacketFocus` at line 3992 chooses `routePacketPreviewRef` before
`routePacketPinnedRef`. Consequently the replaced preview also controls
`.is-packet-focus` and its corresponding route emphasis. The pinned detail
renderer at line 4071 uses the separate pinned reference, explaining why its
first-transition content remains correct while the temporary preview changes.
The preview has `pointer-events: none` in `topology.css` at line 5168; the
tooltip itself does not intercept pointer hit testing.

The shared 140 ms preview-clear timer is a related source-review concern,
but no timer-specific failure was established here. It is not included in
the finding or counted separately.

## Repair boundary and validation target

Preserve the current keyboard destination through focus-driven scrolling.
An incidental hover transition under a stationary pointer should not replace
the transition selected for keyboard preview. Deliberate pointer exploration
should still work, and temporary preview should remain independent of pinning.

Validate click-first → End with the pointer stationary over the rail, then the
same keyboard sequence with the pointer outside. Compare actual focused ref,
preview title, hover ref and correlated highlights after scrolling settles.
Cover both pinned and unpinned states and preserve the passing Escape/Close
controls. Include MX010's click-first → Escape → End repeat and verify that
Enter pins the focused delivery transition independently of the temporary
preview. Existing [packet detail tests](../../frontend/tests/route_packet_details.test.mjs)
exercise normalization and rendering; the
[frontend audit regression checks](../../tests/test_frontend_audit_regressions.py)
check packet-handler wiring and markup but do not execute this composed
keyboard-scroll-pointer sequence.

Documentation drift check: this report records audit evidence only. No plug-in
behavior, public APIs, examples or author commands changed, so no maintained
authoring-document update or conformance rerun was required.
