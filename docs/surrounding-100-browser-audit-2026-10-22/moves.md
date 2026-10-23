# 100-move browser ledger

Each row is one numbered step in a stateful browser sequence. Adaptations and incomplete activations are retained. Supplementary controls and the two confirmed defects appear after the numbered rows.

| Move | Original plan | Actual action and observation | Outcome |
| --- | --- | --- | --- |
| 001 | Jump to Route trace from the retained VPN graph | Jump to Route trace from the retained VPN graph. Route trace section retained nested-VPN Forward result and focused-path view. | no-defect-observed |
| 002 | Choose MTU-drop packet scenario | Choose packet-mtu-drop. Scenario and default IPv4/default-VRF endpoints changed; prior trace cleared. | no-defect-observed |
| 003 | Request both trace directions | Select Both directions. Directions control changed to Both directions. | no-defect-observed |
| 004 | Run MTU-drop trace | Run MTU-drop trace. Both direction tabs reported dropped; Forward evidence reported MTU exceeded after encapsulation. | no-defect-observed |
| 005 | Select the terminal packet transition | Select the terminal MTU-drop transition. The only transition was selected: PE-A encapsulation 1490 to 1510 B, DROP / MTU EXCEEDED. | no-defect-observed |
| 006 | Select the first packet transition | Close details, then select the first MTU-drop transition. The same single transition was selected again; this did not exercise two distinct packet transitions. | no-defect-observed |
| 007 | Switch packet-drop graph to All paths | Switch MTU-drop graph to All paths. All paths selected; Forward remained selected and dropped. | no-defect-observed |
| 008 | Inspect Return direction | Select Return in All paths. Return selected and reported dropped; All paths remained selected. | no-defect-observed |
| 009 | Restore Forward direction | Select Forward again. Forward selected; dropped outcome retained. | no-defect-observed |
| 010 | Restore Focused path view | Switch back to Focused path. Focused path selected and MTU-drop evidence restored. | no-defect-observed |
| 011 | Choose exact-MTU packet scenario | Choose packet-mtu-exact. Exact-MTU scenario selected; prior result invalidated. | no-defect-observed |
| 012 | Run exact-MTU trace | Run exact-MTU trace; reconnect after browser-tool timeout. Recovered capture showed a resolved complete observed path with three transitions and Deliver / MTU fits. No precise trace duration can be inferred from this recovered record. | no-defect-observed |
| 013 | Inspect its delivered packet transition | Select exact-MTU delivery transition. PE-B transition3 selected, decapsulation1500 to 1480 B, DELIVER / MTU FITS. | no-defect-observed |
| 014 | Expand advanced trace options | Expand advanced trace options. Advanced options expanded with observed steering, hops 64, recursion 16. | no-defect-observed |
| 015 | Choose forced-steering packet scenario | Choose packet-forced-steering. Forced-steering scenario selected, initially observed steering. | no-defect-observed |
| 016 | Select an advertised counterfactual steering rule | Select Force alternate path through P2. Advertised force-alternate-p2 profile selected. | no-defect-observed |
| 017 | Run forced trace | Run forced Both-directions trace. Complete alternative returned, visibly Counterfactual, with three transitions and delivery. | no-defect-observed |
| 018 | Change to Return only | Change to Return only. Return-only control selected; previous result invalidated. | no-defect-observed |
| 019 | Run Return-only forced trace | Run Return-only forced trace. Return result showed complete counterfactual alternate P2 path and delivery. | no-defect-observed |
| 020 | Restore Both directions | Restore Both directions. Both directions selected. | no-defect-observed |
| 021 | Reduce hop budget to one | Set maximum hops to 1. Hops control showed 1 and prior trace cleared. | no-defect-observed |
| 022 | Run constrained-hop trace | Run constrained-hop trace. Traversal limit reached / Hop limit reached / Incomplete appeared; counterfactual packet evidence ended Continuation Required. | no-defect-observed |
| 023 | Restore hop budget to 64 | Restore maximum hops to 64. Hops control showed 64 and result invalidated. | no-defect-observed |
| 024 | Submit invalid recursion limit zero | Run legal recursion 0; subsequently try invalid recursion -1. Zero is the advertised legal minimum and ran. First -1 pointer-submit attempt unexpectedly navigated to PE-A; attribution unresolved. After recovery, native keyboard submission retained -1 on Fabric and did not execute a trace. | pending/limited |
| 025 | Restore recursion limit and run successfully | Recover Fabric, restore recursion 16, run trace. Earlier retry encountered another timeout/navigation anomaly. Final capture showed restored Both-directions forced trace with complete Return alternative and delivery; intermediate pointer navigation is not established as an application defect. | pending/limited |
| 026 | Jump to Route tables and search packet-mtu | Jump to Route tables and search packet-mtu. Visible routes 8/693; search value packet-mtu. | no-defect-observed |
| 027 | Filter route tables to PE-A | Filter matching route rows to PE-A. Visible routes 4/693. | no-defect-observed |
| 028 | Filter routes to default VRF | Filter to Default VRF. Four matching rows remained. | no-defect-observed |
| 029 | Filter to IPv4 family | Filter to IPv4 Unicast family. Four matching rows remained. | no-defect-observed |
| 030 | Filter to an available protocol | Select Static protocol/source. Combined filters produced0/693 rows; empty combination is not a defect. | no-defect-observed |
| 031 | Expand a route's plug-in details | Clear Static protocol filter, then expand first row's Plug-in details. Four rows returned; the selected Plug-in details disclosure expanded. | no-defect-observed |
| 032 | Collapse those details | Collapse the same Plug-in details disclosure. Disclosure returned to collapsed state. | no-defect-observed |
| 033 | Apply a nonexistent destination filter | Set destination filter to not-a-real-prefix-100. Visible routes 0/693 with No routes match the current filters. | no-defect-observed |
| 034 | Clear all route filters | Clear route filters. Search cleared and Visible routes 693/693 restored. | no-defect-observed |
| 035 | Search forced-steering routes | Search packet-forced-steering. Four matching routes displayed. | no-defect-observed |
| 036 | Use one matching route to seed trace | Use first PE-A forced-steering route row for trace. Seed reset Forward only and endpoints; selected row was explicitly the inactive counterfactual P2 candidate, so forced P2 steering is expected. | no-defect-observed |
| 037 | Run seeded trace and inspect form/result identity | Run seeded route. Forward forced-P2 counterfactual result matched selected row; this is not proof of stale steering retention. | no-defect-observed |
| 038 | Jump to inter-node Links | Jump to inter-node Links. Links section reached with existing route state retained. | no-defect-observed |
| 039 | Open a link endpoint in its node workspace | Open link endpoint in node workspace. Node URL opened and loading UI appeared; cold endpoint initialization had not completed before move 40 Back. Full node workflow not validated here. | pending/limited |
| 040 | Return to fabric with browser Back | Browser Back to Fabric during endpoint loading. Fabric reconstructed and eventually settled by move 45. Long process-wide CPU/loading observation exists, but earlier outstanding work prevents attributing it solely to Back/reconstruction. The route-table field/state mismatch noticed here was subsequently confirmed in a controlled post-100 followup. | pending/limited |
| 041 | Jump to Fabric | Jump to Fabric while reconstruction remained pending. Fabric anchor reached; capture still showed reconstruction and loading route capabilities, so this is not a settled reconstruction check. | pending/limited |
| 042 | Open How to read | Expand How to read while loading. Guide disclosure expanded and held focus. | no-defect-observed |
| 043 | Close How to read | Collapse How to read. Guide disclosure collapsed and held focus. | no-defect-observed |
| 044 | Filter devices to P1 | Fill device filter with P1 while reconstruction was pending. Field showed P1 and retained focus; filtering a settled graph was not established by this capture. | pending/limited |
| 045 | Switch attention highlighting | Choose Highlight attention. Attention selected; reconstruction had settled. Retained route-search text with 693/693 unfiltered results was noticed here and later confirmed as the separately recorded browser-Back filter defect. | no-defect-observed |
| 046 | Switch incomplete highlighting | Choose Highlight incomplete. Incomplete selected; other highlight choices unselected. | no-defect-observed |
| 047 | Restore all-device highlighting | Restore Highlight all. Highlight all selected. | no-defect-observed |
| 048 | Clear device text filter | Clear device text filter. Filter field empty; all-device highlighting retained. | no-defect-observed |
| 049 | Collapse device list | Expand device list using Show all. Button became expanded Show less; original plan incorrectly called this collapse. | no-defect-observed |
| 050 | Expand device list | Collapse device list using Show less. Button became collapsed Show all; original plan incorrectly called this expand. | no-defect-observed |
| 051 | Select Underlay plane | Select Underlay plane. Underlay selected; five detail layers retained; graph readout76%. | no-defect-observed |
| 052 | Open Elements picker | Open Elements picker. Picker expanded with five of six detail layers enabled. | no-defect-observed |
| 053 | Enable Subinterfaces | Enable Subinterfaces. All preset / six of six layers shown. | no-defect-observed |
| 054 | Disable Interfaces | Disable Interfaces. Custom preset / five of six layers; checkbox unchecked. | no-defect-observed |
| 055 | Disable Subnets | Disable Subnets. Custom preset / four of six layers; checkbox unchecked. | no-defect-observed |
| 056 | Disable External networks | Disable External networks. Custom preset / three of six layers; external network excluded. | no-defect-observed |
| 057 | Disable VLANs | Disable VLANs. Custom preset / two of six layers. | no-defect-observed |
| 058 | Disable LAGs | Disable LAGs. Custom preset / one of six layers; separate LAG component controls removed. | no-defect-observed |
| 059 | Disable the last remaining layer and inspect empty presentation | Disable Subinterfaces, the last remaining detail layer. Custom preset / zero of six; Connectivity only. Connection labels and device/domain identities remain intentionally; AX and source do not establish a compact fallback. Detailed visual junction geometry was not independently verified in this ledger. | no-defect-observed |
| 060 | Restore Subnets and Interfaces | Restore Compact preset and close picker. Two layers, subnets plus interfaces, restored; separate physical-interface component controls returned. | no-defect-observed |
| 061 | Select P1 in topology graph | Select P1 in Underlay graph. Header Open target and spotlight changed to P1. | no-defect-observed |
| 062 | Set graph zoom to 1:1 | Set graph to 1:1. Zoom readout changed from 76% to 100%. | no-defect-observed |
| 063 | Pan graph left repeatedly | Focus graph and press Left repeatedly. Original capture retained graph focus and 100% zoom but did not record transform geometry. Later controlled repetition confirmed ten Left presses changed translation x from -130.4 to 229.6 (+360 px), with y fixed at -82 and scale 1. | no-defect-observed |
| 064 | Pan graph down repeatedly | Press Down repeatedly in graph. Original capture retained graph focus and 100% zoom but did not record transform geometry. Later controlled repetition confirmed ten Down presses changed translation y from -82 to -442 (-360 px), with x fixed at 229.6 and scale 1. | no-defect-observed |
| 065 | Fit graph with keyboard | Use graph keyboard Fit. Zoom readout returned to 76%; graph retained focus. Later controlled Fit captured matrix scale 0.757062 and translation (44.0294, 15.661), corroborating the rounded readout. | no-defect-observed |
| 066 | Switch to VPN plane | Switch to VPN plane. VPN selected with 83% readout; prior P1 focus retained. | no-defect-observed |
| 067 | Select PE-B graph node | Attempt pointer selection of PE-B VPN node. Header and spotlight remained P1. Intended PE-B activation was not demonstrated; tool targeting versus product behavior remains unresolved. | pending/limited |
| 068 | Return to Underlay | Return to Underlay. Underlay selected with 76% readout and P1 focus retained; this does not retrospectively prove move 67 worked. | no-defect-observed |
| 069 | Reconstruct at minus360 seconds | Reconstruct at -360 seconds. Initially pending; followup confirmed applied -360 s. Subsequent extra pin/filter keyboard sequence found a new focus defect recorded separately. | no-defect-observed |
| 070 | Move reconstruction slider to oldest boundary | Move reconstruction slider to oldest boundary. Pending display distinguished selected -720 s from graph -360 s; followup confirmed applied -720 s. | no-defect-observed |
| 071 | Move slider to newest boundary | Move reconstruction slider to newest boundary. Pending display distinguished selected 0 s from graph -720 s; followup confirmed applied 0 s. | no-defect-observed |
| 072 | Reconstruct with strict clock policy | Reconstruct with Strict clock policy. Followup showed Strict and applied 0 s; incomplete/uncertain coverage stayed explicit. | no-defect-observed |
| 073 | Switch to absolute time basis | Switch to absolute-time basis. Absolute UTC input exposed, value1759680719996000000. | no-defect-observed |
| 074 | Submit an invalid absolute timestamp | Submit absolute timestamp not-a-time. Inline rejection: Absolute time must be an integer nanosecond timestamp; last applied graph retained with Controls changed disclosure. | expected-rejection |
| 075 | Submit a valid timestamp | Submit absolute timestamp1759680719996000000. Followup confirmed applied absolute UTC1759680719.996 s. | no-defect-observed |
| 076 | Restore relative watermark zero and best-effort policy | Restore relative watermark0 and Best effort, reconstruct. Followup confirmed applied 0 s and Best effort. | no-defect-observed |
| 077 | Remove PE-B from selected members | Uncheck PE-B without applying reconstruction. Selection showed 9/10 and Controls changed; previous graph remained explicitly last applied. | no-defect-observed |
| 078 | Inspect route behavior with PE-B excluded | Attempt trace while PE-B excluded from selection. Endpoint PE-B outside reconstructed device set message requested selecting device and reconstructing; no valid trace returned. | expected-rejection |
| 079 | Restore PE-B and reconstruct | Restore PE-B and reconstruct. Ten members restored; later followup confirmed Global topology API and applied 0 s. | no-defect-observed |
| 080 | Open PE-A node workspace | Open PE-A node workspace. Initial record and progress followup were still loading; later readiness followup reported all 1,250,005 normalized events and7,510 resources loaded. Node interaction coverage belongs to moves81 onward. | no-defect-observed |
| 081 | Open resource lane picker | Open resource lane picker. Picker expanded with 13 selected resource lanes out of 7,510 and two log lanes. | no-defect-observed |
| 082 | Filter lanes for DTE000009 | Search lanes for DTE000009, then correct to canonical dte-000009. Initial compact label had no matches; canonical hyphenated resource label found one DTE. The initial miss is not a product failure. | no-defect-observed |
| 083 | Enable matching resource lane | Enable dte-000009 lane and close picker. Canonical DTE checkbox became checked; subsequent capture showed 14 lanes. | no-defect-observed |
| 084 | Jump to its known failure event | Activate known DTE failure event from issue summary. Selected Dte Next Hop Dependency Change, node-a/scale-event-01000759 at +600.075 s; followup settled. | no-defect-observed |
| 085 | Inspect selected event in an adjacent component | Inspect selected event/resource in dependency graph. Dependency-graph section reached, selected failure retained, and incoming/outgoing resource context was shown. | no-defect-observed |
| 086 | Zoom the event timeline | Zoom timeline in once. Zoom changed from 1 to 1.5; Back view enabled. | no-defect-observed |
| 087 | Use timeline Back | Use timeline Back view. Zoom returned to 1; Forward view enabled; selected event remained DTE failure. | no-defect-observed |
| 088 | Jump to node topology at selected cursor | Jump to temporal topology. Temporal-topology section reached with selected DTE failure and absolute-time controls. | no-defect-observed |
| 089 | Inspect a resource relationship | Activate next_hop relationship for dte-000009. Outgoing-correlation popup showed exact DTE to IP_ROUTING/blue identity and +600.000 to +600.150 s interval. Slight reported edge overhang had no saved screenshot/material impact and is not counted as a defect. | no-defect-observed |
| 090 | Return to node overview | Return to node Overview. Overview reached; saved state showed latest +720 s moment and no selected event. This record does not assert selection continuity across that move. | no-defect-observed |
| 091 | Search for the selected event identity | Search exact event UID node-a/scale-event-01000759. Settled server-windowed history reported one matching record; search retained focus. | no-defect-observed |
| 092 | Clear event search | Clear event search. Settled history restored 1,250,005 matching records; input remained focused. | no-defect-observed |
| 093 | Jump to event log | Move to event-log controls. Normalized-events control received focus; search was empty. Exact-row activation was exercised in move 94. | no-defect-observed |
| 094 | Activate a log-row detail card | Reapply exact UID search and activate matching log row. Row selected and detail card displayed DTE failure at +600.075 s, modify/failure, no mutation and status unchanged. | no-defect-observed |
| 095 | Hide selected resource lane | Hide selected DTE resource lane. Lane count dropped from 14 to 13; selected event remained available in inspector/log. | no-defect-observed |
| 096 | Jump to selected event again | Use log Reveal in timeline and wait for settled reveal. Immediate record still showed 13 lanes; followup restored 14 and focused a visible 10-event cluster in dte-000009 whose interval contains the selected event. Exact event UID remained selected; cluster last UID is not the selected-event identity. | no-defect-observed |
| 097 | Return to fabric | Return to Fabric from node workspace. Initial capture loaded capabilities; followup restored Fabric and forced-steering controls. | no-defect-observed |
| 098 | Run the restored route | Run restored forced-P2 route. Forward alternative completed with Counterfactual status and expected PE-A to P2 to PE-B path. | no-defect-observed |
| 099 | Reload the route workspace | Reload route workspace. Initial capture showed reinitialization rather than a completed trace; subsequent move 100 successfully exercised the reloaded page. | no-defect-observed |
| 100 | Run and fit a final successful route | Choose exact-MTU scenario, trace, and Fit. Final Forward focused path resolved completely with observed forwarding; Fit button held focus. This intentionally changed the restored forced-steering scenario. | no-defect-observed |

## Supplementary controls and findings

### after-69-pinned-filter-focus

**new-defect**. Pin10.64.0.0/24, focus Filter nodes, type p, then type1 without refocusing.

First character p is inserted, then activeElement becomes Close topology details; the next native key leaves filter p. A second pin/filter sequence reproduced the same result. After closing the pin, typing p1 retained input focus and displayed one matching device. Passive graph redraw restores the pin through unconditional close-button focus.

Evidence: `followups.jsonl:pin-before-filter`, `followups.jsonl:pinned-filter-keyboard-first-character`, `followups.jsonl:pinned-filter-next-character`, `pinned-filter-keyboard-focus.json`, `pinned-filter-keyboard-focus.png`, `followups.jsonl:focus-repeat-pinned`, `followups.jsonl:focus-repeat-query-lost`, `pinned-filter-repeat.json`, `pinned-filter-repeat.png`, `followups.jsonl:focus-no-pin-control`, `filter-no-pin-control.png`.

### after-40-route-filter-restoration

**new-defect**. Reproduce after move 100: apply search packet-mtu, Node PE-A, and destination demo:node-b:packet-mtu-exact; open Management; browser Back; wait for settled Fabric.

Before navigation one matching route was shown. After Back, search and destination text persisted, Node reset to All nodes, and 693/693 routes appeared including nonmatching rows. Editing only search reduced results to eight while the visible destination still did not apply; editing destination reduced results to one. Reselecting PE-A retained one. This confirms visible text fields were out of sync with filter state.

Evidence: `moves.jsonl:id=37`, `moves.jsonl:id=45`, `moves.jsonl:id=50`, `followups.jsonl:back-filter-before-navigation`, `followups.jsonl:back-filter-return-settled`, `followups.jsonl:back-filter-reapply-search-only`, `followups.jsonl:back-filter-reapply-destination`, `followups.jsonl:back-filter-recovered-all-three`, `back-filter-before.png`, `back-filter-mismatch.json`, `back-filter-mismatch.png`, `back-filter-recovered.png`.

### 24-25-unexpected-node-navigation

**pending/limited**. Pointer-submit invalid/recovered trace controls.

Unexpected PE-A navigation recorded; keyboard invalid-input retry behaved correctly. No source navigation path from budget validation was found. Tool targeting, popup overlap, and scrolling remain hypotheses.

Evidence: `followups.jsonl:24-unexpected-navigation`, `followups.jsonl:24-invalid-keyboard-submit`, `followups.jsonl:25-trace-retry-timeout`.

### 40-return-loading-cost

**pending/limited**. Observe process while immediately returning from a still-loading node workspace.

A64.436-second observation window accumulated54.547 process CPU seconds, with RSS peak3550547968bytes. Window includes earlier asynchronous work and later UI operations; neither CPU attribution nor exact completion time is isolated.

Evidence: `move40-reconstruction-observation.json`.

The machine-readable [ledger](move-ledger.json) maps every numbered move to its raw capture and relevant follow-ups. Read the [report](README.md) for root-cause evidence and measurement limits.
