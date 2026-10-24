# 100 browser moves

These are recorded operations/workflows, not100 independent passing tests. Durations include tool overhead and may stop before asynchronous work completes. Raw capture status is preserved in moves.json; the assessment below determines what each capture establishes.

| Move | Action | Classification | Assessment | Workflow ms |
| --- | --- | --- | --- | ---: |
| 1 | Reload committed build at historical context | pending-navigation | Reload snapshot was still reconstructing; move2 establishes settled result. | 232 |
| 2 | Rerun restored historical VPN trace | control-observed | Historical VPN trace completed with both endpoints reachable. | 4471 |
| 3 | Search a new traffic destination CE-East | action-observed | Destination text entry, not a submitted route assertion. | 991 |
| 4 | Configure A→CE-East default IPv4 trace | action-observed | VRF default and advanced controls are visible before the later family edit. | 1566 |
| 5 | Trace CE-East before its uncertainty window | harness-inconclusive | Actual UI had a blue-VRF inventory error; helper incorrectly waited only for ROUTE OUTCOME. Not a20-second UI stall. Later37/38 establish context coercion. | 20802 |
| 6 | Reapply default VRF after family/type change and trace | control-observed | Reapplied default; CE-East unresolved before endpoint admission. | 4764 |
| 7 | CE-East one ns before validity | boundary-control-observed | CE-East unresolved at UTC+601.014999999. | 6366 |
| 8 | CE-East exact validity boundary | boundary-control-observed | CE-East reachable at exact UTC+601.015. | 6376 |
| 9 | Rewind CE-East to 1 ns before admission | functional-pass | CE-East at UTC+601.014999999 is unresolved in both directions; the destination final-hop gap is retained. | 9506 |
| 10 | Repeat CE-East exact admission boundary | functional-pass | Exact CE-East +601.015 boundary resolves both directions after rewind. | 6424 |
| 11 | Cross destination to Edge-C at CE-East threshold | harness-inconclusive | Click failed with No node found at given location after destination edit; snapshot has no completed trace. Do not infer route failure. | 1293 |
| 12 | Trace Edge-C after destination field settled | functional-pass | Explicit retry after field settlement gives unresolved Edge-C in both directions at +601.015, as expected. | 4493 |
| 13 | Advance Edge-C to 1 ns before admission | functional-pass | Edge-C remains unresolved 1ns before +601.025. | 6335 |
| 14 | Advance Edge-C to exact admission | functional-pass | Exact Edge-C +601.025 boundary resolves both directions. | 6429 |
| 15 | Select return Edge-C path | functional-pass | Return tab selected; endpoint remains PE-A, with Edge-C as return origin. | 992 |
| 16 | Focus return path | functional-pass | Focused path stays in Return and shows Edge-C via C/P2 to PE-A. | 898 |
| 17 | Bound trace to one hop | harness-inconclusive | Trace-button click failed after budget edit/layout invalidation. This does not test the one-hop result. | 1460 |
| 18 | Restore hop budget | harness-inconclusive | Wait helper timed out; snapshot contains empty alerts and generic idle trace guidance. Restore itself invalidates the result and requires rerun. No input-validation error or backend failure is established. | 21244 |
| 19 | Change type to MPLS L3VPN | functional-pass | Changing route TYPE to MPLS L3VPN updates dependent family/VRF to VPNv4/blue. This type-driven compatibility is expected. | 311 |
| 20 | Attempt default VRF while L3VPN selected | trigger-inconclusive | Default text remains in snapshot with L3VPN/VPNv4. It does not reproduce silent reset; native change/blur emission was not established. | 479 |
| 21 | Repeat conflicting VRF edit | trigger-inconclusive | Repeated equal-value fill likewise remains default. Not confirmation of reset and not evidence of an asynchronous app race. | 400 |
| 22 | Change route type before editing VRF | functional-pass | Changing TYPE to IPv4 first yields IPv4 family/default VRF; recovery context is valid. | 430 |
| 23 | Trace corrected route context after blur | functional-pass | Explicit trace with corrected context restores Edge-C reachability at +601.025. | 4560 |
| 24 | Load transit observation scenario | functional-pass | Transit scenario loads P1 as observation start and A as packet source; no trace result yet. | 1001 |
| 25 | Trace transit scenario before +610 admission | functional-pass | At prior inventory time +601.025, later-observed transit scenario stays incomplete in both directions. | 4491 |
| 26 | Advance transit scenario to +610.015999999 | functional-pass | Transit at +610.015999999 remains incomplete in both directions. | 6688 |
| 27 | Advance transit scenario to +610.016 | functional-pass | Exact +610.016 resolves forward P1 to B and return B to source A. | 6476 |
| 28 | Trace only the return flow from transit scenario | functional-pass | Return-only disables unused start and Forward tab; reachable return ends at A. | 3393 |
| 29 | Trace only forward from transit observation | functional-pass | Forward-only restores observation start P1 and disables Return tab; reachable forward ends at B. | 3346 |
| 30 | Restore both and all paths | functional-pass | Both directions and All paths restore correct distinct observation and endpoint semantics. | 5326 |
| 31 | Load EVPN all-active and reconstruct first branch boundary | functional-pass | At +610.018, E branch segments are Resolved, B branch is Incomplete, return has two candidates. Aggregate Trace is incomplete is intended: one selected active branch remains unknown. | 7545 |
| 32 | Complete second EVPN branch at +610.019 | functional-pass | At +610.019 both forward branches complete; summary correctly allows reachable asymmetric endpoint sets. | 6870 |
| 33 | Rewind EVPN to first-branch-only instant | functional-pass | Rewind +610.018 makes B incomplete again; focused E remains Resolved. Aggregate incompleteness does not contradict focused branch success. | 7183 |
| 34 | Restore both branches and return direction | functional-pass | At +610.019 current forward branch resolves again. Snapshot remains Forward; title mentions return, but return switching is only established by35. | 6813 |
| 35 | Select EVPN return then alternate branch | functional-pass | Return tab and focused E-to-A path are consistent. Saved snapshot shows ecmp-p1; it alone does not establish a separate alternate-branch selection. | 1134 |
| 36 | Change EVPN to MPLS VPN context | functional-pass | Changing TYPE from EVPN to MPLS L3VPN correctly applies VPNv4/blue and invalidates prior result. | 961 |
| 37 | Edit VRF then request IPv4 family with old VPN type | confirmed-finding | Parent recorded explicit default edit followed by selecting IPv4 FAMILY; settled DOM instead reads blue/VPNv4/MPLS-L3VPN. This is silent old-type-priority coercion, corroborated by existing change handler. | 441 |
| 38 | Repeat family-only IPv4 change while VPN type remains | confirmed-finding | Same family-change operation repeats blue/VPNv4/MPLS-L3VPN. Confirms the same interaction finding, not a second defect. | 380 |
| 39 | Open PE-A single-node workspace from absolute route context | pending-navigation | Node opened from fabric absolute context; initial helper limit still left some loading. Later40–43 establish settled node state. | 14846 |
| 40 | Set node cursor before second ES0 service attachment | Cursor control observed | Range starts240.01 and graph reports selected+240.010; this alone does not establish all resource semantics. | 5225 |
| 41 | Switch to Ethernet Segment table | Action observed | ES table navigation at unchanged cursor. | 2202 |
| 42 | Search ES0 compound resource identity | Action observed | ES0 search at unchanged cursor; graph is not yet selected to ES0. | 3888 |
| 43 | Focus ES0 correlation before service375 attaches | Defect reproduced | ES0 at+240.010 has service375 member_of_es/active_path before attachment. | 1647 |
| 44 | Search service375 while ES0 remains selected | Action observed | Disjoint ETG search while ES selection remains; empty current-kind rows are not a defect. | 826 |
| 45 | Switch from empty ES search to matching ETG | Boundary control observed | ETG375 row is single-home at+240.010; ES graph still exhibits early membership. | 732 |
| 46 | Focus ETG375 correlations before multihoming | Defect reproduced | Focused ETG375 exposes member_of_es ES0 while its table says single-home. | 2404 |
| 47 | Advance to one ns before ETG375 attachment | Defect reproduced | At240.037499999 table single-home, early membership retained. | 3763 |
| 48 | Advance ETG375 to exact attachment | Boundary control observed | Exact240.037500000 changes ETG375 to all-active and adds backup ownership. | 3966 |
| 49 | Rewind ETG375 attachment again | Defect reproduced | Rewind1ns returns table to single-home but leaves membership. | 2697 |
| 50 | Show all correlations at pre-attachment time | Defect reproduced across scope | Full graph also contains the early edge; truncation is disclosed. Does not prove entire full graph coverage. | 1879 |
| 51 | Return to selected ETG after bounded graph | Defect reproduced across scope | Focus selected recovers the same early membership at pre-attachment time. | 1175 |
| 52 | Search alternate service749 at same cursor | Action observed | ETG749 search changes rows while preserving the cursor. | 680 |
| 53 | Focus ETG749 before second ES374 attachment | Defect reproduced on second identity | ETG749 is single-home yet attached to ES374 before its own attachment. | 3693 |
| 54 | Move ETG749 to one ns before attachment | Defect reproduced on boundary | ETG749 remains single-home at240.074899999 with early ES membership. | 4724 |
| 55 | Move ETG749 to exact attachment | Boundary control observed | Exact240.074900000 changes ETG749 to all-active. | 6130 |
| 56 | Search shared ES374 | Action observed | ES374 filter change; does not itself assert graph selection changed. | 685 |
| 57 | Switch to ES374 table | Table control observed | ES374 row up at unchanged cursor. | 664 |
| 58 | Focus ES374 after both attachments | Correlation control observed | ES374 selected after both attachments; primary374 and primary749 active_path identities present. | 1137 |
| 59 | Withdraw ES374 before service failovers | Historical control observed | At360.0374 ES374 withdrawn while both service paths still primary. This stagger is intended. | 5892 |
| 60 | Fail first ES374 service | Historical control observed | At360.0749 active_path is backup374 plus primary749. | 5786 |
| 61 | Fail second ES374 service | Historical control observed | At360.1124 both active_paths are backups. | 4111 |
| 62 | Rewind second failover by one ns | Backward control observed | At360.112399999 mixed backup374/primary749 returns. | 5849 |
| 63 | Restore ES before services | Historical control observed | At480.0374 ES374 up while both paths remain backups. | 5177 |
| 64 | Restore first ES374 service | Historical control observed | At480.0749 active_path is primary374 plus backup749. | 6180 |
| 65 | Restore second ES374 service | Historical control observed | At480.1124 both paths primary. | 5821 |
| 66 | Rewind restoration to mixed paths | Backward control observed | At480.112399999 mixed primary374/backup749 returns. | 3943 |
| 67 | Search shared interface ae-00000 | Action observed | VIF0 search does not advance the ES-selected cursor. | 849 |
| 68 | Open shared interface table | Table control observed | VIF0 row shows neighbor_count2 and all-active at480.112399999. | 660 |
| 69 | Focus VIF0 correlations | Correlation control observed | Focus VIF0 contains two has_neighbor identities, both up. | 1284 |
| 70 | Rewind VIF0 before neighbor374 creation | Boundary control observed | At120.037399999 VIF0 neighbor_count1; only peer0 association present. | 3358 |
| 71 | Advance VIF0 to exact neighbor374 creation | Boundary control observed | Exact120.0374 gives count2 and adds peer374 association. | 5204 |
| 72 | Rewind shared-neighbor creation one ns | Backward control observed | Rewind1ns restores count1 and removes peer374 association. | 2095 |
| 73 | Move to staggered neighbor withdrawal | Historical control observed | At360.037399999 both associations remain; peer0 down, peer374 up.9.457s complete move duration is a latency observation, not CPU attribution. | 9457 |
| 74 | Complete second neighbor withdrawal | Historical control observed | Exact360.0374 both neighbors down, both structural associations remain. | 3703 |
| 75 | Move to staggered neighbor restore | Historical control observed | At480.037399999 peer0 up, peer374 down; associations/count unchanged. | 5737 |
| 76 | Complete second neighbor restore | Historical control observed | Exact480.0374 both neighbors up and count2. | 6412 |
| 77 | Inspect shared neighbor relationship popup | Pointer defect reproduced | Intended peer374 edge opens peer0 resource card; see occlusion review. | 688 |
| 78 | Keyboard activate neighbor374 edge after pointer result | Keyboard control observed | Enter on exact edge opens relationship has_neighbor VIF0→peer374. | 506 |
| 79 | Repeat pointer activation of neighbor374 edge | Pointer defect reproduced | Repeated pointer action opens selected VIF0 resource card instead. | 657 |
| 80 | Open intended neighbor374 node popup | Target-node control observed | Actual peer374 node opens correct peer374 resource card. | 470 |
| 81 | Search normalized log for ES374 withdrawal event | performance-observation | Exact-ID event search began cold index construction; capture is pending, not a search result. | 309 |
| 82 | Open neighbor table while log search is pending | control-observed | Neighbor table changes remained responsive during the cold index build. | 734 |
| 83 | Focus neighbor374 via table | control-observed | Neighbor374 focused correctly with one incoming has_neighbor from VIF0 while event search remained pending. | 1839 |
| 84 | Clear event search while awaiting exact ID | action-observed | Clear canceled pending first search; no settled unfiltered result was captured here. | 334 |
| 85 | Search ES374 withdrawal by event name | performance-observation | Event-name search began while cold construction was active; final sidecar publication follows. Exact request attribution unavailable. | 821 |
| 86 | Return resource table to shared interface | control-observed | VIF0 table and correlation focus restored while log indexing continued. | 1935 |
| 87 | Repeat exact cursor while event index builds | control-observed | Repeated exact cursor kept the VIF graph coherent; workflow cost is not isolated backend latency. | 3651 |
| 88 | Reopen covered correlation label with keyboard | keyboard-control-observed | Correct has_neighbor VIF0-to-peer374 relationship popup. Pre-click hit test was off-screen and empty, so it is not occlusion proof. | 564 |
| 89 | Repeat pointer activation of covered label | defect-reproduced | Pointer activation again opened ae-00000 resource popup. Visible after-click hit-test places node above exact edge label (HC3-3). | 800 |
| 90 | Collapse correlation graph during log indexing | control-observed | Graph collapsed; Expand correlation is present. | 3222 |
| 91 | Reopen correlation after collapse | control-observed | Focused correlation graph reopened. | 765 |
| 92 | Return to fabric from independently moved node cursor | pending-navigation | Return-to-fabric snapshot still loading but URL retained original UTC+610.019. Move93 establishes settled route. | 279 |
| 93 | Reload a valid transit scenario after node return | control-observed | Transit scenario remains reachable after node return, with P1 observation and A return target. | 6404 |
| 94 | Browser Back from fabric to node | navigation-observed | Browser Back returns original explicit node URL and+610.023 native cursor; some initial data loading persisted. | 7752 |
| 95 | Clear event search after return | action-observed | Clear entered, but immediate capture still showed previous event-name results. Do not claim settled unfiltered recovery here. | 156 |
| 96 | Repeat exact event-ID search after index construction | warm-search-control | Exact event ID returns1 record in3.002s workflow after cold index publication. | 3002 |
| 97 | Select exact ES374 withdrawal log row | control-observed | Exact ES374 withdrawal event inspected; affected_services is not exposed, leaving that separate source candidate unconfirmed in browser. | 826 |
| 98 | Close event detail without losing history search | control-observed | Timeline-details dialog closed and event search retained. | 529 |
| 99 | Restore unfiltered normalized stream | warm-search-control | Unfiltered stream visibly restored1,250,005 matching records;785ms workflow. | 785 |
| 100 | Repeat exact ES374 event search warm | warm-search-control | Repeated exact-ID query visibly returned1 matching record;660ms workflow without index rebuild. | 660 |
