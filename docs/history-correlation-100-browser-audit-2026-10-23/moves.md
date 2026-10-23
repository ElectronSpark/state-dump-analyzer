# 100-move execution ledger

Each row represents a stateful browser move, not an independent test case. “Observed” means the action and snapshot were recorded; it does not assert every visible component passed. Review the findings and archived source/evidence reviews for settled correctness claims.

Original plan is preserved separately. Actual actions sometimes adapt that plan to observed UI or more discriminating controls. Snapshots are inside evidence.zip; execution timestamps and URLs are in moves.json.

| # | Planned move | Actual action | Evidence assessment | Recorded observation |
|---:|---|---|---|---|
| 001 | Baseline latest-watermark primary trace | Baseline latest-watermark primary trace | Pending / supplemental evidence needed |  |
| 002 | Inspect return direction at latest | Inspect return direction at latest | Observed |  |
| 003 | Switch to all-paths at latest | Switch to all-paths at latest | Observed |  |
| 004 | Use absolute best-effort at +89s | Use absolute best-effort at +89s | Pending / supplemental evidence needed |  |
| 005 | Trace before carrier failure | Trace before carrier failure | Pending / supplemental evidence needed |  |
| 006 | Reconstruct +90.049s | Reconstruct +90.049s | Pending / supplemental evidence needed | Within clock uncertainty; ambiguity is permitted |
| 007 | Trace immediately before carrier-down | Trace immediately before carrier-down | Pending / supplemental evidence needed |  |
| 008 | Reconstruct +90.051s | Reconstruct +90.051s | Pending / supplemental evidence needed | Within clock uncertainty; ambiguity is permitted |
| 009 | Trace immediately after carrier-down | Trace immediately after carrier-down | Pending / supplemental evidence needed |  |
| 010 | Inspect return during carrier-down | Inspect forward direction after return at carrier-down boundary | Observed |  |
| 011 | Reconstruct +100s | Reconstruct +100s | Pending / supplemental evidence needed |  |
| 012 | Compare route table validity with selected historical basis | Compare route table validity with selected historical basis | HC-01 |  |
| 013 | Trace generic blue VPN at +100s | Trace generic blue VPN at +100s | HC-01 | Seeded row contains observed_at_ns 1759680600996000000, later than applied +100s; cold trace completed after several seconds |
| 014 | Switch historical VPN to all paths | Switch historical VPN to all paths | HC-01 |  |
| 015 | Inspect historical VPN service details | Inspect historical VPN service details | HC-01 |  |
| 016 | Reconstruct +119.999s | Reconstruct +119.999s | Pending / supplemental evidence needed | Near boundary; uncertainty expected |
| 017 | Trace before next-hop change | Trace before next-hop change | Qualified / limited |  |
| 018 | Reconstruct +120.001s | Reconstruct +120.001s | Pending / supplemental evidence needed |  |
| 019 | Trace after next-hop change | Trace after next-hop change | Qualified / limited | Trace settled in 5010ms (includes browser observation) |
| 020 | Reconstruct +179.999s | Reconstruct +179s and target PE-D | Pending / supplemental evidence needed | Adjusted away from uncertainty boundary |
| 021 | Trace before interface deletion | Trace before interface deletion | Observed |  |
| 022 | Reconstruct +180.001s | Reconstruct +181s after interface deletion | Pending / supplemental evidence needed |  |
| 023 | Inspect deleted-node topology and trace | Inspect deleted-node topology and trace | Observed |  |
| 024 | Reconstruct +240.099s | Reconstruct +239s with SRv6 all-active | Pending / supplemental evidence needed |  |
| 025 | Trace before carrier restoration | Trace before carrier restoration | Qualified / limited |  |
| 026 | Reconstruct +240.101s | Reconstruct +241s after carrier restoration | Pending / supplemental evidence needed |  |
| 027 | Trace after carrier restoration | Trace after carrier restoration | Qualified / limited |  |
| 028 | Reconstruct +299.999s | Reconstruct +299s before interface recreation | Pending / supplemental evidence needed |  |
| 029 | Reconstruct +300.001s | Reconstruct +301s after interface recreation | Pending / supplemental evidence needed |  |
| 030 | Trace after interface recreation | Trace after interface recreation | Qualified / limited |  |
| 031 | Select EVPN all-active at +399.999s | EVPN all-active trace at +399s | Qualified / limited |  |
| 032 | Reconstruct +400.001s and trace EVPN | EVPN trace at +401s after attachment failure | Qualified / limited |  |
| 033 | Inspect EVPN return after attachment down | Inspect EVPN return after attachment down | Qualified / limited |  |
| 034 | Switch topology to VPN at historical failure | Switch topology to VPN at historical failure | Qualified / limited |  |
| 035 | Reconstruct +559.999s | Reconstruct +559s before EVPN attachment restore | Pending / supplemental evidence needed |  |
| 036 | Reconstruct +560.001s and trace restored EVPN | Reconstruct +561s and trace restored EVPN | Observed |  |
| 037 | Switch strict clock policy and reconstruct | Switch strict clock policy and reconstruct | Pending / supplemental evidence needed |  |
| 038 | Return best-effort and trace | Return best-effort and trace | Observed |  |
| 039 | Reconstruct before capture start | Reconstruct before capture start | Pending / supplemental evidence needed |  |
| 040 | Trace before capture start | Trace before capture start | Observed |  |
| 041 | Reconstruct after watermark | Reconstruct after watermark | Pending / supplemental evidence needed |  |
| 042 | Trace after watermark | Trace after watermark | Qualified / limited |  |
| 043 | Invalid absolute timestamp then retain last result | Invalid absolute timestamp then retain last result | Observed |  |
| 044 | Recover valid +610s and trace | Recover valid +610s and trace | Observed |  |
| 045 | Scrub historical slider to start | Scrub historical slider to start | Pending / supplemental evidence needed |  |
| 046 | Scrub slider to end | Scrub slider to end | Pending / supplemental evidence needed |  |
| 047 | Repeated past-present-past reconstruction | Trace P1→P2 at +100s → +241s → +100s | HC-02 | Explicit carrier-linked scenario replaces broad repeat |
| 048 | Inspect direction after repeated reconstruction | Inspect direction after repeated reconstruction | HC-02 |  |
| 049 | Navigate historical node then Back | Open P1 historical node from +100s route | Pending / supplemental evidence needed | Cross-component validity check; Back follows once loaded Initial page loading; settled P1 local carrier evidence is p1-local-interface.txt. |
| 050 | Restore latest and primary trace | Restore latest and primary trace | Observed | P1 local interface was down while direct historical route was complete; saved separate evidence |
| 051 | Open PE-A single-node workspace | Open PE-A single-node workspace | Pending / supplemental evidence needed |  |
| 052 | Open resource explorer | Open resource explorer | Observed |  |
| 053 | Find DTE000000 | Find DTE000000 | Observed |  |
| 054 | Select DTE000000 correlation | Select DTE000000 correlation | Observed |  |
| 055 | Expand ETG relationship branch | Inspect current DTE→ETG17 relationship | Observed | Adapted: graph relation inspector rather than ungrounded tree expansion |
| 056 | Inspect selected resource details | Inspect selected resource details | HC-03 (supplement) |  |
| 057 | Set cursor before DTE creation | Set cursor before DTE creation | Pending / supplemental evidence needed |  Pending; settled precreation repeat at97 closes this check. |
| 058 | Set cursor at DTE creation | Set cursor at DTE creation | Observed |  |
| 059 | Inspect graph after DTE creation | Inspect graph after DTE creation | Observed |  |
| 060 | Set cursor before multihome | Set cursor before multihome | Observed |  |
| 061 | Set cursor after multihome | Set cursor after multihome | Observed |  |
| 062 | Inspect primary and backup edge identities | Inspect primary and backup edge identities | Observed |  |
| 063 | Set cursor before failover | Set cursor before failover | Observed |  |
| 064 | Set cursor after failover | Set cursor after failover | Observed |  |
| 065 | Compare graph and tree after failover | Compare graph and tree after failover | Observed |  |
| 066 | Set cursor before restoration | Set cursor before restoration | Observed |  |
| 067 | Set cursor after restoration | Set cursor after restoration | Observed |  |
| 068 | Compare restored primary and backup | Compare DTE restoration target with resource state | Observed | DTE returns from IP_ROUTING to ETG0 |
| 069 | Set cursor before first churn | Set cursor before first churn | Observed | Exact-cursor UI sequence and settled table: 14538ms |
| 070 | Set cursor after first churn | Set cursor after first churn | Observed | Action completed; observation resumed after 60s multi-action tool limit. No per-action timing claim. |
| 071 | Verify DTE points ETG000017 | Verify DTE points ETG000017 | Observed |  |
| 072 | Set cursor after second churn | Set cursor after second churn | Observed | Exact-cursor UI workflow 9581ms including observation |
| 073 | Verify DTE points IP_ROUTING fallback | Verify DTE points IP_ROUTING fallback | Observed |  |
| 074 | Select failed churn event | Select failed churn event | Pending / supplemental evidence needed |  |
| 075 | Compare no-effects event and resource state | Reveal failed event and compare retained resource state | Observed |  |
| 076 | Move cursor before failure | Move cursor before failure | Observed | Exact-cursor workflow 11641ms |
| 077 | Move cursor after failure | Move cursor after failure | Pending / supplemental evidence needed | Exact-cursor workflow 1935ms Table settled but graph updating; use78 for combined assertion. |
| 078 | Verify failed operation preserves next hop | Verify failed operation preserves next hop | Observed |  |
| 079 | Select primary ETE resource | Select primary ETE resource | Pending / supplemental evidence needed |  |
| 080 | Inspect ETE/ES correlation at failure | Inspect ETE/ES correlation at failure | Observed |  |
| 081 | Select backup ETE resource | Select backup ETE resource | Pending / supplemental evidence needed |  |
| 082 | Inspect backup relationship at failure | Inspect backup relationship at failure | Observed |  |
| 083 | Compare source record and normalized event | Include synthetic CTF sources while exact failed-event search remains active | Qualified / limited |  No retained source counterpart for this UID; stream toggle only. |
| 084 | Reveal event in timeline | Reveal event in timeline | Pending / supplemental evidence needed |  |
| 085 | Jump from timeline to log | Reveal selected failed event through event-log toolbar | Pending / supplemental evidence needed | Adapted from timeline-to-log jump: mark is collapsed at full span; reveal toolbar selected the DTE and event time. |
| 086 | Return log to timeline | Zoom the selected failed-event interval | Observed | Selected +600.74–600.76 s to expose individual event markers. |
| 087 | Change graph perspective at same cursor | Ctrl-click exact failed timeline event back to log | Qualified / limited | Ctrl-click cleared the log search and initially focused the correct event row with navigation-target, aria-selected=false. Later virtualized rows omitted it, so no persistent selection was established. Correct initial target observed; persistent row/focus not established. Inconclusive. |
| 088 | Restore observed perspective | Search and reveal the same failed event again | Pending / supplemental evidence needed | Restored exact UID search after Ctrl-click cleared filters; toolbar reveal works. Persistent log navigation focus not established. |
| 089 | Zoom into churn interval | Switch single-node topology to control-plane perspective | Observed | Automatic reconstruction settled; same +600.750 s cursor. Cross-layer unknown states explicitly labelled. |
| 090 | Expand same resource in a second tree branch | Restore data-bridge topology perspective | Observed | Correlation focus remains DTE0. |
| 091 | Collapse and re-expand relationship branch | Expand DTE0 relationship lane at full span | Observed | Retains full-viewport historical links while selected-time graph remains current. |
| 092 | Search resource while preserving cursor | Search DTE0 while preserving failed-event cursor | Observed | Selected moment +600.750 s and IP_ROUTING correlation preserved. |
| 093 | Clear resource search | Clear resource search before cursor performance control | Observed | No product data changed; removes active resource-query string. |
| 094 | Select another node then return | Select a fresh churn timestamp with empty resource search | Observed | +600.800 s; complete cursor workflow 3420 ms. Adapted node-switch move: PE-A/P1 round trip was covered at49–51. Empty-search workflow control:3420 ms; not an isolated CPU/request measurement. |
| 095 | Change temporal range and verify correlation scope | Select a range spanning failover and restore without changing the cursor | Observed | Correlation remains the instant +600.800 s; historical range should not be unioned into its graph. |
| 096 | Reopen correlation detail after range change | Inspect exact next-hop correlation after range change | Observed | Popup declares DTE0 to IP_ROUTING, consistent with selected instant. |
| 097 | Repeat early-late-early cursor sequence | Repeat precreation → creation → precreation at exact nanosecond boundary | Observed | Settled graph snapshots saved in creation-boundary-repeat.json. Settled absent→ETG0→absent in creation-boundary-repeat.json. |
| 098 | Compare cursor, details and graph after repeat | Inspect absent precreation focus after round trip | Observed | Graph and index both explicitly report no active correlation; settles the earlier pending move57. |
| 099 | Browser reload preserves or consistently resets state | Reload historical single-node workspace | Observed | Reload restored URL member context at latest resolved time and cleared ephemeral range/cursor/focus consistently. |
| 100 | Final historical correlation inspection | Reopen DTE0 at exact failover time after reload | Pending / supplemental evidence needed | Selected +360.0375 s: graph and table reconstruct next_hop to IP_ROUTING; no stale latest ETG17 relation. Initial snapshot pending. Correct IP_ROUTING graph verified in100-settled.txt and100-settled-graph.txt. |
