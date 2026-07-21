# Sample inputs

This directory combines a public decoder fixture with synthetic router-domain
fixtures. No product or customer data is included.

## Included coverage

| Component | Fixture | Purpose |
|---|---|---|
| Nested dump discovery | `generated/node-a.tgz` | A node archive containing three layer `.tgz` archives and deliberately nonstandard internal roots. |
| Multi-section status | Status text inside each layer archive | Interfaces, routes, grouped resources, hardware objects, and neighbor tables. |
| CTF 2 decoder | `external/ctf2-smalltrace`, nested `ctf2-smalltrace.tgz`, and `ctf2-router-domain.tgz` | A tiny valid public CTF 2 trace plus a product-shaped synthetic CTF 2 trace with resource/action/properties/result fields. |
| Codec-chain discovery | Nested `codec-chain-marker.zst.gz` | Deterministic gzip containing a valid raw-block Zstandard frame, to verify content-based codec-chain handling without third-party generator dependencies. |
| Domain event parsing | `lltng_domain_export.jsonl` in each layer | Synthetic create/update/state-change events, properties, clock domains, and success/failure results. This stands in for proprietary CTF event payloads. |
| Arbitrary debug logs | `lltng_info.log` / `lltng_error.log` | Line-oriented debug, info, and error records. |
| gRPC payload parsing | `resource_update.proto` and `resource_updates.jsonl` | A synthetic protobuf schema and decoded message examples. |
| Comprehensive protocol scenario | `generated/illustrative/topology.json`, `resources.jsonl`, and plugin-owned kind/relationship/causal-link descriptors | Six-node CE/PE/P topology with IS-IS, SR-MPLS, SRv6 and EVPN; 24 typed resources across 15 plugin-defined kinds. |
| Correlation and reconstruction | `generated/illustrative/{lifecycle,state,relationship}-intervals.jsonl`, mutations, causal links, and coverage | Resource create/modify/delete periods, a shared ingress/egress Forwarding Group, ETG/ETE ownership, standalone DTE next hops, Glue/VIF/hardware associations, and cross-layer failover. |
| Dashboard | `generated/illustrative/dashboard-summary.json` and `dashboard-descriptors.json` | Summary counts plus four plugin-owned modules demonstrating common statistics, tables, default-open/collapsed state, and movable layout. |
| Route calculation | `generated/illustrative/route-resolution*.json` and `route-scenarios.jsonl` | Observed-capture-vector and reconstructed route results plus failover, unresolved, and recursion-cycle acceptance cases. |
| EVPN scale, fan-out, and churn | `generated-scale/*` (on demand) | Deterministic 100K-event/resource scenario with single-home creation, all-active EVPN multi-homing, bulk ES withdrawal/failover, bulk restore, DTE next-hop dependency changes, and a separate 100K-edge fan-out stream. |
| One-file packed demo dump | `generated-scale/router-state-lab-100k.tgz` | One outer TGZ containing four nested container TGZs. Every container has a synthetic CTF 2 stream, a normalized event export, and resource-status text; two containers use one table and two use multiple typed tables. The outer pack also carries the complete scale corpus and browser review projection. |

## Generate

From the repository root with Python 3.12:

```text
python scripts/fetch_babeltrace_sample.py
python scripts/generate_sample_bundle.py
python scripts/generate_scale_fixtures.py --events 100000 --resources 100000
python scripts/generate_packed_scale_bundle.py
```

The generator is deterministic: archive member names, ordering, metadata, and
gzip timestamps are fixed. The downloaded trace is pinned by commit and checked
with SHA-256.

The review-sized scenario has 25 normalized events, 24 resources, 37 status
intervals, and 27 relationship intervals. An ETG always has at least one active
ETE while it exists. One failed ETE programming event returns a non-OK status but
has no state mutation; the subsequent successful retry starts the next accepted
status interval. An `add` callback against an existing ETE is intentionally
classified as a modification. There is no DTG kind: each DTE independently
matches a label or SID, performs a remove/swap action, and forwards to either an
ETG or IP routing.

The scale scenario is organized into five ordered event waves:
`single_home_create`, `multihome_add`, `mass_es_withdraw`,
`mass_es_restore`, and `next_hop_churn`. Its plug-in-owned resource schema
includes ETG, primary and backup ETE paths, standalone DTEs, Ethernet Segments,
virtual interfaces, and IP routing. Start with
`generated-scale/walkthrough.json` for two readable service histories, use
`scenario.json` for exact phase and expected-change counts, then stream the
full JSONL files for scale testing.

The packed generator assigns every scale event and resource to exactly one
container: EVPN control, multi-home forwarding, single-home forwarding, or the
underlay agent. The normal `launch_demo.cmd` path is hard-coded to this outer
TGZ and creates it automatically when it is missing.

## Public CTF source and license

The CTF trace comes from:

`efficios/babeltrace`, `tests/data/ctf-traces/2/succeed/smalltrace`, commit
`e4109f9c87f9e93c73abf32c1ffb43e5eaacc4a5`.

The Babeltrace repository's REUSE declaration licenses `tests/data/*` as
CC0-1.0. The fetch script leaves the source files unchanged.

Useful expanded corpora:

- Passing CTF 2 traces: https://github.com/efficios/babeltrace/tree/stable-2.1/tests/data/ctf-traces/2/succeed
- Negative CTF 2 traces: https://github.com/efficios/babeltrace/tree/stable-2.1/tests/data/ctf-traces/2/fail
- LTTng tutorial for producing your own trace: https://lttng.org/docs/

For proprietary formats, the safest and most useful long-term corpus is a
synthetic generator owned by each platform/version plugin. It should create
normal, partial, corrupt, out-of-order, clock-skewed, and failed-update cases.
