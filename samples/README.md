# Sample inputs

This directory combines a public decoder fixture with synthetic router-domain
fixtures. No product or customer data is included.

## Included coverage

| Component | Fixture | Purpose |
|---|---|---|
| Public decoder seed | `external/ctf2-smalltrace` | A pinned, tiny valid public CTF 2 trace for decoder work. |
| Parser conformance vector | `demo/fixtures/minimal-status.jsonl` | Exact bytes rendered from the installed demo plug-in's conformance records; not a second hand-written dump. |
| Canonical demo authoring source | `demo/router-state-lab-default.scenario.json` | Ordinary independent-tool save containing private topology intent and explicit historical observations; this is the durable source for future mock dumps. |
| Complete demo input | `demo/fixtures/router-state-lab-demo.tgz` (generated on demand) | One ten-node assembly used by both the fabric and individual-node workspaces. |
| Per-node raw packets | `nodes/<node-id>.tgz` inside the assembly | Four heterogeneous container TGZs with synthetic CTF 2, retained non-CTF logs, and one- or multi-table status text. |
| Per-node normalized state | `normalized-scale/` inside each node pack | 125,000 scalable events plus the node's explicit authored observations, at least 100,000 real state-changing events, and a 7,500-resource baseline plus final authored resources, relationships, and mutations. |
| Plug-in projections | `plugin-projection/` inside each node pack | Immutable demo-owned topology, route, forwarding, packet, evidence, and checksum records generated from the same node model. |
| Checkable behavior registry | `coverage.json` in the outer assembly | Versioned evidence connecting advertised demo behavior to generated records; its current schema is documented in the demo guide. |

## Generate

The source of truth is
`demo/router-state-lab-default.scenario.json`, not the generated TGZ. From the
repository root with Python 3.12, install the independent authoring tool and
validate that save:

```powershell
python -m pip install -e .\state-dump-generator
python -m state_dump_generator validate .\demo\router-state-lab-default.scenario.json
```

For a visual preview, start the standalone studio:

```powershell
python -m state_dump_generator serve --open
```

Click **Open**, choose `demo/router-state-lab-default.scenario.json`, and move
the scenario-time control. Stop the studio with `Ctrl+C`. You can also compile
the save directly into the independent tool's neutral, topology-free output:

```powershell
python -m state_dump_generator generate `
  .\demo\router-state-lab-default.scenario.json `
  --output .\artifacts\router-state-lab-default.node-dumps.tgz
```

That neutral assembly is not the full demo input. After running the
repository's normal demo setup, use the separate demo materializer for the
scalable fixture:

```powershell
python -X utf8 -m generator --write-conformance-fixture demo/fixtures/minimal-status.jsonl
python -X utf8 -m generator --verify-conformance-fixture demo/fixtures/minimal-status.jsonl
python -X utf8 -m generator --output demo/fixtures/router-state-lab-demo.tgz
python -X utf8 -m generator --check-launchable demo/fixtures/router-state-lab-demo.tgz
python -X utf8 -m generator --ensure-launchable demo/fixtures/router-state-lab-demo.tgz
python -X utf8 -m generator --validate demo/fixtures/router-state-lab-demo.tgz --deep-validate
```

The generator belongs to the example plug-in distribution and does not start a
server. After generation, the core-owned application can open the archive
through the installed example plug-in:

```powershell
router-dump-analyzer --plugin demo_router --input demo/fixtures/router-state-lab-demo.tgz --no-browser
```

For a source checkout, the equivalent direct target is
`--plugin-module plugin`; the module loader defaults
to the `plugin` attribute.

The demo generator is deterministic: archive member names, ordering, metadata,
and gzip timestamps are fixed. Its standard-library adapter reads the
canonical save without importing the independent authoring package. It
converts explicit node-local history and attachment evidence into the demo
plug-in's resource model, then adds distinct scalable filler and immutable
projections. Each raw node pack embeds a deterministic synthetic CTF trace, so
generation does not depend on a downloaded fixture.

The first demo command renders the tiny JSONL vector from
`ExampleRouterPlugin`-owned records; the second fails if its checked-in bytes
drift. `--check-launchable` is the fast launcher probe: it verifies the
canonical full-scale node inventory, coverage metadata, current authoring-save
SHA-256 digest, current generator/demo-plug-in materializer fingerprint, and
one bounded, checksum-matching opaque pack per node without decoding those
packs. `--ensure-launchable` reuses or generates that corpus. A save edit or
materialization-code change therefore makes an older TGZ stale. Generation
rechecks both identities immediately before atomic publication. The command
replaces only an exact generator-owned preferred archive; unknown preferred
inputs stay in place while the fixed `.generated.tgz` sibling is selected, and
an unknown recovery sibling fails closed. `--validate` performs the full
nested integrity audit.

Alongside the explicitly authored history, each node's scalable filler is
organized into five ordered event waves:
`single_home_create`, `multihome_add`, `mass_es_withdraw`,
`mass_es_restore`, and `next_hop_churn`. Its plug-in-owned resource schema
includes ETG, primary and backup ETE paths, standalone DTEs, Ethernet Segments,
virtual interfaces, neighbors, and IP routing. Failed updates are retained
without fabricating a state mutation; add-on-existing is represented as a
modification. There is no DTG kind: each DTE independently matches a label or
SID and forwards to an ETG or IP routing.

The canonical authored history is intentionally small enough to inspect. Its
useful relative-time boundaries are `+30 s`, `+210 s`, and `+270 s` for PE-A
route lifecycle; `+90.050 s` through `+240.100 s` for asymmetric P1/P2 failure
and recovery; `+180 s` through `+304 s` for PE-D structural detach/reattach;
`+360 s` for a failed PE-B next-hop change; `+420 s` through `+535 s` for
delayed Ottawa failure and recovery; and `+610 s` for PE-A's final next-hop
change. The
[demo checkpoint table](../demo/README.md#past-time-reconstruction-checkpoints)
lists the expected reconstructed state.

The generator assigns every event and resource to exactly one raw container:
EVPN control, multi-home forwarding, single-home forwarding, or the underlay
agent. It stages and packs one node at a time, then writes the outer assembly
atomically. The normal launch scripts fast-check and reuse this TGZ, generate
or replace it only at a safe generator-owned path, and preserve unknown inputs
while selecting the fixed recovery sibling.

Node packs deliberately contain only node-local status, local logs, and
plug-in-readable attachment evidence. The authoring save's private medium IDs
and any global participant lists are not serialized into final node dumps or
their topology projections; the analyzer must reconstruct connectivity from
matching local claims.

The outer registry and node-local projections are generated together so their
evidence cannot silently drift. Their current projection format, candidate
binding, evidence shapes, and runtime validation rules belong to the
[demo-specific contract](../demo/README.md#generated-mock-dumps), not to this
sample-generation guide.

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
