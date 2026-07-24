# Plug-in author quickstart

Use this guide to build the smallest correct node/device plug-in without
reverse-engineering the server. Copy the working example first; add advanced
capabilities only after its validator and golden test pass.

The complete normative rules remain in `docs/plugin-contract.md`.

## What this guide produces

The example plug-in:

1. is an independently installable Python package;
2. is discoverable through `router_dump_analyzer.plugins`;
3. recognizes one platform from a safe artifact inventory;
4. selects one status file with explicit parser dispatch;
5. converts each line into a typed resource observation with evidence; and
6. passes the generic author validator and its own golden test.

This repository is still a design/conformance demo. The validator proves the
plug-in-facing package and protocol shape; the main review server does not yet
run arbitrary installed plug-ins through a production ingestion coordinator.
Do not work around that by importing a plug-in directly from `demo_app.py`.

## 1. Run the known-good example

From the repository root, using Python 3.12 in the analyzer environment:

```text
python -m pip install -e .
python -m pip install --no-deps -e examples/minimal_plugin
router-dump-plugin-validate --list
router-dump-plugin-validate minimal_router --artifact examples/minimal_plugin/fixtures/minimal-status.jsonl --node-hint router-1 --metadata platform=minimal-router-os --metadata software_version=1
python -m unittest discover -s examples/minimal_plugin/tests -v
```

The validator must end with:

```text
OK: example.minimal-router
```

Do not start a new implementation until these commands work unchanged.

## 2. Copy this package, not the demo server

Use `examples/minimal_plugin/` as the template:

```text
examples/minimal_plugin/
|-- pyproject.toml
|-- README.md
|-- fixtures/
|   `-- minimal-status.jsonl
|-- src/
|   `-- minimal_router_plugin/
|       `-- __init__.py
`-- tests/
    `-- test_minimal_plugin.py
```

Rename the distribution, import package, entry-point name, plug-in ID, platform
ID, parser ID, resource kinds, and fixture vocabulary. Keep the `src/` layout
and the golden test.

The entry point must target a module-level instance:

```toml
[project.entry-points."router_dump_analyzer.plugins"]
my_router = "my_router_plugin:plugin"
```

```python
plugin: AnalyzerPlugin = MyRouterPlugin()
```

Do not target `MyRouterPlugin` or a factory function. Do not load Python code
from a router dump.

## 3. Implement only five things

Subclass `AnalyzerPluginBase`. A first status-only plug-in implements these
members:

### A. Manifest

```python
manifest = PluginManifest(
    plugin_id="example.my-router",
    plugin_version="0.1.0",
    core_api_version=CORE_PLUGIN_API_VERSION,
    supported_platforms=("my-router-os",),
    supported_software_versions=">=1,<2",
    capabilities=frozenset({PluginCapability.STATUS_PARSE}),
    reconstruction_default=ReconstructionSupport.EXACT,
)
```

Use the standard `PluginCapability` enum. A capability is a promise that its
hook is implemented. `AnalyzerPluginBase` raises instead of silently ignoring
a declared-but-missing hook.

The current v1 API has no runtime configuration injection hook. Keep defaults
immutable and packaged with the plug-in; do not read hidden environment
variables. The core records `supported_software_versions`, while `probe()` owns
the actual version interpretation and `exact`/`compatible` decision.

### B. Static schema

`describe()` returns one deterministic `PluginSchema`. It declares every
resource kind, relationship type, source-record type, dashboard, topology
projection, and other semantic type that the plug-in may emit.

For a first plug-in, declare one resource kind and no relationships. The example
declares `INTERFACE`, its typed key field, safe properties, display fields, and
normalized condition field.

Never return HTML, JavaScript, CSS, SQL, remote URLs, or layout coordinates.

### C. Probe

`probe(inventory)` examines only `DumpInventory` metadata and safe
`ArtifactInfo` records. It returns:

- `ProbeReport(result=None)` when no recognizable artifact or signature is
  present;
- a `ProbeResult` with `ProbeMatchKind.NONE` when the artifact is recognizable
  but explicit platform or software-version evidence is incompatible; or
- a `ProbeResult` with confidence, reasons, detected values, and
  `ProbeMatchKind.EXACT` or `COMPATIBLE`.

An empty inventory is normal input and must not raise.

Do not open artifacts, archives, or host paths during probing.

### D. Input selection

`locate_inputs(inventory)` yields `InputSpec` or `PluginDiagnostic`.
Every new input sets `parser_kind`:

| Parser kind | Core calls | Required capability |
|---|---|---|
| `InputParserKind.STATUS` | `parse_status(reader, spec)` | `STATUS_PARSE` |
| `InputParserKind.CTF` | `parse_ctf(spec, messages)` | `CTF_PARSE` |
| `InputParserKind.TEXT_TRACE` | `parse_text_trace(reader, spec)` | `TEXT_TRACE_PARSE` |

`role` and `parser_id` are stable plug-in-owned identifiers. They do not select
the hook. `parser_kind=None` is accepted only for legacy adapters and fails the
default validator.

An input can contain several `artifact_ids`. Use that for a logical CTF tree;
the core performs safe materialization.

### E. Parser

`parse_status()` receives a quota-enforced `ArtifactReader`. Stream the file and
yield typed outputs. Do not read an unbounded file into memory.

The common status output is `SnapshotObservation`:

- `resource`: canonical `ResourceKey`;
- capture interval for this particular record;
- `PropertyPatch` with exact set/remove/unknown semantics;
- plug-in-normalized `condition` and `ConditionClass`;
- `Provenance`, `Quality`, and `Evidence`.

Malformed input yields a stable, namespaced `PluginDiagnostic`; it must not
crash the entire parser.

## 4. Know which hooks are optional

These three hooks are always required:

| Hook | Purpose |
|---|---|
| `describe()` | Declare the immutable semantic schema. |
| `probe()` | Decide whether this platform/release matches. |
| `locate_inputs()` | Select bounded logical inputs and parser dispatch. |

Everything else is capability-gated:

| Capability | Override | Main output |
|---|---|---|
| `STATUS_PARSE` | `parse_status()` | observations, source records, diagnostics |
| `CTF_PARSE` | `parse_ctf()` | domain events, source records, diagnostics |
| `TEXT_TRACE_PARSE` | `parse_text_trace()` | domain events, source records, diagnostics |
| `EVENT_REDUCTION` | `apply()` | atomic `ChangeSet` |
| `EVENT_REVERSION` | `revert()` | inverse/unknown `ChangeSet` |
| `CORRELATION` | `correlate()` | causal links, relationship changes, clock anchors |
| `CONSISTENCY_CHECK` | `check_consistency()` | PASS/FAIL/UNKNOWN findings |
| `TOPOLOGY_PROJECTION` | `project_topology()` | bounded typed topology records |
| `FORWARDING_PROJECTION` | `project_forwarding()` | bounded forwarding IR mutations |

Inherit undeclared hooks from `AnalyzerPluginBase`; they return safe empty
results. Do not copy placeholder implementations into a new plug-in.

## 5. Use keys that cannot alias

The plug-in owns key meaning and ordering. The core owns canonical encoding and
identity.

Use native typed values when their meaning is already unambiguous:

```python
ResourceKey(
    namespace="vendor.router",
    node="node-a",
    layer="forwarding",
    kind="ETE",
    parts=(("etg_id", 41), ("path_id", 2)),
)
```

Use `KeyAtom` when the same representation can mean different things:

```python
KeyAtom("opaque_uint", 41)        # hardware ID, not IPv4
KeyAtom("ipv4", 0xC0000201)       # 192.0.2.1 encoded numerically
KeyAtom("uuid", uuid_bytes)       # exactly 16 bytes
KeyAtom("ipv6", ipv6_bytes)       # exactly 16 bytes
KeyAtom("bytes", opaque_bytes)
```

A native `UUID`, UUID text, UUID bytes, IPv6 bytes, an integer, and a string stay
distinct. Compound child keys are encouraged when identity is scoped by a
parent, such as `(etg_id, path_id)` for an ETE.

Never:

- join key parts into an ambiguous display string;
- use a boolean key part;
- parse another resource's display ID to recover semantics; or
- use a plug-in run ID as resource identity.

Relationships, not key parsing, control grouping and dependency traversal.

## 6. Preserve source records and evidence

Every output should point back to stable evidence such as `line:12`,
`bytes:100+20`, `ctf:stream=2,message=481`, or a JSON pointer.

Parser hooks may yield `SourceRecordEmission` for matched or unmatched input.
The plug-in supplies decoded source semantics and an optional
`matched_event_uid`. It does **not** assign `source_record_uid`; the core turns
the emission into a persisted `SourceRecord` with stable identity.

For trace normalization:

1. derive `DomainEvent.event_uid` with
   `derive_event_uid(plugin_id, parser_id, source_ref, local_discriminator)`;
2. emit a `SourceRecordEmission` for retained input when requested;
3. set its `matched_event_uid` when normalization succeeded; and
4. keep unmatched records rather than inventing domain events.

The helper uses a versioned, length-delimited SHA-256 encoding of the canonical
source identity. Use `local_discriminator` only when one source record produces
several domain events. Its type is significant, so integer `1`, string `"1"`,
and byte `b"1"` remain distinct. Never use Python `hash()`, random UUIDs, the
wall clock, or list position after filtering. Increment `parser_id` when a
release changes how one source record is split into domain events.

## 7. Keep core and plug-in responsibilities separate

Put a decision in the node/device plug-in when it depends on:

- platform, release, layer, or protocol vocabulary;
- resource kind or key-field names;
- UUID/byte/integer interpretation;
- vendor status normalization;
- resource relationships or matching rules;
- route-resolution text;
- topology projection;
- dashboards, table columns, labels, or icons.

Put mechanics in core when they apply identically to every plug-in:

- safe archive inventory and materialization;
- canonical envelopes and key serialization;
- clock fitting and temporal selector resolution;
- interval persistence and pagination;
- budgets, validation, authorization, and generic rendering.

Cross-node matching that interprets normalized claims belongs to a separate
federation/linker plug-in. A node plug-in stops at its local connector claim.

### Forwarding loops and ingress-dependent policy

This is an optional advanced forwarding capability; the minimal example does
not need it. When your device suppresses a candidate according to where the
packet or route entered, do not hide that rule in a display string or an opaque
attribute:

1. Put the proprietary equality identity in `ForwardingPolicyScope`. Its
   `contract_id` and ordered typed arguments belong to your plug-in.
2. Attach a `ForwardingCandidateConstraint` to the affected
   `ForwardingMember`, including the applicable traffic classes and
   `ResolutionContribution` evidence.
3. Tell core whether the ingress-scope set is complete. A known-empty set is
   different from an incomplete capture: an applicable non-match is permitted
   only when `ingress_scopes_complete=True`; otherwise it is unknown.
4. Let core's `evaluate_forwarding_constraint()` produce one
   `ForwardingPolicyDecision`, or use `evaluate_forwarding_policy()` to produce
   a `ForwardingPolicyEvaluation` containing the aggregate verdict and all
   decisions. Core compares complete scopes only; it does not understand EVPN,
   BGP, ESI, EVI, DF, VLAN, or vendor policy.
5. Canonicalize all state needed to distinguish a forwarding visit in
   `ForwardingTraversalStateKey`. Include the forwarding object/domain,
   ingress resource, lookup and packet context, policy scopes,
   `policy_scopes_complete`, member, and perspective. Do not use only a router
   ID.
6. Use `detect_forwarding_cycle()` when you need a
   `ForwardingCycleReport | None`. Use bounded
   `evaluate_forwarding_traversal()` when you need a
   `ForwardingTraversalEvaluation`; its optional `.cycle` carries that report.
   A same-router revisit with changed context is not automatically a loop.

Keep a policy-blocked candidate in output with its explanation. It is an
intentional exclusion, not a failed physical link. Test at least an exact
scope match, a known non-match, an incomplete-scope non-match, a
non-applicable class, an unknown class, an exact recursive or cross-node
cycle, a legitimate changed-state revisit, and a separate hop-limit result.
The executable type cases are in `tests/test_plugin_api.py`; the core helper and
end-to-end route cases are in `tests/test_multi_node_route.py`. The complete
ownership and conformance rules are in the forwarding section of
`docs/plugin-contract.md`.

## 8. Validate after every change

Run:

```text
router-dump-plugin-validate my_router --artifact path/to/representative-status.txt --node-hint router-1 --metadata platform=my-router-os --metadata software_version=1
python -m unittest discover -s path/to/my_plugin/tests -v
```

The generic validator checks:

- entry-point target is an instance;
- manifest API version and required fields;
- deterministic `PluginSchema`;
- required hooks;
- capability-to-hook overrides;
- empty-inventory probe and discovery behavior;
- representative author-fixture probe and input selection when `--artifact`
  and metadata are supplied;
- bounded discovery output; and
- explicit parser dispatch with a matching capability.

It does not open the fixture or execute a parser, so it cannot verify
proprietary semantics. Your golden tests must cover normal, missing, malformed,
truncated, repeated, out-of-order, failed-update, and clock-skewed input wherever
each case applies to the declared capabilities. Record non-applicable cases in
the test plan rather than fabricating meaningless tests. Scale parsers must also
stream 100K+ records within their budget.

Common failures:

| Message | Fix |
|---|---|
| `entry-point target must be ... instance` | Export `plugin = MyPlugin()`. |
| `core_api_version ... does not match` | Build against the installed core API. |
| `requires an override` | Implement the advertised hook or remove the capability. |
| `has no parser_kind` | Set `InputParserKind` on every new `InputSpec`. |
| `does not declare ...` | Add the matching standard capability. |
| `describe() must be deterministic` | Build one immutable schema without clocks, randomness, or input state. |

## Definition of done

A first plug-in is ready for review only when:

- [ ] installation and entry-point discovery work in a clean environment;
- [ ] the generic validator prints `OK`;
- [ ] empty and missing input return a report/diagnostic rather than raising;
- [ ] every selected input has explicit parser dispatch;
- [ ] every emitted type is declared in `PluginSchema`;
- [ ] keys are typed, stable, and collision-safe;
- [ ] status/outcome/effect are not inferred by core or browser code;
- [ ] observations and events carry evidence and honest quality;
- [ ] failed events do not mutate state unless device semantics prove a change;
- [ ] golden tests cover applicable bad-input and temporal edge cases; and
- [ ] no plug-in-specific branch was added to core or the browser.

After this passes, use the relevant advanced sections of
`docs/plugin-contract.md` for reducers, temporal correlation, dashboards,
topology, forwarding, and federation.
