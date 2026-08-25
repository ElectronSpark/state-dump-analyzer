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
5. converts each line into a typed resource observation and a retained source
   record with evidence;
6. supplies a safe, optional plain-text copy projection for that source
   record;
7. runs through the core-owned runtime-v2 ingestion/workspace test independently
   of the large demo's compatibility adapter;
8. projects one bounded revision-level relationship after all snapshot inputs
   have been assembled;
9. implements one bounded revision-consistency rule whose findings are
   materialized durably with the frozen execution plan; and
10. passes the generic author validator and its own golden test.

The validator proves the plug-in-facing package and protocol shape. The core
owns both the web command and the durable headless ingestion command. For an
ordinary parser plug-in, core builds `runtime.v2` from the standard hooks;
authors do not add a path-opening runtime adapter. The optional single-host
control plane can persist uploads and revisions and probe several allowlisted
plug-ins, but this adds no tenant, queue, session, annotation, report, HTTP, or
database hook to the plug-in contract. The demo publishes the same example
through normal entry-point discovery and contains no application entry point.

## 1. Run the known-good example

From the repository root, using Python 3.12 in the analyzer environment:

```text
python -m pip install -e ".[test,web]"
python -m pip install -e demo
router-dump-plugin-validate --list
python -X utf8 -m rsl_demo_generator --verify-conformance-fixture demo/fixtures/minimal-status.jsonl
router-dump-plugin-validate demo_router --artifact demo/fixtures/minimal-status.jsonl --node-hint router-1 --metadata platform=demo-router-os --metadata software_version=1
python -m unittest discover -s demo/tests -v
python -m unittest tests.test_artifact_core tests.test_ingestion tests.test_relationship_projection_materialization tests.test_relationship_projection_ingestion tests.test_consistency_materialization tests.test_consistency_ingestion tests.test_revision_world -v
python -m unittest discover -s state-dump-generator/tests -p "test_runtime_v2_vectors.py" -v
python -X utf8 -m router_dump_analyzer.pipeline_cli --plugin demo_router --state-dir .runtime/plugin-author-state --tenant author-smoke --project example --workspace first-run --input demo/fixtures/minimal-status.jsonl --node-hint router-1 --pretty
```

The first command installs `router-dump-analyzer-core` with the test and web
extras needed by this repository's complete smoke path. The second installs
the single demo distribution so its `demo_router` entry point is discoverable.
Your own device plug-in depends only on the core distribution; it does not
depend on either repository example package.

The installed core also exposes a complete PEP 561 typing surface. Every
`router_dump_analyzer` Python module has a sibling `.pyi`, and the package ships
`py.typed`, so editors and type checkers resolve `AnalyzerPlugin`,
`AnalyzerPluginBase`, the descriptor models, and all optional capability
protocols without a separate stub package. The demo's `rsl_demo_plugin` and
`rsl_demo_generator` packages and the independent `state_dump_generator`
package use the same module-for-module layout.
Generated dataclass constructors retain every runtime parameter, including an
underscore-prefixed storage parameter when it is intentionally callable, and
runtime-sealed contract values are statically final. Exported annotations are
fully declared rather than falling back to `_typeshed.Incomplete`.

Repository contributors verify both stub drift and a strict consumer with:

```text
python -m pip install -e ".[test,web]" -e demo -e state-dump-generator
python scripts/export_type_stubs.py --check
python -m mypy --python-version 3.12 --strict --no-incremental tests/typing/public_api.py state-dump-generator/tests/typing/generator_public_api.py
```

For an intentional exported-signature change, run
`python scripts/export_type_stubs.py`, review the changed `.pyi` files, and
repeat both commands. In an independent plug-in repository, run strict mypy on
the plug-in package after installing `router-dump-analyzer-core`; runtime
validation still comes from `router-dump-plugin-validate` and the conformance
tests below, not from the stubs.

The validator must end with:

```text
OK: demo.example-router
```

Validator diagnostics preserve bounded safe plug-in detail, but core replaces
oversized text, host/traversal paths, unsafe invisible text, and ambiguous
display characters before writing to the terminal or CI log. Do not depend on
private exception text as a machine-readable validator interface. The validator
resolves the installed object's manifest and each relevant hook descriptor only
once per run. An ordinary descriptor failure produces a bounded failed result;
`KeyboardInterrupt`, `SystemExit`, and `GeneratorExit` remain process controls
and are not converted into validation errors. The same process-control rule
applies to core capability execution, registry probing, and trusted inline
ingestion. Any other throwable is contained by a bounded core boundary; public
errors never depend on the plug-in exception's text. Treat structured
`PluginDiagnostic` records as the only supported way to publish useful failure
detail.

The default `router-dump-analyzer` host enters the core application lifespan
before Uvicorn starts logging. Runtime open and context-entry failures therefore
exit with status 1 and one bounded `router-dump-analyzer: error: ...` line. In
`--api-only` mode, ordinary input discovery/parsing and default indexing also
run at that fail-fast startup boundary. With the reusable frontend enabled,
runtime-v2 parsing is intentionally deferred to the first workspace request so
both browser views can show progress; a failure becomes a bounded API error and
the shared indicator enters `failed`. No mode prints a traceback or host path,
and the three process-control exceptions still propagate unchanged.

Durable executable identity fingerprints every ordinary package file. Only an
actual VCS/cache **directory** named `.git`, `.hg`, `.svn`, `__pycache__`,
`.mypy_cache`, `.pytest_cache`, or `.ruff_cache` is pruned. A regular file or
contained alias with one of those names still participates in identity; an
escaping alias fails closed.

On durable publication the core also creates an immutable execution plan for
the revision. A plug-in author does not construct or persist this plan. Keep
`describe()`, the normalized schema, capability declarations, and output
deterministic; the deployment registration supplies the exact distribution,
entry-point/module, configuration digest, and optional decoder identity. The
public plan stores only a configuration digest, never configuration values.
Changing any pinned executable, configuration, schema, capability, or decoder
identity changes the plan digest. Current ordinary ingestion produces one pin
with the core role `primary_parser`. A deployment may add separately configured
capability-provider pins through a content-addressed
`PluginCompositionPolicy`. A rule matches the exact primary instance and
registered execution identity, then lists canonically ordered auxiliary
instance identities and roles. The core freezes that policy digest with the
import and as the v4 plan's `composition_policy_digest`, then rejects worker
or child-plan drift. Therefore any policy edit changes the plan, normalized
dataset, catalog revision, session member, and private-analysis revision
identity even when this primary parser selects the same rule. Plan v4 also
records the weakest whole-plan `PluginExecutionPlanAuthority` in
`execution_plan_authority`: `process`,
`trusted_inline_attested`, or `trusted_inline_manifest`. Each PROCESS pin also
commits to its exact inert child bootstrap so target substitution is rejected
before import; trusted-inline pins carry no subprocess-bootstrap commitment.
Retained plan-v3 rows preserve their authority and remain executable. Plan-v2 rows
remain executable and decode that formerly absent field as
`legacy_unrecorded`; retained plan-v1 rows remain displayable but cannot route
capabilities or produce private evidence. The core's `PlanBoundCapabilityRouter`
resolves the resulting plan; never emulate composition with a synthetic
composite plug-in, infer a provider from names, or depend on registration
order. Immediately before an auxiliary pin is frozen, core revalidates that
provider's executable bytes and manifest in both inline and process execution;
registration-time validation alone is not execution authority. Because a
process child may parse for a long time, the parent repeats those live checks
around identity/schema reads and at the final child-plan acceptance edge.
Auxiliary drift after spawn fails the import before revision staging.
The trusted composition root packages that policy with its exact
`PluginRegistry` and `CapabilityProviderRegistry` in one frozen
`PluginCompositionDeployment`. Load it with the mutually exclusive
`--plugin-deployment-module PACKAGE:ATTRIBUTE` selector. Its factory receives
only `PluginCompositionDeploymentContext.state_dir`; platform names, firmware
rules, chip identities, credentials, and configuration values remain in the
deployment module rather than core or the durable plan.
Create every primary and auxiliary registration before constructing the
deployment. Construction takes sealed exact snapshots of both registries, so a
later change to your caller-owned containers neither changes the deployment
digest nor adds execution authority.

The descriptor remains PROCESS-only unless its trusted source explicitly opts
in at construction:

```python
from router_dump_analyzer import PluginCompositionDeployment

return PluginCompositionDeployment(
    primary_registry,
    capability_providers,
    composition_policy,
    allow_inline_only=True,
)
```

Use this only for a trusted single-host deployment. It admits registry-created
`inline_only` registrations, including a registry's explicit manifest-identity
fallback. The deployment-v2 digest commits to the flag. Its derived
`requires_inline_execution` examines every primary and provider record, not
only the provider selected by today's policy; an unused historical provider can
therefore force the complete primary pipeline inline. The four core composition
roots forward this policy, and neither an HTTP request nor uploaded data can
enable it.

That flag spelling applies to the standalone server, headless ingester, and
private-analysis CLI. The interactive analyzer has two separate authorities:
its required `--plugin` or `--plugin-module` selects the immediate startup
input, while its optional embedded durable control plane uses
`--plugin-composition-deployment-module` and requires
`--control-plane-dir`. A runnable source-tree command is:

```text
python -m router_dump_analyzer \
  --plugin-module rsl_demo_plugin \
  --input demo/fixtures/minimal-status.jsonl \
  --control-plane-dir .runtime/plugin-author-embedded \
  --plugin-composition-deployment-module rsl_demo_plugin.deployment:build_plugin_deployment \
  --no-browser
```

The immediate runtime selector is not inferred from the deployment descriptor,
and the descriptor is not inferred from the immediate runtime plug-in.

Private-model evidence follows the same plan boundary. Generic normalized
records are attributed to the exact `primary_parser` role; optional evidence
names one declared capability. The supported plug-in contract supplies no
model client, runner selector, disclosure authority, or prompt assembly
interface. Plug-in code remains trusted and unsandboxed; authors must not use
ambient host privileges to add a model/network side channel. If full-fidelity
local analysis is enabled by deployment and workspace policy, retained
`SourceRecordEmission.copy_text` and plug-in-owned normalized values may enter
the core's immutable evidence corpus, so keep them bounded, deterministic, and
truthful. Plug-ins do not assign the core-owned evidence class per item. Keep
material that must never reach an assistant out of `copy_text` and other
full-fidelity normalized values, and mark sensitive client-view fields through
the declared descriptor policy. A deployment must not authorize full-fidelity
analysis for a data set whose retained plug-in values are unsafe to disclose;
the core rejects a corpus classified `never_assistant` entirely.

Installed entry points are pinned with their real distribution and
`module:attribute` coordinates. Direct `--plugin-module` use is deliberately
identified by the `direct-module` / `0` sentinel instead of claiming an
installed distribution. A registered decoder is recorded only when parsing
actually invokes it.

The generator verification proves that the tiny JSONL vector exactly matches
the plug-in-owned `CONFORMANCE_STATUS_RECORDS`; it is not a second hand-written
mock dump. The two core tests execute safe artifact access and the standard
hooks through the core-owned ingestion coordinator, including a `/v1/workspace`
request for a parse-only plug-in. The standalone vector test checks the
generator-independent temporal/identity expectations. The final command admits
that same vector through the durable core queue, publishes one immutable
catalog revision, and emits a bounded JSON result. Its
`.runtime/plugin-author-state` directory is disposable local smoke state. Do not start
a new implementation until these commands work unchanged.

The browser bootstrap is core-owned. A node plug-in supplies normalized
identity, descriptors, counts, time bounds, and capabilities; it does not
build the `/v1/workspace` envelope or ship page templates.

The executable v1 `TopologyProjectionDescriptor` declares topology semantics
and supported status perspectives, but it does not contain browser-profile
fields. Today the coordinator or assembly profile adapter publishes
`presentation_roles` and optional safe `empty_action_label` text around a
selected plug-in projection. Use the exact `vpn` role only for a profile
genuinely intended for the VPN view; the browser will not guess from EVPN,
VRF, protocol, or projection names. Adding those fields directly to a device
plug-in requires a versioned protocol addition, not an extra attribute or
executable frontend code.

If an optional topology projection emits normalized assembly claims, validate
the few fields on which the generic core is allowed to act instead of branching
on your own raw strings:

```python
from router_dump_analyzer import (
    InterNodeLinkPresentation,
    InterNodeRouteTraceRole,
    TopologyDomainRole,
    TopologyPluginSemanticsDescriptor,
)

semantics = TopologyPluginSemanticsDescriptor(
    role=raw_role,
    coverage_complete=projection_is_complete,
)
external = semantics.external_classification
normalized_role = (
    TopologyDomainRole.EXTERNAL.value
    if external is not None
    else str(semantics.role)
)

presentation = InterNodeLinkPresentation(
    route_trace=InterNodeRouteTraceRole.OVERLAY,
)
normalized_presentation = {
    "route_trace": presentation.route_trace.value,
}
```

`role` remains bounded plug-in vocabulary; only `external` with an exact
`coverage_complete=True` has generic core meaning. An inter-node claim may emit
`include` or `overlay`. It must never emit `conflict`, which is a core-produced
response when two valid claims disagree. Keep the entire semantics and
presentation envelopes JSON-safe and bounded; unsupported objects, binary
values, non-finite numbers, cycles, and oversized values fail closed. The
generated example applies the domain-role portion in
`demo/rsl_demo_plugin/topology_contract.py`; the include/overlay and
response-only conflict cases are executable in
`tests/test_multi_node_topology.py`.

To run the generated example through the core-owned server after an assembly
has been generated, use either discovery mode:

```text
python -m pip install -e ".[web]"
router-dump-analyzer --plugin demo_router --input demo/fixtures/router-state-lab-demo.tgz --no-browser
python -m router_dump_analyzer --plugin-module rsl_demo_plugin --input demo/fixtures/router-state-lab-demo.tgz --no-browser
```

Both launch forms leave `/openapi.json`, `/docs`, and `/redoc` absent by
default. For local API exploration, add `--expose-api-docs` on a loopback
listener. Core rejects that option for every non-loopback bind, including
`0.0.0.0` and `::`.

`--plugin` selects an installed entry-point name.
`--plugin-module PACKAGE[:ATTRIBUTE]` imports a module-level instance directly;
`ATTRIBUTE` defaults to `plugin`. The repository launch scripts generate the
large assembly when it is absent.

## 2. Copy the teaching slice, not the fixture runtime

The runnable teaching slice is kept beside the real demo so there is only one
example implementation:
`demo/rsl_demo_plugin/__init__.py`.

```text
demo/
|-- pyproject.toml
|-- fixtures/
|   `-- minimal-status.jsonl
|-- rsl_demo_plugin/
|   `-- __init__.py
|-- rsl_demo_generator/
|   `-- __init__.py
`-- tests/
    `-- test_plugin.py
```

Copy the parser/schema/relationship-projection/revision-consistency portion of
`rsl_demo_plugin/__init__.py`, its
`CONFORMANCE_STATUS_RECORDS` plus renderer, its golden test, and the entry-point
declaration into a new independently installable `src/`-layout distribution.
Rename the distribution, import package, entry-point name, plug-in ID, platform
ID, parser ID, resource kinds, and fixture vocabulary. Do not copy the demo
runtime adapter, scenario builders, `ExampleRouterGeneratedProjectionPolicy`,
generated-corpus policies, or fixture generator.

`ExampleRouterPlugin.generated_projection_policy` is a demo-only offline
fixture facade. The comprehensive generator, archive validator, and runtime
loader all validate that one installed policy, and stored projection manifests
truthfully record `parser_replayed: false`. It is not a standard
`AnalyzerPlugin` hook and a normal device parser does not need it.

Copy none of the offline materializer into a normal live parser. If you are
deliberately building an independently versioned precomputed-projection
workflow, treat it as a separate application contract with equivalent
validation; the bundled implementation's current format and evidence rules live
in the [demo guide](../demo/README.md#generated-mock-dumps).

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

## 3. Implement the parser and revision analysis

Subclass `AnalyzerPluginBase`. The teaching plug-in implements one status
parser, one bounded revision relationship projector, and one bounded
consistency rule through these members:

### A. Manifest

```python
manifest = PluginManifest(
    plugin_id="example.my-router",
    plugin_version="0.1.0",
    core_api_version=CORE_PLUGIN_API_VERSION,
    supported_platforms=("my-router-os",),
    supported_software_versions=">=1,<2",
    capabilities=frozenset(
        {
            PluginCapability.STATUS_PARSE,
            PluginCapability.RELATIONSHIP_PROJECTION,
            PluginCapability.CONSISTENCY_CHECK,
        }
    ),
    reconstruction_default=ReconstructionSupport.EXACT,
    timeline_time_basis=TimelineTimeBasis.ABSOLUTE_UNIX_NS,
)
```

Import `TimelineTimeBasis` beside the other `plugin_api` values. The example's
`captured_at_ns` values are Unix nanoseconds, so it declares
`ABSOLUTE_UNIX_NS` explicitly. Use the default
`REVISION_START_RELATIVE_NS` only when normalized timestamps are signed offsets
from the revision start. Use `SOURCE_CLOCK_NS` for another producer clock and
also set one path-safe opaque `timeline_clock_domain` such as
`vendor.clock.asic-0`. Do not label uptime, monotonic, device-local, or
revision-relative counters as Unix time. Emit relative offsets exactly once:
core preserves those coordinates, and treats `timeline_start_ns` only as the
lower bound rather than subtracting it as another origin. Core includes
timestamp uncertainty in published bounds and rejects negative absolute
coordinates or a relative span larger than signed 64-bit nanoseconds. Changing
the declaration changes the frozen execution identity, plan, and revision
identity.

Use the standard `PluginCapability` enum. A capability is a promise that its
hook is implemented. `AnalyzerPluginBase` raises instead of silently ignoring
a declared-but-missing hook.

The normal parsing API has no arbitrary runtime-configuration injection hook.
Keep parser defaults immutable and packaged with the plug-in; do not read
hidden environment variables. In the normal `runtime.v2` path, core receives
the selected host path and never passes it to the plug-in. The core records
`supported_software_versions`, while `probe()` owns the actual version
interpretation and `exact`/`compatible` decision.

### B. Static schema

`describe()` returns one deterministic `PluginSchema`. It declares every
resource kind, relationship type, source-record type, dashboard, topology
projection, and other semantic type that the plug-in may emit.

For a first plug-in, declare one resource kind and only the relationship types
that its parser or projector can actually emit. The example declares
`INTERFACE`, its typed key field, safe properties, display fields, normalized
condition field, and one generic
`RelationshipTypeDescriptor(relation_type="corresponds_to", ...)`. It also
declares one source-record group and one
`SourceRecordTypeDescriptor(source_type="status-json")`; every emitted source
type must appear in this static schema.

```python
relationship_types=(
    RelationshipTypeDescriptor(
        relation_type="corresponds_to",
        label="Corresponds to",
        directed=False,
        structural=False,
    ),
)
```

Every browser-visible state/key field must have a `PropertyDescriptor`.
Undeclared fields are server-side only and are removed from resource
projections and search text. Set `client_visible=False` for a declared property
that reducers or server-side analysis need but the browser must not receive;
set `sensitive=True` for secret material. Either setting also prevents that
property from becoming a search oracle or a public `condition_field` value.
`client_visible` defaults to `True` for compatibility, so the declaration
itself is the allowlist.

A dotted descriptor name such as `credentials.token` removes that relative
path anywhere inside a plug-in property payload, including objects nested in
lists. It also removes a literal key named `credentials.token`. Property rules
are deliberately scoped to plug-in-owned containers such as `state`, `key`,
`properties`, `attributes`, `before`, `after`, and `result`; they never delete
a same-named core field such as an event's `action`, a resource's
`resource_id`, or the workspace `revision_id`. Do not try to hide a core
envelope field by declaring a colliding property name. Conversely, names inside
those opaque containers are not interpreted from their spelling: a plug-in key
ending in `_ns` keeps its bounded JSON value and type in correlation reports.
At the final AI-facing report boundary, core renders Unicode `Cc`, `Cn`, `Cs`,
`Zl`, and `Zp` characters, every `Cf` character except U+200C ZWNJ and U+200D
ZWJ, every `Zs` separator except ordinary ASCII space, and the assigned
invisible or blank characters U+115F, U+1160, U+17B4, U+17B5, U+2800, U+3164,
U+FFA0, U+13441, and U+13442 in every string and object key as visible `\\uNNNN` or
supplementary `\\UNNNNNNNN` text. This applies
recursively to opaque plug-in metadata and covers the complete Unicode TAG
block. Existing backslashes are doubled before conversion, so a literal
`\uNNNN`/`\UNNNNNNNN` value or object key never collapses onto the escaped
form of an actual unsafe character. U+16FE4 KHITAN SMALL SCRIPT FILLER retains its legitimate cluster-layout
semantics inside visibly anchored text. Combining grapheme joiner,
unregistered or misplaced variation selectors, U+FFFC OBJECT REPLACEMENT
CHARACTER, and private-use (`Co`) text remain valid in bounded source display
labels, but the report renders those characters as visible escapes while
preserving surrounding text. U+FE0E/U+FE0F remain raw only when paired with
the immediately preceding base in Unicode's registered emoji-variation table;
standalone/repeated selectors escape and every selector remains invalid in
identities. Do not depend on private-use or invisible formatting as the sole
semantic identity.
Do not emit `provenance_class`: core assigns the closed report-only
`CorrelationReportProvenanceClass` after separating plug-in facts, human
assertions, and core corroboration. Your normalized facts still use the
plug-in contract's `Provenance` enum.

Keep public metadata typed. `evidence`, `provenance`, `unknown_fields`, and
`incarnation` are bounded normalized envelopes, not extension dictionaries.
Put device-specific values in declared properties. The core publishes only
the normalized metadata fields and scalar shapes it knows, and drops
unrecognized metadata children. An incarnation is a string or integer, never
an object or Boolean.

For event payload redaction, identify resources explicitly. Use an event-level
`resource_kind`, typed `subjects`/`effects`, and canonical IDs in
`affected_resources`. The core resolves those IDs against the immutable
resource catalog and applies every involved kind's policy. The generic event
`kind` is the event classification and is never treated as a resource kind.
An unresolved affected ID makes publication use the conservative union of
sensitive fields. If a private property is also the descriptor's
`condition_field`, public resource, interval, effect, and top-level event
condition/status values become `unknown`.
Nested `subject`, `affected_resources`, `effects`, and
`relationship_effects` records are core-owned typed envelopes. Unknown
children are dropped; put device-specific values under a declared property
payload such as `properties`, `after`, or `result`.

Never return HTML, JavaScript, CSS, SQL, remote URLs, or layout coordinates.
The core owns the generic browser pages, widgets, interaction logic, and
accessible rendering. Plug-ins contribute declarative domain presentation
only: labels, icons, tags, table/dashboard descriptors, topology projections,
and route or packet explanation text.

### C. Probe

`probe(inventory)` examines only `DumpInventory` metadata and safe
`ArtifactInfo` records. It returns:

- `ProbeReport(result=None)` when no recognizable artifact or signature is
  present;
- a `ProbeResult` with `ProbeMatchKind.NONE` when the artifact is recognizable
  but explicit platform or software-version evidence is incompatible; or
- a `ProbeResult` with confidence, reasons, detected values, and
  `ProbeMatchKind.EXACT` or `COMPATIBLE`.

`ProbeResult` validates itself at construction, and the core's shared
`validate_probe_report()` contract revalidates the complete report during
author validation, durable selection, and direct ingestion. Confidence must be
finite from `0` through `1`; provide 1 to 128 non-empty reasons of at most
1,024 characters each. Optional detected platform and software-version strings
are non-empty and at most 256 characters. Probe diagnostics use the same
`validate_plugin_diagnostic()` field and evidence bounds as parser and optional
capability diagnostics; they must have plug-in origin and probe stage. NUL is
rejected everywhere. The durable selector also inventories with the exact
`ArtifactLimits` configured on the registered ingestion coordinator, so a
candidate cannot pass selection under looser artifact quotas and then fail
every ingestion attempt. Do not rely on a value passing probing but failing
later ingestion.

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

The inventory contains portable logical names and opaque artifact UUIDs, not
the original host path. Parser hooks receive the core `ArtifactReader` and may
open a fresh read-only binary stream, request one session-private file, or
request one session-private logical tree for the selected IDs. Those private
materializations are not the original file, are invalid after the ingestion
session closes, and must never be retained as application paths.

The current reader accepts one regular file, directory, top-level tar, or
top-level ZIP. It streams selected members and never calls `extractall()`;
recursive nested-codec peeling is future work. Plug-in code is trusted and is
**not** sandboxed. Durable control-plane probe and ingestion do run in
killable, deadline-bounded child processes, but those children retain the host
user's filesystem, network, environment, and OS privileges. Never load code
from the dump, and do not mistake bounded artifact/output validation or this
fault boundary for a hardened production sandbox.

### E. Parser

`parse_status()` receives a quota-enforced `ArtifactReader`. Stream the file and
yield typed outputs. Do not read an unbounded file into memory.

The example yields two records for each accepted line. The first is a
`SourceRecordEmission` that preserves the decoded input and evidence; the
second is the typed `SnapshotObservation` that changes resource state.

The state observation contains:

- `resource`: canonical `ResourceKey`;
- capture interval for this particular record;
- `PropertyPatch` with exact set/remove/unknown semantics;
- plug-in-normalized `condition` and `ConditionClass`;
- `Provenance`, `Quality`, and `Evidence`.

The source emission uses a short bounded `message` for generic hover surfaces
and may use `copy_text` for an already-safe verbatim export. Malformed input
yields a stable, namespaced `PluginDiagnostic`; it must not crash the entire
parser.

Core validates every discovery and parser output before normalization. It
requires exact dataclass/enumeration shapes, declared resource/property/
relationship/source types, evidence that refers only to the selected input,
ordered integer time bounds, and real booleans where a boolean is required.
Unsupported values, cycles, non-finite floats, oversized integers, strings,
bytes, containers, nesting, discovery results, or parser streams fail closed;
core never stringifies or truncates an invalid semantic value.

Each discovery or parser `yield` transfers ownership of that value to core
immediately. Core takes a bounded, typed deep snapshot and revalidates the
snapshot before it advances or closes the iterator. Mutating a yielded
dataclass, mapping, sequence, or nested value afterward cannot change the
published revision. Plug-ins must still treat yielded values as immutable and
must not rely on object identity being retained.

Those checks share one ingestion-wide budget rather than resetting for each
yield. The default aggregate ceilings are 2,000,000 outputs, 100,000
diagnostics, 4,000,000 each of evidence items, event subjects, and event links,
64,000,000 normalized value units, and 256 MiB of UTF-8 text. Decoder output
has its own 2,000,000-item ceiling. A single output is also limited to 4,096
evidence items, subjects, or event links, in addition to the smaller
per-value depth/container/atom limits. Treat these as hard ceilings, not batch
size targets; stream much smaller batches in production.

The current coordinator validates and retains
`RelationshipCollectionObservation` completeness markers as private normalized
ingestion metadata. It does not yet materialize those markers into public
relationship intervals or completeness query semantics. Emit honest scoped
markers now, but do not write a test that assumes the current runtime-v2
workspace has already applied their absence inference.

### F. Revision relationship projection

Use `project_relationships(world)` when a relationship can be derived only
after all independently parsed snapshot sources have been assembled into one
revision. This is different from `parse_status()`, whose view is one selected
`InputSpec`, and from event-window `correlate()`. The hook reads an immutable,
bounded base `ReadOnlyWorld` and yields `RelationshipDeclaration` values:

```python
def project_relationships(self, world: ReadOnlyWorld):
    scan_limit = 10_000
    interfaces = tuple(
        world.iter_states(
            kinds=frozenset({"INTERFACE"}),
            limit=scan_limit + 1,
        )
    )
    if len(interfaces) > scan_limit:
        return  # never claim completeness from a bounded prefix
    by_name = {}
    for state in interfaces:
        name = state.properties.get("name")
        if state.exists is True and type(name) is str and name and state.evidence:
            by_name.setdefault(name, []).append(state)

    for name in sorted(by_name):
        matches = sorted(
            by_name[name],
            key=lambda state: (
                state.resource.node,
                state.resource.layer,
                repr(state.resource.parts),
            ),
        )
        if len(matches) != 2 or matches[0].resource == matches[1].resource:
            continue
        left, right = matches
        yield RelationshipDeclaration(
            source=left.resource,
            target=right.resource,
            relation_type="corresponds_to",
            attributes=PropertyPatch(
                set_values={"match_basis": "shared-interface-name"},
                remove_fields=(),
                complete=True,
            ),
            evidence=(left.evidence[0], right.evidence[0]),
            provenance=Provenance.CORRELATED,
            quality=Quality.EXACT,
            perspective_ref=world.perspective_ref,
        )
```

Import `RelationshipDeclaration` and declare `corresponds_to` with a
`RelationshipTypeDescriptor`. A declaration asserts presence only for the
exact revision basis; it has no timestamp, `present` flag, producer, or basis
field. Core attaches the authoritative basis digest and exact plan-bound
provider. Attributes must be a complete `PropertyPatch` with no removals.
Both endpoints must already exist in the base world, the relation type and
optional perspective must belong to the primary revision schema, and all
evidence must belong to the admitted revision inventory. The hook never merges
the two resource identities. Durable/admin records retain the complete
attributes, while browser and public HTTP projections apply the declared
resource-kind sensitivity rules to those plug-in-owned attributes.

Every selected projector sees the same base world, never another projector's
same-phase output. Core collapses identical emissions while retaining their
provider/evidence contributions. Different semantic claims for the same edge
remain separate and produce one conservative ambiguous edge containing only
common attributes. Per-provider executor limits and revision-wide provider,
declaration, diagnostic, evidence, world-read, resource, and byte limits all
apply.

The primary parser participates automatically when it declares
`RELATIONSHIP_PROJECTION`. An auxiliary projector must be explicitly composed
with `REVISION_RELATIONSHIP_PROJECTION_ROLE`; capability declaration alone does
not schedule it. Auxiliary declarations still use the primary revision's
resource kinds, relationship types, and perspectives. An auxiliary may have a
different schema for its own direct calls; the durable coordinator alone binds
its scheduled call to the primary schema. Do not call the private coordinator
helper or add a schema argument to `project_relationships()`.

A recoverable diagnostic yielded by this hook must use
`DiagnosticStage.RELATIONSHIP_PROJECTION`. Core attaches the selected provider
identity and persists it separately from declarations. A fatal diagnostic, a
diagnostic for another stage, or malformed output aborts publication rather
than publishing a prefix.

Local perspective references in parser observations and projected
declarations are qualified by core with the primary plug-in instance and
schema digest. The perspective is part of edge identity: the same endpoints
and relation type in two perspectives are two independent edges, not a
conflict. If an explicit parser observation and a projected edge address the
same fully qualified edge, the explicit observation remains authoritative in
the augmented world.

This hook sees folded `ResourceStateView` values. If two raw observations use
the same `ResourceKey`, the revision world merges them before projection and
retains only the final ordered observation's state evidence. Use distinct
resource identities when the comparison must survive that fold; raw
observation/source access is not part of this hook.

### G. Revision consistency rule

The runnable example also implements `check_consistency(world)`. Keep this
rule device-specific: the plug-in interprets `oper_status`, while core supplies
an immutable final-revision `ReadOnlyWorld` and owns execution, quotas,
provenance, storage, and HTTP projection. Return each `ConsistencyFinding`
with `basis=world.basis`; do not manufacture a timestamp or replace a capture
vector with the dataset's latest event time.

```python
def check_consistency(self, world: ReadOnlyWorld):
    scan_limit = 10_000
    scanned = tuple(
        world.iter_states(
            kinds=frozenset({"INTERFACE"}),
            limit=scan_limit + 1,  # one completeness sentinel
        )
    )
    truncated = len(scanned) > scan_limit
    states = scanned[:scan_limit]
    failing = tuple(
        state for state in states
        if state.properties.get("oper_status") != "up"
    )
    if failing:
        result = FindingResult.FAIL
        severity = DiagnosticSeverity.ERROR
        summary = f"At least {len(failing)} interface(s) are not up."
    elif truncated or not states:
        result = FindingResult.UNKNOWN
        severity = DiagnosticSeverity.WARNING
        summary = (
            "The bounded scan was incomplete."
            if truncated
            else "No interface state was available."
        )
    else:
        result = FindingResult.PASS
        severity = DiagnosticSeverity.INFO
        summary = "All observed interfaces are operationally up."
    yield ConsistencyFinding(
        rule_id="example.interface-operational-status",
        severity=severity,
        result=result,
        summary=summary,
        resources=tuple(state.resource for state in failing[:32]),
        provenance=Provenance.RECONSTRUCTED,
        quality=Quality.EXACT if failing or (states and not truncated) else Quality.UNKNOWN,
        basis=world.basis,
        evidence=tuple(
            evidence
            for state in failing[:32]
            for evidence in state.evidence[:1]
        ),
        details={
            "interface_count": len(states),
            "scan_limit": scan_limit,
            "scan_truncated": truncated,
        },
    )
```

Import `ConsistencyFinding`, `DiagnosticSeverity`, `FindingResult`,
`Provenance`, `Quality`, and `ReadOnlyWorld` from
`router_dump_analyzer.plugin_api`. The complete example
also returns `UNKNOWN` when no interface state exists or the sentinel proves
that the bounded scan was truncated. Never infer PASS from an unverified
prefix. Evidence must belong to this revision's admitted artifact
inventory, and every referenced resource must use the declared schema. Exact
evidence locators are retained in the durable/admin record for trusted offline
review. Public browser and HTTP projections deliberately omit `locator`; only
the plug-in-owned `details` mapping uses descriptor-sensitive property
redaction, while core basis/evidence fields use closed field-and-domain
allowlists.

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
| `RELATIONSHIP_PROJECTION` | `project_relationships()` | revision-scoped relationship declarations |
| `CONSISTENCY_CHECK` | `check_consistency()` | PASS/FAIL/UNKNOWN findings |
| `TOPOLOGY_PROJECTION` | `project_topology()` | bounded topology records, local connector claims, diagnostics |
| `FORWARDING_PROJECTION` | `project_forwarding()` | bounded forwarding IR mutations |
| `FORWARDING_TRACE` | `resolve_forwarding_step()` | one bounded node-local packet transition |
| `EVIDENCE_ANALYSIS` | `analyze_evidence()` | citation-scoped advisory observations over already-authorized evidence |

Inherit undeclared hooks from `AnalyzerPluginBase`; they return safe empty
results. Do not copy placeholder implementations into a new plug-in.

Core callers must not invoke these optional hooks directly. The root package
exports `PluginCapabilityExecutor`, the executable boundary used by host code
and by a plug-in's golden tests:

```python
from router_dump_analyzer import PluginCapabilityExecutor

executor = PluginCapabilityExecutor(plugin)
changes = executor.apply(event, world)
correlation = executor.correlate(reader, window)
projection = executor.project_relationships(world)
```

The executor checks the manifest before calling a hook, gives world-reading
hooks a core-bounded read-only view, closes bounded output iterators, and
validates exact request/result shapes and every schema reference. `apply()` and
`revert()` return a validated `ChangeSet`; the other optional calls return
typed execution envelopes containing validated values and recoverable
diagnostics. A missing capability raises
`PluginCapabilityUnavailableError`, an invalid caller request raises
`PluginCapabilityInputError`, malformed or over-budget plug-in output raises
`PluginCapabilityOutputError`, and any non-recoverable diagnostic raises
`PluginCapabilityExecutionError` with the diagnostics retained. Correlation is
the one exception to the world wrapper: the caller supplies the already
bounded/indexed `CorrelationReader`, and the executor validates its exact
bounded `CorrelationWindow` and outputs.

The durable ingestion pipeline additionally schedules two optional hooks. It
freezes the execution plan, builds the immutable base revision world, executes
all selected `RELATIONSHIP_PROJECTION` providers against that same world,
augments the world with the conservatively resolved edges, and only then runs
selected `CONSISTENCY_CHECK` providers. It stores both stages before canonical
dataset bytes are hashed and published. The primary parser participates in
each stage when it declares that capability. An auxiliary participates only
when its exact plan pin carries the corresponding root-exported
`REVISION_RELATIONSHIP_PROJECTION_ROLE` or `REVISION_CONSISTENCY_ROLE`; merely
declaring a capability is not enough. Malformed output, a foreign endpoint or
evidence item, stale provider, schema/basis mismatch, quota failure, timeout,
or fatal diagnostic aborts publication rather than producing a partial
revision. A newly published stage without a selected provider stores
`not_applicable`. Legacy consistency revisions are projected as
`not_materialized`; a legacy revision predating relationship projection has no
relationship-projection envelope and is never executed during a read.
Capture ranges, per-node resolutions, nested evidence, and aggregate basis
evidence are bounded before core traverses or snapshots them.

`analyze_evidence()` is also deliberately narrower than a world-reading hook.
It receives an immutable `EvidenceAnalysisRequest` containing only evidence
facts that core has already authorized and disclosed for this private-analysis
request. Each fact carries the immutable reference digest, exact node/revision,
schema/provenance/time metadata, and a deeply detached bounded JSON payload.
Return canonically ordered `EvidenceAnalysisObservation` values; every
observation must cite one or more input reference digests and cannot cite
anything outside the request. This hook is advisory: its request supplies no
artifact reader, world query, model/network client, mutation interface, runner
selector, or plug-in selector. Core/deployment selects the exact configured
instance from the retained execution plan and stores validated output as
derived evidence. The core validates only this supported interface; because
plug-ins are trusted unsandboxed Python, authors remain responsible for not
reaching ambient filesystem, network, process, or model facilities directly.

An evidence interpreter does not need to be the primary parser. For mixed
platform, firmware, or chip deployments, register it as a separately
identified capability-only instance and attach it to the exact primary parser
identity with a `PluginCompositionPolicy` role such as
`private_analysis_evidence`. Keep capability-only instances out of the primary
parser registry and register them only in the capability-provider registry.
Core then freezes both pins into the revision plan and later routes only to
that retained auxiliary; registration order, display names, and model arguments
never choose it. The runnable demo's
`rsl_demo_plugin.deployment:build_plugin_deployment` and semantic contract test
exercise this pattern end to end.

The input/execution/output distinction is deliberate: validate the request
before invoking the hook, report a hook failure as execution failure, and
report only the plug-in's returned value as output failure. This keeps a bad
host call such as `apply(None, world)` from being blamed on a plug-in that was
never invoked.

Use this executor in tests for every capability you advertise. Do not construct
it inside the plug-in. A production coordinator must route through the
revision plan instead of constructing an unbound executor or consulting the
currently installed plug-ins. This is host integration, not code a device
plug-in should copy. Run the complete executable examples with:

```text
python -m unittest tests.test_capability_router -v
```

Those cases construct every registry, plan, member, reader, and window they
use; this guide intentionally avoids a partial snippet with deployment-owned
values left undefined.

Use `instance_id` as the deployment's logical configured-instance identity.
Two configured instances may intentionally share the same plug-in ID, version,
and executable package. Their probe candidates remain distinct because core
also records `instance_id` and the content-addressed
`registered_execution_identity`; selection clients echo those two fields as a
pair.
IDs are unique within one plan; the provider registry may retain several exact
installed releases for that same logical ID so old and new revisions remain
replayable. A configuration change always requires a new logical instance ID,
even if only one configuration appears in a plan. A node/revision selects one
exact release only through its immutable plan.
A selector that matches zero or several pins fails closed.
Role and instance qualifiers disambiguate; plan order is never a tie-breaker.
The router revalidates artifact, manifest, configuration, schema, capability,
and decoder identity before and after each call. Manifest-only compatibility
records cannot be capability providers. A perspective-specific world
must carry the pin's complete instance/schema qualification, and forwarding
steps must name the selected revision-set member. The returned
`CapabilityInvocation` always retains a
detached `CapabilityProviderRef`; do not merge different providers' results
without an explicit core-owned federation/linking operation.

#### Optional typed connector claims

Use this only when a local topology endpoint must be joined to another
revision-set member. Keep ordinary node-local resources and links as
`TopologyProjectionRecord` values. Then:

1. Add one or more `ConnectorMatchPolicyDescriptor` values to
   `PluginSchema.connector_match_policies`.
2. Return a `TopologyResourceRecord` for the local endpoint from
   `project_topology()` (or make that exact endpoint available in the bounded
   `ReadOnlyWorld`).
3. Return a `ConnectorClaim` from the same iterator. Its
   `claim_contract_id`, `match_policy_id`, and complete ordered argument-name
   tuple must match the schema declaration exactly. Declare its normalized
   link semantics explicitly when they are not the safe defaults:

   ```python
   ConnectorClaim(
       # identity, endpoint, policy, arguments, provenance, and quality omitted
       link_type="underlay.adjacency",
       presentation=InterNodeLinkPresentation(
           route_trace=InterNodeRouteTraceRole.INCLUDE,
       ),
   )
   ```

   The defaults are `link_type="connector"` and route-trace role `include`.
   Use `overlay` for a presentation-only overlay; plug-ins cannot declare the
   core-produced `conflict` role.
4. Use `KeyAtom` or nested typed tuples whenever integer, string, byte, UUID,
   IP, label, SID, or compound-key representations could alias. Do not add a
   guessed remote endpoint to the local claim.
5. Let the core qualify the claim with member, immutable revision, and exact
   provider identity. `exact_token` policies are joined by complete typed
   equality in core. A `linker` policy is sent only to its allowlisted
   `FederationLinkerPlugin` with bounded normalized claims.

`TopologyProjectionRequest.max_records` and `max_claims` are independent.
The execution result exposes `records_complete` and `claims_complete`; never
infer claim completeness from resource preview pagination. Unmatched and
ambiguous claims are valid, visible federation outcomes rather than a reason
to select the first candidate. The runnable implementation is
`demo/rsl_demo_plugin/typed_topology.py`, and
`tests/test_topology_federation.py` exercises different plug-ins and versions,
typed-key separation, temporal claims, ambiguity, policy drift, and linker
allowlisting.

Validity remains half-open, but federation evaluates it over the selected
world's resolved uncertainty interval, not only at a nominal point. The
selection's `basis_time_ns` must equal that world's `requested_time_ns`. A
bounded claim is authoritative only when
`valid_from_ns <= resolved_at_min_ns` and
`resolved_at_max_ns < valid_to_ns` (with either validity bound optional). A
claim wholly outside that interval is inactive; one whose validity boundary
crosses the interval, or whose bounded member basis is unknown, is excluded
and makes the scoped typed result incomplete. It is never assumed current.
Core applies the corresponding half-open validity gate to typed resources,
endpoints, and links. Keep
`catalog_revision_id`, `member_id`, revision IDs, and plug-in coordinates as
exact non-empty strings. Core does not stringify them or fall back to another
revision, and it discovers the optional typed projection from the exact
immutable capability route rather than from an extra metadata opt-in flag.

Typed `TopologyEndpointRecord` values are returned alongside resources and
links. Federation output retains claim, result, and candidate properties,
quality, evidence, provenance, and all grouped ambiguity audit material.
Multiple local claims for the same token remain distinct candidates, including
same-member fanout; neither iterator order nor a first-candidate shortcut may
resolve them. A strict route boundary may consume a typed connector only when
its resolution is `matched`, its federation execution is complete, and it is
not truncated, and `presentation.route_trace` is `include`. `overlay` remains
inspectable presentation evidence and never becomes a forwarding hop. For a
directed result, core compares the ordered source and target using their exact
member, revision, plug-in instance, projection, perspective, and typed resource
identity; reversing those endpoints does not match. Undirected results may
match either exact order. Malformed or partially qualified typed endpoints fail
closed, while legacy non-typed link matching remains compatible.

When a generated next hop selects a typed connector, carry a core-generic
reference in its `topology_references` list:

```json
{
  "reference_kind": "typed_inter_node_link",
  "source_endpoint": {
    "node_id": "node-a",
    "resource_id": "interface/a",
    "typed_resource_key": {
      "namespace": "example",
      "node": "node-a",
      "layer": "underlay",
      "kind": "INTERFACE",
      "parts": [
        {"name": "name", "value": {"type": "string", "value": "a"}}
      ]
    }
  },
  "target_endpoint": {
    "node_id": "node-b",
    "resource_id": "interface/b",
    "typed_resource_key": {
      "namespace": "example",
      "node": "node-b",
      "layer": "underlay",
      "kind": "INTERFACE",
      "parts": [
        {"name": "name", "value": {"type": "string", "value": "b"}}
      ]
    }
  }
}
```

The plug-in declares the ordered endpoint nodes, its existing local next-hop
resource IDs, and its own typed `ResourceKey` values. It neither predicts a
core link hash nor supplies member, revision, plug-in-instance, projection, or
perspective coordinates. Core binds those typed keys to the frozen topology's
fully qualified endpoint references and then requires one exact
`_matching_link` result for the ordered pair. Once this typed reference is
declared, malformed, absent, reversed-directed, overlay, incomplete,
truncated, or multiply matching evidence leaves the boundary unresolved;
core does not downgrade it to another connectivity-domain reference in the
same declaration. A next hop with no typed reference retains the legacy exact
connectivity-domain/attachment join. Typed route use also requires the
topology response's global `typed_federation_complete` to be `true` and
`typed_federation_truncated` and `inter_node_links_truncated` to be `false`;
one individually complete link cannot override partial federation coverage or
an incomplete link page. Resource-record preview pagination is independent:
an overall or node preview may be partial without invalidating a complete,
untruncated claim/link decision. On success, the generated boundary's
`graph_presentation.semantic_owner` copies the matched link's validated
`inference.owner`: `core_exact_matcher` for core exact-token results or
`federation_linker_plugin` for allowlisted-linker results. Its resolution
summary and `text_source` follow that owner rather than describing a linker
result as a core exact match. The response-level
`semantic_ownership.boundary_resolution` summarizes the complete rendered
boundary owners as that one owner, `node_topology_plugin`, `mixed`, or `none`.

Identity matching does not make an unknown operational state healthy. In
`strict` mode a matched typed link with `operational_status="unknown"` remains
inactive and unresolved. In `best_effort` mode it may remain as a provisional
`best_effort_inferred` branch, but it is still unobserved, has reduced
confidence, and carries
`typed_boundary_operational_status_unknown` with core-inference provenance.
Emit `usable` or `unusable` only when your plug-in actually has that evidence.

The generic topology and route HTTP providers publish these routed results.
The host reconstructs each member's typed resource
states and supplies them through `ReadOnlyWorld`; keep the topology plug-in
stateless and module-level so a PROCESS worker can reproduce the exact target.
Do not put a node dump or revision-specific claim list in the plug-in
constructor and then represent it only with a `configuration_digest`: that
digest attests configuration identity but does not transport configuration to
a spawned worker.

The generic node browser can show a bounded list of plug-in-projected route
choices, but v1 has no separate route-catalog hook. The coordinator derives
that capability from `FORWARDING_PROJECTION` or another explicitly versioned
projection. If your projection participates, give each route decision one
opaque, revision-stable `route_id`; keep node/revision/provider identity
explicit; and declare only basis kinds the coordinator can execute. Do not put
a URL in the plug-in or expect the browser to infer a destination, VRF,
label/SID, or fallback route from display text. Unknown IDs and unsupported
bases must fail closed. The normalized HTTP shape is in
[`api-contract.md`](api-contract.md#51-advertised-single-node-route-choices).

A projected row that only inventories local or null-scenario forwarding state
may set `traceable: false`, leave `trace_query` empty, and supply a bounded
`trace_unavailable_reason`. Core can still list that row, but it must not invent
a cross-node candidate or let the browser submit it as a trace.

### Core-owned runtime v2 and the compatibility runtime

Stop here for an ordinary parser plug-in. It does **not** need a
`plugin.runtime` attribute. The core command inventories its input, calls
`describe()`, `probe()`, and `locate_inputs()`, dispatches only parser kinds
whose declared capability and hook agree, validates every output, assigns
stable identities, reconstructs the normalized dataset, and exposes the basic
node workspace through a core-owned `router_dump_analyzer.runtime.v2` session.

The current v2 session intentionally supplies only the normalized data
workspace. Its `temporal_provider`, `topology_provider`, and `route_provider`
are `None`, its history source has no optional structural index, and its route
catalog reports unavailable. Do not advertise those views merely because the
parser emitted similarly named resource properties. Add them only through the
corresponding executable, versioned provider contracts.

`plugin.runtime` is a compatibility surface for an independently versioned,
precomputed fixture or assembly that cannot yet enter through the standard
parser hooks. The bundled million-event-per-node generated demo uses it. New live
device parsers should not. A compatibility adapter implements
`PluginRuntimeCapability` and identifies itself as
`router_dump_analyzer.runtime.v1`:

```python
from contextlib import contextmanager
from pathlib import Path

from router_dump_analyzer.runtime import PLUGIN_RUNTIME_CAPABILITY_ID


class MyRuntimeCapability:
    capability_id = PLUGIN_RUNTIME_CAPABILITY_ID

    @contextmanager
    def open(self, input_path: Path):
        session = open_my_non_web_session(input_path)
        try:
            yield session
        finally:
            session.close()
```

This is only the compatibility wrapper;
`open_my_non_web_session()` represents the fixture adapter's tested session
constructor. The complete executable reference is
[`demo/rsl_demo_plugin/session.py`](../demo/rsl_demo_plugin/session.py),
covered by
[`demo/tests/test_runtime.py`](../demo/tests/test_runtime.py).

The yielded `PluginRuntimeSession` is a structural protocol with six non-web
surfaces:

| Session member | Requirement | Responsibility |
|---|---|---|
| `revision_store` | required | Immutable assembly/revision lookup implementing core `RevisionStore`. |
| `data_source` | required | Revision-scoped normalized dataset loading and optional indexed history implementing `NormalizedDatasetSource`. |
| `data_policy` | required | Opaque analysis/workspace metadata, route-row lookup, and safe source-record formatting implementing `NormalizedDataPolicy`. |
| `temporal_provider` | optional; use `None` when unsupported | Supply temporal descriptors; `for_revision()` must return the core `TemporalTopologyService`. |
| `topology_provider` | optional; use `None` when unsupported | Expose a stable `topology_id` and return the topology service from `get()`. |
| `route_provider` | optional; use `None` when unsupported | Return the route/packet service from `get()`. |

`NormalizedDatasetSource`, `NormalizedDataPolicy`, and
`NormalizedDataService` are exported by `router_dump_analyzer.normalized_data`.
The remaining structural protocols are exported by
`router_dump_analyzer.runtime`. Core constructs the data service and validates
that optional providers return the corresponding core service class; a plug-in
must not copy or replace those generic query engines.

Keep the two required adapters small:

```python
class MyDatasetSource:
    def revision_scope(self, revision_id): ...
    def load_dataset(self, revision_id=None, **selection): ...
    def revision_id(self, dataset): ...
    def indexed_history(self, dataset):
        return None  # or a structural IndexedHistory


class MyDataPolicy:
    def analysis_metadata(self, dataset): ...
    def workspace_metadata(
        self, dataset, *, revision_id, history_mode
    ): ...
    def route_resolution_capability(self, dataset):
        return {"available": False, "routes": []}
    def route_row(self, route_id, dataset):
        raise KeyError(route_id)
    def source_record_for_event(self, event): ...
```

`load_dataset()` returns the normalized envelope produced by the plug-in.
`indexed_history()` may return `None`; it is an optimization, not a second
semantic model. The two route methods above are the correct no-route
implementation. Core owns all resource/event traversal after these callbacks.
`open()` must be a context manager so the core application lifespan can close
stores, indexes, and caches exactly once.

Core already shows an indeterminate `loading_revision` indicator around
`load_dataset()`. A precomputed-fixture adapter that knows real row/member
counts may optionally make it determinate without changing the source method:

```python
from router_dump_analyzer import AnalysisLoadStage, report_analysis_load

report_analysis_load(AnalysisLoadStage.PARSING, records_processed=0)
for ordinal, record in enumerate(records, start=1):
    load_record(record)
    if ordinal % 1_024 == 0 or ordinal == len(records):
        report_analysis_load(
            AnalysisLoadStage.PARSING,
            completed=ordinal,
            total=len(records),
            records_processed=ordinal,
        )
report_analysis_load(
    AnalysisLoadStage.INDEXING,
    records_processed=len(records),
)
```

Use `total=None` (or omit it) whenever the complete denominator is unknown.
Do not invent weighted percentages across unrelated phases. The reporter is a
safe no-op when this function is run by a conformance test outside the hosted
runtime, and malformed optional progress cannot fail an otherwise-valid load.
The generated demo's assembly and scale loaders are the executable reference.

This compatibility adapter supplies precomputed data and device policy, not an
application. Do not return
FastAPI, `APIRouter`, middleware, routes, page templates, assets, or browser
code. The core creates all of those. A standard parser plug-in without this
adapter is served through core-owned runtime v2.

### Durable admission does not change the plug-in

`router-dump-ingest` and the optional `/v1/control-plane` upload queue use the
same `describe()`, `probe()`, `locate_inputs()`, and parser hooks. A deployment
constructs an explicit `PluginRegistry`; uploaded bytes cannot install or
select code outside that allowlist. Core records the complete deterministic
probe set and, when selection is needed, requires the client to echo the
probe-set hash plus your exact plug-in ID, version, and returned package
identity. A trusted loader may supply an immutable artifact digest. Otherwise
the durable CLI/server derives an executable digest from the complete bounded
import scope and fails closed if it cannot do so. Packages use
`package-sha256:<digest>`. If a PEP 420 namespace precedes your plug-in, all
search locations of its first namespace ancestor participate even when your
plug-in then enters a regular subpackage. A genuine top-level module uses
`module-sha256:<digest>` and is never presented as a one-file package. Core
does not derive identities from sourceless `.pyc`/`.pyo` files because their
embedded build paths are not relocation-stable; a trusted loader must supply
an immutable artifact digest for that deployment. Core recalculates either
registry-derived identity immediately before execution.
Programmatic
registries have the same fail-closed default. A compatibility-only embedding
must spell `PluginRegistry(..., allow_manifest_identity=True)` to enable a
manifest-only fallback. A strict durable deployment deliberately rejects that
registry before state is created. The explicit trusted-inline descriptor above
is the intended composition-root admission path. A lower-level trusted
embedding may instead pass the same exact-boolean `allow_inline_only=True` to
`ControlPlane` or `DurableIngestionPipeline`; it must also select INLINE plug-in
execution when an admitted registration is INLINE-only. None of these options
can be supplied by an upload, HTTP request, or tenant.

That opt-in also covers the narrower case where core can derive the package
digest but cannot statically attest a stateful subprocess target. The
registration is then marked `inline_only`: trusted local capability calls may
use it after package revalidation, but PROCESS mode rejects it. An explicitly
opted-in trusted-inline durable deployment may freeze and route it; the plan's
authority records whether all package bytes were attested or whether the weaker
manifest-only identity was used. An explicit package hash or the default strict
registry never falls back. Do not enable this merely to make an untrusted or
public production plug-in register; supply an importable immutable process
target instead. Durable pipelines snapshot and seal their primary/provider
directories, so registrations added afterward remain local.

`trusted_inline_manifest` is deliberately weaker than reproducible executable
identity: core can recheck the frozen manifest and registered identity, but not
the plug-in's code bytes. `process` describes only primary ingestion behind the
child-process boundary; it does not claim that later capability hooks are
subprocess-isolated. Trusted inline ingestion has no killable timeout, crash or
resource-exhaustion containment, and `close()` may stall or fail. The live
object and its mutable state may be shared across jobs, tenants, and concurrent
workers with ambient host access. All tenants/operators sharing the process
must trust the plug-in; make it thread-safe or set `max_workers=1`. Core keeps
the publisher in PROCESS mode by default unless the embedding separately and
explicitly overrides it.

For ordinary entry-point packages this is automatic. Keep every package or
namespace search root inspectable and stable while it is loaded: across the
complete scope, at most 4,096 fingerprint entries (regular files, ordinary
directories, or validated contained link/junction aliases), at most 8,192
examined paths, 32 MiB per
regular file, 128 MiB total, and portable relative paths. Generated caches and
version-control directories are ignored. The first namespace ancestor is a
deliberately conservative boundary so parent-relative helpers cannot escape the
identity. For the narrowest durable identity, put the exported plug-in and its
helpers under a top-level regular package rather than below a large shared
namespace. Do
not replace a package's runtime `__path__` after registration; adding a valid
search root changes its executable identity, while dropping the defining root
is rejected.

By default, the durable servers and headless command invoke both probe and ingestion in a
fresh child created with Python's `spawn` start method. Core serializes only a
bounded inert bootstrap: it never pickles the live plug-in, registry,
coordinator, decoder, provider, or a bound method. Installed/direct-module
loading uses the exported module-level plug-in instance. A programmatically
registered default-constructed plug-in, custom coordinator, or decoder may use
an importable no-argument class constructor. Stateful or configured objects
MUST instead expose a module-level instance and register its explicit
`plugin_process_module_target`, `coordinator_module_target`, or
`decoder_module_target`; the target must reconstruct the same frozen execution
identity. A non-default `configuration_digest` is the programmatic signal that
configured state exists: PROCESS mode rejects the registration unless
`plugin_process_module_target` names a module-level instance (not a class
constructor), plus explicit coordinator/decoder targets when those custom
objects carry the asserted state. Installed entry-point and direct-module
loaders already provide the plug-in target. If the exported live instance must
also carry a parent-only runtime/session adapter, keep that adapter out of the
parser class identity and opt into an exact no-argument class bootstrap:

```python
from typing import Any

from router_dump_analyzer.plugin_api import AnalyzerPlugin, AnalyzerPluginBase
from router_dump_analyzer.plugin_loading import (
    PluginProcessBootstrapDescriptor,
)
from .session import runtime as application_runtime

class ExamplePlugin(AnalyzerPluginBase):
    plugin_process_bootstrap: PluginProcessBootstrapDescriptor = (
        PluginProcessBootstrapDescriptor(
            module_target="example_router_plugin:ExamplePlugin",
            construct_class=True,
        )
    )
    runtime: Any
    # describe/probe/locate_inputs/parser hooks must need no runtime attribute.

entry_plugin = ExamplePlugin()
entry_plugin.runtime = application_runtime
plugin: AnalyzerPlugin = entry_plugin
```

The loader accepts that declaration only as an exact attribute on the live
instance's concrete class and registration attests the named exact class. It
does not copy `runtime` or any other live/configured state into the child. The
runnable demo exercises this split in an actual fresh-process ingestion test.
Do not use it for a configured parser; a non-default configuration digest still
requires an explicit module-level instance process target.

An advanced custom coordinator still hands data back through the core-owned
publication boundary. It must return an exact `IngestionResult` whose
`node_id` equals the requested `node_hint` when one was supplied. Each
`SourceRecordEmission` must have one aligned, unique
`SourceRecordOrigin(parser_id, input_ordinal, output_ordinal)` within the
registered coordinator's frozen input/output limits. Core captures result
references once, reapplies those limits, detaches and validates the inventory,
schema, and typed streams, rebuilds the closed dataset, and requires the
coordinator's dataset to match exactly. Do not inject custom dataset fields or
rely on relaxed limits from a mutated coordinator. Embeddings and conformance
tests may call the root-exported
`snapshot_ingestion_result_for_publication()` directly; the durable pipeline
always applies that boundary before publication.

Trusted inline-only tests and explicitly opted-in deployments may keep
a live object, but that does not make it PROCESS-capable. Open files, sockets,
native iterators, and thread-affine objects only
inside the child hook. The default child deadline is 300 seconds;
`router-dump-ingest --timeout` may lower it.
A registered-execution identity covers the complete non-recursive process
bootstrap: loader kinds and targets for the plug-in/coordinator/decoder,
source-backed executable identities for every external target,
package-verification mode, artifact and configuration coordinates, frozen
ingestion/artifact limits, and optional decoder identity. Target identity binds
the exact import coordinate, bounded module/package bytes, and Python
implementation code. Dynamic aliases, sourceless targets, and unverifiable
re-exports fail closed. Live Python functions/classes must still match their
source-declared recursive code, signatures, defaults, and safe global/static
dependencies. The identity traversal follows the exact globals, static
attribute paths, and statically resolvable local imports named by helper
bytecode across package boundaries; it does not stop at the target package.
Identity calculation never executes an import to discover authority. Load any
bytecode-referenced local import during deterministic package initialization;
the installed entry point must register strictly in a fresh process without a
separate warm-up call.
Function-owned executable state is part of the same identity. One identity has a shared limit of 64 value levels,
32,768 value nodes, 2,048 code objects, and 32 MiB of runtime value bytes.
Local-import source is token-count preflighted against the remaining node
budget before its AST is constructed; keep module declarations bounded rather
than relying on unreachable code to hide a large source graph.
Callable module instances also bind their canonical `__dict__` and slot values,
ordinary class state, properties, callable members, and descriptors. Use
immutable bounded scalar/tuple/frozenset state (or the supported frozen
dataclass and enum forms); opaque native state and unsupported mutable state
are not PROCESS-capable. Runtime-generated code, unsafe closures, and custom
builtins likewise fail closed. Keep process targets as ordinary module
declarations with immutable defaults and source-backed helper callables. Only the expected
identity sent to the child is excluded to avoid hashing itself. Retained live
class and mutable-object snapshots are rechecked after the complete traversal,
before the digest is returned. Changing only
a process target or one of those limits therefore changes the plan/revision
authority. Core revalidates target bytes immediately before spawn, the child
re-attests before invoking them, and the parent checks again after the child
and at final revision staging.
A timeout or crashed/invalid child fails the import without publishing a
partial revision and removes its partial staged dataset.
An embedding may explicitly choose synchronous `inline` execution only for
trusted local/tests. Inline mode has no timeout or bounded-cancellation claim;
process mode is the only killable boundary.

Your plug-in must remain deterministic across a retry and must not write to the
catalog, upload store, session store, review overlay, or HTTP response. It does
not receive tenant/project/workspace, fixture/import, or principal identity and
does not decide which user may select it. It receives only the same optional
node hint and caller-supplied bounded import metadata during probe and parsing.
The headless flags are `--node-hint` and `--metadata-json`; HTTP uses
`X-Node-Hint` and JSON-object `X-Import-Metadata`. Core owns content
addressing, idempotency, queue leases, progress, immutable publication,
multi-revision sessions, human annotations, cross-node exact-match mechanics,
and correlation-report envelopes.

Before probing, core stages the complete fixture-admission request and
operation ID. After parsing, it stages the complete
revision-publication request and operation ID. A lost catalog response at
either boundary is replayed exactly; publication replay does not invoke your
plug-in again. Explicit selection is also a durable idempotent receipt, so the
same key/request remains a valid retry after processing advances.
Catalog admission/publication has a separate core-owned deadline and, in the
production default, a killable spawned-process boundary. It does not interrupt
your hook or expose a new hook; it bounds catalog/RPC work after plug-in output
has been staged, retaining the exact outbox and pin when expiry leaves the
external outcome ambiguous. This affects only the core/deployment publisher;
it adds no plug-in method or state.

To test durable admission for your package, replace `demo_router` and the
fixture in the final command of step 1. Repeat `--plugin` to admit several
installed candidates, or repeat `--plugin-module` during source development;
the two selector forms are mutually exclusive. `--no-auto-select` should leave
an applicable fixture in `awaiting_selection` and exit with status 2 rather
than allowing the plug-in to choose itself. The full operator contract is in
[`control-plane.md`](control-plane.md).

The runnable demo also exercises the trusted descriptor path:

```text
router-dump-ingest \
  --plugin-deployment-module rsl_demo_plugin.deployment:build_plugin_deployment \
  --state-dir .runtime/plugin-author-composed \
  --tenant quickstart --project plugin-author --workspace composed \
  --input demo/fixtures/minimal-status.jsonl
```

Use a deployment descriptor when several exact platform, firmware, or helper
instances must coexist. Keep the ordinary `--plugin` smoke above for the
single plug-in's parser conformance; neither form lets a plug-in choose its own
peers.

To verify that your installed entry point can participate in the production
API-only composition, start the core server with an explicit allowlist and a
deployment identity resolver:

```text
router-dump-server --plugin-deployment-module rsl_demo_plugin.deployment:build_plugin_deployment --state-dir .runtime/plugin-server \
  --trust-control-plane-headers --host 127.0.0.1
```

After the known-good check, replace the demo descriptor with your trusted
deployment target (or use one ordinary `--plugin` selector). This command does
not load an analysis input or frontend. It uses the
same standard hooks and process boundary, and uploaded bytes cannot add another
plug-in. `--plugin-module PACKAGE[:ATTRIBUTE]` is the mutually exclusive
source-development form; all three selector families are mutually exclusive.
The shown trusted-header mode is only a loopback
development adapter, never a plug-in feature or production authentication; a
production host uses `--identity-resolver-module PACKAGE:ATTRIBUTE` backed by
verified credentials.

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

`ResourceKey.parts` must be a non-empty tuple of at most 32 unique
`(name, value)` pairs. Names are bounded dotted field paths. Values may contain
only `int`, `str`, `bytes`, `UUID`, `KeyAtom`, or nested tuples of those types;
tuple nesting, item counts, integer bit length, and text/byte length are
bounded by the core. Floats, mappings, lists, booleans, and arbitrary Python
objects are rejected before storage or federation.

Never:

- join key parts into an ambiguous display string;
- use a boolean key part;
- parse another resource's display ID to recover semantics; or
- use a plug-in run ID as resource identity.

Relationships, not key parsing, control grouping and dependency traversal.
Analysis `revision_id` values are separately core-owned opaque identifiers.
They may contain `/`; neither plug-ins nor clients may split them to recover
node, platform, or resource meaning. A client putting one in a URL must
percent-encode the whole value and use the revision-scoped route returned by
the API.

## 6. Preserve source records and evidence

Every output should point back to stable evidence such as `line:12`,
`bytes:100+20`, `ctf:stream=2,message=481`, or a JSON pointer.

Parser hooks may yield `SourceRecordEmission` for matched or unmatched input.
The plug-in supplies decoded source semantics and an optional
`matched_event_uid`. Use `matched_event_uids` when one decoded input contributes
to several normalized events. It does **not** assign `source_record_uid`; the
core turns the emission into a persisted `SourceRecord` with stable identity.

Set `copy_text` only when the plug-in can provide a safe canonical plain-text
form for an operator to copy. The plug-in must redact secrets before assigning
it: core treats the string as opaque and will return it verbatim. This is not
the short hover `message`, raw private payload, HTML, a template, or a browser
callback. It must be a string, contain no NUL, and be at most 65,536 UTF-8
bytes. The core keeps it out of ordinary log/timeline/bootstrap projections,
resolves explicit immutable selections, and applies deduplication plus
item/byte quotas. The host authorizes access to that endpoint; the browser owns
selection gestures and the final Clipboard API call.

A source-record group may set a 1-to-80-character `copy_action_label`, such as
`Copy status rows`. A mixed-group selection uses a generic core label rather
than choosing one plug-in label arbitrarily.

`RecordLanePreset.pattern` uses the same deterministic subset as a user-created
record lane: top-level alternatives composed of literals, character classes,
dot, anchors, and at most one `*`, `+`, or `?` quantified atom per alternative.
Groups, counted repetition, lookaround, backreferences, ambiguous/nested
repetition, and unsupported escapes are rejected. Prefer simple patterns such
as `ESI|mass withdraw`, `^BGP`, or `error.*peer`; the core applies the same
pattern, haystack, lane, and result bounds at runtime.

For trace normalization:

1. derive `DomainEvent.event_uid` with
   `derive_event_uid(plugin_id, parser_id, source_ref, local_discriminator)`;
2. keep `timestamp_ns` inside signed `int64`; use `None` when time is unknown,
   and provide uncertainty only as a non-negative signed-`int64` value beside
   a known timestamp, with the complete uncertainty interval still inside
   signed `int64`;
3. emit a `SourceRecordEmission` for retained input when requested;
4. set its `matched_event_uid` or `matched_event_uids` when normalization
   succeeded; and
5. keep unmatched records rather than inventing domain events.

Every nanosecond coordinate declared by the core contract is an exact signed
64-bit integer (`-2^63` through `2^63-1`), or `None` only where that field
explicitly permits unknown time. This applies not just to `DomainEvent`, but to
source/evidence/CTF timestamps, mutation and observation times, validity
bounds, temporal selectors, reconstruction watermarks and resolved bases,
topology/connector validity, and capability outputs. Uncertainty and paired
bounds must remain valid inside the same range. A
`RelativeToWatermarkSelector.offset_ns` must also be zero or negative, and the
core fails closed if adding it to its scoped watermark would overflow.

The helper uses a versioned, length-delimited SHA-256 encoding of the canonical
source identity. Use `local_discriminator` only when one source record produces
several domain events. Its type is significant, so integer `1`, string `"1"`,
and byte `b"1"` remain distinct. Never use Python `hash()`, random UUIDs, the
wall clock, or list position after filtering. Increment `parser_id` when a
release changes how one source record is split into domain events.

### Represent topology resource lifecycles

If your topology adapter emits the compact resource replay shape, start with
`initial_status` and `initial_state`, then place updates in `changes[]` with a
`time_ns`. Use `status: "down"` when the resource still exists but is unusable.
Use boolean `exists: false` for deletion and `exists: true` for recreation. You
may instead use the generic `operation` values `delete`/`remove` and
`create`/`add`/`insert`; explicit `exists` wins when both are present.

Set `state_changed: false` on a failed or proposed update that changed nothing.
The core then ignores that change's lifecycle, status, and state fields.
`valid_from_ns` is inclusive and `valid_to_ns` is exclusive and always bounds
the result, so a create cannot extend a resource outside its declared validity
window. A delete followed by a create produces an absence gap for the same
canonical resource ID.

For equal timestamps, core replays by
`(timestamp_ns, source_sequence, stable event/change ID)`. Emit a real
`source_sequence` whenever one producer can report more than one item at the
same instant; never rely on parser iteration order.

Topology change queries use the same half-open rule:
`start_ns <= change_time_ns < end_ns`. An event on a shared boundary belongs
only to the later adjacent window. Do not compensate by moving a timestamp or
duplicating a change.

Keep an exact connectivity-domain key small and type-stable. Core tags atom,
container, and mapping-key types and rejects non-finite floats, cycles, more
than four nested container levels, more than 32 items in one container, more
than 1,024 total value units, strings/bytes over 4,096 units, or integers over
4,096 bits. Missing and explicit null are different. Do not stringify a
numeric, byte, UUID, or compound key merely to fit the transport.

Plug-in hooks provide ordinary Python values; core normalizes them exactly once
before storage or JSON transport. A stored/API key is already a tagged
normalized value. Core validates and canonicalizes that representation
directly, counts only the plug-in's logical containers toward the four-level
limit, rejects unknown tags, extra fields, invalid encodings, non-canonical
mapping order, or duplicate canonical mapping keys, and verifies an optional
`typed_key` against the candidate key. Never feed a tagged transport value back
through the raw-value normalizer or infer meaning from its JSON shape.

When an optional runtime topology adapter declares relative reconstruction
watermarks, scope each one by the exact node/member revision, plug-in run,
status perspective, and topology projection. Provide `local_time_ns`,
`clock_domain`, and `complete`; provide both absolute bounds or neither. A
complete local-only watermark supports a relative query without a wall-clock
transform. New adapters should declare these watermarks. Omitting them invokes
only the legacy capture-time-minus-projection-lag compatibility path, which
still needs the node clock mapping and is identified as legacy in the result.

## 7. Keep core and plug-in responsibilities separate

Put a decision in the node/device plug-in when it depends on:

- platform, release, layer, or protocol vocabulary;
- resource kind or key-field names;
- UUID/byte/integer interpretation;
- vendor status normalization;
- resource relationships or matching rules;
- candidate paths, directional/per-visit forwarding decisions, or which exact
  connectivity-domain key and attachment resources a next hop names;
- route-resolution text;
- endpoint attachment or local delivery/termination meaning;
- topology projection;
- dashboards, table columns, labels, or icons.

Put mechanics in core when they apply identically to every plug-in:

- safe archive inventory and materialization;
- canonical envelopes and key serialization;
- clock fitting and temporal selector resolution;
- interval persistence and pagination;
- exact equality joins between a plug-in-declared connectivity-domain
  matcher/key and the selected normalized domain plus current attachments,
  including fail-closed missing/ambiguous/truncated/unusable results;
- immutable flow direction, exact endpoint-goal matching, and bidirectional
  reachability aggregation;
- tenant/project/workspace scope mechanics, optimistic concurrency,
  idempotency, budgets, validation, and generic rendering. Deployment
  authentication and role authorization remain outside the plug-in.

Dashboard comparison is likewise bounded: 16 nested container levels, 1,024
items per container, 4,096 comparison units, 65,536-character/byte atoms, and
4,096-bit integers. Keep filter and statistic fields within those limits.
Cyclic, unsupported, or over-bound values do not match filters and do not
contribute to `count_distinct`; non-finite floats may be compared as tagged
values but never contribute to numeric aggregates.

Dashboard field lookup is presence-aware. An explicit envelope value, including
null, wins over a same-named state or key value; a missing field does not match
ordinary comparisons and is omitted from table projection. `exists` tests
presence (`value` defaults to true), explicit null participates in equality and
`count_distinct`, and numeric aggregates accept only finite numeric values
(never booleans or numeric strings). An empty `sum` is `0` with
`sample_count: 0`; `average`, `minimum`, and `maximum` are null with zero
samples. `max_rows` must be an exact non-boolean integer from 1 through 500.

Cross-node matching that interprets normalized claims belongs to a separate
federation/linker plug-in. A node plug-in stops at its local connector claim.

### Route endpoints and trace starts

This is optional advanced forwarding behavior; the minimal example does not
implement it. Keep these identities separate:

- the packet's immutable source and destination endpoints;
- the forward trace start/ingress where observation begins; and
- the target endpoint for the current direction.

A start may be a transit router. Do not rewrite the packet source to that router
and do not require return traffic to revisit it. The default reverse traversal
starts from a declared destination attachment and targets the exact source
endpoint. Core swaps those directional goals and aggregates the result.
If a bidirectional request explicitly chooses a reverse start, it must be one
of those destination attachments; an arbitrary return-side observation proves
only the suffix it actually traverses.

Your node plug-in declares normalized, time-valid endpoint attachments and
classifies local delivery or origination using canonical resources or typed
match references with provenance and evidence. It does not assemble a
multi-node route. The federation/linker plug-in matches bounded attachment and
boundary claims between members. Core exact-matches the declared terminal,
retains attachment uncertainty and multipath coverage, and reports whether
forward reached the destination and return reached the source. Its
`evaluate_endpoint_reachability_pair()` helper classifies the pair after those
typed directional endpoint results are known; it does not replace plug-in
terminal evidence.
All plug-in-selected active branches must reach before core reports a fully
reachable direction. Mixed success/failure is
`partial_active_reachability`, while incomplete evidence remains unknown.

Node-sequence symmetry is only explanatory. A forward trace starting inside the
flow and a full return trace have `path_relation=not_comparable`; that does not
make a bidirectionally reachable flow inconsistent. Conversely, a complete
return path that ends at the forward start but not the source endpoint is not
successful. The executable endpoint-pair cases are in
`tests/test_multi_node_route.py`.
When calling `evaluate_endpoint_reachability_pair()` directly, pass
`reverse_starts_at_destination_endpoint=True` only after exact attachment
resolution proves it. Omitting that proof preserves directional endpoint
reachability but returns `path_relation=not_comparable` with
`reverse_endpoint_start_unknown` instead of inventing symmetry.

If a compatibility route executor advertises one fixed source/destination
pair, a caller may supply that exact pair in either order. Reversing the pair
selects the executor's opposite directional declarations while the response
keeps the caller's requested `forward` or `reverse` label. Provide complete
directional decisions for both orders. A fixed scenario whose declared
destination has several possible attachments cannot be reversed safely unless
it also declares an exact source-attachment contract; core rejects that
ambiguous request.

Always declare route group mode in new projections. `single_active` permits at
most one selected path; `all_active` explicitly declares concurrent selected
members. The legacy route-executor v1 omission is accepted only when zero or
one path is selected, where it unambiguously means `single_active`. Omission
with several selected paths fails instead of inventing ECMP.

### Packet transformations and trace-time forwarding

This is an optional advanced capability. Keep it separate from status parsing
and follow this order:

1. Implement and test `FORWARDING_PROJECTION` first so the plug-in exposes
   stable canonical forwarding objects at a qualified perspective.
2. Declare `FORWARDING_TRACE` only when
   `resolve_forwarding_step(request, world)` returns a bounded,
   node-local `ForwardingStepResult`. Do not return an end-to-end route or read
   another assembly member.
3. Represent the current packet with `ForwardingPacketState`. Put
   `ForwardingPacketLayer` values outermost to innermost, give each layer a
   stable identity within the branch, and use your own versioned contract ID
   and typed fields. Core does not know what a label, SID, VNI, VPN, or
   proprietary wrapper means. The layer `label` is presentation-only and is
   excluded from equality, hashing, continuity, and structural change
   detection.
4. Return one `ForwardingPacketTransition` whose `before` matches the request
   and whose `after` is the actual plug-in-declared result. Choose the
   normalized disposition (`continue`, `deliver`, `drop`, `punt`, `replicate`,
   or `unknown`) from device semantics and attach explanation/evidence. A
   `continue` result is non-terminal and names its next forwarding object. Any
   other disposition is terminal for that linear branch and supplies no next
   object or lookup context.
5. If size matters, declare both `ForwardingSizeObservation` and
   `ForwardingMtuConstraint` using the same opaque `basis_contract_id`. Core
   performs comparison only; your plug-in owns overhead, effective MTU,
   fragmentation, PTB/ICMP behavior, and the final disposition.
6. Have the coordinator call `validate_forwarding_step_result()` before
   accepting the result. It checks the request step and packet-before state and
   retains exact user steering rule/candidate coupling without interpreting
   the candidate.
7. Test complete continuity, incomplete packet size or policy-scope evidence,
   exact cycle identity, and the independent step/hop/recursion budgets with
   the helpers in `route_trace_core.py`.

Treat every request object as read-only. Core keeps an authority snapshot and
passes your hook a separate copy; forwarding step packet state and steering
rules are deeply detached. Outputs are validated against the untouched core
snapshot, so changing a request's IR, step/member identity, packet state, or
steering rules inside the hook cannot authorize the changed result. In
particular, only a rule present in the caller-authorized snapshot may justify
`USER_FORCED`.

Do not encode push, swap, PHP, SR behavior, or decapsulation only in
`action_label` or `resolution_text`; the before/after packet states are the
machine-readable result. A removed outer layer with an inner layer retained is
valid and lets core represent nested tunnels without protocol inference.
Adding or removing that outer layer does not by itself mark every retained
inner layer as moved; `moved` means relative order among retained layers
changed. The structural diff's `complete` flag is false when either packet
identity is incomplete, so an empty diff is not overstated as conclusive.

`ForwardingSteeringRule` is user-supplied counterfactual input. Core
exact-matches its target step and optional expected packet snapshot, resolves
one highest-priority rule, and preserves actor/rule provenance. A forced
transition must be `origin=user_forced` and must never replace observed
reachability. Normal device policy remains `origin=node_plugin`.

The public types and core helpers are executable and covered by
`tests/test_packet_trace_core.py`. The generated demo evaluates its declared
packet cases through those generic helpers; current case counts and fixture
details live in the [demo guide](../demo/README.md#generated-mock-dumps).
This is not yet a production coordinator that discovers and calls
`resolve_forwarding_step()` for every installed node. See
[Packet state, transitions, and MTU](plugin-contract.md#packet-state-transitions-and-mtu)
for the normative rules.

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

Set an executor's `identity_complete=True` only after all cycle-relevant typed
state is present. The compatibility field defaults to false. Repeating the
same opaque key while identity is incomplete remains a repeated observation,
not proof of a cycle; core still applies hop and recursion limits.

Keep a policy-blocked candidate in output with its explanation. It is an
intentional exclusion, not a failed physical link. Test at least an exact
scope match, a known non-match, an incomplete-scope non-match, a
non-applicable class, an unknown class, an exact recursive or cross-node
cycle, a legitimate changed-state revisit, a separate hop-limit result, a
transit start distinct from the traffic source, and a return path that reaches
the source without revisiting that start.
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

For the repository example, also keep the compact runtime-v2 corpus and its
standalone normative vector synchronized:

```text
python -X utf8 -m rsl_demo_generator --write-ingestion-conformance-corpus path/to/runtime-v2-ingestion-conformance.tgz
python -X utf8 -m rsl_demo_generator --verify-ingestion-conformance-corpus path/to/runtime-v2-ingestion-conformance.tgz
python -m unittest tests.test_ingestion tests.test_capability_executor tests.test_plugin_composition tests.test_capability_router tests.test_relationship_projection_materialization tests.test_relationship_projection_ingestion tests.test_consistency_materialization tests.test_consistency_ingestion tests.test_revision_world -v
python scripts/run_topology_federation_gate.py
python -m unittest discover -s state-dump-generator/tests -p "test_runtime_v2_vectors.py" -v
```

The focused topology gate also executes the core-owned browser contract and
JavaScript tests, so Node.js 18 or newer and `npm` must be available. Every
phase has a 300-second deadline and a fresh bytecode cache; timeout cleanup
terminates that phase's process tree instead of leaving plug-in test workers
running.

The archive is deliberately compact. Its status member executes through the
current example parser and core ingestion coordinator. It also carries text,
CTF, malformed, unsupported, identity, relationship, and uncertainty vectors
with an `execution_stage`/`support` label. Those labels are normative: this
repository does **not** claim a built-in CTF decoder, and the CTF cases require
an explicitly supplied core `TraceDecoder`.

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

The validator also does not execute core runtime v2. Exercise
`IngestionCoordinator` and at least one core `/v1/workspace` request in the
plug-in's integration suite. If a precomputed-fixture plug-in exposes the
compatibility `plugin.runtime`, add a separate smoke test that enters
`runtime.open(input_path)`, calls `validate_runtime_session()`, exercises every
non-`None` provider, and proves the context closes its resources. Then run the
core command against that input.

Common failures:

| Message | Fix |
|---|---|
| `entry-point target must be ... instance` | Export `plugin = MyPlugin()`. |
| `core_api_version ... does not match` | Build against the installed core API. |
| `requires an override` | Implement the advertised hook or remove the capability. |
| `has no parser_kind` | Set `InputParserKind` on every new `InputSpec`. |
| `does not declare ...` | Add the matching standard capability. |
| `describe() must be deterministic` | Build one immutable schema without clocks, randomness, or input state. |
| `does not expose runtime.v1 and does not implement the standard core-ingestion parser contract` | Export a real `AnalyzerPlugin` instance with `manifest`, `describe()`, `probe()`, and `locate_inputs()`; use runtime.v1 only for a tested precomputed fixture. |

## Definition of done

A first plug-in is ready for review only when:

- [ ] installation and entry-point discovery work in a clean environment;
- [ ] the plug-in package type-checks against the installed core's PEP 561
  surface;
- [ ] the generic validator prints `OK`;
- [ ] empty and missing input return a report/diagnostic rather than raising;
- [ ] every selected input has explicit parser dispatch;
- [ ] every emitted type is declared in `PluginSchema`;
- [ ] keys are typed, stable, and collision-safe;
- [ ] status/outcome/effect are not inferred by core or browser code;
- [ ] observations and events carry evidence and honest quality;
- [ ] failed events do not mutate state unless device semantics prove a change;
- [ ] every advertised optional capability passes through
  `PluginCapabilityExecutor` in a golden test, including its over-budget or
  malformed-output case;
- [ ] every revision relationship declaration uses existing base-world
  endpoints, a primary-schema relationship type, a complete no-removal patch,
  and evidence from the admitted revision;
- [ ] every emitted connector claim names a declared policy, points to an
  emitted or world-visible local resource, preserves typed arguments, and has
  matched/unresolved/ambiguous plus budget-completeness coverage;
- [ ] golden tests cover applicable bad-input and temporal edge cases; and
- [ ] no plug-in-specific branch was added to core or the browser.

For every ordinary parser plug-in:

- [ ] core-owned runtime v2 can inventory a representative input and serve its
  normalized `/v1/workspace`;
- [ ] malformed or over-budget discovery/parser output fails closed; and
- [ ] unsupported temporal, topology, and route providers remain unavailable.

If a precomputed-fixture plug-in also supplies a compatibility input session:

- [ ] `plugin.runtime.capability_id` equals
  `router_dump_analyzer.runtime.v1`;
- [ ] `open(input_path)` yields a valid non-web session and closes it once;
- [ ] every unsupported optional provider is explicitly `None`; and
- [ ] both installed-name and direct-module loading are smoke-tested as
  applicable.

After this passes, use the relevant advanced sections of
`docs/plugin-contract.md` for reducers, temporal correlation, dashboards,
topology, forwarding, and federation.
