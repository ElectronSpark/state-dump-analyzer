# State Dump Generator

State Dump Generator is a standalone, local scenario studio for creating
temporal router state dumps. Draw the physical situation you want to reproduce,
schedule what each router observes, and export one dump per router inside a
deterministic assembly.

It is intentionally independent from Router State Lab, the demo, and analyzer
plug-ins. It uses only Python's standard library at runtime and does not import
or invoke analyzer code.

> [!IMPORTANT]
> A saved authoring project and a generated dump are deliberately different.
> The project JSON is private ground truth: it can contain the supposed physical
> topology, canvas positions, propagation intent, and all planned changes.
> Generated node dumps contain only that router's final status and node-local
> history. They never contain the physical topology, private medium IDs,
> scenario, oracle, propagation plan, or global participant list.

Router State Lab keeps its future demo authoring source at
[`../demo/router-state-lab-default.scenario.json`](../demo/router-state-lab-default.scenario.json).
That file is an ordinary save from this tool. This package can edit, validate,
preview, and compile it, but it still does not depend on or invoke the analyzer,
demo, or any plug-in. The demo crosses the boundary in the other direction by
reading the saved JSON with its own standard-library data adapter.

## Quick start

Python 3.12 or newer is required. The included Conda environment is the easiest
way to run the editor.

### Windows

From this directory:

```powershell
.\launch.ps1
```

The launcher finds Conda in `PATH` or a normal per-user Anaconda/Miniconda
installation, then creates the environment automatically when it does not
exist. A Command Prompt wrapper is also available:

```bat
launch.cmd
```

To choose another port or avoid opening a browser:

```powershell
.\launch.ps1 -Port 8877 -NoBrowser
```

### Linux or WSL

```bash
./launch.sh
```

Like the Windows launcher, `launch.sh` creates the
`state-dump-generator` Conda environment when it is missing. It does not open a
browser by default. Open
[http://127.0.0.1:8770](http://127.0.0.1:8770), use
`./launch.sh --open` to open it automatically, or use
`./launch.sh --port 8877` to select another port.

The editor is unauthenticated and deliberately refuses non-loopback bind
addresses. It is for local authoring, not network deployment.

## Author a scenario in the web editor

The editor follows the familiar GNS2 pattern:

1. Drag routers, hosts, switches, and shared media onto the canvas.
2. Connect objects and name the router-side ports.
3. Move the time cursor to when a change should occur.
4. Add, edit, or remove a node-local event. Choose whether it updates that
   node's final snapshot.
5. Optionally preview and apply best-effort propagation. Adjust the targets,
   delay, jitter, and outcome before accepting the generated observations.
6. Validate the project, save its JSON, and generate the dump assembly.

Saving preserves schema-valid identifiers and references exactly, including
`+`, `@`, and `~`. Identifiers contain 1–256 characters, start with an ASCII
letter or digit, and then use letters, digits, or `_.:@/+~-`. Invalid or
overlong identifiers produce an error and leave the project unsaved.
Seeds are nonnegative exact integers. Store seeds above `9007199254740991` as
decimal strings; opening and saving preserves their value without JavaScript
number rounding. Invalid seeds produce an error instead of being clamped.
Generating a dump exports derived evidence and preserves the unsaved-project
flag. Save the source JSON to mark authoring edits saved; a generated TGZ cannot
replace that source file.
Pending New/Open requests cannot replace later edits, undo history, or a newer
project load. The latest request wins only while the current project remains
unchanged; stale responses are discarded.

To work on the bundled Router State Lab scenario, click **Open** and choose
`demo/router-state-lab-default.scenario.json` from the repository checkout.
That saved file, rather than a generated TGZ, is the durable source for future
demo generations.

Changing physical truth does not silently pretend that all routers learned the
change at once. Observations are separate temporal events, so a link can be
physically down while one router still reports a neighbor as up. Events can be
local, delayed, suppressed, partial, duplicated, or explicitly failed.

The final snapshot is calculated by replaying each node's status-changing
events through the capture time. Editing an event in the past therefore changes
the reconstructed history while later events still determine the latest state.
An attempted event may also be retained as a log without changing the snapshot.

Omitted snapshot flags default to **false** for `log`, `log-only`, and `clock`
events, and **true** for other node-local kinds. Underscores in kind names are
equivalent to hyphens. Explicit `update_snapshot` takes precedence over the
legacy `update_final_state` alias; opening, editing, and saving retain that
decision. Failed events still do not update snapshots unless `apply_on_failure`
is enabled. A clock event is a local history record; the node's `clock` object
sets the offset actually applied to exported timestamps.

An event's resource type defaults to `resource`, never its event kind or target
type. Explicit `resource_type`, then `resource_kind`, then the payload's
`resource_type` take precedence. The editor preserves these rules and lets the
compiler supply the default log message when no message was authored.

## Command-line workflow

The commands in this section assume the current directory is
`state-dump-generator/`. Install the package in a Python 3.12 environment:

```bash
python -m pip install -e .
```

Create a blank authoring project:

```bash
state-dump-generator new lab.json
```

A blank project has no topology and intentionally fails validation. Before
generating, edit `lab.json`: replace `"nodes": []` with at least one
dump-producing router, keeping the other generated fields. For example:

```json
"nodes": [{"node_id": "r1", "kind": "router"}]
```

Alternatively, use the browser editor below to open `lab.json`, add a router,
and save the project. Then validate the saved, authored project:

```bash
state-dump-generator validate lab.json
```

Generate an assembly with one node dump per router:

```bash
state-dump-generator generate lab.json --output lab-state-dumps.tgz
```

Path notices and errors preserve Unicode on UTF-8 consoles. On legacy console
encodings, only unrepresentable characters are displayed as backslash escapes;
the actual file names are unchanged. JSON reports use JSON-safe ASCII escapes
and preserve their original string values when parsed, including non-BMP text.

Run the browser editor:

```bash
state-dump-generator serve --open
```

The module form is equivalent:

```bash
python -m state_dump_generator serve --port 8877 --open
```

`new` refuses to overwrite an existing file unless `--force` is supplied.
`validate` uses these exit codes and output streams:

| Exit code | Output | Meaning |
|---:|---|---|
| `0` | JSON report on stdout | The loaded, normalized project passes validation; warnings may still be present. |
| `1` | JSON report on stdout | The loaded, normalized project fails semantic validation, such as having no dump-producing nodes. |
| `2` | Usage/error text on stderr, no JSON report | An argument, path/read, JSON/root, or model-construction error prevented validation. |

`generate` validates before writing and replaces its
regular-file destination atomically. It refuses an output path that traverses
a symbolic link or Windows junction.

### Validate, preview, and compile the canonical demo save

The editor obtains physical state from the generator's Python replay using
`POST /api/scenario/preview` with `view: "physical"` and `at_time_ns`. This
bounded view returns one state per medium and does not construct node histories.
It is private authoring data. Reconstruction and the canvas use the same state
precedence and event ordering, including exact timestamp/order integers.
While a preview is pending or unavailable, the canvas shows unknown state;
responses for an older cursor or edited project are discarded.

From the Router State Lab repository root, these PowerShell commands are
copy-paste ready:

```powershell
python -m pip install -e .\state-dump-generator
python -m state_dump_generator validate .\demo\router-state-lab-default.scenario.json
python -m state_dump_generator serve --open
```

The last command starts the studio. Click **Open**, select the canonical JSON,
and use the scenario-time control to preview physical state and scheduled local
observations. Stop the server with `Ctrl+C` when finished.

To compile the authoring save into the independent tool's small neutral
assembly:

```powershell
python -m state_dump_generator generate `
  .\demo\router-state-lab-default.scenario.json `
  --output .\artifacts\router-state-lab-default.node-dumps.tgz
```

This output intentionally does not contain Router State Lab's full-scale
filler or plug-in projections. To generate and launch the comprehensive demo,
use its separate materializer and core launcher:

```powershell
python -X utf8 -m rsl_demo_generator `
  --output .\demo\fixtures\router-state-lab-demo.tgz
.\scripts\launch_demo.cmd -NoBrowser
```

The canonical timeline starts at `2025-10-05 16:00:00 UTC`. Useful preview
boundaries include `+30 s` (route creation), `+90 s` to `+108 s` (physical
failure followed by asymmetric, stale, and failed observations), `+180 s` to
`+304 s` (local detach and reattach), `+420 s` to `+535 s` (delayed Ottawa
failure and recovery), and `+610 s` (the final next-hop update). See the
[demo guide](../demo/README.md#past-time-reconstruction-checkpoints) for exact
node and resource expectations.

## What is in a saved project?

The authoring JSON is a versioned, generator-owned format. Its main concepts
are:

- **Objects** — routers that produce dumps plus hosts, switches, and shared
  media used to express physical intent. Canvas positions are authoring data.
- **Physical links** — endpoint and port pairs with an initial state. Their
  status can change over scenario time.
- **Node-local events** — an observation time, observing router, subject,
  action, outcome, structured payload, optional source-log text, and whether
  the event is replayed into final state.
- **Propagation intent** — target scope, delay, jitter, cadence, and outcome
  used to schedule editable observations from a selected event.
- **Capture time** — the latest point replayed to produce each router's final
  snapshot.

Every event has stable identity so it can be edited or removed without
rewriting unrelated history. The saved project is the source of truth for
regeneration; do not send it to the analyzer as though it were a router dump.

### Attachment export boundary

An attachment can hold private editor metadata and separately declare the
node-local evidence that may enter its router's dump:

```json
{
  "node_id": "r1",
  "port_id": "xe-0/0/0",
  "properties": {
    "canvas_note": "authoring-only",
    "supposed_failure_domain": "west"
  },
  "node_local_observation": {
    "resource_id": "interface:r1-xe-0/0/0.310",
    "resource_type": "virtual-interface",
    "observed_state": "up",
    "properties": {
      "interface_name": "xe-0/0/0.310",
      "subnet_prefix": "192.0.2.0/31",
      "vlan_id": 310
    }
  }
}
```

Only `node_local_observation` is eligible for interface snapshot and propagated
physical-observation records. Attachment-level `properties` stay in the saved
authoring project and private preview; the simulator never copies them into a
node dump. This is true even when `node_local_observation` is absent. The
top-level attachment `resource_id` (or legacy `local_resource_id`, then the
port ID) is retained only as the fallback identity of that node's local
interface record. Top-level `properties` and `observed_state` are not promoted
into node-local evidence.
Unqualified fallback ports gain an `interface:` prefix; already-qualified
ports such as `interface:xe0` retain their identity through browser saves.

Existing schema-v1 saves can still be opened, but authors must move every value
that should cross the dump boundary into an explicit
`node_local_observation`. Saving writes that explicit envelope; it does not
silently reclassify authoring metadata as router evidence. The envelope is
neutral generator JSON and does not depend on analyzer or plug-in types.
Forbidden authoring keys are rejected recursively inside export-eligible
values. An exact private medium ID is rejected when it appears in any
identity-bearing field: built-in fields and plug-in-defined `*_id`, `*_ids`,
`*_key`, or `*_keys` fields all participate. The same ordinary text in a
non-identity note is not treated as topology identity.
Validation also checks the resolved local event resource identity, including
`subject` and `target_id` aliases, before compilation.

## Best-effort propagation

The generator is not a protocol emulator. Propagation is a general scheduling
aid that turns an initiating change into proposed node-local observations.
Review the preview, then keep, edit, delay, fail, or remove each proposed event.
That makes successful convergence and intentionally broken behavior equally
expressible.

The editor includes reusable starting patterns:

| Pattern | What it helps model |
|---|---|
| Clean link flap | Physical down/up with converged observations |
| One-sided detection | Only one endpoint notices a change |
| Delayed convergence | Different routers learn the same change later |
| Stale neighbor | Physical and reported adjacency disagree |
| Failed update | A logged attempt that does not change final state |
| Next-hop change | Dependency replacement and route churn |
| Node restart | Withdrawal and restoration burst |
| Clock skew | Bounded differences in local event timestamps |
| Log gap | Missing node-local evidence |
| Partial multi-access failure | One participant or member lags behind |

Because generated observations remain ordinary editable events, patterns can be
combined. For example, apply a link flap, suppress one endpoint's propagation,
delay a transit node, and turn one route update into a failed attempt.

### Capture horizon and cadence

Propagation preview and **Apply propagation** use the same generator-owned
Python scheduler as compilation. The browser does not independently choose
targets, cadence, jitter, or outcomes. The local editor endpoint
`POST /api/scenario/propagation` accepts `{ "scenario": ..., "event_id": ... }`
and returns editable node-local events. Preview is bounded to 512 observations and a
conservative 4 MiB response budget; select fewer targets when it exceeds either
bound. The generator remains standalone and uses no analyzer or plug-in code.

Every explicitly attached interface on a selected node receives its own
observation, even when several interfaces share one medium. They share that
node's scheduled time and outcome and have distinct history IDs. A declared
LAG, member, or subinterface is updated only when it is itself an attachment;
the scheduler does not infer effects on other parent/member resources. The
partial multi-access pattern likewise addresses local attachment identities,
never the private medium's name or ID. Preview is limited to 512 observations,
so multiple attachments count separately toward its allocation budget.
Successful carrier observations replace `oper_status` from the attachment's
starting properties with the newly observed state while preserving other local
properties. Failed or stale observations leave the previous state unchanged.

Validation computes the latest possible generated observation using the actual
eligible target set, delay, absolute jitter bound, and cadence:

- `parallel` schedules every target from the same base delay;
- `serial` advances each target by another base-delay slot (at least 1 ms);
- `waves` advances each pair of targets by half a base-delay slot (at least
  1 ms).

When that conservative horizon is later than `capture_time_ns`, validation
returns a warning rather than changing the scenario. Observations after capture
remain in the authoring plan but do not enter final snapshots or exported
history. If capture time is omitted, the loader chooses a default at least one
second beyond the calculated horizon. Explicit capture time always wins, which
lets an author deliberately test incomplete propagation.

The editor preserves an imported explicit capture time, including when saving
or validating the project. New projects leave capture automatic so the Python
loader chooses the horizon. Applying propagation may retain generated child
observations after an explicit capture: validation warns, and those children
remain in the authoring project but are excluded from the exported snapshot
and history. An ordinary authored event after capture is still an error.

Omitted propagation targets request inference from `target_mode`; an explicit
empty target list requests no observations. Opening and saving preserves this
distinction, nanosecond delay/jitter, per-node outcomes, and inherited parent
outcomes. Selecting **Propagation attempt fails** forces failed, non-mutating
observations regardless of the outcome control. Nanosecond coordinates and
source-order fields must be integers; fractional values are rejected.
The event-time editor displays exact decimal seconds with nanosecond precision,
so opening and saving an event without changing its time preserves its timestamp.

Clock `offset_ns` and `uncertainty_ns` also preserve exact integer values,
including the `clock_offset_ns` and `clock_uncertainty_ns` import aliases.
Use decimal JSON strings beyond JavaScript's safe integer range
(`-9007199254740991` through `9007199254740991`); the editor rejects larger
numeric literals rather than rounding them. Offsets may be negative, while
uncertainty must be non-negative. Fractional clock coordinates are rejected.

## Generated archive layout

`generate` writes a deterministic outer TGZ:

```text
lab-state-dumps.tgz
├── manifest.json
└── nodes/
    ├── router-a.tgz
    ├── router-b.tgz
    └── ...
```

The outer manifest identifies the generated node archives and their checksums.
It contains no topology or scenario model, private authoring medium IDs, or
global participant list. Each nested node TGZ contains:

```text
manifest.json
status/final-state.jsonl
status/final-state.txt
logs/history.jsonl
```

`status/final-state.*` is the final node-local snapshot at capture time.
`logs/history.jsonl` is the timestamp-ordered local history used to reconstruct
past status. The text status file is convenient for inspecting or adapting the
output; JSON Lines preserves structured values.

Every exported timestamp uses the node's own clock domain: `captured_at_ns`,
history `timestamp_ns`, and final-state `updated_at_ns` all include that node's
configured offset. The private editor timeline is not exported as an absolute
clock oracle. History rows also carry `source_sequence`, which preserves the
author-defined order of changes that share one local timestamp.
History rows also retain an explicit `status` when an observation declares
one, even if its properties do not contain a status field.

The generation boundary rejects forbidden authoring/oracle keys recursively
and also rejects a private physical-medium identifier if it is copied into an
export-eligible node-local identity field, including a plug-in-defined
`*_id` or `*_key`. A generated dump therefore contains only the attachment
evidence declared in
`node_local_observation`, such as an interface, VLAN, or subnet observation,
but not attachment-level authoring metadata or the editor's physical medium
identity. The writer produces stable ordering, ownership metadata, and gzip
headers so identical projects generate identical bytes.

Automatic propagation inherits a failed, stale, suppressed, or dropped parent
outcome unless the author explicitly overrides the outcome for a target. This
prevents a failed initiating update from silently becoming a successful remote
state change. The editor remains a scheduling aid rather than a protocol
emulator.

Project inputs, static assets, and output targets are checked lexically before
path resolution; symbolic-link and junction traversal is refused at those file
boundaries. The local HTTP editor bounds body reads and closes a connection
when rejecting a POST before consuming its body, so HTTP/1.1 keep-alive cannot
reinterpret unread bytes as another request.

## Independence and integration

This project owns scenario authoring, generic propagation scheduling, replay,
and its neutral output format. It does not know how Router State Lab plug-ins
name resources or interpret vendor protocols. Conversely, the analyzer core
does not depend on this generator.

A consumer can read the neutral JSON Lines directly or implement a separate
adapter for its own dump ingestion format. Router State Lab's demo does exactly
that: its standard-library adapter reads the canonical save through the JSON
file boundary, derives shared domains only from repeated node-local attachment
evidence, and its separate materializer adds deterministic scalable filler and
plug-in projections. The demo records the exact save digest in its assembly and
node manifests, alongside a fingerprint of its independent materializer and
demo plug-in code, so launch preparation invalidates a TGZ after either the
save or the interpretation logic changes.

Any adapter remains outside this package. Physical ground truth, private medium
IDs, and global participant lists must not be copied into the resulting node
dumps.

## Development

The installed `state_dump_generator` package includes a `py.typed` marker and
one `.pyi` file per Python module, so IDEs and strict type checkers can consume
its public model, compiler, replay, archive, and server interfaces without a
separate stub package. Repository-wide stub regeneration and validation are
owned by `../scripts/export_type_stubs.py`; the generated declarations remain
a static projection of the executable implementation.

From the repository root, check its strict installed-package consumer with:

```text
python -m mypy --python-version 3.12 --strict --no-incremental state-dump-generator/tests/typing/generator_public_api.py
```

Run the standalone tests from this directory:

```bash
python -m unittest discover -s tests -v
```

The test suite verifies deterministic archives, per-node isolation, recursive
rejection of authoring truth, safe archive paths, the local web API, and the
absence of analyzer/demo/plugin runtime dependencies.

Browser conformance tests execute the editor's JavaScript with Node.js and
compare it with the Python implementation. CI installs Node.js 22 and fails
before testing if it is unavailable; these checks are required on both Windows
and Linux. Local runs without Node.js skip the browser-specific tests.
