# Router dump analyzer design pack

This repository turns the product brief into an implementation-ready design for
a Python 3.12 server. It is intentionally generic: platform- and release-specific
archive discovery, parsing, correlation, consistency, and forwarding semantics
remain in versioned plugins.

## Run the local review demo

The repository now includes **Router State Lab**, a runnable FastAPI and browser
demo launched from one synthetic 100K outer TGZ. The scenario combines an
IS-IS underlay, SR-MPLS and SRv6 forwarding, EVPN routes, and plugin-defined
Forwarding Group, ETG/ETE, standalone DTE, Virtual Interface, Glue, and hardware
resources. It is designed for product and domain review: the timeline,
point-in-time resource tables, temporal correlation graph, consistency findings,
route explanations, archive inventory, and review notes are interactive, while
every fixture-only or missing capability stays visible.

### WSL / Linux (recommended)

Keep the repository on the native WSL filesystem rather than below `/mnt/c`.
On the first run, the bootstrap installs a checksum-verified, WSL-native
Miniforge distribution when Conda is not already available, creates the
`router-dump-analyzer-demo` environment, and runs the complete test suite:

```bash
cd ~/state-dump-analyzer
./scripts/bootstrap_wsl.sh
```

Launch the hard-coded packed 100K+ demo at `http://127.0.0.1:8765`:

```bash
./scripts/launch_demo.sh
```

The default launch now indexes the complete 125,000-matched-event, 100,000-resource
normalized corpus (including 274,998 temporal relationships and 219,998
relationship mutations). The loader streams the TGZ once and builds state and
lifecycle intervals lazily for only the resources a bounded query touches. In
the reference WSL workspace, a cold build is about 4–5 seconds and peaks below
0.9 GiB; hardware and filesystem caches will vary. Browser tables, event-log
rows, timeline lanes, and graph layouts are virtualized, while totals, event
density, range counts, and plug-in statistics are calculated from the full
corpus. Use `--review-projection` only when the small embedded projection is
intentionally desired.

The WSL launcher does not open a browser by default because Windows can reach
the WSL service through localhost. A different port and a fixture rebuild are
available when needed:

```bash
./scripts/launch_demo.sh --port 8876 --rebuild-fixture
```

### Windows / PowerShell

From PowerShell, create the Python 3.12 Conda environment and run its tests. The
`.cmd` wrapper also works on machines whose execution policy blocks local
PowerShell scripts:

```powershell
.\scripts\setup_demo.cmd
```

If the demo is already running, stop that process before rerunning setup; Windows
locks the installed launcher while it is in use. The wrapper enables UTF-8 for
older Conda versions, so repositories below Unicode paths are supported.

Then launch the demo (it opens `http://127.0.0.1:8765`; the former Splunk-facing
port is not used). The launcher generates the deterministic scale corpus,
browser projection, and packed TGZ when they are missing:

```powershell
.\scripts\launch_demo.cmd
```

Use a different port or avoid opening the default browser when needed:

```powershell
.\scripts\launch_demo.cmd -Port 8080 -NoBrowser
```

Force regeneration of the complete packed fixture when needed:

```powershell
.\scripts\launch_demo.cmd -RebuildFixture -NoBrowser
```

The equivalent manual commands are:

```powershell
& "$env:USERPROFILE\anaconda3\Scripts\conda.exe" env create -f environment.yml
& "$env:USERPROFILE\anaconda3\Scripts\conda.exe" run --no-capture-output -n router-dump-analyzer-demo router-dump-demo --fixture-archive samples\generated-scale\router-state-lab-100k.tgz --full-scale --open-browser
```

The demo deliberately does not accept arbitrary dump uploads or claim to decode
caller-provided archives. The hard-coded outer TGZ contains four nested container
dumps, each with CTF logs and one or more resource-status tables, plus the full
125K matched normalized-event corpus. By default the server indexes that
complete corpus directly from the TGZ; the embedded browser-sized projection remains available
through `--review-projection`. It inventories the raw container packs without
extracting them. Every timeline lane has one canonical resource;
an event selection, arbitrary point cursor, and horizontal-drag range remain
independent. Hover cards expose lifecycle/status duration and failed updates.
A selected range highlights intersecting events and intervals, groups its
matching normalized events at the start of the event log, and shows relationship
changes plus a supplemental endpoint diff. Exact range endpoints
can also be entered as decimal-second offsets, or adjusted with the draggable
**Start** and **End** borders; the band and its borders stay aligned when the
timeline is zoomed. Moving the pointer across a lane displays a vertical guide
through every lane with its exact offset tagged at the top, and compact labels
separate the plug-in-defined resource type from its layer. A dedicated event
density lane aggregates canonical normalized events into zoom-aware bins and
shows failure density without counting duplicated correlation-tree lanes. Its
high-resolution histogram uses 180 temporal bins per zoom unit, with no
independent resolution cap, so its bin count follows the timeline scale
directly. Timeline zoom itself has no application-defined upper bound; the
numeric scale control accepts any value at or above 1, and Ctrl-wheel zoom is
multiplicative. Density storage is sparse, so empty bins are not allocated.
Pressing **Esc**
clears the selected range, event, and
explicit point-in-time cursor while returning queries to capture time. The
**Lanes** chooser displays any
explicit resource subset or the selected resource and its current correlations;
plugin-defined relationship ribbons show how those correlations change across
time. Correlations can be shown as one combined temporal association lane or
as separate resource lanes with parent and association-period highlights. The
point-in-time correlation panel separates expandable outgoing
dependencies or owned targets from incoming dependents, while retaining the
plug-in-defined relationship type and exact source-to-target direction. Its
selected-moment tag is bound to the returned graph timestamp; while a new query
is pending, the prior graph is dimmed and cannot be mistaken for the new moment.
The focused graph uses three explicit columns for dependents, the selected
resource, and the resources it depends on or owns. The all-correlations view
arranges connected resources by dependency rank, omits unrelated isolated
resources with an explicit count, and temporarily isolates a resource's
immediate links on hover or keyboard focus. With no explicit resource focus,
the panel shows all time-valid correlations rather than silently choosing an
arbitrary resource.
Ctrl-click navigates between timeline events and normalized log rows; a
collapsed event mark targets its latest event, while a specific hover-list
entry targets that exact event. Ctrl-clicking a correlation resource only
navigates to it; clicking a timeline lane's left resource block expands or
collapses a recursive correlation tree beneath that lane. Tree nodes are lane
instances, so one canonical resource may appear under multiple parents and
each branch keeps independent expansion state. The left pane uses compact
Explorer-style rows with disclosure chevrons and continuous nesting guides.
Resource-kind glyphs come from optional, validated plug-in SVG path metadata;
missing or invalid metadata uses a generic core fallback. Ordinary clicks in
the point-in-time
correlation view do not navigate; its resource and relationship tags expose
details on hover or keyboard focus. Resource cards include the complete
selected-time normalized state and completeness information, so the correlation
view uses the full width without a persistent selected-object side panel. At the
end of the page, plug-in-defined
dashboard descriptors are rendered through common point-in-time statistics and
resource-table widgets. An Explorer-style tree index shows every available
module in display order, with branch guides and clear open/closed states.
Modules may be opened, closed, expanded, collapsed, moved
with buttons, or dragged into a new order; that layout remains in local browser
storage and can be reset to the plug-in defaults. The plug-in supplies resource
kinds, safe field paths, aggregates, columns, and initial open/collapse behavior,
but never injects HTML, CSS, or JavaScript. Open
**Review gaps** in the UI to prioritize the production work
and copy a review brief; selections remain in local browser storage only. API
endpoints and payloads are also visible at `/docs` while the server is running.

## Recommended architecture

Build a modular server with these boundaries:

1. A FastAPI control/API process accepts a dump and creates an immutable analysis revision.
2. A separate Linux worker safely inventories nested archives and runs Babeltrace 2.1 plus the selected proprietary plugin.
3. Plugins declare and emit all domain resources, derived resources, temporal relationship types, event correlations, findings, and forwarding objects. The core handles them generically and never invents domain semantics.
4. PostgreSQL serves temporal resource and relationship intervals; object storage retains original artifacts. Optional Parquet/DuckDB is an overflow and offline-analysis path, not a requirement at 100K records.
5. A thin browser client virtualizes lanes and uses WebGL for the timeline. The backend and all domain logic stay in Python 3.12; browser rendering necessarily uses TypeScript/JavaScript.

The most important correctness rule is that **a final snapshot plus forward-only
logs does not always determine the past**. Missing before-values, unsynchronized
clocks, and incomplete events must appear as `unknown` or `ambiguous`, never as
invented state.

## Contents

- [Architecture and library decisions](docs/architecture.md)
- [Plugin contract and lifecycle](docs/plugin-contract.md)
- [API payload contract](docs/api-contract.md)
- [Public sample-input catalog](docs/public-sample-catalog.md)
- [Reference Python protocol](src/router_dump_analyzer/plugin_api.py)
- [Sample input guide](samples/README.md)
- [Synthetic nested dump generator](scripts/generate_sample_bundle.py)
- [Packed 100K+ dump generator](scripts/generate_packed_scale_bundle.py)
- [Pinned public CTF 2 fixture fetcher](scripts/fetch_babeltrace_sample.py)

## Build the fixtures

Python 3.12 is sufficient; the fixture tooling has no third-party dependencies.

```text
python scripts/fetch_babeltrace_sample.py
python scripts/generate_sample_bundle.py
python scripts/generate_scale_fixtures.py --events 125000 --resources 100000
python scripts/generate_packed_scale_bundle.py
python -m unittest discover -s tests -v
```

The generated `samples/generated/node-a.tgz` contains three nested layer dumps,
multi-section status output, public and product-shaped synthetic CTF 2 traces,
synthetic domain-event exports, debug logs, codec-chain data, and protobuf
examples. Sibling files under `samples/generated/illustrative/` demonstrate the
full protocol/resource scenario, typed resource descriptors, resource lifecycle
and status intervals, temporal correlations, findings, dashboard summaries,
declarative dashboard modules, and route responses; they are not embedded in the
input archive.
The scale generator streams its output and creates a 125K-matched-event,
100K-resource fixture without checking the large generated files into source
control.
The packed generator compresses that corpus, four nested per-container CTF/status
dumps, and the review projection into
`samples/generated-scale/router-state-lab-100k.tgz`, which is the launch
script's hard-coded demo input.

This remains a design and conformance-fixture package plus a review demo, not a
production analyzer. The staged build order in the architecture document is
intended to prevent UI work from getting ahead of temporal correctness and plugin
contracts.
