# Router State Lab core frontend

This directory contains the browser application people see when they run
Router State Lab. The normal demo launcher serves it together with the API, so
most users do not need to run anything in this directory.

The frontend is part of the analyzer core. It owns all generic HTML pages,
JavaScript, CSS, page routes, and their deployment manifest. Python does not
contain or construct page templates; the optional core web adapter reads
`frontend-manifest.json` and hosts this distribution.

Device plug-ins do not copy or replace these files. They contribute validated
resource icons, labels, dashboards, table layouts, source-record controls,
topology projections, and route presentation declarations that this frontend
renders through core-owned components.

## Pages

With the normal server on port 8765:

| URL | Page |
|---|---|
| `http://127.0.0.1:8765/` | Canonical multi-node topology, route trace, and route-table workspace |
| `http://127.0.0.1:8765/topology` | Compatibility alias for the topology home |
| `http://127.0.0.1:8765/node` | Individual-node timeline, resources, correlations, and dashboards |
| `http://127.0.0.1:8765/analysis` | Workspace-scoped private-analysis run, evidence report, and explicit human proposal-review workflow |
| `http://127.0.0.1:8765/manage` | Durable catalog, imports, sessions/snapshots, revision inspection, policy/retention, and server status |
| `http://127.0.0.1:8765/docs` | Interactive core API documentation, available only when the loopback server is started with `--expose-api-docs` |

The topology page links to the corresponding individual-node workspace. The
node page links back to the fabric while preserving the available
reconstruction context.

The static pages do not advertise `/docs` because API documentation is closed
by default. Operators who deliberately enable `--expose-api-docs` can open the
URL above directly; enabling it is a server policy decision, not a browser
control.

The private-analysis page deliberately does not accept scope, identity, run,
or query values in its URL. Tenant, project, workspace, principal, opaque run
ID, and an unsent query exist only in the live page and JavaScript state. The
page does not use browser storage, caches, service workers, or navigation
state. After submission, the run, query, and validated outcome are durable
server-side records. Create is sent once with one stable idempotency key;
execute and cancel are sent once with the latest strong ETag, and uncertain
outcomes are reconciled only with read-only polling. A cancellation attempt is
locked to one workspace generation and opaque run ID before its version
refresh, so parallel calls, later versions, and caller retries cannot replay
the POST. A report is exposed only when its run ID and lossless version exactly
match the current cleanup-complete terminal run.

Proposal review is deliberately separate from report rendering. Proposal text
is read-only; the page requires an acknowledgement and never pre-fills a
promotion target from model output. A reviewer either rejects the exact
digest-pinned proposal or authors independent annotation/manual-correlation
JSON. The controller takes run, result, and proposal authority only from its
validated frozen report, sends one conditional/idempotent decision mutation,
and accepts decision receipts only when both digests match that same report.
After an ambiguous decision response it refreshes durable state read-only for
display but disables review until reload; a same-proposal receipt is not proof
of the attempted rationale, disposition, or target. A durably pending promotion
exposes a separate **Resume pending promotion** button. List/detail reads and
repeated decision requests never resume work, concurrent clicks share one
attempt, and another mutation always requires another explicit click. An
ambiguous recovery performs one read-only reconciliation and re-enables the
button only when the same frozen report and durable decision remain exact; the
refresh itself never sends another recovery POST.

### Manage durable data

On `/manage`, connect an authorized tenant/principal, select a project and
workspace, then use Projects, Data & revisions, Imports, Sessions,
Administration, or Server status. The startup demo is not automatically an
imported fixture. Read-only identities can browse and inspect; changes require
write capability, policy/retention requires admin, and process-wide diagnostics
requires the separate instance-operator role. The browser's identity fields
are not authentication and are never saved in URLs or browser storage.

Imports send raw file bytes and an optional node identity hint to the same-origin
control plane, then show exact probed parser candidates and paginated processing
events. Session tools select
published revision members and can freeze immutable snapshots. A snapshot
protects its parent session from deletion. Project/workspace rename/delete,
plug-in installation, and deployment configuration editing are not supported.

**Inspect analysis** opens the dedicated inspector inside `/manage`. It pages
resources, events, relationship observations, and materialized findings for one
explicit member of a revision/session/snapshot selection. Its exact-nanosecond
moment controls reconstruct resource/relationship observations; event ranges
are inclusive and independently selected. Findings are not rerun. The response
vector/default-member digest guards later queries; use **Reload current
session membership** only to deliberately accept a changed live selection.
Before/after revisions of the same node remain different members.

This inspector does not replace the startup runtime or rebind the existing
Fabric/Node pages. Advanced route/topology execution is unavailable here;
relationship observations are not a newly inferred network graph. The UI
requests 50-row pages from the bounded
[durable analysis API](../docs/api-contract.md#scoped-durable-analysis-query).
Search scans only safe visible projections, while verified durable loading
still returns a detached dataset per request; full-archive index/latency
improvements are not implied by the paged UI.

Related review/private-analysis links open the existing pages without passing
identity or saving it in browser storage; connect again using the displayed
scope. Node review still annotates the startup input. Private evidence analysis
selects published revisions after connecting. Following a link does not submit
data or start a model run.

Administration shows only a read-only deployment ownership/capability summary.
Policy changes require a fresh version and explicit confirmation. Retention
requires a fresh, untruncated bounded preview of the exact request, an
acknowledgement, and the typed workspace ID; editing cutoffs clears approval.
The preview is advisory, and execution rechecks live protection. Ingestion
retention settings remain deployment-owned. An uncertain write blocks further
writes until the user inspects state and reconnects; this page does not persist
a retry journal or automatically retry mutations.

Import following refreshes every 2.5 seconds while processing, unless disabled,
hidden, terminal, or awaiting selection. Server-status polling is separate,
opt-in every 10 seconds while visible, and evaluates health payloads rather
than treating HTTP 200 as healthy. Ordinary requests time out after 30 seconds;
upload admission after 120 seconds. The API-only `router-dump-server` does not
host this page: use the integrated analyzer or the same-origin frontend proxy.

### Select a reconstructed topology moment

After the first successful fabric reconstruction, the **Reconstructed status**
bar appears immediately above the link-status graph. It shows two different
things while a new time is being selected:

- the cyan notch is the moment currently applied to the graph;
- the amber handle is the newly selected moment.

Click or drag the handle, or focus it and use the arrow, **Home**, and **End**
keys. Finishing the pointer or keyboard change submits a reconstruction after a
short debounce. The selector is disabled before the first successful
reconstruction and while a request is running.

Absolute mode uses the advertised UTC history bounds. Relative mode is an
offset axis ending at zero; one value is applied separately to each selected
node's projection watermark. It is therefore a capture vector, not a claim
that the node clocks are simultaneous. If the pending query controls switch
between absolute and relative bases, apply or restore that basis before using
the bar again.

## Develop the frontend separately

Node.js 18 or newer is required. No package installation is needed.

From the repository root, start the backend without integrated pages:

```powershell
.\scripts\launch_demo.cmd -ApiOnly -NoBrowser
```

Then, in a second terminal, run the dependency-free Node development server:

```powershell
npm --prefix frontend run serve
```

Open `http://127.0.0.1:4173`. The frontend server proxies the API paths declared
in the manifest to `http://127.0.0.1:8765`. With a concrete configured frontend
address, every proxied request must have exactly its matching `Host`, including
reads and requests without `Origin`; rewriting Host must not bypass the
backend's DNS-rebinding protection. For mutating requests with an
`Origin` header, the proxy requires exactly the configured frontend origin
and matching request `Host` before rewriting the origin to the backend origin.
Foreign, opaque `null`, duplicate, and mismatched sources are rejected before
forwarding. Use the exact displayed frontend URL: `localhost` and
`127.0.0.1` are not interchangeable authorities. No-Origin CLI requests with
the valid Host keep their absent Origin, and authentication, tenant/principal, conditional,
and idempotency headers still pass through to backend authorization.

The development server accepts `--host`, `--port`, and `--backend` after npm's
`--` separator. For example, with a backend on port 8876:

```powershell
npm --prefix frontend run serve -- --backend http://127.0.0.1:8876 --port 4174
```

For browser mutations, `--host` must name the concrete address used in the
browser URL. Wildcard listeners (`0.0.0.0` or `::`) cannot establish a trusted
browser origin and reject Origin-bearing mutations; they do not disable
backend authentication. This proxy is a local development tool, not a
production authentication gateway.

### Resource timeline navigation

The time ruler and Earlier/Later navigation stick below the main page header
while the resource lanes cross the top of the screen. They release at the end
of the lanes, before the selected-time footer and following sections. The
offset follows the main header's actual height, including wrapped navigation.

Zoom changes the visible time window, not the width of a giant scrollable
canvas. Use **Earlier** / **Later** directly above the lanes to move left or
right by 10% of the visible duration. The adjacent readout shows the window's
start and end; buttons disable at the capture boundaries. Panning preserves
the zoom, selected time, selected duration, and visible lanes.

Horizontal two-finger scrolling or Shift+wheel also pans. Click a resource
lane, event, timeline background, or Earlier/Later button to use the direction
keys: Left/Right pans time and Up/Down scrolls the lanes. Holding an arrow keeps
moving; horizontal repeats are frame-coalesced using the same bounded refresh
path as trackpad panning. Ordinary dragging still selects a duration. Text
fields, sliders, range handles, and the zoom/history toolbar retain their own
keyboard behavior; shortcuts do not intercept keys elsewhere in the page.
**Back view** / **Forward view** traverse zoom/pan history, while **Fit** shows
the complete capture again. The **Selected time** slider remains independent:
it changes the reconstructed moment, not the viewport position.

### Frontend checks

Use `npm --prefix frontend run check` to validate the manifest, local asset
references, JavaScript syntax, single-source frontend boundary, and the
framework-free helper tests under `frontend/tests/`, without installing
packages. `dev_proxy.test.mjs` uses short-lived local HTTP servers to verify
origin rejection, accepted-origin rewriting, and preserved request authority
and body; the servers are closed after the test. `durable_review_controller.test.mjs` executes timeout/abort,
pagination, stale-connection, mutation-lock, ambiguous-result reconciliation,
atomic watermark restart, confirmed-marker replacement, persistent-journal
reload/tamper/capacity recovery, and blocked-storage behavior against injected
browser primitives. Source-text checks cover module wiring and HTML ownership
only; production behavior is exercised through imported functions.
`timeline_models.test.mjs` imports the same closed event outcome, state-change,
effect-status, and mark classifiers used by `app.js`; those timeline decisions
therefore have direct behavioral tests instead of depending on source-text
inspection of the page entry point.
`private_analysis_controller.test.mjs` exercises private-analysis request
shapes, lossless ETag/version checks, stale response and scope-generation
rejection, one-shot mutations, read-only ambiguity reconciliation, bounded
single-flight polling, run-bound cancellation, strict report-envelope
acceptance, cleanup-aware terminal behavior, digest-pinned human decision
requests, one-shot review mutation, ambiguity reconciliation without replay,
and explicit pending-saga recovery. `private_analysis_contract.test.mjs`
checks the browser's closed discovery, run/report, and proposal-decision wire
contracts against the hosted page and manifest.
The same executable suite captures the actual `fetch()` initialization to
verify `Idempotency-Key` and `If-Match` propagation, and exercises current,
stale, and failed-refresh `409` reconciliation paths. Durable POST creation,
version-guarded PATCH/DELETE, and read-only report POST options are built by
tested helpers: empty or malformed idempotency/version tokens fail before a
request can be sent, and mutation ambiguity cannot depend on duplicated
header spelling at individual UI call sites. The tested scoped adapter then
binds tenant/principal headers and carries those helpers through the actual
transport; retryable failures and both conditional mutation methods are
exercised end to end with an injected `fetch` implementation. The unresolved
mutation journal gives distinct writes distinct operation identities while an
unchanged exact payload reuses its identity until reconciliation. The journal
is validated and persisted across reload, bounded per scope and globally, and
offers separate current-scope discard and warned all-scope reset actions.
Operation identities are checked across every UI scope sharing the server's
tenant/project/workspace review namespace, so a principal or revision change
cannot hide a colliding stored identity.
Annotation hydration reads every bounded page and probes the safety-cap
boundary under one audit watermark. It restarts once on concurrent mutation,
then fails visibly while preserving the last confirmed same-scope marker index
instead of installing a partial one. Every guarded asynchronous read checks its
immutable connection token both before and after the await.
