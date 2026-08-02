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
| `http://127.0.0.1:8765/docs` | Interactive core API documentation |

The topology page links to the corresponding individual-node workspace. The
node page links back to the fabric while preserving the available
reconstruction context.

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
in the manifest to `http://127.0.0.1:8765`, avoiding browser CORS differences
between integrated and split-process operation.

The development server accepts `--host`, `--port`, and `--backend` after npm's
`--` separator. For example, with a backend on port 8876:

```powershell
npm --prefix frontend run serve -- --backend http://127.0.0.1:8876 --port 4174
```

Use `npm --prefix frontend run check` to validate the manifest, local asset
references, JavaScript syntax, single-source frontend boundary, and the
framework-free helper tests under `frontend/tests/`, without installing
packages. `durable_review_controller.test.mjs` executes timeout/abort,
pagination, stale-connection, mutation-lock, ambiguous-result reconciliation,
atomic watermark restart, confirmed-marker replacement, persistent-journal
reload/tamper/capacity recovery, and blocked-storage behavior against injected
browser primitives. Source-text checks cover module wiring and HTML ownership
only; production behavior is exercised through imported functions.
`timeline_models.test.mjs` imports the same closed event outcome, state-change,
effect-status, and mark classifiers used by `app.js`; those timeline decisions
therefore have direct behavioral tests instead of depending on source-text
inspection of the page entry point.
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
