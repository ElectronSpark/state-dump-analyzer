# Core management console implementation

Baseline committed and pushed: `1a5d98a` (2026-09-05).

The core owns this console. Plug-ins continue to supply device semantics and
validated presentations, not project management, authorization or HTML pages.
Each item requires executable tests and a real browser exercise before it is
marked complete. Mutations are explicit, scoped, bounded and never retried
automatically after an uncertain result.

## Implementation checklist

- [x] 1. Core Management navigation, explicit identity connection, permission
  discovery, clear disconnected/read-only states and bounded request helpers.
- [x] 2. Browse/create projects and workspaces with pagination, empty states,
  current-scope breadcrumbs and stale-response protection.
- [x] 3. Server status: readiness, queue/workers and errors; explicit refresh
  and optional bounded polling; instance-operator-only operational counters.
- [x] 4. Fixture/revision catalog: inspect provenance, versions, capabilities
  and publication state without dumping entire large datasets.
- [x] 5. Upload/import workflow: file admission, queue, progress, candidate
  inspection/selection, resume/cancel and actionable error states.
- [x] 6. Session lifecycle: create/rename/delete sessions, add/remove/replace
  revision members, inspect versions and create/browse immutable snapshots.
- [x] 7. Open a durable revision/session in the bounded read-only inspector without changing the
  global startup runtime or leaking another tenant's data; preserve explicit
  scope and identify unavailable plug-in capabilities honestly.
- [x] 8. Workspace administration: inspect/edit private-analysis disclosure
  policy with optimistic concurrency, explicit confirmation and permissions.
- [x] 9. Retention administration: advisory preview/completeness, explicit
  destructive confirmation, bounded execution and audit history.
- [x] 10. Deployment settings: display ownership and permission boundaries;
  distinguish read-only host configuration from editable workspace policy.
- [x] 11. Integrate durable review/private analysis navigation and document
  how browser startup input differs from the published revision catalog.
- [x] 12. Final browser regression, executable frontend/backend tests, public
  interface stubs and documentation drift check; record remaining defects.

## Deliberate boundaries, not pretend controls

No web endpoint currently provisions accounts/roles, installs arbitrary plug-ins,
changes listener/authentication configuration or restarts the host. These remain
deployment responsibilities, explicitly described in the console. Tenant admins
must not acquire instance-operator privileges. Project/workspace rename/delete
has no existing contract; the console does not invent destructive semantics for
containers holding immutable revisions. Session rename/delete is supported.

## Validation and discoveries

Validation used a separate loopback API and frontend proxy, a disposable
`management-validation` tenant, one small checked-in synthetic status fixture,
and no external/private model calls. The million-event demo was not republished
or regenerated. Destructive retention was not run against the user's data.

| Step | Executed validation |
| --- | --- |
| 1 | Browser disconnected/connected states; context tests pin exact read/write/admin/operator grants; client tests cover same-origin transport, stale reads, timeout ambiguity and write exclusion. |
| 2 | Created and selected a project/workspace in the browser. Actual-entry tests cover both card and dropdown selection, pagination selection outside quick-picker bounds, pending writes and old-scope controls. |
| 3 | Browser showed API-only mode, 2/2 healthy workers and operator-only diagnostics refusal for tenant admin. Polling is opt-in, visible-only and cancelled on navigation. |
| 4 | Browser opened published revision provenance and materialized findings. Executable tests prevent late detail reads from painting another scope/view. |
| 5 | Browser uploaded the synthetic fixture, manually selected its exact parser identity, followed publication, explicitly resumed a failed import and cancelled an awaiting-selection import. Tests cover raw Blob identity, optional node hint, safe upload headers, cancellation ETags and retryable resume. |
| 6 | Browser created/renamed a session, added a default member and created an immutable snapshot. Actual-entry tests exercise member save/remove with refreshed versions and protected-delete conflict without automatic retry. |
| 7 | Browser opened a published revision and moved the reconstruction slider to an earlier moment: later observations became absent. Backend tests cover same-node multi-revision members, snapshot/live-vector identity, cross-scope isolation, exact nanoseconds, resources/events/relationships/findings and a 1.25-million-event page. Actual-entry tests exercise explicit digest-conflict recovery. |
| 8 | Browser read and explicitly saved the disabled policy with its version; no disclosure scope was broadened. Tests cover all supported policy modes, role separation, stale versions and reconfirmation. |
| 9 | Browser previewed disabled retention, reviewed completeness, and verified execution remained disabled. Executable UI tests exercise input/confirmation gates and independent audit cursors; existing backend retention remains authoritative. |
| 10 | Browser inspected the read-only deployment/permission table and the distinction between tenant administration and instance operation. No host settings or credentials are exposed. |
| 11 | Browser followed Private analysis, independently connected the validation workspace, discovered the revision and saw policy-disabled run controls. No identity was transferred in links, and no model was invoked. Node review remains tied to startup input as explicitly explained. |

### Defects found and fixed during implementation

1. Card-based workspace selection initially bypassed the dropdown's generation
   invalidation and selection reset. Both now use the same operation.
2. Late findings/snapshot reads and failed health reads could append into a
   different view. Continuations now verify ownership before rendering.
3. A project picker could show a rejected selection during a pending mutation.
   It now restores the actual selected project.
4. A shared button wrapper restored its original disabled state, overriding
   audit pagination availability. Busy state is now separate from availability.
5. A session-vector conflict prevented the recovery button from rendering.
   Recovery now exists before the request and requires an explicit reload;
   no digest is silently replaced.
6. Invalid time filters could poison subsequent refreshes. Canonical bounded
   nanoseconds are checked before updating the selected filter state.
7. Selecting a catalog item beyond the quick picker's bounded first page could
   leave its dropdown blank. The exact selected option is now retained.
8. Unknown relationship presence was lost by the new response projection.
   `present: null` is preserved and labelled separately from confirmed edges;
   absent relationships are excluded by the existing reconstruction engine.
9. Stub validation uncovered a pre-existing `Incomplete` export for the temporal
   topology perspective reader. An explicit source annotation fixes the generated
   interface without changing runtime behavior.
10. A deliberately renamed fixture was unrecognized by the example parser,
    whose declared input requires `minimal-status.jsonl`. The failure stays
    visible; the UI now explains artifact-layout checks and that retrying does
    not change uploaded bytes. Core does not guess plug-in filename semantics.
11. Existing exact frontend-route tests needed the newly declared `/manage`
    route. Manifest, host allowlist, checker and tests now agree.

### Verification results

- Complete frontend suite: **202 passed**, including actual entry-module tests
  with controlled browser primitives, not only source-text assertions.
- Focused backend analysis suite: **18 passed**; context suite: **6 passed**.
- Combined context/analysis/frontend-host/core-web run: **35 passed** before
  the additional tri-state regression; that regression passed in the 18-test run.
- Context, author-documentation and typing checks: **32 passed**.
- Generated interface drift check: **129 modules passed**.
- Frontend manifest/asset/syntax checks, new Python module/test lint, documented
  minimal-fixture conformance and demo plug-in validation passed.
- Independent implementation audit: navigation races and tri-state loss above
  were reproduced, fixed and covered by executable regression tests.
- Plug-in-authoring stewardship completed: no discovery/manifest/hook contract
  changed; quickstart, normative plug-in contract and runnable example required
  no churn. HTTP, architecture, control-plane and human-facing launch docs were
  updated and their smoke checks executed.
- Final integrated demo check: `/manage` and live server-status cards work on
  port 8765; `/health` reports analysis ready with 1,250,005 events and 7,504
  resources. The generated input was reused. Temporary validation servers on
  ports 8877 and 4173 were stopped. The demo's resolver configuration remains
  unchanged; enabling trusted-header development access requires an explicit
  opt-in, not a new default grant.

### Remaining capability boundaries

The scoped durable inspector is **not** a binding of arbitrary published
sessions into the existing Fabric/Node graph runtime. It provides bounded
resource/event/relationship/finding queries with exact selection and time;
advanced route/topology provider execution against that selection remains
unavailable and is reported as such by both API and UI. That runtime-binding
feature is follow-up work, not a completed graph capability.

The verified durable loader still decodes/deep-copies the selected dataset per
request, and filtered searches scan client-safe projections. A persistent
indexed durable query backend remains a separate performance follow-up. The
response is bounded, not a claim that all million-row computations are constant
time. Browser identity settings are intentionally not an account-management or
authentication system; the host operator must configure the resolver.
