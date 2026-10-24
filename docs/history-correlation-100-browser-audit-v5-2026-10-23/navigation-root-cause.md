# Navigation time-basis root cause

Read-only source validation on `d29f981`; no browser, server, or API actions. The parent reports browser confirmation that fabric UTC +179.993 s opens PE-D at native +180.001 s, while the same applied fabric connector remains Usable. Local before/exact/after proof is being collected by the parent.

## Finding

**Absolute and relative failures share a missing resolved-time handoff between fabric navigation and single-node initialization.** Fabric reconstructs a member-specific native instant correctly, but navigation retains only the original request selector. The node workspace echoes that selector without resolving it; startup then assumes any `time_ns` is already native, or falls back to capture when it is absent.

### Source chain

1. `src/router_dump_analyzer/multi_node_topology.py:1920`, `_resolve_time`, already distinguishes domains. For absolute UTC it computes `local_time = query_time + local_minus_absolute_ns` at lines 2211–2219 and returns both `query_time_ns` and `local_time_ns` at 2235–2237. For a relative basis it computes `local_watermark + offset` at 2046–2050 and returns the member-local result at 2122, plus `watermark_local_time_ns` and `relative_offset_ns` at 2160–2163.
2. Both `_node_deep_link` (4629) and `_resource_deep_link` (4666) call `_basis_link_params` (4702). That helper emits requested UTC `time_ns` for absolute navigation or `basis_offset_ns` for relative navigation. It does not transmit the resolved local instant. Preserving the original selector is useful for context/return navigation, but it cannot stand in for an already resolved native cursor.
3. `frontend/assets/topology.js:3162`, `basisForNode`, chooses `query_time_ns` before `local_time_ns` and exposes only that choice as `queryTime`; its `clock_domain` is preferentially the member's native clock. `applyNodeNavigationBasis` (9253) preserves an explicit `time_ns`; for relative navigation it deliberately removes `time_ns` and preserves the offset. `navigationHref` (9303) then attaches the native clock domain if absent. Thus absolute links can carry a UTC integer labeled by a native domain, and relative links carry no resolved cursor at all.
4. `frontend/assets/app.js:391` parses those values. `bootstrapDatasetPath` (429) forwards them to `/v1/nodes/{node_id}/workspace`.
5. `src/router_dump_analyzer/web/runtime_api.py:839`, `node_workspace_dataset`, validates mutually exclusive selectors, loads `client_dataset(node_id=...)`, and echoes the raw requested basis into `node_snapshot.basis` (915–922). It does not call the topology resolver, derive local time, or change the workspace's native capture/time bounds. `workspace` is changed only to add assembly/node/revision identity (931–937).
6. `frontend/assets/app.js:12802` initializes `state.cursorNs = clampNs(toNs(navigationContext.timeNs || declaredCaptureNs, ...))`. Absolute `time_ns` is therefore interpreted as native. Relative navigation has no `time_ns`, so it selects capture; `basisOffsetNs` is never used in cursor calculation. The complete references to `basisOffsetNs` are parsing (400), bootstrap (438), and banner text (484).
7. This affects queries, not just labels: `requestTimeline` sends the cursor unchanged as `cursor_time_ns` (5557), and `requestResources` sends it unchanged as `time_ns` (5733). Generated authored event timestamps, timeline start, and capture are native (`demo/rsl_demo_generator/assembly.py:1048`, 1283, 1307).

### Exact PE-D consequence

- Native clock offset: **-8 ms**; native base: **1759679999992000000**.
- Interface deletion: native **1759680179992000000**, offset **180 s**.
- Requested UTC: **1759680179993000000**, UTC offset **179.993 s**.
- Correct native instant: **1759680179985000000**, native offset **179.993 s**.
- Current startup instead uses **1759680179993000000**, native offset **180.001 s**: after the deletion.
- Clock uncertainty is ±6 ms, so the fabric interval **179.987–179.999 s** is entirely before deletion. Uncertainty cannot explain this discrepancy.

### Relative-offset consequence

For a selected projection watermark of native +720 s, relative -120 s should yield native +600 s. Current startup sees no `time_ns` and uses capture, native +720 s. The arithmetic must use the **selected projection/member's resolved local watermark**, not assume every projection watermark equals the dump capture. This is the same missing-resolution handoff, with a different fallback outcome.

### Misleading presentation and test gap

`renderTopologyNavigationBanner` (`app.js:484–485`) calls the raw absolute value “resolved time” and asserts relative navigation “opened at its resolved time” without checking a resolved result. A nearby comment at 8656–8658 states relative cross-node queries open at the exact resolved member time; the implementation no longer establishes that premise.

`tests/test_multi_node_topology.py:1857` and `:1980` verify selector-preserving URL/API round trips. The absolute test explicitly expects the original requested UTC integer to survive; that is reasonable for request context but does not test its interpretation as the node cursor. `frontend/tests/node_startup_progressive.test.mjs:22–24` uses `timeNs: '5'` with generic 0–10 bounds and no clock conversion or relative offset. These tests cannot catch either observed navigation failure.

The fix boundary is the handoff/initialization of the resolved native cursor, retaining original requested basis separately for context. No new plug-in clock semantics are required: the existing fabric resolver already computes both forms correctly. This review does not prescribe trusting a URL-derived local value or replacing projection watermark semantics with capture arithmetic.

Documentation drift check: this file is an ignored runtime audit record; product and author-visible APIs are unchanged.
