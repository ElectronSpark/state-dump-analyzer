# Demo and sensor plug-in browser audit — 2026-09-30

Launched the core UI with the bundled `demo_router` and the new
`sensor_plugin:plugin` from the final minimal-prompt trial. Browsed both using
the Codex in-app browser. Findings are recorded below; implementations were
not changed. A fresh GPT-6.1 Sol subagent independently reviewed the sensor's
web integration and reproduced its evidence issue through core materialization.

## Running examples and scope

- Bundled demo: <http://127.0.0.1:8876>, ten-node development assembly generated
  from current sources with 300 baseline events and 120 baseline resources per
  node, plus authored scenarios. The generator reports 41 coverage cases.
- New sensor: <http://127.0.0.1:8877/node>, two input records (`up` and `down`).
  The default `/` landing page has the problem recorded as B1.
- Used the installed Python 3.12.13 analyzer environment with its web
  dependencies and an inherited audit-local bytecode cache. Both servers bind
  to loopback. State, logs, screenshots and reproductions are under
  `.runtime/browser-audit`, `.runtime/browser-demo-state`, and
  `.runtime/browser-sensor-state`.

Paths under `.runtime` refer to local audit artifacts excluded from Git; they
are not included in a fresh clone.

The existing `demo/fixtures/router-state-lab-demo.generated.tgz` fails the
generator's launch-readiness check: it does not match the current canonical
authoring scenario. This is a fixture/environment limitation, not evidence of
a generator defect. The normal launcher would need to regenerate it. This
audit preserved that archive and its pre-existing lock and generated a separate
small current assembly. It does not validate full-scale performance or a
successful full-scale launcher run.

## Browser checks completed

| Check | Observed result |
|---|---|
| Bundled fabric | All 10 nodes listed; 8 connectivity domains and 21 attachments rendered. Clock uncertainty and ambiguous joins remained explicit |
| Default route scenario | PE-A ↔ PE-B reachable in both directions; primary and standby candidates displayed |
| Packet/MTU negative scenario | Both directions reported dropped; packet size changed from 1,490 to 1,510 bytes; the plug-in-declared MTU drop and evidence explanation appeared |
| PE-A node workspace | Loaded with 20 inventoried artifacts, zero parse errors/skips, 305 exact resources and four passing findings; interface/neighbor bundled table worked |
| Sensor node workspace | Two resources and two timeline lanes loaded; no parse errors; top-level statuses were incorrectly unknown for the supplied up/down data (B2) |
| Sensor retained logs | Enabling Sensor status showed both retained records; searching `down` reduced the log to the correct single record |
| Sensor combined analysis | Ordinary CLI page showed zero relationships/findings despite the prior durable trial's projected pair and FAIL (B3) |
| Console/logs | No captured JavaScript warning/error in the inspected demo and sensor pages. Sensor topology requests correctly returned unavailable/501; the landing-page presentation is B1 |

These are focused interactive checks, not an exhaustive browser regression
suite. Management mutation flows, durable session review, native CTF decoding,
responsive/mobile layouts, and every route scenario were not exercised.

## Additional findings

### B1 · P2 · A parser-only launch opens an unsupported topology page

Opening <http://127.0.0.1:8877> shows “Topology page could not initialize” and
`/v1/topologies/capabilities: the loaded plug-in does not provide multi-node
topology`. The revision panel continues to say Loading and the device list
continues to say Loading devices. Opening `/node` succeeds.

The [frontend manifest](../frontend/frontend-manifest.json) maps `/` to the
topology page, and [the CLI](../src/router_dump_analyzer/cli.py) selects that
base URL for browser launches without checking multi-node support. The current
quickstart likewise points a parser-only user at the base URL.

Expected improvement: choose the node workspace for a parser-only launch or
provide a clear capability-aware fallback, and clear loading states when the
capability is unavailable. The unavailable topology API itself is expected.

Evidence: `.runtime/browser-audit/sensor-home.jpg` and `sensor-home-dom.txt`.

### B2 · P2 · The new sensor plug-in does not declare its displayed condition

At `/node`, both rows and timeline lanes show `unknown`, although the retained
records show `up` and `down`. The trial emits a `status` property but omits
`SnapshotObservation.condition` and `condition_class`; its resource descriptor
also omits `condition_field`.

The relevant local implementation is
`.runtime/skill-trials-simple/combined-r3/sensor_plugin.py`.
[Core ingestion](../src/router_dump_analyzer/ingestion.py) derives the top-level
status from the observation condition, falling back to its UNKNOWN class.
This is a trial plug-in presentation gap, not lost parser data.

Expected improvement: declare the condition field, emit the intended condition
and class, and test resource/timeline presentation through the browser-facing
path. The current golden tests checked state values without checking this UI
contract.

Evidence: `.runtime/browser-audit/sensor-node-dom.txt` and `sensor-node.jpg`.

### B3 · P2 integration gap · Ordinary CLI browsing omits combined analysis

The sensor browser page reports zero pass/fail/unknown findings and no active
relationships. The same plug-in's earlier durable pipeline run produced a
projected pair and one FAIL finding.

This follows the current host boundary: `CoreIngestionRuntime._open` invokes
`IngestionCoordinator` directly. Relationship projection and consistency are
scheduled by the durable execution-plan materializer. Supplying
`--control-plane-dir` does not replace the ordinary startup workspace with an
already materialized durable revision. This audit does not claim that the
ordinary runtime violates the documented scheduling contract.

Expected improvement: provide and validate a documented browser flow for the
durable sensor revision/session. If combined findings must appear in the
ordinary CLI workspace, implement that host scheduling explicitly. A successful
parser page alone does not validate the combined plug-in's web integration.

Evidence: `.runtime/browser-audit/sensor-findings.jpg`; the previous durable
trial's `state` and `VALIDATION.md` remain under
`.runtime/skill-trials-simple/combined-r3`.

### B4 · P2 · Aggregate FAIL can omit the unhealthy sensor from its evidence

The trial computes a finding over every projected pair but truncates cited
resources and evidence to `selected[:32]`. With 34 sensors in 17 pairs, core
ingestion and combined materialization accept a FAIL that cites only healthy
members. The sole down sensor's `line:22` evidence is absent. Core canonical
relationship order determines which members the slice omits.

Expected improvement: emit a finding per pair or prioritize the members that
justify FAIL/UNKNOWN before bounding citations. Add a case with more than 16
pairs and assert that the failing member and its evidence remain in output.

Reproduction: `.runtime/browser-audit/reproduce_core_citation.py`, with
`PYTHONPATH` containing `src` and the `combined-r3` directory and a fresh
inherited `PYTHONPYCACHEPREFIX`. The parent independently reproduced:

```text
resources=34; pairs=17; result=fail; cited=32; down_line_22_cited=False
```

Fixture, accepted dataset and output are retained in `citation-fixture`,
`citation-core-dataset.json`, `citation-core-results.txt`, and
`parent-core-repro.log` under the audit directory. This reproduction enters
ingestion and the execution-plan materializer; it does not claim HTTP or
durable-publication validation of the larger fixture.

## Documentation stewardship

Completed the `AGENTS.md` drift check. Only audit documentation and isolated
validation artifacts were added; public behavior, maintained example code,
skills and authoring commands were not changed in this follow-up. The findings
remain open. No maintained-author-document update or broad suite rerun was
required for this report-only change.
