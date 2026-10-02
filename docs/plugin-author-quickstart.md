# Plug-in author quickstart

Run the working parser, inspect its golden test, then adapt that teaching slice
to your device. Python 3.12 is required. Run every command from the repository
root in the same Python environment.

The [detailed author guide](plugin-author-guide.md) covers optional capabilities
and their conformance commands. The [plug-in contract](plugin-contract.md) is
the normative reference.

For a specific hook or combined workflow, use the
[API validation map](plugin-api-validation.md). Repository agents can use
[`router-plugin-author`](../.agents/skills/router-plugin-author/SKILL.md) for
implementation and [`router-plugin-validate`](../.agents/skills/router-plugin-validate/SKILL.md)
for conformance audits.

## 1. Run the known-good example

Install the core and the one runnable example distribution:

```text
python -m pip install -e ".[test,web]"
python -m pip install -e demo
```

Then verify the fixture, validate the installed entry point, run its golden
tests, and ingest that input into a durable revision:

<!-- quickstart-smoke:start -->
```text
router-dump-plugin-validate --list
python -X utf8 -m rsl_demo_generator --verify-conformance-fixture demo/fixtures/minimal-status.jsonl
router-dump-plugin-validate demo_router --artifact demo/fixtures/minimal-status.jsonl --node-hint router-1 --metadata platform=demo-router-os --metadata software_version=1
python -m unittest discover -s demo/tests -v
python -X utf8 -m router_dump_analyzer.pipeline_cli --plugin-module rsl_demo_plugin:parser_plugin --state-dir .runtime/plugin-author-state --tenant author-smoke --project example --workspace first-run --input demo/fixtures/minimal-status.jsonl --pretty
```
<!-- quickstart-smoke:end -->

Discovery should list `demo_router`; validation and tests should pass; the last
command should print a successful job and its revision ID. It writes local
state beneath `.runtime/plugin-author-state`. `parser_plugin` exposes the
teaching parser without the generated archive's compatibility runtime.

The validator checks package and protocol shape. Golden tests check actual
resource identities, values, relationships, evidence, and consistency findings.
Core also supplies generic loading progress and bounded browser waits; the
parser needs no progress hook. See the [runtime loading contract](api-contract.md#analysis-loading-progress)
for stages, advisory fixture reporting, and manual retry behavior.
The repository also executes this exact smoke block in a temporary state
directory through `tests.test_plugin_authoring_docs`.

To inspect the same parser in the browser, run:

```text
python -X utf8 -m router_dump_analyzer.cli --plugin-module rsl_demo_plugin:parser_plugin --input demo/fixtures/minimal-status.jsonl --control-plane-dir .runtime/plugin-author-state --port 8876 --no-browser
```

Open `http://127.0.0.1:8876`. The core owns `router-dump-analyzer`, its web
application, and runtime-v2 ingestion. The timeline uses the fixture's recorded
nanosecond bounds and opens at capture with all three resources present, even
though this status-only input emits no semantic events. Stop the server with `Ctrl+C`. The
[core demo walkthrough](demo-core-coverage.md) exercises durable review in more
detail.

In the event log, enable Status input to inspect the four retained records.
The window-only observation displays Unknown time and remains selectable;
it does not create a point on the timeline.

## 2. Inspect and copy the teaching slice

Read these files together:

- [`demo/rsl_demo_plugin/__init__.py`](../demo/rsl_demo_plugin/__init__.py):
  parser, schema, relationship projection, and revision consistency rule.
- [`demo/fixtures/minimal-status.jsonl`](../demo/fixtures/minimal-status.jsonl):
  the tiny synthetic input.
- [`demo/tests/test_plugin.py`](../demo/tests/test_plugin.py): expected results.
- [`demo/pyproject.toml`](../demo/pyproject.toml): packaging and discovery.

Copy the parser/schema/relationship/consistency portions, the
`CONFORMANCE_STATUS_RECORDS` fixture plus renderer, and their golden tests into
your own independently installable `src/`-layout distribution. Rename the
distribution, import package, entry-point name, plug-in ID, platform ID, parser
ID, resource kinds, and fixture vocabulary. Your package depends on
`router-dump-analyzer-core`; the demo package is only a working reference.

Keep the example's basic implementation pattern: subclass `AnalyzerPluginBase`,
declare `PluginCapability.STATUS_PARSE`, select `InputParserKind.STATUS`, retain
evidence with `SourceRecordEmission`, and use `derive_event_uid` for event
identity. Choose timestamp semantics that match your device. Each behavior is
exercised by the example's tests.

The generated corpus policy, scenario builders, archive adapter, and fixture
generator are separate demo concerns. Copy only the teaching slice described
above. See the [detailed implementation walkthrough](plugin-author-guide.md#3-implement-the-parser-and-revision-analysis)
when adapting individual hooks.

## 3. Publish and validate your entry point

Your package's entry point must target a module-level plug-in instance:

```toml
[project.entry-points."router_dump_analyzer.plugins"]
my_router = "my_router_plugin:plugin"
```

In that module, expose `plugin: AnalyzerPlugin = MyRouterPlugin()` after
implementing your class. Install your distribution, run
`router-dump-plugin-validate` with its entry-point name and synthetic input, then
run its golden tests. Keep those checks passing as you add capabilities.

Core owns artifact safety, persistence, APIs, and the generic frontend. Plug-ins
supply device meaning and declarative domain presentation. Producer limitation
metadata describes input and evidence quality; core reports configured host
services. Optional topology and forwarding hooks are introduced in the
[author guide](plugin-author-guide.md#4-know-which-hooks-are-optional), with focused tests for
each boundary.
