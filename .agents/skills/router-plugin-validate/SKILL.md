---
name: router-plugin-validate
description: Audit Router State Lab plug-in API conformance, documentation drift, or interactions between parsers, revision hooks, providers, and runtime adapters. Use for requested validation or audits, including individual and combined API checks.
---

# Router plug-in validation

Use the repository root containing `src/router_dump_analyzer`. When this skill
is supplied by absolute path, the repository is three directories above the
skill folder. Read `AGENTS.md` and [the API validation map](../../../docs/plugin-api-validation.md).

## Establish scope and evidence

Identify the requested hook, protocol, or combined workflow from the map. Compare
the implementation and typed signature with the relevant contract section and
tests. Distinguish a parser capability, a schema descriptor, a core service,
and a compatibility-runtime extension before proposing another plug-in hook.

Run `python scripts/check_plugin_conformance.py --list` to check inventory drift.
This checks that declarations have a conformance group; it does not prove every
method or behavioral branch is tested. For an individual hook, select relevant
module/class/method tests from the mapped suites. Use `--group` for a complete
surface or shared behavior change. For a full plug-in audit run `--all`;
a whole-repository audit also needs the demo,
generator, frontend, and typing checks listed in the map.

Reuse completed checks for the same code: full core discovery already includes
the grouped test modules, so run the inventory check and any new scenario
instead of repeating overlapping groups. Keep verbose logs for broad runs;
small generated assemblies can still require several minutes of setup.

Use one installed Python environment throughout. Verify its executable and
required imports first; if dependencies are missing, inspect the configured
environment via the map's troubleshooting steps before using source-only paths
or reporting the dependency unavailable. Prefer the documented
`unittest` runner: pytest's default assertion rewriting changes fixture plug-in
bytecode and can fail executable-identity checks. If a focused pytest command
is needed, use `--assert=plain -p no:cacheprovider`. A missing dependency, denied
cache path, or platform skip is a validation limit, not a product regression.
Capture the exact failure and rerun only the affected check after resolving it.
For executable-identity failures on unchanged imported code, follow the map's
[environment troubleshooting](../../../docs/plugin-api-validation.md#executable-identity-troubleshooting).
Do not treat a registration-only fix as successful ingestion: inspect the next
stage's result and retained diagnostics too.

## Validate APIs together

Pair isolated boundary tests with a realistic composed flow. Select the flow
that matches the request: parser to durable revision to relationship/consistency,
schema to query/redaction, topology to federation to forwarding, or pinned
providers to evidence analysis. Verify exact identities and intermediate results,
not just a successful exit or HTTP 200. Confirm unavailable and malformed
capabilities fail at the core boundary without publishing partial results.
Parser golden tests must enter `IngestionCoordinator` or the durable CLI to
establish schema acceptance; direct parser output checks alone are insufficient.

If the user asks for model-based validation of a skill, have fresh subagents
**use the changed skill** to implement or diagnose representative tasks in
isolated temporary directories without inherited conversation. Give them only
the task, skill paths, and allowed outputs (plus any user-supplied fixture),
without API hints, implementation steps, test names, or expected assertions.
Keep each batch's skill version fixed and record the prompts and skill hashes.
Use the user's requested
model; otherwise preserve the configured model. Assign disjoint files and
include both an individual API task and a combined task. Read their artifacts
and actual test results, fix demonstrated instruction gaps in the skill, and
repeat only the affected task with a fresh agent and the same minimal prompt.
Avoid follow-up coaching that would hide a skill gap. If subagents are unavailable, report that limit and run the
same scenarios locally.

For loading or cache changes, use the map's
[performance boundaries](../../../docs/plugin-api-validation.md#loading-and-performance-boundaries).
Compare cold and warm behavior, including changed inputs and failed or
superseded requests. A faster successful call does not establish unchanged
identity enforcement, archive safety, or browser readiness.

For combined history changes, exercise cache retirement with an active
reader, same-revision replacement, dense and sparse searches, refinement,
paged layer filters, and cold narrow timeline windows against exact raw
references. Check retained bytes and visited records, not only response
limits. The performance map lists relevant tests and generation commands;
a small fixture establishes correctness, not million-event performance.

For timeline/density changes, follow
[zoom-query validation](../../../docs/plugin-api-validation.md#zoom-and-history-query-validation).
Check both coarse summaries and exact drill-down with the same evidence;
separate bounded output from bounded computation, and verify warm-cache
identity, disclosure, cancellation, and concurrent requests.

## Report accurately

Record the API inventory, reproducible findings, edits, commands, pass/fail/skip
counts, and remaining limits. Never turn a declaration inventory or a handful
of passing tests into a claim of exhaustive coverage. Fix demonstrated issues
within scope, preserve unrelated working-tree changes, and complete `AGENTS.md`'s
plug-in documentation drift check before handoff.
