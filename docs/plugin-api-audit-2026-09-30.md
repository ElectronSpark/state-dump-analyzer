# Plug-in APIs and agent skills audit — 2026-09-30

The subsequent [interactive browser audit](plugin-browser-audit-2026-09-30.md)
records additional landing-page, presentation, combined-host integration, and
evidence-citation findings discovered after these API/skill-use trials.

## Scope and method

Reviewed repository structure, maintained author documentation, local Markdown
links, public Python interfaces/stubs, CI commands, and conformance coverage
across core, demo, standalone generator, and frontend. The detailed source
review focused on plug-in boundaries and their composed execution paths; this
is not a claim that every source line or possible API combination was inspected.

Three explicitly selected `gpt-6.1-sol` subagents reviewed foundational APIs,
optional capabilities, and combined execution respectively. Six fresh Sol
subagents then used the newly written skills to implement original synthetic
plug-ins in isolated `.runtime/skill-trials` directories. Those initial prompts
also named useful API boundaries and validation expectations. They tested
execution and exposed instruction gaps, but alone could not establish that
the skills supplied the implementation guidance. The parent reviewed their
artifacts and assertions as well as reported outcomes. A later minimal-dispatch
pass, recorded below, removes that extra prompt guidance.

An independent Sol reviewer checked the initial skills, map, runner,
metadata and documentation diff. Its only wording correction (counting public
protocols rather than calling all of them supporting protocols) was applied;
the inventory and four runner regression tests passed in that review.

The [API validation map](plugin-api-validation.md) covers all 15 analyzer hooks
(three required and 12 capability hooks), every `PluginCapability` member,
15 public protocols across the three plug-in-facing modules, schema
descriptors, and combined workflows. The inventory runner detects new unmapped
declarations and missing test modules. It does not measure branch coverage or
prove that all descriptor fields and interactions have tests.

The skills use concise repository-specific constraints and targeted references.
Model choice followed the user's explicit GPT-6.1 Sol request. OpenAI's
[model page](https://developers.openai.com/api/docs/models/gpt-6.1-sol) and
[prompting guidance](https://developers.openai.com/api/docs/guides/latest-model#prompting-best-practices)
were consulted; the latter describes GPT-6 Astra observations and recommends
evaluation on the chosen model/workload. The trials below provide local
behavioral evidence, not a comparative model-performance benchmark.

## Findings and changes

1. The author guide incorrectly said every undeclared base hook returns an
   empty result. `resolve_forwarding_step()` raises `NotImplementedError`;
   normal core callers reject missing capability before calling it. Corrected
   the guide without changing runtime behavior.
2. The quickstart's optional-hook link used a nonexistent anchor. Corrected it
   and checked local document targets and heading anchors.
3. There were no repository skill files. Added `router-plugin-author` and
   `router-plugin-validate`, with discoverable metadata and links to maintained
   contracts. The API map and `scripts/check_plugin_conformance.py` provide
   focused groups and a combined validation route.
4. Default pytest assertion rewriting can conflict with fixture executable
   identity. Two initially failing focused checks passed with `--assert=plain`.
   The runner uses the established `unittest` path; docs explain the pytest
   option without weakening product identity checks.
5. Actual skill use exposed a parser-only instruction that was ambiguous for
   capability-only providers, and a durable trial defined in `__main__` failed
   executable identity. Clarified no-input providers and importable-module
   trials, then requested affected trial reruns against the final skill.
6. Broad integration runs were expensive despite small synthetic inputs.
   Clarified focused module/class/method selection for individual changes and
   reserved grouped suites for broader checks. Full core discovery subsumes
   grouped tests, so completed same-code evidence should be reused instead of
   repeating overlapping suites.
7. Minimal prompts exposed two gaps that richer dispatches could mask. Parser
   golden tests could pass without core schema acceptance, and unchanged
   imported code could fail executable identity with the shared bytecode cache.
   Added explicit ingestion checks, source-type declarations, bounded-read
   guidance, and cache troubleshooting. Fresh retries receive the same short
   tasks with only their output directories changed; no corrective API hints
   are sent to them.

No plug-in runtime API or public signature was changed. The independently
reviewed foundational, optional, and composition boundaries did not yield a
confirmed implementation defect requiring a product patch.

## Skill-use trials

| Fresh Sol task | Actual boundary and assertions | Evidence |
|---|---|---|
| Two-port status plug-in | `validate_plugin` and `IngestionCoordinator`; typed keys/values, line evidence/digests, unknown time, retained malformed records and safe copy text | Two local golden tests passed; foundation group: 188 tests passed |
| Evidence-analysis plug-in | `PluginCapabilityExecutor`; advisory accepted, foreign citation rejected, missing capability rejected before invocation | Three local tests passed; evidence group: 82 tests passed; three local tests passed again after capability-only clarification |
| CTF/text trace, reduction, reversion and correlation | Actual ingestion dispatch with a typed fake CTF decoder, stable distinct event identities, retained sources; executor accepts a state change, its inverse and an evidenced causal link | Three local tests passed, including missing decoder, undeclared reducer, malformed output and invalid correlation-quota rejection |
| Topology, forwarding, packet step and federation | Actual capability and federation executors; shared endpoint identity across projections, accepted packet transition, two qualified federation members, malformed/outside-revision rejection | Three local tests plus three focused existing boundary tests passed |
| Parser → relationship → consistency | Durable ingestion; two resource kinds, projected endpoints, shared source evidence, exact plan/basis/revision, persisted PASS finding; malformed projector prevents revision/dataset publication | Positive and negative scenarios passed again using the final skills; grouped-suite result recorded below |
| Normalized source → query → public bootstrap | `NormalizedDatasetSource` and `NormalizedDataPolicy` through `NormalizedDataService`; revision/resource/event identities, schema disclosure, core rejection of missing descriptor, propagation of provider-owned stale-revision refusal | Three local tests passed; inventory check passed; three tests passed again using revised focused-selection guidance |

Together these independent trials exercised all 12 capability hooks, required
plug-in hooks and the separate federation linker through actual core callers.
The status trial used module loading and did not test installed entry-point
packaging. The evidence trial began with an already-authorized request. The
trace trial used a fake decoder and bounded correlation-reader fixture; native
CTF decoding was not tested. The topology trial used an empty packet-layer
tuple and did not model protocol-specific transformations. The combined trial
used explicit trusted-inline registration, not process isolation. Existing
conformance suites exercise additional boundaries separately.

The normalized-source trial exercised embedded history through the core service;
it did not implement `IndexedHistory`, `Runtime*Provider`, or a compatibility
session, and did not test HTTP or durable provider pinning. Its initial state
interval fixture used the wrong field name; the agent corrected that input
from the core consumer and reran only its three tests. This exposed no skill
blocker and did not require a product or execution-policy change.
After the final test-selection refinement, the same Sol agent used both revised
skills to select and rerun only its three relevant tests. It found the guidance
actionable and caught a conflicting older phrase in the API map; that phrase
was corrected to agree with the exercised workflow.

Trial source, fixtures, results and `TRIAL.md` notes remain in
`.runtime/skill-trials/{status,evidence,trace,topology,combined,runtime}`; they are intentionally
excluded from tracked product code. Reproduce the local tasks with the
installed repository Python environment:

```text
python .runtime/skill-trials/status/test_status.py
python -m unittest discover -s .runtime/skill-trials/evidence -v
python .runtime/skill-trials/trace/test_trial.py
python .runtime/skill-trials/topology/test_trial.py
python -m unittest discover -s .runtime/skill-trials/runtime -v
```

Use the combined trial's recorded import-based command in its `TRIAL.md`.

## Minimal-dispatch revalidation

Following the user's request, six new `gpt-6.1-sol` tasks were completed with
`fork_turns="none"`. Each prompt contains only a task, both skill paths, an
isolated output directory, a request for brief validation notes, and a restriction
against reading earlier trial/audit artifacts. The prompts are 28–36
whitespace-delimited words. They omit API helpers, implementation instructions,
test names, expected assertions, environment paths, and previous conversation.

For example, the complete status-task prompt is:

> Use .agents/skills/router-plugin-author/SKILL.md and .agents/skills/router-plugin-validate/SKILL.md to build and validate a tiny fan-status plug-in. Write only in .runtime/skill-trials-simple/status, including brief validation notes. Do not consult earlier trial or audit artifacts.

Exact prompts and starting skill hashes are retained locally in
`.runtime/skill-trials-simple/dispatch.json`. Original implementations and
validation notes stay in each task's subdirectory. These local artifacts are
ignored by Git. This pass tests whether a small task prompt is sufficient when
the skills and their linked repository references are available; it is not a
no-skill control experiment or proof that every decision originates in a skill.

The parent reviewed all six implementations, tests, and notes and independently
replayed their 17 local tests. All 17 passed; that did **not** make the original
durable tasks successful. Initial results were:

| Short task | Local tests | Boundary reached and limits |
|---|---:|---|
| Fan status | 3 passed | Direct parser and validator; durable CLI registration failed executable identity |
| CTF/text trace, undo and correlation | 4 passed | Direct parsers plus core reduction/reversion/correlation executor; no parser-ingestion acceptance or native CTF decoder |
| Evidence analysis | 4 passed | Core executor, bounded observations and foreign-citation rejection; supplied authorized request, no retained provider plan |
| Topology, forwarding, packet steps and federation | 2 passed | Capability executors and core exact-token federation; local terminal delivery, no custom linker or end-to-end cross-node route |
| Status, relationships and consistency | 2 passed | Direct parser plus executor composition over a manually assembled world; durable CLI registration failed executable identity |
| Normalized adapter, queries and disclosure | 2 passed | Core normalized service, revision/resource identity, search/filtering and redaction; no hosted session, HTTP or indexed history |

Agents also ran focused existing checks: evidence 1, trace 47, topology 3,
combined 108, and normalized data 3, all passing. These overlap the earlier
repository suite. Every agent ran the declaration inventory. They used the
default Python 3.12.5 with source-tree import paths after discovering that core
was not installed there. The combined agent asked for an interpreter preference;
the parent supplied none and referred it back to the skills/repository guidance.

For the unchanged fan artifact, the parent reproduced the registration error
at `PropertyPatch.__post_init__`. Keeping Python 3.12.5 and redirecting bytecode
reads to a fresh cache cleared registration. Switching to installed Python
3.12.13 with the shared cache did not. This controlled result identifies a
cache-sensitive validation failure; the original cache producer and reason for
the mismatch remain unconfirmed. Python documents that a
[cache prefix](https://docs.python.org/3.12/library/sys.html#sys.pycache_prefix)
ignores source-tree caches, while `-B` only prevents bytecode writes.

The parent's subsequent fan CLI run failed ingestion for a separate, concrete
reason retained in the failure diagnostics: `parse_status[0:0] references
undeclared source type 'fan-json'`. The first agent's passing tests had not
checked that boundary. Both original failures remain recorded; the parent
diagnosis is not counted as an unassisted agent pass.

The skills now require parser acceptance through ingestion, distinguish durable
materialization from manually composed worlds, and link cache troubleshooting.
They also prescribe minimal dispatch, fixed skill versions during a batch,
recorded prompts/hashes, and fresh retries after skill fixes. Three new agents
completed status, trace and combined tasks against those revised skills:

| Fresh retry | Completed evidence | Remaining limits |
|---|---|---|
| Fan status | 3 golden tests through `IngestionCoordinator`, including schema-accepted source evidence, stable revision identity, malformed and oversized rejection; 25 existing validation tests passed | No durable persistence or installed entry-point test |
| CTF/text trace | 3 golden tests through ingestion and capability executor; 3 focused executor cases passed | Synthetic decoder, no durable persistence. The focused invocation also selected an ingestion test whose module could not import `fastapi`; that invocation exited 1 and the affected existing check was not retried in this environment |
| Status → relationships → consistency | 3 local tests, including durable process PASS/FAIL/UNKNOWN scenarios; persisted resources, sources, edges and findings, matching basis/plan, producer revision and evidence; 2 existing boundary cases passed | No packaging, browser, or performance claim; malformed/oversized checks directly inspect parser diagnostics |

Every retry also passed the inventory check. The combined agent independently
discovered that `-X pycache_prefix` alone did not reach its worker effectively;
an inherited `PYTHONPYCACHEPREFIX` resolved the worker identity failure. The
parent reproduced that distinction with the unchanged original fan artifact:
the flag-only CLI failed probe revalidation, while the environment-prefixed CLI
reached ingestion and reported the undeclared source type. Updated the map to
use an inherited environment setting for child-process commands.
The parent independently replayed all nine retry tests successfully, including
the three durable subprocess outcomes. The documented inherited-cache smoke
also passed all 18 author-documentation tests, including the quickstart, in
13.958 seconds. The earlier flag-prefixed smoke and runner regression invocation
passed all 22 tests in 13.131 seconds.

The final fresh combined task used inherited `PYTHONPYCACHEPREFIX` throughout
execution, completed durable CLI ingestion, and passed four golden tests. Its
persisted result has two resources, two source records, one projected pair and
a FAIL finding; additional PASS/UNKNOWN/missing-pair cases use the core
materialization helper rather than separate durable subprocess runs. Malformed
and oversized inputs fail through ingestion. The parent independently completed
a fresh durable CLI run and replayed all four tests. One selected existing
relationship-ingestion test could not import `fastapi` in the agent's Python
environment and remains recorded as a failed invocation, not a conformance pass.
Ambiguous-group and scan-limit branches have no dedicated trial tests.

This pass comprises ten fresh implementation tasks (six initial, three retries,
one final combined retry), plus an independent fresh Sol reviewer. The reviewer
used the validation skill, confirmed the prompt/hash records and inventory,
inspected the completed second-pass evidence, and found no blocking defect in
the reviewed changes. Its report-completion reminder was addressed. The final
combined result was subsequently reviewed and reproduced by the parent. None
of the implementation agents received corrective API or environment coaching.

The final skills and API map are validated by actual use with short dispatches,
with the limits above. This is evidence of completion without detailed parent
instructions; without a no-skill control, it does not isolate the contribution
of skills from the model's prior knowledge or its reading of repository code.

## Repository validation

Environment: Windows, installed Python 3.12.13 analyzer environment and Node
20.17.0. Results overlap; do not add focused counts to the full-suite count.

| Check | Result |
|---|---|
| Full core unittest suite | 2,564 tests run in 6,419.267 seconds; OK, three skips and no failures/errors |
| Demo unittest suite | 29 tests passed |
| Standalone generator unittest suite | 123 tests run, OK, three platform/environment skips |
| Frontend `npm run check` | 351 tests passed, no failures/skips |
| Public stub drift | 141 module stubs verified across four packages |
| Strict public consumers | Two source files passed |
| Strict complete exported surface | 141 source files passed |
| CI typed core implementations | Three source files passed |
| Source and test compilation | Core, demo and standalone generator passed; bytecode written to ignored audit cache |
| CI syntax/undefined-name lint | Passed |
| New conformance runner lint/strict typing | Passed |
| Runner inventory regression tests and author-doc smoke | 22 tests passed, including the exact quickstart smoke block |
| New runner, `--group foundation` | 188 tests passed |
| New runner, `--group revision --group composition --group combined` | 580 of 581 passed in 1,571.172 seconds; one retention test failed, then passed its isolated rerun |
| Both skill metadata validators | Passed |
| Local document targets/heading anchors | No missing local targets or Markdown anchors in the checked documentation set |

The audit agents also completed 320 combined-boundary tests with 477 subtests,
170 optional-boundary tests with 473 subtests, and focused foundational checks.
Partially observed auxiliary audit runs are not counted as passes; only
completed tool results are reported.

The grouped run's failure was
`DurableIngestionPipelineTests.test_completed_blob_and_dataset_remain_pinned_until_catalog_release`:
the import was FAILED where the test expected COMPLETED. Its isolated rerun
passed after repository edits had settled. The original temporary job diagnostics
were not retained by that test, so the cause is unconfirmed; neither source
drift nor concurrent load is established as the cause. The grouped invocation
is recorded as failed with a successful focused rerun, not as a clean full pass.
The separate full core discovery subsequently completed with no failures or
errors, including the retention test's module. The original grouped failure
remains recorded rather than being erased by that later result.

The existing Starlette/httpx deprecation warning remains. Sandbox restrictions
blocked Node's ancestor-path resolution; the same frontend command passed
after approved execution outside that filesystem sandbox. No dependency
upgrade or global Git configuration was made. Linux, Node 22, minimum-Uvicorn,
launcher and wheel-install CI matrix checks were not reproduced locally.

The full core run exceeded the CI Python job's 45-minute budget on this machine.
Read-only stack snapshots located active executable-identity revalidation inside
`test_generic_route_catalog_reaches_every_ordered_router_pair`; its synthetic
pair list showed completed iterations. This is a local performance observation,
not a controlled regression benchmark or proof of a deadlock. The diagnostic
used [py-spy](https://github.com/benfred/py-spy) from an ignored temporary tooling
directory, without modifying project dependencies or the running test code.

## Documentation stewardship

Reviewed all task-owned changes against `AGENTS.md`. Updated the quickstart,
guide, contract navigation, example README, and root README alongside the new
author-facing conformance command. Runtime semantics, example implementation,
HTTP contracts and architecture are unchanged, so those implementations and
the API/architecture documents need no churn. The quickstart smoke and relevant
conformance checks were executed. The pre-existing generated-demo lock was
preserved.
