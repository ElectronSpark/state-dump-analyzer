# Audit follow-up investigation — 2026-10-20

This investigates the remaining findings after [the audit fixes](audit-fixes-2026-10-20.md).
The identity repair and projection optimization were subsequently implemented;
see [implementation and validation](identity-projection-2026-10-20.md).
Production source and the running demo were left unchanged. GPT 6.1 Sol agents
used the repository skills for isolated investigations; the parent reviewed the
artifacts and independently reproduced the key correctness findings. These are
investigation results, not shipped optimizations.

## 1. Executable identity can miss a callable object's changed state

**Priority: repair before further performance tuning.** In
`src/router_dump_analyzer/plugin_identity.py`, the exact-type test
`type(value) in {tuple, frozenset}` at the time of investigation (line 6519)
uses metaclass hashing/equality. A custom metaclass can make its class compare
equal to `tuple`. A callable instance with an empty iterator is then traversed
as an empty immutable container, skipping its callable implementation and state.

The source-backed probe defines a callable `VALUE` whose `__call__` returns
`self.state`, whose `__iter__` returns `iter(())`, and whose metaclass hashes as
`tuple` and compares equal to it. The callback is `return VALUE()`.
Changing `VALUE.state` from 1 to 2 changes the callback result while **both**
`executable_callable_fingerprint` and `executable_module_target_fingerprint`
remain unchanged. The equivalent ordinary-class control changes both
fingerprints. The parent independently reran these public-API checks.

A separate unhashable metaclass raises raw `TypeError` through both APIs,
instead of the documented `PluginExecutableIdentityError`. A direct
`return VALUE.state` callback does bind the state through another path; that
containment does not cover the demonstrated `VALUE()` call.

This establishes a public fingerprint-boundary defect, not a demonstrated
end-to-end ingestion or private-analysis exploit. It conflicts with the existing
contract's recursive global-state and fail-closed identity guarantees. Several
other intended exact-type guards use membership tests and need the same review.
Use identity comparisons, then validate mutable state, callable implementation,
custom metaclasses, normal built-ins, and declared error behavior at both public
entry points. Do not cache a successful identity decision as a workaround.

A bounded repair prototype replaces 16 direct type-membership sites with
identity comparisons. The parent reran it: both public fingerprints now change
for the spoofed callable and ordinary/real-tuple controls. The unhashable class
can be fingerprinted, while unsafe iterator globals still raise
`PluginExecutableIdentityError` through both APIs. This supports the repair
direction, but is not a complete audit: aliased type-membership expressions
remain outside the prototype transformer and full identity suites were not run
against it.

Evidence: `.runtime/followup-investigation-2026-10-20/type-guards/`, including
`probe_module.py`, `run_probe.py`, `result.json`, and `parent-probe.log`.
The repair is in `plugin_identity_prototype.py`, with `run_prototype.py`,
`prototype-result.json`, and `parent-prototype.log`.

## 2. Cold search is dominated by safe projection

The current implementation was profiled with the same
`demo/fixtures/router-state-lab-algorithms-2026-10-02.tgz` million-event fixture.
PE-A produces 1,250,005 safe search documents and 1,768,382,872 characters.
The instrumented cold query took 163.88 seconds; about 123.37 seconds (75%)
was cumulative safe projection, 20.20 seconds (12%) JSON encoding, and 3.13
seconds (2%) compression. These profile timings include instrumentation
overhead and are not user-facing latency estimates.

An isolated in-memory prototype returns early for exact built-in scalar types
in recursive redaction and checks ordinary dictionaries before the generic
`Mapping` path in two projection helpers. Generic mappings and subclasses keep
their existing behavior; the prototype does not cache mutable projections.

| Unprofiled measurement | Current | Prototype |
| --- | ---: | ---: |
| Setup wall time, before the query | 50.386 s | 49.430 s |
| Cold query wall time | 69.057 s | 56.441 s |
| Cold query process CPU | 67.344 s | 55.016 s |
| Search sidecar | 75,038,720 bytes | 75,038,720 bytes |

The measured reduction is 18.3% for both cold-query wall time and CPU in this
single pair. Each uses a fresh process and empty search cache on Python 3.12.13.
Other bounded investigations ran on the host; this is not a repeated,
randomized performance estimate. RSS and navigation memory were not measured
for this prototype, so the earlier production memory results remain the latest
memory evidence. Warm other-term CPU was 2.281 → 2.063 seconds; absent-term CPU
was 1.781 → 1.719 seconds. Those small differences are not a separate speedup
claim.

The first draft used tuple membership for scalar types. Parent review found
that metaclass equality could then bypass redaction. It was corrected to
explicit `is` comparisons before the candidate measurement. The parent reran
20,005 differential redaction cases, including generic mappings, nested
Unicode/NUL data, and a hostile dict metaclass; all pass. This review also
prompted the separate production identity finding above.

Both measured corpora have the same metadata, complete-corpus digest
`e822d341feb8f3d1172725004d2e286614416d42c07e21446f4de725faef6b36`,
character count, sidecar size, and response-page digests. An independent
sidecar decoder validates document framing/hashes, rebuilds the corpus digest,
and compares every ordered match with the production query path: 24,925
`failure`, 1,225,080 `success`, and zero absent-term matches in both versions.
The parent inspected and independently reran this complete decoder/query check;
it passed (`cold-search/parent-ordered-matches.log`).
The monkeypatched projection also passes the focused normalized-data,
revision-query, HTTP event-redaction, and history-search suites: 75 tests run,
74 passed, one Windows symlink-privilege skip. The parent inspected the log.
The initial sandbox run stalled constructing the Proactor loop for TestClient;
a 90-second diagnostic timeout captured `socket.accept` in `_fallback_socketpair`.
The identical suite outside the sandbox completed without failures or errors.
This environment limitation is separate from the reset-cleanup defect below.

A deterministic sample of 512 documents from 32 evenly spaced blocks confirms
that `subject` also occurs in `subjects`; `affected_resources` is not a third
copy of that record. Dropping redundant-looking fields would change exact
JSON-substring search semantics. The sample is not a random estimate.
Compression changes have a much smaller measured ceiling than projection.

Evidence: `.runtime/followup-investigation-2026-10-20/cold-search/`, including
`measure.py`, `profile/profile.txt`, both `metrics.json` files,
`candidate/prototype.py`, `differential.json`, and `ordered-match-parity.json`.
Parent sampling and adversarial guard checks are in `corpus_sample.*` and
`parent_scalar_guard.py` in the investigation root.

## 3. More aggressive search pauses did not improve imports

The previous real-path trial retained 19 parent identity checks taking 14.516
seconds wall time but 3.516 seconds thread CPU. Child ingestion consumed about
2.9 seconds, including 2.4 seconds in identity checks. This supports contention
around parent verification as a remaining contributor, rather than extra
parsing work or garbage collection.

Bounded trials used actual two-worker durable imports, the real SQLite session
catalog, and a synthetic CPU-producing search corpus. All seven successful
imports retained 19 parent identity checks and published byte-identical
datasets. Ordered search results and complete resource/source/state material
also match across variants.

An 8,192-document trial tested additional eight-document checkpoints, a 1 ms
Python switch interval, and a 1 ms requested cooperation pause. No material
gain was demonstrated. The denser 131,072-document pair gave:

| Measurement | Current 100 µs pause | 1 ms pause |
| --- | ---: | ---: |
| Import wall | 31.530 s | 31.729 s |
| Search wall | 22.258 s | 23.200 s |
| Parent identity wall | 13.456 s | 13.958 s |
| Parent identity thread CPU | 3.859 s | 3.672 s |

Do not promote these scheduling knobs. These are single exploratory trials
with synthetic projection, possible host contention, and a different bytecode
cache configuration from the browser trials. They are not million-event
browser latency forecasts. A useful next experiment is source/stat/read span
measurement during real cold projection, followed by evaluating bounded work
handoff or separate-process projection while preserving live verification,
cancellation, exact safe text, and sidecar corruption recovery.

Evidence: `.runtime/followup-investigation-2026-10-20/import-delay/`, especially
`findings.txt`, `measurements.json`, `bounded_trials.py`, and `summarize.py`.

## 4. Windows reset cleanup remains a runtime issue

The parent independently reran the deterministic CPython 3.12.13 transport
probe: a reset during socket shutdown interrupts close and server detach.
Suppressing the exception afterward does not complete that interrupted cleanup.
The inspected [upstream 3.12 implementation](https://raw.githubusercontent.com/python/cpython/3.12/Lib/asyncio/proactor_events.py)
retains the same ordering; a patch-version upgrade was not established as a fix.

A public Selector event-loop factory avoids that Proactor implementation, but
Windows Selector has a 512-socket limit and lacks asyncio subprocess support.
See [Python's platform support documentation](https://docs.python.org/3.12/library/asyncio-platforms.html).
Both Proactor and Selector passed separate 30-connection loopback probes,
including graceful and abortive closes, exact-once notifications, and bounded
server shutdown. The parent reran the probes and inspected all child exit codes
and results. These real-socket trials did **not** reproduce the intermittent
reset, and do not establish an application-wide remedy or long-term handle
stability. No runtime patch, logging suppression, or server-loop change was made.

Evidence: `.runtime/followup-investigation-2026-10-20/windows-cleanup/`,
including `REPORT.md`, `probe.py`, `result.json`, and `parent-probe.log`.

## Validation and documentation stewardship

These investigations used the current author and validator skills. They are
skill-guided investigations with parent review and follow-ups, not fresh blind
skill-validation trials. The configured interpreter was
`C:/Users/82046/anaconda3/envs/router-dump-analyzer-demo/python.exe`.
Environment discovery was initially missed by one agent; the existing map
already contains the required guidance. Denied system TEMP cleanup and
sandboxed loop initialization were recorded as environment limitations and
retried with bounded workspace-local or approved execution.

Documentation drift check: no production API, author-visible behavior,
examples, or commands changed during this investigation. The existing skills
and maintained quickstart/contract/example therefore need no additional
change for this report. The executable identity implementation needs a repair
to uphold the existing contract; this report does not redefine that contract.
