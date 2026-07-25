# Minimal router analyzer plug-in

This directory is a complete, installable example of the current
`AnalyzerPlugin` contract. It recognizes one file named
`minimal-status.jsonl` and maps each line to a typed `INTERFACE` snapshot plus
a retained source record.

The example deliberately implements only status parsing:

- the plug-in owns the JSONL vocabulary, interface key, status normalization,
  resource descriptor, short source summary, and exact copied text;
- the core owns artifact access, validation, persistence, temporal
  reconstruction, and rendering;
- `AnalyzerPluginBase` supplies safe no-ops for unadvertised optional hooks and
  fails loudly if a declared capability has no override.

## Install and test from the repository root

```powershell
python -m pip install -e .
python -m pip install --no-deps -e examples/minimal_plugin
router-dump-plugin-validate minimal_router --artifact examples/minimal_plugin/fixtures/minimal-status.jsonl --node-hint router-1 --metadata platform=minimal-router-os --metadata software_version=1
python -m unittest discover -s examples/minimal_plugin/tests -v
```

The repository-root install is the protocol-neutral
`router-dump-analyzer-core` distribution. This example deliberately has no
dependency on `router-dump-analyzer-demo` or its synthetic plug-in policies.

The entry point is published under `router_dump_analyzer.plugins` as
`minimal_router`. An application discovers the object
`minimal_router_plugin:plugin`; it must never import executable code from the
router dump itself.

## Fixture format

Each non-empty JSONL line is one complete interface observation:

```json
{"kind":"interface","captured_at_ns":1759680000000000000,"ifindex":7,"name":"xe-0/0/0","admin_status":"up","oper_status":"up","description":"core uplink"}
```

This teaching format assumes:

- the core has already inventoried the file and supplies a quota-enforced
  `ArtifactReader`;
- inventory metadata contains `platform=minimal-router-os` and
  `software_version=1` before the probe can claim an exact match;
- `captured_at_ns` is a device-clock timestamp for that individual record, not
  a fabricated dump-wide instant;
- `ifindex` is stable for the analyzed revision and is therefore the typed
  resource key;
- `oper_status=up` means `healthy`, `down` means `error`, and any other accepted
  value means `unknown`. That mapping is device semantics and belongs here,
  not in core code.

The fixture and golden tests produce two independent resources: ifindex 7 is
healthy and ifindex 8 is in error. Each accepted row also emits
`SourceRecordEmission(source_type="status-json")`. Its `message` is the bounded
hover summary, while `copy_text` is the already-safe original JSON line. The
declared `Status input` source group labels the generic selection action
`Copy status rows`. The plug-in supplies already-safe text, core resolves and
bounds the requested selection, the host authorizes it, and the browser performs
the clipboard write.

## Why advanced forwarding is not in this minimal example

This package intentionally stops at status parsing. A plug-in that also
advertises `FORWARDING_PROJECTION` may attach typed
`ForwardingCandidateConstraint` values to a `ForwardingMember` and provide the
full local context for `ForwardingTraversalStateKey`. Core then evaluates the
exact ingress-scope rule and detects exact repeated traversal states. Device
and protocol meanings such as EVPN or BGP split horizon remain in that advanced
plug-in; generic comparison, bounds, cycle reporting, and rendering remain in
core. Advanced plug-ins must also distinguish a complete known-empty scope set
from incomplete scope evidence; core treats the latter as unknown, not as an
automatic policy permit.

An advanced route plug-in must also keep the immutable packet source and
destination separate from the trace start/ingress. It declares local endpoint
attachments and terminal delivery evidence; core exact-matches directional
goals and does not require a return path to revisit a transit forward start.
Path symmetry remains descriptive rather than a consistency rule. Every
plug-in-selected active branch contributes to the directional result, so mixed
success/failure remains partial and incomplete evidence remains unknown.

An advanced plug-in may additionally advertise `FORWARDING_TRACE` and answer
one bounded `ForwardingStepRequest` with a `ForwardingStepResult`. It declares
ordered outermost-to-innermost packet layers, exact before/after transitions,
device-owned disposition and MTU semantics, and evidence. Core validates
continuity and exact-basis size arithmetic without interpreting MPLS, SRv6,
VPN, IP-in-IP, or proprietary contracts. User-forced steering stays marked
counterfactual and never replaces observed reachability. Advanced bundled
scenarios exercise the generic evaluators through a demo provider, but the
server does not yet discover and orchestrate this hook across every installed
member.

Follow “Route endpoints and trace starts”, “Packet transformations and
trace-time forwarding”, and “Forwarding loops and ingress-dependent policy” in
the
[plug-in author quickstart](../../docs/plugin-author-quickstart.md) and its
executable conformance cases before adding that capability. Do not copy
placeholder forwarding hooks into this status-only teaching package.
