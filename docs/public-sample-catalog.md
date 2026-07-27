# Public sample-input catalog

The generated-on-demand `demo/fixtures/router-state-lab-demo.tgz` assembly is
the primary product smoke input. One generator produces its outer multi-node
assembly and the node packs used by both fabric and single-node views:

```powershell
python -m rsl_demo_generator --output demo/fixtures/router-state-lab-demo.tgz
```

The sources below broaden individual decoder, parser, and archive-safety tests
without requiring proprietary router dumps. The current public CTF seed is the
pinned Babeltrace `smalltrace` fixture downloaded to
`samples/external/ctf2-smalltrace` by
`python scripts/fetch_babeltrace_sample.py`. URLs are commit-pinned where
practical.

Review upstream license notices again before copying any fixture into a product
repository. A link and license note are not a substitute for your organization's
third-party review.

## Nested archive discovery and safety

AboutCode ExtractCode has Apache-2.0 recursive and hostile-path fixtures:

- Nested tarballs: https://raw.githubusercontent.com/aboutcode-org/extractcode/bdb7598539a8879b0325fccb8279d2214ba6241d/tests/data/extract/nested/nested_tars.tar.gz
- Expected recursive paths: https://github.com/aboutcode-org/extractcode/blob/bdb7598539a8879b0325fccb8279d2214ba6241d/tests/test_extract.py#L449
- Absolute-path negative fixture: https://raw.githubusercontent.com/aboutcode-org/extractcode/bdb7598539a8879b0325fccb8279d2214ba6241d/tests/data/archive/tgz/absolute_path.tar.gz
- Symlink negative fixture: https://raw.githubusercontent.com/aboutcode-org/extractcode/bdb7598539a8879b0325fccb8279d2214ba6241d/tests/data/archive/tgz/symlink.tar.gz
- License: https://github.com/aboutcode-org/extractcode/blob/bdb7598539a8879b0325fccb8279d2214ba6241d/apache-2.0.LICENSE

Use these for archive mechanics only. Keep the router-specific node/layer layout,
duplicate-member, expansion-bomb, deep-nesting, corrupt-inner-archive, and
`.zst.gz` cases synthetic. Add deterministic stacked-compression, corrupt, and
expansion-ratio variants to the ingestion conformance suite when those formats
are supported.

## CTF 1.8 and CTF 2

The official Babeltrace test corpus is the best decoder conformance source:

- CTF 2 passing corpus: https://github.com/efficios/babeltrace/tree/stable-2.1/tests/data/ctf-traces/2/succeed
- CTF 2 negative corpus: https://github.com/efficios/babeltrace/tree/stable-2.1/tests/data/ctf-traces/2/fail
- CTF 1.8 passing corpus: https://github.com/efficios/babeltrace/tree/stable-2.1/tests/data/ctf-traces/1/succeed
- Tiny CTF 2 fixture used here: https://github.com/efficios/babeltrace/tree/e4109f9c87f9e93c73abf32c1ffb43e5eaacc4a5/tests/data/ctf-traces/2/succeed/smalltrace
- License declaration for that pinned tree (`tests/data/*` is CC0-1.0): https://raw.githubusercontent.com/efficios/babeltrace/e4109f9c87f9e93c73abf32c1ffb43e5eaacc4a5/.reuse/dep5

Babeltrace 2 is a tool generation; CTF 2 is a format revision. Inspect the trace
metadata instead of treating the `babeltrace2` command name as a format marker.
Babeltrace 2.1 is required for full CTF 2 support through MIP 1.

Public traces do not contain the product-shaped ETG/ETE/failover/callback
model. Every generated demo node pack therefore embeds deterministic synthetic
CTF 2 filesystem traces in its raw containers, while the pinned public
`smalltrace` remains a separate decoder smoke input. Each real plug-in should
generate its own CTF domain events for success, typed failure, retry, duplicate,
missing packet, multiple streams, clock skew, and a 100K-event load case.

## Router status text and expected records

Network to Code's NTC Templates supplies Apache-2.0 raw/expected fixture pairs:

- `show ip interface` raw: https://raw.githubusercontent.com/networktocode/ntc-templates/6a024b3c6d33b2cde4d48be1af4fd2eea70f158a/tests/cisco_ios/show_ip_interface/cisco_ios_show_ip_interface.raw
- `show ip interface` expected YAML: https://raw.githubusercontent.com/networktocode/ntc-templates/6a024b3c6d33b2cde4d48be1af4fd2eea70f158a/tests/cisco_ios/show_ip_interface/cisco_ios_show_ip_interface.yml
- `show ip route` raw: https://raw.githubusercontent.com/networktocode/ntc-templates/6a024b3c6d33b2cde4d48be1af4fd2eea70f158a/tests/cisco_ios/show_ip_route/cisco_ios_show_ip_route.raw
- `show ip route` expected YAML: https://raw.githubusercontent.com/networktocode/ntc-templates/6a024b3c6d33b2cde4d48be1af4fd2eea70f158a/tests/cisco_ios/show_ip_route/cisco_ios_show_ip_route.yml
- ARP/neighbor raw: https://raw.githubusercontent.com/networktocode/ntc-templates/6a024b3c6d33b2cde4d48be1af4fd2eea70f158a/tests/cisco_ios/show_ip_arp/cisco_ios_show_ip_arp.raw
- ARP/neighbor expected YAML: https://raw.githubusercontent.com/networktocode/ntc-templates/6a024b3c6d33b2cde4d48be1af4fd2eea70f158a/tests/cisco_ios/show_ip_arp/cisco_ios_show_ip_arp.yml
- License: https://github.com/networktocode/ntc-templates/blob/6a024b3c6d33b2cde4d48be1af4fd2eea70f158a/LICENSE

FRRouting has realistic open-router topotest outputs, but its repository is
file-by-file mixed-license. Prefer generating output in an FRR lab or checking
each file's header before redistribution:

- Route-table reference: https://raw.githubusercontent.com/FRRouting/frr/78d41fd007d0ce5836b0849c9b97354f99e74032/tests/topotests/all_protocol_startup/r1/ipv4_routes.ref
- OSPF interface reference: https://raw.githubusercontent.com/FRRouting/frr/78d41fd007d0ce5836b0849c9b97354f99e74032/tests/topotests/all_protocol_startup/r1/show_ip_ospf_interface.ref
- FRR licensing guidance: https://github.com/FRRouting/frr/blob/78d41fd007d0ce5836b0849c9b97354f99e74032/COPYING

Proprietary status fixtures should be synthetic and include repeated headers,
several groups in one file, composite typed keys, CRLF and LF, truncation,
unknown columns, empty sections, malformed records, and 100K rows.

## MPLS, SRv6, EVPN, and IS-IS behavior

No single public fixture combines these protocols with the product-shaped
ETG/ETE/DTE event model. Generate the integrated semantic fixture locally and
use the following projects as behavioral oracles:

- netlab integration tests (MIT), including IS-IS/SRv6 VPN and EVPN over MPLS
  or Segment Routing:
  https://github.com/ipspace/netlab/tree/6ddb8646849d6c467fae4a9d15328c3bebcf4cf3/tests/integration
- FRRouting IS-IS/SRv6 add/remove/restore sequence:
  https://github.com/FRRouting/frr/blob/78d41fd007d0ce5836b0849c9b97354f99e74032/tests/topotests/isis_srv6_topo1/test_isis_srv6_topo1.py
- FRRouting SR-MPLS topology and MPLS-table references:
  https://github.com/FRRouting/frr/tree/78d41fd007d0ce5836b0849c9b97354f99e74032/tests/topotests/isis_sr_topo1
- FRRouting EVPN L3VNI modify/cleanup behavior:
  https://github.com/FRRouting/frr/tree/78d41fd007d0ce5836b0849c9b97354f99e74032/tests/topotests/bgp_evpn_l3vni_modify

FRRouting is mixed-license; inspect each file's SPDX header and do not copy a
whole topotest directory by assumption. The integrated demo uses original
reserved addressing, resources, state transitions, and event text. Standards
semantics come from RFC 7432 (EVPN), RFC 8667 (IS-IS SR-MPLS), RFC 9252 (BGP
overlay services over SRv6), and RFC 9352 (IS-IS SRv6 extensions).

## Arbitrary debug/error/info logs

Fluent Bit provides Apache-2.0 generic framing and severity fixtures:

- Mixed multiline/stack/panic log: https://raw.githubusercontent.com/fluent/fluent-bit/fd5ea1f0d5038a12f36421151299e0376e3d650c/documentation/examples/multiline/filter_multiline/test.log
- Small INFO/DEBUG severity log: https://raw.githubusercontent.com/fluent/fluent-bit/fd5ea1f0d5038a12f36421151299e0376e3d650c/tests/runtime/data/stackdriver/stackdriver_multi_entries_severity.log
- License: https://github.com/fluent/fluent-bit/blob/fd5ea1f0d5038a12f36421151299e0376e3d650c/LICENSE

Use them for generic encoding, line framing, severity, and multiline behavior.
Keep `lltng*debug/error/info` filenames and product-specific messages synthetic.
Add invalid UTF-8, missing timestamps, interleaved threads, oversized lines,
embedded JSON, and filename/content severity disagreement.

## gRPC and protobuf update messages

OpenConfig gNMI is a useful Apache-2.0 network-domain analogue:

- `gnmi.proto`: https://raw.githubusercontent.com/openconfig/gnmi/3208daeead54bcf307fbfe3e5ec0771981c2d596/proto/gnmi/gnmi.proto
- Update/delete examples: https://raw.githubusercontent.com/openconfig/gnmi/3208daeead54bcf307fbfe3e5ec0771981c2d596/subscribe/subscribe_test.go
- License: https://github.com/openconfig/gnmi/blob/3208daeead54bcf307fbfe3e5ec0771981c2d596/LICENSE

It models timestamped update/delete paths and typed values, but it is not a
substitute for the product schema. The official Apache-2.0 gRPC Route Guide is
useful for transport mechanics:

- Proto: https://raw.githubusercontent.com/grpc/grpc/8542e01ff47eb07247ff6cfbd545f3b6f4e9b5d3/examples/protos/route_guide.proto
- Python server: https://raw.githubusercontent.com/grpc/grpc/8542e01ff47eb07247ff6cfbd545f3b6f4e9b5d3/examples/python/route_guide/route_guide_server.py
- Sample JSON database: https://raw.githubusercontent.com/grpc/grpc/8542e01ff47eb07247ff6cfbd545f3b6f4e9b5d3/examples/python/route_guide/route_guide_db.json
- License: https://github.com/grpc/grpc/blob/8542e01ff47eb07247ff6cfbd545f3b6f4e9b5d3/LICENSE

Generate product-shaped protobuf-JSON, textproto, and binary messages from a toy
schema. Cover create/update/delete, unknown actions, absent optionals, UUID arrays,
nested text properties, duplicates/retries, fan-out, typed error status, schema
evolution, and unknown fields. Do not use captured production gRPC traffic.
