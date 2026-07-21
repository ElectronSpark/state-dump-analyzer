"""Generate a deterministic synthetic router dump with nested layer archives.

The fixture uses general names and contains no proprietary formats. A real CTF 2
trace from the public Babeltrace corpus is embedded when it has been fetched by
``fetch_babeltrace_sample.py``.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import shutil
import struct
import tarfile
import tempfile
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

try:
    from .ctf_fixture import FILES as CTF_FILES, validate_blob
except ImportError:  # Direct ``python scripts/generate_sample_bundle.py`` use.
    from ctf_fixture import FILES as CTF_FILES, validate_blob


CAPTURE_NS = 1_759_680_006_000_000_000
OWNERSHIP_MARKER = b"router-dump-analyzer sample generator v1\n"


# Presentation belongs to this illustrative plug-in fixture, not to the core.
PLUGIN_RESOURCE_ICON_PATHS = {
    "DTE": "M3 12h12m-4-4 4 4-4 4M18 5h3v14h-3",
    "ETE": "M5 19c0-4 2-6 6-6h3c3 0 5-2 5-6M16 7h3V4M5 21a2 2 0 1 0 0-4 2 2 0 0 0 0 4",
    "ETG": "M4 7l8-4 8 4-8 4zM4 7v10l8 4 8-4V7M12 11v10",
    "EVPN_ROUTE": "M4 6h16M4 12h11M4 18h8M16 15l4 3-4 3",
    "FORWARDING_GROUP": "M5 4v16M5 8h8M5 16h8M13 5l3 3-3 3M13 13l3 3-3 3",
    "GLUE": "M9 15l6-6M7.5 17.5l-1 1a3.5 3.5 0 0 1-5-5l3-3a3.5 3.5 0 0 1 5 0M16.5 6.5l1-1a3.5 3.5 0 0 1 5 5l-3 3a3.5 3.5 0 0 1-5 0",
    "IP_ROUTING": "M4 5h6v6H4zM14 3v4M12 5h4M17 13h3v7h-7v-3M10 8l7 9",
    "ISIS_ADJACENCY": "M8 12h8M5 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8M19 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8",
    "MPLS_LABEL_ENTRY": "M4 5h10l6 7-6 7H4zM8 9h.01",
    "MPLS_PREFIX_SID": "M4 5h10l6 7-6 7H4zM8 9h.01M10 15h6",
    "PHYSICAL_INTERFACE": "M5 4h14v12H5zM8 16v4M16 16v4M8 8h2v3H8zM14 8h2v3h-2z",
    "SRV6_LOCAL_SID": "M12 3l8 4.5v9L12 21l-8-4.5v-9zM9 12h6M12 9v6",
    "SRV6_LOCATOR": "M12 21s7-5.5 7-12a7 7 0 1 0-14 0c0 6.5 7 12 7 12zM9 9h6M12 6v6",
    "VIRTUAL_INTERFACE": "M4 5h16v10H4zM8 19h8M12 15v4",
    "VRF": "M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z",
}


CONTROL_STATUS = """\
=== INTERFACES ===
Interface: Ethernet1
  Admin state: up
  Operational state: up
  IPv4 address: 192.0.2.1/31
  VRF: blue

Interface: Ethernet2
  Admin state: up
  Operational state: down
  IPv4 address: 198.51.100.1/31
  VRF: blue

=== ROUTES ===
VRF   Prefix          Protocol  Preference  Next hop       Interface  Selected
blue  203.0.113.0/24  bgp       20          192.0.2.0      Ethernet1  yes
blue  192.0.2.128/25  static    1           198.51.100.0   Ethernet2  yes

=== CONTROL RESOURCES ===
Kind  Key                    State     Depends on
ETG   vrf=blue,id=etg-100    ready     fg-7
ETE   etg=etg-100,id=ete-a   active    nbr-192.0.2.0
ETE   etg=etg-100,id=ete-b   standby   nbr-198.51.100.0
NBR   vrf=blue,ip=192.0.2.0  reachable Ethernet1
NBR   vrf=blue,ip=198.51.100.0 failed  Ethernet2
"""


BRIDGE_STATUS = """\
Resource-Type: ETG
Key: vrf=blue,id=etg-100
Program-State: programmed
Failover-Group: fg-7
Hardware-Link: hw-etg-44
Entries: ete-a,ete-b
---
Resource-Type: ETE
Key: etg=etg-100,id=ete-a
Program-State: programmed
Neighbor: 192.0.2.0
Role: primary
---
Resource-Type: ETE
Key: etg=etg-100,id=ete-b
Program-State: error
Neighbor: 198.51.100.0
Role: backup
Last-Error: neighbor-unresolved
---
Resource-Type: FG
Key: id=fg-7
Primary: ete-a
Backup: ete-b
Selected: ete-a
"""


HARDWARE_STATUS = """\
OBJECT     ID         PARENT     ADMIN  OPER    RESULT
TUNNEL-GRP hw-etg-44  -          up     up      OK
TUNNEL-ENT hw-ete-51  hw-etg-44  up     up      OK
TUNNEL-ENT hw-ete-52  hw-etg-44  up     down    NBR_MISS
FAILOVER   hw-fg-9    -          up     active  PRIMARY

NEIGHBOR TABLE
VRF   ADDRESS         PORT       STATE
blue  192.0.2.0       Ethernet1  reachable
blue  198.51.100.0    Ethernet2  failed
"""


DOMAIN_EVENTS = [
    {
        "timestamp_ns": "1759680000100000000",
        "clock_domain": "node-a-realtime",
        "layer": "control-plane",
        "event_name": "lltng_route_update",
        "resource": "route:blue:203.0.113.0/24",
        "action": "create",
        "properties": {"next_hop": "192.0.2.0", "etg": "etg-100"},
        "result": {"routeStatus": "Ok"},
    },
    {
        "timestamp_ns": "1759680000130000000",
        "clock_domain": "node-a-realtime",
        "layer": "data-bridge-layer",
        "event_name": "lltng_etg_update",
        "resource": "etg:blue:etg-100",
        "action": "create",
        "properties": {"failover_group": "fg-7", "entries": ["ete-a", "ete-b"]},
        "result": {"bridgeStatus": "Ok"},
    },
    {
        "timestamp_ns": "1759680000170000000",
        "clock_domain": "node-a-realtime",
        "layer": "hardware-driver-plane",
        "event_name": "lltng_tunnel_program",
        "resource": "tunnel-group:hw-etg-44",
        "action": "create",
        "properties": {"source_etg": "etg-100", "entry_count": 2},
        "result": {"driverStatus": "Ok"},
    },
    {
        "timestamp_ns": "1759680001500000000",
        "clock_domain": "node-a-realtime",
        "layer": "data-bridge-layer",
        "event_name": "lltng_ete_dependency_update",
        "resource": "ete:etg-100:ete-a",
        "action": "update",
        "properties": {
            "before_neighbor": "192.0.2.2",
            "after_neighbor": "192.0.2.0",
        },
        "result": {"bridgeStatus": "Ok"},
    },
    {
        "timestamp_ns": "1759680003000000000",
        "clock_domain": "node-a-realtime",
        "layer": "hardware-driver-plane",
        "event_name": "lltng_neighbor_event",
        "resource": "neighbor:blue:198.51.100.0",
        "action": "state-change",
        "properties": {"before": "reachable", "after": "failed"},
        "result": {"driverStatus": "Ok"},
    },
    {
        "timestamp_ns": "1759680003015000000",
        "clock_domain": "node-a-realtime",
        "layer": "data-bridge-layer",
        "event_name": "lltng_ete_update",
        "resource": "ete:etg-100:ete-b",
        "action": "update",
        "properties": {"program_state": "error", "error": "neighbor-unresolved"},
        "result": {"bridgeStatus": "DependencyError"},
    },
]

# Additional events form a deliberately compact but cross-protocol story.  The
# original six records remain in the raw layer exports for compatibility with
# early fixture consumers.
DOMAIN_EVENTS.extend(
    [
        {"timestamp_ns": "1759680000010000000", "clock_domain": "node-a-realtime", "layer": "control-plane", "event_name": "isis_adj_p1_create", "resource": "isis-adjacency:pe-a:p-1", "action": "create", "properties": {"level": 2, "system_id": "0000.0000.0001"}, "result": {"isisStatus": "Ok"}},
        {"timestamp_ns": "1759680000020000000", "clock_domain": "node-a-realtime", "layer": "control-plane", "event_name": "isis_adj_p2_create", "resource": "isis-adjacency:pe-a:p-2", "action": "create", "properties": {"level": 2, "system_id": "0000.0000.0002"}, "result": {"isisStatus": "Ok"}},
        {"timestamp_ns": "1759680000030000000", "clock_domain": "node-a-realtime", "layer": "control-plane", "event_name": "srv6_locator_create", "resource": "srv6-locator:pe-b", "action": "create", "properties": {"prefix": "fc00:0:2::/48"}, "result": {"srv6Status": "Ok"}},
        {"timestamp_ns": "1759680000140000000", "clock_domain": "node-a-realtime", "layer": "data-bridge-layer", "event_name": "dte_ingress_create", "resource": "dte:dte-mpls-16011", "action": "create", "properties": {"match": {"mpls_label": 16011}, "action": "swap", "out_label": 16012}, "result": {"bridgeStatus": "Ok"}},
        {"timestamp_ns": "1759680002000000000", "clock_domain": "node-a-realtime", "layer": "data-bridge-layer", "event_name": "ete_backup_add", "resource": "ete:etg-evpn-east:ete-srv6-p2", "action": "add", "properties": {"path": "via-p2", "segments": ["fc00:0:2:100::"]}, "result": {"bridgeStatus": "Ok"}},
        {"timestamp_ns": "1759680003010000000", "clock_domain": "node-a-realtime", "layer": "control-plane", "event_name": "isis_adj_p1_down", "resource": "isis-adjacency:pe-a:p-1", "action": "state-change", "properties": {"before": "up", "after": "down"}, "result": {"isisStatus": "Ok"}},
        {"timestamp_ns": "1759680003012000000", "clock_domain": "node-a-realtime", "layer": "data-bridge-layer", "event_name": "ete_primary_degraded", "resource": "ete:etg-evpn-east:ete-srmpls-p1", "action": "update", "properties": {"before": "active", "after": "ineligible"}, "result": {"bridgeStatus": "Ok"}},
        {"timestamp_ns": "1759680003020000000", "clock_domain": "node-a-realtime", "layer": "data-bridge-layer", "event_name": "fg_failover_select", "resource": "forwarding-group:fg-blue-east", "action": "update", "properties": {"before": "ete-srmpls-p1", "after": "ete-srv6-p2"}, "result": {"bridgeStatus": "Ok"}},
        {"timestamp_ns": "1759680003021000000", "clock_domain": "node-a-realtime", "layer": "control-plane", "event_name": "evpn_mac_withdraw", "resource": "evpn-route:blue:mac-02:00:00:00:00:11", "action": "delete", "properties": {"route_type": 2}, "result": {"evpnStatus": "Ok"}},
        {"timestamp_ns": "1759680003023000000", "clock_domain": "node-a-realtime", "layer": "control-plane", "event_name": "evpn_mac_relearn", "resource": "evpn-route:blue:mac-02:00:00:00:00:11", "action": "create", "properties": {"route_type": 2, "mobility_sequence": 8}, "result": {"evpnStatus": "Ok"}},
        {"timestamp_ns": "1759680003025000000", "clock_domain": "node-a-realtime", "layer": "control-plane", "event_name": "evpn_prefix_reselect", "resource": "route:blue:203.0.113.0/24", "action": "update", "properties": {"selected_path": "p2"}, "result": {"evpnStatus": "Ok"}},
        {"timestamp_ns": "1759680003500000000", "clock_domain": "node-a-realtime", "layer": "data-bridge-layer", "event_name": "ete_retry_success", "resource": "ete:etg-evpn-east:ete-srv6-p2", "action": "update", "properties": {"program_state": "programmed", "role": "selected"}, "result": {"bridgeStatus": "Ok"}},
        {"timestamp_ns": "1759680004000000000", "clock_domain": "node-a-realtime", "layer": "control-plane", "event_name": "evpn_vni_modify", "resource": "evpn-route:blue:203.0.113.0/24", "action": "update", "properties": {"before_vni": 3109, "after_vni": 60810}, "result": {"evpnStatus": "Ok"}},
        {"timestamp_ns": "1759680004100000000", "clock_domain": "node-a-realtime", "layer": "data-bridge-layer", "event_name": "dte_action_modify", "resource": "dte:dte-mpls-16011", "action": "update", "properties": {"before": {"action": "swap", "label": 16012}, "after": {"action": "pop"}}, "result": {"bridgeStatus": "Ok"}},
        {"timestamp_ns": "1759680004500000000", "clock_domain": "node-a-realtime", "layer": "data-bridge-layer", "event_name": "ete_primary_delete", "resource": "ete:etg-evpn-east:ete-srmpls-p1", "action": "delete", "properties": {"reason": "path-retired"}, "result": {"bridgeStatus": "Ok"}},
        {"timestamp_ns": "1759680005000000000", "clock_domain": "node-a-realtime", "layer": "hardware-driver-plane", "event_name": "port_p1_restore", "resource": "interface:Ethernet1", "action": "state-change", "properties": {"before": "down", "after": "up"}, "result": {"driverStatus": "Ok"}},
        {"timestamp_ns": "1759680005010000000", "clock_domain": "node-a-realtime", "layer": "control-plane", "event_name": "isis_adj_p1_up", "resource": "isis-adjacency:pe-a:p-1", "action": "state-change", "properties": {"before": "down", "after": "up"}, "result": {"isisStatus": "Ok"}},
        {"timestamp_ns": "1759680005020000000", "clock_domain": "node-a-realtime", "layer": "data-bridge-layer", "event_name": "ete_existing_add", "resource": "ete:etg-core-srv6:ete-core-p2", "action": "add", "properties": {"existing": True, "metric": 15}, "result": {"bridgeStatus": "Ok"}},
        {"timestamp_ns": "1759680005500000000", "clock_domain": "node-a-realtime", "layer": "hardware-driver-plane", "event_name": "srv6_sid_update", "resource": "local-sid:fc00:0:1:100::", "action": "update", "properties": {"behavior": "End.DT4", "vrf": "blue"}, "result": {"driverStatus": "Ok"}},
    ]
)


EVENT_METADATA: dict[str, dict[str, object]] = {
    "lltng_route_update": {"resource_id": "control-plane/EVPN_ROUTE/blue/203.0.113.0/24", "effects": [{"resource_id": "control-plane/EVPN_ROUTE/blue/203.0.113.0/24", "effect_type": "create", "state_changed": True}]},
    "lltng_etg_update": {"resource_id": "data-bridge-layer/ETG/blue/etg-evpn-east", "effects": [
        {"resource_id": "data-bridge-layer/FORWARDING_GROUP/fg-blue-east", "effect_type": "create", "state_changed": True},
        {"resource_id": "data-bridge-layer/ETG/blue/etg-evpn-east", "effect_type": "create", "state_changed": True},
        {"resource_id": "data-bridge-layer/ETG/blue/etg-core-srv6", "effect_type": "create", "state_changed": True},
        {"resource_id": "data-bridge-layer/ETE/etg-evpn-east/ete-srmpls-p1", "effect_type": "create", "state_changed": True},
        {"resource_id": "data-bridge-layer/ETE/etg-core-srv6/ete-core-p2", "effect_type": "create", "state_changed": True},
    ]},
    "lltng_tunnel_program": {"resource_id": "hardware-driver-plane/MPLS_LABEL_ENTRY/16011", "effects": [{"resource_id": "hardware-driver-plane/MPLS_LABEL_ENTRY/16011", "effect_type": "create", "state_changed": True}]},
    "lltng_ete_dependency_update": {"resource_id": "data-bridge-layer/ETE/etg-evpn-east/ete-srmpls-p1", "effects": [{"resource_id": "data-bridge-layer/ETE/etg-evpn-east/ete-srmpls-p1", "effect_type": "modify", "state_changed": True}]},
    "lltng_neighbor_event": {"resource_id": "hardware-driver-plane/PHYSICAL_INTERFACE/Ethernet1", "effects": [{"resource_id": "hardware-driver-plane/PHYSICAL_INTERFACE/Ethernet1", "effect_type": "modify", "state_changed": True}]},
    "lltng_ete_update": {"resource_id": "data-bridge-layer/ETE/etg-evpn-east/ete-srv6-p2", "effects": []},
    "isis_adj_p1_create": {"resource_id": "control-plane/ISIS_ADJACENCY/pe-a/p-1", "effects": [{"resource_id": "control-plane/ISIS_ADJACENCY/pe-a/p-1", "effect_type": "create", "state_changed": True}]},
    "isis_adj_p2_create": {"resource_id": "control-plane/ISIS_ADJACENCY/pe-a/p-2", "effects": [{"resource_id": "control-plane/ISIS_ADJACENCY/pe-a/p-2", "effect_type": "create", "state_changed": True}]},
    "srv6_locator_create": {"resource_id": "control-plane/SRV6_LOCATOR/pe-b/fc00:0:2::/48", "effects": [{"resource_id": "control-plane/SRV6_LOCATOR/pe-b/fc00:0:2::/48", "effect_type": "create", "state_changed": True}]},
    "dte_ingress_create": {"resource_id": "data-bridge-layer/DTE/dte-mpls-16011", "effects": [{"resource_id": "data-bridge-layer/DTE/dte-mpls-16011", "effect_type": "create", "state_changed": True}]},
    "ete_backup_add": {"resource_id": "data-bridge-layer/ETE/etg-evpn-east/ete-srv6-p2", "effects": [{"resource_id": "data-bridge-layer/ETE/etg-evpn-east/ete-srv6-p2", "effect_type": "create", "state_changed": True}]},
    "isis_adj_p1_down": {"resource_id": "control-plane/ISIS_ADJACENCY/pe-a/p-1", "effects": [{"resource_id": "control-plane/ISIS_ADJACENCY/pe-a/p-1", "effect_type": "modify", "state_changed": True}]},
    "ete_primary_degraded": {"resource_id": "data-bridge-layer/ETE/etg-evpn-east/ete-srmpls-p1", "effects": [{"resource_id": "data-bridge-layer/ETE/etg-evpn-east/ete-srmpls-p1", "effect_type": "modify", "state_changed": True}]},
    "fg_failover_select": {"resource_id": "data-bridge-layer/FORWARDING_GROUP/fg-blue-east", "effects": [{"resource_id": "data-bridge-layer/FORWARDING_GROUP/fg-blue-east", "effect_type": "modify", "state_changed": True}]},
    "evpn_mac_withdraw": {"resource_id": "control-plane/EVPN_ROUTE/blue/mac-02:00:00:00:00:11", "effects": [{"resource_id": "control-plane/EVPN_ROUTE/blue/mac-02:00:00:00:00:11", "effect_type": "delete", "state_changed": True}]},
    "evpn_mac_relearn": {"resource_id": "control-plane/EVPN_ROUTE/blue/mac-02:00:00:00:00:11", "effects": [{"resource_id": "control-plane/EVPN_ROUTE/blue/mac-02:00:00:00:00:11", "effect_type": "create", "state_changed": True}]},
    "evpn_prefix_reselect": {"resource_id": "control-plane/EVPN_ROUTE/blue/203.0.113.0/24", "effects": [{"resource_id": "control-plane/EVPN_ROUTE/blue/203.0.113.0/24", "effect_type": "modify", "state_changed": True}]},
    "ete_retry_success": {"resource_id": "data-bridge-layer/ETE/etg-evpn-east/ete-srv6-p2", "effects": [{"resource_id": "data-bridge-layer/ETE/etg-evpn-east/ete-srv6-p2", "effect_type": "modify", "state_changed": True}]},
    "evpn_vni_modify": {"resource_id": "control-plane/EVPN_ROUTE/blue/203.0.113.0/24", "effects": [{"resource_id": "control-plane/EVPN_ROUTE/blue/203.0.113.0/24", "effect_type": "modify", "state_changed": True}]},
    "dte_action_modify": {"resource_id": "data-bridge-layer/DTE/dte-mpls-16011", "effects": [{"resource_id": "data-bridge-layer/DTE/dte-mpls-16011", "effect_type": "modify", "state_changed": True}]},
    "ete_primary_delete": {"resource_id": "data-bridge-layer/ETE/etg-evpn-east/ete-srmpls-p1", "effects": [{"resource_id": "data-bridge-layer/ETE/etg-evpn-east/ete-srmpls-p1", "effect_type": "delete", "state_changed": True}]},
    "port_p1_restore": {"resource_id": "hardware-driver-plane/PHYSICAL_INTERFACE/Ethernet1", "effects": [{"resource_id": "hardware-driver-plane/PHYSICAL_INTERFACE/Ethernet1", "effect_type": "modify", "state_changed": True}]},
    "isis_adj_p1_up": {"resource_id": "control-plane/ISIS_ADJACENCY/pe-a/p-1", "effects": [{"resource_id": "control-plane/ISIS_ADJACENCY/pe-a/p-1", "effect_type": "modify", "state_changed": True}]},
    "ete_existing_add": {"resource_id": "data-bridge-layer/ETE/etg-core-srv6/ete-core-p2", "effects": [{"resource_id": "data-bridge-layer/ETE/etg-core-srv6/ete-core-p2", "effect_type": "modify", "state_changed": True}]},
    "srv6_sid_update": {"resource_id": "hardware-driver-plane/SRV6_LOCAL_SID/fc00:0:1:100::", "effects": [{"resource_id": "hardware-driver-plane/SRV6_LOCAL_SID/fc00:0:1:100::", "effect_type": "modify", "state_changed": True}]},
}

# Preserve source sequence semantics even though compatibility and comprehensive
# records are declared in separate blocks.
DOMAIN_EVENTS.sort(key=lambda item: int(str(item["timestamp_ns"])))


GRPC_PROTO = """\
syntax = "proto3";
package sample.router;

import "google/protobuf/struct.proto";

message StringList {
  repeated string values = 1;
}

message UInt64List {
  repeated uint64 values = 1;
}

message PropertyValue {
  oneof kind {
    int64 int_value = 1;
    double double_value = 2;
    string string_value = 3;
    bytes bytes_value = 4;
    StringList string_list = 5;
    UInt64List uint64_list = 6;
    google.protobuf.Struct object_value = 7;
  }
}

message ResourceUpdate {
  string resource_kind = 1;
  string resource_key = 2;
  string action = 3;
  map<string, PropertyValue> properties = 4;
  string request_id = 5;
}

service ResourceService {
  rpc Apply(ResourceUpdate) returns (ApplyResult);
}

message ApplyResult {
  string status = 1;
  string detail = 2;
}
"""


DEBUG_LOG = """\
2025-10-05T16:00:00.120000000Z INFO  request=req-001 received route update
2025-10-05T16:00:01.500000000Z INFO  resource=ete-a dependency changed to 192.0.2.0
2025-10-05T16:00:03.014000000Z ERROR resource=ete-b neighbor 198.51.100.0 unresolved
2025-10-05T16:00:03.016000000Z INFO  failover-group=fg-7 remains on primary ete-a
"""


ILLUSTRATIVE_RESOURCES = [
    {
        "node": "node-a",
        "layer": "data-bridge-layer",
        "kind": "ETG",
        "key": {"vrf": "blue", "id": "etg-100"},
        "state": {"program_state": "programmed", "failover_group": "fg-7"},
        "provenance": "observed",
        "quality": "exact",
        "observed_at_min_ns": str(CAPTURE_NS),
        "observed_at_max_ns": str(CAPTURE_NS),
        "evidence": [
            {
                "logical_path": "node-a/data-bridge-layer.tgz!/var/lib/bridge-dump/status/resources.txt",
                "locator": "resource:ETG:etg-100",
            }
        ],
    },
    {
        "node": "node-a",
        "layer": "data-bridge-layer",
        "kind": "ETE",
        "key": {"etg": "etg-100", "id": "ete-b"},
        "state": {"program_state": "error", "neighbor": "198.51.100.0"},
        "provenance": "observed",
        "quality": "exact",
        "observed_at_min_ns": str(CAPTURE_NS),
        "observed_at_max_ns": str(CAPTURE_NS),
        "evidence": [
            {
                "logical_path": "node-a/data-bridge-layer.tgz!/var/lib/bridge-dump/status/resources.txt",
                "locator": "resource:ETE:ete-b",
            }
        ],
    },
]


ILLUSTRATIVE_RELATIONSHIPS = [
    {
        "source": "control-plane/ROUTE/blue/203.0.113.0/24",
        "target": "data-bridge-layer/ETG/blue/etg-100",
        "type": "resolves_via",
        "provenance": "event_derived",
        "quality": "best_effort",
        "evidence": [
            {
                "logical_path": "node-a/control-plane.tgz!/var/lib/control-dump/trace/lltng_domain_export.jsonl",
                "locator": "event:lltng_route_update:0",
            }
        ],
    },
    {
        "source": "data-bridge-layer/ETG/blue/etg-100",
        "target": "data-bridge-layer/FG/fg-7",
        "type": "depends_on",
        "provenance": "observed",
        "quality": "exact",
    },
    {
        "source": "data-bridge-layer/ETG/blue/etg-100",
        "target": "data-bridge-layer/ETE/etg-100/ete-a",
        "type": "owns",
        "provenance": "observed",
        "quality": "exact",
    },
    {
        "source": "data-bridge-layer/ETG/blue/etg-100",
        "target": "data-bridge-layer/ETE/etg-100/ete-b",
        "type": "owns",
        "provenance": "observed",
        "quality": "exact",
    },
    {
        "source": "data-bridge-layer/ETG/blue/etg-100",
        "target": "hardware-driver-plane/TUNNEL-GRP/hw-etg-44",
        "type": "cross_layer",
        "provenance": "observed",
        "quality": "exact",
    },
    {
        "source": "data-bridge-layer/ETE/etg-100/ete-a",
        "target": "control-plane/NBR/blue/192.0.2.0",
        "type": "references",
        "provenance": "observed",
        "quality": "exact",
    },
    {
        "source": "data-bridge-layer/ETE/etg-100/ete-b",
        "target": "control-plane/NBR/blue/198.51.100.0",
        "type": "references",
        "provenance": "observed",
        "quality": "exact",
    },
]


def _jsonl(records: list[dict[str, object]]) -> bytes:
    return b"".join(
        (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()
        for record in records
    )


def _normalized_domain_events() -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    per_layer_sequence: dict[str, int] = {}
    for event in DOMAIN_EVENTS:
        layer = str(event["layer"])
        sequence = per_layer_sequence.get(layer, 0)
        per_layer_sequence[layer] = sequence + 1
        source_id = f"node-a/{layer}/lltng_domain_export"
        locator = f"jsonl-record:{sequence}"
        event_uid = hashlib.sha256(f"{source_id}|{locator}".encode()).hexdigest()
        results = tuple(str(value) for value in dict(event["result"]).values())
        outcome = (
            "success"
            if results and all(value == "Ok" for value in results)
            else "failure"
            if results and any(value != "Ok" for value in results)
            else "unknown"
        )
        metadata = EVENT_METADATA.get(str(event["event_name"]), {})
        primary_resource_id = str(metadata.get("resource_id", event["resource"]))
        effects = [dict(item) for item in metadata.get("effects", [])]
        subject_ids = list(
            dict.fromkeys(
                [primary_resource_id]
                + [str(item["resource_id"]) for item in effects if item.get("resource_id")]
            )
        )
        records.append(
            {
                "event_uid": event_uid,
                "timestamp_ns": event["timestamp_ns"],
                "timestamp_uncertainty_ns": "0",
                "clock_domain": event["clock_domain"],
                "source_sequence": sequence,
                "event_type": event["event_name"],
                "action": event["action"],
                "outcome": outcome,
                "state_changed": bool(effects) and outcome != "failure",
                "effects": effects if outcome != "failure" else [],
                "attributes": {
                    "properties": event["properties"],
                    "result": event["result"],
                },
                "subjects": [
                    {
                        "node": "node-a",
                        "layer": identifier.split("/", 1)[0] if "/" in identifier else layer,
                        "raw_key": event["resource"],
                        "resource_id": identifier,
                    }
                    for identifier in subject_ids
                ],
                "provenance": "observed",
                "quality": "exact",
                "source": {
                    "source_id": source_id,
                    "message_ordinal": sequence,
                },
                "evidence": {
                    "logical_path": (
                        f"node-a/{layer}.tgz!/"
                        + (
                            "var/lib/control-dump/trace/lltng_domain_export.jsonl"
                            if layer == "control-plane"
                            else "var/lib/bridge-dump/mnt/trace/lltng_domain_export.jsonl"
                            if layer == "data-bridge-layer"
                            else "opt/driver-dump/trace/lltng_domain_export.jsonl"
                        )
                    ),
                    "locator": locator,
                    "raw_timestamp_ns": event["timestamp_ns"],
                    "clock_domain": event["clock_domain"],
                },
            }
        )
    return records


def _write_comprehensive_illustrative(
    illustrative: Path, normalized_events: list[dict[str, object]]
) -> None:
    """Write the product-shaped temporal projection used by the web demo."""

    uids = {
        str(event["event_type"]): str(event["event_uid"])
        for event in normalized_events
    }
    t = {
        str(event["event_type"]): str(event["timestamp_ns"])
        for event in normalized_events
    }

    def resource(
        identifier: str,
        kind: str,
        label: str,
        state: dict[str, Any],
        key: dict[str, Any],
        *,
        tags: list[str] | None = None,
    ) -> dict[str, Any]:
        layer = identifier.split("/", 1)[0]
        return {
            "resource_id": identifier,
            "node": "node-a",
            "layer": layer,
            "kind": kind,
            "label": label,
            "key": key,
            "state": state,
            "presentation_tags": tags or [],
            "plugin_defined": True,
            "provenance": "reconstructed",
            "quality": "exact",
            "evidence": [
                {
                    "logical_path": f"node-a/{layer}.tgz",
                    "locator": f"plugin-derived-resource:{identifier}",
                }
            ],
            "observed_at_min_ns": str(CAPTURE_NS),
            "observed_at_max_ns": str(CAPTURE_NS),
        }

    resources = [
        resource("control-plane/VRF/blue", "VRF", "blue", {"status": "active", "rd": "65000:3109"}, {"name": "blue"}),
        resource("control-plane/ISIS_ADJACENCY/pe-a/p-1", "ISIS_ADJACENCY", "PE-A ↔ P-1", {"status": "up", "level": 2, "metric": 10}, {"local": "pe-a", "remote": "p-1"}),
        resource("control-plane/ISIS_ADJACENCY/pe-a/p-2", "ISIS_ADJACENCY", "PE-A ↔ P-2", {"status": "up", "level": 2, "metric": 20}, {"local": "pe-a", "remote": "p-2"}),
        resource("control-plane/EVPN_ROUTE/blue/203.0.113.0/24", "EVPN_ROUTE", "Type-5 203.0.113.0/24", {"status": "selected", "route_type": 5, "vni": 60810}, {"vrf": "blue", "nlri": "203.0.113.0/24"}),
        resource("control-plane/EVPN_ROUTE/blue/mac-02:00:00:00:00:11", "EVPN_ROUTE", "Type-2 02:00:00:00:00:11", {"status": "selected", "route_type": 2, "mobility_sequence": 8}, {"vrf": "blue", "mac": "02:00:00:00:00:11"}),
        resource("control-plane/MPLS_PREFIX_SID/p-1/16011", "MPLS_PREFIX_SID", "P-1 prefix SID 16011", {"status": "active", "label": 16011, "algorithm": 0}, {"node": "p-1", "label": 16011}),
        resource("control-plane/SRV6_LOCATOR/pe-b/fc00:0:2::/48", "SRV6_LOCATOR", "PE-B locator", {"status": "active", "prefix": "fc00:0:2::/48"}, {"node": "pe-b", "prefix": "fc00:0:2::/48"}),
        resource("control-plane/IP_ROUTING/blue", "IP_ROUTING", "IPv4 routing in blue", {"status": "ready", "afi": "ipv4"}, {"vrf": "blue", "afi": "ipv4"}),
        resource("data-bridge-layer/FORWARDING_GROUP/fg-blue-east", "FORWARDING_GROUP", "Blue eastbound forwarding", {"status": "active", "direction": "eastbound", "selected_ete": "ete-srv6-p2"}, {"id": "fg-blue-east"}),
        resource("data-bridge-layer/ETG/blue/etg-evpn-east", "ETG", "EVPN east ETG", {"status": "programmed", "overlay_destination": "203.0.113.0/24", "encapsulation_actions": [{"operation": "push_vlan", "vlan": 60810}, {"operation": "push_mpls", "labels": [24001]}]}, {"vrf": "blue", "id": "etg-evpn-east"}),
        resource("data-bridge-layer/ETG/blue/etg-core-srv6", "ETG", "SRv6 core ETG", {"status": "programmed", "overlay_destination": "pe-b", "encapsulation_actions": [{"operation": "encap_ipv6"}, {"operation": "push_srv6", "sids": ["fc00:0:2:100::"]}]}, {"vrf": "blue", "id": "etg-core-srv6"}),
        resource("data-bridge-layer/ETE/etg-evpn-east/ete-srmpls-p1", "ETE", "SR-MPLS path via P-1", {"status": "deleted", "path": "via-p1", "encapsulation": {"labels": [24001, 16011]}}, {"etg": "etg-evpn-east", "id": "ete-srmpls-p1"}),
        resource("data-bridge-layer/ETE/etg-evpn-east/ete-srv6-p2", "ETE", "SRv6 path via P-2", {"status": "active", "path": "via-p2", "encapsulation": {"sids": ["fc00:0:2:100::"]}}, {"etg": "etg-evpn-east", "id": "ete-srv6-p2"}),
        resource("data-bridge-layer/ETE/etg-core-srv6/ete-core-p2", "ETE", "Core path via P-2", {"status": "active", "path": "via-p2", "metric": 15}, {"etg": "etg-core-srv6", "id": "ete-core-p2"}),
        resource("data-bridge-layer/DTE/dte-mpls-16011", "DTE", "MPLS 16011 disposition", {"status": "programmed", "match": {"mpls_label": 16011}, "packet_action": {"operation": "pop"}, "next_hop_mode": "IP_ROUTING"}, {"id": "dte-mpls-16011"}),
        resource("data-bridge-layer/DTE/dte-srv6-dt4", "DTE", "SRv6 End.DT4 disposition", {"status": "programmed", "match": {"sid": "fc00:0:1:100::"}, "packet_action": {"operation": "remove_ipv6_and_srh"}, "next_hop_mode": "IP_ROUTING"}, {"id": "dte-srv6-dt4"}),
        resource("data-bridge-layer/VIRTUAL_INTERFACE/vi-p1", "VIRTUAL_INTERFACE", "Underlay path P-1", {"status": "up", "interface_class": "routed"}, {"id": "vi-p1"}),
        resource("data-bridge-layer/VIRTUAL_INTERFACE/vi-p2", "VIRTUAL_INTERFACE", "Underlay path P-2", {"status": "up", "interface_class": "routed"}, {"id": "vi-p2"}),
        resource("data-bridge-layer/GLUE/glue-p1", "GLUE", "P-1 interface binding", {"status": "bound", "medium": "ethernet"}, {"id": "glue-p1"}, tags=["connector", "compact"]),
        resource("data-bridge-layer/GLUE/glue-p2", "GLUE", "P-2 interface binding", {"status": "bound", "medium": "ethernet"}, {"id": "glue-p2"}, tags=["connector", "compact"]),
        resource("hardware-driver-plane/PHYSICAL_INTERFACE/Ethernet1", "PHYSICAL_INTERFACE", "Ethernet1 to P-1", {"status": "up", "oper_state": "up"}, {"name": "Ethernet1"}),
        resource("hardware-driver-plane/PHYSICAL_INTERFACE/Ethernet2", "PHYSICAL_INTERFACE", "Ethernet2 to P-2", {"status": "up", "oper_state": "up"}, {"name": "Ethernet2"}),
        resource("hardware-driver-plane/MPLS_LABEL_ENTRY/16011", "MPLS_LABEL_ENTRY", "Incoming label 16011", {"status": "programmed", "operation": "pop-or-swap"}, {"label": 16011}),
        resource("hardware-driver-plane/SRV6_LOCAL_SID/fc00:0:1:100::", "SRV6_LOCAL_SID", "Local SID End.DT4", {"status": "programmed", "behavior": "End.DT4", "vrf": "blue"}, {"sid": "fc00:0:1:100::"}),
    ]

    kinds = sorted({item["kind"] for item in resources})
    descriptors = [
        {
            "kind": kind,
            "display_name": kind.replace("_", " ").title(),
            "display_name_fields": ["name", "id"],
            "default_table_fields": (
                ["medium", "status"]
                if kind == "GLUE"
                else ["status", "oper_state", "program_state"]
            ),
            "condition_field": "status",
            "presentation_tags": ["connector", "compact"] if kind == "GLUE" else [],
            "icon": {
                "path": PLUGIN_RESOURCE_ICON_PATHS[kind],
                "view_box": [0, 0, 24, 24],
                "render_mode": "stroke",
                "stroke_width": 1.8,
            },
            "plugin_defined": True,
        }
        for kind in kinds
    ]

    dashboard_descriptors = [
        {
            "dashboard_id": "forwarding-health",
            "title": "Forwarding health",
            "description": "Forwarding Groups, ETGs, ETEs and DTEs at the selected time.",
            "default_open": True,
            "collapsible": True,
            "default_expanded": True,
            "movable": True,
            "plugin_defined": True,
            "statistics": [
                {
                    "statistic_id": "forwarding-objects",
                    "label": "Forwarding objects",
                    "aggregation": "count",
                    "resource_kinds": ["FORWARDING_GROUP", "ETG", "ETE", "DTE"],
                },
                {
                    "statistic_id": "eligible-entries",
                    "label": "Usable ETEs",
                    "aggregation": "count",
                    "resource_kinds": ["ETE"],
                    "filters": [
                        {
                            "field": "status",
                            "operator": "in",
                            "value": ["active", "standby", "selected-pending"],
                        }
                    ],
                },
                {
                    "statistic_id": "forwarding-errors",
                    "label": "Error states",
                    "aggregation": "count",
                    "resource_kinds": ["FORWARDING_GROUP", "ETG", "ETE", "DTE"],
                    "filters": [
                        {
                            "field": "status_class",
                            "operator": "eq",
                            "value": "error",
                        }
                    ],
                },
            ],
            "tables": [
                {
                    "table_id": "forwarding-paths",
                    "title": "Forwarding paths",
                    "resource_kinds": ["FORWARDING_GROUP", "ETG", "ETE"],
                    "columns": [
                        {
                            "field": "label",
                            "label": "Resource",
                            "value_format": "resource",
                        },
                        {"field": "kind", "label": "Type", "value_format": "text"},
                        {
                            "field": "status",
                            "label": "Status",
                            "value_format": "status",
                        },
                        {"field": "state.path", "label": "Path", "value_format": "text"},
                        {
                            "field": "state.program_state",
                            "label": "Program state",
                            "value_format": "status",
                        },
                    ],
                    "max_rows": 20,
                    "sort_field": "kind",
                    "sort_direction": "ascending",
                },
                {
                    "table_id": "disposition-actions",
                    "title": "Disposition actions",
                    "resource_kinds": ["DTE"],
                    "columns": [
                        {
                            "field": "label",
                            "label": "Resource",
                            "value_format": "resource",
                        },
                        {
                            "field": "status",
                            "label": "Status",
                            "value_format": "status",
                        },
                        {"field": "state.match", "label": "Match", "value_format": "auto"},
                        {
                            "field": "state.packet_action",
                            "label": "Packet action",
                            "value_format": "auto",
                        },
                        {
                            "field": "state.next_hop_mode",
                            "label": "Next hop",
                            "value_format": "text",
                        },
                    ],
                    "max_rows": 12,
                    "sort_field": "label",
                    "sort_direction": "ascending",
                },
            ],
        },
        {
            "dashboard_id": "protocol-state",
            "title": "Protocol state",
            "description": "IS-IS, EVPN, MPLS and SRv6 control-plane resources.",
            "default_open": True,
            "collapsible": True,
            "default_expanded": False,
            "movable": True,
            "plugin_defined": True,
            "statistics": [
                {
                    "statistic_id": "protocol-resources",
                    "label": "Protocol resources",
                    "aggregation": "count",
                    "resource_kinds": [
                        "ISIS_ADJACENCY",
                        "EVPN_ROUTE",
                        "MPLS_PREFIX_SID",
                        "SRV6_LOCATOR",
                    ],
                },
                {
                    "statistic_id": "isis-average-metric",
                    "label": "Average IS-IS metric",
                    "aggregation": "average",
                    "resource_kinds": ["ISIS_ADJACENCY"],
                    "field": "state.metric",
                    "precision": 1,
                },
                {
                    "statistic_id": "evpn-route-types",
                    "label": "EVPN route types",
                    "aggregation": "count_distinct",
                    "resource_kinds": ["EVPN_ROUTE"],
                    "field": "state.route_type",
                },
            ],
            "tables": [
                {
                    "table_id": "protocol-objects",
                    "title": "Protocol objects",
                    "resource_kinds": [
                        "ISIS_ADJACENCY",
                        "EVPN_ROUTE",
                        "MPLS_PREFIX_SID",
                        "SRV6_LOCATOR",
                    ],
                    "columns": [
                        {
                            "field": "label",
                            "label": "Resource",
                            "value_format": "resource",
                        },
                        {"field": "kind", "label": "Type", "value_format": "text"},
                        {
                            "field": "status",
                            "label": "Status",
                            "value_format": "status",
                        },
                        {
                            "field": "state.metric",
                            "label": "Metric",
                            "value_format": "number",
                        },
                        {
                            "field": "state.route_type",
                            "label": "Route type",
                            "value_format": "number",
                        },
                    ],
                    "max_rows": 20,
                    "sort_field": "kind",
                    "sort_direction": "ascending",
                }
            ],
        },
        {
            "dashboard_id": "encapsulation-inventory",
            "title": "Encapsulation inventory",
            "description": "MPLS labels and SRv6 SIDs used by tunnel and disposition resources.",
            "default_open": False,
            "collapsible": True,
            "default_expanded": True,
            "movable": True,
            "plugin_defined": True,
            "statistics": [
                {
                    "statistic_id": "tunnel-groups",
                    "label": "ETGs",
                    "aggregation": "count",
                    "resource_kinds": ["ETG"],
                },
                {
                    "statistic_id": "tunnel-entries",
                    "label": "ETEs",
                    "aggregation": "count",
                    "resource_kinds": ["ETE"],
                },
                {
                    "statistic_id": "programmed-identifiers",
                    "label": "Programmed identifiers",
                    "aggregation": "count",
                    "resource_kinds": ["MPLS_LABEL_ENTRY", "SRV6_LOCAL_SID"],
                    "filters": [
                        {
                            "field": "status",
                            "operator": "eq",
                            "value": "programmed",
                        }
                    ],
                },
            ],
            "tables": [
                {
                    "table_id": "encapsulation-resources",
                    "title": "Encapsulation resources",
                    "resource_kinds": [
                        "ETG",
                        "ETE",
                        "MPLS_LABEL_ENTRY",
                        "SRV6_LOCAL_SID",
                    ],
                    "columns": [
                        {
                            "field": "label",
                            "label": "Resource",
                            "value_format": "resource",
                        },
                        {"field": "kind", "label": "Type", "value_format": "text"},
                        {
                            "field": "status",
                            "label": "Status",
                            "value_format": "status",
                        },
                        {
                            "field": "state.behavior",
                            "label": "Behavior",
                            "value_format": "text",
                        },
                        {
                            "field": "state.operation",
                            "label": "Operation",
                            "value_format": "text",
                        },
                    ],
                    "max_rows": 24,
                    "sort_field": "kind",
                    "sort_direction": "ascending",
                }
            ],
        },
        {
            "dashboard_id": "interface-bindings",
            "title": "Interface bindings",
            "description": "Virtual interfaces, Glue connectors and physical interfaces.",
            "default_open": False,
            "collapsible": False,
            "default_expanded": True,
            "movable": True,
            "plugin_defined": True,
            "statistics": [
                {
                    "statistic_id": "interface-endpoints",
                    "label": "Interfaces",
                    "aggregation": "count",
                    "resource_kinds": ["VIRTUAL_INTERFACE", "PHYSICAL_INTERFACE"],
                },
                {
                    "statistic_id": "glue-connectors",
                    "label": "Glue connectors",
                    "aggregation": "count",
                    "resource_kinds": ["GLUE"],
                },
            ],
            "tables": [
                {
                    "table_id": "binding-resources",
                    "title": "Binding resources",
                    "resource_kinds": [
                        "VIRTUAL_INTERFACE",
                        "GLUE",
                        "PHYSICAL_INTERFACE",
                    ],
                    "columns": [
                        {
                            "field": "label",
                            "label": "Resource",
                            "value_format": "resource",
                        },
                        {"field": "kind", "label": "Type", "value_format": "text"},
                        {
                            "field": "status",
                            "label": "Status",
                            "value_format": "status",
                        },
                        {
                            "field": "state.interface_class",
                            "label": "Class",
                            "value_format": "text",
                        },
                        {
                            "field": "state.medium",
                            "label": "Medium",
                            "value_format": "text",
                        },
                    ],
                    "max_rows": 20,
                    "sort_field": "kind",
                    "sort_direction": "ascending",
                }
            ],
        },
    ]

    resource_by_id = {item["resource_id"]: item for item in resources}
    create_event = {
        "control-plane/ISIS_ADJACENCY/pe-a/p-1": "isis_adj_p1_create",
        "control-plane/ISIS_ADJACENCY/pe-a/p-2": "isis_adj_p2_create",
        "control-plane/SRV6_LOCATOR/pe-b/fc00:0:2::/48": "srv6_locator_create",
        "control-plane/EVPN_ROUTE/blue/203.0.113.0/24": "lltng_route_update",
        "data-bridge-layer/FORWARDING_GROUP/fg-blue-east": "lltng_etg_update",
        "data-bridge-layer/ETG/blue/etg-evpn-east": "lltng_etg_update",
        "data-bridge-layer/ETG/blue/etg-core-srv6": "lltng_etg_update",
        "data-bridge-layer/ETE/etg-evpn-east/ete-srmpls-p1": "lltng_etg_update",
        "data-bridge-layer/ETE/etg-core-srv6/ete-core-p2": "lltng_etg_update",
        "data-bridge-layer/ETE/etg-evpn-east/ete-srv6-p2": "ete_backup_add",
        "data-bridge-layer/DTE/dte-mpls-16011": "dte_ingress_create",
        "hardware-driver-plane/MPLS_LABEL_ENTRY/16011": "lltng_tunnel_program",
    }
    lifecycle: list[dict[str, Any]] = []
    for identifier in resource_by_id:
        event_name = create_event.get(identifier)
        lifecycle.append(
            {
                "resource": identifier,
                "valid_from_ns": t[event_name] if event_name else None,
                "valid_to_ns": t["ete_primary_delete"] if identifier.endswith("ete-srmpls-p1") else None,
                "start_event_uid": uids[event_name] if event_name else None,
                "end_event_uid": uids["ete_primary_delete"] if identifier.endswith("ete-srmpls-p1") else None,
                "provenance": "event_derived" if event_name else "observed",
                "quality": "exact" if event_name else "best_effort",
            }
        )
    # The Type-2 route demonstrates a deletion followed by recreation of the same identity.
    mac_id = "control-plane/EVPN_ROUTE/blue/mac-02:00:00:00:00:11"
    lifecycle = [item for item in lifecycle if item["resource"] != mac_id]
    lifecycle.extend(
        [
            {"resource": mac_id, "valid_from_ns": None, "valid_to_ns": t["evpn_mac_withdraw"], "start_event_uid": None, "end_event_uid": uids["evpn_mac_withdraw"], "provenance": "reconstructed", "quality": "best_effort"},
            {"resource": mac_id, "valid_from_ns": t["evpn_mac_relearn"], "valid_to_ns": None, "start_event_uid": uids["evpn_mac_relearn"], "end_event_uid": None, "provenance": "event_derived", "quality": "exact"},
        ]
    )

    states: list[dict[str, Any]] = []

    def state(
        identifier: str,
        start: str | None,
        end: str | None,
        status: str,
        status_class: str,
        properties: dict[str, Any],
        start_event: str | None = None,
        end_event: str | None = None,
    ) -> None:
        states.append(
            {
                "resource": identifier,
                "valid_from_ns": start,
                "valid_to_ns": end,
                "status": status,
                "status_class": status_class,
                "properties": {"status": status, **properties},
                "start_event_uid": uids[start_event] if start_event else None,
                "end_event_uid": uids[end_event] if end_event else None,
                "provenance": "event_derived" if start_event else "reconstructed",
                "quality": "exact" if start_event else "best_effort",
                "unknown_fields": [],
            }
        )

    dynamic_ids = {
        "control-plane/ISIS_ADJACENCY/pe-a/p-1",
        "control-plane/EVPN_ROUTE/blue/203.0.113.0/24",
        "data-bridge-layer/FORWARDING_GROUP/fg-blue-east",
        "data-bridge-layer/ETE/etg-evpn-east/ete-srmpls-p1",
        "data-bridge-layer/ETE/etg-evpn-east/ete-srv6-p2",
        "data-bridge-layer/ETE/etg-core-srv6/ete-core-p2",
        "data-bridge-layer/DTE/dte-mpls-16011",
        "hardware-driver-plane/PHYSICAL_INTERFACE/Ethernet1",
    }
    for item in resources:
        if item["resource_id"] in dynamic_ids or item["resource_id"] == mac_id:
            continue
        start_event = create_event.get(item["resource_id"])
        current_status = str(item["state"].get("status", "ready"))
        state(item["resource_id"], t[start_event] if start_event else None, None, current_status, "healthy", item["state"], start_event)
    state("control-plane/ISIS_ADJACENCY/pe-a/p-1", t["isis_adj_p1_create"], t["isis_adj_p1_down"], "up", "healthy", {"level": 2, "metric": 10}, "isis_adj_p1_create", "isis_adj_p1_down")
    state("control-plane/ISIS_ADJACENCY/pe-a/p-1", t["isis_adj_p1_down"], t["isis_adj_p1_up"], "down", "error", {"level": 2, "reason": "link-down"}, "isis_adj_p1_down", "isis_adj_p1_up")
    state("control-plane/ISIS_ADJACENCY/pe-a/p-1", t["isis_adj_p1_up"], None, "up", "healthy", {"level": 2, "metric": 10}, "isis_adj_p1_up")
    state("control-plane/EVPN_ROUTE/blue/203.0.113.0/24", t["lltng_route_update"], t["evpn_prefix_reselect"], "selected", "healthy", {"route_type": 5, "vni": 3109, "path": "p1"}, "lltng_route_update", "evpn_prefix_reselect")
    state("control-plane/EVPN_ROUTE/blue/203.0.113.0/24", t["evpn_prefix_reselect"], t["evpn_vni_modify"], "selected", "healthy", {"route_type": 5, "vni": 3109, "path": "p2"}, "evpn_prefix_reselect", "evpn_vni_modify")
    state("control-plane/EVPN_ROUTE/blue/203.0.113.0/24", t["evpn_vni_modify"], None, "selected", "healthy", {"route_type": 5, "vni": 60810, "path": "p2"}, "evpn_vni_modify")
    state(mac_id, None, t["evpn_mac_withdraw"], "selected", "healthy", {"route_type": 2, "mobility_sequence": 7}, None, "evpn_mac_withdraw")
    state(mac_id, t["evpn_mac_relearn"], None, "selected", "healthy", {"route_type": 2, "mobility_sequence": 8}, "evpn_mac_relearn")
    state("data-bridge-layer/FORWARDING_GROUP/fg-blue-east", t["lltng_etg_update"], t["fg_failover_select"], "active", "healthy", {"direction": "eastbound", "selected_ete": "ete-srmpls-p1"}, "lltng_etg_update", "fg_failover_select")
    state("data-bridge-layer/FORWARDING_GROUP/fg-blue-east", t["fg_failover_select"], None, "active", "healthy", {"direction": "eastbound", "selected_ete": "ete-srv6-p2"}, "fg_failover_select")
    state("data-bridge-layer/ETE/etg-evpn-east/ete-srmpls-p1", t["lltng_etg_update"], t["ete_primary_degraded"], "active", "healthy", {"program_state": "programmed", "path": "via-p1", "labels": [24001, 16011]}, "lltng_etg_update", "ete_primary_degraded")
    state("data-bridge-layer/ETE/etg-evpn-east/ete-srmpls-p1", t["ete_primary_degraded"], t["ete_primary_delete"], "ineligible", "error", {"program_state": "programmed", "path": "via-p1", "reason": "adjacency-down"}, "ete_primary_degraded", "ete_primary_delete")
    state("data-bridge-layer/ETE/etg-evpn-east/ete-srv6-p2", t["ete_backup_add"], t["fg_failover_select"], "standby", "healthy", {"program_state": "programmed", "path": "via-p2"}, "ete_backup_add", "fg_failover_select")
    state("data-bridge-layer/ETE/etg-evpn-east/ete-srv6-p2", t["fg_failover_select"], t["ete_retry_success"], "selected-pending", "warning", {"program_state": "programmed", "path": "via-p2"}, "fg_failover_select", "ete_retry_success")
    state("data-bridge-layer/ETE/etg-evpn-east/ete-srv6-p2", t["ete_retry_success"], None, "active", "healthy", {"program_state": "programmed", "path": "via-p2", "sids": ["fc00:0:2:100::"]}, "ete_retry_success")
    state("data-bridge-layer/ETE/etg-core-srv6/ete-core-p2", t["lltng_etg_update"], t["ete_existing_add"], "active", "healthy", {"program_state": "programmed", "metric": 20}, "lltng_etg_update", "ete_existing_add")
    state("data-bridge-layer/ETE/etg-core-srv6/ete-core-p2", t["ete_existing_add"], None, "active", "healthy", {"program_state": "programmed", "metric": 15, "add_on_existing_resolved_as": "modify"}, "ete_existing_add")
    state("data-bridge-layer/DTE/dte-mpls-16011", t["dte_ingress_create"], t["dte_action_modify"], "programmed", "healthy", {"match": {"mpls_label": 16011}, "packet_action": {"operation": "swap", "label": 16012}, "next_hop_mode": "ETG"}, "dte_ingress_create", "dte_action_modify")
    state("data-bridge-layer/DTE/dte-mpls-16011", t["dte_action_modify"], None, "programmed", "healthy", {"match": {"mpls_label": 16011}, "packet_action": {"operation": "pop"}, "next_hop_mode": "IP_ROUTING"}, "dte_action_modify")
    state("hardware-driver-plane/PHYSICAL_INTERFACE/Ethernet1", None, t["lltng_neighbor_event"], "up", "healthy", {"oper_state": "up"}, None, "lltng_neighbor_event")
    state("hardware-driver-plane/PHYSICAL_INTERFACE/Ethernet1", t["lltng_neighbor_event"], t["port_p1_restore"], "down", "error", {"oper_state": "down"}, "lltng_neighbor_event", "port_p1_restore")
    state("hardware-driver-plane/PHYSICAL_INTERFACE/Ethernet1", t["port_p1_restore"], None, "up", "healthy", {"oper_state": "up"}, "port_p1_restore")

    relationships: list[dict[str, Any]] = []

    def relation(source: str, target: str, relation_type: str, start_event: str | None = None, end_event: str | None = None) -> None:
        evidence_event = start_event or end_event
        relationships.append(
            {
                "relationship_id": hashlib.sha256(f"{source}|{relation_type}|{target}|{start_event}".encode()).hexdigest()[:20],
                "source": source,
                "target": target,
                "relation_type": relation_type,
                "valid_from_ns": t[start_event] if start_event else None,
                "valid_to_ns": t[end_event] if end_event else None,
                "start_event_uid": uids[start_event] if start_event else None,
                "end_event_uid": uids[end_event] if end_event else None,
                "provenance": "event_derived" if start_event or end_event else "observed",
                "quality": "exact",
                "plugin_defined": True,
                "evidence": (
                    [{"event_uid": uids[evidence_event], "role": "correlation_basis"}]
                    if evidence_event
                    else [
                        {
                            "logical_path": f"node-a/{source.split('/', 1)[0]}.tgz",
                            "locator": f"plugin-derived-relationship:{relation_type}:{source}->{target}",
                        }
                    ]
                ),
            }
        )

    fg = "data-bridge-layer/FORWARDING_GROUP/fg-blue-east"
    etg = "data-bridge-layer/ETG/blue/etg-evpn-east"
    etg2 = "data-bridge-layer/ETG/blue/etg-core-srv6"
    ete1 = "data-bridge-layer/ETE/etg-evpn-east/ete-srmpls-p1"
    ete2 = "data-bridge-layer/ETE/etg-evpn-east/ete-srv6-p2"
    ete3 = "data-bridge-layer/ETE/etg-core-srv6/ete-core-p2"
    dte1 = "data-bridge-layer/DTE/dte-mpls-16011"
    ipr = "control-plane/IP_ROUTING/blue"
    relation("control-plane/EVPN_ROUTE/blue/203.0.113.0/24", fg, "resolves_via", "lltng_route_update")
    relation(fg, etg, "contains_egress", "lltng_etg_update")
    relation(fg, etg2, "contains_egress", "lltng_etg_update")
    relation(fg, dte1, "contains_ingress", "dte_ingress_create")
    relation(fg, "data-bridge-layer/DTE/dte-srv6-dt4", "contains_ingress")
    relation(etg, ete1, "owns", "lltng_etg_update", "ete_primary_delete")
    relation(etg, ete2, "owns", "ete_backup_add")
    relation(etg2, ete3, "owns", "lltng_etg_update")
    relation(etg, etg2, "next_hop", "lltng_etg_update")
    relation(etg2, ipr, "next_hop", "lltng_etg_update")
    relation(dte1, etg, "next_hop", "dte_ingress_create", "dte_action_modify")
    relation(dte1, ipr, "next_hop", "dte_action_modify")
    relation("data-bridge-layer/DTE/dte-srv6-dt4", ipr, "next_hop")
    relation(fg, ete1, "selected_egress", "lltng_etg_update", "fg_failover_select")
    relation(fg, ete2, "selected_egress", "fg_failover_select")
    relation(ete1, "hardware-driver-plane/MPLS_LABEL_ENTRY/16011", "encapsulates_with", "lltng_tunnel_program", "ete_primary_delete")
    relation(ete2, "hardware-driver-plane/SRV6_LOCAL_SID/fc00:0:1:100::", "encapsulates_with", "ete_backup_add")
    relation(ete1, "data-bridge-layer/GLUE/glue-p1", "egresses_via", "lltng_etg_update", "ete_primary_delete")
    relation(ete2, "data-bridge-layer/GLUE/glue-p2", "egresses_via", "ete_backup_add")
    relation(ete3, "data-bridge-layer/GLUE/glue-p2", "egresses_via", "lltng_etg_update")
    relation("data-bridge-layer/GLUE/glue-p1", "data-bridge-layer/VIRTUAL_INTERFACE/vi-p1", "associates")
    relation("data-bridge-layer/GLUE/glue-p1", "hardware-driver-plane/PHYSICAL_INTERFACE/Ethernet1", "binds_hardware")
    relation("data-bridge-layer/GLUE/glue-p2", "data-bridge-layer/VIRTUAL_INTERFACE/vi-p2", "associates")
    relation("data-bridge-layer/GLUE/glue-p2", "hardware-driver-plane/PHYSICAL_INTERFACE/Ethernet2", "binds_hardware")
    relation("control-plane/ISIS_ADJACENCY/pe-a/p-1", "data-bridge-layer/VIRTUAL_INTERFACE/vi-p1", "uses_interface", "isis_adj_p1_create")
    relation("control-plane/ISIS_ADJACENCY/pe-a/p-2", "data-bridge-layer/VIRTUAL_INTERFACE/vi-p2", "uses_interface", "isis_adj_p2_create")
    relation("control-plane/SRV6_LOCATOR/pe-b/fc00:0:2::/48", "hardware-driver-plane/SRV6_LOCAL_SID/fc00:0:1:100::", "programmed_as", "srv6_locator_create")

    structural_relationship_types = {
        "associates",
        "binds_hardware",
        "contains_egress",
        "contains_ingress",
        "owns",
        "programmed_as",
        "uses_interface",
    }
    relationship_descriptors = [
        {
            "relation_type": relation_type,
            "label": relation_type.replace("_", " ").title(),
            "directed": True,
            "structural": relation_type in structural_relationship_types,
            "plugin_defined": True,
        }
        for relation_type in sorted({item["relation_type"] for item in relationships})
    ]

    mutations: list[dict[str, Any]] = []
    for item in relationships:
        base = {
            key: item[key]
            for key in (
                "relationship_id",
                "source",
                "target",
                "relation_type",
                "quality",
                "provenance",
                "plugin_defined",
                "evidence",
            )
        }
        if item["valid_from_ns"] is not None:
            mutations.append({**base, "operation": "add", "effective_time_ns": item["valid_from_ns"], "cause_event_uid": item["start_event_uid"]})
        if item["valid_to_ns"] is not None:
            mutations.append({**base, "operation": "remove", "effective_time_ns": item["valid_to_ns"], "cause_event_uid": item["end_event_uid"]})

    final_relationships = [
        {**item, "type": item["relation_type"]}
        for item in relationships
        if item["valid_to_ns"] is None
        and (item["valid_from_ns"] is None or int(item["valid_from_ns"]) <= CAPTURE_NS)
    ]
    findings = [
        {"rule_id": "etg-has-entry", "result": "pass", "severity": "info", "resources": [etg, etg2], "summary": "Every existing ETG owns at least one ETE for its whole lifetime.", "provenance": "reconstructed", "quality": "exact", "evidence": []},
        {"rule_id": "failed-update-retry", "result": "fail", "severity": "warning", "resources": [ete2], "summary": "A NoSpace/DependencyError programming event failed; it created an event mark but no state mutation.", "provenance": "event_derived", "quality": "exact", "event_uid": uids["lltng_ete_update"], "evidence": []},
        {"rule_id": "raw-source-correlation", "result": "unknown", "severity": "warning", "resources": ["data-bridge-layer/GLUE/glue-p2"], "summary": "The generated fixture demonstrates the link; a real plugin still needs a stable cross-layer key.", "provenance": "correlated", "quality": "unknown", "evidence": []},
    ]
    causal = [
        {"source_event_uid": uids["lltng_neighbor_event"], "target_event_uid": uids["isis_adj_p1_down"], "link_type": "observed_propagation", "confidence": 0.99, "provenance": "correlated", "quality": "exact"},
        {"source_event_uid": uids["isis_adj_p1_down"], "target_event_uid": uids["ete_primary_degraded"], "link_type": "dependency_state_change", "confidence": 0.98, "provenance": "correlated", "quality": "exact"},
        {"source_event_uid": uids["ete_primary_degraded"], "target_event_uid": uids["fg_failover_select"], "link_type": "forwarding_failover", "confidence": 0.98, "provenance": "correlated", "quality": "exact"},
    ]
    for link in causal:
        link["plugin_defined"] = True
        link["evidence"] = [
            {"event_uid": link["source_event_uid"], "role": "cause"},
            {"event_uid": link["target_event_uid"], "role": "effect"},
        ]
    causal_link_descriptors = [
        {
            "link_type": link_type,
            "label": link_type.replace("_", " ").title(),
            "directed": True,
            "plugin_defined": True,
        }
        for link_type in sorted({item["link_type"] for item in causal})
    ]
    topology = {
        "nodes": [
            {"id": "ce-a", "role": "customer-edge"}, {"id": "pe-a", "role": "provider-edge"},
            {"id": "p-1", "role": "provider"}, {"id": "p-2", "role": "provider"},
            {"id": "pe-b", "role": "provider-edge"}, {"id": "ce-b", "role": "customer-edge"},
        ],
        "links": [["ce-a", "pe-a"], ["pe-a", "p-1"], ["pe-a", "p-2"], ["p-1", "pe-b"], ["p-2", "pe-b"], ["pe-b", "ce-b"]],
        "protocols": ["IS-IS Level 2", "SR-MPLS", "SRv6", "BGP EVPN"],
    }

    (illustrative / "README.md").write_text(
        "# Comprehensive illustrative normalized output\n\nSynthetic MPLS, SRv6, EVPN and IS-IS data with plugin-defined temporal resources, correlations, resource-kind icons, and declarative dashboard modules. GLUE is an ordinary typed resource with compact connector presentation metadata. DTE is standalone; no DTG kind exists.\n",
        encoding="utf-8", newline="\n"
    )
    (illustrative / "domain-events.jsonl").write_bytes(_jsonl(normalized_events))
    (illustrative / "resources.jsonl").write_bytes(_jsonl(resources))
    (illustrative / "kind-descriptors.json").write_text(json.dumps(descriptors, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    (illustrative / "dashboard-descriptors.json").write_text(json.dumps(dashboard_descriptors, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    (illustrative / "relationship-descriptors.json").write_text(json.dumps(relationship_descriptors, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    (illustrative / "causal-link-descriptors.json").write_text(json.dumps(causal_link_descriptors, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    (illustrative / "lifecycle-intervals.jsonl").write_bytes(_jsonl(lifecycle))
    (illustrative / "state-intervals.jsonl").write_bytes(_jsonl(states))
    (illustrative / "relationship-intervals.jsonl").write_bytes(_jsonl(relationships))
    (illustrative / "relationship-mutations.jsonl").write_bytes(_jsonl(mutations))
    (illustrative / "relationships.jsonl").write_bytes(_jsonl(final_relationships))
    (illustrative / "consistency-findings.jsonl").write_bytes(_jsonl(findings))
    (illustrative / "causal-links.jsonl").write_bytes(_jsonl(causal))
    (illustrative / "topology.json").write_text(json.dumps(topology, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    (illustrative / "reconstruction-coverage.json").write_text(json.dumps({"scope": "node-a", "exact_outputs": len(states) + len(relationships), "best_effort_outputs": sum(item["quality"] == "best_effort" for item in states), "ambiguous_outputs": 0, "unknown_outputs": 1, "unknown_reasons": {"missing_cross_layer_key": 1}}, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    (illustrative / "dashboard-summary.json").write_text(json.dumps({"revision_id": "illustrative-revision-node-a", "parse": {"artifacts": 16, "errors": 0, "skipped": 0}, "consistency": {"pass": 1, "fail": 1, "unknown": 1}, "reconstruction": {"exact": len(states) + len(relationships), "best_effort": 4, "ambiguous": 0, "unknown": 1}, "resource_counts": dict(sorted(Counter(item["kind"] for item in resources).items())), "protocols": ["MPLS", "SRv6", "EVPN", "IS-IS"], "failed_events_without_mutation": 1}, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    route = {
        "vrf": "blue", "destination": "203.0.113.42", "matched_prefix": "203.0.113.0/24",
        "next_hops": ["fc00:0:2:100::"], "egress_interfaces": ["Ethernet2"],
        "basis": {"kind": "reconstructed_time", "time_ns": str(CAPTURE_NS), "clock_domain": "node-a-realtime"},
        "provenance": "reconstructed", "quality": "best_effort",
        "explanation": {"kind": "correlation_chain", "resource": "control-plane/EVPN_ROUTE/blue/203.0.113.0/24", "children": [{"kind": "forwarding_group", "resource": fg, "children": [{"kind": "encapsulation_tunnel_group", "resource": etg, "children": [{"kind": "selected_entry", "resource": ete2}]}]}]},
        "evidence": [],
    }
    (illustrative / "route-resolution.json").write_text(json.dumps(route, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    observed = {**route, "basis": {"kind": "observed_capture_vector", "capture_ranges": [{"scope": "node-a", "observed_at_min_ns": str(CAPTURE_NS), "observed_at_max_ns": str(CAPTURE_NS), "clock_domain": "node-a-realtime"}]}, "provenance": "observed", "quality": "exact"}
    (illustrative / "route-resolution-observed.json").write_text(json.dumps(observed, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    (illustrative / "route-scenarios.jsonl").write_bytes(_jsonl([{"scenario": "srv6-selected-after-sr-mpls-failure", "basis": "reconstructed_time", "destination": "203.0.113.42", "expected_result": "resolved"}, {"scenario": "capture-observation", "basis": "observed_capture_vector", "destination": "203.0.113.42", "expected_result": "resolved"}]))


def _validate_archive_name(logical_name: str) -> PurePosixPath:
    """Validate a regular-file member name using POSIX archive semantics."""

    if not logical_name or "\x00" in logical_name or "\\" in logical_name:
        raise ValueError(f"unsafe archive name: {logical_name!r}")
    if logical_name.startswith("/") or (
        len(logical_name) >= 2
        and logical_name[0].isalpha()
        and logical_name[1] == ":"
    ):
        raise ValueError(f"unsafe archive name: {logical_name!r}")
    path = PurePosixPath(logical_name)
    if (
        path == PurePosixPath(".")
        or path.is_absolute()
        or ".." in path.parts
        or path.as_posix() != logical_name
    ):
        raise ValueError(f"unsafe archive name: {logical_name!r}")
    reserved_windows_names = {
        "con",
        "prn",
        "aux",
        "nul",
        *(f"com{index}" for index in range(1, 10)),
        *(f"lpt{index}" for index in range(1, 10)),
    }
    for part in path.parts:
        base_name = part.split(".", 1)[0].casefold()
        if (
            ":" in part
            or part.endswith((".", " "))
            or base_name in reserved_windows_names
        ):
            raise ValueError(f"unsafe archive name: {logical_name!r}")
    return path


def _tar_gz_bytes(files: Mapping[str, bytes]) -> bytes:
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for logical_name in sorted(files):
            path = _validate_archive_name(logical_name)
            content = files[logical_name]
            info = tarfile.TarInfo(path.as_posix())
            info.size = len(content)
            info.mode = 0o644
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            archive.addfile(info, io.BytesIO(content))
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", mtime=0, filename="") as compressor:
        compressor.write(tar_buffer.getvalue())
    return output.getvalue()


def _gzip_bytes(content: bytes) -> bytes:
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", mtime=0, filename="") as compressor:
        compressor.write(content)
    return output.getvalue()


def _zstd_raw_frame(content: bytes) -> bytes:
    """Create a valid single-segment Zstandard frame with one raw block."""

    if len(content) > 255:
        raise ValueError("the dependency-free sample Zstandard frame is limited to 255 bytes")
    block_header = (len(content) << 3) | 1  # raw block, last block
    return (
        b"\x28\xb5\x2f\xfd"
        + b"\x20"  # single segment, one-byte frame content size
        + bytes((len(content),))
        + block_header.to_bytes(3, "little")
        + content
    )


def _synthetic_router_ctf2_archive() -> bytes:
    """Build a small product-shaped CTF 2 trace from the public smalltrace shape."""

    metadata_uuid = bytes.fromhex("00112233445566778899aabbccddeeff")
    metadata_documents = [
        {
            "type": "preamble",
            "uuid": list(metadata_uuid),
            "version": 2,
        },
        {
            "type": "trace-class",
            "uid": "00112233-4455-6677-8899-aabbccddeeff",
            "packet-header-field-class": {
                "type": "structure",
                "member-classes": [
                    {
                        "name": "magic",
                        "field-class": {
                            "type": "fixed-length-unsigned-integer",
                            "length": 32,
                            "alignment": 32,
                            "byte-order": "little-endian",
                            "preferred-display-base": 16,
                            "roles": ["packet-magic-number"],
                        },
                    },
                    {
                        "name": "uuid",
                        "field-class": {
                            "type": "static-length-blob",
                            "length": 16,
                            "roles": ["metadata-stream-uuid"],
                        },
                    },
                ],
            },
        },
        {"type": "data-stream-class"},
        {
            "type": "event-record-class",
            "name": "router-resource-update",
            "payload-field-class": {
                "type": "structure",
                "member-classes": [
                    {
                        "name": "timestamp_ns",
                        "field-class": {
                            "type": "fixed-length-unsigned-integer",
                            "length": 64,
                            "alignment": 8,
                            "byte-order": "little-endian",
                            "preferred-display-base": 10,
                        },
                    },
                    *(
                        {
                            "name": name,
                            "field-class": {"type": "null-terminated-string"},
                        }
                        for name in (
                            "resource",
                            "action",
                            "properties_json",
                            "result_key",
                            "result_value",
                        )
                    ),
                ],
            },
        },
    ]
    metadata = b"".join(
        b"\x1e"
        + json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
        + b"\n"
        for document in metadata_documents
    )

    records = (
        (
            1_759_680_000_100_000_000,
            "route:blue:203.0.113.0/24",
            "create",
            '{"etg":"etg-100","next_hop":"192.0.2.0"}',
            "routeStatus",
            "Ok",
        ),
        (
            1_759_680_003_015_000_000,
            "ete:etg-100:ete-b",
            "update",
            '{"error":"neighbor-unresolved","program_state":"error"}',
            "bridgeStatus",
            "DependencyError",
        ),
    )
    stream = bytearray(b"\xc1\x1f\xfc\xc1" + metadata_uuid)
    for timestamp_ns, *strings in records:
        stream.extend(struct.pack("<Q", timestamp_ns))
        for value in strings:
            stream.extend(value.encode("utf-8") + b"\x00")
    return _tar_gz_bytes(
        {
            "routertrace/metadata": metadata,
            "routertrace/dummystream": bytes(stream),
        }
    )


def _ctf_archive(ctf_source: Path) -> bytes:
    files: dict[str, bytes] = {}
    for name in CTF_FILES:
        candidate = ctf_source / name
        if not candidate.is_file():
            raise FileNotFoundError(
                f"missing {candidate}; run scripts/fetch_babeltrace_sample.py first"
            )
        content = candidate.read_bytes()
        try:
            validate_blob(name, content)
        except RuntimeError as error:
            raise RuntimeError(f"{candidate}: {error}") from error
        files[f"smalltrace/{name}"] = content
    return _tar_gz_bytes(files)


def _build_bundle_in_empty_output(output: Path, ctf_source: Path) -> Path:
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    ownership_marker = output / ".router-dump-analyzer-generated"
    ownership_marker.write_bytes(OWNERSHIP_MARKER)
    unpacked = output / "unpacked" / "node-a"
    unpacked.mkdir(parents=True, exist_ok=True)

    event_bytes = _jsonl(DOMAIN_EVENTS)
    normalized_events = _normalized_domain_events()
    normalized_event_bytes = _jsonl(normalized_events)
    layer_event_bytes = {
        layer: _jsonl([event for event in DOMAIN_EVENTS if event["layer"] == layer])
        for layer in ("control-plane", "data-bridge-layer", "hardware-driver-plane")
    }
    grpc_messages = _jsonl(
        [
            {
                "requestId": "req-001",
                "resourceKind": "ETG",
                "resourceKey": "vrf=blue,id=etg-100",
                "action": "CREATE",
                "properties": {
                    "failover_group": {"stringValue": "fg-7"},
                    "member_uuids": {
                        "uint64List": {"values": ["1001", "1002"]}
                    },
                    "labels": {
                        "stringList": {"values": ["primary", "encap"]}
                    },
                    "opaque_id": {"bytesValue": "AQIDBA=="},
                    "weight": {"doubleValue": 1.0},
                    "metadata": {
                        "objectValue": {
                            "esi": "00:00:00:00:00:00:00:00:00:01",
                            "enabled": True,
                        }
                    },
                },
            },
            {
                "requestId": "req-002",
                "resourceKind": "ETE",
                "resourceKey": "etg=etg-100,id=ete-b",
                "action": "UPDATE",
                "properties": {
                    "program_state": {"stringValue": "error"},
                    "error_code": {"intValue": "17"},
                },
            },
        ]
    )

    ctf_tgz = _ctf_archive(ctf_source)
    router_ctf_tgz = _synthetic_router_ctf2_archive()
    codec_chain = _gzip_bytes(
        _zstd_raw_frame(b"synthetic gzip-then-zstd codec-chain fixture\n")
    )
    protocol_status = {
        "isis.json": {
            "instance": "UNDERLAY",
            "level": 2,
            "adjacencies": [
                {"neighbor": "p-1", "interface": "Ethernet1", "state": "up", "metric": 10},
                {"neighbor": "p-2", "interface": "Ethernet2", "state": "up", "metric": 20},
            ],
        },
        "evpn.json": {
            "vrf": "blue",
            "routes": [
                {"route_type": 2, "mac": "02:00:00:00:00:11", "vni": 60810, "status": "selected"},
                {"route_type": 5, "prefix": "203.0.113.0/24", "vni": 60810, "status": "selected"},
            ],
        },
        "mpls.json": {
            "srgb": [16000, 23999],
            "prefix_sids": [{"node": "p-1", "label": 16011}],
            "service_labels": [24001],
        },
        "srv6.json": {
            "locators": [{"node": "pe-b", "prefix": "fc00:0:2::/48"}],
            "local_sids": [{"sid": "fc00:0:1:100::", "behavior": "End.DT4", "vrf": "blue"}],
        },
    }
    bridge_resource_status = {
        "forwarding_groups": [{"id": "fg-blue-east", "direction": "eastbound", "egress_etgs": ["etg-evpn-east", "etg-core-srv6"], "ingress_dtes": ["dte-mpls-16011", "dte-srv6-dt4"]}],
        "etgs": [
            {"id": "etg-evpn-east", "overlay_destination": "203.0.113.0/24", "encapsulation_actions": [{"operation": "push_vlan", "vlan": 60810}, {"operation": "push_mpls", "labels": [24001]}], "etes": ["ete-srv6-p2"]},
            {"id": "etg-core-srv6", "overlay_destination": "pe-b", "encapsulation_actions": [{"operation": "push_srv6", "sids": ["fc00:0:2:100::"]}], "etes": ["ete-core-p2"]},
        ],
        "dtes": [
            {"id": "dte-mpls-16011", "match": {"mpls_label": 16011}, "action": {"operation": "pop"}, "next_hop": {"kind": "IP_ROUTING", "key": "blue"}},
            {"id": "dte-srv6-dt4", "match": {"sid": "fc00:0:1:100::"}, "action": {"operation": "remove_ipv6_and_srh"}, "next_hop": {"kind": "IP_ROUTING", "key": "blue"}},
        ],
        "virtual_interfaces": [{"id": "vi-p1"}, {"id": "vi-p2"}],
        "glue": [
            {"id": "glue-p1", "virtual_interface": "vi-p1", "physical_interface": "Ethernet1"},
            {"id": "glue-p2", "virtual_interface": "vi-p2", "physical_interface": "Ethernet2"},
        ],
    }
    hardware_programming = {
        "interfaces": [{"name": "Ethernet1", "oper_state": "up"}, {"name": "Ethernet2", "oper_state": "up"}],
        "mpls_entries": [{"label": 16011, "operation": "pop-or-swap"}],
        "srv6_local_sids": [{"sid": "fc00:0:1:100::", "behavior": "End.DT4", "vrf": "blue"}],
    }
    layers: dict[str, dict[str, bytes]] = {
        "control-plane": {
            "var/lib/control-dump/status/all-status.txt": CONTROL_STATUS.encode(),
            "var/lib/control-dump/trace/lltng_domain_export.jsonl": layer_event_bytes[
                "control-plane"
            ],
            "var/lib/control-dump/proto/resource_update.proto": GRPC_PROTO.encode(),
            "var/lib/control-dump/proto/resource_updates.jsonl": grpc_messages,
            **{
                f"var/lib/control-dump/status/{name}": (
                    json.dumps(payload, indent=2, sort_keys=True) + "\n"
                ).encode()
                for name, payload in protocol_status.items()
            },
        },
        "data-bridge-layer": {
            "var/lib/bridge-dump/status/resources.txt": BRIDGE_STATUS.encode(),
            "var/lib/bridge-dump/mnt/trace/ctf2-smalltrace.tgz": ctf_tgz,
            "var/lib/bridge-dump/mnt/trace/ctf2-router-domain.tgz": router_ctf_tgz,
            "var/lib/bridge-dump/mnt/trace/codec-chain-marker.zst.gz": codec_chain,
            "var/lib/bridge-dump/mnt/trace/lltng_domain_export.jsonl": layer_event_bytes[
                "data-bridge-layer"
            ],
            "var/lib/bridge-dump/mnt/trace/lltng_info.log": DEBUG_LOG.encode(),
            "var/lib/bridge-dump/status/typed-resources.json": (
                json.dumps(bridge_resource_status, indent=2, sort_keys=True) + "\n"
            ).encode(),
        },
        "hardware-driver-plane": {
            "opt/driver-dump/status/hardware.txt": HARDWARE_STATUS.encode(),
            "opt/driver-dump/trace/lltng_domain_export.jsonl": layer_event_bytes[
                "hardware-driver-plane"
            ],
            "opt/driver-dump/trace/lltng_error.log": DEBUG_LOG.encode(),
            "opt/driver-dump/status/forwarding-programming.json": (
                json.dumps(hardware_programming, indent=2, sort_keys=True) + "\n"
            ).encode(),
        },
    }

    top_files: dict[str, bytes] = {}
    for layer, files in layers.items():
        layer_archive = _tar_gz_bytes(files)
        top_name = f"node-a/{layer}.tgz"
        top_files[top_name] = layer_archive
        layer_path = unpacked / f"{layer}.tgz"
        layer_path.write_bytes(layer_archive)

    manifest = {
        "node": "node-a",
        "capture_time_ns": str(CAPTURE_NS),
        "capture_clock_domain": "node-a-realtime",
        "software_family": "synthetic-router-os",
        "software_version": "2025.10-test1",
        "platform": "synthetic-x86",
        "scenario": "mpls-srv6-evpn-isis-failover",
        "protocols": ["IS-IS Level 2", "SR-MPLS", "SRv6", "BGP EVPN"],
        "layers": sorted(layers),
    }
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    top_files["node-a/manifest.json"] = manifest_bytes
    (unpacked / "manifest.json").write_bytes(manifest_bytes)

    illustrative = output / "illustrative"
    illustrative.mkdir(parents=True, exist_ok=True)
    (illustrative / "README.md").write_text(
        "# Illustrative normalized output\n\n"
        "These records demonstrate the proposed semantics and are not canonical "
        "plugin-conformance goldens. They include normalized events, dynamic "
        "state/relationship history, causal links, coverage, dashboard data, "
        "and observed/reconstructed route examples.\n",
        encoding="utf-8",
        newline="\n",
    )
    (illustrative / "domain-events.jsonl").write_bytes(normalized_event_bytes)
    (illustrative / "resources.jsonl").write_bytes(
        _jsonl(ILLUSTRATIVE_RESOURCES)
    )
    relationship_records = []
    for relationship in ILLUSTRATIVE_RELATIONSHIPS:
        record = {
            "node": "node-a",
            "evidence": [
                {
                    "logical_path": "node-a/data-bridge-layer.tgz!/var/lib/bridge-dump/status/resources.txt",
                    "locator": f"relationship:{relationship['type']}",
                }
            ],
            **relationship,
        }
        if relationship["provenance"] == "observed":
            record["observed_at_min_ns"] = str(CAPTURE_NS)
            record["observed_at_max_ns"] = str(CAPTURE_NS)
        else:
            record["effective_from_ns"] = "1759680000100000000"
            record["reconstructed_through_ns"] = str(CAPTURE_NS)
        relationship_records.append(record)
    (illustrative / "relationships.jsonl").write_bytes(
        _jsonl(relationship_records)
    )
    (illustrative / "consistency-findings.jsonl").write_bytes(
        _jsonl(
            [
                {
                    "rule_id": "resource-operational-health",
                    "result": "fail",
                    "severity": "error",
                    "resources": ["data-bridge-layer/ETE/etg-100/ete-b"],
                    "summary": "Bridge entry is in an error state after a dependency failure.",
                    "provenance": "observed",
                    "quality": "exact",
                    "evidence": [
                        {
                            "logical_path": "node-a/data-bridge-layer.tgz!/var/lib/bridge-dump/status/resources.txt",
                            "locator": "resource:ETE:ete-b",
                        }
                    ],
                },
                {
                    "rule_id": "route-next-hop-resolved",
                    "result": "fail",
                    "severity": "error",
                    "resources": ["control-plane/ROUTE/blue/192.0.2.128/25"],
                    "summary": "Selected route points to a failed neighbor.",
                    "provenance": "observed",
                    "quality": "exact",
                    "evidence": [
                        {
                            "logical_path": "node-a/control-plane.tgz!/var/lib/control-dump/status/all-status.txt",
                            "locator": "section:ROUTES:row:192.0.2.128/25",
                        }
                    ],
                },
                {
                    "rule_id": "route-next-hop-resolved",
                    "result": "pass",
                    "severity": "info",
                    "resources": ["control-plane/ROUTE/blue/203.0.113.0/24"],
                    "summary": "Selected route resolves through a reachable neighbor.",
                    "provenance": "observed",
                    "quality": "exact",
                    "evidence": [
                        {
                            "logical_path": "node-a/control-plane.tgz!/var/lib/control-dump/status/all-status.txt",
                            "locator": "section:ROUTES:row:203.0.113.0/24",
                        }
                    ],
                },
                {
                    "rule_id": "route-to-hardware-correlation",
                    "result": "unknown",
                    "severity": "warning",
                    "resources": ["control-plane/ROUTE/blue/192.0.2.128/25"],
                    "summary": "No evidence maps this route to a hardware object.",
                    "provenance": "correlated",
                    "quality": "unknown",
                    "evidence": [],
                },
            ]
        )
    )
    (illustrative / "route-resolution.json").write_bytes(
        (
            json.dumps(
                {
                    "vrf": "blue",
                    "destination": "203.0.113.42",
                    "matched_prefix": "203.0.113.0/24",
                    "next_hops": ["192.0.2.0"],
                    "egress_interfaces": ["Ethernet1"],
                    "basis": {
                        "kind": "reconstructed_time",
                        "time_ns": str(CAPTURE_NS),
                        "clock_domain": "node-a-realtime",
                    },
                    "provenance": "reconstructed",
                    "quality": "best_effort",
                    "evidence": [
                        {
                            "logical_path": "node-a/control-plane.tgz!/var/lib/control-dump/status/all-status.txt",
                            "locator": "section:ROUTES:row:203.0.113.0/24",
                        },
                        {
                            "logical_path": "node-a/control-plane.tgz!/var/lib/control-dump/trace/lltng_domain_export.jsonl",
                            "locator": "event:lltng_route_update:0",
                        },
                    ],
                    "explanation": {
                        "kind": "fib_entry",
                        "resource": "control-plane/ROUTE/blue/203.0.113.0/24",
                        "children": [
                            {
                                "kind": "resolution_relation",
                                "relation_type": "resolves_via",
                                "resource": "data-bridge-layer/ETG/blue/etg-100",
                                "children": [
                                    {
                                        "kind": "selected_member",
                                        "resource": "data-bridge-layer/ETE/etg-100/ete-a",
                                        "children": [
                                            {
                                                "kind": "adjacency",
                                                "resource": "control-plane/NBR/blue/192.0.2.0",
                                                "state": "reachable",
                                            }
                                        ],
                                    }
                                ],
                            }
                        ],
                    },
                },
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
    )

    (illustrative / "route-resolution-observed.json").write_bytes(
        (
            json.dumps(
                {
                    "vrf": "blue",
                    "destination": "203.0.113.42",
                    "matched_prefix": "203.0.113.0/24",
                    "next_hops": ["192.0.2.0"],
                    "egress_interfaces": ["Ethernet1"],
                    "basis": {
                        "kind": "observed_capture_vector",
                        "capture_ranges": [
                            {
                                "scope": "control-plane/ROUTE/blue/203.0.113.0/24",
                                "observed_at_min_ns": str(CAPTURE_NS),
                                "observed_at_max_ns": str(CAPTURE_NS),
                                "clock_domain": "node-a-realtime",
                            },
                            {
                                "scope": "control-plane/NBR/blue/192.0.2.0",
                                "observed_at_min_ns": str(CAPTURE_NS),
                                "observed_at_max_ns": str(CAPTURE_NS),
                                "clock_domain": "node-a-realtime",
                            },
                        ],
                    },
                    "provenance": "observed",
                    "quality": "exact",
                    "explanation": {
                        "kind": "fib_entry",
                        "resource": "control-plane/ROUTE/blue/203.0.113.0/24",
                        "children": [
                            {
                                "kind": "adjacency",
                                "resource": "control-plane/NBR/blue/192.0.2.0",
                                "state": "reachable",
                                "children": [
                                    {
                                        "kind": "interface",
                                        "resource": "control-plane/INTERFACE/Ethernet1",
                                    }
                                ],
                            }
                        ],
                    },
                    "evidence": [
                        {
                            "logical_path": "node-a/control-plane.tgz!/var/lib/control-dump/status/all-status.txt",
                            "locator": "section:ROUTES:row:203.0.113.0/24",
                        }
                    ],
                },
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
    )

    relationship_change_ns = "1759680001500000000"
    error_change_ns = "1759680003015000000"
    (illustrative / "state-intervals.jsonl").write_bytes(
        _jsonl(
            [
                {
                    "resource": "data-bridge-layer/ETE/etg-100/ete-b",
                    "valid_from_ns": None,
                    "valid_to_ns": error_change_ns,
                    "properties": {"neighbor": "198.51.100.0"},
                    "unknown_fields": [
                        {
                            "name": "program_state",
                            "reason_code": "missing_before_value",
                            "message": "the update records the new error state but not the prior state",
                        }
                    ],
                    "provenance": "reconstructed",
                    "quality": "unknown",
                    "evidence": [
                        {
                            "logical_path": "node-a/data-bridge-layer.tgz!/var/lib/bridge-dump/mnt/trace/lltng_domain_export.jsonl",
                            "locator": "jsonl-record:2",
                        }
                    ],
                },
                {
                    "resource": "data-bridge-layer/ETE/etg-100/ete-b",
                    "valid_from_ns": error_change_ns,
                    "valid_to_ns": None,
                    "properties": {
                        "neighbor": "198.51.100.0",
                        "program_state": "error",
                    },
                    "unknown_fields": [],
                    "provenance": "event_derived",
                    "quality": "exact",
                    "evidence": [
                        {
                            "logical_path": "node-a/data-bridge-layer.tgz!/var/lib/bridge-dump/mnt/trace/lltng_domain_export.jsonl",
                            "locator": "jsonl-record:2",
                        }
                    ],
                },
            ]
        )
    )
    (illustrative / "relationship-mutations.jsonl").write_bytes(
        _jsonl(
            [
                {
                    "operation": "remove",
                    "source": "data-bridge-layer/ETE/etg-100/ete-a",
                    "target": "control-plane/NBR/blue/192.0.2.2",
                    "relation_type": "references",
                    "effective_time_ns": relationship_change_ns,
                    "provenance": "event_derived",
                    "quality": "exact",
                    "evidence": [
                        {
                            "logical_path": "node-a/data-bridge-layer.tgz!/var/lib/bridge-dump/mnt/trace/lltng_domain_export.jsonl",
                            "locator": "jsonl-record:1",
                        }
                    ],
                },
                {
                    "operation": "add",
                    "source": "data-bridge-layer/ETE/etg-100/ete-a",
                    "target": "control-plane/NBR/blue/192.0.2.0",
                    "relation_type": "references",
                    "effective_time_ns": relationship_change_ns,
                    "provenance": "event_derived",
                    "quality": "exact",
                    "evidence": [
                        {
                            "logical_path": "node-a/data-bridge-layer.tgz!/var/lib/bridge-dump/mnt/trace/lltng_domain_export.jsonl",
                            "locator": "jsonl-record:1",
                        }
                    ],
                },
            ]
        )
    )
    (illustrative / "relationship-intervals.jsonl").write_bytes(
        _jsonl(
            [
                {
                    "source": "data-bridge-layer/ETE/etg-100/ete-a",
                    "target": "control-plane/NBR/blue/192.0.2.2",
                    "relation_type": "references",
                    "valid_from_ns": None,
                    "valid_to_ns": relationship_change_ns,
                    "provenance": "event_derived",
                    "quality": "exact",
                    "evidence": [
                        {
                            "logical_path": "node-a/data-bridge-layer.tgz!/var/lib/bridge-dump/mnt/trace/lltng_domain_export.jsonl",
                            "locator": "jsonl-record:1",
                        }
                    ],
                },
                {
                    "source": "data-bridge-layer/ETE/etg-100/ete-a",
                    "target": "control-plane/NBR/blue/192.0.2.0",
                    "relation_type": "references",
                    "valid_from_ns": relationship_change_ns,
                    "valid_to_ns": None,
                    "provenance": "event_derived",
                    "quality": "exact",
                    "evidence": [
                        {
                            "logical_path": "node-a/data-bridge-layer.tgz!/var/lib/bridge-dump/mnt/trace/lltng_domain_export.jsonl",
                            "locator": "jsonl-record:1",
                        }
                    ],
                },
            ]
        )
    )
    event_uids = {
        str(event["event_type"]): str(event["event_uid"])
        for event in normalized_events
    }
    (illustrative / "causal-links.jsonl").write_bytes(
        _jsonl(
            [
                {
                    "source_event_uid": event_uids["lltng_neighbor_event"],
                    "target_event_uid": event_uids["lltng_ete_update"],
                    "link_type": "propagated_dependency_failure",
                    "confidence": 0.98,
                    "provenance": "correlated",
                    "quality": "best_effort",
                    "evidence": [
                        {
                            "logical_path": "node-a/hardware-driver-plane.tgz!/opt/driver-dump/trace/lltng_domain_export.jsonl",
                            "locator": "jsonl-record:1",
                        },
                        {
                            "logical_path": "node-a/data-bridge-layer.tgz!/var/lib/bridge-dump/mnt/trace/lltng_domain_export.jsonl",
                            "locator": "jsonl-record:2",
                        },
                    ],
                    "details": {
                        "shared_neighbor": "198.51.100.0",
                        "normalized_separation_ns": "15000000",
                    },
                }
            ]
        )
    )
    (illustrative / "reconstruction-coverage.json").write_text(
        json.dumps(
            {
                "scope": "node-a",
                "exact_outputs": 11,
                "best_effort_outputs": 2,
                "ambiguous_outputs": 0,
                "unknown_outputs": 1,
                "unknown_reasons": {"missing_before_value": 1},
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (illustrative / "dashboard-summary.json").write_text(
        json.dumps(
            {
                "revision_id": "illustrative-revision-node-a",
                "parse": {"artifacts": 13, "errors": 0, "skipped": 0},
                "consistency": {"pass": 1, "fail": 2, "unknown": 1},
                "reconstruction": {
                    "exact": 11,
                    "best_effort": 2,
                    "ambiguous": 0,
                    "unknown": 1,
                },
                "cross_layer": [
                    {
                        "resource": "ETE/etg-100/ete-b",
                        "control_neighbor": "failed",
                        "bridge_program_state": "error",
                        "hardware_oper": "down",
                        "result": "fail",
                        "drilldown": {
                            "event_uids": [
                                event_uids["lltng_neighbor_event"],
                                event_uids["lltng_ete_update"],
                            ]
                        },
                    }
                ],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (illustrative / "route-scenarios.jsonl").write_bytes(
        _jsonl(
            [
                {
                    "scenario": "latest-observed-healthy",
                    "basis": "observed_capture_vector",
                    "destination": "203.0.113.42",
                    "expected_result": "resolved",
                },
                {
                    "scenario": "historical-failover-best-effort",
                    "basis": "reconstructed_time",
                    "destination": "203.0.113.42",
                    "expected_result": "partially_resolved",
                },
                {
                    "scenario": "failed-neighbor",
                    "basis": "observed_capture_vector",
                    "destination": "192.0.2.200",
                    "expected_result": "unresolved",
                },
                {
                    "scenario": "recursive-cycle-guard",
                    "basis": "synthetic-conformance-case",
                    "destination": "198.51.100.200",
                    "expected_result": "cycle",
                },
            ]
        )
    )

    # Overwrite the early minimal examples above with the comprehensive,
    # internally consistent projection consumed by the current demo UI/API.
    _write_comprehensive_illustrative(illustrative, normalized_events)

    bundle_path = output / "node-a.tgz"
    bundle_path.write_bytes(_tar_gz_bytes(top_files))
    return bundle_path


def _directory_fingerprint(directory: Path) -> str | None:
    """Hash a small generated tree so a concurrent change is never overwritten."""

    if not directory.exists():
        return None
    if not directory.is_dir() or directory.is_symlink():
        raise RuntimeError(f"output is not a regular directory: {directory}")
    digest = hashlib.sha256()
    for candidate in sorted(directory.rglob("*"), key=lambda item: item.as_posix()):
        relative = candidate.relative_to(directory).as_posix().encode("utf-8")
        if candidate.is_symlink():
            raise RuntimeError(f"generated output contains a symbolic link: {candidate}")
        if candidate.is_dir():
            digest.update(b"D\x00" + relative + b"\x00")
            continue
        if not candidate.is_file():
            raise RuntimeError(f"generated output contains a special file: {candidate}")
        digest.update(b"F\x00" + relative + b"\x00")
        with candidate.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
        digest.update(b"\x00")
    return digest.hexdigest()


def build_bundle(output: Path, ctf_source: Path) -> Path:
    """Build in staging and replace only an empty or generator-owned directory."""

    if output.is_symlink():
        raise RuntimeError(f"refusing symbolic-link output: {output}")
    output = output.resolve()
    parent = output.parent
    parent.mkdir(parents=True, exist_ok=True)
    lock = parent / f".{output.name}.router-dump-analyzer.lock"
    lock_fd: int | None = None
    stage: Path | None = None
    backup: Path | None = None
    try:
        try:
            lock_fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as error:
            raise RuntimeError(f"another generator is using output: {output}") from error

        marker = output / ".router-dump-analyzer-generated"
        if output.exists():
            if not output.is_dir():
                raise RuntimeError(f"output is not a directory: {output}")
            existing = list(output.iterdir())
            if existing and (
                marker.is_symlink()
                or not marker.is_file()
                or marker.read_bytes() != OWNERSHIP_MARKER
            ):
                raise RuntimeError(
                    f"refusing to replace non-empty unowned output directory: {output}"
                )
        initial_fingerprint = _directory_fingerprint(output)

        stage = Path(tempfile.mkdtemp(prefix=".rda-sample-stage-", dir=parent))
        _build_bundle_in_empty_output(stage, ctf_source)
        if _directory_fingerprint(output) != initial_fingerprint:
            raise RuntimeError(f"output changed while the fixture was built: {output}")
        if output.exists():
            backup = Path(tempfile.mkdtemp(prefix=".rda-sample-old-", dir=parent))
            backup.rmdir()
            output.replace(backup)
        stage.replace(output)
        if backup is not None:
            shutil.rmtree(backup, ignore_errors=True)
        return output / "node-a.tgz"
    except BaseException:
        if stage is not None and stage.exists():
            shutil.rmtree(stage)
        if backup is not None and backup.exists() and not output.exists():
            backup.replace(output)
        raise
    finally:
        if lock_fd is not None:
            os.close(lock_fd)
            lock.unlink(missing_ok=True)


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=root / "samples" / "generated")
    parser.add_argument(
        "--ctf-source",
        type=Path,
        default=root / "samples" / "external" / "ctf2-smalltrace",
    )
    args = parser.parse_args()
    build_bundle(args.output.resolve(), args.ctf_source.resolve())
    print("Generated the synthetic nested dump bundle.")


if __name__ == "__main__":
    main()
