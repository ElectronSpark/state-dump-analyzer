import {
  api,
  byId,
  escapeHtml,
  safeClass,
  titleCase,
  toBigInt,
} from "./shared.js";
import {
  declaredHealthPresentation,
  routeEndpointSeedValue,
} from "./view_models.js";

const MAX_NODES = 32;
const MAX_LINKS = 500;
const MAX_SEGMENT_ATTACHMENTS = 4000;
const RESOURCE_PREVIEW_LIMIT = 8;
const MAX_ROUTE_PATHS = 64;
const MAX_ROUTE_TABLE_ROWS = 1000;
const ROUTE_TABLE_QUERY_LIMIT = 500;
const MAX_PACKET_LAYERS = 256;
const PACKET_SUMMARY_LAYER_LIMIT = 4;
const PACKET_DETAIL_LAYER_LIMIT = 32;
const PACKET_FIELD_PREVIEW_LIMIT = 12;
const PACKET_VALUE_ITEM_LIMIT = 12;
const PACKET_VALUE_DEPTH_LIMIT = 4;
const PACKET_REFERENCE_PREVIEW_LIMIT = 6;
const PACKET_EVIDENCE_PREVIEW_LIMIT = 6;
const MAP_NODE_FALLBACK_WIDTH = 188;
const MAP_NODE_FALLBACK_HEIGHT = 108;
const MAP_COLUMN_PITCH = 235;
const MAP_ROW_PITCH = 165;
const MAP_OUTER_PADDING = 90;
const MAP_EDGE_CLEARANCE = 8;
const MAP_EDGE_LANE_GAP = 18;
const MAP_EDGE_BASE_BEND_MIN = 28;
const MAP_EDGE_BASE_BEND_MAX = 72;
const MAP_EDGE_BASE_BEND_RATIO = 0.16;
const MAP_EDGE_MAX_BEND_RATIO = 0.22;
const ROUTE_OVERVIEW_LAYOUT_VERSION = 2;
const TOPOLOGY_LAYOUT_VERSION = "incidence-v3";
const TOPOLOGY_LAYOUT_SWEEPS = 6;
const TOPOLOGY_LAYOUT_RANK_GAP = 118;
const TOPOLOGY_LAYOUT_CROSS_GAP = 32;
const TOPOLOGY_LAYOUT_GRID_GAP = 32;
const TOPOLOGY_LAYOUT_MAX_CROSS_ITEMS = 5;
const TOPOLOGY_LAYOUT_BAND_GAP = 64;
const TOPOLOGY_LAYOUT_COMPONENT_GAP = 92;
const TOPOLOGY_LAYOUT_OUTER_PADDING = 52;
const TOPOLOGY_ELEMENT_KEYS = Object.freeze(["subnets", "vlans", "interfaces", "subinterfaces", "lags", "external"]);
const TOPOLOGY_ELEMENT_PRESETS = Object.freeze({
  compact: Object.freeze(["subnets", "interfaces"]),
  all: TOPOLOGY_ELEMENT_KEYS,
});
const state = {
  bootstrap: null,
  capabilities: null,
  query: null,
  apiMode: "loading",
  apiError: "",
  selectedNodeKeys: new Set(),
  focusedNodeKey: "",
  topologyFocusedNodeKey: "",
  focusedResourceRef: null,
  nodeFilter: "",
  healthFilter: "all",
  pending: false,
  topologyRequestGeneration: 0,
  topologyAbortController: null,
  routeRequestGeneration: 0,
  routeAbortController: null,
  queryControlsDirty: false,
  urlStateApplied: false,
  resizeFrame: null,
  resizeTargets: new Set(),
  routeCapabilities: null,
  routeCapabilityError: "",
  routeBundle: null,
  routeTraces: { forward: null, reverse: null },
  routeTrace: null,
  routePending: false,
  activeRouteDirection: "forward",
  selectedRoutePathIds: { forward: "", reverse: "" },
  selectedRoutePathId: "",
  requestedRoutePathId: "",
  routeGraphMode: "focused",
  previewRoutePathId: "",
  previewRoutePresentationId: "",
  routePresentationPinned: false,
  routePresentationTrigger: null,
  routePresentationSuppressFocusPreview: false,
  routePreviewHideTimer: null,
  routePreviewAnchor: null,
  topologyInspectorItems: new Map(),
  topologyInspectorKey: "",
  topologyInspectorPinned: false,
  topologyInspectorTrigger: null,
  topologyInspectorHideTimer: null,
  topologyInspectorSuppressFocusPreview: false,
  routeHoverTokens: new Set(),
  routeHoverSource: "",
  routeHoverExact: false,
  routePacketPreviewRef: "",
  routePacketPinnedRef: "",
  routePacketPreviewSource: "",
  routePacketPreviewAnchor: null,
  routePacketPinnedTrigger: null,
  routePacketPreviewTimer: null,
  routeTableSnapshot: null,
  routeTablePending: false,
  routeTableError: "",
  routeTableSource: "",
  routeTableFilters: {
    search: "",
    node: "",
    vrf: "",
    family: "",
    type: "",
    protocol: "",
    destination: "",
  },
  routeTableOpenNodes: new Set(),
  routeTablesInitialized: false,
  focusedRouteEntryId: "",
  focusedRouteEntryRef: null,
  topologyNetworkView: "underlay",
  topologyElementVisibility: new Set(TOPOLOGY_ELEMENT_PRESETS.compact),
  graphViews: {
    topology: { scale: 1, panX: 0, panY: 0, positions: new Map(), viewports: new Map(), initialized: false, dimensions: null },
    route: { scale: 1, panX: 0, panY: 0, positions: new Map(), viewports: new Map(), initialized: false, dimensions: null },
  },
};

function firstArray(...values) {
  return values.find((value) => Array.isArray(value) && value.length) || [];
}

function firstDeclaredString(...values) {
  for (const value of values) {
    if (value === null || value === undefined || typeof value === "object") continue;
    const normalized = String(value).trim();
    if (normalized) return normalized;
  }
  return "";
}

function formatInteger(value) {
  const number = Number(value ?? 0);
  return Number.isFinite(number) ? number.toLocaleString() : String(value ?? "0");
}

function formatDurationNs(value) {
  let ns = toBigInt(value);
  const sign = ns < 0n ? "−" : "";
  if (ns < 0n) ns = -ns;
  if (ns < 1_000n) return `${sign}${ns} ns`;
  if (ns < 1_000_000n) return `${sign}${(Number(ns) / 1e3).toFixed(1)} µs`;
  if (ns < 1_000_000_000n) return `${sign}${(Number(ns) / 1e6).toFixed(1)} ms`;
  return `${sign}${(Number(ns) / 1e9).toFixed(3)} s`;
}

function compactTime(value) {
  if (value === null || value === undefined || value === "") return "unknown";
  const raw = String(value);
  if (!/^-?\d+$/.test(raw)) return raw;
  const ns = toBigInt(raw);
  const negative = ns < 0n;
  const absolute = negative ? -ns : ns;
  const seconds = absolute / 1_000_000_000n;
  const fraction = String(absolute % 1_000_000_000n)
    .padStart(9, "0").slice(0, 3);
  return `${negative ? "-" : ""}${seconds}.${fraction} s`;
}

function parseSecondsToNs(value) {
  const match = String(value ?? "").trim().match(/^([+-]?)(\d+)(?:\.(\d{0,9}))?$/);
  if (!match) throw new Error("Use signed seconds with up to 9 decimal places, for example -5 or -0.250.");
  const ns = BigInt(match[2]) * 1_000_000_000n + BigInt((match[3] || "").padEnd(9, "0") || "0");
  return match[1] === "-" ? -ns : ns;
}

function nsToSecondsInput(value, fallback = "-5") {
  if (value === null || value === undefined || value === "") return fallback;
  const ns = toBigInt(value);
  const negative = ns < 0n;
  const absolute = negative ? -ns : ns;
  const whole = absolute / 1_000_000_000n;
  const fraction = String(absolute % 1_000_000_000n).padStart(9, "0").replace(/0+$/, "");
  return `${negative ? "-" : ""}${whole}${fraction ? `.${fraction}` : ""}`;
}

function isAbortError(error) {
  return error?.name === "AbortError";
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function immutableSnapshot(value) {
  const clone = JSON.parse(JSON.stringify(value));
  const freeze = (item) => {
    if (!item || typeof item !== "object" || Object.isFrozen(item)) return item;
    Object.values(item).forEach(freeze);
    return Object.freeze(item);
  };
  return freeze(clone);
}

function setFormBusy(formId, busy) {
  const form = byId(formId);
  if (!form) return;
  form.querySelectorAll("button, input, select, textarea").forEach((control) => {
    if (busy) {
      if (!control.dataset.disabledBeforeBusy) control.dataset.disabledBeforeBusy = control.disabled ? "true" : "false";
      control.disabled = true;
      return;
    }
    if (!control.dataset.disabledBeforeBusy) return;
    control.disabled = control.dataset.disabledBeforeBusy === "true";
    delete control.dataset.disabledBeforeBusy;
  });
}

function pluginId(raw) {
  return firstDeclaredString(raw?.plugin_set_id);
}

function projectionId(raw) {
  if (typeof raw === "string") return raw;
  return firstDeclaredString(raw?.projection_id, raw?.topology_projection_id, raw?.id);
}

function perspectiveId(raw) {
  if (typeof raw === "string") return raw;
  return firstDeclaredString(raw?.perspective_id, raw?.status_perspective_id, raw?.layer_id, raw?.id);
}

function normalizePlugin(raw, node, topLevel) {
  const nestedProjections = firstArray(raw?.plugins).flatMap((provider) =>
    firstArray(provider?.projections).map((projection) => ({
      ...projection,
      provider_plugin_id: projection?.provider_plugin_id || provider?.plugin_id,
      plugin_id: projection?.plugin_id || provider?.plugin_id,
      plugin_version: provider?.version,
    }))
  );
  const projections = firstArray(
    raw?.topology_projections,
    raw?.projections,
    nestedProjections,
    node?.topology_projections,
    node?.projections,
    topLevel?.topology_projections,
    topLevel?.projections,
  );
  const explicitPerspectives = firstArray(
    raw?.status_perspectives,
    raw?.perspectives,
    node?.status_perspectives,
    node?.perspectives,
    topLevel?.status_perspectives,
    topLevel?.perspectives,
  );
  const declaredProjections = projections.filter((projection) => projectionId(projection));
  const perspectiveMap = new Map();
  for (const perspective of explicitPerspectives) {
    const id = perspectiveId(perspective);
    if (id) perspectiveMap.set(id, perspective);
  }
  for (const projection of declaredProjections) {
    for (const id of firstArray(
      projection?.supported_status_perspective_ids,
      projection?.status_perspective_ids,
    ).map(String).filter(Boolean)) {
      if (!perspectiveMap.has(id)) perspectiveMap.set(id, { perspective_id: id, label: titleCase(id) });
    }
  }
  const declaredPluginId = pluginId(raw);
  return {
    ...raw,
    plugin_set_id: declaredPluginId,
    label: raw?.label || raw?.display_name || (declaredPluginId ? titleCase(declaredPluginId) : "Provider unavailable"),
    version: firstDeclaredString(raw?.version, raw?.plugin_version, raw?.api_version),
    projections: declaredProjections,
    perspectives: [...perspectiveMap.values()],
  };
}

function nodeIdentity(raw, index = 0) {
  const nodeId = String(raw?.node_id ?? raw?.device_id ?? raw?.router_id ?? raw?.id ?? `node-${index + 1}`);
  const revisionId = String(raw?.revision_id ?? raw?.analysis_revision_id ?? raw?.revision ?? state.bootstrap?.workspace?.revision_id ?? "unknown-revision");
  const memberId = String(raw?.member_id ?? raw?.topology_member_id ?? `${nodeId}@${revisionId}`);
  return { member_id: memberId, node_id: nodeId, revision_id: revisionId };
}

function nodeKey(value, index = 0) {
  const identity = nodeIdentity(value, index);
  return `${identity.member_id}\u241f${identity.revision_id}\u241f${identity.node_id}`;
}

function normalizeNode(raw, index, topLevel, fallbackPlugins) {
  const identity = nodeIdentity(raw, index);
  let pluginSource = firstArray(raw?.installed_plugin_sets, raw?.plugin_sets, raw?.plugins, raw?.providers);
  if (!pluginSource.length) {
    pluginSource = fallbackPlugins.filter((plugin) => {
      const members = firstArray(plugin?.member_ids, plugin?.node_ids, plugin?.supported_nodes);
      return !members.length || members.map(String).includes(identity.member_id) || members.map(String).includes(identity.node_id);
    });
  }
  const plugins = pluginSource
    .map((plugin) => normalizePlugin(plugin, raw, topLevel))
    .filter((plugin) => plugin.plugin_set_id);
  const defaultPluginSetId = firstDeclaredString(
    raw?.default_plugin_set_id,
    raw?.active_plugin_set_id,
    plugins[0]?.plugin_set_id,
  );
  const defaultPlugin = plugins.find((plugin) => plugin.plugin_set_id === defaultPluginSetId) || null;
  return {
    ...raw,
    ...identity,
    key: nodeKey(identity),
    label: raw?.label || raw?.display_name || raw?.hostname || identity.node_id,
    site: raw?.site || raw?.location || raw?.region || "unassigned site",
    device_type: raw?.device_type || raw?.device_family || raw?.platform || raw?.role || "router",
    resources_available: raw?.resources_available !== false,
    plugins,
    default_plugin_set_id: defaultPluginSetId,
    default_projection_id: firstDeclaredString(
      raw?.default_projection_id,
      raw?.topology_projection_id,
      projectionId(defaultPlugin?.projections?.[0]),
    ),
    default_status_perspective_id: firstDeclaredString(
      raw?.default_status_perspective_id,
      raw?.status_perspective_id,
      perspectiveId(defaultPlugin?.perspectives?.[0]),
    ),
  };
}

function normalizeProfile(raw) {
  const id = firstDeclaredString(raw?.profile_id, raw?.topology_profile_id, raw?.id);
  return {
    ...raw,
    profile_id: id,
    projection_role: firstDeclaredString(raw?.projection_role, raw?.semantic_role, raw?.intent),
    label: raw?.label || raw?.display_name || (id ? titleCase(id) : "Topology profile unavailable"),
    presentation_roles: firstArray(
      raw?.presentation_roles,
      raw?.presentation?.roles,
      raw?.ui?.presentation_roles,
    ).map(String),
    empty_action_label: String(
      raw?.empty_action_label
      ?? raw?.presentation?.empty_action_label
      ?? raw?.ui?.empty_action_label
      ?? "",
    ),
  };
}

function profileForPresentationRole(role) {
  return state.capabilities?.profiles?.find(
    (profile) => firstArray(profile?.presentation_roles).some(
      (candidate) => String(candidate) === String(role),
    ),
  ) || null;
}

function normalizeCapabilities(raw, mode) {
  const fallbackPlugins = firstArray(raw?.plugin_sets, raw?.plugins, raw?.providers);
  const nodeSource = firstArray(raw?.members, raw?.nodes, raw?.node_descriptors, raw?.scope?.nodes);
  const nodes = nodeSource.slice(0, MAX_NODES).map((node, index) => normalizeNode(node, index, raw, fallbackPlugins));
  const profileSource = firstArray(
    raw?.topology_profiles,
    raw?.fabric_profiles,
    raw?.profiles,
  );
  const profiles = profileSource.map(normalizeProfile).filter((profile) => profile.profile_id);
  const perspectiveSource = firstArray(raw?.status_roles, raw?.status_perspectives, raw?.perspectives);
  const perspectiveMap = new Map();
  for (const item of perspectiveSource) {
    const id = perspectiveId(item);
    if (id) perspectiveMap.set(id, item);
  }
  for (const node of nodes) {
    for (const plugin of node.plugins) {
      for (const item of plugin.perspectives) {
        const id = perspectiveId(item);
        if (id) perspectiveMap.set(id, item);
      }
    }
  }
  const defaults = raw?.defaults || {};
  return {
    ...raw,
    nodes,
    profiles,
    perspectives: [...perspectiveMap.values()],
    default_profile_id: firstDeclaredString(
      raw?.default_profile_id,
      raw?.default_topology_profile_id,
      defaults?.profile_id,
      profiles[0]?.profile_id,
    ),
    default_perspective_id: firstDeclaredString(
      raw?.default_status_perspective_id,
      defaults?.status_perspective_id,
      perspectiveId([...perspectiveMap.values()][0]),
    ),
    default_clock_policy: String(raw?.default_clock_policy ?? defaults?.clock_policy ?? "strict"),
    source_mode: mode,
  };
}

function selectedProfile() {
  const id = byId("mn-projection")?.value;
  return state.capabilities?.profiles.find((item) => item.profile_id === id) || state.capabilities?.profiles[0];
}

function findMappedValue(mapping, node, plugin) {
  if (!mapping || typeof mapping !== "object") return null;
  return mapping[node.member_id] ?? mapping[node.node_id]
    ?? (plugin?.plugin_set_id ? mapping[plugin.plugin_set_id] : null)
    ?? null;
}

function pickDeclaredId(items, requestedId, idGetter, fallbackId) {
  if (!items.length) return "";
  // Projection and perspective identifiers are opaque plug-in data.  The
  // browser may select an exact coordinator mapping or an advertised default;
  // labels and "semantic" substrings are presentation only and must never
  // choose executable behavior.
  const exact = items.find((item) => idGetter(item) === requestedId);
  if (exact) return idGetter(exact);
  const advertisedDefault = items.find((item) => idGetter(item) === fallbackId);
  return advertisedDefault ? idGetter(advertisedDefault) : "";
}

function nodePlan(node) {
  const profile = selectedProfile();
  const requestedPerspective = byId("mn-perspective")?.value || state.capabilities?.default_perspective_id;
  const mappedPlugin = findMappedValue(profile?.plugin_set_by_member ?? profile?.plugin_sets, node, { plugin_set_id: "" });
  const requestedPluginId = firstDeclaredString(mappedPlugin, node.default_plugin_set_id);
  const plugin = node.plugins.find((item) => item.plugin_set_id === requestedPluginId) || null;
  const mappedProjection = findMappedValue(profile?.projection_by_member ?? profile?.node_projections, node, plugin);
  const projection = pickDeclaredId(
    plugin?.projections || [],
    firstDeclaredString(mappedProjection, node.default_projection_id),
    projectionId,
    node.default_projection_id,
  );
  const mappedPerspective = findMappedValue(profile?.perspective_by_member ?? profile?.node_perspectives, node, plugin);
  const perspective = pickDeclaredId(
    plugin?.perspectives || [],
    firstDeclaredString(mappedPerspective, requestedPerspective, node.default_status_perspective_id),
    perspectiveId,
    node.default_status_perspective_id,
  );
  const missing = [];
  if (!plugin) missing.push("plug-in set");
  if (!projection) missing.push("topology projection");
  if (!perspective) missing.push("status perspective");
  const executable = missing.length === 0;
  return {
    member_id: node.member_id,
    node_id: node.node_id,
    revision_id: node.revision_id,
    plugin_set_id: plugin?.plugin_set_id || "",
    plugin_version: plugin?.version || "",
    plugin_id: firstDeclaredString(
      plugin?.projections.find((item) => projectionId(item) === projection)?.provider_plugin_id,
      plugin?.projections.find((item) => projectionId(item) === projection)?.plugin_id,
      plugin?.plugins?.[0]?.plugin_id,
    ),
    projection_id: projection,
    status_perspective_id: perspective,
    executable,
    unavailable_reason: executable
      ? ""
      : `${node.label || node.node_id} has no declared ${missing.join(", ")} for this topology profile.`,
  };
}

function currentBasis() {
  const kind = byId("mn-basis-kind").value;
  const clockPolicy = byId("mn-clock-policy").value;
  if (kind === "absolute_time") {
    const raw = byId("mn-absolute-time").value.trim();
    if (!/^-?\d+$/.test(raw)) throw new Error("Absolute time must be an integer nanosecond timestamp.");
    return { kind, time_ns: BigInt(raw).toString(), clock_domain: "utc", clock_policy: clockPolicy };
  }
  const offsetNs = parseSecondsToNs(byId("mn-relative-seconds").value);
  if (offsetNs > 0n) throw new Error("A watermark-relative offset must be zero or in the past.");
  return { kind, offset_ns: offsetNs.toString(), clock_policy: clockPolicy };
}

function buildQueryRequest() {
  const nodes = state.capabilities.nodes.filter((node) => state.selectedNodeKeys.has(node.key));
  if (!nodes.length) throw new Error("Select at least one device.");
  const profile = selectedProfile();
  return {
    ...(profile?.profile_id ? { topology_profile_id: profile.profile_id } : {}),
    basis: currentBasis(),
    clock_policy: byId("mn-clock-policy").value,
    node_queries: nodes.map((node) => {
      const plan = nodePlan(node);
      if (!plan.executable) throw new Error(plan.unavailable_reason);
      return {
        member_id: plan.member_id,
        node_id: plan.node_id,
        revision_id: plan.revision_id,
        plugin_set_id: plan.plugin_set_id,
        ...(plan.plugin_version ? { plugin_version: plan.plugin_version } : {}),
        projections: [{
          ...(plan.plugin_id ? { plugin_id: plan.plugin_id } : {}),
          projection_id: plan.projection_id,
          status_perspective_id: plan.status_perspective_id,
        }],
      };
    }),
    include: ["nodes", "network_segments", "segment_attachments", "inter_node_links", "resource_previews"],
    node_limit: MAX_NODES,
    network_segment_limit: MAX_LINKS,
    segment_attachment_limit: MAX_SEGMENT_ATTACHMENTS,
    inter_node_link_limit: MAX_LINKS,
    resource_limit: RESOURCE_PREVIEW_LIMIT,
  };
}

function refIdentity(raw, fallbackNode = null) {
  if (typeof raw === "string") {
    return {
      member_id: fallbackNode?.member_id || "unknown-member",
      revision_id: fallbackNode?.revision_id || "unknown-revision",
      node_id: fallbackNode?.node_id || raw,
      resource_id: fallbackNode ? raw : null,
    };
  }
  const outer = raw || {};
  const node = outer?.resource_ref || outer?.scoped_ref || outer || fallbackNode || {};
  const identity = nodeIdentity(node);
  return {
    ...identity,
    resource_id: node?.resource_id ?? node?.local_resource_id ?? outer?.resource_id ?? node?.resource_uid ?? node?.canonical_resource_id ?? node?.focus_resource_id ?? null,
    label: node?.label ?? node?.display_name ?? null,
    navigation_target: outer?.navigation_target ?? outer?.deep_link ?? outer?.navigation ?? node?.navigation_target ?? null,
  };
}

function resourceRefKey(ref) {
  return `${ref?.member_id ?? ""}\u241f${ref?.revision_id ?? ""}\u241f${ref?.node_id ?? ""}\u241f${ref?.resource_id ?? ""}`;
}

function resultNodeSource(raw) {
  return firstArray(raw?.nodes, raw?.node_results, raw?.members, raw?.member_results);
}

function nodeResolvedBasis(raw) {
  return raw?.resolved_basis || raw?.basis || raw?.resolved_time || raw?.clock || {};
}

function normalizeResultNode(raw, index) {
  const identity = nodeIdentity(raw, index);
  const capability = state.capabilities.nodes.find((node) =>
    node.member_id === identity.member_id
    || (node.node_id === identity.node_id && node.revision_id === identity.revision_id)
  ) || normalizeNode(identity, index, state.capabilities, []);
  const fallbackPlan = nodePlan(capability);
  const plan = raw?.node_query || raw?.plugin_plan || raw?.selection || {};
  const pluginSetId = firstDeclaredString(plan?.plugin_set_id, fallbackPlan.plugin_set_id);
  const planProjectionId = firstDeclaredString(
    plan?.projection_id,
    plan?.topology_projection_id,
    fallbackPlan.projection_id,
  );
  const planPerspectiveId = firstDeclaredString(
    plan?.status_perspective_id,
    plan?.perspective_id,
    fallbackPlan.status_perspective_id,
  );
  const resources = firstArray(raw?.resource_previews, raw?.resources?.items, raw?.resources, raw?.items)
    .slice(0, RESOURCE_PREVIEW_LIMIT)
    .map((item) => ({
      ...item,
      ...refIdentity(item, capability),
      resource_id: String(item?.resource_id ?? item?.id ?? item?.resource_uid ?? "unknown-resource"),
    }));
  const basis = nodeResolvedBasis(raw);
  const coverage = raw?.coverage || raw?.completeness || {};
  return {
    ...capability,
    ...raw,
    ...identity,
    key: nodeKey(identity),
    label: raw?.label || raw?.display_name || raw?.hostname || capability.label,
    plugins: capability.plugins,
    plan: {
      ...fallbackPlan,
      ...plan,
      plugin_set_id: pluginSetId,
      projection_id: planProjectionId,
      status_perspective_id: planPerspectiveId,
      executable: Boolean(pluginSetId && planProjectionId && planPerspectiveId),
    },
    resolved_basis: basis,
    coverage,
    resources,
    resource_count: Number(raw?.resource_count ?? raw?.counts?.resources ?? raw?.resources?.total ?? resources.length),
    navigation_target: raw?.navigation_target || raw?.node_navigation_target || raw?.navigation || null,
  };
}

function endpointRef(raw, side, resultNodes) {
  const aliases = side === "source"
    ? [raw?.source_ref, raw?.source, raw?.from, raw?.endpoint_a, raw?.a]
    : [raw?.target_ref, raw?.target, raw?.to, raw?.endpoint_b, raw?.b];
  let value = aliases.find((item) => item !== undefined && item !== null);
  const nodeId = side === "source"
    ? raw?.source_node_id ?? raw?.from_node_id ?? raw?.node_a_id
    : raw?.target_node_id ?? raw?.to_node_id ?? raw?.node_b_id;
  const memberId = side === "source"
    ? raw?.source_member_id ?? raw?.from_member_id
    : raw?.target_member_id ?? raw?.to_member_id;
  const resourceId = side === "source"
    ? raw?.source_resource_id ?? raw?.from_resource_id
    : raw?.target_resource_id ?? raw?.to_resource_id;
  if (typeof value === "string") value = resourceId || nodeId ? { node_id: nodeId, member_id: memberId, resource_id: resourceId || value } : { node_id: value };
  value = value || { node_id: nodeId, member_id: memberId, resource_id: resourceId };
  let fallback = resultNodes.find((node) =>
    (memberId && node.member_id === String(memberId)) || (nodeId && node.node_id === String(nodeId))
  );
  if (!fallback && resultNodes.length === 1) fallback = resultNodes[0];
  return refIdentity(value, fallback);
}

function normalizeLink(raw, index, resultNodes) {
  const source = endpointRef(raw, "source", resultNodes);
  const target = endpointRef(raw, "target", resultNodes);
  source.navigation_target = source.navigation_target || raw?.deep_links?.endpoint_a || raw?.deep_links?.source;
  target.navigation_target = target.navigation_target || raw?.deep_links?.endpoint_b || raw?.deep_links?.target;
  const resolution = String(raw?.resolution ?? raw?.match_status ?? raw?.quality ?? (raw?.ambiguous ? "ambiguous" : "matched"));
  return {
    ...raw,
    link_id: String(raw?.link_id ?? raw?.relationship_id ?? raw?.edge_id ?? raw?.id ?? `link-${index + 1}`),
    source,
    target,
    kind: String(raw?.kind ?? raw?.link_type ?? raw?.relation_type ?? raw?.type ?? "inter-node"),
    status: String(raw?.status ?? raw?.operational_status ?? raw?.operational ?? raw?.state ?? "unknown"),
    resolution,
    network_id: String(raw?.network_id ?? raw?.network_segment_id ?? raw?.segment_id ?? raw?.subnet_id ?? raw?.broadcast_domain_id ?? raw?.fabric_id ?? ""),
    network_prefix: String(raw?.network_prefix ?? raw?.prefix ?? raw?.subnet?.prefix ?? raw?.network?.prefix ?? ""),
    network_role: String(raw?.network_role ?? raw?.segment_role ?? raw?.connectivity_role ?? raw?.scope_role ?? ""),
    vrf: String(raw?.vrf ?? raw?.vrf_id ?? raw?.routing_instance ?? ""),
    vlan: raw?.vlan ?? raw?.vlan_id ?? raw?.encapsulation?.vlan ?? null,
    source_attachment: normalizeNetworkAttachment(raw, "source", source),
    target_attachment: normalizeNetworkAttachment(raw, "target", target),
    candidates: firstArray(raw?.candidates, raw?.match_candidates, raw?.resolution_candidates),
    evidence: firstArray(raw?.evidence, raw?.provenance, raw?.source_records),
  };
}

function normalizeNetworkAttachment(raw, side, fallbackRef = null) {
  const endpoint = side === "source"
    ? raw?.source_ref ?? raw?.source ?? raw?.from ?? raw?.endpoint_a ?? raw?.a
    : raw?.target_ref ?? raw?.target ?? raw?.to ?? raw?.endpoint_b ?? raw?.b;
  const attachment = side === "source"
    ? raw?.source_attachment ?? raw?.from_attachment ?? raw?.attachment_a ?? raw?.source_port
    : raw?.target_attachment ?? raw?.to_attachment ?? raw?.attachment_b ?? raw?.target_port;
  const value = (attachment && typeof attachment === "object" ? attachment : {}) || {};
  const endpointValue = endpoint && typeof endpoint === "object" ? endpoint : {};
  const resourceNames = (items) => (items || [])
    .map((item) => String(item?.resource_id ?? item?.name ?? item?.interface_name ?? item?.id ?? item))
    .filter(Boolean);
  const addressValues = (items) => (items || [])
    .map((item) => String(item?.address ?? item?.prefix ?? item?.value ?? item))
    .filter(Boolean);
  const physicalInterfaces = resourceNames(firstArray(
    value?.physical_interface_resource_ids,
    value?.physical_interfaces,
    endpointValue?.physical_interface_resource_ids,
    endpointValue?.physical_interfaces,
  ));
  const subinterface = String(value?.logical_interface_resource_id ?? value?.subinterface_resource_id
    ?? value?.subinterface ?? value?.subinterface_name
    ?? endpointValue?.logical_interface_resource_id ?? endpointValue?.subinterface_resource_id
    ?? endpointValue?.subinterface ?? endpointValue?.subinterface_name ?? "");
  const parentInterface = String(value?.parent_interface_resource_id ?? value?.parent_interface
    ?? endpointValue?.parent_interface_resource_id ?? endpointValue?.parent_interface ?? "");
  const lag = String(value?.lag_resource_id ?? value?.lag ?? value?.lag_name ?? value?.bundle ?? value?.bundle_name
    ?? endpointValue?.lag_resource_id ?? endpointValue?.lag ?? endpointValue?.bundle ?? "");
  const names = firstArray(
    value?.interfaces,
    value?.interface_names,
    endpointValue?.interfaces,
    endpointValue?.interface_names,
  ).map((item) => String(item?.name ?? item?.interface_name ?? item?.id ?? item)).filter(Boolean);
  const singular = value?.interface_name ?? value?.interface ?? value?.port_name ?? value?.port
    ?? endpointValue?.interface_name ?? endpointValue?.interface ?? endpointValue?.port_name ?? endpointValue?.port
    ?? fallbackRef?.resource_id;
  if (singular && !names.includes(String(singular))) names.unshift(String(singular));
  return {
    attachment_id: String(value?.attachment_id ?? value?.membership_id ?? endpointValue?.attachment_id
      ?? endpointValue?.membership_id ?? endpointValue?.resource_id ?? fallbackRef?.resource_id ?? ""),
    interface_kind: String(value?.interface_kind ?? endpointValue?.interface_kind ?? "interface"),
    interface_names: [...new Set([...names, ...physicalInterfaces, subinterface, lag, parentInterface].filter(Boolean))],
    physical_interfaces: [...new Set(physicalInterfaces)],
    parent_interface: parentInterface,
    lag,
    subinterface,
    vlan: value?.vlan ?? value?.vlan_id ?? endpointValue?.vlan ?? endpointValue?.vlan_id ?? null,
    address: String(value?.address ?? value?.ip_address ?? endpointValue?.address ?? endpointValue?.ip_address ?? ""),
    addresses: addressValues(firstArray(value?.addresses, endpointValue?.addresses)),
    role: String(value?.role ?? value?.interface_role ?? endpointValue?.interface_role ?? ""),
  };
}

function normalizeConnectivityDomain(raw, index, resultNodes) {
  const semantics = raw?.plugin_semantics || raw?.semantics || {};
  const domainId = firstDeclaredString(
    raw?.network_id,
    raw?.segment_id,
    raw?.subnet_id,
    raw?.broadcast_domain_id,
    raw?.vpn_id,
    raw?.id,
  );
  const role = firstDeclaredString(
    semantics?.role,
    raw?.network_role,
    raw?.segment_role,
    raw?.connectivity_role,
    raw?.role,
  );
  const kind = firstDeclaredString(
    semantics?.network_kind,
    raw?.network_kind,
    raw?.segment_kind,
    raw?.kind,
    raw?.type,
  );
  const rawMembers = firstArray(raw?._attachments, raw?.members, raw?.attachments, raw?.endpoints, raw?.interfaces, raw?.claims);
  const members = rawMembers.map((member, memberIndex) => {
    const refSource = { ...(member?.endpoint || member?.node_ref || member?.endpoint_ref || {}), ...(member?.resource_ref || {}) };
    const nodeId = refSource?.node_id ?? member?.node_id ?? member?.device_id;
    const memberId = refSource?.member_id ?? member?.member_id ?? member?.topology_member_id;
    const fallback = resultNodes.find((node) => (memberId && node.member_id === String(memberId))
      || (nodeId && node.node_id === String(nodeId)));
    const ref = refIdentity(refSource || {}, fallback);
    return {
      ...member,
      member_id: String(member?.attachment_id ?? member?.membership_id ?? `${domainId}:member:${memberIndex + 1}`),
      ref,
      attachment: normalizeSegmentAttachmentModel(member, ref),
      status: String(member?.operational_status ?? member?.status ?? member?.state ?? raw?.operational_status ?? raw?.status ?? "unknown"),
      resolution: String(member?.quality ?? member?.resolution ?? raw?.quality ?? raw?.resolution ?? "unknown"),
      link_ids: firstArray(member?.link_ids, member?.topology_link_ids).map(String),
    };
  });
  const prefix = String(semantics?.prefix ?? raw?.network_prefix ?? raw?.prefix ?? raw?.cidr ?? raw?.subnet?.prefix ?? "");
  const routingScope = semantics?.routing_scope;
  const scopeKind = String(typeof routingScope === "object" ? routingScope?.kind ?? routingScope?.type ?? "" : "");
  const vrf = String((typeof routingScope === "object"
    ? routingScope?.id ?? routingScope?.name ?? routingScope?.value ?? routingScope?.vrf
    : routingScope) ?? raw?.vrf ?? raw?.vrf_id ?? raw?.routing_instance ?? "");
  const vlan = raw?.vlan ?? raw?.vlan_id ?? raw?.encapsulation?.vlan ?? null;
  const label = String(semantics?.label ?? raw?.label ?? raw?.display_name
    ?? (prefix || (vlan !== null ? `VLAN ${vlan}` : domainId)));
  return {
    ...raw,
    network_id: domainId,
    label: label || domainId,
    prefix,
    role,
    kind,
    vrf,
    routing_scope_kind: scopeKind,
    vlan,
    status: String(raw?.operational_status ?? raw?.status ?? raw?.state ?? "unknown"),
    resolution: String(raw?.quality ?? raw?.resolution ?? raw?.match_status ?? "unknown"),
    connectivity_enabled: semantics?.participates_in_connectivity !== false
      && raw?.connectivity_enabled !== false && raw?.participates_in_connectivity !== false,
    presentation_plane: firstDeclaredString(semantics?.presentation_group, raw?.presentation_plane, raw?.network_plane),
    is_vpn: raw?.is_vpn === true,
    separate_view: semantics?.separate_view === true || raw?.separate_view === true,
    plugin_asserted_external: raw?.plugin_asserted_external === true || semantics?.plugin_asserted_external === true,
    coverage_complete: raw?.coverage_complete === true || semantics?.coverage_complete === true,
    topology_presentation: {
      ...(semantics?.topology_presentation || {}),
      ...(raw?.topology_presentation || {}),
    },
    existing_node_count: Number(raw?.existing_node_count ?? raw?.node_count ?? 0),
    existing_attachment_count: Number(raw?.existing_attachment_count ?? raw?.attachment_count ?? 0),
    returned_attachment_count: Number(raw?.returned_attachment_count ?? members.length),
    semantic_conflict: raw?.semantic_conflict === true,
    members,
    source: "plugin",
  };
}

function normalizeSegmentAttachmentModel(member, fallbackRef) {
  const model = member?.attachment_model || {};
  const vlan = model?.vlan?.id ?? model?.vlan_id ?? member?.vlan?.id ?? member?.vlan_id ?? null;
  const physical = firstArray(model?.physical_interface_resource_ids, model?.physical_interfaces).map(String);
  const logical = model?.logical_interface_resource_id ?? model?.subinterface_resource_id ?? "";
  const parent = model?.parent_interface_resource_id ?? "";
  const lag = model?.lag_resource_id ?? "";
  const interfaceNames = [...new Set([logical, lag, parent, ...physical, fallbackRef?.resource_id].filter(Boolean).map(String))];
  const addresses = firstArray(model?.addresses, member?.addresses).map((item) => String(item?.address ?? item?.prefix ?? item)).filter(Boolean);
  return {
    attachment_id: String(member?.attachment_id ?? member?.membership_id ?? fallbackRef?.resource_id ?? ""),
    interface_kind: String(model?.interface_kind ?? member?.interface_kind ?? "interface"),
    interface_names: interfaceNames,
    lag: String(lag),
    subinterface: String(logical),
    parent_interface: String(parent),
    physical_interfaces: physical,
    vlan,
    address: addresses.join(", "),
    addresses,
    role: String(model?.role ?? member?.role ?? ""),
  };
}

function normalizeQuery(raw, request, sourceMode) {
  const nodeTimes = firstArray(raw?.node_times, raw?.resolved_basis?.nodes, raw?.resolved_basis?.node_times);
  let nodes = resultNodeSource(raw).map(normalizeResultNode);
  if (!nodes.length) {
    nodes = state.capabilities.nodes
      .filter((node) => state.selectedNodeKeys.has(node.key))
      .map((node, index) => {
        const time = nodeTimes.find((item) =>
          String(item?.member_id || "") === node.member_id
          || String(item?.node_id || item?.id || "") === node.node_id
        );
        return normalizeResultNode({ ...node, ...(time || {}), resolved_basis: time || node.resolved_basis }, index);
      });
  }
  const topResources = firstArray(raw?.resource_previews, raw?.resources?.items, raw?.resources);
  if (topResources.length) {
    const resourcefulNodes = nodes.filter((node) => node.resources_available !== false);
    nodes = nodes.map((node) => {
      if (node.resources.length) return node;
      const resources = topResources.filter((item) => {
        const member = String(item?.member_id ?? item?.topology_member_id ?? "");
        const resourceNode = String(item?.node_id ?? item?.device_id ?? "");
        if (member || resourceNode) return member === node.member_id || resourceNode === node.node_id;
        return resourcefulNodes.length === 1 && resourcefulNodes[0].key === node.key;
      }).slice(0, RESOURCE_PREVIEW_LIMIT).map((item) => ({
        ...item,
        ...refIdentity(item, node),
        resource_id: String(item?.resource_id ?? item?.id ?? item?.resource_uid ?? "unknown-resource"),
      }));
      return {
        ...node,
        resources,
        resource_count: Number(raw?.counts?.resources ?? node.resource_count ?? resources.length),
      };
    });
  }
  const explicitLinks = firstArray(raw?.inter_node_links, raw?.links, raw?.boundary_links, raw?.edges);
  const linkSource = explicitLinks.length
    ? explicitLinks
    : firstArray(raw?.inferred_connectivity);
  const unresolvedGroups = firstArray(raw?.connector_resolutions, raw?.boundary_resolutions)
    .filter((item) => ["unresolved", "conflict"].includes(String(item?.resolution || "")))
    .map((item, index) => {
      const claims = firstArray(item?.claims, item?.candidates);
      const claim = claims[0] || {};
      const linker = item?.linker_plugin_provenance || item?.plugin_provenance || {};
      return {
        link_id: `resolution:${item?.matcher_id || "matcher"}:${item?.match_key || index}`,
        source: claim,
        target: {
          label: item?.resolution === "conflict" ? "Conflicting remote endpoints" : "No compatible remote endpoint",
        },
        link_type: item?.matcher_id || "connector-resolution",
        status: "unknown",
        resolution: item?.resolution || "unresolved",
        candidates: claims,
        evidence: [{
          label: `${linker?.plugin_id || "federation linker"} preserved ${item?.resolution || "unresolved"} result`,
        }],
        resolution_only: true,
      };
    });
  const links = [...linkSource, ...unresolvedGroups]
    .slice(0, MAX_LINKS)
    .map((link, index) => normalizeLink(link, index, nodes));
  const domainSource = firstArray(
    raw?.connectivity_domains,
    raw?.network_segments,
  );
  const segmentAttachments = firstArray(raw?.segment_attachments, raw?.network_attachments, raw?.connectivity_attachments)
    .filter((attachment) => attachment?.exists !== false);
  const connectivityDomains = domainSource.map((domain, index) => {
    const segmentId = String(domain?.segment_id ?? domain?.network_id ?? domain?.id ?? "");
    const attachmentIds = new Set(firstArray(domain?.attachment_ids, domain?.member_ids).map(String));
    const attachments = segmentAttachments.filter((attachment) => {
      const attachmentSegmentId = String(attachment?.segment_id ?? attachment?.network_segment_id ?? attachment?.network_id ?? "");
      return attachmentSegmentId === segmentId || attachmentIds.has(String(attachment?.attachment_id ?? attachment?.id ?? ""));
    });
    return normalizeConnectivityDomain({ ...domain, _attachments: attachments }, index, nodes);
  }).filter((domain) => domain.network_id);
  return {
    ...raw,
    request: raw?.request || request,
    context_id: raw?.context_id || raw?.query_context_id || raw?.reconstruction_id || "",
    nodes,
    links,
    connectivity_domains: connectivityDomains,
    resolved_basis: raw?.resolved_basis || raw?.basis || request.basis,
    counts: raw?.counts || raw?.summary || {},
    completeness: raw?.completeness || raw?.coverage || {},
    source_mode: sourceMode,
  };
}

function routeValueId(raw, fallback = "") {
  if (typeof raw === "string" || typeof raw === "number") return String(raw);
  return String(raw?.scenario_id ?? raw?.start_id ?? raw?.endpoint_id ?? raw?.source_id ?? raw?.destination_id ?? raw?.route_type ?? raw?.type_id ?? raw?.target_id ?? raw?.value ?? raw?.prefix ?? raw?.id ?? fallback);
}

function normalizeRouteEndpoint(raw, index, kind) {
  const endpoint = typeof raw === "object" ? raw : { value: String(raw) };
  const idField = kind === "source" ? "source_id" : "destination_id";
  const selectorId = firstDeclaredString(
    endpoint?.[idField],
    endpoint?.endpoint_id,
    routeValueId(endpoint),
  );
  const canonicalEndpointId = firstDeclaredString(endpoint?.endpoint_id, selectorId);
  const value = firstDeclaredString(endpoint?.value, endpoint?.prefix, endpoint?.address, endpoint?.label, selectorId);
  return {
    ...endpoint,
    endpoint_id: canonicalEndpointId,
    [idField]: selectorId,
    value,
    label: endpoint?.label || endpoint?.display_name || value,
  };
}

function normalizeRouteStartPoint(raw, index) {
  const point = typeof raw === "object" ? raw : { start_id: String(raw) };
  const startId = firstDeclaredString(point?.start_id, point?.id);
  return {
    ...point,
    start_id: startId,
    value: firstDeclaredString(point?.value, point?.node_id, startId),
    label: firstDeclaredString(point?.label, point?.display_name, point?.node_id, startId),
  };
}

function routeStartSelectorValue(raw) {
  if (raw === undefined || raw === null) return "";
  if (typeof raw !== "object") return String(raw);
  return String(
    raw.start_id
    ?? raw.id
    ?? raw.resource_id
    ?? raw.member_id
    ?? raw.node_id
    ?? raw.value
    ?? raw.label
    ?? "",
  );
}

function normalizeRouteCapabilities(raw) {
  const scenarios = firstArray(raw?.scenarios, raw?.trace_scenarios, raw?.route_scenarios).map((item) => {
    const scenario = typeof item === "object" ? item : { scenario_id: String(item) };
    const scenarioId = firstDeclaredString(scenario?.scenario_id, scenario?.id);
    return {
      ...scenario,
      scenario_id: scenarioId,
      label: scenario?.label || scenario?.display_name || titleCase(scenarioId),
      description: scenario?.description || scenario?.semantics || "Plug-in supplied route trace scenario",
    };
  }).filter((scenario) => scenario.scenario_id);
  const sources = firstArray(raw?.sources, raw?.route_sources, raw?.source_examples)
    .map((item, index) => normalizeRouteEndpoint(item, index, "source"))
    .filter((source) => source.source_id);
  const destinations = firstArray(raw?.destinations, raw?.route_destinations, raw?.targets, raw?.destination_examples)
    .map((item, index) => normalizeRouteEndpoint(item, index, "destination"))
    .filter((destination) => destination.destination_id);
  const startPoints = firstArray(raw?.start_points, raw?.observation_points, raw?.ingresses)
    .map((item, index) => normalizeRouteStartPoint(item, index))
    .filter((point) => point.start_id);
  const directionalPairs = firstArray(raw?.directional_pairs, raw?.route_pairs, raw?.endpoint_pairs).map((item) => ({
    ...(typeof item === "object" ? item : {}),
    pair_id: firstDeclaredString(item?.pair_id, item?.id),
    source_id: firstDeclaredString(item?.source_id, item?.a_source_id, item?.endpoint_a_id),
    destination_id: firstDeclaredString(item?.destination_id, item?.b_destination_id, item?.endpoint_b_id),
  }));
  const routeTypes = firstArray(raw?.types, raw?.route_types, raw?.destination_types).map((item) => ({
    ...(typeof item === "object" ? item : { type_id: String(item) }),
    type_id: firstDeclaredString(
      typeof item === "object" ? item?.type_id : item,
      typeof item === "object" ? item?.route_type : null,
      typeof item === "object" ? item?.id : null,
    ),
    label: item?.label || item?.display_name || titleCase(firstDeclaredString(
      typeof item === "object" ? item?.type_id : item,
      typeof item === "object" ? item?.route_type : null,
      typeof item === "object" ? item?.id : null,
    )),
  })).filter((item) => item.type_id);
  const vrfs = firstArray(raw?.vrfs, raw?.route_vrfs, raw?.routing_instances).map((item) => {
    const value = typeof item === "object" ? item : { vrf: String(item) };
    const vrf = firstDeclaredString(value?.vrf, value?.name, value?.value, value?.vrf_id);
    return {
      ...value,
      vrf_id: firstDeclaredString(value?.vrf_id, value?.id),
      vrf,
      label: firstDeclaredString(value?.label, value?.display_name, vrf),
    };
  }).filter((item) => item.vrf);
  const routeFamilies = firstArray(raw?.route_families, raw?.address_families, raw?.families).map((item) => {
    const value = typeof item === "object" ? item : { route_family: String(item) };
    const routeFamily = firstDeclaredString(value?.route_family, value?.family, value?.address_family, value?.value);
    return {
      ...value,
      route_family: routeFamily,
      address_family: firstDeclaredString(value?.address_family, value?.afi, routeFamily),
      safi: firstDeclaredString(value?.safi),
      label: firstDeclaredString(value?.label, value?.display_name, titleCase(routeFamily)),
    };
  }).filter((item) => item.route_family);
  const policies = firstArray(raw?.resolution_modes, raw?.resolution_policies, raw?.policies, raw?.missing_hop_policies)
    .map((item) => firstDeclaredString(
      typeof item === "object" ? item?.mode : item,
      typeof item === "object" ? item?.policy : null,
      typeof item === "object" ? item?.id : null,
    ))
    .filter(Boolean);
  const steeringProfiles = firstArray(raw?.steering_profiles).map((item) => {
    const profile = item && typeof item === "object" ? item : { profile_id: String(item ?? "") };
    const profileId = firstDeclaredString(profile?.profile_id, profile?.steering_profile_id, profile?.id);
    return {
      ...profile,
      profile_id: profileId,
      label: String(profile?.label ?? profile?.display_name ?? profileId),
      description: String(profile?.description ?? profile?.reason ?? "Server-advertised counterfactual steering profile"),
    };
  }).filter((profile) => profile.profile_id);
  const defaults = raw?.default_request || raw?.defaults || {};
  const defaultSource = defaults?.flow?.source ?? defaults?.source;
  const defaultDestination = defaults?.flow?.destination ?? defaults?.destination;
  const defaultStart = defaults?.trace_starts?.forward ?? defaults?.ingress ?? defaults?.starting_point;
  if (!sources.length && defaultSource) {
    const declaredSource = normalizeRouteEndpoint(defaultSource, 0, "source");
    if (declaredSource.source_id) sources.push(declaredSource);
  }
  if (!destinations.length && defaultDestination) {
    const declaredDestination = normalizeRouteEndpoint(defaultDestination, 0, "destination");
    if (declaredDestination.destination_id) destinations.push(declaredDestination);
  }
  if (!startPoints.length && defaultStart) {
    const declaredStart = normalizeRouteStartPoint(defaultStart, 0);
    if (declaredStart.start_id) startPoints.push(declaredStart);
  }
  const requestedDefaultScenario = firstDeclaredString(raw?.default_scenario_id, defaults?.scenario_id);
  const defaultScenario = scenarios.find((scenario) => scenario.scenario_id === requestedDefaultScenario)
    || scenarios[0]
    || null;
  const requestedDefaultPolicy = firstDeclaredString(
    raw?.default_resolution_policy,
    defaults?.resolution_mode,
    defaults?.resolution_policy,
    defaults?.policy,
  );
  const defaultPolicy = policies.includes(requestedDefaultPolicy)
    ? requestedDefaultPolicy
    : policies[0] || "";
  const requestedDefaultSteering = firstDeclaredString(
    raw?.default_steering_profile_id,
    defaults?.steering_profile_id,
  );
  const defaultSteering = steeringProfiles.some((profile) => profile.profile_id === requestedDefaultSteering)
    ? requestedDefaultSteering
    : "";
  const requestedDefaultVrf = firstDeclaredString(
    raw?.default_vrf_id,
    raw?.default_vrf,
    defaults?.vrf_id,
    defaults?.vrf,
  );
  const defaultVrf = vrfs.find((vrf) =>
    vrf.vrf === requestedDefaultVrf || vrf.vrf_id === requestedDefaultVrf
  ) || vrfs[0] || null;
  return {
    ...raw,
    scenarios,
    sources,
    destinations,
    start_points: startPoints,
    directional_pairs: directionalPairs,
    route_types: routeTypes,
    vrfs,
    route_families: routeFamilies,
    policies,
    steering_profiles: steeringProfiles,
    default_scenario_id: defaultScenario?.scenario_id || "",
    default_source: firstDeclaredString(
      raw?.default_source_id,
      raw?.default_source,
      defaults?.source_id,
      defaultSource?.source_id,
      defaultSource?.endpoint_id,
      defaultSource?.value,
      defaultSource?.address,
      defaultSource,
      sources[0]?.source_id,
      sources[0]?.value,
    ),
    default_destination: firstDeclaredString(
      raw?.default_destination_id,
      raw?.default_destination,
      defaults?.destination_id,
      defaultDestination?.destination_id,
      defaultDestination?.endpoint_id,
      defaultDestination?.value,
      defaultDestination?.prefix,
      defaultDestination?.address,
      defaultDestination,
      destinations[0]?.destination_id,
      destinations[0]?.value,
    ),
    default_start: routeStartSelectorValue(
      raw?.default_start_id
      ?? raw?.default_start
      ?? defaults?.start_id
      ?? defaultStart
      ?? startPoints[0]?.start_id
      ?? "",
    ),
    default_policy: defaultPolicy,
    default_steering_profile: defaultSteering,
    default_vrf: defaultVrf?.vrf || "",
    default_route_family: String(raw?.default_route_family ?? defaults?.route_family ?? defaults?.address_family ?? routeFamilies[0]?.route_family ?? ""),
    default_route_type: String(raw?.default_route_type ?? defaults?.route_type ?? routeTypes[0]?.type_id ?? ""),
    route_table_query_href: String(raw?.route_table_query_href ?? raw?.route_tables_href ?? raw?.route_tables?.query_href ?? ""),
  };
}

function advertisedRouteType(value) {
  return state.routeCapabilities?.route_types.find((item) => item.type_id === String(value || "")) || null;
}

function advertisedRouteFamily(value) {
  const requested = String(value || "");
  return state.routeCapabilities?.route_families.find((item) =>
    item.route_family === requested || item.address_family === requested
  ) || null;
}

function advertisedVrf(value) {
  const requested = String(value || "");
  return state.routeCapabilities?.vrfs.find((item) => item.vrf === requested || item.vrf_id === requested) || null;
}

function steeringProfilesForScenario(scenario) {
  const advertised = firstArray(state.routeCapabilities?.steering_profiles);
  const declaredIds = firstArray(scenario?.steering_profiles).map((item) =>
    String(typeof item === "object"
      ? item?.profile_id ?? item?.steering_profile_id ?? item?.id ?? ""
      : item)
  ).filter(Boolean);
  if (declaredIds.length) {
    const allowed = new Set(declaredIds);
    return advertised.filter((profile) => allowed.has(profile.profile_id));
  }
  const defaultId = String(state.routeCapabilities?.default_steering_profile || "");
  return defaultId
    ? advertised.filter((profile) => profile.profile_id === defaultId)
    : [];
}

function renderRouteSteeringProfiles(scenario, requestedProfileId = "") {
  const select = byId("mn-route-steering");
  const profiles = steeringProfilesForScenario(scenario);
  select.innerHTML = [
    '<option value="">No steering override</option>',
    ...profiles.map((profile) =>
      `<option value="${escapeHtml(profile.profile_id)}" title="${escapeHtml(profile.description)}">${escapeHtml(profile.label)}</option>`
    ),
  ].join("");
  const requested = String(requestedProfileId || "");
  const fallback = String(
    state.routeCapabilities?.default_steering_profile || ""
  );
  select.value = profiles.some((profile) => profile.profile_id === requested)
    ? requested
    : profiles.some((profile) => profile.profile_id === fallback)
      ? fallback
      : "";
  select.disabled = !profiles.length;
}

function advertisedValues(values, fields = []) {
  return firstArray(values).map((item) => {
    if (typeof item !== "object") return String(item);
    return String(fields.map((field) => item?.[field]).find((value) => value !== undefined && value !== null) ?? routeValueId(item));
  }).filter(Boolean);
}

function routeFamilySupportsType(family, routeType) {
  if (!family || !routeType) return true;
  const supported = advertisedValues(family.supported_route_types, ["route_type", "type_id"]);
  return !supported.length || supported.includes(routeType);
}

function vrfSupportsRouteContext(vrf, family, routeType) {
  if (!vrf) return false;
  const families = advertisedValues(vrf.route_families, ["route_family", "family"]);
  const types = advertisedValues(vrf.supported_route_types, ["route_type", "type_id"]);
  return (!family || !families.length || families.includes(family.route_family))
    && (!routeType || !types.length || types.includes(routeType));
}

function resolveCompatibleRouteContext({ routeType, routeFamily, vrf, scenario = null }) {
  const capabilities = state.routeCapabilities;
  if (!capabilities) return { routeType: String(routeType || ""), family: null, vrf: null };
  const scenarioType = String(scenario?.route_type ?? "");
  const requestedType = String(routeType || scenarioType || capabilities.default_route_type || "");
  const resolvedType = advertisedRouteType(requestedType)?.type_id
    || advertisedRouteType(scenarioType)?.type_id
    || advertisedRouteType(capabilities.default_route_type)?.type_id
    || capabilities.route_types[0]?.type_id || "";
  const scenarioFamily = advertisedRouteFamily(scenario?.route_family ?? scenario?.address_family);
  const requestedFamily = advertisedRouteFamily(routeFamily);
  const defaultFamily = advertisedRouteFamily(capabilities.default_route_family);
  const family = [requestedFamily, scenarioFamily, defaultFamily, ...capabilities.route_families]
    .find((candidate) => candidate && routeFamilySupportsType(candidate, resolvedType)) || null;
  const scenarioVrf = advertisedVrf(scenario?.vrf ?? scenario?.vrf_id);
  const requestedVrf = advertisedVrf(vrf);
  const defaultVrf = advertisedVrf(capabilities.default_vrf);
  const resolvedVrf = [requestedVrf, scenarioVrf, defaultVrf, ...capabilities.vrfs]
    .find((candidate) => vrfSupportsRouteContext(candidate, family, resolvedType)) || null;
  return { routeType: resolvedType, family, vrf: resolvedVrf };
}

function applyCompatibleRouteContext({ routeType, routeFamily, vrf, scenario = selectedRouteScenario() }) {
  const context = resolveCompatibleRouteContext({ routeType, routeFamily, vrf, scenario });
  if (context.routeType) ensureRouteSelectValue(byId("mn-route-type"), context.routeType);
  if (context.family) ensureRouteSelectValue(byId("mn-route-family"), context.family.route_family);
  if (context.vrf) byId("mn-route-vrf").value = context.vrf.vrf;
  return context;
}

function routeDisplayValue(value, fallback = "") {
  if (value === null || value === undefined || value === "") return fallback;
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return String(value);
  return String(value?.label ?? value?.display_name ?? value?.value ?? value?.name ?? value?.address
    ?? value?.prefix ?? value?.source_id ?? value?.destination_id ?? value?.resource_id ?? value?.id ?? fallback);
}

function routeEntryRefKey(ref, fallback = "") {
  if (ref === null || ref === undefined || ref === "") return fallback;
  if (typeof ref !== "object") return String(ref);
  const direct = ref?.route_entry_id ?? ref?.entry_id ?? ref?.row_id ?? ref?.resource_id ?? ref?.id;
  const populatedKeys = Object.keys(ref).filter((key) => ref[key] !== null && ref[key] !== undefined && ref[key] !== "");
  if (direct && populatedKeys.length === 1) return String(direct);
  try {
    return canonicalJson(ref);
  } catch (_error) {
    return fallback;
  }
}

function normalizedRouteEnum(value) {
  if (value === null || value === undefined || typeof value === "object") return "";
  return String(value).trim().toLowerCase().replace(/[\s-]+/g, "_");
}

function firstRouteEnum(...values) {
  for (const value of values) {
    const normalized = normalizedRouteEnum(value);
    if (normalized) return normalized;
  }
  return "";
}

function routeStateEnum(value) {
  if (value && typeof value === "object") {
    return firstRouteEnum(value.state, value.status, value.result, value.disposition);
  }
  return normalizedRouteEnum(value);
}

function explicitRouteBoolean(...values) {
  for (const value of values) {
    if (value === true || value === false) return value;
  }
  return null;
}

const ROUTE_ACTIVE_STATES = new Set(["active", "selected_active"]);
const ROUTE_INACTIVE_STATES = new Set(["inactive", "standby", "backup", "withdrawn", "disabled"]);
const ROUTE_SELECTED_STATES = new Set(["selected", "selected_primary", "ecmp_member"]);
const ROUTE_STANDBY_STATES = new Set([
  "eligible_standby",
  "inactive_candidate",
  "best_effort_candidate",
  "comparison_only",
  "control_expected_not_observed",
]);
const ROUTE_TERMINAL_RESULTS = new Set([
  "drop",
  "dropped",
  "discard",
  "discarded",
  "dead",
  "terminated",
  "unusable",
  "unreachable",
  "withdrawn",
  "failed",
  "terminal_failure",
  "ineligible_dead",
]);
const ROUTE_CYCLE_RESULTS = new Set([
  "cycle",
  "recursive_cycle",
  "resolution_cycle",
  "forwarding_loop",
  "loop",
]);
const ROUTE_CYCLE_REASONS = new Set([
  "recursive_resolution_cycle",
  "forwarding_loop",
  "next_hop_cycle",
]);
const ROUTE_POLICY_BLOCKED_RESULTS = new Set([
  "policy_blocked",
  "blocked_by_policy",
  "policy_rejected",
  "suppressed",
  "reject",
  "blocked",
]);
const ROUTE_CONTROL_PLANE_STATES = new Set([
  "control_plane_only",
  "control_plane_observed",
  "control_plane_only_not_forwarding",
  "not_installed",
  "not_forwarding",
  "eligible_not_installed",
]);
const ROUTE_INFERRED_COMPLETENESS = new Set([
  "best_effort",
  "best_effort_inferred",
  "best_effort_resolved",
  "inferred",
]);
const ROUTE_UNRESOLVED_COMPLETENESS = new Set([
  "incomplete",
  "partial",
  "unresolved",
  "missing",
  "gap",
  "terminal_failure",
]);
const ROUTE_UNKNOWN_COMPLETENESS = new Set(["", "unknown", "not_reported"]);
const ROUTE_INCONSISTENT_STATES = new Set([
  "inconsistent",
  "conflict",
  "mismatch",
  "disagreement",
  "inconsistent_one_way_drop",
  "cross_layer_mismatch",
]);
const ROUTE_CONSISTENT_STATES = new Set([
  "consistent",
  "consistent_with_selected_observations",
  "consistent_after_failover",
]);

function explicitRouteActivity(value) {
  const direct = firstRouteEnum(value?.activity, value?.activity_state);
  if (direct) return direct;
  const active = explicitRouteBoolean(value?.active, value?.state?.active);
  return active === true ? "active" : active === false ? "inactive" : "unknown";
}

function explicitRouteSelection(value) {
  return firstRouteEnum(
    value?.selection,
    value?.selection_state,
    value?.eligibility,
    value?.alternative_state,
  ) || "unknown";
}

function explicitRouteCompleteness(value) {
  const direct = routeStateEnum(value?.completeness ?? value?.completeness_status ?? value?.coverage ?? value?.resolution);
  if (direct) return direct;
  const complete = explicitRouteBoolean(value?.complete, value?.end_to_end_resolved);
  return complete === true ? "complete" : complete === false ? "incomplete" : "unknown";
}

function explicitRouteConsistency(value) {
  const direct = routeStateEnum(value?.consistency ?? value?.consistency_state ?? value?.consistency_status);
  if (direct) return direct;
  const consistent = explicitRouteBoolean(value?.consistent);
  return consistent === true ? "consistent" : consistent === false ? "inconsistent" : "unknown";
}

function explicitRouteDisposition(value) {
  const routeState = value?.state && typeof value.state === "object" ? value.state : {};
  return firstRouteEnum(
    value?.disposition,
    value?.result,
    value?.outcome,
    value?.terminal_disposition,
    routeState?.terminal_disposition,
  ) || "unknown";
}

function legacyRouteDisposition(value) {
  const routeState = value?.state && typeof value.state === "object" ? value.state : {};
  return firstRouteEnum(value?.status, value?.operational, routeState?.operational);
}

function routeCompletenessIsInferred(value) {
  return ROUTE_INFERRED_COMPLETENESS.has(routeStateEnum(value?.completeness ?? value));
}

function routeCompletenessIsUnresolved(value) {
  return ROUTE_UNRESOLVED_COMPLETENESS.has(routeStateEnum(value?.completeness ?? value));
}

function routeCompletenessIsUnknown(value) {
  return ROUTE_UNKNOWN_COMPLETENESS.has(routeStateEnum(value?.completeness ?? value));
}

function routeConsistencyIsInconsistent(value) {
  const explicit = explicitRouteBoolean(value?.inconsistent);
  if (explicit !== null) return explicit;
  return ROUTE_INCONSISTENT_STATES.has(explicitRouteConsistency(value));
}

function normalizeRouteForwardingActions(raw) {
  const actions = firstArray(raw?.forwarding_actions, raw?.forwarding?.actions).slice(0, 8);
  return actions.map((item, actionIndex) => {
    const action = item && typeof item === "object" ? item : { values: [item] };
    const values = firstArray(action?.values, action?.entries, action?.identifiers).slice(0, 32).map((rawValue, valueIndex) => {
      const value = rawValue && typeof rawValue === "object" ? rawValue : { value: rawValue };
      return {
        ...value,
        value: routeDisplayValue(value?.display ?? value, "unknown"),
        kind: String(value?.kind ?? value?.type ?? "opaque"),
        value_type: String(value?.value_type ?? "opaque"),
        role: routeDisplayValue(value?.role, ""),
        position: Number.isFinite(Number(value?.position)) ? Number(value.position) : valueIndex,
      };
    }).sort((left, right) => left.position - right.position);
    return {
      ...action,
      action_id: String(action?.action_id ?? action?.id ?? `forwarding-action-${actionIndex + 1}`),
      kind: String(action?.kind ?? action?.type ?? "forwarding_identifiers"),
      label: routeDisplayValue(action?.label, titleCase(action?.kind ?? action?.type ?? "Forwarding identifiers")),
      operation: routeDisplayValue(action?.operation ?? action?.action, "apply"),
      order: routeDisplayValue(action?.order, "declared order"),
      applies_to_next_hop_id: String(action?.applies_to_next_hop_id ?? action?.next_hop_id ?? ""),
      values,
    };
  }).filter((action) => action.values.length);
}

function routeTableItems(raw) {
  let items = firstArray(raw?.items, raw?.entries, raw?.route_table_entries, raw?.routes);
  if (items.length) return items;
  const tables = raw?.route_tables ?? raw?.tables ?? raw?.node_route_tables;
  if (Array.isArray(tables)) return tables.flatMap((table) => firstArray(table?.items, table?.entries, table?.routes)
    .map((entry) => ({ ...entry, node_id: entry?.node_id ?? table?.node_id, member_id: entry?.member_id ?? table?.member_id })));
  items = firstArray(tables?.items, tables?.entries, tables?.route_table_entries);
  if (items.length) return items;
  return firstArray(tables?.nodes, tables?.node_tables).flatMap((table) => firstArray(table?.items, table?.entries, table?.routes)
    .map((entry) => ({ ...entry, node_id: entry?.node_id ?? table?.node_id, member_id: entry?.member_id ?? table?.member_id })));
}

function normalizeRouteTableEntry(raw, index) {
  const destination = raw?.destination && typeof raw.destination === "object" ? raw.destination : {};
  const entryId = String(raw?.route_entry_id ?? raw?.entry_id ?? raw?.row_id ?? raw?.route_id ?? raw?.id ?? `route-entry-${index + 1}`);
  const entryRef = raw?.route_entry_ref ?? raw?.entry_ref ?? raw?.ref ?? entryId;
  const traceQuery = raw?.trace_query && typeof raw.trace_query === "object" && !Array.isArray(raw.trace_query)
    ? raw.trace_query
    : {};
  const declaredTraceable = explicitRouteBoolean(raw?.traceable);
  const traceable = declaredTraceable !== false && Object.keys(traceQuery).length > 0;
  const egress = raw?.egress_interface && typeof raw.egress_interface === "object"
    ? raw.egress_interface : { name: raw?.egress_interface ?? raw?.interface ?? raw?.outgoing_interface };
  const nextHops = firstArray(raw?.next_hops, raw?.nexthops, raw?.next_hop_group?.members).map((item, nextHopIndex) => {
    const hop = typeof item === "object" ? item : { value: item };
    return {
      ...hop,
      next_hop_id: String(hop?.next_hop_id ?? hop?.id ?? `next-hop-${nextHopIndex + 1}`),
      value: routeDisplayValue(hop, "unresolved"),
      egress: routeDisplayValue(hop?.egress_interface ?? hop?.egress_interface_resource_id ?? hop?.interface, ""),
      activity: explicitRouteActivity(hop),
      selection: explicitRouteSelection(hop),
      active: explicitRouteBoolean(hop?.active),
      backup: explicitRouteBoolean(hop?.backup, hop?.standby),
    };
  });
  if (!nextHops.length && raw?.next_hop !== undefined) {
    nextHops.push({
      next_hop_id: `${entryId}:next-hop`,
      value: routeDisplayValue(raw.next_hop, "unresolved"),
      egress: routeDisplayValue(egress, ""),
      activity: "unknown",
      selection: "unknown",
      active: null,
      backup: null,
    });
  }
  const provenance = raw?.plugin_provenance && typeof raw.plugin_provenance === "object"
    ? raw.plugin_provenance : raw?.provenance && typeof raw.provenance === "object" ? raw.provenance : {};
  const prefix = String(raw?.prefix ?? destination?.value ?? destination?.prefix ?? raw?.destination_prefix
    ?? (typeof raw?.destination === "string" ? raw.destination : "unknown destination"));
  const source = raw?.source && typeof raw.source === "object" ? raw.source : { value: raw?.source };
  return {
    ...raw,
    route_entry_id: entryId,
    route_entry_ref: entryRef,
    route_entry_ref_key: routeEntryRefKey(entryRef, entryId),
    node_id: String(raw?.node_id ?? raw?.device_id ?? source?.node_id ?? "unknown-node"),
    member_id: String(raw?.member_id ?? raw?.topology_member_id ?? ""),
    vrf_id: String(raw?.vrf_id ?? raw?.routing_instance_id ?? raw?.vrf ?? "default"),
    vrf: String(raw?.vrf ?? raw?.vrf_name ?? raw?.vrf_id ?? "default"),
    address_family: String(raw?.address_family ?? raw?.afi ?? "unknown"),
    route_family: String(raw?.route_family ?? raw?.family ?? raw?.address_family ?? "unknown"),
    route_type: String(raw?.route_type ?? raw?.type ?? raw?.route_family ?? "unknown"),
    prefix,
    destination: {
      ...destination,
      destination_id: String(destination?.destination_id ?? raw?.destination_id ?? ""),
      value: String(destination?.value ?? destination?.prefix ?? prefix),
    },
    source,
    source_label: routeDisplayValue(source, raw?.protocol ? String(raw.protocol) : "unknown source"),
    protocol: String(raw?.protocol ?? source?.protocol ?? source?.kind ?? raw?.source_protocol ?? "unknown"),
    next_hops: nextHops,
    forwarding_actions: normalizeRouteForwardingActions(raw),
    egress_interface: {
      ...egress,
      resource_id: String(egress?.resource_id ?? egress?.egress_interface_resource_id ?? raw?.egress_interface_resource_id ?? ""),
      name: routeDisplayValue(egress, "unresolved"),
    },
    metric: raw?.metric ?? raw?.cost ?? null,
    preference: raw?.preference ?? raw?.distance ?? raw?.admin_distance ?? null,
    installed: explicitRouteBoolean(raw?.installed, raw?.programmed),
    selected: explicitRouteBoolean(raw?.selected),
    active: explicitRouteBoolean(raw?.active),
    backup: explicitRouteBoolean(raw?.backup, raw?.standby),
    activity: explicitRouteActivity(raw),
    selection: explicitRouteSelection(raw),
    disposition: explicitRouteDisposition(raw),
    completeness: explicitRouteCompleteness(raw),
    consistency: explicitRouteConsistency(raw),
    forwarding_capable: explicitRouteBoolean(raw?.forwarding_capable),
    status: String(raw?.status ?? raw?.install_status ?? raw?.state ?? "unknown"),
    traceable,
    trace_query: traceQuery,
    plugin_provenance: provenance,
    plugin_details: raw?.plugin_details && typeof raw.plugin_details === "object" ? raw.plugin_details
      : raw?.attributes && typeof raw.attributes === "object" ? raw.attributes : {},
  };
}

function normalizeRouteTableSnapshot(raw, source = "context-query") {
  const items = routeTableItems(raw).slice(0, MAX_ROUTE_TABLE_ROWS).map(normalizeRouteTableEntry);
  const summaries = firstArray(raw?.node_summaries, raw?.nodes, raw?.route_tables?.nodes);
  const nodesById = new Map(selectedResultNodes().map((node) => [node.node_id, node]));
  for (const node of state.capabilities?.nodes || []) if (!nodesById.has(node.node_id)) nodesById.set(node.node_id, node);
  const groupsByNode = new Map();
  const ensureGroup = (nodeId, memberId = "") => {
    const id = String(nodeId || "unknown-node");
    if (!groupsByNode.has(id)) {
      const node = nodesById.get(id);
      const summary = summaries.find((item) => String(item?.node_id ?? item?.device_id ?? "") === id
        || (memberId && String(item?.member_id ?? item?.topology_member_id ?? "") === String(memberId))) || {};
      const summaryBasis = summary?.resolved_basis ?? summary?.basis
        ?? (summary?.resolved_time && typeof summary.resolved_time === "object" ? summary.resolved_time
          : summary?.resolved_time !== undefined ? { resolved_time_ns: summary.resolved_time } : node?.resolved_basis ?? {});
      groupsByNode.set(id, {
        ...summary,
        node_id: id,
        member_id: String(summary?.member_id ?? memberId ?? node?.member_id ?? ""),
        label: String(summary?.label ?? summary?.display_name ?? node?.label ?? id),
        resolved_basis: {
          ...(typeof summaryBasis === "object" ? summaryBasis : { resolved_time_ns: summaryBasis }),
          uncertainty_ns: summary?.uncertainty_ns ?? summary?.clock_uncertainty_ns ?? summaryBasis?.uncertainty_ns,
        },
        completeness: summary?.completeness ?? summary?.coverage
          ?? (summary?.complete !== undefined ? { status: summary.complete ? "complete" : "incomplete" } : node?.coverage ?? {}),
        entry_count: Number(summary?.entry_count ?? summary?.total ?? 0),
        returned_count: Number(summary?.returned_count ?? summary?.count ?? 0),
        plugin_provenance: summary?.plugin_provenance ?? summary?.provenance ?? {},
        entries: [],
      });
    }
    return groupsByNode.get(id);
  };
  for (const summary of summaries) ensureGroup(summary?.node_id ?? summary?.device_id, summary?.member_id ?? summary?.topology_member_id);
  for (const item of items) ensureGroup(item.node_id, item.member_id).entries.push(item);
  const nodeOrder = new Map([...nodesById.keys()].map((nodeId, index) => [nodeId, index]));
  const groups = [...groupsByNode.values()].sort((left, right) =>
    (nodeOrder.get(left.node_id) ?? Number.MAX_SAFE_INTEGER) - (nodeOrder.get(right.node_id) ?? Number.MAX_SAFE_INTEGER)
      || left.label.localeCompare(right.label)
  );
  return {
    ...raw,
    items,
    groups,
    source,
    route_table_context_id: String(raw?.route_table_context_id ?? raw?.context_id ?? ""),
    topology_context_id: String(raw?.topology_context_id ?? state.query?.context_id ?? ""),
    resolved_basis: raw?.resolved_basis ?? raw?.basis ?? state.query?.resolved_basis ?? {},
    counts: raw?.counts ?? { entries: items.length, nodes: groups.length },
    page: raw?.page ?? raw?.pagination ?? {},
    completeness: raw?.completeness ?? raw?.coverage ?? {},
  };
}

function routeEndpointRef(raw, side, nodes) {
  const direct = side === "source"
    ? raw?.source_ref ?? raw?.from_ref ?? raw?.source ?? raw?.from ?? raw?.ingress
    : raw?.target_ref ?? raw?.to_ref ?? raw?.target ?? raw?.to ?? raw?.egress;
  const memberIds = firstArray(raw?.member_ids).map(String);
  const nodeIds = firstArray(raw?.node_ids).map(String);
  const memberId = side === "source"
    ? raw?.source_member_id ?? raw?.from_member_id ?? raw?.ingress_member_id
    : raw?.target_member_id ?? raw?.to_member_id ?? raw?.egress_member_id;
  const nodeId = side === "source"
    ? raw?.source_node_id ?? raw?.from_node_id ?? raw?.ingress_node_id
    : raw?.target_node_id ?? raw?.to_node_id ?? raw?.egress_node_id;
  const resourceId = side === "source"
    ? raw?.source_resource_id ?? raw?.from_resource_id ?? raw?.ingress_resource_id
    : raw?.target_resource_id ?? raw?.to_resource_id ?? raw?.egress_resource_id;
  const arrayMemberId = side === "source" ? memberIds[0] : memberIds[1] ?? memberIds[0];
  const arrayNodeId = side === "source" ? nodeIds[0] : nodeIds[1] ?? nodeIds[0];
  const resolvedMemberId = memberId ?? arrayMemberId ?? raw?.member_id;
  const resolvedNodeId = nodeId ?? arrayNodeId ?? raw?.node_id;
  const value = direct && typeof direct === "object"
    ? direct
    : { member_id: resolvedMemberId, node_id: resolvedNodeId || (typeof direct === "string" ? direct : null), resource_id: resourceId };
  const fallback = nodes.find((node) => (resolvedMemberId && node.member_id === String(resolvedMemberId)) || (resolvedNodeId && node.node_id === String(resolvedNodeId)));
  return refIdentity(value, fallback);
}

function refRouteTokens(ref) {
  const tokens = [];
  if (ref?.member_id && ref.member_id !== "unknown-member") tokens.push(`member:${ref.member_id}`);
  if (ref?.node_id && ref.node_id !== "unknown-node") tokens.push(`node:${ref.node_id}`);
  if (ref?.resource_id) {
    tokens.push(`resource:${ref.resource_id}`);
    if (ref?.member_id) tokens.push(`resource:${ref.member_id}:${ref.resource_id}`);
  }
  return tokens;
}

function routeTokensFor(raw, segment = null) {
  const tokens = new Set(segment?.component_tokens || []);
  const linkId = raw?.topology_link_id ?? raw?.link_id ?? raw?.edge_id ?? raw?.relationship_id;
  const networkSegmentId = raw?.network_segment_id ?? raw?.connectivity_domain_id ?? raw?.network_id;
  const networkAttachmentIds = firstArray(
    raw?.network_segment_attachment_ids,
    raw?.connectivity_attachment_ids,
  ).map(String);
  const segmentId = raw?.segment_id ?? raw?.hop_id;
  const memberId = raw?.member_id ?? raw?.topology_member_id;
  const nodeId = raw?.node_id ?? raw?.device_id;
  const resourceId = raw?.resource_id ?? raw?.local_resource_id;
  if (linkId) tokens.add(`link:${linkId}`);
  if (networkSegmentId) tokens.add(`network-segment:${networkSegmentId}`);
  for (const attachmentId of networkAttachmentIds) tokens.add(`network-attachment:${attachmentId}`);
  if (segmentId) tokens.add(`segment:${segmentId}`);
  if (memberId) tokens.add(`member:${memberId}`);
  if (nodeId) tokens.add(`node:${nodeId}`);
  if (resourceId) {
    tokens.add(`resource:${resourceId}`);
    if (memberId) tokens.add(`resource:${memberId}:${resourceId}`);
  }
  for (const targetId of firstArray(raw?.interaction_target_ids, raw?.target_ids)) tokens.add(`target:${targetId}`);
  const refs = firstArray(raw?.component_refs, raw?.components, raw?.resource_refs, raw?.related_components);
  for (const ref of refs) refRouteTokens(refIdentity(ref)).forEach((token) => tokens.add(token));
  return [...tokens];
}

function normalizeRouteSegment(raw, index, nodes) {
  const source = routeEndpointRef(raw, "source", nodes);
  const target = routeEndpointRef(raw, "target", nodes);
  const segmentId = String(raw?.segment_id ?? raw?.hop_id ?? raw?.id ?? `segment-${index + 1}`);
  const topologyLinkId = raw?.topology_link_id ?? raw?.link_id ?? raw?.edge_id ?? raw?.relationship_id ?? null;
  const networkSegmentId = raw?.network_segment_id ?? raw?.connectivity_domain_id ?? raw?.network_id ?? null;
  const stateValue = raw?.state;
  const status = String(raw?.status ?? raw?.resolution_status ?? stateValue?.operational ?? stateValue?.status ?? stateValue?.state
    ?? (typeof stateValue === "string" ? stateValue : "unknown"));
  const role = firstRouteEnum(raw?.role, raw?.path_role, raw?.forwarding_role)
    || (raw?.primary === true ? "primary" : firstRouteEnum(raw?.alternative_state))
    || "unknown";
  const activity = explicitRouteActivity(raw);
  const selection = explicitRouteSelection(raw);
  const completeness = explicitRouteCompleteness(raw);
  const consistency = explicitRouteConsistency(raw);
  const disposition = explicitRouteDisposition(raw);
  const inferredFlag = explicitRouteBoolean(raw?.inferred, raw?.inference, raw?.best_effort);
  const unresolvedFlag = explicitRouteBoolean(raw?.unresolved);
  const inferred = inferredFlag !== null ? inferredFlag : routeCompletenessIsInferred(completeness) ? true : null;
  const unresolved = unresolvedFlag !== null ? unresolvedFlag : routeCompletenessIsUnresolved(completeness) ? true : null;
  const inconsistentFlag = explicitRouteBoolean(raw?.inconsistent);
  const consistentFlag = explicitRouteBoolean(raw?.consistent, raw?.consistency?.consistent);
  const inconsistent = inconsistentFlag !== null
    ? inconsistentFlag
    : consistentFlag !== null ? !consistentFlag
      : ROUTE_INCONSISTENT_STATES.has(consistency) ? true
        : ROUTE_CONSISTENT_STATES.has(consistency) ? false : null;
  const segment = {
    ...raw,
    segment_id: segmentId,
    topology_link_id: topologyLinkId ? String(topologyLinkId) : null,
    network_segment_id: networkSegmentId ? String(networkSegmentId) : null,
    network_segment_attachment_ids: firstArray(
      raw?.network_segment_attachment_ids,
      raw?.connectivity_attachment_ids,
    ).map(String),
    source,
    target,
    status,
    role,
    activity,
    selection,
    completeness,
    consistency,
    disposition,
    node_occurrence_id: String(raw?.node_occurrence_id ?? raw?.occurrence_id ?? ""),
    source_occurrence_id: String(raw?.source_occurrence_id
      ?? raw?.from_occurrence_id
      ?? raw?.source?.occurrence_id
      ?? raw?.source_ref?.occurrence_id
      ?? ""),
    target_occurrence_id: String(raw?.target_occurrence_id
      ?? raw?.to_occurrence_id
      ?? raw?.target?.occurrence_id
      ?? raw?.target_ref?.occurrence_id
      ?? ""),
    policy_decision_refs: firstArray(
      raw?.policy_decision_refs,
      raw?.policy_decision_ids,
    ).map(String),
    forwarding_capable: explicitRouteBoolean(raw?.forwarding_capable, stateValue?.forwarding_capable),
    inferred,
    unresolved,
    inconsistent,
  };
  const explicitHighlightTargets = firstArray(
    raw?.highlight_target_ids,
    raw?.route_resolution?.highlight_target_ids,
  ).map(String);
  const localMemberId = source.member_id === target.member_id ? source.member_id : null;
  segment.highlight_target_ids = explicitHighlightTargets.length
    ? explicitHighlightTargets
    : [segment.topology_link_id ? `link:${segment.topology_link_id}`
      : segment.network_segment_id ? `network-segment:${segment.network_segment_id}`
      : localMemberId && localMemberId !== "unknown-member" ? `node-member:${localMemberId}`
        : `route-segment:${segmentId}`];
  const resourceTokens = firstArray(raw?.resource_refs).flatMap((ref) => refRouteTokens(refIdentity(ref)));
  segment.component_tokens = [
    `segment:${segmentId}`,
    ...(segment.topology_link_id ? [`link:${segment.topology_link_id}`] : []),
    ...(segment.network_segment_id ? [`network-segment:${segment.network_segment_id}`] : []),
    ...segment.network_segment_attachment_ids.map((attachmentId) => `network-attachment:${attachmentId}`),
    ...refRouteTokens(source),
    ...refRouteTokens(target),
    ...resourceTokens,
    ...firstArray(raw?.interaction_target_ids).map((targetId) => `target:${targetId}`),
  ];
  return segment;
}

function sameRouteRef(left, right) {
  return Boolean(
    (left?.member_id && right?.member_id && left.member_id === right.member_id)
    || (left?.node_id && right?.node_id && left.node_id === right.node_id)
  );
}

function normalizedRouteOccurrences(raw, pathId, segments, nodes) {
  const declared = firstArray(raw?.node_occurrences, raw?.hop_occurrences, raw?.occurrences)
    .map((occurrence, index) => {
      const item = occurrence && typeof occurrence === "object"
        ? occurrence
        : { node_id: String(occurrence ?? "") };
      const refSource = item.ref ?? item.node_ref ?? item.endpoint_ref ?? item;
      const fallback = findNodeForRef(refIdentity(refSource), nodes);
      return {
        ...item,
        occurrence_id: String(item.occurrence_id ?? item.hop_occurrence_id ?? item.id
          ?? `${pathId}:occurrence:${index + 1}`),
        occurrence_index: Math.max(0, Number(item.ordinal ?? item.occurrence_index ?? index + 1) - 1),
        ref: refIdentity(refSource, fallback),
      };
    });

  if (declared.length) {
    let cursor = 0;
    for (const segment of segments) {
      if (segment.node_occurrence_id) {
        segment.source_occurrence_id ||= segment.node_occurrence_id;
        segment.target_occurrence_id ||= segment.node_occurrence_id;
      }
      const sourceIndex = segment.source_occurrence_id
        ? declared.findIndex((item) => item.occurrence_id === segment.source_occurrence_id)
        : declared.findIndex((item, index) => index >= Math.max(0, cursor - 1)
          && sameRouteRef(item.ref, segment.source));
      const resolvedSourceIndex = sourceIndex >= 0 ? sourceIndex : cursor;
      const targetIndex = segment.target_occurrence_id
        ? declared.findIndex((item) => item.occurrence_id === segment.target_occurrence_id)
        : declared.findIndex((item, index) => index >= resolvedSourceIndex
          && sameRouteRef(item.ref, segment.target));
      if (!segment.source_occurrence_id && declared[resolvedSourceIndex]) {
        segment.source_occurrence_id = declared[resolvedSourceIndex].occurrence_id;
      }
      if (!segment.target_occurrence_id && declared[targetIndex]) {
        segment.target_occurrence_id = declared[targetIndex].occurrence_id;
      }
      cursor = targetIndex >= 0 ? targetIndex : resolvedSourceIndex;
    }
    return declared;
  }

  const occurrences = [];
  const append = (ref, occurrenceId = "") => {
    const previous = occurrences.at(-1);
    if (!occurrenceId && previous && sameRouteRef(previous.ref, ref)) return previous;
    const item = {
      occurrence_id: occurrenceId || `${pathId}:occurrence:${occurrences.length + 1}`,
      occurrence_index: occurrences.length,
      ref,
    };
    occurrences.push(item);
    return item;
  };
  for (const segment of segments) {
    const source = append(segment.source, segment.source_occurrence_id);
    segment.source_occurrence_id = source.occurrence_id;
    const target = append(segment.target, segment.target_occurrence_id);
    segment.target_occurrence_id = target.occurrence_id;
  }
  return occurrences;
}

function normalizeRoutePolicyDecision(raw, index, segments) {
  const item = raw && typeof raw === "object" ? raw : { reason: String(raw ?? "") };
  const decisionId = String(item.decision_id ?? item.policy_decision_id ?? item.id
    ?? `policy-decision-${index + 1}`);
  const segmentId = String(item.segment_id ?? item.blocked_segment_id ?? "");
  const segment = segments.find((candidate) => candidate.segment_id === segmentId) || null;
  const reason = firstRouteEnum(
    item.reason,
    item.reason_code,
    item.policy_reason,
    item.terminal_reason,
  ) || "policy_blocked";
  const result = firstRouteEnum(
    item.result,
    item.core_verdict,
    item.outcome,
    item.decision,
    item.disposition,
  )
    || "policy_blocked";
  const policyCategory = firstDeclaredString(
    item.policy_category,
    item.category,
    item.policy_kind,
    "policy",
  );
  const label = firstDeclaredString(
    item.label,
    item.title,
    "Forwarding policy blocked this candidate",
  );
  const text = firstDeclaredString(
    item.text,
    item.label,
    item.title,
    "Forwarding policy blocked this candidate.",
  );
  const scopeTokens = firstArray(item.scope_refs, item.policy_scope_refs).map((scope) =>
    `policy-scope:${scope?.scope_type ?? scope?.kind ?? "scope"}:${scope?.scope_id ?? scope?.id ?? scope}`
  );
  return {
    ...item,
    decision_id: decisionId,
    segment_id: segmentId || segment?.segment_id || null,
    result,
    reason,
    policy_category: policyCategory,
    label,
    detail: String(item.detail ?? item.description ?? item.explanation ?? ""),
    step_id: String(item.step_id ?? decisionId),
    text,
    status: result,
    parts: [],
    component_tokens: [
      `policy-decision:${decisionId}`,
      ...(item.constraint_id ? [`policy-constraint:${item.constraint_id}`] : []),
      ...scopeTokens,
      ...routeTokensFor(item, segment),
    ],
    highlight_target_ids: firstArray(item.highlight_target_ids, segment?.highlight_target_ids).map(String),
    provided_by: item.provided_by ?? item.plugin_provenance ?? null,
  };
}

function normalizeRoutePresentationLayer(raw, index, pathId) {
  const item = raw && typeof raw === "object" ? raw : { label: String(raw ?? "") };
  const presentationId = String(item.presentation_id ?? item.layer_id ?? item.id
    ?? `presentation:${pathId}:${index + 1}`);
  const role = String(item.role ?? item.presentation_role ?? "annotation");
  const style = ["path", "band", "badge", "callout"].includes(String(item.style))
    ? String(item.style)
    : null;
  const styleRoles = {
    path: "outer-forwarding",
    band: "service-overlay",
    badge: "annotation",
    callout: "callout",
  };
  const topologyReferences = firstArray(item.topology_references);
  const contractEndpointRefs = topologyReferences.flatMap((reference) => {
    const target = reference?.resource ?? reference?.match?.arguments;
    return target?.node_id || target?.member_id ? [refIdentity(target)] : [];
  });
  const endpointRefs = firstArray(item.endpoint_refs, item.node_refs, contractEndpointRefs)
    .map((ref) => refIdentity(ref));
  const rawFacts = item.facts;
  const facts = Array.isArray(rawFacts)
    ? rawFacts
    : rawFacts && typeof rawFacts === "object"
      ? Object.entries(rawFacts).map(([key, value]) => ({ label: titleCase(key), value }))
      : [];
  return {
    ...item,
    presentation_id: presentationId,
    group_id: String(item.group_id ?? presentationId),
    role,
    scope: String(item.scope ?? "path"),
    label: String(item.label ?? item.display_name ?? `Context ${index + 1}`),
    detail: String(item.detail ?? item.description ?? ""),
    style: style ?? "badge",
    style_role: String(style ? styleRoles[style] : item.style_role ?? "context"),
    geometry_role: String(item.geometry_role ?? "context"),
    participates_in_forwarding_geometry: item.participates_in_forwarding_geometry === true,
    semantic_owner: String(item.semantic_owner ?? "plugin"),
    topology_references: topologyReferences,
    anchor_resources: firstArray(item.anchor_resources).map((ref) => refIdentity(ref)),
    endpoint_refs: endpointRefs,
    path_ids: firstArray(item.path_ids).length ? firstArray(item.path_ids).map(String) : [String(pathId)],
    segment_ids: firstArray(item.segment_ids).map(String),
    topology_link_ids: firstArray(item.topology_link_ids).map(String),
    topology_targets: firstArray(item.topology_targets),
    interaction_target_ids: firstArray(item.interaction_target_ids).map(String),
    facts,
    status: String(item.status ?? "unknown"),
  };
}

function routePresentationLayers(path, role = null) {
  const layers = firstArray(path?.presentations);
  return role === null ? layers : layers.filter((layer) => layer.role === role);
}

function routeForwardingSegments(path) {
  return firstArray(path?.segments).filter((segment) => {
    const role = String(segment?.geometry_role ?? segment?.presentation_role ?? "forwarding");
    return segment?.participates_in_forwarding_geometry !== false
      && !["context", "overlay", "annotation"].includes(role);
  });
}

function routeResolutionSource(raw) {
  if (Array.isArray(raw?.route_resolution_sequence)) return raw.route_resolution_sequence;
  if (Array.isArray(raw?.route_resolution)) return raw.route_resolution;
  if (Array.isArray(raw?.route_resolution?.steps)) return raw.route_resolution.steps;
  return firstArray(raw?.route_resolution_steps, raw?.resolution_steps, raw?.steps);
}

function normalizeRouteStep(raw, index, segments) {
  const step = typeof raw === "object" ? raw : { text: String(raw) };
  const resolution = step?.route_resolution && typeof step.route_resolution === "object" ? step.route_resolution : {};
  const segmentId = String(step?.segment_id ?? step?.hop_id ?? "");
  const segmentIndex = Number(step?.segment_index ?? step?.hop_index ?? index);
  const segment = segments.find((item) => item.segment_id === segmentId) || segments[segmentIndex] || null;
  const text = step?.text ?? resolution?.text ?? step?.route_resolution_text ?? step?.message ?? step?.description
    ?? segment?.route_resolution?.text ?? segment?.route_resolution_text
    ?? `${nodeLabelForRef(segment?.source)} resolves toward ${nodeLabelForRef(segment?.target)}.`;
  const parts = firstArray(step?.parts, resolution?.parts, step?.text_parts).map((part, partIndex) => ({
    ...(typeof part === "object" ? part : { text: String(part) }),
    part_id: String(part?.part_id ?? part?.id ?? `part-${partIndex + 1}`),
    text: String(part?.text ?? part?.label ?? part),
    component_tokens: routeTokensFor(typeof part === "object" ? part : {}, segment),
    highlight_target_ids: firstArray(
      part?.highlight_target_ids,
      resolution?.highlight_target_ids,
      step?.highlight_target_ids,
      segment?.highlight_target_ids,
    ).map(String),
  }));
  const componentTokens = new Set([
    ...routeTokensFor(step, segment),
    ...routeTokensFor(resolution, segment),
  ]);
  return {
    ...step,
    step_id: String(step?.step_id ?? step?.id ?? `step-${index + 1}`),
    segment_id: segment?.segment_id || segmentId || null,
    text: String(text),
    detail: String(step?.detail ?? resolution?.detail ?? step?.explanation ?? step?.evidence ?? ""),
    status: String(step?.status ?? segment?.status ?? "unknown"),
    component_tokens: [...componentTokens],
    highlight_target_ids: firstArray(
      step?.highlight_target_ids,
      resolution?.highlight_target_ids,
      segment?.highlight_target_ids,
    ).map(String),
    parts,
    provided_by: step?.provided_by ?? resolution?.provided_by ?? null,
    text_source: step?.text_source ?? resolution?.text_source ?? null,
    inferred: explicitRouteBoolean(step?.inferred, resolution?.inferred, segment?.inferred),
    unresolved: explicitRouteBoolean(step?.unresolved, resolution?.unresolved, segment?.unresolved),
    inconsistent: explicitRouteBoolean(step?.inconsistent, resolution?.inconsistent, segment?.inconsistent),
  };
}

function normalizedPacketNumber(value) {
  if (value === null || value === undefined || value === "") return null;
  const numeric = Number(value);
  return Number.isFinite(numeric) && numeric >= 0 ? numeric : null;
}

function normalizePacketFields(raw) {
  const entries = Array.isArray(raw)
    ? raw.filter((entry) => Array.isArray(entry) && entry.length >= 2)
    : raw && typeof raw === "object" ? Object.entries(raw) : [];
  return entries.map(([name, value]) => ({
    name: String(name),
    value,
  }));
}

function normalizePacketLayer(raw, index, stateId) {
  const layer = raw && typeof raw === "object" ? raw : {};
  const layerId = String(layer.layer_id ?? layer.id ?? `${stateId}:layer:${index + 1}`);
  const contractId = String(layer.contract_id ?? "unknown");
  const complete = explicitRouteBoolean(layer.complete);
  return {
    ...layer,
    layer_id: layerId,
    contract_id: contractId,
    label: String(layer.label ?? layer.display_name ?? contractId),
    fields: normalizePacketFields(layer.fields),
    size_bytes: normalizedPacketNumber(layer.size_bytes),
    complete: complete === null ? false : complete,
  };
}

function normalizePacketSize(raw) {
  if (!raw || typeof raw !== "object") return null;
  const complete = explicitRouteBoolean(raw.complete);
  return {
    ...raw,
    basis_contract_id: String(raw.basis_contract_id ?? "unknown"),
    size_bytes: normalizedPacketNumber(raw.size_bytes),
    complete: complete === null ? false : complete,
  };
}

function normalizePacketState(raw, stateId) {
  const packet = raw && typeof raw === "object" ? raw : {};
  const complete = explicitRouteBoolean(packet.complete);
  return {
    ...packet,
    layers: firstArray(packet.layers).slice(0, MAX_PACKET_LAYERS)
      .map((layer, index) => normalizePacketLayer(layer, index, stateId)),
    size: normalizePacketSize(packet.size),
    complete: complete === null ? false : complete,
  };
}

function normalizePacketContribution(raw, index) {
  const contribution = raw && typeof raw === "object" ? raw : { text: String(raw ?? "") };
  return {
    ...contribution,
    contribution_id: String(contribution.contribution_id ?? contribution.id ?? `contribution-${index + 1}`),
    phase: String(contribution.phase ?? "resolution"),
    text: String(contribution.text ?? contribution.description ?? contribution.message ?? ""),
    quality: String(contribution.quality ?? "unknown"),
    resource_references: firstArray(contribution.resource_references, contribution.resource_refs),
    topology_references: firstArray(contribution.topology_references),
    evidence: firstArray(contribution.evidence),
  };
}

function packetResourceReferenceTokens(raw) {
  const resource = raw?.resource ?? raw?.resource_ref ?? raw;
  if (!resource || typeof resource !== "object") return [];
  const typedResourceKey = resource.namespace && resource.node
    && resource.layer && resource.kind;
  const tokens = new Set(
    typedResourceKey ? [] : refRouteTokens(refIdentity(resource))
  );
  const nodeId = resource.node ?? resource.node_id;
  if (nodeId) tokens.add(`node:${nodeId}`);
  return [...tokens];
}

function packetTopologyReferenceTokens(raw) {
  const reference = raw && typeof raw === "object" ? raw : {};
  if (reference.resource) return packetResourceReferenceTokens(reference.resource);
  return firstArray(reference.match?.resolved_candidates)
    .flatMap(packetResourceReferenceTokens);
}

function packetTransitionRef(pathId, stepId, transitionId) {
  return JSON.stringify([String(pathId), String(stepId), String(transitionId)]);
}

function normalizePacketTransitionEvaluation(raw, index, pathId, steps, segments) {
  const evaluation = raw && typeof raw === "object" ? raw : {};
  const transitionRaw = evaluation.transition && typeof evaluation.transition === "object"
    ? evaluation.transition : {};
  const sourceStepId = String(transitionRaw.step_id ?? evaluation.step_id ?? `packet-step-${index + 1}`);
  const transitionId = String(transitionRaw.transition_id ?? evaluation.transition_id ?? `${sourceStepId}:transition`);
  const explicitSegmentId = String(
    evaluation.segment_id ?? transitionRaw.segment_id ?? ""
  );
  const step = steps.find((candidate) =>
    candidate.step_id === sourceStepId
    || candidate.segment_id === sourceStepId
    || (explicitSegmentId && candidate.segment_id === explicitSegmentId)
  ) || null;
  const stepId = String(step?.step_id || sourceStepId);
  const segment = segments.find((candidate) =>
    candidate.segment_id === explicitSegmentId
    || candidate.segment_id === step?.segment_id
    || candidate.segment_id === sourceStepId
  ) || null;
  const contributions = firstArray(transitionRaw.contributions, evaluation.contributions)
    .map(normalizePacketContribution);
  const contributionTokens = contributions.flatMap((contribution) =>
    [
      ...contribution.resource_references.flatMap(packetResourceReferenceTokens),
      ...contribution.topology_references.flatMap(packetTopologyReferenceTokens),
    ]
  );
  const contributionTargets = contributions.flatMap((contribution) =>
    firstArray(contribution.highlight_target_ids, contribution.interaction_target_ids).map(String)
  );
  const explicitTargets = firstArray(
    evaluation.highlight_target_ids,
    transitionRaw.highlight_target_ids,
  ).map(String);
  const componentTokens = new Set([
    ...(step?.component_tokens || []),
    ...routeTokensFor(evaluation, segment),
    ...routeTokensFor(transitionRaw, segment),
    ...contributionTokens,
    `packet-transition:${transitionId}`,
    `packet-step:${stepId}`,
    ...(sourceStepId === stepId ? [] : [`packet-step:${sourceStepId}`]),
  ]);
  const diffRaw = evaluation.diff && typeof evaluation.diff === "object" ? evaluation.diff : {};
  const mtuRaw = evaluation.mtu && typeof evaluation.mtu === "object" ? evaluation.mtu : {};
  const mtuConstraintRaw = transitionRaw.mtu_constraint
    && typeof transitionRaw.mtu_constraint === "object"
    ? transitionRaw.mtu_constraint : null;
  const transition = {
    ...transitionRaw,
    transition_id: transitionId,
    step_id: stepId,
    before: normalizePacketState(transitionRaw.before, `${transitionId}:before`),
    after: normalizePacketState(transitionRaw.after, `${transitionId}:after`),
    action_contract_id: String(transitionRaw.action_contract_id ?? "unknown"),
    action_label: String(transitionRaw.action_label ?? "Packet transition"),
    disposition: firstRouteEnum(transitionRaw.disposition) || "unknown",
    origin: firstRouteEnum(transitionRaw.origin) || "unknown",
    actor_id: String(transitionRaw.actor_id ?? "unknown"),
    forced_rule_id: transitionRaw.forced_rule_id === null || transitionRaw.forced_rule_id === undefined
      ? null : String(transitionRaw.forced_rule_id),
    mtu_constraint: mtuConstraintRaw ? {
      ...mtuConstraintRaw,
      basis_contract_id: String(mtuConstraintRaw.basis_contract_id ?? "unknown"),
      limit_bytes: normalizedPacketNumber(mtuConstraintRaw.limit_bytes),
      complete: explicitRouteBoolean(mtuConstraintRaw.complete) === true,
      resource: mtuConstraintRaw.resource && typeof mtuConstraintRaw.resource === "object"
        ? mtuConstraintRaw.resource : null,
    } : null,
    contributions,
  };
  return {
    ...evaluation,
    packet_ref: packetTransitionRef(pathId, stepId, transitionId),
    path_id: pathId,
    step_id: stepId,
    source_step_id: sourceStepId,
    segment_id: segment?.segment_id || explicitSegmentId || null,
    transition,
    diff: {
      ...diffRaw,
      added_layer_ids: firstArray(diffRaw.added_layer_ids).map(String),
      removed_layer_ids: firstArray(diffRaw.removed_layer_ids).map(String),
      changed_layer_ids: firstArray(diffRaw.changed_layer_ids).map(String),
      moved_layer_ids: firstArray(diffRaw.moved_layer_ids).map(String),
      complete: explicitRouteBoolean(diffRaw.complete),
    },
    mtu: {
      ...mtuRaw,
      outcome: firstRouteEnum(mtuRaw.outcome) || "not_declared",
      size_bytes: normalizedPacketNumber(mtuRaw.size_bytes),
      limit_bytes: normalizedPacketNumber(mtuRaw.limit_bytes),
      excess_bytes: normalizedPacketNumber(mtuRaw.excess_bytes),
      basis_contract_id: mtuRaw.basis_contract_id === null || mtuRaw.basis_contract_id === undefined
        ? null : String(mtuRaw.basis_contract_id),
    },
    counterfactual: explicitRouteBoolean(evaluation.counterfactual) === true
      || transition.origin === "user_forced",
    continuity_valid: explicitRouteBoolean(evaluation.continuity_valid),
    component_tokens: [...componentTokens],
    highlight_target_ids: [...new Set([
      ...explicitTargets,
      ...contributionTargets,
      ...(step?.highlight_target_ids || []),
    ])],
  };
}

function normalizePacketTrace(raw, pathId, steps, segments) {
  if (!raw || typeof raw !== "object") return null;
  const transitions = firstArray(raw.transitions).map((evaluation, index) =>
    normalizePacketTransitionEvaluation(evaluation, index, pathId, steps, segments)
  );
  for (const evaluation of transitions) {
    const step = steps.find((candidate) => candidate.step_id === evaluation.step_id);
    if (step) {
      step.packet_refs = [...new Set([...(step.packet_refs || []), evaluation.packet_ref])];
    }
    const segment = segments.find((candidate) => candidate.segment_id === evaluation.segment_id);
    if (segment) {
      segment.packet_refs = [...new Set([...(segment.packet_refs || []), evaluation.packet_ref])];
    }
  }
  const continuityComplete = explicitRouteBoolean(raw.continuity_complete);
  const counterfactual = explicitRouteBoolean(raw.counterfactual);
  return {
    ...raw,
    initial_state: normalizePacketState(raw.initial_state, `${pathId}:initial`),
    outcome: firstRouteEnum(raw.outcome) || "unknown",
    continuity_complete: continuityComplete === null ? false : continuityComplete,
    counterfactual: counterfactual === true || transitions.some((evaluation) => evaluation.counterfactual),
    transitions,
  };
}

function normalizeRoutePath(raw, index, nodes) {
  const pathId = String(raw?.path_id ?? raw?.route_id ?? raw?.id ?? `path-${index + 1}`);
  const segments = firstArray(raw?.segments, raw?.hops, raw?.edges).map((segment, segmentIndex) =>
    normalizeRouteSegment(segment, segmentIndex, nodes)
  );
  const nodeOccurrences = normalizedRouteOccurrences(raw, pathId, segments, nodes);
  const explicitSteps = routeResolutionSource(raw);
  let steps = explicitSteps.map((step, stepIndex) => normalizeRouteStep(step, stepIndex, segments));
  if (!steps.length) {
    steps = segments.flatMap((segment, segmentIndex) => {
      const resolutions = Array.isArray(segment?.route_resolution)
        ? segment.route_resolution
        : Array.isArray(segment?.route_resolution?.steps)
          ? segment.route_resolution.steps
          : [segment?.route_resolution ?? segment?.route_resolution_text ?? segment?.resolution_text].filter(Boolean);
      return (resolutions.length ? resolutions : [{}]).map((resolution, resolutionIndex) =>
        normalizeRouteStep({
          ...(typeof resolution === "object" ? resolution : { text: resolution }),
          segment_id: segment.segment_id,
          step_id: `${segment.segment_id}:${resolutionIndex + 1}`,
        }, segmentIndex, segments)
      );
    });
  }
  const alternativeState = firstRouteEnum(raw?.alternative_state);
  const role = firstRouteEnum(raw?.role, raw?.path_role, raw?.preference)
    || (raw?.primary === true ? "primary"
      : alternativeState === "selected_primary" ? "primary"
        : alternativeState === "ecmp_member" ? "ecmp"
          : alternativeState === "eligible_standby" ? "standby"
            : alternativeState ? "alternative" : "unknown");
  const activity = explicitRouteActivity(raw);
  const selection = explicitRouteSelection(raw);
  const completeness = explicitRouteCompleteness(raw);
  const consistency = explicitRouteConsistency(raw);
  const inconsistentFlag = explicitRouteBoolean(raw?.inconsistent);
  const consistentFlag = explicitRouteBoolean(raw?.consistent, raw?.consistency?.consistent);
  const segmentConsistency = segments.map((segment) => segment.inconsistent).filter((value) => value !== null);
  const inconsistent = inconsistentFlag !== null
    ? inconsistentFlag
    : consistentFlag !== null ? !consistentFlag
      : ROUTE_INCONSISTENT_STATES.has(consistency) || segmentConsistency.includes(true) ? true
        : ROUTE_CONSISTENT_STATES.has(consistency) || (segments.length > 0 && segmentConsistency.length === segments.length && segmentConsistency.every((value) => value === false)) ? false : null;
  const inferredFlag = explicitRouteBoolean(raw?.inferred);
  const inferred = inferredFlag !== null
    ? inferredFlag
    : routeCompletenessIsInferred(completeness) || segments.some((segment) => segment.inferred === true) ? true : null;
  const unresolvedFlag = explicitRouteBoolean(raw?.unresolved);
  const unresolved = unresolvedFlag !== null
    ? unresolvedFlag
    : routeCompletenessIsUnresolved(completeness) || segments.some((segment) => segment.unresolved === true) ? true : null;
  const specialResult = [
    raw?.result,
    raw?.disposition,
    raw?.outcome,
    raw?.terminal_disposition,
  ].map(normalizedRouteEnum).find((value) =>
    ROUTE_CYCLE_RESULTS.has(value) || ROUTE_POLICY_BLOCKED_RESULTS.has(value)
  );
  const result = specialResult || explicitRouteDisposition(raw);
  const eligibility = firstRouteEnum(raw?.eligibility, raw?.selection_state, raw?.selection, alternativeState) || "unknown";
  const terminalReason = String(raw?.terminal_reason ?? raw?.termination_reason
    ?? segments.findLast?.((segment) => segment?.state?.terminal)?.state?.terminal ?? "");
  const graphTargetIds = firstArray(raw?.graph_target_ids).map(String);
  const presentationLayers = firstArray(raw?.presentations)
    .map((layer, layerIndex) => normalizeRoutePresentationLayer(layer, layerIndex, pathId));
  const policyDecisions = firstArray(raw?.policy_decisions, raw?.forwarding_policy_decisions)
    .map((decision, decisionIndex) => normalizeRoutePolicyDecision(decision, decisionIndex, segments));
  const cycle = raw?.cycle && typeof raw.cycle === "object"
    ? {
      ...raw.cycle,
      first_occurrence_id: String(raw.cycle.first_occurrence_id
        ?? raw.cycle.entry_occurrence_id
        ?? raw.cycle.start_occurrence_id
        ?? ""),
      closing_occurrence_id: String(raw.cycle.closing_occurrence_id ?? raw.cycle.end_occurrence_id ?? ""),
      first_step: Number(raw.cycle.first_step ?? 0),
      closing_step: Number(raw.cycle.closing_step ?? 0),
      closing_segment_id: String(raw.cycle.closing_segment_id
        ?? raw.cycle.segment_id
        ?? ""),
    }
    : null;
  const packetTrace = normalizePacketTrace(raw?.packet_trace, pathId, steps, segments);
  return {
    ...raw,
    path_id: pathId,
    label: raw?.label || raw?.display_name || `Path ${index + 1}`,
    rank: Number(raw?.rank ?? raw?.priority ?? index + 1),
    role,
    activity,
    selection,
    completeness,
    consistency,
    inconsistent,
    inferred,
    unresolved,
    result,
    eligibility,
    forwarding_capable: explicitRouteBoolean(raw?.forwarding_capable),
    terminal_reason: terminalReason,
    cycle,
    node_occurrences: nodeOccurrences,
    policy_decisions: policyDecisions,
    graph_target_ids: graphTargetIds,
    presentations: presentationLayers,
    packet_trace: packetTrace,
    segments,
    steps,
  };
}

function normalizeRouteFinding(raw, index, paths) {
  const finding = typeof raw === "object" ? raw : { message: String(raw) };
  const pathIds = firstArray(finding?.path_ids, finding?.affected_path_ids, finding?.path_refs).map(String);
  const segment = paths.flatMap((path) => path.segments).find((item) => item.segment_id === String(finding?.segment_id ?? ""));
  return {
    ...finding,
    finding_id: String(finding?.finding_id ?? finding?.issue_id ?? finding?.id ?? `finding-${index + 1}`),
    severity: String(finding?.severity ?? finding?.status ?? finding?.level ?? "info"),
    kind: String(finding?.kind ?? finding?.type ?? finding?.category ?? "observation"),
    title: String(finding?.title ?? finding?.summary ?? titleCase(finding?.kind ?? finding?.type ?? "Route observation")),
    message: String(finding?.message ?? finding?.description ?? finding?.detail ?? finding?.summary ?? "No additional detail returned."),
    path_ids: pathIds,
    component_tokens: routeTokensFor(finding, segment),
  };
}

function normalizeRouteTrace(raw, request) {
  const nodes = selectedResultNodes();
  const pathSource = firstArray(raw?.paths, raw?.candidate_paths, raw?.routes, raw?.results?.paths).slice(0, MAX_ROUTE_PATHS);
  const paths = pathSource.map((path, index) => normalizeRoutePath(path, index, nodes))
    .sort((left, right) => left.rank - right.rank || compareLayoutIds(left.path_id, right.path_id));
  const findings = firstArray(raw?.findings, raw?.issues, raw?.consistency_findings, raw?.warnings, raw?.report?.findings)
    .map((finding, index) => normalizeRouteFinding(finding, index, paths));
  const interactionTargets = firstArray(raw?.interaction_targets, raw?.targets).map((target) => ({
    ...target,
    target_id: String(target?.target_id ?? target?.id ?? ""),
  }));
  const consistency = explicitRouteConsistency(raw);
  const traceConsistent = explicitRouteBoolean(raw?.consistent, raw?.consistency?.consistent);
  const inconsistentIssueIds = new Set([
    ...firstArray(raw?.consistency?.issue_refs, raw?.consistency_issue_refs).map(String),
    ...findings.filter((finding) => finding?.affects_consistency === true).map((finding) => finding.finding_id),
  ]);
  for (const path of paths) {
    const issueRefs = firstArray(path?.issue_refs, path?.finding_refs).map(String);
    if (issueRefs.some((issueId) => inconsistentIssueIds.has(issueId))) path.inconsistent = true;
  }
  const completeness = explicitRouteCompleteness(raw);
  return {
    ...raw,
    request: raw?.request || request,
    trace_id: String(raw?.trace_id ?? raw?.route_trace_id ?? raw?.id ?? "route-trace"),
    summary: raw?.summary || raw?.counts || {},
    completeness,
    consistency,
    inconsistent: traceConsistent === null
      ? ROUTE_INCONSISTENT_STATES.has(consistency) ? true
        : ROUTE_CONSISTENT_STATES.has(consistency) ? false : null
      : !traceConsistent,
    forwarding_capable: explicitRouteBoolean(raw?.forwarding_capable),
    paths,
    findings,
    interaction_targets: interactionTargets,
  };
}

function normalizeRouteTraceBundle(raw, request) {
  const nested = raw?.traces || raw?.directional_traces || {};
  const forwardRaw = nested?.forward ?? raw?.forward_trace ?? raw?.forward ?? null;
  const reverseRaw = nested?.reverse ?? raw?.reverse_trace ?? raw?.reverse ?? null;
  const explicitBundle = Boolean(forwardRaw || reverseRaw || raw?.trace_mode === "bidirectional" || raw?.direction === "both");
  const traces = { forward: null, reverse: null };
  if (forwardRaw) traces.forward = normalizeRouteTrace(forwardRaw, { ...request, direction: "forward" });
  if (reverseRaw) traces.reverse = normalizeRouteTrace(reverseRaw, { ...request, direction: "reverse" });
  if (!explicitBundle || (!traces.forward && !traces.reverse)) {
    const direction = ["forward", "reverse"].includes(String(raw?.direction))
      ? String(raw.direction)
      : ["forward", "reverse"].includes(String(request?.direction)) ? String(request.direction) : "forward";
    traces[direction] = normalizeRouteTrace(raw, { ...request, direction });
  }
  const symmetry = raw?.bidirectional_validation || raw?.symmetry || raw?.directional_consistency || raw?.bidirectional_summary || {};
  return {
    raw,
    trace_mode: raw?.trace_mode || (traces.forward && traces.reverse ? "bidirectional" : "single_direction"),
    pair_id: String(raw?.pair_id ?? raw?.directional_pair?.pair_id ?? raw?.bidirectional_validation?.pair_id ?? ""),
    traces,
    symmetry: {
      ...symmetry,
      state: firstRouteEnum(symmetry?.state, symmetry?.status)
        || (traces.forward && traces.reverse ? "unknown" : "not_compared"),
      one_way: explicitRouteBoolean(symmetry?.one_way, symmetry?.asymmetric_drop),
      issues: firstArray(symmetry?.issues, symmetry?.findings, symmetry?.warnings),
    },
  };
}

function topologyAssemblyId() {
  const assemblyId = state.capabilities?.assembly_id ?? state.capabilities?.topology_id;
  if (!assemblyId) throw new Error("Topology capabilities did not declare assembly_id.");
  return String(assemblyId);
}

async function discoverRouteCapabilities() {
  const assemblyId = topologyAssemblyId();
  const raw = await api(`/v1/topology-assemblies/${encodeURIComponent(assemblyId)}/routes/capabilities`);
  return normalizeRouteCapabilities(raw);
}

async function fetchRouteTablePages(endpoint, body, signal) {
  const first = await api(endpoint, { method: "POST", body: JSON.stringify(body), signal });
  const items = [...routeTableItems(first)];
  const seenCursors = new Set();
  let nextCursor = first?.page?.next_cursor ?? first?.pagination?.next_cursor ?? null;
  while (nextCursor && items.length < MAX_ROUTE_TABLE_ROWS && !seenCursors.has(nextCursor)) {
    seenCursors.add(nextCursor);
    const remaining = MAX_ROUTE_TABLE_ROWS - items.length;
    const nextBody = {
      ...body,
      page: { cursor: nextCursor, limit: Math.min(ROUTE_TABLE_QUERY_LIMIT, remaining) },
    };
    const next = await api(endpoint, { method: "POST", body: JSON.stringify(nextBody), signal });
    items.push(...routeTableItems(next));
    nextCursor = next?.page?.next_cursor ?? next?.pagination?.next_cursor ?? null;
  }
  const total = Number(first?.counts?.total ?? first?.page?.total ?? items.length);
  const truncated = Boolean(nextCursor) || items.length < total;
  return {
    ...first,
    items,
    counts: { ...(first?.counts || {}), returned: items.length, total },
    page: {
      ...(first?.page || {}),
      offset: 0,
      returned: items.length,
      total,
      truncated,
      next_cursor: nextCursor,
    },
    completeness: {
      ...(first?.completeness || {}),
      complete: Boolean(first?.completeness?.topology_complete ?? first?.completeness?.complete) && !truncated,
      rows_truncated: truncated,
    },
  };
}

async function queryRouteTables(query, signal) {
  if (!state.routeCapabilities || !query?.request) throw new Error("Reconstruct the topology before reading route tables.");
  const assemblyId = topologyAssemblyId();
  const advertised = state.routeCapabilities.route_table_query_href;
  const endpoints = [...new Set([
    advertised,
    `/v1/topology-assemblies/${encodeURIComponent(assemblyId)}/routes/tables/query`,
    "/v1/topologies/routes/tables/query",
  ].filter(Boolean))];
  const nodeQueries = firstArray(query.request.node_queries);
  const body = {
    topology_context_id: query.context_id || null,
    basis: query.request.basis,
    clock_policy: query.request.clock_policy,
    filters: {},
    page: { offset: 0, limit: ROUTE_TABLE_QUERY_LIMIT },
    include_plugin_details: true,
  };
  if (nodeQueries.length) body.node_queries = nodeQueries;
  else body.node_ids = query.nodes.map((node) => node.node_id);
  const failures = [];
  for (const endpoint of endpoints) {
    try {
      const raw = await fetchRouteTablePages(endpoint, body, signal);
      return normalizeRouteTableSnapshot(raw, "context-query");
    } catch (error) {
      if (isAbortError(error)) throw error;
      failures.push(`${endpoint}: ${error.message}`);
    }
  }
  const embeddedItems = routeTableItems(state.routeCapabilities);
  if (embeddedItems.length) return normalizeRouteTableSnapshot(state.routeCapabilities, "capability-fallback");
  throw new Error(failures.join("; ") || "No route-table query endpoint was advertised.");
}

async function loadRouteTables(query, generation, signal) {
  state.routeTablePending = true;
  state.routeTableError = "";
  state.routeTableSnapshot = null;
  state.routeTableSource = "";
  state.routeTablesInitialized = false;
  state.routeTableOpenNodes.clear();
  state.focusedRouteEntryId = "";
  state.focusedRouteEntryRef = null;
  renderRouteTables();
  try {
    const snapshot = await queryRouteTables(query, signal);
    if (generation !== state.topologyRequestGeneration) return;
    state.routeTableSnapshot = snapshot;
    state.routeTableSource = state.routeTableSnapshot.source;
  } catch (error) {
    if (isAbortError(error) || generation !== state.topologyRequestGeneration) return;
    state.routeTableError = error.message;
  } finally {
    if (generation !== state.topologyRequestGeneration) return;
    state.routeTablePending = false;
    renderRouteTables();
  }
}

async function discoverCapabilities() {
  const revisionId = new URLSearchParams(location.search).get("revision_id") || state.bootstrap?.workspace?.revision_id || "";
  const routes = [
    { path: `/v1/topologies/capabilities${revisionId ? `?revision_id=${encodeURIComponent(revisionId)}` : ""}`, mode: "global-api" },
    ...(revisionId ? [{ path: `/v1/revisions/${encodeURIComponent(revisionId)}/multi-node/capabilities`, mode: "revision-alias" }] : []),
  ];
  const failures = [];
  for (const route of routes) {
    try {
      return normalizeCapabilities(await api(route.path), route.mode);
    } catch (error) {
      failures.push(`${route.path}: ${error.message}`);
    }
  }
  throw new Error(failures.join("; "));
}

async function reconstruct(request, signal) {
  const revisionId = state.bootstrap?.workspace?.revision_id || request?.node_queries?.[0]?.revision_id || "";
  const routes = state.capabilities.source_mode === "global-api"
    ? [
      { path: "/v1/topologies/reconstruct", body: request, mode: "global-api" },
      ...(revisionId ? [{ path: `/v1/revisions/${encodeURIComponent(revisionId)}/multi-node/query`, body: request, mode: "revision-alias" }] : []),
    ]
    : state.capabilities.source_mode === "revision-alias"
      ? [
        { path: `/v1/revisions/${encodeURIComponent(revisionId)}/multi-node/query`, body: request, mode: "revision-alias" },
        { path: "/v1/topologies/reconstruct", body: request, mode: "global-api" },
      ]
      : [];
  const failures = [];
  for (const route of routes) {
    try {
      const raw = await api(route.path, { method: "POST", body: JSON.stringify(route.body), signal });
      return normalizeQuery(raw, request, route.mode);
    } catch (error) {
      if (isAbortError(error)) throw error;
      failures.push(`${route.path}: ${error.message}`);
    }
  }
  throw new Error(failures.join("; ") || "No multi-node topology reconstruction endpoint was advertised.");
}

function selectedRouteScenario() {
  const scenarioId = byId("mn-route-scenario")?.value;
  return state.routeCapabilities?.scenarios.find((scenario) => scenario.scenario_id === scenarioId)
    || state.routeCapabilities?.scenarios[0]
    || null;
}

function directionalPairForScenario(scenario = selectedRouteScenario()) {
  if (!scenario) return null;
  return state.routeCapabilities?.directional_pairs.find((pair) =>
    pair.scenario_id === scenario.scenario_id || (scenario.pair_id && pair.pair_id === scenario.pair_id)
  ) || null;
}

function routeEndpointDescriptor(kind) {
  return {
    input: byId(kind === "source" ? "mn-route-source" : "mn-route-destination"),
    values: kind === "source" ? state.routeCapabilities?.sources || [] : state.routeCapabilities?.destinations || [],
    idField: kind === "source" ? "source_id" : "destination_id",
  };
}

function routeEndpointMatch(kind, rawValue) {
  const value = String(rawValue ?? "");
  const { values, idField } = routeEndpointDescriptor(kind);
  const canonical = values.find((item) =>
    item[idField] === value || item.endpoint_id === value
  );
  if (canonical) return canonical;
  const displayMatches = values.filter((item) => routeEndpointDisplayValue(kind, item) === value);
  if (displayMatches.length === 1) return displayMatches[0];
  const matches = values.filter((item) => item.value === value || item.label === value);
  return matches.length === 1 ? matches[0] : null;
}

function routeEndpointDisplayValue(kind, endpoint) {
  if (!endpoint) return "";
  const { values, idField } = routeEndpointDescriptor(kind);
  const preferred = kind === "destination"
    ? String(endpoint.value || endpoint.label || endpoint[idField])
    : String(endpoint.label || endpoint.value || endpoint[idField]);
  const duplicates = values.filter((item) => {
    const candidate = kind === "destination"
      ? String(item.value || item.label || item[idField])
      : String(item.label || item.value || item[idField]);
    return candidate === preferred;
  });
  if (duplicates.length <= 1) return preferred;
  return `${preferred} (${String(endpoint[idField] || endpoint.node_id || "unidentified")})`;
}

function routeEndpointInputValue(kind, rawValue) {
  const value = String(rawValue ?? "");
  const match = routeEndpointMatch(kind, value);
  if (!match) return value;
  return routeEndpointDisplayValue(kind, match);
}

function setRouteEndpointInput(kind, rawValue) {
  const { input, idField } = routeEndpointDescriptor(kind);
  const match = routeEndpointMatch(kind, rawValue);
  const display = routeEndpointInputValue(kind, rawValue);
  input.value = display;
  if (match) {
    input.dataset.endpointId = String(match[idField]);
    input.dataset.endpointDisplay = display;
  } else {
    delete input.dataset.endpointId;
    delete input.dataset.endpointDisplay;
  }
}

function refreshRouteEndpointIdentity(kind) {
  const { input } = routeEndpointDescriptor(kind);
  setRouteEndpointInput(kind, input.value.trim());
}

function routeEndpointRequestValue(kind) {
  const { input } = routeEndpointDescriptor(kind);
  if (input.dataset.endpointId && input.value.trim() === input.dataset.endpointDisplay) return input.dataset.endpointId;
  return input.value.trim();
}

function selectedRouteEndpoint(kind) {
  const { input, values, idField } = routeEndpointDescriptor(kind);
  if (input.dataset.endpointId && input.value.trim() === input.dataset.endpointDisplay) {
    return values.find((item) => item[idField] === input.dataset.endpointId) || null;
  }
  return routeEndpointMatch(kind, input.value.trim());
}

function routeStartMatch(rawValue) {
  const value = String(rawValue ?? "");
  const points = state.routeCapabilities?.start_points || [];
  const exactIds = points.filter((item) => item.start_id === value);
  if (exactIds.length === 1) return exactIds[0];
  const matches = points.filter((item) =>
    item.label === value
    || item.value === value
    || item.node_id === value
    || item.member_id === value
    || item.resource_id === value
  );
  return matches.length === 1 ? matches[0] : null;
}

function advertisedRouteStart(raw, fallbackNodeId = "") {
  const points = state.routeCapabilities?.start_points || [];
  if (raw !== undefined && raw !== null && typeof raw !== "object") {
    const direct = routeStartMatch(raw);
    if (direct) return direct;
  }
  if (raw && typeof raw === "object") {
    const startId = routeStartSelectorValue({ start_id: raw.start_id ?? raw.id });
    if (startId) {
      const exact = points.filter((item) => item.start_id === startId);
      if (exact.length === 1) return exact[0];
    }
    const identities = ["resource_id", "member_id", "node_id"]
      .filter((field) => raw[field] !== undefined && raw[field] !== null && String(raw[field]) !== "");
    if (identities.length) {
      const matches = points.filter((item) =>
        identities.every((field) => String(item[field] ?? "") === String(raw[field]))
      );
      if (matches.length === 1) return matches[0];
    }
    const displayValue = raw.value ?? raw.label;
    if (displayValue !== undefined) {
      const displayMatch = routeStartMatch(displayValue);
      if (displayMatch) return displayMatch;
    }
  }
  if (fallbackNodeId) {
    const nodeMatches = points.filter((item) => item.node_id === fallbackNodeId);
    if (nodeMatches.length === 1) return nodeMatches[0];
  }
  return null;
}

function routeStartSeedValue(raw, fallbackNodeId = "") {
  const advertised = advertisedRouteStart(raw, fallbackNodeId);
  if (advertised) return advertised.start_id;
  if (raw && typeof raw === "object") return routeStartSelectorValue(raw);
  if (raw !== undefined && raw !== null) return String(raw);
  return "";
}

function routeStartDisplayValue(point) {
  if (!point) return "";
  const label = String(point.label || point.node_id || point.start_id);
  const duplicates = (state.routeCapabilities?.start_points || [])
    .filter((item) => String(item.label || item.node_id || item.start_id) === label);
  return duplicates.length > 1 ? `${label} (${point.start_id})` : label;
}

function setRouteStartInput(rawValue) {
  const input = byId("mn-route-start");
  const match = routeStartMatch(rawValue);
  const display = match ? routeStartDisplayValue(match) : String(rawValue ?? "");
  input.value = display;
  if (match) {
    input.dataset.startId = match.start_id;
    input.dataset.startDisplay = display;
  } else {
    delete input.dataset.startId;
    delete input.dataset.startDisplay;
  }
}

function refreshRouteStartIdentity() {
  setRouteStartInput(byId("mn-route-start").value.trim());
}

function selectedRouteStart() {
  const input = byId("mn-route-start");
  if (input.dataset.startId && input.value.trim() === input.dataset.startDisplay) {
    return state.routeCapabilities?.start_points.find(
      (item) => item.start_id === input.dataset.startId
    ) || null;
  }
  return routeStartMatch(input.value.trim());
}

function routeStartRequestValue() {
  const input = byId("mn-route-start");
  if (input.dataset.startId && input.value.trim() === input.dataset.startDisplay) {
    return input.dataset.startId;
  }
  return input.value.trim();
}

function sameCanonicalRouteEndpoint(source, destination) {
  const sourceId = String(source?.endpoint_id ?? "");
  const destinationId = String(destination?.endpoint_id ?? "");
  return Boolean(sourceId && destinationId && sourceId === destinationId);
}

function routeUsesForwardStart() {
  return byId("mn-route-validation")?.value !== "reverse";
}

function syncRouteStartControlState() {
  const input = byId("mn-route-start");
  const field = byId("mn-route-start-field");
  const help = byId("mn-route-start-help");
  if (!input || !field || !help) return;
  const used = routeUsesForwardStart();
  input.disabled = !state.routeCapabilities || !used;
  field.classList.toggle("is-unused", !used);
  field.setAttribute("data-route-start-usage", used ? "used" : "unused");
  help.textContent = used
    ? "Forward observation/lookup node; it may be a transit node"
    : "Not used for return-only tracing; return starts at the destination side";
}

function routeEndpointScopeIssue(source, destination) {
  const selectedIds = new Set(selectedResultNodes().flatMap((node) => [node.node_id, node.member_id]).filter(Boolean));
  const missing = [source, destination].filter((endpoint) => endpoint?.node_id || endpoint?.member_id)
    .filter((endpoint) => !selectedIds.has(endpoint.node_id) && !selectedIds.has(endpoint.member_id));
  if (!missing.length) return "";
  const labels = [...new Set(missing.map((endpoint) => endpoint.label || endpoint.node_id || endpoint.member_id))];
  return `The endpoint ${labels.join(" / ")} is outside the reconstructed device set. Select its device and reconstruct before tracing.`;
}

function routeStartScopeIssue(start) {
  if (!start?.node_id && !start?.member_id) return "";
  const selectedIds = new Set(selectedResultNodes()
    .flatMap((node) => [node.node_id, node.member_id]).filter(Boolean));
  if (selectedIds.has(start.node_id) || selectedIds.has(start.member_id)) return "";
  return `The trace start ${start.label || start.node_id || start.member_id} is outside the reconstructed device set. Select its device and reconstruct before tracing.`;
}

function buildRouteTraceRequest() {
  if (!state.routeCapabilities) throw new Error(state.routeCapabilityError || "The route tracer is unavailable.");
  if (!state.query?.request) throw new Error("Reconstruct the topology before tracing a route.");
  const scenario = selectedRouteScenario();
  const sourceValue = byId("mn-route-source").value.trim();
  const destination = byId("mn-route-destination").value.trim();
  const startValue = byId("mn-route-start").value.trim();
  const vrfValue = byId("mn-route-vrf").value.trim();
  const familyValue = byId("mn-route-family").value;
  const routeType = byId("mn-route-type").value;
  const resolutionMode = byId("mn-route-policy").value;
  const steeringProfileId = byId("mn-route-steering").value;
  const requestedDirection = byId("mn-route-validation").value;
  const direction = requestedDirection === "bidirectional" ? "both" : requestedDirection;
  const usesForwardStart = direction !== "reverse";
  if (!scenario) throw new Error("Choose a route trace scenario.");
  if (!sourceValue) throw new Error("Choose a route source.");
  if (!destination) throw new Error("Enter a destination to trace.");
  if (usesForwardStart && !startValue) throw new Error("Choose where forward tracing starts.");
  if (!state.routeCapabilities.policies.includes(resolutionMode)) {
    throw new Error("Choose a plug-in-advertised resolution policy.");
  }
  if (steeringProfileId
    && !steeringProfilesForScenario(scenario).some((profile) => profile.profile_id === steeringProfileId)) {
    throw new Error("Choose a steering profile advertised for this scenario.");
  }
  const sourceCapability = selectedRouteEndpoint("source");
  const destinationCapability = selectedRouteEndpoint("destination");
  const startCapability = usesForwardStart ? selectedRouteStart() : null;
  const scopeIssue = routeEndpointScopeIssue(sourceCapability, destinationCapability);
  if (scopeIssue) throw new Error(scopeIssue);
  const startScopeIssue = usesForwardStart ? routeStartScopeIssue(startCapability) : "";
  if (startScopeIssue) throw new Error(startScopeIssue);
  if (sameCanonicalRouteEndpoint(sourceCapability, destinationCapability)) {
    throw new Error("Choose different traffic source and destination endpoints for an end-to-end validation.");
  }
  const familyCapability = state.routeCapabilities.route_families.find((family) =>
    family.route_family === familyValue || family.address_family === familyValue
  );
  const vrfCapability = state.routeCapabilities.vrfs.find((vrf) => vrf.vrf === vrfValue || vrf.vrf_id === vrfValue);
  const compatibleContext = resolveCompatibleRouteContext({
    routeType,
    routeFamily: familyValue,
    vrf: vrfValue,
    scenario,
  });
  if (compatibleContext.routeType !== routeType
    || compatibleContext.family?.route_family !== familyCapability?.route_family
    || compatibleContext.vrf?.vrf_id !== vrfCapability?.vrf_id) {
    throw new Error(`Choose a compatible routing context. ${titleCase(compatibleContext.routeType)} uses ${compatibleContext.vrf?.label || "an advertised VRF"} / ${compatibleContext.family?.label || "an advertised family"}.`);
  }
  const request = {
    topology_context_id: state.query.context_id || null,
    scenario_id: scenario.scenario_id,
    source: sourceCapability || { kind: "plugin_owned", value: sourceValue },
    destination: destinationCapability || { kind: destination.includes("/") ? "ip_prefix" : "plugin_owned", value: destination },
    flow: {
      source: sourceCapability || { kind: "plugin_owned", value: sourceValue },
      destination: destinationCapability || { kind: destination.includes("/") ? "ip_prefix" : "plugin_owned", value: destination },
    },
    direction,
    resolution_mode: resolutionMode,
    basis: state.query.request.basis,
    clock_policy: state.query.request.clock_policy,
    node_queries: state.query.request.node_queries,
    include_inactive_paths: true,
    include_route_resolution: true,
    max_paths: MAX_ROUTE_PATHS,
  };
  if (usesForwardStart) {
    const forwardStart = startCapability || { start_id: startValue, value: startValue };
    request.ingress = forwardStart;
    request.trace_starts = { forward: forwardStart };
  }
  if (sourceCapability?.source_id) request.source_id = sourceCapability.source_id;
  if (destinationCapability?.destination_id) request.destination_id = destinationCapability.destination_id;
  if (vrfValue) {
    request.vrf = vrfCapability?.vrf || vrfValue;
    if (vrfCapability?.vrf_id) request.vrf_id = vrfCapability.vrf_id;
  }
  if (familyValue) {
    request.route_family = familyCapability?.route_family || familyValue;
    request.address_family = familyCapability?.address_family || familyValue;
  }
  if (routeType) request.route_type = routeType;
  if (steeringProfileId) request.steering_profile_id = steeringProfileId;
  if (state.focusedRouteEntryRef) {
    request.route_table_context_id = state.routeTableSnapshot?.route_table_context_id || null;
    request.route_entry_ref = state.focusedRouteEntryRef;
  }
  return request;
}

async function traceRoute(request, signal) {
  const assemblyId = topologyAssemblyId();
  const raw = await api(`/v1/topology-assemblies/${encodeURIComponent(assemblyId)}/routes/trace`, {
    method: "POST",
    body: JSON.stringify(request),
    signal,
  });
  return normalizeRouteTraceBundle(raw, request);
}

function basisForNode(node) {
  const basis = node?.resolved_basis || {};
  const queryTime = basis.query_time_ns ?? basis.resolved_time_ns ?? basis.time_ns ?? basis.local_time_ns;
  const min = basis.resolved_at_min_ns ?? basis.absolute_min_ns ?? basis.min_ns;
  const max = basis.resolved_at_max_ns ?? basis.absolute_max_ns ?? basis.max_ns;
  return {
    kind: basis.kind || state.query?.resolved_basis?.kind || state.query?.request?.basis?.kind || "unknown",
    queryTime,
    min,
    max,
    uncertainty: basis.uncertainty_ns ?? basis.clock_uncertainty_ns ?? (min !== undefined && max !== undefined ? (toBigInt(max) - toBigInt(min)).toString() : null),
    resolution: basis.resolution ?? basis.mapping_quality ?? basis.quality ?? "unknown",
    clock_domain: basis.clock_domain ?? basis.local_clock_domain ?? "node-local",
  };
}

function nodeHealth(node) {
  if (node?.resources_available === false || node?.complete === false) return "warning";
  const resources = node?.resource_previews || node?.resources || [];
  const resourceClasses = resources.map((resource) =>
    declaredHealthPresentation(resource) || "warning"
  );
  if (resourceClasses.includes("error")) return "error";
  if (resourceClasses.includes("warning")) return "warning";
  if (resourceClasses.length && resourceClasses.every((value) => value === "good")) return "good";
  const coverage = node?.coverage || node?.completeness || {};
  const declared = [node, coverage].map(declaredHealthPresentation).filter(Boolean);
  if (declared.includes("error")) return "error";
  if (declared.includes("warning")) return "warning";
  if (declared.includes("good")) return "good";
  // Clock uncertainty is reported separately. When no plug-in/coordinator
  // health class exists, do not silently turn absent evidence into green.
  return "warning";
}

function linkHealth(link) {
  // Connectivity-domain payloads may carry the normalized health vocabulary
  // in `status` rather than a `*_class` transport field.  Only consume status
  // values that the shared vocabulary recognizes; all other values remain
  // explicitly uncertain.
  return declaredHealthPresentation(link, { includeStatus: true }) || "warning";
}

function selectedResultNodes() {
  const nodes = state.query?.nodes || [];
  if (!state.queryControlsDirty) return nodes;
  return nodes.filter((node) => state.selectedNodeKeys.has(node.key));
}

function visibleNodes() {
  const needle = state.nodeFilter.trim().toLowerCase();
  return selectedResultNodes().filter((node) => {
    const plan = node.plan || nodePlan(node);
    const haystack = [node.label, node.node_id, node.member_id, node.site, node.device_type, plan.plugin_set_id, plan.projection_id]
      .filter(Boolean).join(" ").toLowerCase();
    const health = nodeHealth(node);
    const healthMatches = state.healthFilter === "all"
      || (state.healthFilter === "degraded" && health !== "good")
      || (state.healthFilter === "incomplete" && (node.resources_available === false || /partial|incomplete|missing|unknown/.test(JSON.stringify(node.coverage || {}).toLowerCase())));
    return (!needle || haystack.includes(needle)) && healthMatches;
  });
}

function showToast(message) {
  const toast = byId("mn-toast");
  toast.textContent = message;
  toast.classList.add("visible");
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => toast.classList.remove("visible"), 2200);
}

function defaultRoutePath(trace = state.routeTrace) {
  const paths = trace?.paths || [];
  return paths.find((path) => path.path_id === trace?.focused_path_id)
    || paths.find((path) => path?.focused === true)
    || paths.find((path) => ROUTE_SELECTED_STATES.has(firstRouteEnum(path?.selection, path?.eligibility))
      && ROUTE_ACTIVE_STATES.has(firstRouteEnum(path?.activity)))
    || paths[0]
    || null;
}

function pinnedRoutePath() {
  return (state.routeTrace?.paths || []).find((path) => path.path_id === state.selectedRoutePathId) || null;
}

function selectedRoutePath() {
  return pinnedRoutePath() || (state.routeGraphMode === "focused" ? defaultRoutePath() : null);
}

function routePathById(pathId) {
  return (state.routeTrace?.paths || []).find((path) => path.path_id === pathId) || null;
}

function routeValueIsTerminal(value) {
  const disposition = explicitRouteDisposition(value);
  if (ROUTE_TERMINAL_RESULTS.has(disposition)) return true;
  // Compatibility is intentionally limited to whole legacy enum values.
  return ROUTE_TERMINAL_RESULTS.has(legacyRouteDisposition(value));
}

function routeValueIsCycle(value) {
  const reason = firstRouteEnum(value?.terminal_reason, value?.termination_reason, value?.reason);
  const routeState = value?.state && typeof value.state === "object" ? value.state : {};
  const cycleDisposition = [
    value?.result,
    value?.disposition,
    value?.outcome,
    value?.terminal_disposition,
    routeState?.terminal_disposition,
  ].some((item) => ROUTE_CYCLE_RESULTS.has(normalizedRouteEnum(item)));
  return cycleDisposition
    || ROUTE_CYCLE_REASONS.has(reason)
    || Boolean(value?.cycle && typeof value.cycle === "object");
}

function routeValueIsPolicyBlocked(value) {
  const routeState = value?.state && typeof value.state === "object" ? value.state : {};
  const policyDisposition = [
    value?.result,
    value?.disposition,
    value?.outcome,
    value?.terminal_disposition,
    routeState?.terminal_disposition,
  ].some((item) => ROUTE_POLICY_BLOCKED_RESULTS.has(normalizedRouteEnum(item)));
  return policyDisposition
    || Boolean(firstArray(value?.policy_decisions).some((decision) =>
      ROUTE_POLICY_BLOCKED_RESULTS.has(firstRouteEnum(
        decision?.result,
        decision?.core_verdict,
        decision?.outcome,
        decision?.decision,
        decision?.disposition,
      ))
    ));
}

function routePolicyPresentation(value) {
  const decision = firstArray(value?.policy_decisions).find(routeValueIsPolicyBlocked)
    || firstArray(value?.policy_decisions)[0]
    || null;
  return {
    category: firstDeclaredString(
      decision?.policy_category,
      decision?.category,
      decision?.policy_kind,
      value?.policy_category,
      "policy",
    ),
    label: firstDeclaredString(
      decision?.label,
      decision?.title,
      value?.policy_label,
      "Policy blocked",
    ),
    detail: firstDeclaredString(
      decision?.detail,
      decision?.description,
      decision?.text,
      value?.policy_detail,
      "A plug-in-declared forwarding policy excludes this candidate.",
    ),
  };
}

function pathIsDead(path) {
  return routeValueIsTerminal(path)
    || Boolean(routeForwardingSegments(path).some((segment) => routeValueIsTerminal(segment)));
}

function routeSegmentIsCycleClosing(segment, path, index) {
  if (!routeValueIsCycle(path)) return routeValueIsCycle(segment);
  const closingId = String(path?.cycle?.closing_segment_id ?? "");
  if (closingId) return segment?.segment_id === closingId;
  const closingOccurrenceId = String(path?.cycle?.closing_occurrence_id ?? "");
  if (closingOccurrenceId) {
    const boundary = routeForwardingSegments(path).find((item) =>
      item?.target_occurrence_id === closingOccurrenceId
      && item?.source_occurrence_id !== closingOccurrenceId
    );
    if (boundary) return segment?.segment_id === boundary.segment_id;
    if (segment?.node_occurrence_id === closingOccurrenceId) return true;
  }
  const closingStep = Number(path?.cycle?.closing_step ?? 0);
  return closingStep > 0
    ? index === Math.min(routeForwardingSegments(path).length, closingStep) - 1
    : routeValueIsCycle(segment) || index === routeForwardingSegments(path).length - 1;
}

function routeSegmentIsPolicyBlocked(segment, path, index) {
  if (routeValueIsPolicyBlocked(segment)) return true;
  const decisionIds = new Set(firstArray(path?.policy_decisions).map((item) => item?.decision_id).filter(Boolean));
  if (firstArray(segment?.policy_decision_refs).some((decisionId) => decisionIds.has(decisionId))) {
    return true;
  }
  const decision = firstArray(path?.policy_decisions).find((item) =>
    item?.segment_id && item.segment_id === segment?.segment_id
  );
  if (decision) return true;
  return routeValueIsPolicyBlocked(path) && index === routeForwardingSegments(path).length - 1;
}

function routeSegmentIsTerminal(segment, path, index) {
  return routeValueIsTerminal(segment)
    || Boolean(pathIsDead(path) && index === routeForwardingSegments(path).length - 1);
}

function pathIsControlPlaneOnly(path) {
  return path?.forwarding_capable === false
    || [
      path?.eligibility,
      path?.selection,
      path?.alternative_state,
      path?.route_table_install_state,
      path?.install_state,
      path?.forwarding_disposition,
    ].some((value) => ROUTE_CONTROL_PLANE_STATES.has(normalizedRouteEnum(value)));
}

function pathIsInferred(path) {
  const explicit = explicitRouteBoolean(path?.inferred);
  return explicit === true || (explicit === null && routeCompletenessIsInferred(path));
}

function pathIsUnresolved(path) {
  const explicit = explicitRouteBoolean(path?.unresolved);
  return explicit === true || (explicit === null && routeCompletenessIsUnresolved(path));
}

function pathIsInconsistent(path) {
  return routeConsistencyIsInconsistent(path);
}

function pathIsUsableActive(path) {
  const activity = firstRouteEnum(path?.activity);
  const selection = firstRouteEnum(path?.selection, path?.eligibility);
  const selected = ROUTE_SELECTED_STATES.has(selection);
  const active = ROUTE_ACTIVE_STATES.has(activity);
  const excluded = ROUTE_INACTIVE_STATES.has(activity)
    || ROUTE_STANDBY_STATES.has(selection)
    || selection === "ineligible_dead";
  return selected && active && !excluded && !pathIsDead(path)
    && !routeValueIsCycle(path) && !routeValueIsPolicyBlocked(path)
    && !pathIsControlPlaneOnly(path) && !pathIsUnresolved(path)
    && !routeCompletenessIsUnknown(path);
}

function traceIsControlPlaneOnly(trace) {
  const paths = trace?.paths || [];
  return trace?.forwarding_capable === false
    || ROUTE_CONTROL_PLANE_STATES.has(firstRouteEnum(trace?.forwarding_disposition))
    || Boolean(paths.length && paths.every(pathIsControlPlaneOnly));
}

function controlPlaneOnlyFinding(trace) {
  const controlPathIds = new Set((trace?.paths || []).filter(pathIsControlPlaneOnly).map((path) => path.path_id));
  return (trace?.findings || []).find((finding) =>
    finding?.control_plane_only === true
    || finding?.forwarding_capable === false
    || finding.path_ids?.some((pathId) => controlPathIds.has(pathId))
  ) || null;
}

function controlPlaneOnlyReason(trace) {
  const finding = controlPlaneOnlyFinding(trace);
  return finding?.message || finding?.title
    || "The source route resolves in control-plane data but is not installed in the forwarding table.";
}

function routeRoleClasses(value) {
  const role = firstRouteEnum(value?.role);
  const activity = firstRouteEnum(value?.activity);
  const classes = [];
  if (new Set(["primary", "preferred"]).has(role)) classes.push("is-primary");
  if (new Set(["ecmp", "ecmp_member", "all_active", "active_multipath"]).has(role)) classes.push("is-ecmp");
  if (new Set(["standby", "backup", "alternative", "candidate"]).has(role)
    || ROUTE_INACTIVE_STATES.has(activity)) classes.push("is-standby");
  return classes;
}

function routeQualityClasses(value) {
  const classes = routeRoleClasses(value);
  const activity = firstRouteEnum(value?.activity);
  const selection = firstRouteEnum(value?.selection, value?.eligibility);
  const cycle = routeValueIsCycle(value);
  const policyBlocked = routeValueIsPolicyBlocked(value);
  if (ROUTE_ACTIVE_STATES.has(activity) && ROUTE_SELECTED_STATES.has(selection)) classes.push("is-active");
  if (ROUTE_INACTIVE_STATES.has(activity) || ROUTE_STANDBY_STATES.has(selection)
    || selection === "ineligible_dead") classes.push("is-inactive");
  if (pathIsControlPlaneOnly(value)) classes.push("is-control-plane-only", "is-not-installed");
  if (cycle) classes.push("is-cycle");
  if (policyBlocked) classes.push("is-policy-blocked");
  if (routeValueIsTerminal(value) || (value?.segments && pathIsDead(value))) classes.push("is-dead", "is-dropped");
  if (pathIsInconsistent(value)) classes.push("is-inconsistent");
  if (pathIsInferred(value)) classes.push("is-inferred", "is-best-effort");
  const unresolved = pathIsUnresolved(value)
    || (Object.hasOwn(value || {}, "completeness") && routeCompletenessIsUnknown(value));
  if (!cycle && !policyBlocked && unresolved) classes.push("is-unresolved");
  return [...new Set(classes)];
}

const ROUTE_QUALITY_CLASS_NAMES = Object.freeze([
  "is-primary",
  "is-ecmp",
  "is-standby",
  "is-active",
  "is-inactive",
  "is-control-plane-only",
  "is-not-installed",
  "is-cycle",
  "is-policy-blocked",
  "is-dead",
  "is-dropped",
  "is-inconsistent",
  "is-inferred",
  "is-best-effort",
  "is-unresolved",
]);

function routeSegmentQualityState(path, segment, index) {
  const segments = routeForwardingSegments(path);
  const terminal = routeSegmentIsTerminal(segment, path, index);
  const segmentHasInferredPeer = segments.some((item) => item.inferred);
  const segmentHasUnresolvedPeer = segments.some((item) => item.unresolved);
  const segmentHasInconsistentPeer = segments.some((item) => item.inconsistent);
  const inferred = Boolean(segment?.inferred || (path?.inferred && !segmentHasInferredPeer));
  const unresolved = Boolean(segment?.unresolved || (path?.unresolved && !segmentHasUnresolvedPeer));
  const inconsistent = Boolean(segment?.inconsistent || (path?.inconsistent && !segmentHasInconsistentPeer));
  const segmentState = segment?.state && typeof segment.state === "object" ? { ...segment.state } : {};
  const terminalReason = path?.terminal_reason || path?.termination_reason
    || segment?.terminal_reason || segment?.termination_reason
    || segmentState.terminal || "";
  const segmentDisposition = explicitRouteDisposition(segment);
  const pathDisposition = explicitRouteDisposition(path);
  const terminalDisposition = segmentDisposition !== "unknown"
    ? segmentDisposition
    : pathDisposition !== "unknown" ? pathDisposition : legacyRouteDisposition(segment) || "unknown";
  const cycleClosing = routeSegmentIsCycleClosing(segment, path, index);
  const policyBlocked = routeSegmentIsPolicyBlocked(segment, path, index);
  return {
    ...path,
    ...segment,
    segments: [segment],
    state: terminal
      ? { ...(path?.state && typeof path.state === "object" ? path.state : {}), ...segmentState }
      : segmentState,
    result: cycleClosing ? "cycle" : policyBlocked ? "policy_blocked"
      : terminal ? terminalDisposition : segmentDisposition,
    terminal_reason: terminal ? terminalReason : (segment?.terminal_reason || ""),
    termination_reason: terminal ? terminalReason : (segment?.termination_reason || ""),
    status: terminal ? (segment?.status || path?.status || "unknown") : (segment?.status || "unknown"),
    operational: terminal ? (segment?.operational || path?.operational || "unknown") : (segment?.operational || "unknown"),
    inconsistent,
    inferred,
    unresolved,
    cycle: cycleClosing ? (path?.cycle || { closing_segment_id: segment?.segment_id }) : null,
    policy_decisions: policyBlocked ? firstArray(path?.policy_decisions) : [],
  };
}

function routeNodeQualityClasses(node, path) {
  const tokens = [`member:${node.member_id}`, `node:${node.node_id}`, ...interactionTokensForNode(node)];
  const incidentSegments = routeForwardingSegments(path).map((segment, index) => ({ segment, index })).filter(({ segment }) =>
    (node.route_occurrence_id
      ? [segment.source_occurrence_id, segment.target_occurrence_id].includes(node.route_occurrence_id)
      : refRouteTokens(segment.source).some((token) => tokens.includes(token))
        || refRouteTokens(segment.target).some((token) => tokens.includes(token)))
  );
  const classes = incidentSegments.flatMap(({ segment, index }) =>
    routeQualityClasses(routeSegmentQualityState(path, segment, index))
  );
  return [...new Set(classes.length ? classes : routeQualityClasses(path))];
}

function routeQualitySignature(classes) {
  return [...new Set(classes || [])].sort().join(" ");
}

function readRouteQualityData(element, key, fallback) {
  try {
    return JSON.parse(element?.dataset?.[key] || "") ?? fallback;
  } catch (_error) {
    return fallback;
  }
}

function applyRouteOverviewNodeQuality(element, activePathId) {
  const baseline = readRouteQualityData(element, "routeBaseQuality", []);
  const byPath = readRouteQualityData(element, "routeQualityByPath", {});
  const active = activePathId && Array.isArray(byPath[activePathId]) ? byPath[activePathId] : baseline;
  const activeClasses = new Set(active);
  ROUTE_QUALITY_CLASS_NAMES.forEach((className) => element.classList.toggle(className, activeClasses.has(className)));
  element.classList.toggle("is-route-mixed", !activePathId && element.dataset.routeMixed === "true");
  const installGate = element.querySelector("[data-route-install-gate]");
  if (installGate) {
    const gateByPath = readRouteQualityData(element, "routeInstallGateByPath", {});
    const gateVisible = activePathId && Object.hasOwn(gateByPath, activePathId)
      ? Boolean(gateByPath[activePathId])
      : element.dataset.routeBaseInstallGate === "true";
    installGate.hidden = !gateVisible;
  }
}

function routeTokensAttribute(tokens) {
  return escapeHtml(JSON.stringify([...new Set(tokens || [])]));
}

function routeFocusTargetsAttribute(targetIds) {
  return escapeHtml(JSON.stringify([...new Set(targetIds || [])]));
}

function readRouteTokens(element) {
  try {
    return JSON.parse(element?.dataset?.routeTokens || "[]");
  } catch (_error) {
    return [];
  }
}

function readRouteFocusTargets(element) {
  try {
    return JSON.parse(element?.dataset?.routeFocusTargets || "[]");
  } catch (_error) {
    return [];
  }
}

function tokensOverlap(left, right) {
  if (!left?.size || !right?.length) return false;
  return right.some((token) => left.has(token));
}

function applyRouteHighlights() {
  const active = state.routeHoverTokens;
  const allElements = document.querySelectorAll("[data-route-tokens], [data-route-focus-targets]");
  allElements.forEach((element) => {
    element.classList.remove("is-route-correlated", "is-route-dimmed");
  });
  if (!active.size) return;
  const selector = state.routeHoverExact
    ? "#route-trace [data-route-focus-targets]"
    : "[data-route-tokens]";
  document.querySelectorAll(selector).forEach((element) => {
    const values = state.routeHoverExact ? readRouteFocusTargets(element) : readRouteTokens(element);
    const correlated = tokensOverlap(active, values);
    element.classList.toggle("is-route-correlated", correlated);
    element.classList.toggle("is-route-dimmed", !correlated);
  });
}

function setRouteHover(tokens, source, exact = false) {
  state.routeHoverTokens = new Set(tokens || []);
  state.routeHoverSource = source || "";
  state.routeHoverExact = exact;
  applyRouteHighlights();
}

function clearRouteHover(source) {
  if (source && state.routeHoverSource && source !== state.routeHoverSource) return;
  state.routeHoverTokens.clear();
  state.routeHoverSource = "";
  state.routeHoverExact = false;
  applyRouteHighlights();
}

function bindRouteCorrelationElements(scope = document) {
  scope.querySelectorAll("[data-route-tokens], [data-route-focus-targets]").forEach((element) => {
    if (element.dataset.routeBound === "true") return;
    element.dataset.routeBound = "true";
    const source = `${element.dataset.routeKind || "component"}:${element.dataset.routeId || Math.random().toString(36).slice(2)}`;
    element.dataset.routeHoverSource = source;
    const exactTargets = readRouteFocusTargets(element);
    const enter = () => setRouteHover(exactTargets.length ? exactTargets : readRouteTokens(element), source, Boolean(exactTargets.length));
    const leave = (event) => {
      const next = event.relatedTarget?.closest?.("[data-route-focus-targets], [data-route-tokens]");
      if (next && scope.contains(next) && next.dataset.routeBound === "true") {
        const nextExactTargets = readRouteFocusTargets(next);
        setRouteHover(
          nextExactTargets.length ? nextExactTargets : readRouteTokens(next),
          next.dataset.routeHoverSource,
          Boolean(nextExactTargets.length),
        );
        return;
      }
      clearRouteHover(source);
    };
    element.addEventListener("pointerenter", enter);
    element.addEventListener("pointerleave", leave);
    element.addEventListener("focus", enter);
    element.addEventListener("blur", leave);
  });
  applyRouteHighlights();
}

function packetTransitionsForPath(path) {
  return firstArray(path?.packet_trace?.transitions);
}

function routePacketEvaluationByRef(packetRef) {
  if (!packetRef) return null;
  for (const path of state.routeTrace?.paths || []) {
    const evaluation = packetTransitionsForPath(path).find((item) => item.packet_ref === packetRef);
    if (evaluation) return evaluation;
  }
  return null;
}

function routePacketPathForEvaluation(evaluation) {
  return state.routeTrace?.paths.find((path) => path.path_id === evaluation?.path_id) || null;
}

function routePacketContext(evaluation) {
  const path = routePacketPathForEvaluation(evaluation);
  const step = path?.steps.find((candidate) => candidate.step_id === evaluation?.step_id) || null;
  const segment = path?.segments.find((candidate) => candidate.segment_id === evaluation?.segment_id) || null;
  const source = segment ? nodeLabelForRef(segment.source) : "";
  const target = segment ? nodeLabelForRef(segment.target) : "";
  const location = source && target && source !== target ? `${source} → ${target}` : source || target || `Step ${evaluation?.step_id || "unknown"}`;
  return { path, step, segment, location };
}

function packetRefsAttribute(refs) {
  return escapeHtml(JSON.stringify([...new Set(refs || [])]));
}

function readRoutePacketRefs(element) {
  if (element?.dataset?.routePacketRef) return [element.dataset.routePacketRef];
  try {
    const refs = JSON.parse(element?.dataset?.routePacketRefs || "[]");
    return Array.isArray(refs) ? refs.map(String) : [];
  } catch (_error) {
    return [];
  }
}

function packetRefsForRouteNode(path, node) {
  if (!path || !node) return [];
  return packetTransitionsForPath(path).filter((evaluation) => {
    const segment = path.segments.find((candidate) => candidate.segment_id === evaluation.segment_id);
    if (!segment) return false;
    if (node.route_occurrence_id) {
      return [segment.source_occurrence_id, segment.target_occurrence_id].includes(node.route_occurrence_id);
    }
    return sameRouteRef(segment.source, node) || sameRouteRef(segment.target, node);
  }).map((evaluation) => evaluation.packet_ref);
}

function packetValueText(value, depth = 0) {
  if (value === null) return "null";
  if (value === undefined) return "unknown";
  if (typeof value !== "object") return String(value);
  if (depth >= PACKET_VALUE_DEPTH_LIMIT) return "…";
  if (Array.isArray(value)) {
    const shown = value.slice(0, PACKET_VALUE_ITEM_LIMIT)
      .map((item) => packetValueText(item, depth + 1));
    if (value.length > PACKET_VALUE_ITEM_LIMIT) shown.push(`+${value.length - PACKET_VALUE_ITEM_LIMIT} more`);
    return `[${shown.join(", ")}]`;
  }
  const entries = Object.entries(value);
  const shown = entries.slice(0, PACKET_VALUE_ITEM_LIMIT)
    .map(([key, item]) => `${key}=${packetValueText(item, depth + 1)}`);
  if (entries.length > PACKET_VALUE_ITEM_LIMIT) shown.push(`+${entries.length - PACKET_VALUE_ITEM_LIMIT} more`);
  return `{${shown.join(", ")}}`;
}

function packetResourceReferenceText(raw) {
  const resource = raw?.resource ?? raw?.resource_ref ?? raw;
  if (!resource || typeof resource !== "object") return String(resource ?? "unknown resource");
  const typedResourceKey = resource.namespace && resource.node
    && resource.layer && resource.kind;
  if (typedResourceKey) {
    const parts = Array.isArray(resource.parts)
      ? resource.parts.map((part) => {
        if (Array.isArray(part)) return `${part[0]}=${packetValueText(part[1])}`;
        return `${part?.name ?? "part"}=${packetValueText(part?.value)}`;
      })
      : Object.entries(resource.parts || {}).map(([name, value]) =>
        `${name}=${packetValueText(value)}`
      );
    return [
      resource.node,
      `${resource.namespace}/${resource.layer}/${resource.kind}`,
      parts.join(", "),
    ].filter(Boolean).join(" · ");
  }
  return String(
    resource.label
    ?? resource.display_name
    ?? resource.resource_id
    ?? resource.local_resource_id
    ?? resource.node_id
    ?? "unknown resource"
  );
}

function packetTopologyReferenceText(raw) {
  const reference = raw && typeof raw === "object" ? raw : {};
  if (reference.resource) return packetResourceReferenceText(reference.resource);
  const match = reference.match;
  if (!match || typeof match !== "object") return "unknown topology reference";
  const candidateCount = firstArray(match.resolved_candidates).length;
  const suffix = candidateCount
    ? ` · ${candidateCount} resolved candidate${candidateCount === 1 ? "" : "s"}`
    : "";
  return `${match.matcher_id || "plug-in matcher"} · ${packetValueText(match.arguments || {})}${suffix}`;
}

function packetEvidenceText(raw) {
  const evidence = raw && typeof raw === "object" ? raw : {};
  const artifact = evidence.artifact_id ? `artifact ${evidence.artifact_id}` : "artifact unknown";
  const locator = evidence.locator ? ` · ${evidence.locator}` : "";
  const clock = evidence.clock_domain ? ` · clock ${evidence.clock_domain}` : "";
  return `${artifact}${locator}${clock}`;
}

function packetStateSummary(packet) {
  const labels = firstArray(packet?.layers).slice(0, PACKET_SUMMARY_LAYER_LIMIT)
    .map((layer) => layer.label);
  if ((packet?.layers?.length || 0) > PACKET_SUMMARY_LAYER_LIMIT) {
    labels.push(`+${packet.layers.length - PACKET_SUMMARY_LAYER_LIMIT} more`);
  }
  return labels.join(" › ") || "No declared layers";
}

function packetSizeLabel(packet) {
  const size = packet?.size?.size_bytes;
  return size === null || size === undefined ? "size unknown" : `${formatInteger(size)} B`;
}

function packetDiffCount(evaluation) {
  const diff = evaluation?.diff || {};
  const changed = firstArray(
    diff.added_layer_ids,
    diff.removed_layer_ids,
    diff.changed_layer_ids,
    diff.moved_layer_ids,
  ).length;
  if (changed) {
    const summary = [
      `+${diff.added_layer_ids?.length || 0}`,
      `−${diff.removed_layer_ids?.length || 0}`,
      `~${diff.changed_layer_ids?.length || 0}`,
      `↕${diff.moved_layer_ids?.length || 0}`,
    ].join(" ");
    return diff.complete === true ? summary : `${summary} · partial diff`;
  }
  if (diff.complete === true) return "no declared layer change";
  if (diff.complete === false) return "partial diff · no-change unproven";
  return "diff completeness unknown";
}

function packetMtuLabel(mtu, compact = false) {
  const outcome = normalizedRouteEnum(mtu?.outcome) || "not_declared";
  if (outcome === "fits") {
    return compact ? "MTU fits" : `${formatInteger(mtu.size_bytes)} B fits ${formatInteger(mtu.limit_bytes)} B MTU`;
  }
  if (outcome === "exceeds") {
    return compact ? "MTU exceeded" : `${formatInteger(mtu.size_bytes)} B exceeds ${formatInteger(mtu.limit_bytes)} B MTU by ${formatInteger(mtu.excess_bytes)} B`;
  }
  if (outcome === "unknown_basis_mismatch") return "MTU basis differs";
  if (outcome === "unknown") return "MTU comparison unknown";
  return "MTU not declared";
}

function packetTransitionClasses(evaluation) {
  const classes = [];
  if (evaluation?.counterfactual) classes.push("is-counterfactual");
  if (evaluation?.transition?.disposition === "drop") classes.push("is-drop");
  if (evaluation?.transition?.disposition === "deliver") classes.push("is-deliver");
  if (evaluation?.mtu?.outcome === "exceeds") classes.push("is-mtu-exceeds");
  if (evaluation?.continuity_valid === false) classes.push("is-continuity-gap");
  if (evaluation?.diff?.complete !== true) classes.push("is-incomplete");
  if (evaluation?.transition?.before?.complete === false || evaluation?.transition?.after?.complete === false) {
    classes.push("is-incomplete");
  }
  return classes;
}

function packetLayerClasses(evaluation, layerId, side) {
  const diff = evaluation?.diff || {};
  const classes = [];
  if (side === "before" && diff.removed_layer_ids?.includes(layerId)) classes.push("is-removed");
  if (side === "after" && diff.added_layer_ids?.includes(layerId)) classes.push("is-added");
  if (diff.changed_layer_ids?.includes(layerId)) classes.push("is-changed");
  if (diff.moved_layer_ids?.includes(layerId)) classes.push("is-moved");
  return classes.join(" ");
}

function packetStateMarkup(evaluation, packet, side, title) {
  const layers = firstArray(packet?.layers);
  const visibleLayers = layers.slice(0, PACKET_DETAIL_LAYER_LIMIT);
  const layerMarkup = visibleLayers.map((layer, index) => {
    const visibleFields = layer.fields.slice(0, PACKET_FIELD_PREVIEW_LIMIT);
    const fields = visibleFields.map((field) =>
      `<div><dt>${escapeHtml(field.name)}</dt><dd><code>${escapeHtml(packetValueText(field.value))}</code></dd></div>`
    ).join("");
    const hiddenFields = layer.fields.length - visibleFields.length;
    return `<li class="mn-route-packet-layer ${packetLayerClasses(evaluation, layer.layer_id, side)}${layer.complete ? "" : " is-incomplete"}" data-packet-layer-id="${escapeHtml(layer.layer_id)}">
      <header><span>${index === 0 ? "OUTER" : index === layers.length - 1 ? "INNER" : index + 1}</span><strong>${escapeHtml(layer.label)}</strong>${layer.size_bytes === null ? "" : `<small>${formatInteger(layer.size_bytes)} B</small>`}</header>
      <code class="mn-route-packet-contract">${escapeHtml(layer.contract_id)}</code>
      ${fields ? `<dl>${fields}</dl>` : '<p>No declared fields</p>'}
      ${hiddenFields > 0 ? `<small class="mn-route-packet-more">+${formatInteger(hiddenFields)} more fields</small>` : ""}
      ${layer.complete ? "" : '<small class="mn-route-packet-incomplete">Layer snapshot is incomplete</small>'}
    </li>`;
  }).join("");
  const hiddenLayers = layers.length - visibleLayers.length;
  return `<section class="mn-route-packet-state is-${side}">
    <header><div><span>${escapeHtml(title)}</span><strong>${escapeHtml(packetStateSummary(packet))}</strong></div><small>${escapeHtml(packetSizeLabel(packet))}</small></header>
    <ol class="mn-route-packet-stack">${layerMarkup || '<li class="mn-route-packet-layer is-empty">No packet layers were declared.</li>'}</ol>
    ${hiddenLayers > 0 ? `<p class="mn-route-packet-more">+${formatInteger(hiddenLayers)} additional layers omitted from this bounded browser view</p>` : ""}
    ${packet?.complete ? "" : '<p class="mn-route-packet-incomplete">Packet snapshot is incomplete; an empty diff does not prove unchanged state.</p>'}
  </section>`;
}

function packetDiffMarkup(evaluation) {
  const diff = evaluation?.diff || {};
  const rows = [
    ["Added", diff.added_layer_ids],
    ["Removed", diff.removed_layer_ids],
    ["Changed", diff.changed_layer_ids],
    ["Moved", diff.moved_layer_ids],
  ].filter(([, ids]) => ids?.length);
  const completeness = diff.complete === true
    ? ""
    : `<p class="mn-route-packet-incomplete">${diff.complete === false
      ? "Structural diff is partial; omitted changes remain possible."
      : "Structural diff completeness was not declared."}</p>`;
  return `<section class="mn-route-packet-changes${diff.complete === true ? "" : " is-incomplete"}">
    <header><span>STRUCTURAL DIFF</span><strong>${escapeHtml(packetDiffCount(evaluation))}</strong></header>
    ${rows.length ? `<dl>${rows.map(([label, ids]) =>
      `<div><dt>${escapeHtml(label)}</dt><dd>${ids.map((id) => `<code>${escapeHtml(id)}</code>`).join("")}</dd></div>`
    ).join("")}</dl>` : `<p>${diff.complete === true
      ? "No layer identity, ordering, or value changes were declared."
      : "No structural difference was declared; an unchanged conclusion is not supported."}</p>`}
    ${completeness}
  </section>`;
}

function packetContributionsMarkup(evaluation) {
  const contributions = evaluation?.transition?.contributions || [];
  if (!contributions.length) return '<p class="mn-route-packet-no-evidence">No additional resolution contribution was returned.</p>';
  return `<ol class="mn-route-packet-contributions">${contributions.map((contribution) => {
    const references = [
      ...contribution.resource_references.map(packetResourceReferenceText),
      ...contribution.topology_references.map(packetTopologyReferenceText),
    ];
    const visibleReferences = references.slice(0, PACKET_REFERENCE_PREVIEW_LIMIT);
    const hiddenReferences = references.length - visibleReferences.length;
    const evidence = contribution.evidence.map(packetEvidenceText);
    const visibleEvidence = evidence.slice(0, PACKET_EVIDENCE_PREVIEW_LIMIT);
    const hiddenEvidence = evidence.length - visibleEvidence.length;
    return `<li>
      <span>${escapeHtml(titleCase(contribution.phase))}</span>
      <p>${escapeHtml(contribution.text)}</p>
      <small>${escapeHtml(`${titleCase(contribution.quality)} · ${references.length} reference${references.length === 1 ? "" : "s"} · ${evidence.length} evidence item${evidence.length === 1 ? "" : "s"}`)}</small>
      ${visibleReferences.length ? `<div class="mn-route-packet-reference-list" aria-label="Contribution resource and topology references">${visibleReferences.map((reference) => `<code>${escapeHtml(reference)}</code>`).join("")}${hiddenReferences > 0 ? `<i>+${formatInteger(hiddenReferences)} more references</i>` : ""}</div>` : ""}
      ${visibleEvidence.length ? `<div class="mn-route-packet-evidence-list" aria-label="Contribution evidence">${visibleEvidence.map((item) => `<code>${escapeHtml(item)}</code>`).join("")}${hiddenEvidence > 0 ? `<i>+${formatInteger(hiddenEvidence)} more evidence items</i>` : ""}</div>` : ""}
    </li>`;
  }).join("")}</ol>`;
}

function packetTransitionPreviewMarkup(evaluation) {
  const context = routePacketContext(evaluation);
  const transition = evaluation.transition;
  return `<header><span>PACKET TRANSITION</span><strong>${escapeHtml(transition.action_label)}</strong><small>${escapeHtml(context.location)}</small></header>
    <div class="mn-route-packet-preview-flow"><span>${escapeHtml(packetStateSummary(transition.before))}</span><b aria-hidden="true">→</b><span>${escapeHtml(packetStateSummary(transition.after))}</span></div>
    <div class="mn-route-packet-preview-badges">
      <span>${escapeHtml(`${packetSizeLabel(transition.before)} → ${packetSizeLabel(transition.after)}`)}</span>
      <span>${escapeHtml(packetDiffCount(evaluation))}</span>
      <span class="is-${safeClass(evaluation.mtu.outcome)}">${escapeHtml(packetMtuLabel(evaluation.mtu, true))}</span>
      <span class="is-${safeClass(transition.disposition)}">${escapeHtml(titleCase(transition.disposition))}</span>
      ${evaluation.counterfactual ? '<span class="is-counterfactual">USER-FORCED · COUNTERFACTUAL</span>' : ""}
    </div>
    <footer>Click or press Enter to pin complete before / change / after details.</footer>`;
}

function packetTransitionDetailMarkup(evaluation) {
  const context = routePacketContext(evaluation);
  const transition = evaluation.transition;
  const mtuConstraint = transition.mtu_constraint;
  const mtuResource = mtuConstraint?.resource
    ? packetResourceReferenceText(mtuConstraint.resource) : "";
  const mtuProvenance = mtuConstraint
    ? `<span title="${escapeHtml(mtuResource || "No MTU resource reference was declared")}">${escapeHtml(`MTU basis: ${mtuConstraint.basis_contract_id}${mtuResource ? ` · ${mtuResource}` : ""}`)}</span>`
    : "";
  const forced = evaluation.counterfactual
    ? `<p class="mn-route-packet-warning"><strong>User-forced counterfactual.</strong> This transition is trace input, not observed forwarding truth.${transition.forced_rule_id ? ` Rule ${escapeHtml(transition.forced_rule_id)}.` : ""}</p>`
    : "";
  return `<header class="mn-route-packet-detail-header">
      <div><span>PINNED PACKET TRANSITION</span><h5>${escapeHtml(transition.action_label)}</h5><small>${escapeHtml(context.location)}</small></div>
      <button type="button" data-route-packet-close aria-label="Close packet transition details">×</button>
    </header>
    ${forced}
    <div class="mn-route-packet-detail-badges">
      <span class="is-${safeClass(transition.disposition)}">${escapeHtml(`Disposition: ${titleCase(transition.disposition)}`)}</span>
      <span class="is-${safeClass(evaluation.mtu.outcome)}">${escapeHtml(packetMtuLabel(evaluation.mtu))}</span>
      ${mtuProvenance}
      <span>${escapeHtml(evaluation.continuity_valid === false ? "Continuity gap" : evaluation.continuity_valid === true ? "Continuity validated" : "Continuity unknown")}</span>
    </div>
    <div class="mn-route-packet-state-grid">
      ${packetStateMarkup(evaluation, transition.before, "before", "Before")}
      ${packetDiffMarkup(evaluation)}
      ${packetStateMarkup(evaluation, transition.after, "after", "After")}
    </div>
    <section class="mn-route-packet-evidence">
      <header><span>PROVENANCE AND REASONS</span><strong>${escapeHtml(`Actor ${transition.actor_id}`)}</strong></header>
      <code>${escapeHtml(transition.action_contract_id)}</code>
      ${packetContributionsMarkup(evaluation)}
    </section>`;
}

function applyRoutePacketFocus() {
  const activeRef = state.routePacketPreviewRef || state.routePacketPinnedRef;
  document.querySelectorAll("[data-route-packet-ref], [data-route-packet-refs]").forEach((element) => {
    const refs = readRoutePacketRefs(element);
    const focused = Boolean(activeRef && refs.includes(activeRef));
    element.classList.toggle("is-packet-focus", focused);
    element.classList.toggle("is-packet-pinned", focused && activeRef === state.routePacketPinnedRef);
    if (element.dataset.routePacketRef) {
      element.setAttribute("aria-pressed", String(element.dataset.routePacketRef === state.routePacketPinnedRef));
    }
  });
}

function positionRoutePacketPreview(anchor, point = null) {
  const card = byId("mn-route-packet-preview");
  if (!card || card.hidden || !anchor?.getBoundingClientRect) return;
  const rect = anchor.getBoundingClientRect();
  const width = Math.min(410, window.innerWidth - 24);
  const height = Math.min(card.scrollHeight || 250, window.innerHeight - 24);
  const anchorX = Number.isFinite(point?.clientX) ? point.clientX : rect.right;
  const anchorY = Number.isFinite(point?.clientY) ? point.clientY : rect.top;
  let left = anchorX + 14;
  if (left + width > window.innerWidth - 12) left = anchorX - width - 14;
  card.style.width = `${width}px`;
  card.style.left = `${Math.max(12, Math.min(window.innerWidth - width - 12, left))}px`;
  card.style.top = `${Math.max(12, Math.min(window.innerHeight - height - 12, anchorY - 18))}px`;
}

function showRoutePacketPreview(packetRef, anchor, point = null) {
  const evaluation = routePacketEvaluationByRef(packetRef);
  if (!evaluation) return;
  clearTimeout(state.routePacketPreviewTimer);
  state.routePacketPreviewRef = packetRef;
  state.routePacketPreviewAnchor = anchor;
  const source = `packet-preview:${packetRef}`;
  state.routePacketPreviewSource = source;
  const card = byId("mn-route-packet-preview");
  if (card.parentElement !== document.body) document.body.append(card);
  card.hidden = false;
  card.innerHTML = packetTransitionPreviewMarkup(evaluation);
  positionRoutePacketPreview(anchor, point);
  setRouteHover(
    evaluation.highlight_target_ids.length ? evaluation.highlight_target_ids : evaluation.component_tokens,
    source,
    Boolean(evaluation.highlight_target_ids.length),
  );
  applyRoutePacketFocus();
}

function clearRoutePacketPreview() {
  clearTimeout(state.routePacketPreviewTimer);
  state.routePacketPreviewTimer = null;
  const source = state.routePacketPreviewSource;
  state.routePacketPreviewRef = "";
  state.routePacketPreviewSource = "";
  state.routePacketPreviewAnchor = null;
  const card = byId("mn-route-packet-preview");
  if (card) {
    card.hidden = true;
    card.innerHTML = "";
  }
  const pinned = routePacketEvaluationByRef(state.routePacketPinnedRef);
  if (pinned) {
    setRouteHover(
      pinned.highlight_target_ids.length ? pinned.highlight_target_ids : pinned.component_tokens,
      `packet-pin:${pinned.packet_ref}`,
      Boolean(pinned.highlight_target_ids.length),
    );
  } else {
    clearRouteHover(source);
  }
  applyRoutePacketFocus();
}

function scheduleClearRoutePacketPreview(delay = 140) {
  clearTimeout(state.routePacketPreviewTimer);
  state.routePacketPreviewTimer = setTimeout(clearRoutePacketPreview, delay);
}

function renderRoutePacketDetail() {
  const detail = byId("mn-route-packet-detail");
  if (!detail) return;
  const evaluation = routePacketEvaluationByRef(state.routePacketPinnedRef);
  detail.hidden = !evaluation;
  detail.innerHTML = evaluation ? packetTransitionDetailMarkup(evaluation) : "";
  detail.querySelector("[data-route-packet-close]")?.addEventListener("click", () => {
    clearRoutePacketSelection({ restoreFocus: true });
  });
}

function selectRoutePacketTransition(packetRef, trigger = null) {
  const evaluation = routePacketEvaluationByRef(packetRef);
  if (!evaluation) return;
  const toggledOff = state.routePacketPinnedRef === packetRef;
  state.routePacketPinnedRef = toggledOff ? "" : packetRef;
  state.routePacketPinnedTrigger = toggledOff ? null : trigger;
  renderRoutePacketDetail();
  if (!toggledOff && !state.routePacketPreviewRef) {
    setRouteHover(
      evaluation.highlight_target_ids.length ? evaluation.highlight_target_ids : evaluation.component_tokens,
      `packet-pin:${packetRef}`,
      Boolean(evaluation.highlight_target_ids.length),
    );
  }
  if (toggledOff && !state.routePacketPreviewRef) clearRouteHover();
  applyRoutePacketFocus();
}

function clearRoutePacketSelection(options = {}) {
  const trigger = state.routePacketPinnedTrigger || state.routePacketPreviewAnchor;
  clearTimeout(state.routePacketPreviewTimer);
  state.routePacketPinnedRef = "";
  state.routePacketPinnedTrigger = null;
  clearRoutePacketPreview();
  renderRoutePacketDetail();
  clearRouteHover();
  if (options.restoreFocus === true && trigger?.isConnected) trigger.focus({ preventScroll: true });
}

function renderRoutePacketEvolution(path) {
  const section = byId("mn-route-packet-evolution");
  const rail = byId("mn-route-packet-rail");
  const status = byId("mn-route-packet-status");
  if (!section || !rail || !status) return;
  const transitions = packetTransitionsForPath(path);
  section.hidden = !transitions.length;
  if (!transitions.length) {
    rail.innerHTML = "";
    status.textContent = "";
    byId("mn-route-packet-detail").hidden = true;
    byId("mn-route-packet-detail").innerHTML = "";
    return;
  }
  const validRefs = new Set(transitions.map((evaluation) => evaluation.packet_ref));
  if (state.routePacketPinnedRef && !validRefs.has(state.routePacketPinnedRef)) {
    state.routePacketPinnedRef = "";
    state.routePacketPinnedTrigger = null;
  }
  if (state.routePacketPreviewRef && !validRefs.has(state.routePacketPreviewRef)) clearRoutePacketPreview();
  const trace = path.packet_trace;
  status.textContent = `${formatInteger(transitions.length)} transition${transitions.length === 1 ? "" : "s"} · ${titleCase(trace.outcome)} · continuity ${trace.continuity_complete ? "complete" : "incomplete"}${trace.counterfactual ? " · counterfactual" : ""}`;
  rail.innerHTML = transitions.map((evaluation, index) => {
    const context = routePacketContext(evaluation);
    const transition = evaluation.transition;
    return `<li><button type="button" class="mn-route-packet-chip ${packetTransitionClasses(evaluation).join(" ")}" data-route-kind="packet-transition" data-route-id="${escapeHtml(transition.transition_id)}" data-route-packet-ref="${escapeHtml(evaluation.packet_ref)}" data-route-tokens="${routeTokensAttribute(evaluation.component_tokens)}" data-route-focus-targets="${routeFocusTargetsAttribute(evaluation.highlight_target_ids)}" aria-pressed="${evaluation.packet_ref === state.routePacketPinnedRef}">
      <span>${index + 1} · ${escapeHtml(context.location)}</span>
      <strong>${escapeHtml(transition.action_label)}</strong>
      <small>${escapeHtml(packetStateSummary(transition.after))}</small>
      <i><b>${escapeHtml(`${packetSizeLabel(transition.before)} → ${packetSizeLabel(transition.after)}`)}</b><b>${escapeHtml(packetDiffCount(evaluation))}</b></i>
      <em>${escapeHtml(titleCase(transition.disposition))}${evaluation.mtu.outcome === "not_declared" ? "" : ` · ${escapeHtml(packetMtuLabel(evaluation.mtu, true))}`}${evaluation.counterfactual ? " · USER-FORCED" : ""}</em>
    </button></li>`;
  }).join("");
  renderRoutePacketDetail();
  applyRoutePacketFocus();
}

function bindRoutePacketElements(scope) {
  scope.querySelectorAll("[data-route-packet-ref]").forEach((element) => {
    if (element.dataset.routePacketBound === "true") return;
    element.dataset.routePacketBound = "true";
    const packetRef = element.dataset.routePacketRef;
    const enter = (event) => showRoutePacketPreview(packetRef, element, {
      clientX: event.clientX,
      clientY: event.clientY,
    });
    element.addEventListener("pointerenter", enter);
    element.addEventListener("pointerleave", () => scheduleClearRoutePacketPreview());
    element.addEventListener("focus", () => showRoutePacketPreview(packetRef, element));
    element.addEventListener("blur", () => scheduleClearRoutePacketPreview());
    element.addEventListener("click", () => selectRoutePacketTransition(packetRef, element));
    element.addEventListener("keydown", (event) => {
      if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
      const buttons = [...scope.querySelectorAll("[data-route-packet-ref]")];
      const current = buttons.indexOf(element);
      const next = event.key === "Home" ? 0 : event.key === "End" ? buttons.length - 1
        : (current + (event.key === "ArrowRight" ? 1 : -1) + buttons.length) % buttons.length;
      event.preventDefault();
      buttons[next]?.focus();
    });
  });
}

function bindRoutePacketGraphElements(scope) {
  if (state.routeGraphMode !== "focused") return;
  scope.querySelectorAll("[data-route-packet-refs]").forEach((element) => {
    if (element.dataset.routePacketGraphBound === "true") return;
    element.dataset.routePacketGraphBound = "true";
    const refs = readRoutePacketRefs(element);
    if (refs.length !== 1) return;
    const packetRef = refs[0];
    const enter = (event) => showRoutePacketPreview(packetRef, element, {
      clientX: event.clientX,
      clientY: event.clientY,
    });
    element.addEventListener("pointerenter", enter);
    element.addEventListener("pointerleave", () => scheduleClearRoutePacketPreview());
    element.addEventListener("focus", () => showRoutePacketPreview(packetRef, element));
    element.addEventListener("blur", () => scheduleClearRoutePacketPreview());
    if (element.dataset.routeKind === "route-segment" && element.getAttribute("aria-hidden") !== "true") {
      element.addEventListener("click", (event) => {
        event.preventDefault();
        event.stopPropagation();
        selectRoutePacketTransition(packetRef, element);
      });
      element.addEventListener("keydown", (event) => {
        if (!["Enter", " "].includes(event.key)) return;
        event.preventDefault();
        selectRoutePacketTransition(packetRef, element);
      });
    }
  });
  applyRoutePacketFocus();
}

function renderSourceBanner() {
  const banner = byId("mn-source-banner");
  banner.className = "section-wrap mn-source-banner";
  if (state.pending) {
    banner.innerHTML = '<span class="mn-spinner" aria-hidden="true"></span><strong>Reconstructing node capture vector…</strong>';
    return;
  }
  if (state.apiMode === "error") {
    banner.classList.add("is-fallback");
    banner.innerHTML = `<span class="mn-spinner" aria-hidden="true"></span><strong>Topology reconstruction failed.</strong><span>${escapeHtml(state.apiError || "No topology result is available for these controls.")}</span>`;
    return;
  }
  if (state.queryControlsDirty && state.query?.nodes?.length) {
    banner.classList.add("is-fallback");
    banner.innerHTML = '<span class="mn-spinner" aria-hidden="true"></span><strong>Controls changed.</strong><span>The maps still show the last applied reconstruction. Run reconstruct to apply the pending device, time, or plug-in choices.</span>';
    return;
  }
  banner.classList.add("is-ready");
  banner.innerHTML = `<span class="mn-spinner" aria-hidden="true"></span><strong>${escapeHtml(state.apiMode === "global-api" ? "Global topology API" : "Revision-scoped alias")}</strong><span>Node-local plug-in plans and the cross-node capture context came from the server.</span>`;
}

function topologyElementVisible(key) {
  return state.topologyElementVisibility.has(key);
}

function sameTopologyElementSet(values) {
  return values.length === state.topologyElementVisibility.size
    && values.every((value) => state.topologyElementVisibility.has(value));
}

function topologyElementPresetName() {
  if (sameTopologyElementSet(TOPOLOGY_ELEMENT_PRESETS.compact)) return "compact";
  if (sameTopologyElementSet(TOPOLOGY_ELEMENT_PRESETS.all)) return "all";
  return "custom";
}

function applyTopologyElementUrlState(params) {
  if (!params.has("topology_layers")) {
    state.topologyElementVisibility = new Set(TOPOLOGY_ELEMENT_PRESETS.compact);
    return;
  }
  const requested = new Set(String(params.get("topology_layers") || "")
    .split(",")
    .map((value) => value.trim().toLowerCase())
    .filter((value) => TOPOLOGY_ELEMENT_KEYS.includes(value)));
  state.topologyElementVisibility = requested;
}

function syncTopologyElementControls() {
  document.querySelectorAll("[data-topology-element]").forEach((control) => {
    control.checked = topologyElementVisible(control.dataset.topologyElement);
  });
  const preset = topologyElementPresetName();
  document.querySelectorAll("[data-topology-element-preset]").forEach((button) => {
    button.setAttribute("aria-pressed", String(button.dataset.topologyElementPreset === preset));
  });
  const summary = byId("mn-topology-element-summary");
  if (summary) {
    const readable = {
      subnets: "subnets",
      vlans: "VLANs",
      interfaces: "interfaces",
      subinterfaces: "subinterfaces",
      lags: "LAGs",
      external: "external networks",
    };
    const visible = TOPOLOGY_ELEMENT_KEYS.filter((key) => topologyElementVisible(key)).map((key) => readable[key]);
    summary.textContent = preset === "all"
      ? "All detail layers"
      : visible.length ? visible.join(" + ") : "Connectivity only";
    summary.title = `${titleCase(preset)} preset · ${visible.length} of ${TOPOLOGY_ELEMENT_KEYS.length} layers visible`;
  }
}

function syncTopologyNetworkViewControls() {
  document.querySelectorAll("[data-topology-network-view]").forEach((button) => {
    button.setAttribute("aria-pressed", String(button.dataset.topologyNetworkView === state.topologyNetworkView));
  });
}

function setAdvertisedSelectValue(select, requested, fallback) {
  const values = [...select.options].map((option) => option.value);
  select.value = values.includes(requested) ? requested : values.includes(fallback) ? fallback : values[0] || "";
}

function normalizedRelativeSeconds(value, fallback = "-5") {
  try {
    const normalized = String(value ?? "").trim();
    return normalized && parseSecondsToNs(normalized) <= 0n ? normalized : fallback;
  } catch (_error) {
    return fallback;
  }
}

function renderControls() {
  const profileSelect = byId("mn-projection");
  const perspectiveSelect = byId("mn-perspective");
  const params = new URLSearchParams(location.search);
  applyTopologyElementUrlState(params);
  syncTopologyElementControls();
  state.topologyNetworkView = params.get("topology_view") === "vpn" ? "vpn" : "underlay";
  syncTopologyNetworkViewControls();
  state.requestedRoutePathId = params.get("route_path") || "";
  state.routeGraphMode = params.get("route_view") === "all" ? "all" : "focused";
  const requestedRouteDirection = params.get("route_focus_direction");
  if (["forward", "reverse"].includes(requestedRouteDirection)) {
    // Preserve the deep-linked direction through the topology query that runs
    // before the initial route trace. The query's URL sync must not reset a
    // requested reverse view back to the default forward direction.
    state.activeRouteDirection = requestedRouteDirection;
  }
  profileSelect.innerHTML = state.capabilities.profiles.map((item) =>
    `<option value="${escapeHtml(item.profile_id)}">${escapeHtml(item.label)}</option>`
  ).join("") || '<option value="">No topology profile advertised</option>';
  const requestedProfile = params.get("topology_profile_id") || state.capabilities.default_profile_id;
  setAdvertisedSelectValue(profileSelect, requestedProfile, state.capabilities.default_profile_id);
  profileSelect.disabled = !state.capabilities.profiles.length;
  perspectiveSelect.innerHTML = state.capabilities.perspectives.map((item) => {
    const id = perspectiveId(item);
    return `<option value="${escapeHtml(id)}">${escapeHtml(item.label || item.display_name || titleCase(id))}</option>`;
  }).join("") || '<option value="">No status perspective advertised</option>';
  const requestedPerspective = params.get("status_perspective_id") || state.capabilities.default_perspective_id;
  setAdvertisedSelectValue(perspectiveSelect, requestedPerspective, state.capabilities.default_perspective_id);
  perspectiveSelect.disabled = !state.capabilities.perspectives.length;
  setAdvertisedSelectValue(
    byId("mn-clock-policy"),
    params.get("clock_policy") || state.capabilities.default_clock_policy,
    state.capabilities.default_clock_policy,
  );
  setAdvertisedSelectValue(
    byId("mn-basis-kind"),
    params.get("basis_kind") || state.capabilities?.defaults?.basis?.kind || "absolute_time",
    state.capabilities?.defaults?.basis?.kind || "absolute_time",
  );
  const capture = state.bootstrap?.workspace?.capture_ns || state.capabilities?.time_bounds?.capture_ns || state.capabilities?.time_bounds?.end_ns || "0";
  const requestedTime = params.get("time_ns");
  byId("mn-absolute-time").value = requestedTime && /^-?\d+$/.test(requestedTime) ? requestedTime : capture;
  const defaultRelative = normalizedRelativeSeconds(nsToSecondsInput(
    params.get("basis_offset_ns") || params.get("offset_ns") || state.capabilities?.defaults?.basis?.offset_ns,
    "-5",
  ), "-5");
  byId("mn-relative-seconds").value = normalizedRelativeSeconds(params.get("relative_seconds"), defaultRelative);
  syncBasisFields();
}

function renderRouteControls() {
  const status = byId("mn-route-api-status");
  const scenarioSelect = byId("mn-route-scenario");
  const startInput = byId("mn-route-start");
  const sourceInput = byId("mn-route-source");
  const destinationInput = byId("mn-route-destination");
  const vrfInput = byId("mn-route-vrf");
  const familySelect = byId("mn-route-family");
  const typeSelect = byId("mn-route-type");
  const policySelect = byId("mn-route-policy");
  const steeringSelect = byId("mn-route-steering");
  const validationSelect = byId("mn-route-validation");
  const run = byId("mn-route-run");
  if (!state.routeCapabilities) {
    status.textContent = "tracer unavailable";
    status.classList.add("is-warning");
    scenarioSelect.innerHTML = '<option value="">Unavailable</option>';
    scenarioSelect.disabled = true;
    startInput.disabled = true;
    sourceInput.disabled = true;
    destinationInput.disabled = true;
    vrfInput.disabled = true;
    familySelect.disabled = true;
    typeSelect.disabled = true;
    policySelect.disabled = true;
    steeringSelect.disabled = true;
    validationSelect.disabled = true;
    run.disabled = true;
    byId("mn-route-empty").innerHTML = `<strong>Route tracing is not advertised by this assembly.</strong><span>${escapeHtml(state.routeCapabilityError || "The topology remains available without a route resolver.")}</span>`;
    return;
  }
  const params = new URLSearchParams(location.search);
  const missingRouteDeclarations = [];
  if (!state.routeCapabilities.scenarios.length) missingRouteDeclarations.push("trace scenario");
  if (!state.routeCapabilities.policies.length) missingRouteDeclarations.push("resolution policy");
  status.textContent = missingRouteDeclarations.length ? "tracer incomplete" : "resolvers ready";
  status.classList.toggle("is-warning", Boolean(missingRouteDeclarations.length));
  scenarioSelect.innerHTML = state.routeCapabilities.scenarios.map((scenario) =>
    `<option value="${escapeHtml(scenario.scenario_id)}" title="${escapeHtml(scenario.description)}">${escapeHtml(scenario.label)}</option>`
  ).join("") || '<option value="">No scenario advertised</option>';
  const requestedScenario = params.get("route_scenario") || state.routeCapabilities.default_scenario_id;
  scenarioSelect.value = state.routeCapabilities.scenarios.some((scenario) => scenario.scenario_id === requestedScenario)
    ? requestedScenario : state.routeCapabilities.scenarios[0]?.scenario_id || "";
  const scenarioPair = directionalPairForScenario();
  byId("mn-route-starts").innerHTML = state.routeCapabilities.start_points.map((point) =>
    `<option value="${escapeHtml(routeStartDisplayValue(point))}">${escapeHtml(point.node_id || point.start_id)}</option>`
  ).join("");
  byId("mn-route-sources").innerHTML = state.routeCapabilities.sources.map((source) =>
    `<option value="${escapeHtml(routeEndpointInputValue("source", source.source_id))}">${escapeHtml(source.resource_id || source.source_id)}</option>`
  ).join("");
  byId("mn-route-destinations").innerHTML = state.routeCapabilities.destinations.map((destination) =>
    `<option value="${escapeHtml(routeEndpointInputValue("destination", destination.destination_id))}">${escapeHtml(destination.label || destination.destination_id)}</option>`
  ).join("");
  byId("mn-route-vrfs").innerHTML = state.routeCapabilities.vrfs.map((vrf) =>
    `<option value="${escapeHtml(vrf.vrf)}">${escapeHtml(vrf.label)}</option>`
  ).join("");
  setRouteEndpointInput("source", params.get("route_source") || scenarioPair?.forward?.source_id || state.routeCapabilities.default_source);
  setRouteEndpointInput("destination", params.get("route_destination") || scenarioPair?.forward?.destination_id || state.routeCapabilities.default_destination);
  const scenario = selectedRouteScenario();
  const sourceStart = state.routeCapabilities.start_points.find(
    (point) => point.node_id === selectedRouteEndpoint("source")?.node_id
  );
  const scenarioStart = routeStartSelectorValue(scenario?.default_start);
  setRouteStartInput(
    params.get("route_start")
    || scenarioStart
    || state.routeCapabilities.default_start
    || sourceStart?.start_id
  );
  familySelect.innerHTML = state.routeCapabilities.route_families.map((family) => {
    const suffix = [family.address_family, family.safi].filter(Boolean).join("/");
    return `<option value="${escapeHtml(family.route_family)}">${escapeHtml(`${family.label}${suffix && suffix !== family.route_family ? ` / ${suffix}` : ""}`)}</option>`;
  }).join("") || '<option value="">Plug-in default</option>';
  const requestedFamily = params.get("route_family") || scenarioPair?.forward?.route_family || scenario?.route_family
    || scenario?.address_family || state.routeCapabilities.default_route_family;
  typeSelect.innerHTML = state.routeCapabilities.route_types.map((type) =>
    `<option value="${escapeHtml(type.type_id)}">${escapeHtml(type.label)}</option>`
  ).join("") || '<option value="">Plug-in default</option>';
  policySelect.innerHTML = state.routeCapabilities.policies.map((policy) =>
    `<option value="${escapeHtml(policy)}">${escapeHtml(titleCase(policy))}</option>`
  ).join("") || '<option value="">No policy advertised</option>';
  const requestedType = params.get("route_type") || scenarioPair?.forward?.route_type || scenario?.route_type
    || state.routeCapabilities.default_route_type;
  const requestedVrf = params.get("route_vrf") || scenario?.vrf || scenario?.vrf_id || state.routeCapabilities.default_vrf;
  applyCompatibleRouteContext({
    routeType: requestedType,
    routeFamily: requestedFamily,
    vrf: requestedVrf,
    scenario,
  });
  const requestedPolicy = params.get("route_policy") || state.routeCapabilities.default_policy;
  policySelect.value = state.routeCapabilities.policies.includes(requestedPolicy)
    ? requestedPolicy
    : state.routeCapabilities.policies[0] || "";
  const requestedSteering = params.get("route_steering")
    || scenario?.steering_profile_id
    || state.routeCapabilities.default_steering_profile;
  renderRouteSteeringProfiles(scenario, requestedSteering);
  const requestedValidation = params.get("route_direction") || "bidirectional";
  validationSelect.value = ["forward", "reverse", "bidirectional"].includes(requestedValidation)
    ? requestedValidation : requestedValidation === "both" ? "bidirectional" : "bidirectional";
  scenarioSelect.disabled = !state.routeCapabilities.scenarios.length;
  startInput.disabled = false;
  sourceInput.disabled = false;
  destinationInput.disabled = false;
  vrfInput.disabled = false;
  familySelect.disabled = false;
  typeSelect.disabled = false;
  policySelect.disabled = !state.routeCapabilities.policies.length;
  validationSelect.disabled = false;
  run.disabled = Boolean(missingRouteDeclarations.length);
  if (missingRouteDeclarations.length) {
    byId("mn-route-empty").innerHTML = `<strong>Route tracing is missing required plug-in declarations.</strong><span>Advertise a ${escapeHtml(missingRouteDeclarations.join(" and "))} before submitting a trace.</span>`;
  }
  syncRouteStartControlState();
}

function routePathNodeRefs(path) {
  const occurrences = firstArray(path?.node_occurrences);
  if (occurrences.length) {
    return occurrences.map((occurrence, index) => ({
      ...occurrence.ref,
      route_occurrence_id: occurrence.occurrence_id,
      route_occurrence_index: Number(occurrence.occurrence_index ?? index),
    }));
  }
  const refs = [];
  for (const segment of routeForwardingSegments(path)) {
    for (const ref of [segment.source, segment.target]) {
      if (!ref?.member_id && !ref?.node_id) continue;
      const previous = refs[refs.length - 1];
      if (previous?.member_id === ref.member_id && previous?.node_id === ref.node_id) continue;
      refs.push(ref);
    }
  }
  return refs;
}

function routeBadge(label, className = "") {
  return `<span class="mn-route-badge ${className}">${escapeHtml(label)}</span>`;
}

function routeEndpointLabel(trace, side) {
  const endpoint = trace?.request?.[side] || trace?.[side] || {};
  const id = String(endpoint?.[`${side}_id`] ?? endpoint?.source_id ?? endpoint?.destination_id ?? trace?.request?.[`${side}_id`] ?? "");
  const capabilities = side === "source" ? state.routeCapabilities?.sources || [] : state.routeCapabilities?.destinations || [];
  const idField = side === "source" ? "source_id" : "destination_id";
  const capability = capabilities.find((item) => item[idField] === id || item.value === id)
    || capabilities.find((item) => item.node_id && item.node_id === endpoint?.node_id);
  const node = selectedResultNodes().find((item) => item.node_id === endpoint?.node_id || item.member_id === endpoint?.member_id);
  return capability?.label || node?.label || endpoint?.label || endpoint?.value || endpoint?.node_id || id || (side === "source" ? "Source" : "Destination");
}

function traceIsInconsistent(trace) {
  return routeConsistencyIsInconsistent(trace)
    || Boolean((trace?.paths || []).some(pathIsInconsistent));
}

function traceIsIncomplete(trace) {
  return routeCompletenessIsUnresolved(trace)
    || routeCompletenessIsInferred(trace)
    || routeCompletenessIsUnknown(trace)
    || Boolean((trace?.paths || []).some((path) => pathIsUnresolved(path) || pathIsInferred(path)));
}

function traceDirectionState(trace) {
  if (!trace) return { code: "not_run", label: "not run", className: "" };
  const paths = trace.paths || [];
  const activePaths = paths.filter(pathIsUsableActive);
  if (paths.some(routeValueIsCycle) && !activePaths.length) {
    return { code: "cycle", label: "loop detected", className: "is-cycle", reason: "cycle" };
  }
  if (paths.some(routeValueIsPolicyBlocked) && !activePaths.length) {
    const presentation = routePolicyPresentation(paths.find(routeValueIsPolicyBlocked));
    return {
      code: "policy_blocked",
      label: presentation.label,
      className: "is-policy-blocked",
      reason: presentation.category,
    };
  }
  if (paths.some(pathIsDead) && !activePaths.length) {
    return { code: "dropped", label: "dropped", className: "is-error", reason: "dropped" };
  }
  if (trace.reachable === false && paths.some(pathIsDead)) {
    return { code: "dropped", label: "dropped", className: "is-error", reason: "dropped" };
  }
  if (trace.reachable === false && traceIsControlPlaneOnly(trace)) {
    return { code: "control_plane_only", label: "not installed", className: "is-warning", reason: "control_plane_only" };
  }
  if (trace.reachable === false) {
    return trace.complete === false || traceIsIncomplete(trace)
      ? { code: "unresolved", label: "unresolved", className: "is-error" }
      : { code: "dropped", label: "dropped", className: "is-error" };
  }
  if (!paths.length || paths.every(pathIsUnresolved)) {
    return { code: "unresolved", label: "unresolved", className: "is-error" };
  }
  if (traceIsInconsistent(trace)) {
    return { code: "inconsistent", label: "inconsistent", className: "is-error" };
  }
  if (traceIsIncomplete(trace)) {
    return { code: "best_effort", label: "best effort", className: "is-warning" };
  }
  if (!activePaths.length) {
    return { code: "unknown", label: "state unknown", className: "is-warning" };
  }
  return {
    code: "resolved",
    label: paths.length === 1 ? "1 path" : `${paths.length} candidates`,
    className: "is-good",
  };
}

function routeDirectionLabel(direction) {
  return direction === "reverse" ? "Return" : "Forward";
}

function routeFlowEndpointLabel(trace, side) {
  const endpoint = trace?.flow?.[side] || trace?.traffic_endpoints?.[side] || trace?.request?.flow?.[side] || {};
  const endpointId = String(endpoint.endpoint_id || endpoint.source_id || endpoint.destination_id || "");
  const capabilities = side === "source"
    ? state.routeCapabilities?.sources || []
    : state.routeCapabilities?.destinations || [];
  const capability = capabilities.find((item) =>
    item.endpoint_id === endpointId
    || item.source_id === endpointId
    || item.destination_id === endpointId
  ) || capabilities.find((item) => item.node_id && item.node_id === endpoint.node_id);
  return capability?.label || endpoint.label || endpoint.value || endpoint.node_id || endpointId
    || (side === "source" ? "traffic source" : "traffic destination");
}

function routeTraceStartLabel(trace) {
  const start = trace?.trace_start || trace?.starting_point || trace?.request?.trace_starts?.[trace?.direction] || {};
  const point = state.routeCapabilities?.start_points.find((item) =>
    item.start_id === start.start_id || item.node_id === start.node_id || item.member_id === start.member_id
  );
  return point?.label || start.label || start.node_id || start.member_id || "trace start";
}

function renderDirectionTabs() {
  const container = byId("mn-route-direction-tabs");
  if (!container) return;
  container.querySelectorAll("[data-route-direction]").forEach((button) => {
    const direction = button.dataset.routeDirection;
    const trace = state.routeTraces[direction];
    const status = traceDirectionState(trace);
    button.disabled = !trace;
    button.setAttribute("aria-selected", String(direction === state.activeRouteDirection));
    button.querySelector("span").textContent = routeDirectionLabel(direction);
    if (trace) {
      const flowSource = routeFlowEndpointLabel(trace, "source");
      const flowDestination = routeFlowEndpointLabel(trace, "destination");
      const start = routeTraceStartLabel(trace);
      button.querySelector("small").textContent = direction === "forward"
        ? `${start} → ${flowDestination} (flow ${flowSource} → ${flowDestination})`
        : `${start} → ${flowSource} (return target)`;
    } else {
      button.querySelector("small").textContent = direction === "forward"
        ? "Trace start → traffic destination"
        : "Destination side → traffic source";
    }
    const indicator = button.querySelector("[data-direction-state]");
    indicator.textContent = status.label;
    indicator.className = status.className;
  });
}

function selectRouteDirection(direction) {
  const trace = state.routeTraces[direction];
  if (!trace) return;
  clearRoutePacketSelection();
  state.selectedRoutePathIds[state.activeRouteDirection] = state.selectedRoutePathId;
  state.activeRouteDirection = direction;
  state.routeTrace = trace;
  const remembered = state.selectedRoutePathIds[direction];
  const validRemembered = trace.paths.some((path) => path.path_id === remembered) ? remembered : "";
  const focusedFallback = defaultRoutePath(trace)?.path_id || "";
  state.selectedRoutePathId = validRemembered || (state.routeGraphMode === "focused" ? focusedFallback : "");
  state.selectedRoutePathIds[direction] = state.selectedRoutePathId;
  state.requestedRoutePathId = state.selectedRoutePathId;
  clearRoutePathPreview();
  clearRouteHover();
  renderRouteTrace();
  renderMap();
  if (state.routeGraphMode === "all") requestAnimationFrame(() => fitGraphViewport("mn-route-map-stage", "route"));
  renderRouteTables();
  syncUrl();
}

function bidirectionalSummary() {
  const forward = state.routeTraces.forward;
  const reverse = state.routeTraces.reverse;
  const symmetry = state.routeBundle?.symmetry || {};
  if (!forward || !reverse) {
    return { code: "single_direction", label: "Single direction", detail: "Opposite direction not requested", className: "is-unresolved" };
  }
  const forwardState = traceDirectionState(forward);
  const reverseState = traceDirectionState(reverse);
  const endpointState = normalizedRouteEnum(
    symmetry.endpoint_state
    || state.routeBundle?.raw?.endpoint_reachability?.state
    || state.routeBundle?.raw?.consistency?.state
    || symmetry.state,
  );
  const pathRelation = normalizedRouteEnum(
    symmetry?.path_relation?.state
    || state.routeBundle?.raw?.path_relation?.state,
  );
  const unavailableCodes = new Set([
    "dropped",
    "unresolved",
    "control_plane_only",
    "cycle",
    "policy_blocked",
  ]);
  const forwardUnavailable = forward.reachable === false || unavailableCodes.has(forwardState.code);
  const reverseUnavailable = reverse.reachable === false || unavailableCodes.has(reverseState.code);
  const oneWayStates = new Set(["one_way", "one_way_reachable", "one_way_failure", "directional_drop", "inconsistent_one_way_drop"]);
  const incompleteStates = new Set([
    "unknown",
    "incomplete",
    "partial",
    "partial_active_reachability",
    "partially_reachable",
    "unknown_incomplete",
    "unknown_reachability",
    "indeterminate",
    "not_compared",
  ]);
  const incompleteComparison = incompleteStates.has(endpointState)
    || [forwardState.code, reverseState.code].some((code) => code === "unknown" || code === "best_effort");
  if (incompleteComparison) {
    return {
      code: "incomplete",
      label: "Endpoint validation incomplete",
      detail: symmetry.endpoint_state || symmetry.state || "At least one endpoint goal is unresolved",
      className: "is-unresolved",
    };
  }
  const oneWay = symmetry.one_way === true || oneWayStates.has(endpointState)
    || forwardUnavailable !== reverseUnavailable;
  if (oneWay) return { code: "one_way", label: "One-way failure", detail: `${forwardState.label} forward · ${reverseState.label} return`, className: "is-inconsistent" };
  if (endpointState === "both_unreachable" || (forwardUnavailable && reverseUnavailable)) {
    return { code: "both_unreachable", label: "Both directions fail", detail: `${forwardState.label} forward · ${reverseState.label} return`, className: "is-inconsistent" };
  }
  if (endpointState === "bidirectionally_reachable" || (!forwardUnavailable && !reverseUnavailable)) {
    if (pathRelation === "not_comparable") {
      return {
        code: "compared",
        label: "Both traffic endpoints are reachable",
        detail: "Return reaches the traffic source; it is not required to revisit the forward observation node.",
        className: "is-good",
      };
    }
    if (pathRelation === "asymmetric") {
      return {
        code: "asymmetric",
        label: "Both endpoints reachable; paths differ",
        detail: "Path shape is informational and does not make endpoint reachability inconsistent.",
        className: "is-good",
      };
    }
  }
  return { code: "compared", label: "Both traffic endpoints are reachable", detail: `${forwardState.label} forward · ${reverseState.label} return`, className: "is-good" };
}

function routeSequenceForDirection(direction) {
  const symmetry = state.routeBundle?.symmetry || {};
  const declared = firstArray(
    direction === "reverse" ? symmetry.reverse_node_sequence : symmetry.forward_node_sequence,
  ).map(String).filter(Boolean);
  if (declared.length) return declared;
  const path = defaultRoutePath(state.routeTraces[direction]);
  return routePathNodeRefs(path).map((ref) => String(ref?.node_id || "")).filter(Boolean);
}

function routeDirectionEdgeKey(left, right) {
  return [String(left || ""), String(right || "")].sort().join("|");
}

function routeDirectionEdges(sequence) {
  return new Set(sequence.slice(0, -1).map((nodeId, index) =>
    routeDirectionEdgeKey(nodeId, sequence[index + 1])
  ));
}

function routeSequenceLabel(sequence) {
  return sequence.map((nodeId) => {
    const node = selectedResultNodes().find((candidate) => candidate.node_id === nodeId);
    return node?.label || nodeId;
  }).join(" → ");
}

function routeDirectionalDifference() {
  const relationState = normalizedRouteEnum(
    state.routeBundle?.symmetry?.path_relation?.state
    || state.routeBundle?.raw?.path_relation?.state
    || state.routeBundle?.symmetry?.state,
  );
  if (!new Set(["asymmetric", "asymmetric_reachable", "different_paths"]).has(relationState)) return null;
  const forwardSequence = routeSequenceForDirection("forward");
  const reverseSequence = routeSequenceForDirection("reverse");
  if (forwardSequence.length < 2 || reverseSequence.length < 2) return null;
  const direction = state.activeRouteDirection === "reverse" ? "reverse" : "forward";
  const oppositeDirection = direction === "reverse" ? "forward" : "reverse";
  const currentSequence = direction === "reverse" ? reverseSequence : forwardSequence;
  const oppositeSequence = direction === "reverse" ? forwardSequence : reverseSequence;
  const oppositeNodes = new Set(oppositeSequence);
  const oppositeEdges = routeDirectionEdges(oppositeSequence);
  return {
    direction,
    oppositeDirection,
    currentSequence,
    oppositeSequence,
    currentOnlyNodeIds: new Set(currentSequence.filter((nodeId) => !oppositeNodes.has(nodeId))),
    currentOnlyEdgeKeys: new Set([...routeDirectionEdges(currentSequence)].filter((edgeKey) => !oppositeEdges.has(edgeKey))),
    title: "Asymmetric paths — both resolved",
    detail: `Forward: ${routeSequenceLabel(forwardSequence)} · Return: ${routeSequenceLabel(reverseSequence)}`,
  };
}

function routePathMatchesDirectionalDifference(path, difference) {
  if (!path || !difference) return false;
  const sequence = routePathNodeRefs(path).map((ref) => String(ref?.node_id || "")).filter(Boolean);
  return sequence.length === difference.currentSequence.length
    && sequence.every((nodeId, index) => nodeId === difference.currentSequence[index]);
}

function renderRouteDirectionalDifference() {
  const difference = routeDirectionalDifference();
  const callout = byId("mn-route-direction-difference");
  if (!callout) return difference;
  callout.hidden = !difference;
  if (!difference) {
    callout.innerHTML = "";
    return null;
  }
  callout.innerHTML = `<strong>${escapeHtml(difference.title)}</strong><span>${escapeHtml(difference.detail)}</span><small>Amber marks a direction-only difference unless a stronger path-local fault style takes precedence.</small>`;
  return difference;
}

function routeTraceOutcome(trace, directional) {
  if (trace.reachable === false && traceIsControlPlaneOnly(trace) && !trace.paths.some(pathIsDead)) {
    return {
      code: "control_plane_only",
      label: "Control-plane route is not installed",
      detail: controlPlaneOnlyReason(trace),
      className: "is-warning",
    };
  }
  if (new Set(["one_way", "both_unreachable"]).has(directional.code)) {
    return { code: directional.code, label: directional.label, detail: directional.detail, className: "is-inconsistent" };
  }
  const directionState = traceDirectionState(trace);
  if (directionState.code === "cycle") {
    return {
      code: "cycle",
      label: "Forwarding loop detected",
      detail: "The trace revisits the same canonical forwarding state. Repeated visits remain visible in the graph.",
      className: "is-cycle",
    };
  }
  if (directionState.code === "policy_blocked") {
    const presentation = routePolicyPresentation(trace.paths.find(routeValueIsPolicyBlocked));
    return {
      code: "policy_blocked",
      label: presentation.label,
      detail: presentation.detail,
      className: "is-policy-blocked",
    };
  }
  if (trace.reachable === false || directionState.code === "dropped") {
    return { code: "unreachable", label: "Route is not reachable", detail: "No complete forwarding path was resolved for the selected direction.", className: "is-inconsistent" };
  }
  const incomplete = traceIsIncomplete(trace) || directional.code === "incomplete";
  const inconsistent = traceIsInconsistent(trace);
  if (incomplete && inconsistent) {
    return { code: "incomplete_inconsistent", label: "Incomplete and inconsistent", detail: "Evidence is missing and the available nodes or status layers also disagree.", className: "is-inconsistent" };
  }
  if (inconsistent) {
    return { code: "inconsistent", label: "Forwarding is inconsistent", detail: "Nodes or status layers disagree about the selected path.", className: "is-inconsistent" };
  }
  if (incomplete) {
    return { code: "incomplete", label: "Trace is incomplete", detail: "At least one node-local resolution step is missing, unresolved, or inferred.", className: "is-unresolved" };
  }
  if (directional.code === "asymmetric") {
    return { code: "asymmetric", label: "Endpoints reachable; paths differ", detail: "Forward and return path shape differs, but both declared traffic endpoints are reachable.", className: "is-good" };
  }
  if (directionState.code === "unknown") {
    return { code: "unknown", label: "Forwarding state is unknown", detail: "The plug-in did not return enough normalized path state to classify this route.", className: "is-unresolved" };
  }
  return { code: "reachable", label: "Route is reachable", detail: directional.detail || "The selected forwarding path is resolved from the available observations.", className: "is-good" };
}

function selectedPathEvidence(path) {
  const status = pathStatusSummary(path);
  const detail = [path?.completeness && titleCase(path.completeness), path?.perspective && titleCase(path.perspective)]
    .filter(Boolean).join(" · ") || "Path-local evidence";
  const className = routeValueIsCycle(path) ? "is-cycle"
    : routeValueIsPolicyBlocked(path) ? "is-policy-blocked"
      : pathIsDead(path) || pathIsInconsistent(path) ? "is-inconsistent"
    : pathIsUnresolved(path) || pathIsInferred(path) || routeCompletenessIsUnknown(path)
      ? "is-unresolved" : "is-good";
  return { status, detail, className };
}

function routePathBadges(path) {
  const badges = [];
  const roleClasses = routeRoleClasses(path);
  const controlPlaneOnly = pathIsControlPlaneOnly(path);
  const activity = normalizedRouteEnum(path?.activity);
  const selection = firstRouteEnum(path?.selection, path?.eligibility, path?.alternative_state);
  if (roleClasses.includes("is-primary")) badges.push(routeBadge("Primary", "is-primary"));
  if (roleClasses.includes("is-ecmp")) badges.push(routeBadge("Active ECMP", "is-ecmp"));
  if (roleClasses.includes("is-standby") && !controlPlaneOnly) {
    badges.push(routeBadge(activity === "inactive" ? "Inactive candidate" : "Standby", "is-standby"));
  }
  if (controlPlaneOnly) badges.push(routeBadge("Control-plane only / not installed", "is-control-plane-only"));
  if (new Set(["comparison_only", "control_expected_not_observed"]).has(selection)) {
    badges.push(routeBadge("Control expected / comparison only", "is-standby"));
  }
  if (path.perspective) badges.push(routeBadge(titleCase(path.perspective), "is-inferred"));
  if (routeValueIsCycle(path)) badges.push(routeBadge("Forwarding loop", "is-cycle"));
  if (routeValueIsPolicyBlocked(path)) {
    badges.push(routeBadge(routePolicyPresentation(path).label, "is-policy-blocked"));
  }
  if (pathIsDead(path)) badges.push(routeBadge("Dead / dropped", "is-dead"));
  if (pathIsInconsistent(path)) badges.push(routeBadge("Inconsistent", "is-inconsistent"));
  if (pathIsInferred(path)) badges.push(routeBadge("Best-effort inferred", "is-inferred"));
  if (!routeValueIsCycle(path) && !routeValueIsPolicyBlocked(path)
    && (pathIsUnresolved(path) || routeCompletenessIsUnknown(path))) {
    badges.push(routeBadge("Unresolved", "is-unresolved"));
  }
  return badges.join("");
}

function pathStatusSummary(path) {
  if (routeValueIsCycle(path)) {
    const reason = firstRouteEnum(path?.terminal_reason, path?.termination_reason);
    return reason ? `Loop detected: ${titleCase(reason)}` : "Forwarding loop detected";
  }
  if (routeValueIsPolicyBlocked(path)) {
    return routePolicyPresentation(path).label;
  }
  if (pathIsDead(path)) {
    const forwardingPerspectives = new Set(["forwarding_observed", "fib_observed", "hardware_observed"]);
    const prefix = forwardingPerspectives.has(normalizedRouteEnum(path?.perspective))
      ? "Observed FIB selected but unusable" : "Dead / dropped";
    return path.terminal_reason ? `${prefix}: ${titleCase(path.terminal_reason)}` : prefix;
  }
  if (pathIsControlPlaneOnly(path)) return "Control-plane only — not installed";
  const selection = firstRouteEnum(path?.selection, path?.eligibility, path?.alternative_state);
  if (new Set(["comparison_only", "control_expected_not_observed"]).has(selection)) {
    return "Control expected / comparison only";
  }
  if (pathIsInconsistent(path)) return "Layer disagreement";
  if (pathIsUnresolved(path)) return "Incomplete";
  if (pathIsInferred(path)) return "Best-effort continuation";
  if (routeCompletenessIsUnknown(path)) return "Completeness unknown";
  if (ROUTE_INACTIVE_STATES.has(normalizedRouteEnum(path?.activity))
    || ROUTE_STANDBY_STATES.has(selection)
    || new Set(["standby", "alternative"]).has(normalizedRouteEnum(path?.role))) return "Available alternative";
  if (explicitRouteDisposition(path) === "resolved") return "Resolved";
  return "Unknown";
}

function routeStepMarkup(step, index) {
  const provider = step?.provided_by?.plugin_id ?? step?.plugin_provenance?.plugin_id ?? step?.text_source;
  const textMarkup = step.parts.length
    ? step.parts.map((part, partIndex) => `<span class="mn-route-step-part ${step.parts.length > 1 && partIndex === 0 ? "is-context" : "is-explanation"}" tabindex="0" data-route-kind="resolution-part" data-route-id="${escapeHtml(part.part_id)}" data-route-tokens="${routeTokensAttribute(part.component_tokens)}" data-route-focus-targets="${routeFocusTargetsAttribute(part.highlight_target_ids)}">${escapeHtml(part.text)}</span>`).join("")
    : escapeHtml(step.text);
  return `<li class="mn-route-step ${routeQualityClasses(step).join(" ")}" tabindex="0" data-route-kind="resolution-step" data-route-id="${escapeHtml(step.step_id)}" data-route-tokens="${routeTokensAttribute(step.component_tokens)}" data-route-focus-targets="${routeFocusTargetsAttribute(step.highlight_target_ids)}" data-route-packet-refs="${packetRefsAttribute(step.packet_refs)}">
    <span class="mn-route-step-index">${index + 1}</span>
    <div><p>${textMarkup}</p>${step.detail ? `<small>${escapeHtml(step.detail)}</small>` : ""}${provider ? `<code>${escapeHtml(`provided by ${provider}`)}</code>` : ""}</div>
  </li>`;
}

function routeDiagnosticItems(path) {
  const diagnostics = [];
  if (routeValueIsCycle(path)) {
    const closingSegment = routeForwardingSegments(path).find((segment, index) =>
      routeSegmentIsCycleClosing(segment, path, index)
    );
    const firstStep = Number(path?.cycle?.first_step ?? 0);
    const closingStep = Number(path?.cycle?.closing_step ?? 0);
    const repeatedState = path?.cycle?.repeated_state;
    const stateDetail = repeatedState && typeof repeatedState === "object"
      ? Object.entries(repeatedState).slice(0, 8)
        .map(([key, value]) => `${titleCase(key)}=${typeof value === "object" ? JSON.stringify(value) : value}`)
        .join(" · ")
      : "";
    diagnostics.push({
      step_id: `${path.path_id}:cycle-diagnostic`,
      text: firstStep && closingStep
        ? `Forwarding state at visit ${closingStep} repeats visit ${firstStep}.`
        : "The same canonical forwarding state is reached again.",
      detail: stateDetail || "The core stopped traversal before following the loop again.",
      result: "cycle",
      cycle: path.cycle || {},
      parts: [],
      component_tokens: closingSegment?.component_tokens || [],
      highlight_target_ids: closingSegment?.highlight_target_ids || [],
      provided_by: null,
    });
  }
  diagnostics.push(...firstArray(path?.policy_decisions).map((decision) => ({
    ...decision,
    detail: decision.detail || "A plug-in-declared forwarding policy excludes this candidate.",
    policy_decisions: [decision],
  })));
  return diagnostics;
}

function routeFindingsMarkup(trace, selectedPathId = "") {
  const relevantFindings = trace.findings.filter((finding) => !finding.path_ids.length || !selectedPathId || finding.path_ids.includes(selectedPathId));
  const findingMarkup = relevantFindings.map((finding) => {
    const severityCode = normalizedRouteEnum(finding.severity);
    const severity = new Set(["error", "critical", "fatal"]).has(severityCode) ? "is-inconsistent"
      : new Set(["warning", "warn", "partial", "incomplete", "inferred"]).has(severityCode) ? "is-inferred" : "is-good";
    return `<article class="mn-route-finding ${severity}" data-route-kind="finding" data-route-id="${escapeHtml(finding.finding_id)}" data-route-tokens="${routeTokensAttribute(finding.component_tokens)}"><span>${escapeHtml(titleCase(finding.severity))}</span><strong>${escapeHtml(finding.title)}</strong><p>${escapeHtml(finding.message)}</p></article>`;
  }).join("");
  if (findingMarkup) return findingMarkup;
  const directionalDifference = routeDirectionalDifference();
  if (directionalDifference) {
    return `<article class="mn-route-finding is-inferred"><span>PAIR COMPARISON</span><strong>No path-local fault</strong><p>${escapeHtml(`${directionalDifference.detail}. The core compared the plug-in-provided active paths; each plug-in still owns its local next-hop decision.`)}</p></article>`;
  }
  return '<article class="mn-route-finding is-unresolved"><span>INFO</span><strong>No findings returned</strong><p>No finding record was supplied for this path.</p></article>';
}

function revealFocusedRouteEntry() {
  const entry = state.routeTableSnapshot?.items.find((item) => item.route_entry_id === state.focusedRouteEntryId);
  if (!entry) return;
  Object.keys(state.routeTableFilters).forEach((key) => { state.routeTableFilters[key] = ""; });
  state.routeTableFilters.node = entry.node_id;
  state.routeTableOpenNodes.add(entry.node_id);
  byId("mn-route-table-search").value = "";
  byId("mn-route-table-destination-filter").value = "";
  byId("mn-route-table-node-filter").value = entry.node_id;
  renderRouteTables();
  requestAnimationFrame(() => document.querySelector(`[data-route-entry-id="${CSS.escape(entry.route_entry_id)}"]`)?.scrollIntoView({
    behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth",
    block: "center",
  }));
}

function renderRouteSeed() {
  const container = byId("mn-route-seed");
  const snapshot = state.routeTableSnapshot;
  const entry = snapshot?.items.find((item) => item.route_entry_id === state.focusedRouteEntryId);
  if (!entry) {
    container.hidden = true;
    container.innerHTML = "";
    return;
  }
  const group = snapshot.groups.find((item) => item.node_id === entry.node_id);
  container.hidden = false;
  container.innerHTML = `<span>Seeded from route table</span><strong>${escapeHtml(`${group?.label || entry.node_id} · ${entry.prefix} · ${entry.vrf}`)}</strong><button type="button" data-route-seed-back>Show source row</button>`;
  container.querySelector("[data-route-seed-back]").addEventListener("click", revealFocusedRouteEntry);
}

function updateRouteViewChrome() {
  const trace = state.routeTrace;
  const paths = trace?.paths || [];
  const pinned = pinnedRoutePath();
  const allPaths = state.routeGraphMode === "all";
  const workbench = document.querySelector(".mn-route-workbench");
  const result = byId("mn-route-result");
  const stage = byId("mn-route-map-stage");
  document.querySelectorAll("button[data-route-graph-mode]").forEach((button) => {
    button.setAttribute("aria-pressed", String(button.dataset.routeGraphMode === state.routeGraphMode));
  });
  byId("mn-route-view-count").textContent = paths.length
    ? `${paths.length} candidate path${paths.length === 1 ? "" : "s"}${paths.length >= MAX_ROUTE_PATHS ? ` (first ${MAX_ROUTE_PATHS})` : ""}`
    : "No candidates yet";
  const clear = byId("mn-route-clear-path");
  clear.hidden = !(allPaths && pinned);
  if (pinned) clear.textContent = `Clear ${pinned.label}`;
  const hideDetail = Boolean(trace && paths.length && allPaths && !pinned);
  result.hidden = hideDetail;
  workbench?.classList.toggle("is-overview-only", hideDetail);
  stage?.classList.toggle("is-all-paths", allPaths);
  stage?.classList.toggle("is-path-pinned", Boolean(pinned));
  stage?.classList.toggle("is-focused-path", !allPaths);
  if (stage) {
    stage.dataset.routeGraphView = state.routeGraphMode;
    if (pinned) stage.dataset.routePinnedPath = pinned.path_id; else delete stage.dataset.routePinnedPath;
  }
  byId("mn-route-map-eyebrow").textContent = allPaths ? "ALL CANDIDATE ROUTES" : "FOCUSED ROUTE TOPOLOGY";
  byId("mn-route-link-layer").setAttribute("aria-label", allPaths ? "All candidate route segments" : "Selected directional route segments");
  byId("mn-route-map-stage").setAttribute("aria-label", allPaths
    ? "All candidate route paths. Choose a path from an edge or node."
    : "Currently focused route topology");
}

function renderUnselectedRoutePathTabs(trace) {
  const indexedPaths = (trace?.paths || []).map((path, index) => ({ path, index }));
  const groups = [
    ["Active paths", indexedPaths.filter(({ path }) => pathIsUsableActive(path))],
    ["Looped paths", indexedPaths.filter(({ path }) => routeValueIsCycle(path))],
    ["Policy-blocked paths", indexedPaths.filter(({ path }) =>
      !routeValueIsCycle(path) && routeValueIsPolicyBlocked(path))],
    ["Selected but unusable", indexedPaths.filter(({ path }) => !pathIsControlPlaneOnly(path)
      && !pathIsUsableActive(path)
      && !routeValueIsCycle(path)
      && !routeValueIsPolicyBlocked(path)
      && (pathIsDead(path)
        || pathIsUnresolved(path)
        || pathIsInconsistent(path)))],
    ["Control-plane evidence", indexedPaths.filter(({ path }) => pathIsControlPlaneOnly(path))],
  ];
  const groupedIds = new Set(groups.flatMap(([, items]) => items.map(({ path }) => path.path_id)));
  groups.push(["Alternatives", indexedPaths.filter(({ path }) => !groupedIds.has(path.path_id))]);
  const pathMarkup = ({ path, index }) => {
    const nodes = routePathNodeRefs(path).map(nodeLabelForRef);
    return `<button type="button" role="tab" aria-selected="false" tabindex="0" class="mn-route-path-tab ${routeQualityClasses(path).join(" ")}" data-route-path="${escapeHtml(path.path_id)}">
      <span class="mn-route-path-number">${index + 1}</span>
      <span><strong>${escapeHtml(path.label)}</strong><small>${escapeHtml(nodes.join(" → ") || "No resolved node sequence")}</small><em>${escapeHtml(pathStatusSummary(path))}</em></span>
    </button>`;
  };
  const container = byId("mn-route-path-tabs");
  container.innerHTML = groups.filter(([, items]) => items.length).map(([label, items]) =>
    `<div class="mn-route-path-group-label" role="presentation"><strong>${escapeHtml(label)}</strong><span>${items.length}</span></div>${items.map(pathMarkup).join("")}`
  ).join("");
  container.querySelectorAll("[data-route-path]").forEach((button) => {
    button.addEventListener("click", () => selectRoutePath(button.dataset.routePath));
  });
}

function renderRouteTrace() {
  renderDirectionTabs();
  renderRouteSeed();
  updateRouteViewChrome();
  renderRoutePacketEvolution(null);
  const empty = byId("mn-route-empty");
  const content = byId("mn-route-content");
  const mapPanel = document.querySelector(".mn-trace-map-panel");
  if (state.routePending) {
    if (mapPanel) mapPanel.hidden = true;
    empty.hidden = false;
    content.hidden = true;
    empty.innerHTML = '<span class="mn-spinner" aria-hidden="true"></span><strong>Resolving candidate paths across node plug-ins…</strong><span>Inactive alternatives and uncertainty are retained.</span>';
    return;
  }
  const trace = state.routeTrace;
  if (!trace) {
    if (mapPanel) mapPanel.hidden = true;
    empty.hidden = false;
    content.hidden = true;
    empty.innerHTML = '<strong>Choose a trace start and traffic endpoints.</strong><span>Trace the route to compare forward, return, primary, and alternate paths.</span>';
    return;
  }
  if (!trace.paths.length) {
    if (mapPanel) mapPanel.hidden = true;
    empty.hidden = true;
    content.hidden = false;
    content.classList.add("is-no-path");
    const directional = bidirectionalSummary();
    const outcome = routeTraceOutcome(trace, directional);
    const traceRequest = trace.request || {};
    const traceVrf = trace?.vrf ?? traceRequest?.vrf ?? traceRequest?.vrf_id ?? "default";
    const traceFamily = trace?.route_family ?? trace?.address_family ?? traceRequest?.route_family ?? traceRequest?.address_family ?? "plug-in default";
    const traceType = trace?.route_type ?? traceRequest?.route_type ?? "plug-in default";
    const summaryClass = traceIsInconsistent(trace) ? "is-inconsistent" : "is-unresolved";
    byId("mn-route-summary").innerHTML = `
      <article><span>Routing context</span><strong>${escapeHtml(traceVrf)}</strong><small>${escapeHtml(`${traceFamily} · ${traceType}`)}</small></article>
      <article><span>Path choices</span><strong>0 active</strong><small>No candidate path returned</small></article>
      <article><span>Trace evidence</span><strong class="${summaryClass}">${escapeHtml(titleCase(trace.completeness))}</strong><small>${escapeHtml(titleCase(trace.consistency))}</small></article>`;
    const comparison = byId("mn-direction-comparison");
    comparison.className = `mn-direction-comparison ${outcome.className}`;
    comparison.innerHTML = `<span>Route outcome</span><div><strong>${escapeHtml(outcome.label)}</strong><small>${escapeHtml(`${routeFlowEndpointLabel(state.routeTraces.forward || trace, "source")} ⇄ ${routeFlowEndpointLabel(state.routeTraces.forward || trace, "destination")}`)}</small></div><div class="mn-route-outcome-detail"><strong>Endpoint result</strong><small>${escapeHtml(outcome.detail)}</small></div>`;
    byId("mn-route-findings").innerHTML = routeFindingsMarkup(trace);
    bindRouteCorrelationElements(content);
    return;
  }
  if (mapPanel) mapPanel.hidden = false;
  empty.hidden = true;
  content.hidden = false;
  content.classList.remove("is-no-path");
  const selected = selectedRoutePath();
  if (!selected) {
    renderUnselectedRoutePathTabs(trace);
    empty.hidden = true;
    content.hidden = true;
    return;
  }
  const activeCount = trace.paths.filter(pathIsUsableActive).length;
  const controlPlaneOnlyCount = trace.paths.filter(pathIsControlPlaneOnly).length;
  const cycleCount = trace.paths.filter(routeValueIsCycle).length;
  const policyBlockedCount = trace.paths.filter((path) =>
    !routeValueIsCycle(path) && routeValueIsPolicyBlocked(path)).length;
  const unusableCount = trace.paths.filter((path) => !pathIsControlPlaneOnly(path) && !pathIsUsableActive(path)
    && !routeValueIsCycle(path) && !routeValueIsPolicyBlocked(path)
    && (pathIsDead(path) || pathIsUnresolved(path) || pathIsInconsistent(path))).length;
  const alternativeCount = Math.max(
    0,
    trace.paths.length - activeCount - controlPlaneOnlyCount
      - cycleCount - policyBlockedCount - unusableCount,
  );
  const pathEvidence = selectedPathEvidence(selected);
  const directional = bidirectionalSummary();
  const outcome = routeTraceOutcome(trace, directional);
  const traceRequest = trace.request || {};
  const traceVrf = trace?.vrf ?? traceRequest?.vrf ?? traceRequest?.vrf_id ?? "default";
  const traceFamily = trace?.route_family ?? trace?.address_family ?? traceRequest?.route_family ?? traceRequest?.address_family ?? "plug-in default";
  const traceType = trace?.route_type ?? traceRequest?.route_type ?? "plug-in default";
  const flowSourceLabel = routeFlowEndpointLabel(trace, "source");
  const flowDestinationLabel = routeFlowEndpointLabel(trace, "destination");
  const directionalFlowLabel = state.activeRouteDirection === "reverse"
    ? `Return flow ${flowDestinationLabel} → ${flowSourceLabel}`
    : `Forward flow ${flowSourceLabel} → ${flowDestinationLabel}`;
  byId("mn-route-summary").innerHTML = `
    <article><span>Routing context</span><strong>${escapeHtml(traceVrf)}</strong><small>${escapeHtml(`${traceFamily} · ${traceType}`)}</small></article>
    <article><span>Directional goal</span><strong>${escapeHtml(`${routeTraceStartLabel(trace)} → ${state.activeRouteDirection === "reverse" ? flowSourceLabel : flowDestinationLabel}`)}</strong><small>${escapeHtml(directionalFlowLabel)}</small></article>
    <article><span>Path choices</span><strong>${formatInteger(activeCount)} active</strong><small>${alternativeCount} alternative · ${cycleCount} looped · ${policyBlockedCount} policy-blocked · ${unusableCount} unusable · ${controlPlaneOnlyCount} control-plane only · ${trace.paths.length} total</small></article>
    <article><span>Selected-path evidence</span><strong class="${pathEvidence.className}">${escapeHtml(pathEvidence.status)}</strong><small>${escapeHtml(pathEvidence.detail)}</small></article>`;
  const symmetryIssue = state.routeBundle?.symmetry?.issues?.[0];
  const symmetryEvidence = typeof symmetryIssue === "string" ? symmetryIssue
    : symmetryIssue?.message || symmetryIssue?.description || symmetryIssue?.title || "";
  const comparison = byId("mn-direction-comparison");
  comparison.className = `mn-direction-comparison ${outcome.className}`;
  const comparisonLabel = new Set(["incomplete", "incomplete_inconsistent", "unknown"]).has(outcome.code) ? "Resolution quality"
    : outcome.code === "unreachable" ? "Forwarding result"
      : directional.label === outcome.label ? "Forward / return" : directional.label;
  const evidenceMarkup = symmetryEvidence && symmetryEvidence !== outcome.detail
    ? `<span class="mn-route-specific-evidence">${escapeHtml(symmetryEvidence)}</span>` : "";
  comparison.innerHTML = `<span>Route outcome</span><div><strong>${escapeHtml(outcome.label)}</strong><small>${escapeHtml(`${routeFlowEndpointLabel(state.routeTraces.forward || trace, "source")} ⇄ ${routeFlowEndpointLabel(state.routeTraces.forward || trace, "destination")}`)}</small></div><div class="mn-route-outcome-detail"><strong>${escapeHtml(comparisonLabel)}</strong><small>${escapeHtml(outcome.detail || directional.detail)}</small>${evidenceMarkup}</div>`;
  const indexedPaths = trace.paths.map((path, index) => ({ path, index }));
  const activePaths = indexedPaths.filter(({ path }) => pathIsUsableActive(path));
  const controlPlaneOnlyPaths = indexedPaths.filter(({ path }) => pathIsControlPlaneOnly(path));
  const cyclePaths = indexedPaths.filter(({ path }) => routeValueIsCycle(path));
  const policyBlockedPaths = indexedPaths.filter(({ path }) =>
    !routeValueIsCycle(path) && routeValueIsPolicyBlocked(path));
  const unusablePaths = indexedPaths.filter(({ path }) => !pathIsControlPlaneOnly(path) && !pathIsUsableActive(path)
    && !routeValueIsCycle(path) && !routeValueIsPolicyBlocked(path)
    && (pathIsDead(path) || pathIsUnresolved(path) || pathIsInconsistent(path)));
  const alternatePaths = indexedPaths.filter(({ path }) => !pathIsControlPlaneOnly(path)
    && !activePaths.some((candidate) => candidate.path.path_id === path.path_id)
    && !cyclePaths.some((candidate) => candidate.path.path_id === path.path_id)
    && !policyBlockedPaths.some((candidate) => candidate.path.path_id === path.path_id)
    && !unusablePaths.some((candidate) => candidate.path.path_id === path.path_id));
  const pathMarkup = ({ path, index }) => {
    const selectedPath = path.path_id === selected.path_id;
    const nodes = routePathNodeRefs(path).map(nodeLabelForRef);
    return `<button type="button" role="tab" aria-selected="${selectedPath}" tabindex="${selectedPath ? "0" : "-1"}" class="mn-route-path-tab ${routeQualityClasses(path).join(" ")}" data-route-path="${escapeHtml(path.path_id)}">
      <span class="mn-route-path-number">${index + 1}</span>
      <span><strong>${escapeHtml(path.label)}</strong><small>${escapeHtml(nodes.join(" → ") || "No resolved node sequence")}</small><em>${escapeHtml(pathStatusSummary(path))}</em></span>
    </button>`;
  };
  byId("mn-route-path-tabs").innerHTML = `${activePaths.length ? `<div class="mn-route-path-group-label" role="presentation"><strong>Active paths</strong><span>${activePaths.length}</span></div>${activePaths.map(pathMarkup).join("")}` : ""}${cyclePaths.length ? `<div class="mn-route-path-group-label" role="presentation"><strong>Looped paths</strong><span>${cyclePaths.length}</span></div>${cyclePaths.map(pathMarkup).join("")}` : ""}${policyBlockedPaths.length ? `<div class="mn-route-path-group-label" role="presentation"><strong>Policy-blocked paths</strong><span>${policyBlockedPaths.length}</span></div>${policyBlockedPaths.map(pathMarkup).join("")}` : ""}${unusablePaths.length ? `<div class="mn-route-path-group-label" role="presentation"><strong>Selected but unusable</strong><span>${unusablePaths.length}</span></div>${unusablePaths.map(pathMarkup).join("")}` : ""}${controlPlaneOnlyPaths.length ? `<div class="mn-route-path-group-label" role="presentation"><strong>Control-plane evidence</strong><span>${controlPlaneOnlyPaths.length}</span></div>${controlPlaneOnlyPaths.map(pathMarkup).join("")}` : ""}${alternatePaths.length ? `<div class="mn-route-path-group-label" role="presentation"><strong>Alternatives</strong><span>${alternatePaths.length}</span></div>${alternatePaths.map(pathMarkup).join("")}` : ""}`;
  byId("mn-route-resolution-title").textContent = selected.label;
  byId("mn-route-path-badges").innerHTML = routeBadge(routeDirectionLabel(state.activeRouteDirection)) + routePathBadges(selected);
  const nodeRefs = routePathNodeRefs(selected);
  const usedBoundarySegments = new Set();
  const sameRouteRef = (left, right) => Boolean(
    (left?.member_id && right?.member_id && left.member_id === right.member_id)
    || (left?.node_id && right?.node_id && left.node_id === right.node_id)
  );
  byId("mn-route-hopline").innerHTML = nodeRefs.map((ref, index) => {
    const node = findNodeForRef(ref, selectedResultNodes());
    const tokens = [...refRouteTokens(ref), ...(node ? interactionTokensForNode(node) : [])];
    const focusTargets = node ? interactionFocusTargetsForNode(node) : [`node-member:${ref.member_id}`];
    const nodePacketRefs = node
      ? packetRefsForRouteNode(selected, node)
      : packetTransitionsForPath(selected).filter((evaluation) => {
        const segment = selected.segments.find((candidate) => candidate.segment_id === evaluation.segment_id);
        return segment && (sameRouteRef(segment.source, ref) || sameRouteRef(segment.target, ref));
      }).map((evaluation) => evaluation.packet_ref);
    const nodeMarkup = `<button type="button" data-route-hop-node="${escapeHtml(node?.key || "")}" data-route-kind="hop-node" data-route-id="${escapeHtml(ref.member_id || ref.node_id)}" data-route-tokens="${routeTokensAttribute(tokens)}" data-route-focus-targets="${routeFocusTargetsAttribute(focusTargets)}" data-route-packet-refs="${packetRefsAttribute(nodePacketRefs)}">${escapeHtml(nodeLabelForRef(ref))}</button>`;
    const nextRef = nodeRefs[index + 1];
    if (!nextRef) return nodeMarkup;
    const boundary = selected.segments.find((segment) =>
      !usedBoundarySegments.has(segment.segment_id)
      && sameRouteRef(segment.source, ref)
      && sameRouteRef(segment.target, nextRef)
      && !sameRouteRef(segment.source, segment.target)
    );
    if (!boundary) return `${nodeMarkup}<span aria-hidden="true">→</span>`;
    usedBoundarySegments.add(boundary.segment_id);
    const linkLabel = `${nodeLabelForRef(ref)} to ${nodeLabelForRef(nextRef)} link`;
    return `${nodeMarkup}<button type="button" class="mn-route-hop-link" aria-label="${escapeHtml(linkLabel)}" title="${escapeHtml(linkLabel)}" data-route-kind="hop-link" data-route-id="${escapeHtml(boundary.segment_id)}" data-route-focus-targets="${routeFocusTargetsAttribute(boundary.highlight_target_ids)}" data-route-packet-refs="${packetRefsAttribute(boundary.packet_refs)}"><span aria-hidden="true">→</span></button>`;
  }).join("") || '<span class="mn-route-hop-missing">No node sequence resolved</span>';
  renderRoutePacketEvolution(selected);
  const resolutionItems = [
    ...selected.steps,
    ...routeDiagnosticItems(selected),
  ];
  byId("mn-route-steps").innerHTML = resolutionItems.map((step, index) => routeStepMarkup({
    ...step,
    inconsistent: step.inconsistent === true || pathIsInconsistent(selected),
  }, index)).join("")
    || '<li class="mn-route-step is-unresolved"><span class="mn-route-step-index">!</span><div><p>No plug-in route resolution text was returned for this path.</p></div></li>';
  byId("mn-route-findings").innerHTML = routeFindingsMarkup(trace, selected.path_id);

  byId("mn-route-path-tabs").querySelectorAll("[data-route-path]").forEach((button) => {
    button.addEventListener("click", () => selectRoutePath(button.dataset.routePath));
    button.addEventListener("keydown", (event) => {
      if (!["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key)) return;
      event.preventDefault();
      const tabs = [...byId("mn-route-path-tabs").querySelectorAll("[data-route-path]")];
      const current = tabs.indexOf(event.currentTarget);
      const next = event.key === "Home" ? 0 : event.key === "End" ? tabs.length - 1
        : (current + (event.key === "ArrowDown" ? 1 : -1) + tabs.length) % tabs.length;
      selectRoutePath(tabs[next].dataset.routePath);
      byId("mn-route-path-tabs").querySelector(`[data-route-path="${CSS.escape(tabs[next].dataset.routePath)}"]`)?.focus();
    });
  });
  byId("mn-route-hopline").querySelectorAll("[data-route-hop-node]").forEach((button) => {
    if (button.dataset.routeHopNode) button.addEventListener("click", () => {
      focusNode(button.dataset.routeHopNode);
      document.querySelector(".mn-node-detail")?.scrollIntoView({
        behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth",
        block: "start",
      });
      showToast(`Focused node details for ${button.textContent.trim()}.`);
    });
  });
  bindRouteCorrelationElements(byId("mn-route-content"));
  bindRoutePacketGraphElements(byId("mn-route-content"));
  bindRoutePacketElements(byId("mn-route-packet-evolution"));
}

function selectRoutePath(pathId) {
  if (!state.routeTrace?.paths.some((path) => path.path_id === pathId)) return;
  clearRoutePacketSelection();
  clearRoutePathPreview();
  state.selectedRoutePathId = pathId;
  state.selectedRoutePathIds[state.activeRouteDirection] = pathId;
  state.requestedRoutePathId = pathId;
  clearRouteHover();
  renderRouteTrace();
  renderMap();
  requestAnimationFrame(() => fitGraphViewport("mn-route-map-stage", "route"));
  renderRouteTables();
  syncUrl();
  showToast(`${routePathById(pathId)?.label || "Path"} selected. Resolution details are open.`);
}

function clearSelectedRoutePath({ announce = true } = {}) {
  if (state.routeGraphMode !== "all" || !state.selectedRoutePathId) return;
  clearRoutePacketSelection();
  state.selectedRoutePathId = "";
  state.selectedRoutePathIds[state.activeRouteDirection] = "";
  state.requestedRoutePathId = "";
  clearRoutePathPreview();
  clearRouteHover();
  renderRouteTrace();
  renderMap();
  requestAnimationFrame(() => fitGraphViewport("mn-route-map-stage", "route"));
  renderRouteTables();
  syncUrl();
  if (announce) showToast("Selected path cleared. All candidates remain visible.");
}

function setRouteGraphMode(mode) {
  if (!['all', 'focused'].includes(mode)) return;
  clearRoutePacketSelection();
  if (mode === "all") {
    state.routeGraphMode = "all";
    state.selectedRoutePathId = "";
    // Focused mode seeds both directions with defaults. Those defaults are not
    // explicit all-path selections and must not reopen the side panel when the
    // user switches Forward/Return in overview mode.
    state.selectedRoutePathIds = { forward: "", reverse: "" };
    state.requestedRoutePathId = "";
  } else {
    state.routeGraphMode = "focused";
    const fallback = pinnedRoutePath() || defaultRoutePath();
    state.selectedRoutePathId = fallback?.path_id || "";
    state.selectedRoutePathIds[state.activeRouteDirection] = state.selectedRoutePathId;
    state.requestedRoutePathId = state.selectedRoutePathId;
  }
  clearRoutePathPreview();
  clearRouteHover();
  renderRouteTrace();
  renderMap();
  renderRouteTables();
  syncUrl();
}

function initializeNodeSelection() {
  const params = new URLSearchParams(location.search);
  const requested = new Set((params.get("members") || "").split(",").filter(Boolean));
  const requestedNodes = new Set((params.get("nodes") || params.get("node_ids") || "").split(",").filter(Boolean));
  state.selectedNodeKeys.clear();
  const hasExplicitSelection = requested.size || requestedNodes.size;
  for (const node of state.capabilities.nodes) {
    if ((!hasExplicitSelection && node.default_selected !== false) || requested.has(node.member_id) || requestedNodes.has(node.node_id)) {
      state.selectedNodeKeys.add(node.key);
    }
  }
  if (!state.selectedNodeKeys.size) {
    state.capabilities.nodes.filter((node) => node.available !== false && !node.optional).forEach((node) => state.selectedNodeKeys.add(node.key));
  }
  const focusMember = params.get("focus_member") || params.get("member_id");
  const focusNode = params.get("focus_node") || params.get("node_id");
  const focused = state.capabilities.nodes.find((node) => node.member_id === focusMember || (!focusMember && node.node_id === focusNode));
  state.focusedNodeKey = focused?.key || "";
  const focusResource = params.get("focus_resource") || params.get("resource_id");
  if (focused && focusResource) state.focusedResourceRef = { ...nodeIdentity(focused), resource_id: focusResource };
}

function syncBasisFields() {
  const absolute = byId("mn-basis-kind").value === "absolute_time";
  byId("mn-absolute-field").hidden = !absolute;
  byId("mn-relative-field").hidden = absolute;
}

function renderCapabilityNodeIndex() {
  const container = byId("mn-node-index");
  const needle = state.nodeFilter.trim().toLowerCase();
  const nodes = state.capabilities.nodes.filter((node) => {
    const result = selectedResultNodes().find((item) => item.key === node.key);
    const plan = result?.plan || nodePlan(node);
    return !needle || [node.label, node.node_id, node.site, node.device_type, plan.plugin_set_id, plan.projection_id]
      .filter(Boolean).join(" ").toLowerCase().includes(needle);
  });
  container.innerHTML = nodes.map((node, index) => {
    const result = selectedResultNodes().find((item) => item.key === node.key) || node;
    const plan = result.plan || nodePlan(node);
    const health = nodeHealth(result);
    const toggleId = `mn-node-toggle-${index}`;
    return `<div class="mn-node-index-item${state.focusedNodeKey === node.key ? " is-selected" : ""}${node.available === false ? " is-unavailable" : ""}" data-node-key="${escapeHtml(node.key)}">
      <input id="${toggleId}" type="checkbox" data-node-toggle="${escapeHtml(node.key)}" ${state.selectedNodeKeys.has(node.key) ? "checked" : ""} ${state.pending || node.available === false ? "disabled" : ""} />
      <label for="${toggleId}"><strong>${escapeHtml(node.label)}</strong><small>${escapeHtml(`${node.site} · ${node.device_type}`)}</small><code>${escapeHtml(`${plan.plugin_set_id} → ${plan.projection_id}`)}</code></label>
      <a class="mn-node-open" href="${escapeHtml(navigationHref(result))}" aria-label="${escapeHtml(`Open ${node.label} node workspace`)}">Open</a>
      <i class="mn-health-dot is-${health}" aria-label="${escapeHtml(health)}"></i>
    </div>`;
  }).join("") || '<div class="topology-empty-list">No device matches this filter.</div>';
  container.querySelectorAll("[data-node-toggle]").forEach((input) => input.addEventListener("change", (event) => {
    const key = event.currentTarget.dataset.nodeToggle;
    if (event.currentTarget.checked) state.selectedNodeKeys.add(key); else state.selectedNodeKeys.delete(key);
    markTopologyQueryDirty();
    renderCapabilityNodeIndex();
    renderMetrics();
    renderMap();
    syncUrl();
  }));
  container.querySelectorAll(".mn-node-index-item").forEach((row) => row.addEventListener("click", (event) => {
    if (event.target.closest("input, label, a")) return;
    focusNode(row.dataset.nodeKey);
  }));
  const selectableNodes = state.capabilities.nodes.filter((node) => node.available !== false);
  const selectedCount = selectableNodes.filter((node) => state.selectedNodeKeys.has(node.key)).length;
  const unavailableCount = state.capabilities.nodes.length - selectableNodes.length;
  const selectAll = byId("mn-select-all");
  if (selectAll) {
    const allAvailableSelected = selectableNodes.length > 0 && selectedCount === selectableNodes.length;
    selectAll.textContent = !selectableNodes.length ? "No devices available" : allAvailableSelected ? "Clear selection" : "Select all";
    selectAll.disabled = state.pending || !selectableNodes.length;
    selectAll.setAttribute("aria-label", `${selectAll.textContent} available devices`);
  }
  const summary = byId("mn-node-selection-summary");
  if (summary) {
    summary.textContent = `${selectedCount} of ${selectableNodes.length} available included${unavailableCount ? ` · ${unavailableCount} unavailable` : ""}${needle ? ` · ${nodes.length} match filter` : ""}`;
  }
}

function renderMetrics() {
  const nodes = selectedResultNodes();
  const links = state.query?.links || [];
  const topologyLinks = links.filter((link) => !link.resolution_only);
  const unresolvedLinks = links.filter((link) => link.resolution_only).length;
  const incomplete = nodes.filter((node) => nodeHealth(node) !== "good").length;
  const domains = topologyConnectivityDomains();
  const hasSegmentProjection = Boolean(state.query?.connectivity_domains?.length);
  const healthItems = hasSegmentProjection ? domains : topologyLinks;
  const failedLinks = healthItems.filter((item) => linkHealth(item) === "error").length;
  const uncertainLinks = healthItems.filter((item) => linkHealth(item) === "warning").length;
  const plugins = new Set(nodes.map((node) => node.plan?.plugin_set_id).filter(Boolean));
  const uncertainClocks = nodes.filter((node) => {
    const basis = basisForNode(node);
    return basis.resolution !== "exact" && basis.resolution !== "aligned" || toBigInt(basis.uncertainty) > 0n;
  }).length;
  byId("mn-node-count").textContent = formatInteger(nodes.length);
  byId("mn-node-coverage").textContent = incomplete ? `${incomplete} incomplete or uncertain` : "All selected nodes complete";
  byId("mn-link-count").textContent = formatInteger(hasSegmentProjection ? domains.length : topologyLinks.length);
  byId("mn-link-metric-label").textContent = hasSegmentProjection
    ? state.topologyNetworkView === "vpn" ? "VPN segments" : "Connectivity domains"
    : "Pairwise adjacencies";
  const attachments = domains.reduce((total, domain) => total + domain.members.length, 0);
  byId("mn-link-health").textContent = hasSegmentProjection
    ? `${attachments} attachments · ${failedLinks} failed · ${uncertainLinks} ambiguous`
    : `${failedLinks} failed · ${uncertainLinks} ambiguous · ${unresolvedLinks} unresolved`;
  byId("mn-plugin-count").textContent = formatInteger(plugins.size);
  byId("mn-clock-count").textContent = formatInteger(uncertainClocks);
  byId("mn-clock-summary").textContent = uncertainClocks ? "nodes with bounded or unknown time" : "all node mappings exact";
  const basis = state.query?.resolved_basis || state.query?.request?.basis;
  const basisKind = basis?.kind || "unknown";
  const requestedKind = basis?.requested?.kind || state.query?.request?.basis?.kind;
  const relativeCapture = basisKind === "relative_to_watermark"
    || basisKind === "relative_capture_vector"
    || basisKind === "mixed_capture_vector"
    || requestedKind === "relative_to_watermark";
  byId("mn-basis-readout").textContent = relativeCapture
    ? "Relative capture vector · simultaneity not implied"
    : `Absolute UTC · ${compactTime(basis?.time_ns ?? basis?.requested?.time_ns)}`;
}

function routeNodeSequence(routePath, nodes) {
  const ordered = [];
  for (const [index, ref] of routePathNodeRefs(routePath || {}).entries()) {
    const occurrenceId = String(ref.route_occurrence_id ?? `${routePath?.path_id || "path"}:occurrence:${index + 1}`);
    const existing = nodes.find((node) =>
      node.route_path_id === routePath?.path_id && node.route_occurrence_id === occurrenceId
    );
    if (existing) {
      ordered.push(existing);
      continue;
    }
    const node = findNodeForRef(ref, nodes);
    if (!node) continue;
    if (node.route_graph_shared === true) {
      ordered.push(node);
      continue;
    }
    const baseKey = node.route_base_key || node.key;
    ordered.push({
      ...node,
      key: `${baseKey}\u241froute:${routePath?.path_id || "path"}:${occurrenceId}`,
      route_base_key: baseKey,
      route_path_id: routePath?.path_id || "",
      route_occurrence_id: occurrenceId,
      route_occurrence_index: Number(ref.route_occurrence_index ?? index),
    });
  }
  return ordered;
}

function findRouteOccurrence(ref, occurrenceId, nodes, pathId = "") {
  if (occurrenceId) {
    const exact = nodes.find((node) =>
      node.route_occurrence_id === String(occurrenceId)
      && (!pathId || !node.route_path_id || node.route_path_id === pathId)
    );
    if (exact) return exact;
  }
  const matches = nodes.filter((node) =>
    (node.member_id === ref?.member_id)
    || (node.node_id === ref?.node_id && node.revision_id === ref?.revision_id)
    || (node.node_id === ref?.node_id)
  );
  return matches.find((node) => !pathId || !node.route_path_id || node.route_path_id === pathId)
    || matches[0]
    || null;
}

function mapLayout(nodes, routePath, options = {}) {
  const stage = byId(options.stageId || "mn-map-stage");
  const minHeight = Number(options.minHeight || 570);
  const columnPitch = Number(options.columnPitch || MAP_COLUMN_PITCH);
  const outerPadding = Number(options.outerPadding || MAP_OUTER_PADDING);
  const fallbackWidth = Number(options.fallbackWidth || 720);
  const defaultColumns = Math.max(1, Math.ceil(Math.sqrt(nodes.length * 1.65)));
  const routeNodes = routeNodeSequence(routePath, nodes);
  const useRouteRail = routeNodes.length >= 2;
  const routeKeys = new Set(routeNodes.map((node) => node.key));
  const otherNodes = nodes.filter((node) => !routeKeys.has(node.key));
  const otherColumns = Math.max(1, Math.min(defaultColumns, otherNodes.length || 1));
  const columns = useRouteRail
    ? Math.max(routeNodes.length, otherColumns)
    : defaultColumns;
  const rows = useRouteRail
    ? 1 + Math.ceil(otherNodes.length / otherColumns)
    : Math.max(1, Math.ceil(nodes.length / columns));
  const width = Math.max(stage.clientWidth || fallbackWidth, columns * columnPitch + outerPadding);
  const height = Math.max(minHeight, rows * MAP_ROW_PITCH + outerPadding);
  const positions = new Map();

  if (useRouteRail) {
    const routeRailWidth = Math.max(1, width - outerPadding * 2);
    routeNodes.forEach((node, index) => positions.set(node.key, {
      x: outerPadding + ((index + 0.5) / routeNodes.length) * routeRailWidth,
      y: (0.5 / rows) * height,
    }));
    otherNodes.forEach((node, index) => {
      const column = index % otherColumns;
      const row = 1 + Math.floor(index / otherColumns);
      positions.set(node.key, {
        x: ((column + 0.5) / otherColumns) * width,
        y: ((row + 0.5) / rows) * height,
      });
    });
  } else {
    nodes.forEach((node, index) => {
      const column = index % columns;
      const row = Math.floor(index / columns);
      positions.set(node.key, {
        x: ((column + 0.5) / columns) * width,
        y: ((row + 0.5) / rows) * height,
      });
    });
  }

  return { columns, rows, width, height, positions, routeNodeKeys: routeKeys };
}

function mapTopologyLayout(nodes, options = {}) {
  const stage = byId(options.stageId || "mn-map-stage");
  const minHeight = Number(options.minHeight || 520);
  const viewportWidth = Math.max(stage.clientWidth || 720, 720);
  const columns = Math.max(1, Math.ceil(Math.sqrt(nodes.length)));
  const rows = Math.max(1, Math.ceil(nodes.length / columns));
  const horizontalPitch = MAP_NODE_FALLBACK_WIDTH + 44;
  const verticalPitch = MAP_NODE_FALLBACK_HEIGHT + 48;
  const stagger = rows > 1 && columns > 1 ? horizontalPitch / 4 : 0;
  const contentWidth = Math.max(0, columns - 1) * horizontalPitch
    + MAP_NODE_FALLBACK_WIDTH + stagger * 2;
  const contentHeight = Math.max(0, rows - 1) * verticalPitch + MAP_NODE_FALLBACK_HEIGHT;
  const layoutPadding = 42;
  const width = Math.max(viewportWidth, contentWidth + layoutPadding * 2);
  const height = Math.max(minHeight, 520, contentHeight + layoutPadding * 2);
  const positions = new Map();

  // A staggered lattice keeps the full-size cards collision-free as assemblies
  // grow. Alternating rows break long collinear runs without constraining later
  // drag coordinates: pan, zoom, and node dragging still operate in an
  // unbounded logical world while the stage clips only the visible viewport.
  nodes.forEach((node, index) => {
    const row = Math.floor(index / columns);
    const column = index % columns;
    const rowCount = Math.min(columns, nodes.length - row * columns);
    const rowSpan = Math.max(0, rowCount - 1) * horizontalPitch;
    const rowStagger = rows > 1 && rowCount > 1 ? (row % 2 ? stagger : -stagger) : 0;
    positions.set(node.key, {
      x: width / 2 - rowSpan / 2 + column * horizontalPitch + rowStagger,
      y: height / 2 - (rows - 1) * verticalPitch / 2 + row * verticalPitch,
    });
  });

  return {
    columns,
    rows,
    width,
    height,
    positions,
    routeNodeKeys: new Set(),
  };
}

function normalizedNetworkRole(domain) {
  return firstDeclaredString(domain?.role, domain?.network_role, domain?.connectivity_role).toLowerCase();
}

function isSuppressedConnectivityDomain(domain) {
  return domain?.connectivity_enabled === false || domain?.participates_in_connectivity === false;
}

function isVpnConnectivityDomain(domain) {
  return domain?.is_vpn === true || ["vpn", "overlay"].includes(String(domain?.presentation_plane || domain?.network_plane || "").toLowerCase());
}

function connectivityDomainKey(link) {
  const declared = link?.network_id || link?.segment_id || link?.subnet_id || link?.broadcast_domain_id
    || link?.fabric_id || link?.connector_key || link?.match_key || link?.boundary_key;
  return declared ? String(declared) : "";
}

function topologyConnectivityDomains() {
  const declaredLinks = new Map(
    (state.query?.links || []).map((link) => [String(link.link_id), link]),
  );
  const domains = (state.query?.connectivity_domains || []).map((domain) => ({
    ...domain,
    members: (domain.members || [])
      .filter((member) => findNodeForRef(member.ref, selectedResultNodes()))
      .map((member) => ({
        ...member,
        link_ids: [...(member.link_ids || [])],
        // Pairwise links are attached only when the declared membership names
        // them. They never create a domain or a membership.
        links: (member.link_ids || [])
          .map((linkId) => declaredLinks.get(String(linkId)))
          .filter(Boolean),
      })),
  }));
  return domains.filter((domain) => {
    if (!domain.members.length) return false;
    if (state.topologyNetworkView === "vpn") return isVpnConnectivityDomain(domain) && domain.separate_view !== false;
    return !isVpnConnectivityDomain(domain) && !isSuppressedConnectivityDomain(domain);
  });
}

function middleEllipsis(value, maxLength = 18) {
  const raw = String(value || "");
  if (raw.length <= maxLength) return raw;
  const visible = Math.max(2, maxLength - 1);
  const left = Math.ceil(visible / 2);
  const right = Math.floor(visible / 2);
  return `${raw.slice(0, left)}…${raw.slice(-right)}`;
}

function compactResourceLabel(value) {
  const raw = String(value || "");
  const pieces = raw.split(/[\\/]/).filter(Boolean);
  return middleEllipsis(pieces.at(-1) || raw);
}

function networkAttachmentLabel(attachment = {}, compact = true) {
  const interfaces = attachment.interface_names || [];
  const primary = attachment.subinterface || attachment.lag || interfaces[0] || "interface";
  const extras = interfaces.length > 1 ? ` +${interfaces.length - 1}` : "";
  const vlan = attachment.vlan !== null && attachment.vlan !== undefined && attachment.vlan !== ""
    ? ` · VLAN ${attachment.vlan}` : "";
  return `${compact ? compactResourceLabel(primary) : primary}${extras}${vlan}`;
}

function topologyAttachmentComponents(attachment = {}, visible = state.topologyElementVisibility) {
  const components = [];
  const interfaceKind = String(attachment.interface_kind || "interface").toLowerCase();
  const physical = [...new Set((attachment.physical_interfaces || []).filter(Boolean).map(String))];
  if (visible.has("interfaces")) {
    let declaredInterfaces = physical;
    if (!declaredInterfaces.length && ["interface", "physical", "physical_interface", "port", "ethernet"].includes(interfaceKind)) {
      const typed = new Set([attachment.subinterface, attachment.lag, attachment.parent_interface].filter(Boolean).map(String));
      declaredInterfaces = (attachment.interface_names || []).filter((value) => !typed.has(String(value)));
    }
    [...new Set(declaredInterfaces.filter(Boolean).map(String))].forEach((resourceId) => components.push({
      kind: "interface",
      label: compactResourceLabel(resourceId),
      full: `Physical interface: ${resourceId}`,
    }));
  }
  if (visible.has("lags") && attachment.lag) {
    components.push({
      kind: "lag",
      label: `LAG ${compactResourceLabel(attachment.lag)}`,
      full: `Link aggregation: ${attachment.lag}`,
    });
  }
  const subinterfaceKind = ["subinterface", "logical_subinterface"].includes(interfaceKind);
  if (visible.has("subinterfaces") && subinterfaceKind && attachment.subinterface) {
    components.push({
      kind: "subinterface",
      label: `Subif ${compactResourceLabel(attachment.subinterface)}`,
      full: `Subinterface: ${attachment.subinterface}`,
    });
  }
  if (visible.has("vlans") && attachment.vlan !== null && attachment.vlan !== undefined && attachment.vlan !== "") {
    components.push({ kind: "vlan", label: `VLAN ${attachment.vlan}`, full: `VLAN: ${attachment.vlan}` });
  }
  return components;
}

function fullTopologyAttachmentLabel(attachment = {}) {
  const components = topologyAttachmentComponents(attachment, new Set(TOPOLOGY_ELEMENT_KEYS));
  const addresses = [...new Set([...(attachment.addresses || []), attachment.address].filter(Boolean).map(String))];
  const details = [...components.map((component) => component.full), ...(addresses.length ? [`Addresses: ${addresses.join(", ")}`] : [])];
  return details.join("; ") || networkAttachmentLabel(attachment, false);
}

function connectivityDomainLabel(domain) {
  const explicitExternal = domain.plugin_asserted_external === true;
  const oneSided = domain.members.length === 1;
  const label = domain.label || domain.prefix || domain.network_id;
  if (!oneSided) return label;
  return explicitExternal ? `${label} · external` : `${label} · outside query scope`;
}

function topologyDomainParticipants(domain, nodes) {
  const participants = new Map();
  for (const member of domain.members || []) {
    const node = findNodeForRef(member.ref, nodes);
    if (!node) continue;
    if (!participants.has(node.key)) participants.set(node.key, { node, members: [] });
    participants.get(node.key).members.push(member);
  }
  return [...participants.values()];
}

function topologyDomainPresentationDecision(domain, nodes) {
  const participants = topologyDomainParticipants(domain, nodes);
  const requestedShape = String(domain.topology_presentation?.two_participant_shape || "domain_node");
  const expectedAttachments = Number(domain.existing_attachment_count || 0);
  const expectedNodes = Number(domain.existing_node_count || 0);
  const completeMembership = domain.coverage_complete === true
    && expectedAttachments > 0
    && (domain.members || []).length === expectedAttachments
    && expectedNodes === participants.length;
  const checks = [
    [requestedShape === "compact_edge", `the plug-in declared ${requestedShape} instead of compact_edge`],
    [domain.source === "plugin", "no stable plug-in domain identity was supplied"],
    [domain.connectivity_enabled === true, "the plug-in excluded the domain from connectivity"],
    [!isVpnConnectivityDomain(domain), "the plug-in placed the domain in the VPN presentation plane"],
    [domain.semantic_conflict !== true, "merge-critical plug-in semantics conflict"],
    [completeMembership, `current membership is incomplete (${domain.members?.length || 0}/${expectedAttachments || "?"} attachments, ${participants.length}/${expectedNodes || "?"} participants)`],
    [participants.length === 2, `there are ${participants.length} distinct current participants rather than 2`],
  ];
  const failed = checks.find(([passed]) => !passed);
  const compact = !failed;
  const coreSteps = [
    `Read the bounded plug-in preference: ${requestedShape}.`,
    `Validated ${domain.members?.length || 0} returned current attachments against ${expectedAttachments || "unknown"} expected and ${participants.length} distinct participants against ${expectedNodes || "unknown"} expected.`,
    "Checked completeness, physical presentation, connectivity eligibility, and merge-critical semantic conflicts.",
    compact
      ? "Rendered one node-to-node line while retaining the domain and every attachment as inspectable records."
      : `Kept an explicit domain object because ${failed?.[1] || "the compact-edge contract was not satisfied"}.`,
    "Grouped only by the plug-in-declared exact matcher and typed opaque key; never by prefix, VRF, VLAN, label, protocol, or address overlap.",
  ];
  return { compact, requestedShape, participants, completeMembership, checks, coreSteps };
}

function topologyInspectorValue(value) {
  if (value === null || value === undefined || value === "") return "not declared";
  if (Array.isArray(value)) return value.map(topologyInspectorValue).join(" · ");
  if (typeof value === "object") return Object.entries(value)
    .map(([key, item]) => `${titleCase(key)}: ${topologyInspectorValue(item)}`).join(" · ");
  return String(value);
}

function topologyEvidenceLabel(item) {
  if (typeof item === "string") return item;
  return String(item?.label ?? item?.detail ?? item?.message ?? item?.evidence_type
    ?? item?.kind ?? item?.source ?? "Plug-in evidence");
}

function topologyPluginIds(domain) {
  const provenance = [
    ...(domain.plugin_provenance || []),
    ...(domain.members || []).map((member) => member.plugin_provenance).filter(Boolean),
  ];
  return [...new Set(provenance.map((item) => item?.plugin_id || item?.plugin_instance_id).filter(Boolean).map(String))];
}

function topologyDomainInspectorItem(domain, decision) {
  const participants = decision.participants.map(({ node, members }) =>
    `${node.label} (${members.length} attachment${members.length === 1 ? "" : "s"})`);
  const inferences = (domain.members || []).map((member) => member.inference || {}).filter((item) => Object.keys(item).length);
  const methods = [...new Set(inferences.map((item) => item.method).filter(Boolean).map(String))];
  const rules = [...new Set(inferences.map((item) => item.rule_id).filter(Boolean).map(String))];
  const evidence = [
    ...(domain.evidence || []),
    ...(domain.members || []).flatMap((member) => member.evidence || []),
  ].map(topologyEvidenceLabel).filter(Boolean);
  const exactMatch = domain.match || {};
  return {
    kind: decision.compact ? "compact connectivity domain" : "connectivity domain",
    title: connectivityDomainLabel(domain),
    summary: decision.compact
      ? "A real plug-in-owned subnet/domain, contracted to one line only for this complete two-participant reconstruction."
      : "A plug-in-owned connectivity domain kept as an explicit graph object.",
    pluginFacts: [
      ["Identity", domain.network_id],
      ["Meaning", [titleCase(domain.kind), titleCase(domain.role)].filter(Boolean).join(" · ")],
      ["Scope", [domain.prefix, domain.vrf ? `VRF ${domain.vrf}` : "", domain.vlan !== null && domain.vlan !== undefined ? `VLAN ${domain.vlan}` : ""].filter(Boolean).join(" · ")],
      ["Participants", participants.join("; ")],
      ["State / quality", `${titleCase(domain.status)} · ${titleCase(domain.resolution)}`],
      ["Presentation request", `${decision.requestedShape}${domain.topology_presentation?.reason ? ` · ${domain.topology_presentation.reason}` : ""}`],
      ["Inference", [methods.join(", "), rules.length ? `rules ${rules.join(", ")}` : ""].filter(Boolean).join(" · ")],
      ["Provenance", topologyPluginIds(domain).join(", ")],
    ].filter(([, value]) => value),
    evidence: [...new Set(evidence)].slice(0, 8),
    coreSteps: decision.coreSteps,
    matcher: exactMatch.matcher_id
      ? `${exactMatch.matcher_id}@${exactMatch.matcher_contract_version || domain.matcher_contract_version || "?"} · typed key ${topologyInspectorValue(exactMatch.typed_key)}`
      : "No stable exact matcher was supplied; this is a compatibility projection.",
  };
}

function topologyAttachmentInspectorItem(domain, member, node) {
  const inference = member.inference || {};
  const evidence = (member.evidence || []).map(topologyEvidenceLabel).filter(Boolean);
  const provider = member.plugin_provenance?.plugin_id || member.plugin_provenance?.plugin_instance_id || "plug-in";
  return {
    kind: "domain attachment",
    title: `${node.label} ↔ ${connectivityDomainLabel(domain)}`,
    summary: "This attachment stack is interpreted by the device plug-in; the core only validates and renders it.",
    pluginFacts: [
      ["Attachment ID", member.member_id],
      ["Interface stack", fullTopologyAttachmentLabel(member.attachment)],
      ["State / quality", `${titleCase(member.status)} · ${titleCase(member.resolution)}`],
      ["Inference method", inference.method],
      ["Rule", inference.rule_id],
      ["Confidence", member.confidence],
      ["Provenance", provider],
    ].filter(([, value]) => value),
    evidence: [...new Set(evidence)].slice(0, 8),
    coreSteps: [
      "Resolved the attachment's plug-in resource reference to the selected node revision and time basis.",
      "Joined it to the domain only through the declared exact matcher/key contract.",
      "Rendered plug-in-declared interface, LAG, subinterface, VLAN, and address components without interpreting their vendor semantics.",
    ],
    matcher: domain.match?.matcher_id
      ? `${domain.match.matcher_id} · exact typed-key equality; never prefix matching`
      : "Compatibility attachment without a stable domain matcher.",
  };
}

function topologyNodeInspectorItem(node) {
  const basis = basisForNode(node);
  const plan = node.plan || nodePlan(node);
  const coverage = node.coverage || {};
  return {
    kind: "topology member",
    title: node.label,
    summary: "One immutable device snapshot selected for this reconstruction.",
    pluginFacts: [
      ["Node / member", `${node.node_id} · ${node.member_id}`],
      ["Device", `${node.site} · ${node.device_type}`],
      ["Plug-in set", `${plan.plugin_set_id}@${plan.plugin_version || "?"}`],
      ["Projection", plan.projection_id],
      ["Resolved time", basis.queryTime],
      ["Clock quality", `${titleCase(basis.resolution)}${basis.uncertainty !== null && basis.uncertainty !== undefined ? ` · ±${basis.uncertainty} ns` : ""}`],
      ["Resource coverage", coverage.status || (node.resources_available === false ? "unavailable" : "available")],
    ].filter(([, value]) => value),
    evidence: [],
    coreSteps: [
      "Selected this immutable node revision using the requested absolute or relative time basis.",
      "Placed the node in the graph and attached only validated plug-in topology records to its outer boundary.",
    ],
    matcher: "Node identity comes from the topology member contract, not a display-name match.",
  };
}

function topologyDirectLinkInspectorItem(link, source, target) {
  const evidence = (link.evidence || []).map(topologyEvidenceLabel).filter(Boolean);
  return {
    kind: "pairwise compatibility link",
    title: `${source.label} ↔ ${target.label}`,
    summary: "A pairwise plug-in/linker projection without a stable connectivity-domain identity.",
    pluginFacts: [
      ["Link ID", link.link_id],
      ["Link type", link.kind || link.link_type],
      ["Endpoint A", fullTopologyAttachmentLabel(link.source_attachment)],
      ["Endpoint B", fullTopologyAttachmentLabel(link.target_attachment)],
      ["State / quality", `${titleCase(link.status)} · ${titleCase(link.resolution)}`],
      ["Provenance", link.plugin_provenance || link.linker_plugin_provenance],
    ].filter(([, value]) => value),
    evidence: [...new Set(evidence)].slice(0, 8),
    coreSteps: [
      "Resolved both endpoint references against the selected node snapshots.",
      "Used a direct compatibility edge because no stable connectivity-domain ID was supplied.",
      "Did not infer a subnet from addresses, prefixes, labels, protocols, or visual proximity.",
    ],
    matcher: "Pairwise fallback; add a plug-in connectivity-domain resource to preserve shared-medium identity.",
  };
}

function mergeAttachment(left = {}, right = {}) {
  const uniqueStrings = (...groups) => [
    ...new Set(
      groups
        .flat()
        .filter((value) => value !== null && value !== undefined && value !== "")
        .map(String),
    ),
  ];
  const firstDeclared = (...values) => values.find(
    (value) => value !== null && value !== undefined && value !== "",
  );
  const interfaceNames = uniqueStrings(
    left.interface_names,
    right.interface_names,
    left.physical_interfaces,
    right.physical_interfaces,
    left.parent_interface,
    right.parent_interface,
    left.lag,
    right.lag,
    left.subinterface,
    right.subinterface,
  );
  const addresses = uniqueStrings(
    left.addresses,
    right.addresses,
    left.address,
    right.address,
  );
  return {
    attachment_id: firstDeclared(left.attachment_id, right.attachment_id, ""),
    interface_kind: firstDeclared(
      [left.interface_kind, right.interface_kind].find(
        (value) => value && String(value).toLowerCase() !== "interface",
      ),
      left.interface_kind,
      right.interface_kind,
      "interface",
    ),
    interface_names: interfaceNames,
    physical_interfaces: uniqueStrings(
      left.physical_interfaces,
      right.physical_interfaces,
    ),
    parent_interface: firstDeclared(
      left.parent_interface,
      right.parent_interface,
      "",
    ),
    lag: firstDeclared(left.lag, right.lag, ""),
    subinterface: firstDeclared(left.subinterface, right.subinterface, ""),
    vlan: firstDeclared(left.vlan, right.vlan, null),
    address: firstDeclared(left.address, right.address, addresses[0], ""),
    addresses,
    role: firstDeclared(left.role, right.role, ""),
  };
}

function mergedParticipantAttachment(members) {
  return (members || []).reduce((combined, member) => mergeAttachment(combined, member.attachment || {}), {});
}

function topologyInspectorFactsMarkup(facts) {
  return facts.map(([label, value]) => `<div><dt>${escapeHtml(label)}</dt><dd>${escapeHtml(topologyInspectorValue(value))}</dd></div>`).join("");
}

function topologyInspectorMarkup(item, interactive = false) {
  const close = interactive ? '<button type="button" data-topology-inspector-close aria-label="Close topology details">×</button>' : "";
  if (!interactive) {
    const facts = (item.pluginFacts || []).slice(0, 4);
    const evidence = item.evidence?.[0];
    const coreDecision = item.coreSteps?.at(-2) || item.coreSteps?.[0] || item.matcher;
    return `<header><div><span>${escapeHtml(item.kind)}</span><strong>${escapeHtml(item.title)}</strong><small>${escapeHtml(item.summary)}</small></div></header>
      <section class="mn-topology-inspector-quick"><dl>${topologyInspectorFactsMarkup(facts)}</dl>${evidence ? `<p><b>Evidence</b>${escapeHtml(evidence)}</p>` : ""}<p><b>Core decision</b>${escapeHtml(coreDecision)}</p></section>
      <footer>Click or press Enter on a domain or link to pin the complete plug-in evidence and core calculation.</footer>`;
  }
  const evidence = item.evidence?.length
    ? `<ul>${item.evidence.map((value) => `<li>${escapeHtml(value)}</li>`).join("")}</ul>`
    : "<p>No additional evidence excerpts were returned.</p>";
  const steps = item.coreSteps.map((value, index) => `<li><span>${index + 1}</span><p>${escapeHtml(value)}</p></li>`).join("");
  return `<header><div><span>${escapeHtml(item.kind)}</span><strong>${escapeHtml(item.title)}</strong><small>${escapeHtml(item.summary)}</small></div>${close}</header>
    <section class="mn-topology-inspector-section is-plugin"><h4>PLUGIN · declared or inferred meaning</h4><dl>${topologyInspectorFactsMarkup(item.pluginFacts)}</dl><h5>Evidence</h5>${evidence}</section>
    <section class="mn-topology-inspector-section is-core"><h4>CORE · presentation calculation</h4><p class="mn-topology-inspector-matcher">${escapeHtml(item.matcher)}</p><ol>${steps}</ol></section>`;
}

function positionTopologyInspector(anchor, point = null) {
  const card = byId("mn-topology-hover-card");
  if (!card || card.hidden || !anchor?.getBoundingClientRect) return;
  const rect = anchor.getBoundingClientRect();
  const width = Math.min(card.classList.contains("is-pinned") ? 440 : 340, window.innerWidth - 24);
  const cardHeight = Math.min(card.scrollHeight || 410, window.innerHeight - 24);
  const anchorLeft = Number.isFinite(point?.clientX) ? point.clientX : rect.left;
  const anchorRight = Number.isFinite(point?.clientX) ? point.clientX : rect.right;
  const anchorTop = Number.isFinite(point?.clientY) ? point.clientY : rect.top;
  let left = anchorRight + 14;
  if (left + width > window.innerWidth - 12) left = anchorLeft - width - 14;
  left = Math.max(12, Math.min(window.innerWidth - width - 12, left));
  const top = Math.max(12, Math.min(window.innerHeight - cardHeight - 12, anchorTop - 18));
  card.style.width = `${width}px`;
  card.style.left = `${left}px`;
  card.style.top = `${top}px`;
}

function clearTopologyInspector(options = {}) {
  const trigger = state.topologyInspectorTrigger;
  clearTimeout(state.topologyInspectorHideTimer);
  state.topologyInspectorHideTimer = null;
  state.topologyInspectorKey = "";
  state.topologyInspectorPinned = false;
  state.topologyInspectorTrigger = null;
  const card = byId("mn-topology-hover-card");
  if (card) {
    card.hidden = true;
    card.classList.remove("is-pinned");
    card.innerHTML = "";
  }
  clearTopologyRelationshipContext();
  if (options.restoreFocus && trigger?.isConnected) {
    state.topologyInspectorSuppressFocusPreview = true;
    trigger.focus({ preventScroll: true });
    state.topologyInspectorSuppressFocusPreview = false;
  }
}

function showTopologyInspector(key, anchor, pinned = false, point = null) {
  const item = state.topologyInspectorItems.get(key);
  const card = byId("mn-topology-hover-card");
  if (!item || !card) return;
  if (state.topologyInspectorPinned && !pinned && state.topologyInspectorKey !== key) return;
  clearTimeout(state.topologyInspectorHideTimer);
  const preservePin = state.topologyInspectorKey === key && state.topologyInspectorPinned;
  state.topologyInspectorKey = key;
  state.topologyInspectorPinned = Boolean(pinned || preservePin);
  state.topologyInspectorTrigger = anchor;
  if (card.parentElement !== document.body) document.body.append(card);
  card.hidden = false;
  card.classList.add("is-floating");
  card.classList.toggle("is-pinned", state.topologyInspectorPinned);
  card.setAttribute("role", state.topologyInspectorPinned ? "dialog" : "tooltip");
  card.setAttribute("aria-label", `${item.title} topology details`);
  card.innerHTML = topologyInspectorMarkup(item, state.topologyInspectorPinned);
  card.scrollTop = 0;
  const keepOpen = () => clearTimeout(state.topologyInspectorHideTimer);
  const release = () => { if (!state.topologyInspectorPinned) scheduleHideTopologyInspector(); };
  card.onpointerenter = keepOpen;
  card.onpointerleave = release;
  card.onmouseenter = keepOpen;
  card.onmouseleave = release;
  card.querySelector("[data-topology-inspector-close]")?.addEventListener("click", () => clearTopologyInspector({ restoreFocus: true }));
  positionTopologyInspector(anchor, state.topologyInspectorPinned ? null : point);
  applyTopologyRelationshipContext(key, {
    expandNodeDomains: state.topologyInspectorPinned,
  });
  if (state.topologyInspectorPinned) card.querySelector("[data-topology-inspector-close]")?.focus({ preventScroll: true });
}

function capturePinnedTopologyInspector() {
  if (!state.topologyInspectorPinned || !state.topologyInspectorKey) return null;
  return {
    key: state.topologyInspectorKey,
    scrollTop: byId("mn-topology-hover-card")?.scrollTop || 0,
  };
}

function restorePinnedTopologyInspector(snapshot) {
  if (!snapshot?.key || !state.topologyInspectorItems.has(snapshot.key)) return;
  const stage = byId("mn-map-stage");
  const anchor = [...(stage?.querySelectorAll("[data-topology-inspect-key]") || [])]
    .find((element) => element.dataset.topologyInspectKey === snapshot.key);
  if (!anchor) return;
  showTopologyInspector(snapshot.key, anchor, true);
  const card = byId("mn-topology-hover-card");
  if (card) card.scrollTop = snapshot.scrollTop;
}

function scheduleHideTopologyInspector(delay = 240) {
  if (state.topologyInspectorPinned) return;
  clearTimeout(state.topologyInspectorHideTimer);
  state.topologyInspectorHideTimer = setTimeout(clearTopologyInspector, delay);
}

function bindTopologyInspectorElements(scope) {
  scope?.querySelectorAll("[data-topology-inspect-key]").forEach((element) => {
    if (element.dataset.topologyInspectorBound === "true") return;
    element.dataset.topologyInspectorBound = "true";
    const key = element.dataset.topologyInspectKey;
    const previewOnly = element.dataset.topologyInspectMode === "preview";
    const enter = (event) => showTopologyInspector(key, element, false, {
      clientX: event.clientX,
      clientY: event.clientY,
    });
    const leave = () => scheduleHideTopologyInspector();
    element.addEventListener("pointerenter", enter);
    element.addEventListener("pointerleave", leave);
    element.addEventListener("mouseenter", (event) => { if (!("PointerEvent" in window)) enter(event); });
    element.addEventListener("mouseleave", () => { if (!("PointerEvent" in window)) leave(); });
    element.addEventListener("pointermove", (event) => {
      if (state.topologyInspectorKey === key && !state.topologyInspectorPinned) {
        positionTopologyInspector(element, { clientX: event.clientX, clientY: event.clientY });
      }
    });
    element.addEventListener("focus", () => {
      if (!state.topologyInspectorSuppressFocusPreview) showTopologyInspector(key, element);
    });
    element.addEventListener("blur", leave);
    element.addEventListener("click", (event) => {
      if (previewOnly) return;
      if (element.closest("[data-graph-position-key]")?.dataset.graphDragMoved === "true") return;
      event.stopPropagation();
      showTopologyInspector(key, element, true);
    });
    element.addEventListener("keydown", (event) => {
      if (previewOnly) return;
      if (!["Enter", " "].includes(event.key)) return;
      event.preventDefault();
      event.stopPropagation();
      showTopologyInspector(key, element, true);
    });
  });
}

function topologyRelationshipItems(stage) {
  return [...stage.querySelectorAll(
    "[data-map-node], [data-network-segment], [data-topology-context-item]",
  )];
}

function clearTopologyRelationshipContext() {
  const stage = byId("mn-map-stage");
  if (!stage) return;
  stage.classList.remove("has-topology-relationship-context");
  delete stage.dataset.topologyRelationshipKind;
  delete stage.dataset.topologyRelationshipScope;
  topologyRelationshipItems(stage).forEach((element) => {
    element.classList.remove(
      "is-topology-context-related",
      "is-topology-context-primary",
      "is-topology-context-muted",
    );
  });
}

function topologyRelationshipFacts(element, facts) {
  if (element.dataset.mapNode) facts.nodeKeys.add(element.dataset.mapNode);
  if (element.dataset.sourceNodeKey) facts.nodeKeys.add(element.dataset.sourceNodeKey);
  if (element.dataset.targetNodeKey) facts.nodeKeys.add(element.dataset.targetNodeKey);
  if (element.dataset.networkSegment) facts.domainIds.add(element.dataset.networkSegment);
  if (element.dataset.networkSegmentId) facts.domainIds.add(element.dataset.networkSegmentId);
  if (element.dataset.networkAttachmentId) facts.attachmentIds.add(element.dataset.networkAttachmentId);
  if (element.dataset.topologyLinkId) facts.linkIds.add(element.dataset.topologyLinkId);
  if (element.dataset.routeId && element.dataset.topologyInspectKey?.startsWith("link:")) {
    facts.linkIds.add(element.dataset.routeId);
  }
}

function applyTopologyRelationshipContext(key, options = {}) {
  const stage = byId("mn-map-stage");
  if (!stage || !key) return;
  clearTopologyRelationshipContext();
  const kind = key.startsWith("attachment:") ? "attachment"
    : key.startsWith("domain:") ? "domain"
      : key.startsWith("link:") ? "link"
        : key.startsWith("node:") ? "node" : "item";
  const facts = {
    nodeKeys: new Set(),
    domainIds: new Set(),
    attachmentIds: new Set(),
    linkIds: new Set(),
  };
  const directlyIncidentItems = new Set();
  const anchors = [...stage.querySelectorAll("[data-topology-inspect-key]")]
    .filter((element) => element.dataset.topologyInspectKey === key);
  anchors.forEach((element) => topologyRelationshipFacts(element, facts));
  if (kind === "node") {
    const originNodeKeys = new Set(facts.nodeKeys);
    stage.querySelectorAll(
      "[data-topology-context-item][data-source-node-key], [data-topology-context-item][data-target-node-key]",
    ).forEach((element) => {
      if (originNodeKeys.has(element.dataset.sourceNodeKey) || originNodeKeys.has(element.dataset.targetNodeKey)) {
        directlyIncidentItems.add(element);
        topologyRelationshipFacts(element, facts);
      }
    });
  }
  const expandNodeDomains = kind === "node" && options.expandNodeDomains === true;
  if (kind === "domain" || expandNodeDomains) {
    stage.querySelectorAll("[data-network-segment-id]").forEach((element) => {
      if (facts.domainIds.has(element.dataset.networkSegmentId)) topologyRelationshipFacts(element, facts);
    });
  }
  const related = (element) => {
    if (element.dataset.mapNode) return facts.nodeKeys.has(element.dataset.mapNode);
    if (element.dataset.networkSegment) return facts.domainIds.has(element.dataset.networkSegment);
    if (kind === "attachment") {
      return facts.attachmentIds.has(element.dataset.networkAttachmentId)
        || element.dataset.topologyInspectKey === key;
    }
    if (kind === "domain") return facts.domainIds.has(element.dataset.networkSegmentId);
    if (kind === "link") {
      return facts.linkIds.has(element.dataset.topologyLinkId)
        || element.dataset.topologyInspectKey === key;
    }
    if (kind === "node") {
      if (!expandNodeDomains) return directlyIncidentItems.has(element);
      return facts.domainIds.has(element.dataset.networkSegmentId)
        || facts.linkIds.has(element.dataset.topologyLinkId);
    }
    return element.dataset.topologyInspectKey === key;
  };
  const items = topologyRelationshipItems(stage);
  if (!items.some(related)) return;
  stage.classList.add("has-topology-relationship-context");
  stage.dataset.topologyRelationshipKind = kind;
  stage.dataset.topologyRelationshipScope = kind === "node"
    ? (expandNodeDomains ? "expanded" : "incident")
    : "relationship";
  items.forEach((element) => {
    const matches = related(element);
    element.classList.toggle("is-topology-context-related", matches);
    element.classList.toggle("is-topology-context-primary", matches && element.dataset.topologyInspectKey === key);
    element.classList.toggle("is-topology-context-muted", !matches);
  });
}

function stableLayoutHash(value) {
  let hash = 2166136261;
  for (const character of String(value || "")) {
    hash ^= character.codePointAt(0);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
}

function compareLayoutIds(left, right) {
  const leftValue = String(left);
  const rightValue = String(right);
  return leftValue < rightValue ? -1 : leftValue > rightValue ? 1 : 0;
}

function layoutRect(point, box, padding = 0) {
  const halfWidth = (box.width || 0) / 2 + padding;
  const halfHeight = (box.height || 0) / 2 + padding;
  return {
    minX: point.x - halfWidth,
    minY: point.y - halfHeight,
    maxX: point.x + halfWidth,
    maxY: point.y + halfHeight,
  };
}

function domainLayoutBox(domain) {
  if (!topologyElementVisible("subnets")) return { width: 18, height: 18 };
  return { width: domain.members.length === 1 ? 164 : 148, height: 66 };
}

function addConnectivityLayoutEdge(adjacency, edgeKeys, left, right) {
  if (!left || !right || left === right || !adjacency.has(left) || !adjacency.has(right)) return;
  const edgeKey = [left, right].sort().join("\u001f");
  if (edgeKeys.has(edgeKey)) return;
  edgeKeys.add(edgeKey);
  adjacency.get(left).add(right);
  adjacency.get(right).add(left);
}

function buildConnectivityLayoutGraph(nodes, domains, compactDecisions, directLinks) {
  const vertices = new Map();
  for (const node of [...nodes].sort((left, right) => compareLayoutIds(left.key, right.key))) {
    const id = `node:${node.key}`;
    vertices.set(id, {
      id,
      kind: "node",
      key: node.key,
      box: { width: MAP_NODE_FALLBACK_WIDTH, height: MAP_NODE_FALLBACK_HEIGHT },
    });
  }
  for (const domain of [...domains].sort((left, right) => compareLayoutIds(left.network_id, right.network_id))) {
    const id = `network:${domain.network_id}`;
    vertices.set(id, {
      id,
      kind: "domain",
      key: domain.network_id,
      box: domainLayoutBox(domain),
    });
  }
  const adjacency = new Map([...vertices.keys()].map((id) => [id, new Set()]));
  const edgeKeys = new Set();
  for (const domain of domains) {
    const domainId = `network:${domain.network_id}`;
    const participantKeys = new Set(topologyDomainParticipants(domain, nodes).map((participant) => participant.node.key));
    for (const nodeKey of [...participantKeys].sort()) {
      addConnectivityLayoutEdge(adjacency, edgeKeys, `node:${nodeKey}`, domainId);
    }
  }
  for (const decision of compactDecisions) {
    const participantKeys = [...new Set(decision.participants.map((participant) => participant.node.key))].sort();
    if (participantKeys.length === 2) {
      addConnectivityLayoutEdge(adjacency, edgeKeys, `node:${participantKeys[0]}`, `node:${participantKeys[1]}`);
    }
  }
  for (const link of directLinks) {
    const source = findNodeForRef(link.source, nodes);
    const target = findNodeForRef(link.target, nodes);
    if (source && target) addConnectivityLayoutEdge(adjacency, edgeKeys, `node:${source.key}`, `node:${target.key}`);
  }
  return { vertices, adjacency };
}

function connectivityLayoutComponents(graph) {
  const remaining = new Set([...graph.vertices.keys()].sort());
  const components = [];
  while (remaining.size) {
    const start = remaining.values().next().value;
    const queue = [start];
    const component = [];
    remaining.delete(start);
    for (let cursor = 0; cursor < queue.length; cursor += 1) {
      const current = queue[cursor];
      component.push(current);
      for (const neighbor of [...graph.adjacency.get(current)].sort()) {
        if (!remaining.has(neighbor)) continue;
        remaining.delete(neighbor);
        queue.push(neighbor);
      }
    }
    components.push(component.sort());
  }
  return components.sort((left, right) => right.length - left.length || compareLayoutIds(left[0], right[0]));
}

function connectivityBfsDistances(start, componentIds, adjacency) {
  const allowed = new Set(componentIds);
  const distances = new Map([[start, 0]]);
  const queue = [start];
  for (let cursor = 0; cursor < queue.length; cursor += 1) {
    const current = queue[cursor];
    for (const neighbor of [...adjacency.get(current)].sort()) {
      if (!allowed.has(neighbor) || distances.has(neighbor)) continue;
      distances.set(neighbor, distances.get(current) + 1);
      queue.push(neighbor);
    }
  }
  return distances;
}

function farthestConnectivityVertex(distances) {
  return [...distances.entries()].sort(
    (left, right) => right[1] - left[1] || compareLayoutIds(left[0], right[0]),
  )[0]?.[0];
}

function rankConnectivityComponent(componentIds, adjacency) {
  const initial = [...componentIds].sort()[0];
  const firstEnd = farthestConnectivityVertex(connectivityBfsDistances(initial, componentIds, adjacency)) || initial;
  const secondPass = connectivityBfsDistances(firstEnd, componentIds, adjacency);
  const secondEnd = farthestConnectivityVertex(secondPass) || firstEnd;
  // A final BFS from the lexically stable peripheral endpoint produces ranks
  // along a deterministic pseudo-diameter without interpreting device or
  // network semantics.
  const rankOrigin = [firstEnd, secondEnd].sort()[0];
  const distances = connectivityBfsDistances(rankOrigin, componentIds, adjacency);
  const ranks = [];
  for (const id of [...componentIds].sort()) {
    const rank = distances.get(id) || 0;
    if (!ranks[rank]) ranks[rank] = [];
    ranks[rank].push(id);
  }
  return ranks.map((rank) => rank || []);
}

function sortConnectivityRank(rank, neighboringRank, adjacency) {
  const neighborOrder = new Map(neighboringRank.map((id, index) => [id, index]));
  const previousOrder = new Map(rank.map((id, index) => [id, index]));
  const barycenter = (id) => {
    const positions = [...adjacency.get(id)].filter((neighbor) => neighborOrder.has(neighbor))
      .map((neighbor) => neighborOrder.get(neighbor));
    return positions.length
      ? positions.reduce((total, position) => total + position, 0) / positions.length
      : previousOrder.get(id);
  };
  rank.sort((left, right) => barycenter(left) - barycenter(right)
    || previousOrder.get(left) - previousOrder.get(right)
    || compareLayoutIds(left, right));
}

function minimizeConnectivityRankCrossings(ranks, adjacency, sweeps = TOPOLOGY_LAYOUT_SWEEPS) {
  const ordered = ranks.map((rank) => [...rank].sort());
  for (let sweep = 0; sweep < sweeps; sweep += 1) {
    for (let rank = 1; rank < ordered.length; rank += 1) {
      sortConnectivityRank(ordered[rank], ordered[rank - 1], adjacency);
    }
    for (let rank = ordered.length - 2; rank >= 0; rank -= 1) {
      sortConnectivityRank(ordered[rank], ordered[rank + 1], adjacency);
    }
  }
  return ordered;
}

function connectivityRankGrid(rank, graph, horizontal) {
  const mainSize = (id) => horizontal ? graph.vertices.get(id).box.width : graph.vertices.get(id).box.height;
  const crossSize = (id) => horizontal ? graph.vertices.get(id).box.height : graph.vertices.get(id).box.width;
  const columns = Math.max(1, Math.ceil(rank.length / TOPOLOGY_LAYOUT_MAX_CROSS_ITEMS));
  const rows = Math.max(1, Math.ceil(rank.length / columns));
  const cellMain = Math.max(...rank.map(mainSize), 1);
  const cellCross = Math.max(...rank.map(crossSize), 1);
  const mainSpan = columns * cellMain + Math.max(0, columns - 1) * TOPOLOGY_LAYOUT_GRID_GAP;
  const crossSpan = rows * cellCross + Math.max(0, rows - 1) * TOPOLOGY_LAYOUT_CROSS_GAP;
  const offsets = new Map();
  rank.forEach((id, index) => {
    const row = Math.floor(index / columns);
    const column = index % columns;
    offsets.set(id, {
      main: column * (cellMain + TOPOLOGY_LAYOUT_GRID_GAP) + cellMain / 2 - mainSpan / 2,
      cross: row * (cellCross + TOPOLOGY_LAYOUT_CROSS_GAP) + cellCross / 2 - crossSpan / 2,
    });
  });
  return { mainSpan, crossSpan, offsets };
}

function layoutConnectivityComponent(componentIds, graph, horizontal, targetMainSpan) {
  const ranks = minimizeConnectivityRankCrossings(
    rankConnectivityComponent(componentIds, graph.adjacency),
    graph.adjacency,
  );
  const rankGrids = ranks.map((rank) => connectivityRankGrid(rank, graph, horizontal));
  const rankThicknesses = rankGrids.map((grid) => grid.mainSpan);
  const rankCrossSpans = rankGrids.map((grid) => grid.crossSpan);
  const bands = [];
  let currentBand = [];
  let currentMainSpan = 0;
  ranks.forEach((rank, rankIndex) => {
    const nextSpan = currentMainSpan
      + (currentBand.length ? TOPOLOGY_LAYOUT_RANK_GAP : 0)
      + rankThicknesses[rankIndex];
    if (currentBand.length && nextSpan > targetMainSpan) {
      bands.push(currentBand);
      currentBand = [];
      currentMainSpan = 0;
    }
    currentMainSpan += (currentBand.length ? TOPOLOGY_LAYOUT_RANK_GAP : 0) + rankThicknesses[rankIndex];
    currentBand.push(rankIndex);
  });
  if (currentBand.length) bands.push(currentBand);
  const positions = new Map();
  const bandMetrics = bands.map((rankIndexes) => ({
    rankIndexes,
    mainSpan: rankIndexes.reduce(
      (total, rankIndex, index) => total + rankThicknesses[rankIndex] + (index ? TOPOLOGY_LAYOUT_RANK_GAP : 0),
      0,
    ),
    crossSpan: Math.max(...rankIndexes.map((rankIndex) => rankCrossSpans[rankIndex]), 1),
  }));
  const componentMainSpan = Math.max(...bandMetrics.map((band) => band.mainSpan), 1);
  let bandCrossCursor = 0;
  bandMetrics.forEach((band, bandIndex) => {
    const mirrored = bandIndex % 2 === 1;
    const bandMainOffset = (componentMainSpan - band.mainSpan) / 2;
    let rankMainCursor = 0;
    band.rankIndexes.forEach((rankIndex, index) => {
      if (index) rankMainCursor += TOPOLOGY_LAYOUT_RANK_GAP;
      const normalMain = rankMainCursor + rankThicknesses[rankIndex] / 2;
      for (const id of ranks[rankIndex]) {
        const local = rankGrids[rankIndex].offsets.get(id);
        const itemMain = normalMain + local.main;
        const main = bandMainOffset + (mirrored ? band.mainSpan - itemMain : itemMain);
        const cross = bandCrossCursor + band.crossSpan / 2 + local.cross;
        positions.set(id, horizontal ? { x: main, y: cross } : { x: cross, y: main });
      }
      rankMainCursor += rankThicknesses[rankIndex];
    });
    bandCrossCursor += band.crossSpan + TOPOLOGY_LAYOUT_BAND_GAP;
  });
  const rects = [...positions.entries()].map(([id, point]) => layoutRect(point, graph.vertices.get(id).box));
  const minX = Math.min(...rects.map((rect) => rect.minX));
  const minY = Math.min(...rects.map((rect) => rect.minY));
  const maxX = Math.max(...rects.map((rect) => rect.maxX));
  const maxY = Math.max(...rects.map((rect) => rect.maxY));
  positions.forEach((point) => {
    point.x -= minX;
    point.y -= minY;
  });
  return { positions, width: maxX - minX, height: maxY - minY };
}

function connectivityLayoutSignature(nodes, domains, compactDecisions, directLinks, layoutMode = {}) {
  const records = [
    `layout:${layoutMode.orientation || "unknown"}:${layoutMode.domainBoxMode || "unknown"}:${layoutMode.geometrySignature || "unknown"}`,
    ...nodes.map((node) => `node:${node.key}`),
    ...domains.map((domain) => {
      const participants = topologyDomainParticipants(domain, nodes).map((participant) => participant.node.key).sort();
      return `domain:${domain.network_id}:${participants.join(",")}`;
    }),
    ...compactDecisions.map((decision) => {
      const participants = decision.participants.map((participant) => participant.node.key).sort();
      return `compact:${decision.domain.network_id}:${participants.join(",")}`;
    }),
    ...directLinks.map((link) => {
      const source = findNodeForRef(link.source, nodes)?.key || "";
      const target = findNodeForRef(link.target, nodes)?.key || "";
      return `direct:${link.link_id}:${[source, target].sort().join(",")}`;
    }),
  ].sort();
  return `${records.length}-${stableLayoutHash(records.join("\u001e")).toString(36)}`;
}

function connectivityLayoutGeometrySignature(dimensions) {
  const records = [
    ...[...dimensions.positions.entries()].map(
      ([key, point]) => `node:${key}:${Math.round(point.x)}:${Math.round(point.y)}`,
    ),
    ...[...dimensions.domainPositions.entries()].map(
      ([key, point]) => `domain:${key}:${Math.round(point.x)}:${Math.round(point.y)}`,
    ),
  ].sort();
  return `${Math.round(dimensions.width)}x${Math.round(dimensions.height)}-${stableLayoutHash(records.join("\u001e")).toString(36)}`;
}

function mapConnectivityLayout(nodes, domains, compactDecisions = [], directLinks = [], options = {}) {
  const stage = byId(options.stageId || "mn-map-stage");
  const minHeight = Number(options.minHeight || 520);
  const viewportWidth = Math.max(stage.clientWidth || 720, 720);
  const horizontal = viewportWidth >= 760;
  const graph = buildConnectivityLayoutGraph(nodes, domains, compactDecisions, directLinks);
  const targetMainSpan = horizontal ? Math.max(1120, viewportWidth + 180) : 720;
  const components = connectivityLayoutComponents(graph).map(
    (componentIds) => layoutConnectivityComponent(componentIds, graph, horizontal, targetMainSpan),
  );
  const packingWidth = Math.max(
    viewportWidth - TOPOLOGY_LAYOUT_OUTER_PADDING * 2,
    ...components.map((component) => component.width),
    1,
  );
  const packedPositions = new Map();
  let cursorX = 0;
  let cursorY = 0;
  let rowHeight = 0;
  let packedWidth = 0;
  for (const component of components) {
    if (cursorX > 0 && cursorX + component.width > packingWidth) {
      cursorX = 0;
      cursorY += rowHeight + TOPOLOGY_LAYOUT_COMPONENT_GAP;
      rowHeight = 0;
    }
    component.positions.forEach((point, id) => packedPositions.set(id, {
      x: point.x + cursorX,
      y: point.y + cursorY,
    }));
    cursorX += component.width + TOPOLOGY_LAYOUT_COMPONENT_GAP;
    rowHeight = Math.max(rowHeight, component.height);
    packedWidth = Math.max(packedWidth, cursorX - TOPOLOGY_LAYOUT_COMPONENT_GAP);
  }
  const packedHeight = cursorY + rowHeight;
  const width = Math.max(viewportWidth, packedWidth + TOPOLOGY_LAYOUT_OUTER_PADDING * 2);
  const height = Math.max(minHeight, packedHeight + TOPOLOGY_LAYOUT_OUTER_PADDING * 2);
  const offsetX = (width - packedWidth) / 2;
  const offsetY = (height - packedHeight) / 2;
  const positions = new Map();
  const domainPositions = new Map();
  for (const [id, point] of packedPositions.entries()) {
    const vertex = graph.vertices.get(id);
    const shifted = { x: point.x + offsetX, y: point.y + offsetY };
    if (vertex.kind === "node") positions.set(vertex.key, shifted);
    else domainPositions.set(vertex.key, shifted);
  }
  return {
    columns: horizontal ? Math.max(...components.map((component) => component.positions.size), 1) : components.length,
    rows: horizontal ? components.length : Math.max(...components.map((component) => component.positions.size), 1),
    width,
    height,
    positions,
    domainPositions,
    routeNodeKeys: new Set(),
    orientation: horizontal ? "horizontal" : "vertical",
    domainBoxMode: topologyElementVisible("subnets") ? "domain-boxes" : "junctions",
  };
}

function interactionTokensForNode(node) {
  return (state.routeTrace?.interaction_targets || [])
    .filter((target) => target?.member_id === node.member_id || target?.node_id === node.node_id
      || target?.resource_ref?.member_id === node.member_id)
    .map((target) => `target:${target.target_id}`);
}

function interactionFocusTargetsForNode(node) {
  const targetIds = (state.routeTrace?.interaction_targets || [])
    .filter((target) => /^(topology_?node|node)$/.test(String(target?.kind || ""))
      && (target?.member_id === node.member_id || target?.node_id === node.node_id))
    .map((target) => target.target_id);
  return [...new Set([...targetIds, `node-member:${node.member_id}`])];
}

function interactionTokensForLink(link) {
  return (state.routeTrace?.interaction_targets || [])
    .filter((target) => String(target?.topology_link_id || "") === link.link_id)
    .map((target) => `target:${target.target_id}`);
}

function interactionFocusTargetsForLink(link) {
  const targetIds = (state.routeTrace?.interaction_targets || [])
    .filter((target) => /^(topology_?link|link)$/.test(String(target?.kind || ""))
      && String(target?.topology_link_id || "") === link.link_id)
    .map((target) => target.target_id);
  return [...new Set([...targetIds, `link:${link.link_id}`])];
}

function interactionTokensForDomain(domain) {
  return (state.routeTrace?.interaction_targets || [])
    .filter((target) => String(target?.network_segment_id || "") === domain.network_id)
    .map((target) => `target:${target.target_id}`);
}

function interactionFocusTargetsForDomain(domain) {
  const targetIds = (state.routeTrace?.interaction_targets || [])
    .filter((target) => /^(network_?segment|connectivity_?domain)$/.test(String(target?.kind || ""))
      && String(target?.network_segment_id || "") === domain.network_id)
    .map((target) => target.target_id);
  return [...new Set([...targetIds, `network-segment:${domain.network_id}`])];
}

function persistentGraphPositions(viewKey, layoutKey, defaults) {
  const view = state.graphViews[viewKey];
  const positions = new Map();
  const storageKeys = new Map();
  for (const [key, point] of defaults.entries()) {
    const storageKey = `${layoutKey}|${key}`;
    if (!view.positions.has(storageKey)) view.positions.set(storageKey, { ...point });
    positions.set(key, { ...view.positions.get(storageKey) });
    storageKeys.set(key, storageKey);
  }
  return { positions, storageKeys };
}

function graphWorldLayers(stage) {
  return [...stage.children].filter((element) => element.matches("svg, #mn-node-layer, #mn-route-node-layer"));
}

function applyGraphTransform(stageId, viewKey) {
  const stage = byId(stageId);
  const view = state.graphViews[viewKey];
  if (!stage || !view) return;
  const transform = `translate(${view.panX}px, ${view.panY}px) scale(${view.scale})`;
  graphWorldLayers(stage).forEach((layer) => {
    layer.style.transformOrigin = "0 0";
    layer.style.transform = transform;
  });
  const readout = stage.querySelector("[data-graph-zoom-readout]");
  if (readout) readout.textContent = `${Math.round(view.scale * 100)}%`;
  stage.style.setProperty("--mn-graph-grid-scale", String(view.scale));
  stage.style.setProperty("--mn-graph-grid-x", `${view.panX}px`);
  stage.style.setProperty("--mn-graph-grid-y", `${view.panY}px`);
  // Layer toggles grant permission to display detail; semantic zoom decides
  // when dense labels remain legible enough to paint them.
  stage.dataset.graphDetail = view.scale < 0.9 ? "overview" : view.scale > 1.35 ? "detail" : "normal";
}

function graphBounds(positions, boxes = new Map()) {
  if (!positions.size) return { minX: 0, minY: 0, maxX: 1, maxY: 1 };
  let minX = Number.POSITIVE_INFINITY;
  let minY = Number.POSITIVE_INFINITY;
  let maxX = Number.NEGATIVE_INFINITY;
  let maxY = Number.NEGATIVE_INFINITY;
  for (const [key, point] of positions.entries()) {
    const box = boxes.get(key) || { width: 120, height: 54 };
    minX = Math.min(minX, point.x - box.width / 2);
    minY = Math.min(minY, point.y - box.height / 2);
    maxX = Math.max(maxX, point.x + box.width / 2);
    maxY = Math.max(maxY, point.y + box.height / 2);
  }
  return { minX, minY, maxX, maxY };
}

function zoomGraphAt(stageId, viewKey, nextScale, clientX, clientY) {
  const stage = byId(stageId);
  const view = state.graphViews[viewKey];
  if (!stage || !view || !Number.isFinite(nextScale) || nextScale <= 1e-5 || nextScale >= 1e5) return;
  const rect = stage.getBoundingClientRect();
  const localX = (clientX ?? rect.left + rect.width / 2) - rect.left;
  const localY = (clientY ?? rect.top + rect.height / 2) - rect.top;
  const worldX = (localX - view.panX) / view.scale;
  const worldY = (localY - view.panY) / view.scale;
  view.scale = nextScale;
  view.panX = localX - worldX * nextScale;
  view.panY = localY - worldY * nextScale;
  applyGraphTransform(stageId, viewKey);
}

function fitGraphViewport(stageId, viewKey) {
  const stage = byId(stageId);
  const view = state.graphViews[viewKey];
  if (!stage || !view?.bounds) return;
  const rect = stage.getBoundingClientRect();
  const bounds = view.bounds;
  const width = Math.max(1, bounds.maxX - bounds.minX);
  const height = Math.max(1, bounds.maxY - bounds.minY);
  const padding = 52;
  const scale = Math.max(1e-5, Math.min((rect.width - padding * 2) / width, (rect.height - padding * 2) / height));
  view.scale = scale;
  view.panX = rect.width / 2 - ((bounds.minX + bounds.maxX) / 2) * scale;
  view.panY = rect.height / 2 - ((bounds.minY + bounds.maxY) / 2) * scale;
  view.initialized = true;
  applyGraphTransform(stageId, viewKey);
}

function setupGraphViewport({ stageId, viewKey, layoutKey, modelPositions, storageKeys, boxes, redraw, defaultPositions = null }) {
  const stage = byId(stageId);
  const view = state.graphViews[viewKey];
  if (!stage || !view) return;
  if (view.activeLayoutKey !== layoutKey) {
    if (view.activeLayoutKey) view.viewports.set(view.activeLayoutKey, {
      scale: view.scale, panX: view.panX, panY: view.panY, initialized: view.initialized,
    });
    const savedViewport = view.viewports.get(layoutKey);
    view.scale = savedViewport?.scale ?? 1;
    view.panX = savedViewport?.panX ?? 0;
    view.panY = savedViewport?.panY ?? 0;
    view.initialized = savedViewport?.initialized ?? false;
    view.activeLayoutKey = layoutKey;
  }
  view.bounds = graphBounds(modelPositions, boxes);
  view.dimensions = {
    width: view.bounds.maxX - view.bounds.minX,
    height: view.bounds.maxY - view.bounds.minY,
  };
  view.redraw = redraw;

  let pan = null;
  stage.onpointerdown = (event) => {
    if (event.button !== 0 || event.target.closest("[data-graph-position-key], [data-route-presentation-trigger], [data-topology-inspect-key], path[role='button'], button, select, a")) return;
    if (!state.topologyInspectorPinned) clearTopologyInspector();
    stage.focus({ preventScroll: true });
    pan = { id: event.pointerId, x: event.clientX, y: event.clientY, panX: view.panX, panY: view.panY };
    stage.setPointerCapture(event.pointerId);
    stage.classList.add("is-graph-panning");
    event.preventDefault();
  };
  stage.onpointermove = (event) => {
    if (!pan || pan.id !== event.pointerId) return;
    view.panX = pan.panX + event.clientX - pan.x;
    view.panY = pan.panY + event.clientY - pan.y;
    applyGraphTransform(stageId, viewKey);
  };
  const finishPan = (event) => {
    if (!pan || (event?.pointerId !== undefined && pan.id !== event.pointerId)) return;
    pan = null;
    stage.classList.remove("is-graph-panning");
  };
  stage.onpointerup = finishPan;
  stage.onpointercancel = finishPan;
  stage.onwheel = (event) => {
    const deltaUnit = event.deltaMode === WheelEvent.DOM_DELTA_LINE ? 16
      : event.deltaMode === WheelEvent.DOM_DELTA_PAGE ? Math.max(1, stage.clientHeight) : 1;
    const deltaX = event.deltaX * deltaUnit;
    const deltaY = event.deltaY * deltaUnit;
    const pinchZoom = event.ctrlKey || event.metaKey;
    const horizontalPan = Math.abs(deltaX) > Math.abs(deltaY) || event.shiftKey;
    const engaged = document.activeElement === stage || stage.contains(document.activeElement);
    // Ordinary vertical scrolling over an unengaged graph continues down the
    // page. Click/focus the graph first to pan vertically with a trackpad.
    if (!pinchZoom && !horizontalPan && !engaged) return;
    event.preventDefault();
    if (!state.topologyInspectorPinned) clearTopologyInspector();
    if (pinchZoom) {
      const factor = Math.exp(-deltaY * 0.0025);
      zoomGraphAt(stageId, viewKey, view.scale * factor, event.clientX, event.clientY);
      return;
    }
    // Native trackpad two-finger motion pans the logical world. Shift+wheel
    // remains a horizontal pan for conventional mouse wheels.
    view.panX -= deltaX || (event.shiftKey ? deltaY : 0);
    view.panY -= event.shiftKey ? 0 : deltaY;
    applyGraphTransform(stageId, viewKey);
  };
  stage.setAttribute("aria-keyshortcuts", "ArrowUp ArrowDown ArrowLeft ArrowRight + - 0 F");
  stage.onkeydown = (event) => {
    if (event.target !== stage) return;
    const panStep = event.shiftKey ? 80 : 36;
    if (["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown"].includes(event.key)) {
      if (event.key === "ArrowLeft") view.panX += panStep;
      if (event.key === "ArrowRight") view.panX -= panStep;
      if (event.key === "ArrowUp") view.panY += panStep;
      if (event.key === "ArrowDown") view.panY -= panStep;
      event.preventDefault();
      applyGraphTransform(stageId, viewKey);
      return;
    }
    if (["+", "=", "-", "_"].includes(event.key)) {
      event.preventDefault();
      zoomGraphAt(stageId, viewKey, view.scale * (["+", "="].includes(event.key) ? 1.25 : 0.8));
      return;
    }
    if (event.key === "0") {
      event.preventDefault();
      const rect = stage.getBoundingClientRect();
      zoomGraphAt(stageId, viewKey, 1, rect.left + rect.width / 2, rect.top + rect.height / 2);
      return;
    }
    if (event.key.toLowerCase() === "f") {
      event.preventDefault();
      fitGraphViewport(stageId, viewKey);
    }
  };
  stage.querySelectorAll("[data-graph-action]").forEach((button) => {
    button.onclick = () => {
      const action = button.dataset.graphAction;
      if (action === "fit") fitGraphViewport(stageId, viewKey);
      if (action === "reset" && defaultPositions) {
        for (const [positionKey, defaultPoint] of defaultPositions.entries()) {
          const point = { ...defaultPoint };
          modelPositions.set(positionKey, point);
          const storageKey = storageKeys.get(positionKey);
          if (storageKey) view.positions.set(storageKey, { ...point });
          const element = stage.querySelector(`[data-graph-position-key="${CSS.escape(positionKey)}"]`);
          if (element) {
            element.style.left = `${point.x}px`;
            element.style.top = `${point.y}px`;
          }
        }
        view.bounds = graphBounds(modelPositions, boxes);
        redraw();
        fitGraphViewport(stageId, viewKey);
        showToast("Topology layout and viewport reset.");
      }
      if (action === "actual") {
        const rect = stage.getBoundingClientRect();
        zoomGraphAt(stageId, viewKey, 1, rect.left + rect.width / 2, rect.top + rect.height / 2);
      }
      if (action === "zoom-in" || action === "zoom-out") {
        const factor = action === "zoom-in" ? 1.25 : 0.8;
        zoomGraphAt(stageId, viewKey, view.scale * factor);
      }
    };
  });

  stage.querySelectorAll("[data-graph-position-key]").forEach((element) => {
    const positionKey = element.dataset.graphPositionKey;
    let drag = null;
    element.onpointerdown = (event) => {
      if (event.button !== 0 || event.target.closest("a, select, .mn-route-node-paths")) return;
      const point = modelPositions.get(positionKey);
      if (!point) return;
      drag = { id: event.pointerId, x: event.clientX, y: event.clientY, point: { ...point }, moved: false };
      element.setPointerCapture(event.pointerId);
      element.classList.add("is-graph-dragging");
      event.stopPropagation();
    };
    element.onpointermove = (event) => {
      if (!drag || drag.id !== event.pointerId) return;
      const dx = (event.clientX - drag.x) / view.scale;
      const dy = (event.clientY - drag.y) / view.scale;
      if (Math.hypot(dx, dy) > 3 / view.scale) drag.moved = true;
      const point = { x: drag.point.x + dx, y: drag.point.y + dy };
      modelPositions.set(positionKey, point);
      const storageKey = storageKeys.get(positionKey);
      if (storageKey) view.positions.set(storageKey, { ...point });
      element.style.left = `${point.x}px`;
      element.style.top = `${point.y}px`;
      view.bounds = graphBounds(modelPositions, boxes);
      cancelAnimationFrame(view.dragFrame);
      view.dragFrame = requestAnimationFrame(redraw);
      event.preventDefault();
      event.stopPropagation();
    };
    const finishDrag = (event) => {
      if (!drag || (event?.pointerId !== undefined && drag.id !== event.pointerId)) return;
      element.dataset.graphDragMoved = drag.moved ? "true" : "";
      drag = null;
      element.classList.remove("is-graph-dragging");
      requestAnimationFrame(() => { delete element.dataset.graphDragMoved; });
    };
    element.onpointerup = finishDrag;
    element.onpointercancel = finishDrag;
  });
  applyGraphTransform(stageId, viewKey);
  if (!view.initialized) requestAnimationFrame(() => fitGraphViewport(stageId, viewKey));
}

function mapNodeMarkup(node, position, routePath = null, routeNodes = [], extraClass = "", options = {}) {
  const health = nodeHealth(node);
  const basis = basisForNode(node);
  const plan = node.plan || nodePlan(node);
  const tokens = [`member:${node.member_id}`, `node:${node.node_id}`, ...interactionTokensForNode(node)];
  const routeSegments = routeForwardingSegments(routePath).filter((segment) =>
    (node.route_occurrence_id
      ? [segment.source_occurrence_id, segment.target_occurrence_id].includes(node.route_occurrence_id)
      : refRouteTokens(segment.source).some((token) => tokens.includes(token))
        || refRouteTokens(segment.target).some((token) => tokens.includes(token)))
  ) || [];
  const routeClasses = routePath ? routeNodeQualityClasses(node, routePath) : [];
  const routeMember = Boolean(routeSegments.length);
  const routeIndex = routeNodes.findIndex((candidate) => candidate.key === node.key);
  const isSource = routePath && routeIndex === 0;
  const isDestination = routePath && routeIndex === routeNodes.length - 1;
  const startMarker = state.activeRouteDirection === "reverse"
    ? "RETURN START"
    : "TRACE START";
  const endMarker = state.activeRouteDirection === "reverse" ? "SOURCE TARGET" : "DESTINATION";
  const controlPlaneOnly = pathIsControlPlaneOnly(routePath);
  const isInstallGate = Boolean(isSource && controlPlaneOnly);
  const routeMarker = isInstallGate
    ? '<b class="mn-route-node-state is-control-plane-only" title="Not installed for forwarding" aria-label="Not installed for forwarding">NO FIB</b>'
    : controlPlaneOnly
      ? '<b class="mn-route-node-state is-control-plane-only" title="Control-plane resolution evidence" aria-label="Control-plane resolution evidence">EVIDENCE</b>'
      : `<b class="mn-route-node-marker">L3 · ${node.route_occurrence_id
        ? `visit ${Number(node.route_occurrence_index ?? routeIndex) + 1}` : "on path"}</b>`;
  const navigationKey = node.route_base_key || node.key;
  const packetRefs = packetRefsForRouteNode(routePath, node);
  const globallySelected = options.showGlobalSelection !== false && state.focusedNodeKey === navigationKey;
  const directionDifferenceLabel = String(options.directionDifferenceLabel || "");
  const titleDetail = directionDifferenceLabel
    ? `${node.label} · ${directionDifferenceLabel}; hover for snapshot details; click to focus this node`
    : `${node.label} · hover for snapshot details; click to focus this node`;
  return `<button class="mn-map-node${globallySelected ? " is-selected" : ""}${node.resources_available === false ? " is-incomplete" : ""}${routeMember ? ` is-route-member ${routeClasses.join(" ")}` : ""}${isSource ? " is-route-source" : ""}${isDestination ? " is-route-destination" : ""}${extraClass}" type="button" title="${escapeHtml(titleDetail)}" data-map-node="${escapeHtml(navigationKey)}" data-route-occurrence-id="${escapeHtml(node.route_occurrence_id || "")}" data-graph-position-key="node:${escapeHtml(node.key)}" data-route-kind="node" data-route-id="${escapeHtml(node.member_id)}" data-route-start-label="${escapeHtml(startMarker)}" data-route-end-label="${escapeHtml(endMarker)}" data-route-tokens="${routeTokensAttribute(tokens)}" data-route-focus-targets="${routeFocusTargetsAttribute(interactionFocusTargetsForNode(node))}" data-route-packet-refs="${packetRefsAttribute(packetRefs)}" style="left:${position.x}px;top:${position.y}px">
    ${directionDifferenceLabel ? `<b class="mn-route-direction-badge">${escapeHtml(directionDifferenceLabel)}</b>` : ""}
    <header><span><strong>${escapeHtml(node.label)}</strong><small>${escapeHtml(`${node.site} · ${node.device_type}`)}</small></span><i class="mn-health-dot is-${health}" aria-label="${escapeHtml(health)}"></i></header>
    <code title="${escapeHtml(`${plan.plugin_set_id}@${plan.plugin_version || "?"}`)}">${escapeHtml(`${plan.plugin_set_id}@${plan.plugin_version || "?"}`)}</code>
    <footer><span>${escapeHtml(plan.projection_id)}</span><span>${routeMember ? routeMarker : escapeHtml(formatDurationNs(basis.uncertainty || 0))}</span></footer>
  </button>`;
}

function renderNodeGraph({ nodes, routePath = null, stageId, nodeLayerId, edgeLayerId, emptyId, showTopology, showRoute, minHeight, columnPitch, outerPadding, fallbackWidth, nodeClassFor = null, nodeOptionsFor = null, routeDirectionDifference = null }) {
  const layer = byId(nodeLayerId);
  const empty = byId(emptyId);
  empty.hidden = Boolean(nodes.length);
  if (!nodes.length) {
    layer.innerHTML = "";
    byId(edgeLayerId).innerHTML = "";
    return;
  }
  const dimensions = showTopology && !showRoute
    ? mapTopologyLayout(nodes, { stageId, minHeight })
    : mapLayout(nodes, routePath, { stageId, minHeight, columnPitch, outerPadding, fallbackWidth });
  layer.style.width = `${dimensions.width}px`;
  layer.style.height = `${dimensions.height}px`;
  const viewKey = stageId === "mn-map-stage" ? "topology" : "route";
  const layoutKey = viewKey === "topology"
    ? `topology:${state.query?.context_id || "query"}:${state.topologyNetworkView}`
    : `route:${state.query?.context_id || "query"}:${state.routeGraphMode}:${state.activeRouteDirection}:${routePath?.path_id || "empty"}`;
  const stored = persistentGraphPositions(viewKey, layoutKey, new Map(
    [...dimensions.positions.entries()].map(([key, point]) => [`node:${key}`, point])
  ));
  const positions = new Map(nodes.map((node) => [node.key, stored.positions.get(`node:${node.key}`)]));
  const routeNodes = routeNodeSequence(routePath, nodes);
  layer.innerHTML = nodes.map((node) => mapNodeMarkup(
    node,
    positions.get(node.key),
    routePath,
    routeNodes,
    nodeClassFor?.(node) || "",
    nodeOptionsFor?.(node) || {},
  )).join("");
  layer.querySelectorAll("[data-map-node]").forEach((button) => button.addEventListener("click", () => {
    if (button.dataset.graphDragMoved === "true") return;
    focusNode(button.dataset.mapNode);
  }));
  const nodeBoxes = new Map(
    [...layer.querySelectorAll("[data-map-node]")].map((button) => [
      String(button.dataset.graphPositionKey || "").replace(/^node:/, "") || button.dataset.mapNode,
      { width: button.offsetWidth, height: button.offsetHeight },
    ])
  );
  const redraw = () => {
    nodes.forEach((node) => positions.set(node.key, stored.positions.get(`node:${node.key}`)));
    renderEdges(nodes, positions, dimensions, nodeBoxes, {
      edgeLayerId,
      routePath,
      showTopology,
      showRoute,
      routeDirectionDifference,
    });
  };
  redraw();
  bindRouteCorrelationElements(byId(stageId));
  if (stageId === "mn-route-map-stage") bindRoutePacketGraphElements(layer);
  setupGraphViewport({
    stageId,
    viewKey,
    layoutKey,
    modelPositions: stored.positions,
    storageKeys: stored.storageKeys,
    boxes: new Map(nodes.map((node) => [`node:${node.key}`, nodeBoxes.get(node.key)])),
    redraw,
  });
}

function connectivityDomainMarkup(domain, position, extraClass = "") {
  const health = linkHealth(domain);
  const vpn = isVpnConnectivityDomain(domain);
  const oneSided = domain.members.length === 1;
  const external = domain.plugin_asserted_external === true;
  const showSubnet = topologyElementVisible("subnets");
  const scope = domain.vrf ? `${String(domain.routing_scope_kind).toLowerCase() === "vrf" ? "VRF " : ""}${domain.vrf}` : "";
  const meta = [domain.prefix, scope, topologyElementVisible("vlans")
    && domain.vlan !== null && domain.vlan !== undefined ? `VLAN ${domain.vlan}` : ""]
    .filter(Boolean).join(" · ");
  const memberLabel = oneSided ? external ? "external attachment" : "one visible attachment" : `${domain.members.length} attachments`;
  const label = `${connectivityDomainLabel(domain)}, ${memberLabel}`;
  const content = showSubnet
    ? `<span>${vpn ? "VPN" : "SUBNET"}</span><strong title="${escapeHtml(connectivityDomainLabel(domain))}">${escapeHtml(connectivityDomainLabel(domain))}</strong>
      <small>${escapeHtml(meta || memberLabel)}</small><i>${escapeHtml(memberLabel)}</i>`
    : `<span class="sr-only">${escapeHtml(label)}</span>`;
  const routeTokens = [
    `network-segment:${domain.network_id}`,
    ...domain.members.map((member) => `network-attachment:${member.member_id}`),
    ...interactionTokensForDomain(domain),
  ];
  const focusTargets = interactionFocusTargetsForDomain(domain);
  return `<div class="mn-network-segment is-${health}${vpn ? " is-vpn" : ""}${oneSided ? " is-one-sided" : ""}${showSubnet ? "" : " is-junction-only"}${extraClass}" tabindex="0" role="button" data-network-segment="${escapeHtml(domain.network_id)}" data-route-tokens="${routeTokensAttribute(routeTokens)}" data-route-focus-targets="${routeFocusTargetsAttribute(focusTargets)}" data-topology-inspect-key="domain:${escapeHtml(domain.network_id)}" data-graph-position-key="network:${escapeHtml(domain.network_id)}" aria-haspopup="dialog" aria-controls="mn-topology-hover-card" style="left:${position.x}px;top:${position.y}px" aria-label="${escapeHtml(`${label}; show calculated topology details`)}">${content}</div>`;
}

function attachmentEdgeAttributes(link, node, domain, member) {
  const links = member.links || [];
  const linkIds = [...new Set([...(member.link_ids || []), ...links.map((item) => item.link_id)])];
  const tokens = [`network-segment:${domain.network_id}`, `network-attachment:${member.member_id}`,
    ...interactionTokensForDomain(domain),
    ...linkIds.map((id) => `link:${id}`), ...refRouteTokens(member.ref),
    ...links.flatMap((item) => [...refRouteTokens(item.source), ...refRouteTokens(item.target), ...interactionTokensForLink(item)])];
  const targets = [...interactionFocusTargetsForDomain(domain), ...links.flatMap(interactionFocusTargetsForLink)];
  return `data-route-kind="topology-link" data-route-id="${escapeHtml(link?.link_id || member.member_id)}" data-network-segment-id="${escapeHtml(domain.network_id)}" data-network-attachment-id="${escapeHtml(member.member_id)}" data-topology-inspect-key="attachment:${escapeHtml(domain.network_id)}:${escapeHtml(member.member_id)}" data-route-tokens="${routeTokensAttribute([...new Set(tokens)])}" data-route-focus-targets="${routeFocusTargetsAttribute([...new Set(targets)])}" data-source-node-key="${escapeHtml(node.key)}" aria-haspopup="dialog" aria-controls="mn-topology-hover-card"`;
}

function topologyContextAttributes({
  networkId = "",
  attachmentId = "",
  linkId = "",
  sourceKey = "",
  targetKey = "",
} = {}) {
  return [
    "data-topology-context-item",
    networkId ? `data-network-segment-id="${escapeHtml(networkId)}"` : "",
    attachmentId ? `data-network-attachment-id="${escapeHtml(attachmentId)}"` : "",
    linkId ? `data-topology-link-id="${escapeHtml(linkId)}"` : "",
    sourceKey ? `data-source-node-key="${escapeHtml(sourceKey)}"` : "",
    targetKey ? `data-target-node-key="${escapeHtml(targetKey)}"` : "",
  ].filter(Boolean).join(" ");
}

function quadraticEdgePoint(geometry, position) {
  const inverse = 1 - position;
  return {
    x: inverse * inverse * geometry.source.x + 2 * inverse * position * geometry.control.x + position * position * geometry.target.x,
    y: inverse * inverse * geometry.source.y + 2 * inverse * position * geometry.control.y + position * position * geometry.target.y,
  };
}

function renderAttachmentComponents(attachment, geometry, attrs, options = {}) {
  const components = topologyAttachmentComponents(attachment);
  const health = safeClass(options.health || "unknown");
  const vpn = options.vpn === true;
  const reverse = options.reverse === true;
  const groupCount = Math.max(1, Number(options.groupCount) || 1);
  const groupOrdinal = Math.max(0, Math.min(groupCount - 1, Number(options.groupOrdinal) || 0));
  const groupSpacing = groupCount <= 1 ? 0 : Math.min(0.055, 0.18 / (groupCount - 1));
  const groupOffset = (groupOrdinal - (groupCount - 1) / 2) * groupSpacing;
  const rank = { interface: 0.2, lag: 0.35, subinterface: 0.5, vlan: 0.66 };
  const totals = new Map();
  const ordinals = new Map();
  components.forEach((component) => totals.set(component.kind, (totals.get(component.kind) || 0) + 1));
  return components.map((component) => {
    const count = totals.get(component.kind) || 1;
    const ordinal = ordinals.get(component.kind) || 0;
    ordinals.set(component.kind, ordinal + 1);
    const spacing = count <= 1 ? 0 : Math.min(0.065, 0.22 / (count - 1));
    const componentPosition = Math.max(0.075, Math.min(0.82,
      rank[component.kind] + groupOffset + (ordinal - (count - 1) / 2) * spacing));
    const pathPosition = reverse ? 1 - componentPosition : componentPosition;
    const point = quadraticEdgePoint(geometry, pathPosition);
    const width = Math.min(122, Math.max(40, component.label.length * 5.1 + 14));
    const label = `${component.full}${attachment.address ? `; address ${attachment.address}` : ""}`;
    return `<g data-topology-context-item class="mn-attachment-component is-${component.kind} is-${health}${vpn ? " is-vpn" : ""}" tabindex="-1" role="button" aria-label="${escapeHtml(`${label}; show calculated topology details`)}" ${attrs} transform="translate(${point.x} ${point.y})">
      <rect x="${-width / 2}" y="-8" width="${width}" height="16" rx="5"></rect>
      <text text-anchor="middle" dominant-baseline="central">${escapeHtml(component.label)}</text>
    </g>`;
  }).join("");
}

function visibleDirectTopologyLinks(nodes, visibleDomains) {
  const planeHasSegments = visibleDomains.length > 0;
  return (state.query?.links || []).filter((link) => {
    const routeTraceRole = String(link.presentation?.route_trace ?? "include");
    const routeIncluded = routeTraceRole === "include";
    if (!routeIncluded || link.resolution_only) return false;
    const legacyFallback = link.unrepresented_legacy === true
      || link.presentation?.unrepresented_legacy === true
      || (state.topologyNetworkView === "underlay" && !planeHasSegments && !connectivityDomainKey(link));
    if (!legacyFallback) return false;
    const source = findNodeForRef(link.source, nodes);
    const target = findNodeForRef(link.target, nodes);
    return Boolean(source && target && source.key !== target.key);
  });
}

function renderConnectivityEdges(nodes, hubDomains, compactDecisions, positions, domainPositions, dimensions, nodeBoxes, domainBoxes, options = {}) {
  const svg = byId("mn-link-layer");
  svg.setAttribute("width", dimensions.width);
  svg.setAttribute("height", dimensions.height);
  svg.setAttribute("viewBox", `0 0 ${dimensions.width} ${dimensions.height}`);
  const markup = [];
  const focusKey = options.focusKey || "";
  const emphasized = options.emphasized || new Set(nodes.map((node) => node.key));
  const filterActive = emphasized.size < nodes.length;
  const orderedHubDomains = [...hubDomains].sort(
    (left, right) => compareLayoutIds(left.network_id, right.network_id),
  );
  const orderedCompactDecisions = [...compactDecisions].sort(
    (left, right) => compareLayoutIds(left.domain.network_id, right.domain.network_id),
  );
  const pairTotals = new Map();
  const pairOrdinals = new Map();
  const memberships = [];
  for (const domain of orderedHubDomains) for (const member of [...domain.members].sort(
    (left, right) => compareLayoutIds(left.member_id, right.member_id),
  )) {
    const node = findNodeForRef(member.ref, nodes);
    if (!node) continue;
    const key = `${node.key}|network:${domain.network_id}`;
    pairTotals.set(key, (pairTotals.get(key) || 0) + 1);
    memberships.push({ domain, member, node, key });
  }
  for (const { domain, member, node, key } of memberships) {
    const nodePoint = positions.get(node.key);
    const domainPoint = domainPositions.get(domain.network_id);
    const geometry = curvedEdgeGeometry(
      nodePoint,
      domainPoint,
      nextEdgeLane(key, pairTotals, pairOrdinals),
      nodeBoxes.get(node.key),
      domainBoxes.get(domain.network_id),
      node.key,
      `network:${domain.network_id}`,
    );
    const link = member.links?.[0] || null;
    const health = linkHealth({
      condition_class: firstDeclaredString(member.condition_class, link?.condition_class, domain.condition_class),
      status_class: firstDeclaredString(member.status_class, link?.status_class, domain.status_class),
      health_class: firstDeclaredString(member.health_class, link?.health_class, domain.health_class),
    });
    const focused = focusKey === node.key;
    const muted = focusKey && !focused;
    const filterMuted = filterActive && !emphasized.has(node.key);
    const vpn = isVpnConnectivityDomain(domain);
    const attrs = attachmentEdgeAttributes(link, node, domain, member);
    const contextAttrs = topologyContextAttributes({
      networkId: domain.network_id,
      attachmentId: member.member_id,
      sourceKey: node.key,
    });
    const label = `${node.label}; ${fullTopologyAttachmentLabel(member.attachment)}; to ${connectivityDomainLabel(domain)}`;
    markup.push(`<path tabindex="0" role="button" aria-label="${escapeHtml(`${label}; show calculated topology details`)}" ${attrs} class="mn-topology-edge-hit" d="${geometry.d}"></path>`);
    markup.push(`<path aria-hidden="true" ${contextAttrs} class="mn-segment-attachment is-${health}${focused ? " is-focused" : ""}${muted ? " is-muted" : ""}${filterMuted ? " is-filter-muted" : ""}${vpn ? " is-vpn" : ""}" d="${geometry.d}"></path>`);
    if (topologyElementVisible("interfaces")) {
      markup.push(`<circle aria-hidden="true" ${contextAttrs} class="mn-interface-port is-${health}${vpn ? " is-vpn" : ""}" cx="${geometry.source.x}" cy="${geometry.source.y}" r="4"></circle>`);
    }
    markup.push(renderAttachmentComponents(member.attachment, geometry, attrs, { health, vpn }));
  }

  // Compact domains retain their stable domain identity; legacy links do not.
  const directLinks = [...(options.directLinks || visibleDirectTopologyLinks(
    nodes,
    [...orderedHubDomains, ...orderedCompactDecisions.map((decision) => decision.domain)],
  ))].sort((left, right) => compareLayoutIds(left.link_id, right.link_id));
  const directTotals = new Map();
  const directOrdinals = new Map();
  for (const decision of orderedCompactDecisions) {
    const participants = [...decision.participants].sort((left, right) => left.node.key.localeCompare(right.node.key));
    if (participants.length !== 2) continue;
    const key = edgePairKey(participants[0].node, participants[1].node);
    directTotals.set(key, (directTotals.get(key) || 0) + 1);
  }
  for (const link of directLinks) {
    const source = findNodeForRef(link.source, nodes); const target = findNodeForRef(link.target, nodes);
    if (!source || !target || source.key === target.key) continue;
    const key = edgePairKey(source, target); directTotals.set(key, (directTotals.get(key) || 0) + 1);
  }
  for (const decision of orderedCompactDecisions) {
    const domain = decision.domain;
    const participants = [...decision.participants].sort((left, right) => left.node.key.localeCompare(right.node.key));
    if (participants.length !== 2) continue;
    const [left, right] = participants;
    const key = edgePairKey(left.node, right.node);
    const geometry = curvedEdgeGeometry(
      positions.get(left.node.key),
      positions.get(right.node.key),
      nextEdgeLane(key, directTotals, directOrdinals),
      nodeBoxes.get(left.node.key),
      nodeBoxes.get(right.node.key),
      left.node.key,
      right.node.key,
    );
    const health = linkHealth(domain);
    const focused = focusKey && [left.node.key, right.node.key].includes(focusKey);
    const muted = focusKey && !focused;
    const filterMuted = filterActive && ![left.node.key, right.node.key].some((key) => emphasized.has(key));
    const members = [...left.members, ...right.members];
    const attachmentIds = members.map((member) => member.member_id);
    const links = members.flatMap((member) => member.links || []);
    const tokens = [...new Set([
      `network-segment:${domain.network_id}`,
      ...attachmentIds.map((attachmentId) => `network-attachment:${attachmentId}`),
      ...interactionTokensForDomain(domain),
      ...members.flatMap((member) => [...refRouteTokens(member.ref), ...(member.link_ids || []).map((id) => `link:${id}`)]),
      ...links.flatMap((link) => [...interactionTokensForLink(link), ...refRouteTokens(link.source), ...refRouteTokens(link.target)]),
    ])];
    const targets = [...new Set([
      ...interactionFocusTargetsForDomain(domain),
      ...links.flatMap(interactionFocusTargetsForLink),
    ])];
    const contextAttrs = topologyContextAttributes({
      networkId: domain.network_id,
      sourceKey: left.node.key,
      targetKey: right.node.key,
    });
    const label = `${left.node.label}; ${fullTopologyAttachmentLabel(mergedParticipantAttachment(left.members))}; through ${connectivityDomainLabel(domain)}; to ${right.node.label}; ${fullTopologyAttachmentLabel(mergedParticipantAttachment(right.members))}`;
    const attrs = `data-route-kind="topology-link" data-route-id="${escapeHtml(domain.network_id)}" data-network-segment-id="${escapeHtml(domain.network_id)}" data-network-attachment-ids="${escapeHtml(JSON.stringify(attachmentIds))}" data-topology-inspect-key="domain:${escapeHtml(domain.network_id)}" data-route-tokens="${routeTokensAttribute(tokens)}" data-route-focus-targets="${routeFocusTargetsAttribute(targets)}" data-source-node-key="${escapeHtml(left.node.key)}" data-target-node-key="${escapeHtml(right.node.key)}" aria-haspopup="dialog" aria-controls="mn-topology-hover-card"`;
    markup.push(`<path tabindex="0" role="button" aria-label="${escapeHtml(`${label}; show calculated topology details`)}" ${attrs} class="mn-compact-domain-hit" d="${geometry.d}"></path>`);
    markup.push(`<path aria-hidden="true" ${contextAttrs} class="mn-compact-domain-edge is-${health}${focused ? " is-focused" : ""}${muted ? " is-muted" : ""}${filterMuted ? " is-filter-muted" : ""}" d="${geometry.d}"></path>`);
    if (topologyElementVisible("subnets")) {
      const midpoint = quadraticEdgePoint(geometry, 0.5);
      markup.push(`<text aria-hidden="true" ${contextAttrs} class="mn-compact-domain-label is-${health}" x="${midpoint.x}" y="${midpoint.y - 9}" text-anchor="middle">${escapeHtml(connectivityDomainLabel(domain))}</text>`);
    }
    if (topologyElementVisible("interfaces")) {
      markup.push(`<circle aria-hidden="true" ${contextAttrs} class="mn-interface-port is-${health}" cx="${geometry.source.x}" cy="${geometry.source.y}" r="4"></circle><circle aria-hidden="true" ${contextAttrs} class="mn-interface-port is-${health}" cx="${geometry.target.x}" cy="${geometry.target.y}" r="4"></circle>`);
    }
    for (const [memberIndex, member] of [...left.members]
      .sort((first, second) => compareLayoutIds(first.member_id, second.member_id)).entries()) {
      markup.push(renderAttachmentComponents(
        member.attachment || {},
        geometry,
        attachmentEdgeAttributes(member.links?.[0] || null, left.node, domain, member),
        { health, groupOrdinal: memberIndex, groupCount: left.members.length },
      ));
    }
    for (const [memberIndex, member] of [...right.members]
      .sort((first, second) => compareLayoutIds(first.member_id, second.member_id)).entries()) {
      markup.push(renderAttachmentComponents(
        member.attachment || {},
        geometry,
        attachmentEdgeAttributes(member.links?.[0] || null, right.node, domain, member),
        { health, reverse: true, groupOrdinal: memberIndex, groupCount: right.members.length },
      ));
    }
  }
  for (const link of directLinks) {
    const source = findNodeForRef(link.source, nodes); const target = findNodeForRef(link.target, nodes);
    if (!source || !target || source.key === target.key) continue;
    state.topologyInspectorItems.set(`link:${link.link_id}`, topologyDirectLinkInspectorItem(link, source, target));
    const key = edgePairKey(source, target);
    const geometry = curvedEdgeGeometry(
      positions.get(source.key),
      positions.get(target.key),
      nextEdgeLane(key, directTotals, directOrdinals),
      nodeBoxes.get(source.key),
      nodeBoxes.get(target.key),
      source.key,
      target.key,
    );
    const health = linkHealth(link);
    const focused = focusKey && [source.key, target.key].includes(focusKey);
    const muted = focusKey && !focused;
    const filterMuted = filterActive && ![source.key, target.key].some((key) => emphasized.has(key));
    const tokens = [`link:${link.link_id}`, ...refRouteTokens(link.source), ...refRouteTokens(link.target), ...interactionTokensForLink(link)];
    const contextAttrs = topologyContextAttributes({
      linkId: link.link_id,
      sourceKey: source.key,
      targetKey: target.key,
    });
    const label = `${source.label}; ${fullTopologyAttachmentLabel(link.source_attachment)}; to ${target.label}; ${fullTopologyAttachmentLabel(link.target_attachment)}; direct pairwise adjacency; no segment identity supplied`;
    const attrs = `data-route-kind="topology-link" data-route-id="${escapeHtml(link.link_id)}" data-topology-inspect-key="link:${escapeHtml(link.link_id)}" data-route-tokens="${routeTokensAttribute(tokens)}" data-route-focus-targets="${routeFocusTargetsAttribute(interactionFocusTargetsForLink(link))}" data-source-node-key="${escapeHtml(source.key)}" data-target-node-key="${escapeHtml(target.key)}" aria-haspopup="dialog" aria-controls="mn-topology-hover-card"`;
    markup.push(`<path tabindex="0" role="button" aria-label="${escapeHtml(`${label}; show calculated topology details`)}" ${attrs} class="mn-topology-edge-hit" d="${geometry.d}"></path>`);
    markup.push(`<path aria-hidden="true" ${contextAttrs} class="mn-edge-path mn-direct-adjacency is-${health}${focused ? " is-focused" : ""}${muted ? " is-muted" : ""}${filterMuted ? " is-filter-muted" : ""}" d="${geometry.d}"></path>`);
    if (topologyElementVisible("interfaces")) {
      markup.push(`<circle aria-hidden="true" ${contextAttrs} class="mn-interface-port is-${health}" cx="${geometry.source.x}" cy="${geometry.source.y}" r="4"></circle><circle aria-hidden="true" ${contextAttrs} class="mn-interface-port is-${health}" cx="${geometry.target.x}" cy="${geometry.target.y}" r="4"></circle>`);
    }
    markup.push(renderAttachmentComponents(link.source_attachment, geometry, attrs, { health }));
    markup.push(renderAttachmentComponents(link.target_attachment, geometry, attrs, { health, reverse: true }));
  }
  svg.innerHTML = markup.join("");
  bindRouteCorrelationElements(svg);
  bindTopologyInspectorElements(svg);
}

function renderTopologyMapSummary({ nodes, allNodes, domainDecisions, hiddenExternalDomains, emphasized, focusKey, focusConnected }) {
  const summary = byId("mn-map-summary");
  if (!summary) return;
  const compactCount = domainDecisions.filter((decision) => decision.compact).length;
  const explicitCount = domainDecisions.length - compactCount;
  const visibleHighlighted = nodes.filter((node) => emphasized.has(node.key)).length;
  const filterActive = visibleHighlighted < nodes.length;
  const focusedNode = allNodes.find((node) => node.key === focusKey);
  const chips = [
    `<span class="mn-summary-chip"><strong>${formatInteger(nodes.length)}</strong> ${state.topologyNetworkView === "vpn" ? `participating of ${formatInteger(allNodes.length)} selected` : "devices in view"}</span>`,
    `<span class="mn-summary-chip"><strong>${formatInteger(explicitCount)}</strong> shared domain${explicitCount === 1 ? "" : "s"} · <strong>${formatInteger(compactCount)}</strong> compact pair${compactCount === 1 ? "" : "s"}</span>`,
  ];
  if (hiddenExternalDomains.length) {
    chips.push(`<span class="mn-summary-chip"><strong>${formatInteger(hiddenExternalDomains.length)}</strong> external network${hiddenExternalDomains.length === 1 ? "" : "s"} hidden</span>`);
  }
  if (filterActive) {
    chips.push(`<span class="mn-summary-chip is-warning"><strong>${formatInteger(visibleHighlighted)}</strong> of ${formatInteger(nodes.length)} devices highlighted</span>`);
  }
  if (focusedNode) {
    chips.push(`<span class="mn-summary-chip${focusConnected ? "" : " is-warning"}"><strong>Spotlight</strong> ${escapeHtml(focusedNode.label)}${focusConnected ? "" : " · no visible connection in this plane"}</span>`);
    chips.push('<button type="button" class="mn-focus-clear" data-topology-focus-clear>Show all connections</button>');
  }
  summary.innerHTML = chips.join("");
  summary.querySelector("[data-topology-focus-clear]")?.addEventListener("click", () => {
    state.topologyFocusedNodeKey = "";
    renderLinkStatusMap();
    showToast("Topology spotlight cleared.");
  });
}

function renderLinkStatusMap() {
  const pinnedInspector = capturePinnedTopologyInspector();
  const emphasized = new Set(visibleNodes().map((node) => node.key));
  const allPlaneDomains = topologyConnectivityDomains();
  const hiddenExternalDomains = topologyElementVisible("external") ? []
    : allPlaneDomains.filter((domain) => domain.plugin_asserted_external === true);
  const domains = topologyElementVisible("external") ? allPlaneDomains
    : allPlaneDomains.filter((domain) => domain.plugin_asserted_external !== true);
  clearTopologyInspector();
  state.topologyInspectorItems.clear();
  byId("mn-map-title").textContent = state.topologyNetworkView === "vpn" ? "VPN and overlay segments" : "Subnet and interface connectivity";
  const note = document.querySelector(".mn-link-map-panel .mn-map-note");
  if (note) note.textContent = state.topologyNetworkView === "vpn"
    ? "VPN segments are a separate plug-in-declared presentation plane; they are not inferred from VRF names or addresses."
    : "Connectivity arranges devices around declared shared media and pairwise links. A complete two-participant domain becomes one line only when its plug-in declares that presentation safe; its identity and evidence remain inspectable.";
  const allNodes = selectedResultNodes();
  const vpnMembers = new Set(domains.flatMap((domain) => domain.members.map((member) => findNodeForRef(member.ref, allNodes)?.key)).filter(Boolean));
  const nodes = state.topologyNetworkView === "vpn" ? allNodes.filter((node) => vpnMembers.has(node.key)) : allNodes;
  const domainDecisions = domains.map((domain) => ({ ...topologyDomainPresentationDecision(domain, nodes), domain }));
  const compactDecisions = domainDecisions.filter((decision) => decision.compact);
  const hubDomains = domainDecisions.filter((decision) => !decision.compact).map((decision) => decision.domain);
  const directLinks = visibleDirectTopologyLinks(nodes, domains);
  const connectedNodeKeys = new Set(domainDecisions.flatMap((decision) => decision.participants.map((participant) => participant.node.key)));
  for (const link of directLinks) {
    connectedNodeKeys.add(findNodeForRef(link.source, nodes).key);
    connectedNodeKeys.add(findNodeForRef(link.target, nodes).key);
  }
  const focusKey = connectedNodeKeys.has(state.topologyFocusedNodeKey) ? state.topologyFocusedNodeKey : "";
  renderTopologyMapSummary({
    nodes,
    allNodes,
    domainDecisions,
    hiddenExternalDomains,
    emphasized,
    focusKey: state.topologyFocusedNodeKey,
    focusConnected: Boolean(focusKey),
  });
  for (const decision of domainDecisions) {
    const domain = decision.domain;
    state.topologyInspectorItems.set(`domain:${domain.network_id}`, topologyDomainInspectorItem(domain, decision));
    for (const member of domain.members || []) {
      const node = findNodeForRef(member.ref, nodes);
      if (node) state.topologyInspectorItems.set(`attachment:${domain.network_id}:${member.member_id}`, topologyAttachmentInspectorItem(domain, member, node));
    }
  }
  const layer = byId("mn-node-layer");
  const empty = byId("mn-map-empty");
  empty.hidden = Boolean(nodes.length);
  if (!nodes.length) {
    layer.innerHTML = "";
    byId("mn-link-layer").innerHTML = "";
    if (state.topologyNetworkView === "vpn") {
      const suggestedProfile = profileForPresentationRole("vpn");
      const actionLabel = suggestedProfile?.empty_action_label || (suggestedProfile ? `Load ${suggestedProfile.label}` : "");
      empty.innerHTML = `<strong>No VPN segments in this reconstruction.</strong><span>VPN identity must come from a device plug-in; the core will not infer it from a VRF name or address.</span>${suggestedProfile ? `<button type="button" data-load-network-view-profile>${escapeHtml(actionLabel)}</button>` : ""}`;
      empty.querySelector("[data-load-network-view-profile]")?.addEventListener("click", () => {
        byId("mn-projection").value = suggestedProfile.profile_id;
        markTopologyQueryDirty();
        byId("mn-query-form").requestSubmit();
      });
    } else {
      empty.innerHTML = state.selectedNodeKeys.size
        ? "<strong>No underlay connectivity to draw.</strong><span>Run a reconstruction with at least one plug-in topology projection.</span>"
        : "<strong>No devices selected.</strong><span>Select one or more devices above, then reconstruct the topology.</span>";
    }
    return;
  }
  const dimensions = mapConnectivityLayout(
    nodes,
    hubDomains,
    compactDecisions,
    directLinks,
    { stageId: "mn-map-stage", minHeight: 520 },
  );
  const layoutSignature = connectivityLayoutSignature(
    nodes,
    hubDomains,
    compactDecisions,
    directLinks,
    {
      orientation: dimensions.orientation,
      domainBoxMode: dimensions.domainBoxMode,
      geometrySignature: connectivityLayoutGeometrySignature(dimensions),
    },
  );
  const layoutKey = `topology:${TOPOLOGY_LAYOUT_VERSION}:${layoutSignature}:${state.query?.context_id || "query"}:${state.topologyNetworkView}:${topologyElementVisible("external") ? "with-external" : "core"}`;
  const defaults = new Map([
    ...[...dimensions.positions.entries()].map(([key, point]) => [`node:${key}`, point]),
    ...[...dimensions.domainPositions.entries()].map(([key, point]) => [`network:${key}`, point]),
  ]);
  const stored = persistentGraphPositions("topology", layoutKey, defaults);
  const positions = new Map(nodes.map((node) => [node.key, stored.positions.get(`node:${node.key}`)]));
  const domainPositions = new Map(hubDomains.map((domain) => [domain.network_id, stored.positions.get(`network:${domain.network_id}`)]));
  layer.style.width = `${dimensions.width}px`;
  layer.style.height = `${dimensions.height}px`;
  layer.innerHTML = nodes.map((node) => mapNodeMarkup(node, positions.get(node.key), null, [], `${emphasized.has(node.key) ? "" : " is-map-filter-muted"}${state.topologyFocusedNodeKey === node.key ? " is-topology-focused" : ""}`, { showGlobalSelection: false })).join("")
    + hubDomains.map((domain) => connectivityDomainMarkup(
      domain,
      domainPositions.get(domain.network_id),
      domain.members.some((member) => emphasized.has(findNodeForRef(member.ref, nodes)?.key)) ? "" : " is-map-filter-muted",
    )).join("");
  for (const node of nodes) state.topologyInspectorItems.set(`node:${node.key}`, topologyNodeInspectorItem(node));
  layer.querySelectorAll("[data-map-node]").forEach((button) => button.addEventListener("click", () => {
    if (button.dataset.graphDragMoved === "true") return;
    state.topologyFocusedNodeKey = state.topologyFocusedNodeKey === button.dataset.mapNode ? "" : button.dataset.mapNode;
    focusNode(button.dataset.mapNode);
  }));
  layer.querySelectorAll("[data-map-node]").forEach((button) => {
    button.dataset.topologyInspectKey = `node:${button.dataset.mapNode}`;
    button.dataset.topologyInspectMode = "preview";
    button.setAttribute("aria-describedby", "mn-topology-hover-card");
  });
  const nodeBoxes = new Map([...layer.querySelectorAll("[data-map-node]")].map((element) => [element.dataset.mapNode, { width: element.offsetWidth, height: element.offsetHeight }]));
  const domainBoxes = new Map([...layer.querySelectorAll("[data-network-segment]")].map((element) => [element.dataset.networkSegment, { width: element.offsetWidth, height: element.offsetHeight }]));
  const redraw = () => {
    nodes.forEach((node) => positions.set(node.key, stored.positions.get(`node:${node.key}`)));
    hubDomains.forEach((domain) => domainPositions.set(domain.network_id, stored.positions.get(`network:${domain.network_id}`)));
    renderConnectivityEdges(nodes, hubDomains, compactDecisions, positions, domainPositions, dimensions, nodeBoxes, domainBoxes, { focusKey, emphasized, directLinks });
  };
  redraw();
  bindRouteCorrelationElements(byId("mn-map-stage"));
  bindTopologyInspectorElements(layer);
  setupGraphViewport({
    stageId: "mn-map-stage",
    viewKey: "topology",
    layoutKey,
    modelPositions: stored.positions,
    storageKeys: stored.storageKeys,
    boxes: new Map([
      ...nodes.map((node) => [`node:${node.key}`, nodeBoxes.get(node.key)]),
      ...hubDomains.map((domain) => [`network:${domain.network_id}`, domainBoxes.get(domain.network_id)]),
    ]),
    redraw,
    defaultPositions: defaults,
  });
  restorePinnedTopologyInspector(pinnedInspector);
}

function allPathGraphNodes(paths, nodes) {
  const ordered = [];
  const sharedNodes = new Map();
  for (const path of paths) {
    const pathCounts = new Map();
    for (const node of routeNodeSequence(path, nodes)) {
      const baseKey = node.route_base_key || node.key;
      const occurrence = pathCounts.get(baseKey) || 0;
      pathCounts.set(baseKey, occurrence + 1);
      if (occurrence > 0) {
        ordered.push(node);
        continue;
      }
      if (!sharedNodes.has(baseKey)) {
        const shared = {
          ...node,
          key: baseKey,
          route_base_key: baseKey,
          route_path_id: "",
          route_occurrence_id: "",
          route_occurrence_index: null,
          route_graph_shared: true,
        };
        sharedNodes.set(baseKey, shared);
        ordered.push(shared);
      }
    }
  }
  return ordered;
}

function routePathMemberships(node, paths) {
  if (node.route_path_id) {
    return paths.filter((path) => path.path_id === node.route_path_id);
  }
  return paths.filter((path) => routePathNodeRefs(path).some((ref) => sameRouteRef(ref, node)));
}

function mapAllPathsLayout(paths, nodes, options = {}) {
  const stage = byId(options.stageId || "mn-route-map-stage");
  const sequences = paths.map((path) => routeNodeSequence(path, nodes));
  const maxHops = Math.max(2, ...sequences.map((sequence) => sequence.length));
  const columns = Math.max(2, maxHops);
  const columnMembers = new Map();
  const nodeColumns = new Map();
  const nodePathRanks = new Map();
  sequences.forEach((sequence, pathIndex) => {
    for (const node of sequence) {
      if (!nodePathRanks.has(node.key)) nodePathRanks.set(node.key, []);
      const ranks = nodePathRanks.get(node.key);
      if (ranks.at(-1) !== pathIndex) ranks.push(pathIndex);
    }
  });
  for (const node of nodes) {
    const occurrences = sequences.flatMap((sequence) => {
      const index = sequence.findIndex((candidate) => candidate.key === node.key);
      return index < 0 ? [] : [sequence.length <= 1 ? 0 : index / (sequence.length - 1)];
    });
    const normalized = occurrences.length
      ? occurrences.reduce((total, value) => total + value, 0) / occurrences.length
      : 0;
    const column = Math.max(0, Math.min(columns - 1, Math.round(normalized * (columns - 1))));
    nodeColumns.set(node.key, column);
    if (!columnMembers.has(column)) columnMembers.set(column, []);
    columnMembers.get(column).push(node);
  }
  const pathRank = (node) => {
    const ranks = nodePathRanks.get(node.key) || [];
    return ranks.length
      ? ranks.reduce((total, value) => total + value, 0) / ranks.length
      : Number.POSITIVE_INFINITY;
  };
  for (const members of columnMembers.values()) members.sort((left, right) =>
    pathRank(left) - pathRank(right)
    || Number(left.route_occurrence_index ?? 0) - Number(right.route_occurrence_index ?? 0)
    || compareLayoutIds(left.key, right.key)
  );
  const largestColumn = Math.max(1, ...[...columnMembers.values()].map((members) => members.length));
  const outerPadding = Number(options.outerPadding || 128);
  const width = Math.max(stage.clientWidth || 760, (columns - 1) * 245 + outerPadding * 2);
  const height = Math.max(Number(options.minHeight || 410), largestColumn * 170 + 150);
  const positions = new Map();
  for (const node of nodes) {
    const column = nodeColumns.get(node.key) || 0;
    const members = columnMembers.get(column) || [node];
    const row = members.findIndex((candidate) => candidate.key === node.key);
    positions.set(node.key, {
      x: columns === 1 ? width / 2 : outerPadding + column * ((width - outerPadding * 2) / (columns - 1)),
      y: ((row + 1) / (members.length + 1)) * height,
    });
  }
  return { columns, rows: largestColumn, width, height, positions, routeNodeKeys: new Set(nodes.map((node) => node.key)) };
}

function allPathNodeMarkup(node, position, paths) {
  const memberships = routePathMemberships(node, paths);
  const plan = node.plan || nodePlan(node);
  const qualityByPath = Object.fromEntries(memberships.map((path) => [path.path_id, routeNodeQualityClasses(node, path)]));
  const qualitySignatures = new Set(Object.values(qualityByPath).map(routeQualitySignature));
  const mixedQuality = qualitySignatures.size > 1;
  const pathClasses = mixedQuality ? [] : (Object.values(qualityByPath)[0] || []);
  const sequences = memberships.map(routePathNodeRefs);
  const occurrenceMatches = (candidate) => node.route_graph_shared
    ? sameRouteRef(candidate, node)
    : candidate?.route_occurrence_id === node.route_occurrence_id;
  const source = sequences.some((sequence) => occurrenceMatches(sequence[0]));
  const destination = sequences.some((sequence) => occurrenceMatches(sequence.at(-1)));
  const startMarker = state.activeRouteDirection === "reverse"
    ? "RETURN START"
    : "TRACE START";
  const endMarker = state.activeRouteDirection === "reverse" ? "SOURCE TARGET" : "DESTINATION";
  const installGateByPath = Object.fromEntries(memberships.map((path, index) => [
    path.path_id,
    Boolean(pathIsControlPlaneOnly(path) && occurrenceMatches(sequences[index][0])),
  ]));
  const installGateValues = Object.values(installGateByPath);
  const baseInstallGate = Boolean(installGateValues.length && installGateValues.every(Boolean));
  const tokens = [`member:${node.member_id}`, `node:${node.node_id}`, ...interactionTokensForNode(node)];
  const pathIds = memberships.map((path) => path.path_id);
  const navigationKey = node.route_base_key || node.key;
  const occurrenceLabel = node.route_occurrence_id
    ? `<span class="mn-route-occurrence-label">visit ${Number(node.route_occurrence_index ?? 0) + 1}</span>`
    : "";
  const chooser = memberships.length <= 4
    ? `<div class="mn-route-node-paths" aria-label="Paths through ${escapeHtml(node.label)}"><span>Choose path</span><div>${memberships.map((path) => {
      const index = paths.findIndex((candidate) => candidate.path_id === path.path_id) + 1;
      return `<button type="button" class="mn-route-node-path-chip ${routeQualityClasses(path).join(" ")}" data-route-node-path="${escapeHtml(path.path_id)}" data-route-path-id="${escapeHtml(path.path_id)}" aria-haspopup="dialog" aria-controls="mn-route-hover-card" aria-label="Select ${escapeHtml(path.label)} through ${escapeHtml(node.label)}" title="${escapeHtml(`${path.label}: ${pathStatusSummary(path)}`)}">P${index}</button>`;
    }).join("")}</div></div>`
    : `<label class="mn-route-node-paths mn-route-node-path-select"><span>${memberships.length} paths through node</span><select data-route-node-path-select aria-label="Select a path through ${escapeHtml(node.label)}"><option value="">Choose path…</option>${memberships.map((path) => `<option value="${escapeHtml(path.path_id)}">${escapeHtml(`${path.label} — ${pathStatusSummary(path)}`)}</option>`).join("")}</select></label>`;
  return `<article class="mn-map-node mn-route-overview-node is-route-member ${pathClasses.join(" ")}${mixedQuality ? " is-route-mixed" : ""}${source ? " is-route-source" : ""}${destination ? " is-route-destination" : ""}" data-route-overview-node="${escapeHtml(node.key)}" data-route-occurrence-id="${escapeHtml(node.route_occurrence_id || "")}" data-graph-position-key="node:${escapeHtml(node.key)}" data-route-path-ids="${escapeHtml(JSON.stringify(pathIds))}" data-route-base-quality="${escapeHtml(JSON.stringify(pathClasses))}" data-route-quality-by-path="${escapeHtml(JSON.stringify(qualityByPath))}" data-route-mixed="${mixedQuality}" data-route-base-install-gate="${baseInstallGate}" data-route-install-gate-by-path="${escapeHtml(JSON.stringify(installGateByPath))}" data-route-kind="node" data-route-id="${escapeHtml(node.member_id)}" data-route-start-label="${escapeHtml(startMarker)}" data-route-end-label="${escapeHtml(endMarker)}" data-route-tokens="${routeTokensAttribute(tokens)}" data-route-focus-targets="${routeFocusTargetsAttribute(interactionFocusTargetsForNode(node))}" style="left:${position.x}px;top:${position.y}px">
    <button type="button" class="mn-route-overview-node-open" data-map-node="${escapeHtml(navigationKey)}" aria-label="Open ${escapeHtml(node.label)} node details, visit ${Number(node.route_occurrence_index ?? 0) + 1}">
      <header><span><strong>${escapeHtml(node.label)}</strong><small>${escapeHtml(`${node.site} · ${node.device_type}`)}</small></span><i class="mn-health-dot is-${nodeHealth(node)}" aria-label="${escapeHtml(nodeHealth(node))}"></i></header>
      <code title="${escapeHtml(`${plan.plugin_set_id}@${plan.plugin_version || "?"}`)}">${escapeHtml(`${plan.plugin_set_id}@${plan.plugin_version || "?"}`)}</code>
      <span class="mn-route-node-layer">L3 resolution point</span>${occurrenceLabel}
    </button>
    ${installGateValues.some(Boolean) ? `<span class="mn-route-node-state mn-route-install-gate is-control-plane-only" data-route-install-gate${baseInstallGate ? "" : " hidden"}>NO FIB / not installed</span>` : ""}
    ${chooser}
  </article>`;
}

function routePresentationGroups(paths, nodes = selectedResultNodes()) {
  const groups = new Map();
  for (const path of paths || []) {
    for (const layer of routePresentationLayers(path, "overlay")) {
      // A band scoped to the full path is the only descriptor that may
      // enclose forwarding geometry. Step/span/resource descriptors remain
      // preserved for their own anchors instead of being misdrawn as paths.
      if (layer.scope !== "path" || layer.style !== "band") continue;
      const groupId = layer.group_id || layer.presentation_id;
      if (!groups.has(groupId)) groups.set(groupId, {
        group_id: groupId,
        layers: [],
        paths: [],
        nodes: [],
      });
      const group = groups.get(groupId);
      group.layers.push(layer);
      if (!group.paths.some((item) => item.path_id === path.path_id)) group.paths.push(path);
      for (const node of routeNodeSequence(path, nodes)) {
        if (!group.nodes.some((item) => item.key === node.key)) group.nodes.push(node);
      }
    }
  }
  return [...groups.values()];
}

function routePresentationOverlayMarkup(paths, nodes, positions, dimensions, nodeBoxes) {
  return routePresentationGroups(paths, nodes).map((group) => {
    if (!group.nodes.length) return "";
    const bounds = group.nodes.reduce((result, node) => {
      const point = positions.get(node.key);
      const box = nodeBoxes.get(node.key) || { width: MAP_NODE_FALLBACK_WIDTH, height: MAP_NODE_FALLBACK_HEIGHT };
      if (!point) return result;
      result.minX = Math.min(result.minX, point.x - box.width / 2);
      result.minY = Math.min(result.minY, point.y - box.height / 2);
      result.maxX = Math.max(result.maxX, point.x + box.width / 2);
      result.maxY = Math.max(result.maxY, point.y + box.height / 2);
      return result;
    }, { minX: Number.POSITIVE_INFINITY, minY: Number.POSITIVE_INFINITY, maxX: Number.NEGATIVE_INFINITY, maxY: Number.NEGATIVE_INFINITY });
    if (!Number.isFinite(bounds.minX)) return "";
    const paddingX = 34;
    const paddingTop = 50;
    const paddingBottom = 30;
    const x = Math.max(12, bounds.minX - paddingX);
    const y = Math.max(12, bounds.minY - paddingTop);
    const right = Math.min(dimensions.width - 12, bounds.maxX + paddingX);
    const bottom = Math.min(dimensions.height - 12, bounds.maxY + paddingBottom);
    const width = Math.max(120, right - x);
    const height = Math.max(88, bottom - y);
    const layer = group.layers[0];
    const pathIds = group.paths.map((path) => path.path_id);
    const statuses = [...new Set(group.layers.map((item) => item.status).filter(Boolean))];
    const statusClass = statuses.length === 1 ? ` is-${safeClass(statuses[0])}` : statuses.length ? " is-mixed" : "";
    const label = layer.label || "Service context";
    const chipLabel = `SERVICE OVERLAY · ${label}`;
    const chipWidth = Math.min(Math.max(156, chipLabel.length * 5.8 + 28), Math.max(156, width - 24));
    const aria = `${label}; service context around ${group.paths.length} candidate path${group.paths.length === 1 ? "" : "s"}; not a forwarding hop`;
    return `<g class="mn-route-presentation-overlay is-${safeClass(layer.style_role)}${statusClass}" data-route-presentation-id="${escapeHtml(group.group_id)}" data-route-path-ids="${escapeHtml(JSON.stringify(pathIds))}">
      <rect class="mn-route-presentation-surface" x="${x}" y="${y}" width="${width}" height="${height}" rx="24"></rect>
      <g class="mn-route-presentation-trigger" tabindex="0" role="button" aria-label="${escapeHtml(aria)}" data-route-presentation-trigger="${escapeHtml(group.group_id)}" transform="translate(${x + 12} ${y + 10})">
        <rect width="${chipWidth}" height="24" rx="8"></rect>
        <text x="11" y="15">${escapeHtml(chipLabel)}</text>
        <title>${escapeHtml(`${aria}. Hover or focus for plug-in details.`)}</title>
      </g>
      <text class="mn-route-presentation-caption" x="${x + width - 12}" y="${y + 25}" text-anchor="end">CONTEXT · NOT A HOP</text>
    </g>`;
  }).join("");
}

function routeBoundaryTagMarkup(segment, geometry, pathId = "") {
  const presentation = segment?.graph_presentation;
  if (!presentation?.label || presentation.role !== "outer-boundary") return "";
  const point = quadraticEdgePoint(geometry, 0.5);
  const label = String(presentation.label);
  const width = Math.min(128, Math.max(62, label.length * 5.4 + 18));
  return `<g class="mn-route-layer-tag" aria-hidden="true" data-route-layer-path-id="${escapeHtml(pathId)}" transform="translate(${point.x} ${point.y})">
    <rect x="${-width / 2}" y="-10" width="${width}" height="20" rx="7"></rect>
    <text text-anchor="middle" dominant-baseline="central">${escapeHtml(label)}</text>
    <title>${escapeHtml(presentation.detail || label)}</title>
  </g>`;
}

function routePresentationFactValue(value) {
  if (value === null || value === undefined) return "unknown";
  if (Array.isArray(value)) return value.map(routePresentationFactValue).join(" → ");
  if (typeof value === "object") return Object.entries(value)
    .map(([key, item]) => `${titleCase(key)}: ${routePresentationFactValue(item)}`).join(" · ");
  return String(value);
}

function routePresentationPreviewMarkup(group, interactive = false) {
  const layer = group.layers[0];
  const facts = [];
  const seen = new Set();
  for (const item of group.layers.flatMap((candidate) => candidate.facts || [])) {
    const label = String(item?.label ?? "Detail");
    const value = routePresentationFactValue(item?.value);
    const key = `${label}:${value}`;
    if (seen.has(key)) continue;
    seen.add(key);
    facts.push({ label, value });
  }
  const provider = layer?.provided_by?.plugin_id
    ?? layer?.plugin_provenance?.[0]?.plugin_id
    ?? "plug-in";
  const rows = facts.length
    ? facts.map((item) => `<li><span>•</span><div><strong>${escapeHtml(item.label)}</strong><small>${escapeHtml(item.value)}</small></div></li>`).join("")
    : '<li><span>•</span><div><strong>No additional presentation facts.</strong></div></li>';
  const close = interactive
    ? '<button type="button" data-route-presentation-close aria-label="Close service context">×</button>'
    : "";
  return `<header><div><span>SERVICE CONTEXT · NOT A FORWARDING HOP</span><strong>${escapeHtml(layer?.label || "Route context")}</strong><small>${escapeHtml(`${group.paths.length} candidate path${group.paths.length === 1 ? "" : "s"} · provided by ${provider}`)}</small></div>${close}</header>
    <p class="mn-route-presentation-detail">${escapeHtml(layer?.detail || "The plug-in attached this context to the outer forwarding path.")}</p>
    <ol>${rows}</ol>`;
}

function routePresentationGroupById(groupId) {
  const paths = state.routeGraphMode === "focused"
    ? [selectedRoutePath()].filter(Boolean)
    : state.routeTrace?.paths || [];
  return routePresentationGroups(paths).find((group) => group.group_id === groupId) || null;
}

function clearRoutePresentationPreview(options = {}) {
  const restoreFocus = options?.restoreFocus === true;
  const trigger = state.routePresentationTrigger;
  state.previewRoutePresentationId = "";
  state.routePresentationPinned = false;
  state.routePresentationTrigger = null;
  clearTimeout(state.routePreviewHideTimer);
  state.routePreviewHideTimer = null;
  const card = byId("mn-route-hover-card");
  if (card) {
    card.hidden = true;
    card.classList.remove("is-pinned");
    card.innerHTML = "";
  }
  if (restoreFocus && trigger?.isConnected) {
    state.routePresentationSuppressFocusPreview = true;
    trigger.focus({ preventScroll: true });
    state.routePresentationSuppressFocusPreview = false;
  }
}

function showRoutePresentationPreview(groupId, anchor, pinned = false, point = null) {
  const group = routePresentationGroupById(groupId);
  if (!group) return;
  if (state.previewRoutePathId) clearRoutePathPreview();
  clearTimeout(state.routePreviewHideTimer);
  const preservePin = state.previewRoutePresentationId === groupId && state.routePresentationPinned;
  state.previewRoutePresentationId = groupId;
  state.routePresentationPinned = Boolean(pinned || preservePin);
  state.routePresentationTrigger = anchor;
  const card = byId("mn-route-hover-card");
  if (card.parentElement !== document.body) document.body.append(card);
  card.hidden = false;
  card.classList.add("is-floating");
  card.classList.toggle("is-pinned", state.routePresentationPinned);
  card.setAttribute("role", state.routePresentationPinned ? "dialog" : "tooltip");
  card.setAttribute("aria-label", `${group.layers[0]?.label || "Service"} context`);
  card.innerHTML = routePresentationPreviewMarkup(group, state.routePresentationPinned);
  card.scrollTop = 0;
  const keepOpen = () => clearTimeout(state.routePreviewHideTimer);
  const release = () => {
    if (!state.routePresentationPinned) scheduleHideRoutePresentationPreview();
  };
  card.onpointerenter = keepOpen;
  card.onpointerleave = release;
  card.onmouseenter = keepOpen;
  card.onmouseleave = release;
  const close = card.querySelector("[data-route-presentation-close]");
  close?.addEventListener("click", () => clearRoutePresentationPreview({ restoreFocus: true }));
  positionRoutePathPreview(anchor, state.routePresentationPinned ? null : point);
  if (state.routePresentationPinned) close?.focus({ preventScroll: true });
}

function scheduleHideRoutePresentationPreview(delay = 220) {
  if (state.routePresentationPinned) return;
  clearTimeout(state.routePreviewHideTimer);
  state.routePreviewHideTimer = setTimeout(clearRoutePresentationPreview, delay);
}

function bindRoutePresentationElements(scope) {
  scope.querySelectorAll("[data-route-presentation-trigger]").forEach((element) => {
    const groupId = element.dataset.routePresentationTrigger;
    const enter = (event) => showRoutePresentationPreview(groupId, element, false, {
      clientX: event.clientX,
      clientY: event.clientY,
    });
    const leave = () => scheduleHideRoutePresentationPreview();
    element.addEventListener("pointerenter", enter);
    element.addEventListener("pointerleave", leave);
    element.addEventListener("mouseenter", (event) => { if (!("PointerEvent" in window)) enter(event); });
    element.addEventListener("mouseleave", () => { if (!("PointerEvent" in window)) leave(); });
    element.addEventListener("focus", () => {
      if (state.routePresentationSuppressFocusPreview) return;
      showRoutePresentationPreview(groupId, element);
    });
    element.addEventListener("blur", () => scheduleHideRoutePresentationPreview());
    element.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      showRoutePresentationPreview(groupId, element, true);
    });
    element.addEventListener("keydown", (event) => {
      if (!["Enter", " "].includes(event.key)) return;
      event.preventDefault();
      showRoutePresentationPreview(groupId, element, true);
    });
  });
}

function routePathPreviewMarkup(path) {
  const nodeLabels = routePathNodeRefs(path).map(nodeLabelForRef);
  const previewItems = [
    ...path.steps,
    ...routeDiagnosticItems(path),
  ];
  const steps = previewItems.length ? previewItems.map((step, index) => {
    const provider = step?.provided_by?.plugin_id ?? step?.plugin_provenance?.plugin_id ?? step?.text_source;
    const classes = routeQualityClasses(step).join(" ");
    return `<li class="${classes}"><span>${index + 1}</span><div><strong>${escapeHtml(step.text)}</strong>${step.detail ? `<small>${escapeHtml(step.detail)}</small>` : ""}${provider ? `<code>${escapeHtml(`provided by ${provider}`)}</code>` : ""}</div></li>`;
  }).join("") : '<li class="is-unresolved"><span>!</span><div><strong>No plug-in resolution steps were returned.</strong></div></li>';
  return `<header><div><span>PATH PREVIEW</span><strong>${escapeHtml(path.label)}</strong><small>${escapeHtml(pathStatusSummary(path))}</small></div></header>
    <div class="mn-route-hover-path">${escapeHtml(nodeLabels.join(" → ") || "No drawable node sequence")}</div>
    <ol>${steps}</ol>
    <footer>Click this path in the graph to select it and open the complete side panel.</footer>`;
}

function applyOverviewPathEmphasis() {
  const activePathId = state.previewRoutePathId || (state.routeGraphMode === "all" ? state.selectedRoutePathId : "");
  const scope = byId("mn-route-map-stage");
  scope?.classList.toggle("has-route-preview", Boolean(state.previewRoutePathId));
  if (scope) {
    if (state.previewRoutePathId) scope.dataset.routePreviewPath = state.previewRoutePathId; else delete scope.dataset.routePreviewPath;
  }
  scope?.querySelectorAll("[data-overview-path-id], [data-route-overview-node], [data-route-node-path]").forEach((element) => {
    const memberships = element.dataset.overviewPathId
      ? [element.dataset.overviewPathId]
      : element.dataset.routeNodePath ? [element.dataset.routeNodePath]
        : (() => { try { return JSON.parse(element.dataset.routePathIds || "[]"); } catch (_error) { return []; } })();
    const matches = Boolean(activePathId && memberships.includes(activePathId));
    element.classList.toggle("is-route-preview", matches && state.previewRoutePathId === activePathId);
    element.classList.toggle("is-route-pinned", matches && !state.previewRoutePathId && state.selectedRoutePathId === activePathId);
    element.classList.toggle("is-route-suppressed", Boolean(activePathId && !matches));
    if (element.matches("[data-route-overview-node]")) applyRouteOverviewNodeQuality(element, matches ? activePathId : "");
  });
  scope?.querySelectorAll("[data-route-layer-path-id], [data-route-presentation-id]").forEach((element) => {
    let memberships = [];
    if (element.dataset.routeLayerPathId) memberships = [element.dataset.routeLayerPathId];
    else {
      try { memberships = JSON.parse(element.dataset.routePathIds || "[]"); } catch (_error) { memberships = []; }
    }
    const matches = Boolean(activePathId && memberships.includes(activePathId));
    element.classList.toggle("is-route-preview", matches && state.previewRoutePathId === activePathId);
    element.classList.toggle("is-route-pinned", matches && !state.previewRoutePathId && state.selectedRoutePathId === activePathId);
    element.classList.toggle("is-route-suppressed", Boolean(activePathId && !matches));
  });
}

function positionRoutePathPreview(anchor, point = null) {
  const card = byId("mn-route-hover-card");
  if (!card || card.hidden || !anchor?.getBoundingClientRect) return;
  const rect = anchor.getBoundingClientRect();
  const width = Math.min(430, window.innerWidth - 24);
  const cardHeight = Math.min(card.scrollHeight || 330, window.innerHeight - 24);
  const anchorLeft = Number.isFinite(point?.clientX) ? point.clientX : rect.left;
  const anchorRight = Number.isFinite(point?.clientX) ? point.clientX : rect.right;
  const anchorTop = Number.isFinite(point?.clientY) ? point.clientY : rect.top;
  let left = anchorRight + 14;
  if (left + width > window.innerWidth - 12) left = anchorLeft - width - 14;
  left = Math.max(12, Math.min(window.innerWidth - width - 12, left));
  const top = Math.max(12, Math.min(window.innerHeight - cardHeight - 12, anchorTop - 18));
  card.style.width = `${width}px`;
  card.style.left = `${left}px`;
  card.style.top = `${top}px`;
}

function showRoutePathPreview(pathId, anchor, point = null) {
  const path = routePathById(pathId);
  if (!path || state.routeGraphMode !== "all") return;
  if (state.previewRoutePresentationId) clearRoutePresentationPreview();
  clearTimeout(state.routePreviewHideTimer);
  state.previewRoutePathId = pathId;
  state.routePreviewAnchor = anchor;
  const card = byId("mn-route-hover-card");
  if (card.parentElement !== document.body) document.body.append(card);
  card.hidden = false;
  card.classList.add("is-floating");
  card.setAttribute("role", "tooltip");
  card.setAttribute("aria-label", `${path.label} resolution preview`);
  card.innerHTML = routePathPreviewMarkup(path);
  card.scrollTop = 0;
  const keepOpen = () => clearTimeout(state.routePreviewHideTimer);
  const release = () => scheduleHideRoutePathPreview();
  card.onpointerenter = keepOpen;
  card.onpointerleave = release;
  card.onmouseenter = keepOpen;
  card.onmouseleave = release;
  positionRoutePathPreview(anchor, point);
  applyOverviewPathEmphasis();
}

function scheduleHideRoutePathPreview(delay = 180) {
  clearTimeout(state.routePreviewHideTimer);
  state.routePreviewHideTimer = setTimeout(clearRoutePathPreview, delay);
}

function clearRoutePathPreview() {
  if (state.previewRoutePresentationId) clearRoutePresentationPreview();
  clearTimeout(state.routePreviewHideTimer);
  state.routePreviewHideTimer = null;
  state.previewRoutePathId = "";
  state.routePreviewAnchor = null;
  const card = byId("mn-route-hover-card");
  if (card) {
    card.hidden = true;
    card.innerHTML = "";
  }
  applyOverviewPathEmphasis();
}

function bindOverviewPathElements(scope) {
  scope.querySelectorAll("[data-overview-path-id], [data-route-node-path]").forEach((element) => {
    const pathId = element.dataset.overviewPathId || element.dataset.routeNodePath;
    const enter = (event) => showRoutePathPreview(pathId, element, {
      clientX: event.clientX,
      clientY: event.clientY,
    });
    const leave = () => scheduleHideRoutePathPreview();
    element.addEventListener("pointerenter", enter);
    element.addEventListener("pointerleave", leave);
    element.addEventListener("mouseenter", (event) => { if (!("PointerEvent" in window)) enter(event); });
    element.addEventListener("mouseleave", () => { if (!("PointerEvent" in window)) leave(); });
    element.addEventListener("focus", enter);
    element.addEventListener("blur", () => scheduleHideRoutePathPreview());
    element.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      selectRoutePath(pathId);
    });
    element.addEventListener("keydown", (event) => {
      if (!['Enter', ' '].includes(event.key)) return;
      event.preventDefault();
      selectRoutePath(pathId);
    });
  });
  applyOverviewPathEmphasis();
}

function renderAllPathEdges(paths, nodes, positions, dimensions, nodeBoxes) {
  const svg = byId("mn-route-link-layer");
  svg.setAttribute("width", dimensions.width);
  svg.setAttribute("height", dimensions.height);
  svg.setAttribute("viewBox", `0 0 ${dimensions.width} ${dimensions.height}`);
  const edges = [];
  const pairTotals = new Map();
  const pairOrdinals = new Map();
  for (const [pathIndex, path] of paths.entries()) {
    for (const [segmentIndex, segment] of routeForwardingSegments(path).entries()) {
      const sourceNode = findRouteOccurrence(
        segment.source,
        segment.source_occurrence_id,
        nodes,
        path.path_id,
      );
      const targetNode = findRouteOccurrence(
        segment.target,
        segment.target_occurrence_id,
        nodes,
        path.path_id,
      );
      if (!sourceNode && !targetNode) continue;
      const terminal = routeSegmentIsTerminal(segment, path, segmentIndex);
      const cycleClosing = routeSegmentIsCycleClosing(segment, path, segmentIndex);
      const policyBlocked = routeSegmentIsPolicyBlocked(segment, path, segmentIndex);
      const stub = !sourceNode || !targetNode || sourceNode.key === targetNode.key;
      if (stub && !terminal && !segment.unresolved && !cycleClosing && !policyBlocked) continue;
      const pairKey = !stub ? edgePairKey(sourceNode, targetNode) : null;
      if (pairKey) pairTotals.set(pairKey, (pairTotals.get(pairKey) || 0) + 1);
      edges.push({
        path,
        pathIndex,
        segment,
        segmentIndex,
        sourceNode,
        targetNode,
        terminal,
        cycleClosing,
        policyBlocked,
        stub,
        pairKey,
      });
    }
  }
  const markup = [`<defs>
    <marker id="mn-route-arrow-all" markerWidth="11" markerHeight="11" refX="10" refY="5.5" orient="auto" markerUnits="userSpaceOnUse"><path d="M0,0 L11,5.5 L0,11 z"></path></marker>
    <marker id="mn-route-gap-all" markerWidth="12" markerHeight="12" refX="6" refY="6" orient="auto" markerUnits="userSpaceOnUse"><path d="M3,2 L3,10 M9,2 L9,10"></path></marker>
    <marker id="mn-route-dead-all" markerWidth="14" markerHeight="14" refX="7" refY="7" orient="auto" markerUnits="userSpaceOnUse"><path d="M2,2 L12,12 M12,2 L2,12"></path></marker>
    <marker id="mn-route-cycle-all" markerWidth="15" markerHeight="15" refX="12" refY="7.5" orient="auto" markerUnits="userSpaceOnUse"><path d="M11,3 A5,5 0 1 0 11,12 M10,1 L13,3 L10,5"></path></marker>
    <marker id="mn-route-policy-all" markerWidth="14" markerHeight="14" refX="7" refY="7" orient="auto" markerUnits="userSpaceOnUse"><path d="M2,2 L12,12 M12,2 L2,12 M1,7 L13,7"></path></marker>
  </defs>`];
  markup.push(routePresentationOverlayMarkup(paths, nodes, positions, dimensions, nodeBoxes));
  for (const edge of edges) {
    const anchor = edge.sourceNode || edge.targetNode;
    const sourcePosition = edge.sourceNode ? positions.get(edge.sourceNode.key) : null;
    const targetPosition = edge.targetNode ? positions.get(edge.targetNode.key) : null;
    const needsDistinctCurve = Boolean(
      edge.pairKey
      && (
        pairTotals.get(edge.pairKey) > 1
        || edge.cycleClosing
        || targetPosition.x <= sourcePosition.x
      )
    );
    const laneBand = needsDistinctCurve
      ? nextEdgeLane(edge.pairKey, pairTotals, pairOrdinals)
      : 0;
    const geometry = edge.pairKey
      ? curvedEdgeGeometry(
        sourcePosition,
        targetPosition,
        laneBand,
        nodeBoxes.get(edge.sourceNode.key),
        nodeBoxes.get(edge.targetNode.key),
        edge.sourceNode.key,
        edge.targetNode.key,
      )
      : unresolvedStubGeometry(anchor, positions, dimensions, nodeBoxes, edge.segmentIndex + edge.pathIndex, !edge.sourceNode);
    const pathState = routeSegmentQualityState(edge.path, edge.segment, edge.segmentIndex);
    const classes = routeQualityClasses(pathState).join(" ");
    let edgeDisposition = edge.terminal ? "terminal drop"
      : edge.segment.unresolved || edge.stub ? "unresolved gap" : "forwarding segment";
    if (edge.cycleClosing) edgeDisposition = "loop-closing segment";
    else if (edge.policyBlocked) edgeDisposition = routePolicyPresentation(edge.path).label;
    const label = `${edge.path.label}, segment ${edge.segmentIndex + 1}: ${nodeLabelForRef(edge.segment.source)} to ${nodeLabelForRef(edge.segment.target)}, ${edgeDisposition}; ${pathStatusSummary(edge.path)}`;
    const instanceId = `${edge.path.path_id}:${edge.segment.segment_id}`;
    const attributes = `data-route-kind="route-segment" data-route-id="${escapeHtml(instanceId)}" data-route-path-id="${escapeHtml(edge.path.path_id)}" data-overview-path-id="${escapeHtml(edge.path.path_id)}" data-route-tokens="${routeTokensAttribute(edge.segment.component_tokens)}" data-route-focus-targets="${routeFocusTargetsAttribute(edge.segment.highlight_target_ids)}" aria-haspopup="dialog" aria-controls="mn-route-hover-card"`;
    const terminalClass = edge.terminal ? " mn-route-terminal-stub is-dead is-dropped"
      : edge.cycleClosing ? " mn-route-cycle-closing is-cycle"
        : edge.policyBlocked ? " mn-route-policy-stop is-policy-blocked"
          : "";
    const marker = edge.cycleClosing ? "mn-route-cycle-all"
      : edge.policyBlocked ? "mn-route-policy-all"
        : edge.terminal ? "mn-route-dead-all"
          : edge.segment.unresolved || edge.stub ? "mn-route-gap-all" : "mn-route-arrow-all";
    markup.push(`<path aria-hidden="true" ${attributes} class="mn-route-edge-hit${terminalClass}" d="${geometry.d}"></path>`);
    markup.push(`<path tabindex="0" role="button" aria-label="${escapeHtml(`${label}. Select path.`)}" ${attributes} class="mn-route-edge ${classes}${terminalClass}" marker-end="url(#${marker})" d="${geometry.d}"><title>${escapeHtml(label)}</title></path>`);
    markup.push(routeBoundaryTagMarkup(edge.segment, geometry, edge.path.path_id));
  }
  svg.innerHTML = markup.join("");
  bindRoutePresentationElements(svg);
  bindOverviewPathElements(svg);
}

function renderAllPathsRouteMap() {
  const paths = state.routeTrace?.paths || [];
  const layer = byId("mn-route-node-layer");
  const empty = byId("mn-route-map-empty");
  const nodes = allPathGraphNodes(paths, selectedResultNodes());
  empty.hidden = Boolean(paths.length && nodes.length);
  if (!paths.length || !nodes.length) {
    layer.innerHTML = "";
    byId("mn-route-link-layer").innerHTML = "";
    empty.textContent = paths.length
      ? "Candidate paths reference devices outside this reconstruction. Add the endpoint devices and reconstruct before tracing."
      : "No candidate paths were returned for this direction.";
    byId("mn-route-map-title").textContent = paths.length ? "Route is outside the reconstructed device set" : "No candidate paths";
    byId("mn-route-map-note").textContent = paths.length
      ? "The resolver returned path evidence, but no route node can be placed safely in the current topology context."
      : "No graph can be drawn for this direction.";
    return;
  }
  const dimensions = mapAllPathsLayout(paths, nodes, { minHeight: 410 });
  const layoutKey = `route:${ROUTE_OVERVIEW_LAYOUT_VERSION}:${state.query?.context_id || "query"}:all:${state.activeRouteDirection}:${paths.map((path) => path.path_id).join(",")}`;
  const stored = persistentGraphPositions("route", layoutKey, new Map(
    [...dimensions.positions.entries()].map(([key, point]) => [`node:${key}`, point])
  ));
  const positions = new Map(nodes.map((node) => [node.key, stored.positions.get(`node:${node.key}`)]));
  layer.style.width = `${dimensions.width}px`;
  layer.style.height = `${dimensions.height}px`;
  layer.innerHTML = nodes.map((node) => allPathNodeMarkup(node, positions.get(node.key), paths)).join("");
  layer.querySelectorAll("[data-map-node]").forEach((button) => button.addEventListener("click", () => {
    if (button.closest("[data-graph-position-key]")?.dataset.graphDragMoved === "true") return;
    focusNode(button.dataset.mapNode);
  }));
  layer.querySelectorAll("[data-route-node-path-select]").forEach((select) => select.addEventListener("change", () => {
    if (select.value) selectRoutePath(select.value);
  }));
  const nodeBoxes = new Map([...layer.querySelectorAll("[data-route-overview-node]")].map((element) => [
    element.dataset.routeOverviewNode,
    { width: element.offsetWidth, height: element.offsetHeight },
  ]));
  const redraw = () => {
    nodes.forEach((node) => positions.set(node.key, stored.positions.get(`node:${node.key}`)));
    renderAllPathEdges(paths, nodes, positions, dimensions, nodeBoxes);
  };
  redraw();
  bindOverviewPathElements(layer);
  bindRouteCorrelationElements(layer);
  setupGraphViewport({
    stageId: "mn-route-map-stage",
    viewKey: "route",
    layoutKey,
    modelPositions: stored.positions,
    storageKeys: stored.storageKeys,
    boxes: new Map(nodes.map((node) => [`node:${node.key}`, nodeBoxes.get(node.key)])),
    redraw,
  });
  const title = byId("mn-route-map-title");
  const note = byId("mn-route-map-note");
  title.textContent = `${routeDirectionLabel(state.activeRouteDirection)} · all ${paths.length} candidates`;
  const controlPlaneOnlyPaths = paths.filter(pathIsControlPlaneOnly);
  const presentationCount = routePresentationGroups(paths, nodes).length;
  const graphSemantics = `Device cards are L3 resolution points and arrows are outer L1/L2 boundaries.${presentationCount ? ` ${presentationCount} tinted service context${presentationCount === 1 ? " is" : "s are"} an overlay, not a hop.` : ""}`;
  const directionalDifference = routeDirectionalDifference();
  const directionNote = directionalDifference
    ? ` Active forward and return paths differ: ${directionalDifference.detail}.`
    : "";
  const deadCount = paths.filter(pathIsDead).length;
  const cycleCount = paths.filter(routeValueIsCycle).length;
  const policyBlockedCount = paths.filter(routeValueIsPolicyBlocked).length;
  const inactiveCount = paths.filter((path) => !pathIsDead(path)
    && !routeValueIsCycle(path)
    && !routeValueIsPolicyBlocked(path)
    && !pathIsControlPlaneOnly(path)
    && (ROUTE_INACTIVE_STATES.has(normalizedRouteEnum(path?.activity))
      || ROUTE_STANDBY_STATES.has(firstRouteEnum(path?.selection, path?.eligibility))
      || new Set(["standby", "backup", "alternative"]).has(normalizedRouteEnum(path?.role)))).length;
  note.classList.toggle("is-control-plane-only", Boolean(controlPlaneOnlyPaths.length));
  if (controlPlaneOnlyPaths.length) {
    const prefix = controlPlaneOnlyPaths.length === paths.length
      ? "No executable forwarding path is installed for this direction."
      : `${controlPlaneOnlyPaths.length} candidate${controlPlaneOnlyPaths.length === 1 ? " is" : "s are"} control-plane only.`;
    note.textContent = `${prefix} ${controlPlaneOnlyReason(state.routeTrace)} The dashed downstream chain shows control-plane resolution evidence, not a packet-forwarding path. ${graphSemantics}${directionNote} ${inactiveCount} other standby/inactive · ${cycleCount} looped · ${policyBlockedCount} policy-blocked · ${deadCount} dead/dropped retained.`;
  } else {
    note.textContent = `Hover or focus a path to preview its resolution; choose it from any segment or node to open details. ${graphSemantics}${directionNote} ${inactiveCount} standby/inactive · ${cycleCount} looped · ${policyBlockedCount} policy-blocked · ${deadCount} dead/dropped retained.`;
  }
  applyOverviewPathEmphasis();
}

function renderFocusedRouteMap() {
  const directionalDifference = renderRouteDirectionalDifference();
  if (state.routeGraphMode === "all") {
    renderAllPathsRouteMap();
    return;
  }
  const routePath = selectedRoutePath();
  const pathDirectionalDifference = routePathMatchesDirectionalDifference(routePath, directionalDifference)
    ? directionalDifference
    : null;
  const nodes = routePath ? routeNodeSequence(routePath, selectedResultNodes()) : [];
  const title = byId("mn-route-map-title");
  const note = byId("mn-route-map-note");
  note.classList.toggle("is-control-plane-only", Boolean(routePath && pathIsControlPlaneOnly(routePath)));
  if (!routePath) {
    title.textContent = "No route focused";
    note.textContent = "Choose a trace start and traffic endpoints to isolate one forwarding path from the link topology.";
  } else if (pathIsControlPlaneOnly(routePath)) {
    const labels = routePathNodeRefs(routePath).map(nodeLabelForRef);
    title.textContent = `${routeDirectionLabel(state.activeRouteDirection)} · ${routePath.label}`;
    note.textContent = `${labels[0] || "unresolved source"} → ${labels.at(-1) || "unresolved destination"} · ${pathStatusSummary(routePath)}. ${controlPlaneOnlyReason(state.routeTrace)} The downstream chain is resolution evidence, not a packet-forwarding path. Device cards are L3 resolution points; arrows are outer L1/L2 boundaries.`;
  } else {
    const labels = routePathNodeRefs(routePath).map(nodeLabelForRef);
    const presentationCount = routePresentationLayers(routePath, "overlay").length;
    const flowSource = routeFlowEndpointLabel(state.routeTrace, "source");
    const flowDestination = routeFlowEndpointLabel(state.routeTrace, "destination");
    const start = routeTraceStartLabel(state.routeTrace);
    const endpointContext = state.activeRouteDirection === "reverse"
      ? ` Return flow ${flowDestination} → ${flowSource}; revisiting the forward observation node is not required.`
      : ` Observed from ${start} for flow ${flowSource} → ${flowDestination}.`;
    const directionNote = pathDirectionalDifference
      ? ` Active forward and return paths differ: ${pathDirectionalDifference.detail}. Amber marks direction-only components when no stronger path-local fault takes precedence.`
      : "";
    title.textContent = `${routeDirectionLabel(state.activeRouteDirection)} · ${routePath.label}`;
    note.textContent = `${labels[0] || "unresolved start"} → ${labels.at(-1) || "unresolved target"} · ${pathStatusSummary(routePath)}.${endpointContext} Only the focused outer L1-L3 path is drawn.${presentationCount ? " The tinted service context is attached to it, not inserted as a hop." : ""}${directionNote}`;
  }
  renderNodeGraph({
    nodes,
    routePath,
    stageId: "mn-route-map-stage",
    nodeLayerId: "mn-route-node-layer",
    edgeLayerId: "mn-route-link-layer",
    emptyId: "mn-route-map-empty",
    showTopology: false,
    showRoute: true,
    minHeight: 340,
    columnPitch: 285,
    outerPadding: 90,
    fallbackWidth: 760,
    nodeClassFor: (node) => pathDirectionalDifference?.currentOnlyNodeIds.has(node.node_id)
      ? " is-direction-difference"
      : "",
    nodeOptionsFor: (node) => pathDirectionalDifference?.currentOnlyNodeIds.has(node.node_id)
      ? { directionDifferenceLabel: `${routeDirectionLabel(pathDirectionalDifference.direction)} only` }
      : {},
    routeDirectionDifference: pathDirectionalDifference,
  });
  if (routePath && !nodes.length) {
    const empty = byId("mn-route-map-empty");
    empty.hidden = false;
    empty.textContent = "This path references devices outside the reconstructed device set. Add the endpoint devices and reconstruct before tracing.";
  }
}

function renderMap() {
  renderLinkStatusMap();
  renderFocusedRouteMap();
  renderDirectionTabs();
}

function findNodeForRef(ref, nodes) {
  return nodes.find((node) => node.member_id === ref.member_id)
    || nodes.find((node) => node.node_id === ref.node_id && node.revision_id === ref.revision_id)
    || nodes.find((node) => node.node_id === ref.node_id);
}

function edgePairKey(sourceNode, targetNode) {
  return [sourceNode.key, targetNode.key].sort().join("|");
}

function nextEdgeLane(pairKey, totals, ordinals) {
  const ordinal = ordinals.get(pairKey) || 0;
  ordinals.set(pairKey, ordinal + 1);
  const total = totals.get(pairKey) || 1;
  if (total === 1) return 1;
  const band = Math.floor(ordinal / 2) + 1;
  return ordinal % 2 === 0 ? band : -band;
}

function stableEdgeBendSign(pairKey) {
  return (stableLayoutHash(pairKey) & 1) === 0 ? -1 : 1;
}

function baseEdgeBend(length) {
  return Math.min(
    MAP_EDGE_BASE_BEND_MAX,
    Math.max(MAP_EDGE_BASE_BEND_MIN, length * MAP_EDGE_BASE_BEND_RATIO),
    length * MAP_EDGE_MAX_BEND_RATIO,
  );
}

function nodeBoundaryPoint(center, toward, box, clearance = MAP_EDGE_CLEARANCE) {
  const dx = toward.x - center.x;
  const dy = toward.y - center.y;
  if (Math.abs(dx) < 0.001 && Math.abs(dy) < 0.001) return { ...center };
  const halfWidth = (box?.width || MAP_NODE_FALLBACK_WIDTH) / 2 + clearance;
  const halfHeight = (box?.height || MAP_NODE_FALLBACK_HEIGHT) / 2 + clearance;
  const scaleX = Math.abs(dx) < 0.001 ? Number.POSITIVE_INFINITY : halfWidth / Math.abs(dx);
  const scaleY = Math.abs(dy) < 0.001 ? Number.POSITIVE_INFINITY : halfHeight / Math.abs(dy);
  const scale = Math.min(scaleX, scaleY, 0.92);
  return { x: center.x + dx * scale, y: center.y + dy * scale };
}

function curvedEdgeGeometry(
  sourceCenter,
  targetCenter,
  laneBand,
  sourceBox,
  targetBox,
  sourceKey,
  targetKey,
) {
  const dx = targetCenter.x - sourceCenter.x;
  const dy = targetCenter.y - sourceCenter.y;
  const length = Math.max(1, Math.hypot(dx, dy));
  const sourceToken = String(sourceKey || `${sourceCenter.x},${sourceCenter.y}`);
  const targetToken = String(targetKey || `${targetCenter.x},${targetCenter.y}`);
  const pairKey = [sourceToken, targetToken].sort().join("|");
  // Define the bend in canonical endpoint order so reversing an edge keeps the
  // same physical curve. Parallel edges alternate across the pair and move into
  // wider bands, while even a singleton retains a visible base arc.
  const orientation = sourceToken <= targetToken ? 1 : -1;
  const normalizedLane = Number.isFinite(laneBand) ? laneBand : 1;
  const curveOffset = normalizedLane === 0
    ? 0
    : stableEdgeBendSign(pairKey)
      * Math.sign(normalizedLane)
      * (baseEdgeBend(length) + (Math.abs(normalizedLane) - 1) * MAP_EDGE_LANE_GAP)
      * orientation;
  const control = {
    x: (sourceCenter.x + targetCenter.x) / 2 - (dy / length) * curveOffset,
    y: (sourceCenter.y + targetCenter.y) / 2 + (dx / length) * curveOffset,
  };
  const source = nodeBoundaryPoint(sourceCenter, control, sourceBox);
  const target = nodeBoundaryPoint(targetCenter, control, targetBox);
  return {
    source,
    target,
    control,
    d: `M ${source.x} ${source.y} Q ${control.x} ${control.y} ${target.x} ${target.y}`,
  };
}

function unresolvedStubGeometry(anchorNode, positions, dimensions, nodeBoxes, index, reverse = false) {
  const center = positions.get(anchorNode.key);
  const distance = 124;
  const directions = [
    { x: 0, y: -1 },
    { x: 1, y: 0 },
    { x: 0, y: 1 },
    { x: -1, y: 0 },
  ];
  const candidates = directions.map((direction, offset) => {
    const target = {
      x: center.x + direction.x * distance,
      y: center.y + direction.y * distance,
    };
    const nearestNode = Math.min(...[...positions.entries()]
      .filter(([key]) => key !== anchorNode.key)
      .map(([, point]) => Math.hypot(target.x - point.x, target.y - point.y)), Number.POSITIVE_INFINITY);
    const travel = Math.hypot(target.x - center.x, target.y - center.y);
    const preference = ((offset - index) % directions.length + directions.length) % directions.length;
    return { target, score: nearestNode + travel * 0.5 - preference * 0.01 };
  });
  const endpoint = candidates.sort((left, right) => right.score - left.score)[0].target;
  const boundary = nodeBoundaryPoint(center, endpoint, nodeBoxes.get(anchorNode.key));
  const control = {
    x: (boundary.x + endpoint.x) / 2,
    y: (boundary.y + endpoint.y) / 2,
  };
  const source = reverse ? endpoint : boundary;
  const target = reverse ? boundary : endpoint;
  return {
    source,
    target,
    control,
    d: `M ${source.x} ${source.y} Q ${control.x} ${control.y} ${target.x} ${target.y}`,
  };
}

function renderEdges(nodes, positions, dimensions, nodeBoxes, options = {}) {
  const svg = byId(options.edgeLayerId || "mn-link-layer");
  const showTopology = options.showTopology !== false;
  const showRoute = options.showRoute === true;
  svg.setAttribute("width", dimensions.width);
  svg.setAttribute("height", dimensions.height);
  svg.setAttribute("viewBox", `0 0 ${dimensions.width} ${dimensions.height}`);
  const visibleKeys = new Set(nodes.map((node) => node.key));
  const paths = [];
  const routePath = options.routePath || null;
  const topologyEdges = [];
  const routeEdges = [];
  const pairTotals = new Map();
  const pairOrdinals = new Map();
  const reservePair = (sourceNode, targetNode) => {
    const pairKey = edgePairKey(sourceNode, targetNode);
    pairTotals.set(pairKey, (pairTotals.get(pairKey) || 0) + 1);
    return pairKey;
  };

  if (showTopology) {
    for (const link of state.query?.links || []) {
      const sourceNode = findNodeForRef(link.source, nodes);
      const targetNode = findNodeForRef(link.target, nodes);
      if (!sourceNode || !targetNode || sourceNode.key === targetNode.key || !visibleKeys.has(sourceNode.key) || !visibleKeys.has(targetNode.key)) continue;
      topologyEdges.push({ link, sourceNode, targetNode, pairKey: reservePair(sourceNode, targetNode) });
    }
  }

  if (showRoute) {
    for (const [index, segment] of routeForwardingSegments(routePath).entries()) {
      const sourceNode = findRouteOccurrence(
        segment.source,
        segment.source_occurrence_id,
        nodes,
        routePath?.path_id,
      );
      const targetNode = findRouteOccurrence(
        segment.target,
        segment.target_occurrence_id,
        nodes,
        routePath?.path_id,
      );
      const fullSourceNode = findNodeForRef(segment.source, selectedResultNodes());
      const fullTargetNode = findNodeForRef(segment.target, selectedResultNodes());
      const filteredEndpoint = (!sourceNode && fullSourceNode) || (!targetNode && fullTargetNode);
      const terminal = routeSegmentIsTerminal(segment, routePath, index);
      const cycleClosing = routeSegmentIsCycleClosing(segment, routePath, index);
      const policyBlocked = routeSegmentIsPolicyBlocked(segment, routePath, index);
      if (filteredEndpoint || (!sourceNode && !targetNode)) continue;
      if (sourceNode && targetNode && sourceNode.key === targetNode.key
        && !segment.unresolved && !terminal && !cycleClosing && !policyBlocked) continue;
      routeEdges.push({
        index,
        segment,
        sourceNode,
        targetNode,
        terminal,
        cycleClosing,
        policyBlocked,
        pairKey: sourceNode && targetNode && sourceNode.key !== targetNode.key
          ? reservePair(sourceNode, targetNode)
          : null,
      });
    }
  }
  if (showRoute) paths.push(`<defs>
    <marker id="mn-route-arrow" markerWidth="11" markerHeight="11" refX="10" refY="5.5" orient="auto" markerUnits="userSpaceOnUse"><path d="M0,0 L11,5.5 L0,11 z"></path></marker>
    <marker id="mn-route-gap" markerWidth="12" markerHeight="12" refX="6" refY="6" orient="auto" markerUnits="userSpaceOnUse"><path d="M3,2 L3,10 M9,2 L9,10"></path></marker>
    <marker id="mn-route-dead" markerWidth="14" markerHeight="14" refX="7" refY="7" orient="auto" markerUnits="userSpaceOnUse"><path d="M2,2 L12,12 M12,2 L2,12"></path></marker>
    <marker id="mn-route-cycle" markerWidth="15" markerHeight="15" refX="12" refY="7.5" orient="auto" markerUnits="userSpaceOnUse"><path d="M11,3 A5,5 0 1 0 11,12 M10,1 L13,3 L10,5"></path></marker>
    <marker id="mn-route-policy" markerWidth="14" markerHeight="14" refX="7" refY="7" orient="auto" markerUnits="userSpaceOnUse"><path d="M2,2 L12,12 M12,2 L2,12 M1,7 L13,7"></path></marker>
  </defs>`);
  if (showRoute && routePath) {
    paths.push(routePresentationOverlayMarkup([routePath], nodes, positions, dimensions, nodeBoxes));
  }
  for (const { link, sourceNode, targetNode, pairKey } of topologyEdges) {
    const geometry = curvedEdgeGeometry(
      positions.get(sourceNode.key),
      positions.get(targetNode.key),
      nextEdgeLane(pairKey, pairTotals, pairOrdinals),
      nodeBoxes.get(sourceNode.key),
      nodeBoxes.get(targetNode.key),
      sourceNode.key,
      targetNode.key,
    );
    const health = linkHealth(link);
    const focused = state.focusedNodeKey && (sourceNode.key === state.focusedNodeKey || targetNode.key === state.focusedNodeKey);
    const muted = state.focusedNodeKey && !focused;
    const tokens = [`link:${link.link_id}`, ...refRouteTokens(link.source), ...refRouteTokens(link.target), ...interactionTokensForLink(link)];
    const focusTargets = interactionFocusTargetsForLink(link);
    const onRoute = Boolean(routePath?.segments.some((segment) => segment.topology_link_id === link.link_id));
    paths.push(`<path tabindex="0" role="button" aria-label="${escapeHtml(`${sourceNode.label} to ${targetNode.label}: ${link.kind}, ${link.resolution}`)}" data-route-kind="topology-link" data-route-id="${escapeHtml(link.link_id)}" data-route-tokens="${routeTokensAttribute(tokens)}" data-route-focus-targets="${routeFocusTargetsAttribute(focusTargets)}" data-source-node-key="${escapeHtml(sourceNode.key)}" data-target-node-key="${escapeHtml(targetNode.key)}" class="mn-edge-path is-${health}${focused ? " is-focused" : ""}${muted ? " is-muted" : ""}${onRoute ? " is-route-member" : routePath ? " is-route-muted" : ""}" d="${geometry.d}"><title>${escapeHtml(`${sourceNode.label} → ${targetNode.label} · ${link.kind} · ${link.resolution}`)}</title></path>`);
  }
  for (const {
    index,
    segment,
    sourceNode,
    targetNode,
    terminal,
    cycleClosing,
    policyBlocked,
    pairKey,
  } of routeEdges) {
    const unresolvedEnd = !sourceNode || !targetNode || sourceNode.key === targetNode.key;
    const geometry = pairKey
      ? curvedEdgeGeometry(
        positions.get(sourceNode.key),
        positions.get(targetNode.key),
        nextEdgeLane(pairKey, pairTotals, pairOrdinals),
        nodeBoxes.get(sourceNode.key),
        nodeBoxes.get(targetNode.key),
        sourceNode.key,
        targetNode.key,
      )
      : unresolvedStubGeometry(
        sourceNode || targetNode,
        positions,
        dimensions,
        nodeBoxes,
        index,
        !sourceNode && Boolean(targetNode)
      );
    const directionDifference = options.routeDirectionDifference;
    const directionEdgeKey = routeDirectionEdgeKey(segment.source?.node_id, segment.target?.node_id);
    const differsByDirection = Boolean(
      directionDifference
      && directionDifference.currentOnlyEdgeKeys.has(directionEdgeKey)
    );
    const classes = `${routeQualityClasses(routeSegmentQualityState(routePath, segment, index)).join(" ")}${differsByDirection ? " is-direction-difference" : ""}`;
    let edgeDisposition = terminal ? "terminal drop"
      : segment.unresolved || unresolvedEnd ? "unresolved gap" : "forwarding segment";
    if (cycleClosing) edgeDisposition = "loop-closing segment";
    else if (policyBlocked) edgeDisposition = routePolicyPresentation(routePath).label;
    const directionDetail = differsByDirection
      ? `; this ${routeDirectionLabel(directionDifference.direction).toLowerCase()} hop differs from the active ${routeDirectionLabel(directionDifference.oppositeDirection).toLowerCase()} path`
      : "";
    const label = `${routePath.label}, segment ${index + 1}: ${nodeLabelForRef(segment.source)} to ${nodeLabelForRef(segment.target)}, ${edgeDisposition}; ${segment.status}; ${pathStatusSummary(routePath)}${directionDetail}`;
    const tokens = routeTokensAttribute(segment.component_tokens);
    const focusTargets = routeFocusTargetsAttribute(segment.highlight_target_ids);
    const sourceKey = sourceNode?.key || "";
    const targetKey = targetNode?.key || "";
    const attributes = `data-route-kind="route-segment" data-route-id="${escapeHtml(segment.segment_id)}" data-route-path-id="${escapeHtml(routePath.path_id)}" data-route-tokens="${tokens}" data-route-focus-targets="${focusTargets}" data-route-packet-refs="${packetRefsAttribute(segment.packet_refs)}" data-source-node-key="${escapeHtml(sourceKey)}" data-target-node-key="${escapeHtml(targetKey)}"`;
    const terminalClass = terminal ? " mn-route-terminal-stub is-dead is-dropped"
      : cycleClosing ? " mn-route-cycle-closing is-cycle"
        : policyBlocked ? " mn-route-policy-stop is-policy-blocked"
          : "";
    const marker = cycleClosing ? "mn-route-cycle"
      : policyBlocked ? "mn-route-policy"
        : terminal ? "mn-route-dead"
          : segment.unresolved || unresolvedEnd ? "mn-route-gap" : "mn-route-arrow";
    paths.push(`<path aria-hidden="true" ${attributes} class="mn-route-edge-hit${terminalClass}" d="${geometry.d}"></path>`);
    paths.push(`<path tabindex="0" role="button" aria-label="${escapeHtml(label)}" ${attributes} class="mn-route-edge ${classes}${terminalClass}" marker-end="url(#${marker})" d="${geometry.d}"><title>${escapeHtml(label)}</title></path>`);
    paths.push(routeBoundaryTagMarkup(segment, geometry, routePath.path_id));
  }
  svg.innerHTML = paths.join("");
  bindRoutePresentationElements(svg);
  bindRouteCorrelationElements(svg);
  bindRoutePacketGraphElements(svg);
}

function safeNavigationTarget(target) {
  if (target && typeof target === "object" && String(target.semantic_owner || target.owner || "").toLowerCase() === "plugin") return null;
  const href = typeof target === "string" ? target : target?.href;
  if (!href) return null;
  try {
    const url = new URL(href, location.origin);
    if (url.origin !== location.origin) return null;
    // Node/resource navigation always enters the dedicated node workspace.
    // Preserve plug-in supplied query parameters and anchors, but do not let a
    // legacy root target replace the primary topology page.
    url.pathname = "/node";
    return `${url.pathname}${url.search}${url.hash}`;
  } catch (_error) {
    return null;
  }
}

function currentReturnTarget(node = null, resource = null) {
  const url = new URL(location.href);
  url.pathname = "/";
  if (node) {
    url.searchParams.set("focus_member", node.member_id);
    url.searchParams.set("focus_node", node.node_id);
  }
  if (resource?.resource_id) {
    url.searchParams.set("focus_resource", resource.resource_id);
  } else {
    url.searchParams.delete("focus_resource");
  }
  url.hash = "fabric";
  return `${url.pathname}${url.search}${url.hash}`;
}

function applyNodeNavigationBasis(url, basis = {}, requestBasis = {}) {
  const kind = url.searchParams.get("basis_kind")
    || requestBasis.kind
    || basis.kind
    || "absolute_time";
  url.searchParams.set("basis_kind", kind);

  if (kind === "relative_to_watermark") {
    const offsetNs = url.searchParams.get("basis_offset_ns")
      ?? url.searchParams.get("offset_ns")
      ?? requestBasis.offset_ns
      ?? "0";
    url.searchParams.delete("time_ns");
    url.searchParams.delete("offset_ns");
    url.searchParams.set("basis_offset_ns", String(offsetNs));
    return url;
  }

  const exactTime = url.searchParams.get("time_ns")
    ?? basis.queryTime
    ?? requestBasis.time_ns;
  url.searchParams.delete("basis_offset_ns");
  url.searchParams.delete("offset_ns");
  if (exactTime !== null && exactTime !== undefined) {
    url.searchParams.set("time_ns", String(exactTime));
  }
  return url;
}

function fallbackNodeHref(node, resource = null) {
  const basis = basisForNode(node);
  const requestBasis = state.query?.request?.basis || {};
  const plan = node.plan || nodePlan(node);
  const url = new URL("/node", location.origin);
  url.searchParams.set("member_id", node.member_id);
  url.searchParams.set("node_id", node.node_id);
  url.searchParams.set("revision_id", node.revision_id);
  if (resource?.resource_id) url.searchParams.set("resource_id", resource.resource_id);
  applyNodeNavigationBasis(url, basis, requestBasis);
  url.searchParams.set("clock_domain", basis.clock_domain || requestBasis.clock_domain || "utc");
  url.searchParams.set("clock_policy", state.query?.request?.clock_policy || requestBasis.clock_policy || "strict");
  url.searchParams.set("plugin_set_id", plan.plugin_set_id);
  url.searchParams.set("projection_id", plan.projection_id);
  url.searchParams.set("status_perspective_id", plan.status_perspective_id);
  if (state.query?.context_id) url.searchParams.set("context_id", state.query.context_id);
  url.searchParams.set("return_to", currentReturnTarget(node, resource));
  url.hash = resource?.resource_id ? "timeline" : "temporal-topology";
  return `${url.pathname}${url.search}${url.hash}`;
}

function navigationHref(node, resource = null) {
  const explicit = safeNavigationTarget(resource?.navigation_target || node?.navigation_target);
  if (!explicit) return fallbackNodeHref(node, resource);
  const url = new URL(explicit, location.origin);
  const basis = basisForNode(node);
  const requestBasis = state.query?.request?.basis || {};
  const plan = node.plan || nodePlan(node);
  if (!url.searchParams.has("member_id")) url.searchParams.set("member_id", node.member_id);
  if (!url.searchParams.has("node_id")) url.searchParams.set("node_id", node.node_id);
  if (!url.searchParams.has("revision_id")) url.searchParams.set("revision_id", node.revision_id);
  if (resource?.resource_id && !url.searchParams.has("resource_id")) url.searchParams.set("resource_id", resource.resource_id);
  applyNodeNavigationBasis(url, basis, requestBasis);
  if (!url.searchParams.has("clock_domain")) url.searchParams.set("clock_domain", basis.clock_domain || requestBasis.clock_domain || "utc");
  if (!url.searchParams.has("clock_policy")) url.searchParams.set("clock_policy", state.query?.request?.clock_policy || requestBasis.clock_policy || "strict");
  if (!url.searchParams.has("plugin_set_id")) url.searchParams.set("plugin_set_id", plan.plugin_set_id);
  if (plan.plugin_id && !url.searchParams.has("plugin_id")) url.searchParams.set("plugin_id", plan.plugin_id);
  if (!url.searchParams.has("projection_id")) url.searchParams.set("projection_id", plan.projection_id);
  if (!url.searchParams.has("status_perspective_id")) url.searchParams.set("status_perspective_id", plan.status_perspective_id);
  if (state.query?.context_id && !url.searchParams.has("context_id")) url.searchParams.set("context_id", state.query.context_id);
  if (!url.searchParams.has("return_to")) url.searchParams.set("return_to", currentReturnTarget(node, resource));
  return `${url.pathname}${url.search}${url.hash}`;
}

function renderNodeDetail() {
  const node = selectedResultNodes().find((item) => item.key === state.focusedNodeKey);
  const target = byId("mn-node-detail");
  const title = byId("mn-detail-title");
  const open = byId("mn-open-node");
  const headerOpen = byId("mn-header-open-node");
  if (!node) {
    title.textContent = "Choose a node";
    open.hidden = true;
    if (headerOpen) headerOpen.hidden = true;
    target.className = "mn-detail-empty";
    target.textContent = "Select a node in the map or index to inspect its local plug-in plan and clock basis.";
    return;
  }
  const basis = basisForNode(node);
  const plan = node.plan || nodePlan(node);
  title.textContent = node.label;
  open.hidden = false;
  open.href = navigationHref(node);
  if (headerOpen) {
    headerOpen.hidden = false;
    headerOpen.href = open.href;
    headerOpen.textContent = `Open ${node.label}`;
  }
  target.className = "";
  const plugins = node.plugins.map((plugin) =>
    `<span class="mn-plugin-badge${plugin.plugin_set_id === plan.plugin_set_id ? " is-active" : ""}">${escapeHtml(`${plugin.plugin_set_id}@${plugin.version}`)}</span>`
  ).join("");
  const focusedResourceId = state.focusedResourceRef
    && (state.focusedResourceRef.member_id === node.member_id || state.focusedResourceRef.node_id === node.node_id)
    ? state.focusedResourceRef.resource_id : "";
  const resourceRows = node.resources.map((resource) => {
    const ref = refIdentity(resource, node);
    const status = resource.status ?? resource.state?.status ?? resource.operational_status ?? "unknown";
    const focused = focusedResourceId && ref.resource_id === focusedResourceId;
    return `<div class="mn-resource-row${focused ? " is-focused" : ""}" ${focused ? 'aria-current="true"' : ""}>
      <span><strong>${escapeHtml(resource.label || resource.display_name || resource.resource_id)}</strong><small>${escapeHtml(`${resource.kind || resource.resource_kind || "resource"} · ${resource.resource_id}`)}</small>${focused ? '<span class="mn-status-pill is-good">return focus</span>' : ""}</span>
      <code>${escapeHtml(String(status))}</code>
      <a href="${escapeHtml(navigationHref(node, { ...resource, ...ref }))}">Timeline ↗</a>
    </div>`;
  }).join("");
  const missingFocusedResource = focusedResourceId && !node.resources.some((resource) => refIdentity(resource, node).resource_id === focusedResourceId)
    ? `<div class="topology-empty-list">Return focus: ${escapeHtml(focusedResourceId)} is not included in this limited resource preview. Open the node workspace to inspect it.</div>` : "";
  target.innerHTML = `
    <div class="mn-node-facts">
      <div><span>Scoped identity</span><code title="${escapeHtml(node.member_id)}">${escapeHtml(node.member_id)}</code></div>
      <div><span>Local query time</span><strong>${escapeHtml(compactTime(basis.queryTime))}</strong></div>
      <div><span>Clock bound</span><strong>${escapeHtml(formatDurationNs(basis.uncertainty || 0))}</strong></div>
      <div><span>Revision</span><code title="${escapeHtml(node.revision_id)}">${escapeHtml(node.revision_id)}</code></div>
      <div><span>Coverage</span><strong>${escapeHtml(node.coverage?.status || (node.resources_available === false ? "topology only" : "available"))}</strong></div>
      <div><span>Resources</span><strong>${escapeHtml(formatInteger(node.resource_count))}</strong></div>
    </div>
    <div class="mn-plugin-stack">${plugins}</div>
    <p class="mn-plugin-plan">This device maps the selected intent to <code>${escapeHtml(plan.projection_id)}</code> using <code>${escapeHtml(plan.status_perspective_id)}</code>. The provider is <code>${escapeHtml(`${plan.plugin_set_id}@${plan.plugin_version || "unspecified"}`)}</code>.</p>
    <div class="mn-resource-preview">${missingFocusedResource}${resourceRows || '<div class="topology-empty-list">No resource preview returned for this member. Open its node view for the full catalog.</div>'}</div>
  `;
}

function nodeLabelForRef(ref) {
  const node = findNodeForRef(ref, selectedResultNodes());
  return node?.label || ref?.node_id || ref?.member_id || "unknown node";
}

function evidenceLabel(value) {
  if (typeof value === "string") return value;
  return value?.label
    || value?.record_id
    || value?.event_uid
    || value?.resource_id
    || value?.resource_ref?.local_resource_id
    || value?.node_id
    || value?.source
    || JSON.stringify(value);
}

function renderLinkTable() {
  const body = byId("mn-link-table-body");
  const links = state.query?.links || [];
  const topologyLinkCount = links.filter((link) => !link.resolution_only).length;
  const resolutionOnlyCount = links.length - topologyLinkCount;
  byId("mn-link-table-count").textContent = resolutionOnlyCount
    ? `${formatInteger(topologyLinkCount)} links · ${formatInteger(resolutionOnlyCount)} unresolved`
    : `${formatInteger(topologyLinkCount)} returned`;
  body.innerHTML = links.map((link) => {
    const sourceNode = findNodeForRef(link.source, selectedResultNodes());
    const targetNode = findNodeForRef(link.target, selectedResultNodes());
    const health = linkHealth(link);
    const sourceLabel = link.source.label || link.source.resource_id || nodeLabelForRef(link.source);
    const targetLabel = link.target.label || link.target.resource_id || nodeLabelForRef(link.target);
    const evidence = link.evidence.map(evidenceLabel).filter(Boolean);
    const candidates = link.candidates.map(evidenceLabel).filter(Boolean);
    const sourceMarkup = sourceNode
      ? `<a href="${escapeHtml(navigationHref(sourceNode, link.source.resource_id ? link.source : null))}" title="${escapeHtml(resourceRefKey(link.source))}">${escapeHtml(sourceLabel)}</a>`
      : `<span>${escapeHtml(sourceLabel)}</span>`;
    const targetMarkup = targetNode
      ? `<a href="${escapeHtml(navigationHref(targetNode, link.target.resource_id ? link.target : null))}" title="${escapeHtml(resourceRefKey(link.target))}">${escapeHtml(targetLabel)}</a>`
      : `<span>${escapeHtml(targetLabel)}</span>`;
    return `<tr data-link-id="${escapeHtml(link.link_id)}">
      <td><div class="mn-link-endpoints">
        ${sourceMarkup}
        <span>→</span>
        ${targetMarkup}
      </div><small>${escapeHtml(`${nodeLabelForRef(link.source)} → ${nodeLabelForRef(link.target)}`)}</small></td>
      <td><span class="mn-status-pill is-${health}">${escapeHtml(link.status)}</span><small>${escapeHtml(link.kind)}</small></td>
      <td><span class="mn-quality-pill is-${health}">${escapeHtml(link.resolution)}</span><small>${escapeHtml(candidates.length ? `${candidates.length} candidates preserved` : "single boundary result")}</small></td>
      <td><strong>${escapeHtml(evidence[0] || "No evidence label")}</strong><code title="${escapeHtml(candidates.join(" · "))}">${escapeHtml(candidates.length ? candidates.join(" · ") : link.link_id)}</code></td>
    </tr>`;
  }).join("") || '<tr><td class="topology-empty-row" colspan="4">No inter-node links were returned. Unresolved boundary matches should be returned explicitly rather than omitted.</td></tr>';
}

function routeTableReportedTotal(snapshot) {
  return Number(snapshot?.counts?.total ?? snapshot?.counts?.entries ?? snapshot?.counts?.entry_count
    ?? snapshot?.page?.total ?? snapshot?.total ?? snapshot?.items?.length ?? 0);
}

function routeTableBasisLabel(snapshot) {
  const basis = snapshot?.resolved_basis || {};
  const kind = String(basis?.kind ?? state.query?.request?.basis?.kind ?? "capture vector");
  if (kind === "absolute_time") return `absolute at ${compactTime(basis?.time_ns ?? basis?.query_time_ns ?? state.query?.request?.basis?.time_ns)}`;
  if (kind === "relative_to_watermark") {
    const offset = basis?.offset_ns ?? state.query?.request?.basis?.offset_ns ?? 0;
    return `per-node watermark ${formatDurationNs(offset)}`;
  }
  return titleCase(kind);
}

function routeTableCompletenessLabel(value) {
  if (typeof value === "string") return value;
  if (value?.complete !== undefined) return value.complete ? "complete" : "incomplete";
  if (value?.all_nodes_complete !== undefined) return value.all_nodes_complete ? "complete" : "incomplete";
  return String(value?.status ?? value?.state ?? value?.resolution ?? value?.quality ?? "unknown");
}

function routeTableFilterOptions() {
  const snapshot = state.routeTableSnapshot;
  if (!snapshot) return;
  const entries = snapshot.items;
  const optionMarkup = (values, selected, allLabel) => `<option value="">${escapeHtml(allLabel)}</option>${values
    .map((value) => `<option value="${escapeHtml(value)}" ${value === selected ? "selected" : ""}>${escapeHtml(titleCase(value))}</option>`).join("")}`;
  byId("mn-route-table-node-filter").innerHTML = `<option value="">All nodes</option>${snapshot.groups.map((group) =>
    `<option value="${escapeHtml(group.node_id)}" ${group.node_id === state.routeTableFilters.node ? "selected" : ""}>${escapeHtml(group.label)}</option>`
  ).join("")}`;
  const unique = (values) => [...new Set(values.filter(Boolean).map(String))].sort((left, right) => left.localeCompare(right));
  byId("mn-route-table-vrf-filter").innerHTML = optionMarkup(unique(entries.map((entry) => entry.vrf)), state.routeTableFilters.vrf, "All VRFs");
  byId("mn-route-table-family-filter").innerHTML = optionMarkup(unique(entries.map((entry) => entry.route_family)), state.routeTableFilters.family, "All families");
  byId("mn-route-table-type-filter").innerHTML = optionMarkup(unique(entries.map((entry) => entry.route_type)), state.routeTableFilters.type, "All types");
  byId("mn-route-table-protocol-filter").innerHTML = optionMarkup(
    unique(entries.flatMap((entry) => [entry.protocol, entry.source_label])), state.routeTableFilters.protocol, "All protocols / sources"
  );
}

function routeTableEntryMatchesFilters(entry) {
  const filters = state.routeTableFilters;
  const search = filters.search.trim().toLowerCase();
  const destination = filters.destination.trim().toLowerCase();
  const nextHopText = entry.next_hops.map((hop) => `${hop.value} ${hop.egress}`).join(" ");
  const forwardingText = entry.forwarding_actions.flatMap((action) => [
    action.label, action.kind, action.operation, action.order,
    action.applies_to_next_hop_id, ...action.values.flatMap((value) => [value.value, value.kind, value.role]),
  ]).join(" ");
  const provenance = entry.plugin_provenance || {};
  const haystack = [
    entry.route_entry_id, entry.node_id, entry.member_id, entry.vrf, entry.vrf_id, entry.address_family,
    entry.route_family, entry.route_type, entry.prefix, entry.destination?.destination_id, entry.source_label,
    entry.protocol, nextHopText, forwardingText, entry.egress_interface?.name, entry.egress_interface?.resource_id, entry.status,
    provenance.plugin_id, provenance.plugin_run_id, provenance.decision_owner,
  ].filter(Boolean).join(" ").toLowerCase();
  return (!filters.node || entry.node_id === filters.node)
    && (!filters.vrf || entry.vrf === filters.vrf || entry.vrf_id === filters.vrf)
    && (!filters.family || entry.route_family === filters.family || entry.address_family === filters.family)
    && (!filters.type || entry.route_type === filters.type)
    && (!filters.protocol || entry.protocol === filters.protocol || entry.source_label === filters.protocol)
    && (!destination || entry.prefix.toLowerCase().includes(destination)
      || entry.destination?.destination_id?.toLowerCase().includes(destination)
      || forwardingText.toLowerCase().includes(destination))
    && (!search || haystack.includes(search));
}

function focusedRouteEntryKeys() {
  const trace = state.routeTrace;
  const path = selectedRoutePath();
  const collect = (sources) => {
    const values = [];
    const fields = [
      "matched_route_table_entry_ids", "matched_route_entry_ids", "matched_route_entry_refs",
      "route_table_entry_ids", "route_entry_ids", "route_entry_refs", "route_entry_ref",
    ];
    for (const source of sources) {
      if (!source) continue;
      for (const field of fields) {
        const value = source[field];
        if (Array.isArray(value)) values.push(...value);
        else if (value !== null && value !== undefined && value !== "") values.push(value);
      }
    }
    return values;
  };
  const pathValues = collect([path, ...(path?.segments || []), ...(path?.steps || [])]);
  const values = pathValues.length ? pathValues : collect([
    trace,
    state.routeBundle?.raw?.traces?.[state.activeRouteDirection],
  ]);
  // A route-table seed is pending input until a trace response correlates it.
  // Once a path supplies row references, those path-local references are the
  // authority; retaining the original seed would highlight the wrong route
  // after the user chooses another candidate.
  if (trace && !values.length) {
    if (state.focusedRouteEntryRef) values.push(state.focusedRouteEntryRef);
    if (state.focusedRouteEntryId) values.push(state.focusedRouteEntryId);
  }
  return new Set(values.flatMap((value) => {
    const key = routeEntryRefKey(value);
    const id = typeof value === "object" ? value?.route_entry_id ?? value?.entry_id ?? value?.id : value;
    return [key, id === null || id === undefined ? "" : String(id)].filter(Boolean);
  }));
}

function routeTableNextHopMarkup(entry) {
  if (!entry.next_hops.length) return '<span class="mn-route-table-next-hop is-inactive"><span><strong>Unresolved</strong><small>No next hop returned</small></span></span>';
  const visible = entry.next_hops.slice(0, 3);
  return visible.map((hop) => `<span class="mn-route-table-next-hop${hop.backup === true ? " is-backup" : ""}${hop.active === false ? " is-inactive" : hop.active === null ? " is-unknown" : ""}">
    <span><strong title="${escapeHtml(hop.value)}">${escapeHtml(hop.value)}</strong><small>${escapeHtml(hop.egress || entry.egress_interface.name || "egress unresolved")}${hop.weight !== undefined ? ` · weight ${escapeHtml(hop.weight)}` : ""}</small></span>
    ${hop.active === null ? "<em>state unknown</em>" : ""}
  </span>`).join("") + (entry.next_hops.length > visible.length ? `<small>+${entry.next_hops.length - visible.length} additional next hops</small>` : "");
}

function routeTableForwardingMarkup(entry) {
  if (!entry.forwarding_actions.length) {
    return '<span class="mn-route-table-forwarding-empty">No forwarding action</span>';
  }
  return entry.forwarding_actions.map((action) => {
    const visible = action.values.slice(0, 4);
    const fullValue = action.values.map((value) => value.value).join(" → ");
    const values = visible.map((value) => `<span class="mn-forwarding-value" title="${escapeHtml(`${action.label} · ${titleCase(value.kind)} · ${value.role || "declared value"} · ${value.value}`)}">
      <code>${escapeHtml(value.value)}</code>${value.role ? `<small>${escapeHtml(titleCase(value.role))}</small>` : ""}
    </span>`).join("");
    const overflow = action.values.length > visible.length
      ? `<span class="mn-forwarding-overflow" title="${escapeHtml(fullValue)}">+${action.values.length - visible.length}</span>` : "";
    const target = action.applies_to_next_hop_id ? ` · next hop ${action.applies_to_next_hop_id}` : "";
    return `<span class="mn-route-table-forwarding-action" title="${escapeHtml(`${action.operation} · ${action.order}${target} · ${fullValue}`)}">
      <span class="mn-forwarding-action-header"><strong>${escapeHtml(action.label)}</strong><small>${escapeHtml(`${titleCase(action.operation)} · ${action.order.replaceAll("_", " ")}`)}</small></span>
      <span class="mn-forwarding-values">${values}${overflow}</span>
    </span>`;
  }).join("");
}

function routeTableRowMarkup(entry, matchedKeys) {
  const provenance = entry.plugin_provenance || {};
  const matched = matchedKeys.has(entry.route_entry_id) || matchedKeys.has(entry.route_entry_ref_key);
  const pending = state.focusedRouteEntryId === entry.route_entry_id && !matched;
  const disposition = explicitRouteDisposition(entry);
  const health = ROUTE_TERMINAL_RESULTS.has(disposition) ? "error"
    : entry.installed === false || entry.active === false || entry.backup === true ? "warning"
      : entry.installed === true && entry.active === true ? "good" : "unknown";
  const installedBadge = entry.installed === true
    ? '<span class="mn-quality-pill is-good">installed</span>'
    : entry.installed === false
      ? '<span class="mn-quality-pill is-warning">not installed</span>'
      : '<span class="mn-quality-pill is-unresolved">installation unknown</span>';
  const activeBadge = entry.active === true
    ? '<span class="mn-quality-pill is-good">active</span>'
    : entry.active === false
      ? '<span class="mn-quality-pill is-error">inactive</span>'
      : '<span class="mn-quality-pill is-unresolved">activity unknown</span>';
  const opaqueDetails = Object.keys(entry.plugin_details || {}).length
    ? `<details class="mn-route-table-details"><summary>Plug-in details</summary><pre>${escapeHtml(JSON.stringify(entry.plugin_details, null, 2))}</pre></details>` : "";
  const traceControl = entry.traceable === true
    ? `<button class="mn-route-table-trace" type="button" data-route-entry-trace="${escapeHtml(entry.route_entry_id)}" aria-label="${escapeHtml(`Use route ${entry.prefix} in VRF ${entry.vrf} for trace`)}">Use in trace</button>`
    : `<button class="mn-route-table-trace is-unavailable" type="button" disabled aria-label="${escapeHtml(`No trace query is available for route ${entry.prefix} in VRF ${entry.vrf}`)}" title="The node plug-in did not provide a usable trace query for this row.">No trace</button>`;
  return `<tr class="mn-route-table-row${matched ? " is-focused-trace" : ""}${pending ? " is-pending-trace" : ""}" data-route-entry-id="${escapeHtml(entry.route_entry_id)}">
    <td><strong title="${escapeHtml(entry.prefix)}">${escapeHtml(entry.prefix)}</strong><small>${escapeHtml(entry.destination?.destination_id || entry.route_entry_id)}</small>${matched ? '<span class="mn-status-pill is-good">used by focused trace</span>' : pending ? '<span class="mn-plugin-badge">loaded into trace</span>' : ""}</td>
    <td><strong>${escapeHtml(entry.vrf)}</strong><small>${escapeHtml(`${entry.address_family} · ${entry.route_family}`)}</small><code>${escapeHtml(entry.route_type)}</code></td>
    <td><strong>${escapeHtml(titleCase(entry.protocol))}</strong><small title="${escapeHtml(entry.source_label)}">${escapeHtml(entry.source_label)}</small><code>${escapeHtml(`pref ${entry.preference ?? "—"} · metric ${entry.metric ?? "—"}`)}</code></td>
    <td><div class="mn-route-table-next-hops">${routeTableNextHopMarkup(entry)}</div></td>
    <td><div class="mn-route-table-forwarding">${routeTableForwardingMarkup(entry)}</div></td>
    <td><strong title="${escapeHtml(entry.egress_interface.resource_id)}">${escapeHtml(entry.egress_interface.name)}</strong><small>${escapeHtml(entry.egress_interface.resource_id || "no resource reference")}</small></td>
    <td><div class="mn-route-table-state"><span class="mn-status-pill is-${health}">${escapeHtml(entry.status)}</span>${installedBadge}${activeBadge}${entry.backup === true ? '<span class="mn-quality-pill is-warning">backup</span>' : ""}</div></td>
    <td><strong title="${escapeHtml(provenance.plugin_id || "")}">${escapeHtml(provenance.plugin_id || "unspecified plug-in")}</strong><small title="${escapeHtml(provenance.plugin_run_id || "")}">${escapeHtml(provenance.decision_owner || provenance.plugin_run_id || "plug-in owned")}</small>${opaqueDetails}</td>
    <td>${traceControl}</td>
  </tr>`;
}

function routeTableGroupBasis(group) {
  const basis = group.resolved_basis || {};
  const queryTime = basis?.query_time_ns ?? basis?.resolved_time_ns ?? basis?.time_ns ?? basis?.local_time_ns;
  const uncertainty = basis?.uncertainty_ns ?? basis?.clock_uncertainty_ns;
  const completeness = routeTableCompletenessLabel(group.completeness);
  const details = [queryTime !== undefined ? compactTime(queryTime) : "node time unavailable"];
  if (uncertainty !== undefined) details.push(`± ${formatDurationNs(uncertainty)}`);
  details.push(completeness);
  return details.join(" · ");
}

function routeTableGroupMarkup(group, entries, matchedKeys) {
  const open = state.routeTableOpenNodes.has(group.node_id);
  const total = group.entry_count || group.returned_count || group.entries.length;
  return `<details class="mn-route-table-group" data-route-table-group="${escapeHtml(group.node_id)}" ${open ? "open" : ""}>
    <summary>
      <span><strong>${escapeHtml(group.label)}</strong><small>${escapeHtml(`${group.node_id}${group.member_id ? ` · ${group.member_id}` : ""}`)}</small></span>
      <span><code>${escapeHtml(routeTableGroupBasis(group))}</code><small>${escapeHtml(group.plugin_provenance?.plugin_id || entries[0]?.plugin_provenance?.plugin_id || "node plug-in snapshot")}</small></span>
      <span><strong>${formatInteger(entries.length)}</strong><small>${entries.length === total ? "routes" : `of ${formatInteger(total)} routes`}</small></span>
    </summary>
    <div class="mn-route-table-scroll"><table class="mn-route-table">
      <thead><tr><th>Destination</th><th>VRF / family</th><th>Protocol / decision</th><th>Next hops</th><th>Forwarding actions</th><th>Egress</th><th>State</th><th>Provenance</th><th>Trace</th></tr></thead>
      <tbody>${entries.map((entry) => routeTableRowMarkup(entry, matchedKeys)).join("") || '<tr><td class="topology-empty-row" colspan="9">No route matches the current filters for this node.</td></tr>'}</tbody>
    </table></div>
  </details>`;
}

function renderRouteTables() {
  const loading = byId("mn-route-table-loading");
  const browser = document.querySelector(".mn-route-table-browser");
  const scope = byId("mn-route-table-scope");
  const error = byId("mn-route-table-error");
  loading.hidden = !state.routeTablePending;
  error.textContent = state.routeTableError;
  if (state.routeTablePending) {
    scope.textContent = "reading capture vector";
    scope.classList.remove("is-warning");
    browser.hidden = true;
    byId("mn-route-table-summary").innerHTML = "";
    return;
  }
  const snapshot = state.routeTableSnapshot;
  if (!snapshot) {
    scope.textContent = "route tables unavailable";
    scope.classList.add("is-warning");
    browser.hidden = false;
    byId("mn-route-table-summary").innerHTML = "";
    byId("mn-route-table-node-index").innerHTML = "";
    byId("mn-route-table-groups").innerHTML = '<div class="mn-route-table-empty"><strong>No route-table snapshot is available for this topology context.</strong></div>';
    return;
  }
  browser.hidden = false;
  const fallback = snapshot.source === "capability-fallback";
  scope.textContent = fallback ? "capability-provided snapshot" : "context-bound snapshot";
  scope.classList.toggle("is-warning", fallback);
  if (!state.routeTablesInitialized) {
    const initiallyOpen = snapshot.groups.find((group) => group.node_id === selectedResultNodes().find((node) => node.key === state.focusedNodeKey)?.node_id)
      || snapshot.groups[0];
    if (initiallyOpen) state.routeTableOpenNodes.add(initiallyOpen.node_id);
    state.routeTablesInitialized = true;
  }
  routeTableFilterOptions();
  const filtered = snapshot.items.filter(routeTableEntryMatchesFilters);
  const reportedTotal = routeTableReportedTotal(snapshot);
  const vrfCount = new Set(snapshot.items.map((entry) => entry.vrf)).size;
  const familyCount = new Set(snapshot.items.map((entry) => entry.route_family)).size;
  const completeness = routeTableCompletenessLabel(snapshot.completeness);
  byId("mn-route-table-summary").innerHTML = `
    <article><span>Visible routes</span><strong>${formatInteger(filtered.length)} / ${formatInteger(reportedTotal)}</strong><small>${reportedTotal > snapshot.items.length ? `${formatInteger(snapshot.items.length)} rows loaded; response is partial` : "complete loaded page"}</small></article>
    <article><span>Node tables</span><strong>${formatInteger(snapshot.groups.length)}</strong><small>${escapeHtml(completeness)} coverage</small></article>
    <article><span>Routing domains</span><strong>${formatInteger(vrfCount)} VRFs</strong><small>${formatInteger(familyCount)} route families</small></article>
    <article><span>Snapshot basis</span><strong title="${escapeHtml(snapshot.route_table_context_id)}">${escapeHtml(routeTableBasisLabel(snapshot))}</strong><small>${escapeHtml(snapshot.route_table_context_id || snapshot.topology_context_id || "static capability context")}</small></article>`;
  const filteredByNode = new Map(snapshot.groups.map((group) => [group.node_id, filtered.filter((entry) => entry.node_id === group.node_id)]));
  byId("mn-route-table-node-index").innerHTML = `<button type="button" data-route-table-node-index="" aria-current="${!state.routeTableFilters.node}"><span>All nodes</span><code>${formatInteger(filtered.length)}</code></button>${snapshot.groups.map((group) =>
    `<button type="button" data-route-table-node-index="${escapeHtml(group.node_id)}" aria-current="${state.routeTableFilters.node === group.node_id}"><span>${escapeHtml(group.label)}</span><code>${formatInteger(filteredByNode.get(group.node_id)?.length || 0)}</code></button>`
  ).join("")}`;
  const hasNonNodeFilter = Object.entries(state.routeTableFilters).some(([key, value]) => key !== "node" && String(value).trim());
  const visibleGroups = snapshot.groups.filter((group) => (!state.routeTableFilters.node || group.node_id === state.routeTableFilters.node)
    && (!hasNonNodeFilter || (filteredByNode.get(group.node_id)?.length || 0)));
  const matchedKeys = focusedRouteEntryKeys();
  byId("mn-route-table-groups").innerHTML = visibleGroups.map((group) =>
    routeTableGroupMarkup(group, filteredByNode.get(group.node_id) || [], matchedKeys)
  ).join("") || '<div class="mn-route-table-empty"><strong>No routes match the current filters.</strong><span>Clear one or more filters to restore the node tables.</span></div>';
  byId("mn-route-table-node-index").querySelectorAll("[data-route-table-node-index]").forEach((button) => {
    button.addEventListener("click", () => {
      state.routeTableFilters.node = button.dataset.routeTableNodeIndex;
      byId("mn-route-table-node-filter").value = state.routeTableFilters.node;
      if (state.routeTableFilters.node) state.routeTableOpenNodes.add(state.routeTableFilters.node);
      renderRouteTables();
    });
  });
  byId("mn-route-table-groups").querySelectorAll("[data-route-table-group]").forEach((details) => {
    details.addEventListener("toggle", () => {
      if (details.open) state.routeTableOpenNodes.add(details.dataset.routeTableGroup);
      else state.routeTableOpenNodes.delete(details.dataset.routeTableGroup);
    });
  });
  byId("mn-route-table-groups").querySelectorAll("[data-route-entry-trace]").forEach((button) => {
    button.addEventListener("click", () => useRouteTableEntry(button.dataset.routeEntryTrace));
  });
}

function ensureRouteSelectValue(select, value) {
  if (!value) return;
  if (![...select.options].some((option) => option.value === value)) {
    select.insertAdjacentHTML("beforeend", `<option value="${escapeHtml(value)}">${escapeHtml(titleCase(value))}</option>`);
  }
  select.value = value;
}

function useRouteTableEntry(entryId) {
  const entry = state.routeTableSnapshot?.items.find((item) => item.route_entry_id === entryId);
  if (!entry || entry.traceable !== true || !state.routeCapabilities) return;
  const query = entry.trace_query || {};
  const explicitFlowSource = query?.flow?.source ?? query?.source;
  const source = routeEndpointSeedValue(explicitFlowSource, "source")
    || query.source_id || entry?.source?.source_id || "";
  const explicitFlowDestination = query?.flow?.destination ?? query?.destination;
  const destination = routeEndpointSeedValue(explicitFlowDestination, "destination")
    || query.destination_id
    || entry.destination?.destination_id
    || entry.destination?.value
    || entry.prefix;
  const startDescriptor = query?.trace_starts?.forward
    ?? query?.ingress
    ?? query?.starting_point
    ?? null;
  const start = routeStartSeedValue(startDescriptor, entry.node_id);
  if (query.scenario_id && state.routeCapabilities.scenarios.some((scenario) => scenario.scenario_id === query.scenario_id)) {
    byId("mn-route-scenario").value = query.scenario_id;
  }
  const steeringScenario = selectedRouteScenario();
  const steeringProfileId = String(
    query.steering_profile_id
    ?? steeringScenario?.steering_profile_id
    ?? state.routeCapabilities.default_steering_profile
    ?? "",
  );
  renderRouteSteeringProfiles(steeringScenario, steeringProfileId);
  // Always replace every seeded field.  Leaving an empty plug-in field alone
  // would silently retain the previous route's endpoint and trace a different
  // flow from the row the operator selected.
  setRouteEndpointInput("source", source);
  setRouteStartInput(start);
  setRouteEndpointInput("destination", destination);
  byId("mn-route-vrf").value = String(query.vrf ?? query.vrf_id ?? entry.vrf);
  ensureRouteSelectValue(byId("mn-route-family"), String(query.route_family ?? query.address_family ?? entry.route_family));
  ensureRouteSelectValue(byId("mn-route-type"), String(query.route_type ?? entry.route_type));
  const requestedDirection = query.direction === "both" ? "bidirectional" : query.direction;
  byId("mn-route-validation").value = ["forward", "reverse", "bidirectional"].includes(requestedDirection)
    ? requestedDirection : "bidirectional";
  state.activeRouteDirection = requestedDirection === "reverse" ? "reverse" : "forward";
  state.focusedRouteEntryId = entry.route_entry_id;
  state.focusedRouteEntryRef = entry.route_entry_ref;
  invalidateRouteTraceResult();
  syncUrl();
  byId("route-trace").scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" });
  showToast("Route parameters loaded. Review them, then trace the route.");
}

function invalidateRouteTraceResult() {
  cancelPendingRouteTrace();
  clearRoutePacketSelection();
  state.routeBundle = null;
  state.routeTraces = { forward: null, reverse: null };
  state.routeTrace = null;
  state.selectedRoutePathIds = { forward: "", reverse: "" };
  state.selectedRoutePathId = "";
  state.requestedRoutePathId = "";
  clearRoutePathPreview();
  clearRouteHover();
  renderRouteTrace();
  renderMap();
  renderRouteTables();
}

function cancelPendingRouteTrace() {
  if (!state.routePending && !state.routeAbortController) return;
  state.routeRequestGeneration += 1;
  state.routeAbortController?.abort();
  state.routeAbortController = null;
  state.routePending = false;
  setFormBusy("mn-route-form", false);
}

function clearFocusedRouteEntry() {
  if (!state.focusedRouteEntryId && !state.focusedRouteEntryRef) return;
  state.focusedRouteEntryId = "";
  state.focusedRouteEntryRef = null;
  renderRouteTables();
  renderRouteSeed();
}

function focusNode(key) {
  clearRouteHover();
  state.focusedNodeKey = key;
  state.focusedResourceRef = null;
  renderCapabilityNodeIndex();
  renderMap();
  syncUrl();
  renderNodeDetail();
  renderLinkTable();
}

function renderAll() {
  renderSourceBanner();
  renderCapabilityNodeIndex();
  renderMetrics();
  renderMap();
  renderNodeDetail();
  renderLinkTable();
  renderRouteTrace();
  renderRouteTables();
}

function markTopologyQueryDirty() {
  if (!state.query || state.pending) return;
  state.queryControlsDirty = true;
  renderSourceBanner();
  syncUrl();
}

function syncUrl() {
  if (!state.capabilities) return;
  const url = new URL(location.href);
  // `/` is the canonical multi-node workspace even when this page was opened
  // through the compatibility `/topology` route.
  url.pathname = "/";
  const basisKind = byId("mn-basis-kind").value;
  url.searchParams.set("topology_profile_id", byId("mn-projection").value);
  url.searchParams.set("status_perspective_id", byId("mn-perspective").value);
  url.searchParams.set("topology_layers", TOPOLOGY_ELEMENT_KEYS
    .filter((key) => topologyElementVisible(key)).join(","));
  url.searchParams.set("topology_view", state.topologyNetworkView);
  url.searchParams.set("basis_kind", basisKind);
  url.searchParams.set("clock_policy", byId("mn-clock-policy").value);
  if (basisKind === "absolute_time") {
    url.searchParams.set("time_ns", byId("mn-absolute-time").value.trim());
    url.searchParams.delete("relative_seconds");
  } else {
    url.searchParams.set("relative_seconds", byId("mn-relative-seconds").value.trim());
    url.searchParams.delete("time_ns");
  }
  const selected = state.capabilities.nodes.filter((node) => state.selectedNodeKeys.has(node.key));
  url.searchParams.set("members", selected.map((node) => node.member_id).join(","));
  const focused = selectedResultNodes().find((node) => node.key === state.focusedNodeKey) || state.capabilities.nodes.find((node) => node.key === state.focusedNodeKey);
  if (focused) {
    url.searchParams.set("focus_member", focused.member_id);
    url.searchParams.set("focus_node", focused.node_id);
  } else {
    url.searchParams.delete("focus_member");
    url.searchParams.delete("focus_node");
  }
  const focusedResourceBelongsToNode = focused && state.focusedResourceRef?.resource_id
    && (state.focusedResourceRef.member_id === focused.member_id || state.focusedResourceRef.node_id === focused.node_id);
  if (focusedResourceBelongsToNode) url.searchParams.set("focus_resource", state.focusedResourceRef.resource_id);
  else url.searchParams.delete("focus_resource");
  if (state.query?.context_id && !state.queryControlsDirty) url.searchParams.set("context_id", state.query.context_id); else url.searchParams.delete("context_id");
  if (state.routeCapabilities) {
    url.searchParams.set("route_scenario", byId("mn-route-scenario").value);
    url.searchParams.set("route_start", routeStartRequestValue());
    url.searchParams.set("route_source", routeEndpointRequestValue("source"));
    url.searchParams.set("route_destination", routeEndpointRequestValue("destination"));
    url.searchParams.set("route_vrf", byId("mn-route-vrf").value.trim());
    url.searchParams.set("route_family", byId("mn-route-family").value);
    url.searchParams.set("route_type", byId("mn-route-type").value);
    url.searchParams.set("route_policy", byId("mn-route-policy").value);
    const steeringProfileId = byId("mn-route-steering").value;
    if (steeringProfileId) url.searchParams.set("route_steering", steeringProfileId);
    else url.searchParams.delete("route_steering");
    url.searchParams.set("route_direction", byId("mn-route-validation").value);
    url.searchParams.set("route_focus_direction", state.activeRouteDirection);
    url.searchParams.set("route_view", state.routeGraphMode);
  }
  if (state.selectedRoutePathId) {
    url.searchParams.set("route_path", state.selectedRoutePathId);
  } else {
    url.searchParams.delete("route_path");
  }
  history.replaceState(null, "", `${url.pathname}${url.search}${url.hash}`);
}

async function runRouteTrace(event) {
  event?.preventDefault();
  const error = byId("mn-route-error");
  let request;
  try {
    request = immutableSnapshot(buildRouteTraceRequest());
    error.textContent = "";
  } catch (requestError) {
    error.textContent = requestError.message;
    return;
  }
  const generation = ++state.routeRequestGeneration;
  state.routeAbortController?.abort();
  const controller = new AbortController();
  state.routeAbortController = controller;
  const params = new URLSearchParams(location.search);
  const requestedPath = state.requestedRoutePathId || params.get("route_path");
  const requestedDirection = params.get("route_focus_direction");
  clearRoutePacketSelection();
  state.routePending = true;
  clearRoutePathPreview();
  clearRouteHover();
  setFormBusy("mn-route-form", true);
  renderRouteTrace();
  try {
    const bundle = await traceRoute(request, controller.signal);
    if (generation !== state.routeRequestGeneration) return;
    state.routeBundle = bundle;
    state.routeTraces = state.routeBundle.traces;
    const fallbackDirection = request.direction === "reverse" ? "reverse" : "forward";
    state.activeRouteDirection = [requestedDirection, state.activeRouteDirection, fallbackDirection, "forward", "reverse"]
      .find((direction) => state.routeTraces[direction]) || fallbackDirection;
    state.routeTrace = state.routeTraces[state.activeRouteDirection];
    const requestedForActive = state.routeTrace.paths.some((path) => path.path_id === requestedPath) ? requestedPath : "";
    state.selectedRoutePathId = requestedForActive
      || (state.routeGraphMode === "focused" ? defaultRoutePath(state.routeTrace)?.path_id || "" : "");
    state.selectedRoutePathIds = {
      forward: state.routeTraces.forward?.paths.some((path) => path.path_id === requestedPath)
        ? requestedPath : state.routeGraphMode === "focused" ? defaultRoutePath(state.routeTraces.forward)?.path_id || "" : "",
      reverse: state.routeTraces.reverse?.paths.some((path) => path.path_id === requestedPath)
        ? requestedPath : state.routeGraphMode === "focused" ? defaultRoutePath(state.routeTraces.reverse)?.path_id || "" : "",
    };
    state.selectedRoutePathIds[state.activeRouteDirection] = state.selectedRoutePathId;
    state.requestedRoutePathId = state.selectedRoutePathId;
  } catch (traceError) {
    if (isAbortError(traceError) || generation !== state.routeRequestGeneration) return;
    state.routeBundle = null;
    state.routeTraces = { forward: null, reverse: null };
    state.routeTrace = null;
    state.selectedRoutePathIds = { forward: "", reverse: "" };
    state.selectedRoutePathId = "";
    state.requestedRoutePathId = "";
    clearRoutePathPreview();
    clearRouteHover();
    error.textContent = traceError.message;
  } finally {
    if (generation !== state.routeRequestGeneration) return;
    state.routePending = false;
    state.routeAbortController = null;
    setFormBusy("mn-route-form", false);
    renderRouteTrace();
    renderMap();
    renderRouteTables();
    syncUrl();
  }
}

async function runQuery(event) {
  event?.preventDefault();
  const error = byId("mn-query-error");
  let request;
  try {
    request = immutableSnapshot(buildQueryRequest());
    error.textContent = "";
  } catch (requestError) {
    error.textContent = requestError.message;
    return;
  }
  const generation = ++state.topologyRequestGeneration;
  state.topologyAbortController?.abort();
  const controller = new AbortController();
  state.topologyAbortController = controller;
  state.routeRequestGeneration += 1;
  state.routeAbortController?.abort();
  state.routeAbortController = null;
  state.pending = true;
  state.routePending = false;
  state.routeBundle = null;
  state.routeTraces = { forward: null, reverse: null };
  state.routeTrace = null;
  if (state.query) state.requestedRoutePathId = "";
  state.selectedRoutePathIds = { forward: "", reverse: "" };
  state.selectedRoutePathId = "";
  clearRoutePacketSelection();
  clearRoutePathPreview();
  clearRouteHover();
  state.routeTableSnapshot = null;
  state.routeTablePending = true;
  state.routeTableError = "";
  state.focusedRouteEntryId = "";
  state.focusedRouteEntryRef = null;
  setFormBusy("mn-query-form", true);
  setFormBusy("mn-route-form", true);
  byId("mn-select-all").disabled = true;
  renderSourceBanner();
  renderCapabilityNodeIndex();
  renderRouteTables();
  let succeeded = false;
  try {
    const query = await reconstruct(request, controller.signal);
    if (generation !== state.topologyRequestGeneration) return;
    state.query = query;
    state.apiMode = state.query.source_mode;
    state.apiError = "";
    state.queryControlsDirty = false;
    if (!state.focusedNodeKey || !state.query.nodes.some((node) => node.key === state.focusedNodeKey)) {
      state.focusedNodeKey = state.query.nodes[0]?.key || "";
      state.focusedResourceRef = null;
    }
    if (!state.query.nodes.some((node) => node.key === state.topologyFocusedNodeKey)) {
      state.topologyFocusedNodeKey = "";
    }
    byId("mn-revision").textContent = state.query.context_id || state.bootstrap?.workspace?.revision_id || "multi-revision query";
    await loadRouteTables(state.query, generation, controller.signal);
    if (generation !== state.topologyRequestGeneration) return;
    succeeded = true;
  } catch (queryError) {
    if (isAbortError(queryError) || generation !== state.topologyRequestGeneration) return;
    error.textContent = queryError.message;
    state.query = { nodes: [], links: [], request, source_mode: "error" };
    state.apiMode = "error";
    state.apiError = queryError.message;
    state.queryControlsDirty = false;
    state.routeTablePending = false;
    state.routeTableError = "Route tables were not queried because topology reconstruction failed.";
  } finally {
    if (generation !== state.topologyRequestGeneration) return;
    state.pending = false;
    state.topologyAbortController = null;
    setFormBusy("mn-query-form", false);
    setFormBusy("mn-route-form", false);
    byId("mn-select-all").disabled = false;
    syncUrl();
    renderAll();
  }
  if (succeeded && generation === state.topologyRequestGeneration && state.routeCapabilities && state.query?.nodes?.length) {
    const scopeIssue = routeEndpointScopeIssue(selectedRouteEndpoint("source"), selectedRouteEndpoint("destination"));
    const startScopeIssue = routeUsesForwardStart() ? routeStartScopeIssue(selectedRouteStart()) : "";
    if (scopeIssue || startScopeIssue) {
      byId("mn-route-error").textContent = `${scopeIssue || startScopeIssue} The topology was reconstructed successfully; route tracing is paused until the requested flow and trace start are in scope.`;
    } else {
      await runRouteTrace();
    }
  }
}

function bindControls() {
  byId("mn-query-form").addEventListener("submit", runQuery);
  byId("mn-route-form").addEventListener("submit", runRouteTrace);
  byId("mn-basis-kind").addEventListener("change", () => {
    syncBasisFields();
    markTopologyQueryDirty();
  });
  byId("mn-projection").addEventListener("change", () => {
    markTopologyQueryDirty();
    renderCapabilityNodeIndex();
    renderNodeDetail();
  });
  byId("mn-perspective").addEventListener("change", () => {
    markTopologyQueryDirty();
    renderCapabilityNodeIndex();
    renderNodeDetail();
  });
  byId("mn-clock-policy").addEventListener("change", markTopologyQueryDirty);
  ["mn-absolute-time", "mn-relative-seconds"].forEach((id) => {
    byId(id).addEventListener("input", markTopologyQueryDirty);
  });
  byId("mn-route-scenario").addEventListener("change", () => {
    const scenario = selectedRouteScenario();
    const pair = directionalPairForScenario(scenario);
    const source = pair?.forward?.source_id ?? scenario?.default_source?.source_id ?? scenario?.default_source?.value
      ?? scenario?.default_source ?? state.routeCapabilities.default_source;
    const destination = pair?.forward?.destination_id ?? scenario?.default_destination?.destination_id ?? scenario?.default_destination?.value
      ?? scenario?.default_destination ?? state.routeCapabilities.default_destination;
    if (source) setRouteEndpointInput("source", source);
    if (destination) setRouteEndpointInput("destination", destination);
    const sourceStart = state.routeCapabilities.start_points.find(
      (point) => point.node_id === selectedRouteEndpoint("source")?.node_id
    );
    setRouteStartInput(
      routeStartSelectorValue(scenario?.default_start)
      || state.routeCapabilities.default_start
      || sourceStart?.start_id
    );
    const vrf = scenario?.vrf ?? scenario?.vrf_id;
    const family = pair?.forward?.route_family ?? scenario?.route_family ?? scenario?.address_family;
    const routeType = pair?.forward?.route_type ?? scenario?.route_type;
    applyCompatibleRouteContext({
      routeType: routeType || byId("mn-route-type").value,
      routeFamily: family || byId("mn-route-family").value,
      vrf: vrf || byId("mn-route-vrf").value,
      scenario,
    });
    const steeringProfileId = String(
      scenario?.steering_profile_id
      ?? state.routeCapabilities.default_steering_profile
      ?? "",
    );
    renderRouteSteeringProfiles(scenario, steeringProfileId);
    clearFocusedRouteEntry();
    invalidateRouteTraceResult();
    syncUrl();
    showToast("Trace scenario loaded. Endpoints and routing context were updated together.");
  });
  ["mn-route-source", "mn-route-destination"].forEach((id) => {
    const control = byId(id);
    control.addEventListener("input", () => {
      if (state.focusedRouteEntryId) clearFocusedRouteEntry();
      if (state.routeTrace || state.routeBundle || state.routePending) invalidateRouteTraceResult();
      syncUrl();
    });
    control.addEventListener("change", () => {
      refreshRouteEndpointIdentity(id === "mn-route-source" ? "source" : "destination");
      clearFocusedRouteEntry();
      if (state.routeTrace || state.routeBundle || state.routePending) invalidateRouteTraceResult();
      syncUrl();
    });
  });
  byId("mn-route-start").addEventListener("input", () => {
    if (state.focusedRouteEntryId) clearFocusedRouteEntry();
    if (state.routeTrace || state.routeBundle || state.routePending) invalidateRouteTraceResult();
    syncUrl();
  });
  byId("mn-route-start").addEventListener("change", () => {
    refreshRouteStartIdentity();
    clearFocusedRouteEntry();
    if (state.routeTrace || state.routeBundle || state.routePending) invalidateRouteTraceResult();
    syncUrl();
  });
  ["mn-route-vrf", "mn-route-family", "mn-route-type"].forEach((id) => {
    const control = byId(id);
    if (control.tagName === "INPUT") control.addEventListener("input", () => {
      if (state.focusedRouteEntryId) clearFocusedRouteEntry();
      if (state.routeTrace || state.routeBundle || state.routePending) invalidateRouteTraceResult();
      syncUrl();
    });
    control.addEventListener("change", () => {
      applyCompatibleRouteContext({
        routeType: byId("mn-route-type").value,
        routeFamily: byId("mn-route-family").value,
        vrf: byId("mn-route-vrf").value,
      });
      clearFocusedRouteEntry();
      if (state.routeTrace || state.routeBundle || state.routePending) invalidateRouteTraceResult();
      syncUrl();
    });
  });
  byId("mn-route-policy").addEventListener("change", () => {
    invalidateRouteTraceResult();
    syncUrl();
  });
  byId("mn-route-steering").addEventListener("change", () => {
    invalidateRouteTraceResult();
    syncUrl();
  });
  byId("mn-route-validation").addEventListener("change", () => {
    syncRouteStartControlState();
    clearFocusedRouteEntry();
    invalidateRouteTraceResult();
    syncUrl();
  });
  byId("mn-route-table-filters").addEventListener("submit", (event) => event.preventDefault());
  const routeTableFilterBindings = {
    "mn-route-table-search": "search",
    "mn-route-table-node-filter": "node",
    "mn-route-table-vrf-filter": "vrf",
    "mn-route-table-family-filter": "family",
    "mn-route-table-type-filter": "type",
    "mn-route-table-protocol-filter": "protocol",
    "mn-route-table-destination-filter": "destination",
  };
  Object.entries(routeTableFilterBindings).forEach(([id, key]) => {
    const control = byId(id);
    control.addEventListener(control.tagName === "INPUT" ? "input" : "change", () => {
      state.routeTableFilters[key] = control.value;
      if (key === "node" && control.value) state.routeTableOpenNodes.add(control.value);
      renderRouteTables();
    });
  });
  byId("mn-route-table-clear").addEventListener("click", () => {
    Object.keys(state.routeTableFilters).forEach((key) => { state.routeTableFilters[key] = ""; });
    byId("mn-route-table-search").value = "";
    byId("mn-route-table-destination-filter").value = "";
    renderRouteTables();
  });
  byId("mn-route-direction-tabs").querySelectorAll("[data-route-direction]").forEach((button) => {
    button.addEventListener("click", () => selectRouteDirection(button.dataset.routeDirection));
  });
  document.querySelectorAll("button[data-route-graph-mode]").forEach((button) => {
    button.addEventListener("click", () => setRouteGraphMode(button.dataset.routeGraphMode));
  });
  byId("mn-route-clear-path").addEventListener("click", () => clearSelectedRoutePath());
  document.addEventListener("keydown", (event) => {
    if (event.key !== "Escape") return;
    if (state.routePacketPinnedRef || state.routePacketPreviewRef) {
      clearRoutePacketSelection({ restoreFocus: true });
      return;
    }
    if (state.topologyInspectorKey) {
      clearTopologyInspector({ restoreFocus: true });
      return;
    }
    const topologyElementPicker = byId("mn-topology-element-picker");
    if (topologyElementPicker?.open) {
      topologyElementPicker.open = false;
      topologyElementPicker.querySelector("summary")?.focus();
      return;
    }
    const topologyGuide = byId("mn-topology-guide");
    if (topologyGuide?.open) {
      topologyGuide.open = false;
      topologyGuide.querySelector("summary")?.focus();
      return;
    }
    if (state.previewRoutePathId) {
      clearRoutePathPreview();
      return;
    }
    if (state.previewRoutePresentationId) {
      clearRoutePresentationPreview({ restoreFocus: true });
      return;
    }
    if (state.routeGraphMode === "all" && state.selectedRoutePathId) clearSelectedRoutePath();
  });
  byId("mn-node-filter").addEventListener("input", (event) => {
    state.nodeFilter = event.target.value;
    renderCapabilityNodeIndex();
    renderMap();
  });
  byId("mn-select-all").addEventListener("click", () => {
    const selectableNodes = state.capabilities.nodes.filter((node) => node.available !== false);
    if (!selectableNodes.length) return;
    const allSelected = selectableNodes.every((node) => state.selectedNodeKeys.has(node.key));
    state.selectedNodeKeys = allSelected ? new Set() : new Set(selectableNodes.map((node) => node.key));
    markTopologyQueryDirty();
    renderCapabilityNodeIndex();
    renderMetrics();
    renderMap();
    syncUrl();
  });
  byId("mn-node-index-expand")?.addEventListener("click", (event) => {
    const expanded = !byId("mn-node-index").classList.contains("is-expanded");
    byId("mn-node-index").classList.toggle("is-expanded", expanded);
    event.currentTarget.setAttribute("aria-expanded", String(expanded));
    event.currentTarget.textContent = expanded ? "Show less" : "Show all";
  });
  document.querySelectorAll("[data-health]").forEach((button) => button.addEventListener("click", () => {
    state.healthFilter = button.dataset.health;
    document.querySelectorAll("[data-health]").forEach((candidate) => candidate.setAttribute("aria-pressed", String(candidate === button)));
    renderMap();
  }));
  document.querySelectorAll("[data-topology-network-view]").forEach((button) => button.addEventListener("click", () => {
    state.topologyNetworkView = button.dataset.topologyNetworkView === "vpn" ? "vpn" : "underlay";
    syncTopologyNetworkViewControls();
    renderMetrics();
    renderLinkStatusMap();
    syncUrl();
  }));
  document.querySelectorAll("[data-topology-element-preset]").forEach((button) => button.addEventListener("click", () => {
    const preset = button.dataset.topologyElementPreset === "all" ? "all" : "compact";
    state.topologyElementVisibility = new Set(TOPOLOGY_ELEMENT_PRESETS[preset]);
    syncTopologyElementControls();
    renderLinkStatusMap();
    syncUrl();
  }));
  document.querySelectorAll("[data-topology-element]").forEach((control) => control.addEventListener("change", () => {
    const key = control.dataset.topologyElement;
    if (!TOPOLOGY_ELEMENT_KEYS.includes(key)) return;
    if (control.checked) state.topologyElementVisibility.add(key); else state.topologyElementVisibility.delete(key);
    syncTopologyElementControls();
    renderLinkStatusMap();
    syncUrl();
  }));
  if ("ResizeObserver" in window) {
    const resizeObserver = new ResizeObserver((entries) => {
      entries.forEach((entry) => state.resizeTargets.add(entry.target.id));
      cancelAnimationFrame(state.resizeFrame);
      state.resizeFrame = requestAnimationFrame(() => {
        const targets = new Set(state.resizeTargets);
        state.resizeTargets.clear();
        if (targets.has("mn-map-stage")) renderLinkStatusMap();
        if (targets.has("mn-route-map-stage")) {
          renderFocusedRouteMap();
          renderDirectionTabs();
        }
      });
    });
    resizeObserver.observe(byId("mn-map-stage"));
    resizeObserver.observe(byId("mn-route-map-stage"));
  }
}

function bootstrapFromCapabilities(capabilities) {
  const revisionId = capabilities?.revision_id
    || capabilities?.nodes?.[0]?.revision_id
    || new URLSearchParams(location.search).get("revision_id")
    || "";
  const captureNs = capabilities?.time_bounds?.capture_ns ?? capabilities?.time_bounds?.end_ns ?? "0";
  return { workspace: { revision_id: revisionId, capture_ns: captureNs } };
}

async function initialize() {
  try {
    state.capabilities = await discoverCapabilities();
    state.bootstrap = bootstrapFromCapabilities(state.capabilities);
    byId("mn-revision").textContent = state.bootstrap?.workspace?.revision_id || "revision set";
    state.apiMode = state.capabilities.source_mode;
    renderControls();
    initializeNodeSelection();
    try {
      state.routeCapabilities = await discoverRouteCapabilities();
    } catch (routeError) {
      state.routeCapabilityError = routeError.message;
    }
    renderRouteControls();
    bindControls();
    renderSourceBanner();
    renderCapabilityNodeIndex();
    await runQuery();
  } catch (error) {
    state.pending = false;
    state.apiMode = "error";
    byId("mn-query-error").textContent = error.message;
    byId("mn-source-banner").classList.add("is-fallback");
    byId("mn-source-banner").innerHTML = `<span class="mn-spinner" aria-hidden="true"></span><strong>Topology page could not initialize.</strong><span>${escapeHtml(error.message)}</span>`;
  }
}

initialize();
