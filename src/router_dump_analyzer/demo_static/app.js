const PALETTE = ["#52e0c4", "#a58bff", "#f5b85b", "#66b8ff", "#ff8eb5", "#9bd66f", "#df9dff"];
const REVIEW_STORAGE_KEY = "router-state-lab-review-v2";
const DASHBOARD_LAYOUT_STORAGE_KEY = "router-state-lab-plugin-dashboards-v1";
const LANE_WIDTH = 280;
const HOVER_OPEN_DELAY_MS = 150;
const HOVER_CLOSE_GRACE_MS = 380;
const EVENT_LOG_ROW_HEIGHT = 44;
const EVENT_LOG_OVERSCAN = 10;
const MAX_RESOURCE_ROWS = 500;
const MAX_LANE_PICKER_ROWS = 300;
const MAX_SCALE_TIMELINE_LANES = 100;
const MAX_RECORD_LANES = 8;
const MAX_RECORD_PATTERN_LENGTH = 160;
const RESOURCE_TYPE_ACRONYMS = new Map([
  ["DTE", "DTE"], ["ETE", "ETE"], ["ETG", "ETG"], ["EVPN", "EVPN"],
  ["IP", "IP"], ["ISIS", "IS-IS"], ["MPLS", "MPLS"], ["SID", "SID"],
  ["SRV6", "SRv6"], ["VRF", "VRF"],
]);

const state = {
  dataset: null,
  timelinePayload: null,
  lanes: [],
  resourceCatalogLanes: [],
  laneByResource: new Map(),
  resourceById: new Map(),
  resourceAliases: new Map(),
  eventByUid: new Map(),
  sourceRecords: [],
  sourceRecordByUid: new Map(),
  sourceRecordTypes: new Map(),
  recordLanePresets: [],
  recordLaneRules: [],
  recordLanes: [],
  selectedSourceRecordUid: null,
  eventLogInclude: {
    normalized: true,
    ctf: false,
    external: false,
  },
  eventLogRows: [],
  eventLogIndexById: new Map(),
  eventLogRenderFrame: null,
  customRecordLaneSequence: 0,
  layerMeta: new Map(),
  activeLayers: new Set(),
  viewStartNs: 0n,
  viewEndNs: 1n,
  cursorNs: 1n,
  cursorSelected: false,
  rangeStartNs: null,
  rangeEndNs: null,
  rangeMode: false,
  brush: null,
  suppressTimelineClickUntil: 0,
  rangeSummary: null,
  rangeRequestId: 0,
  zoom: 1,
  trackWidth: 900,
  selectedEventUid: null,
  selectedEventResourceId: null,
  selectedResourceId: null,
  selectedResourceKind: null,
  laneMode: "all",
  explicitLaneIds: new Set(),
  laneFilterText: "",
  graph: null,
  graphShowFull: false,
  correlationTimelineView: "separate",
  correlationTimelineExpanded: true,
  expandedTimelineTreeKeys: new Set(),
  activeCorrelationEdges: [],
  correlatedResourceIds: new Set(),
  resourceQuery: null,
  graphRequestId: 0,
  graphTimeNs: null,
  graphRequestedTimeNs: null,
  graphPending: false,
  resourceRequestId: 0,
  resourceSearchTimer: null,
  dashboardOrder: [],
  openDashboardIds: new Set(),
  expandedDashboardIds: new Set(),
  dashboardLayoutReady: false,
  draggedDashboardId: null,
  temporalTimer: null,
  hoverModels: new Map(),
  hoverOpenTimer: null,
  hoverCloseTimer: null,
  hoverPinned: false,
  hoverKey: null,
  hoverGuideNs: null,
  hoverGuideClientX: null,
};

const byId = (id) => document.getElementById(id);

function isScaleMode() {
  return Boolean(
    state.dataset?.demo?.scale_mode
    || String(state.dataset?.demo?.mode || "").startsWith("full-scale"),
  );
}

function initialScaleLaneIds() {
  return (state.dataset?.demo?.initial_resource_ids || []).map(String).slice(0, MAX_SCALE_TIMELINE_LANES);
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function toNs(value, fallback = 0n) {
  if (typeof value === "bigint") return value;
  if (value === null || value === undefined || value === "") return fallback;
  try {
    return BigInt(String(value).split(".")[0]);
  } catch (_error) {
    return fallback;
  }
}

function clampNs(value) {
  const candidate = toNs(value, state.viewStartNs);
  return candidate < state.viewStartNs
    ? state.viewStartNs
    : candidate > state.viewEndNs
      ? state.viewEndNs
      : candidate;
}

function ratioBetween(value, start = state.viewStartNs, end = state.viewEndNs) {
  const span = end - start;
  if (span <= 0n) return 0;
  const scaled = ((toNs(value) - start) * 1_000_000n) / span;
  return Math.max(0, Math.min(1, Number(scaled) / 1_000_000));
}

function nsAtRatio(ratio) {
  const scaled = BigInt(Math.round(Math.max(0, Math.min(1, ratio)) * 1_000_000));
  return state.viewStartNs + ((state.viewEndNs - state.viewStartNs) * scaled) / 1_000_000n;
}

function timelinePercent(value) {
  return ratioBetween(value) * 100;
}

function formatDuration(value) {
  if (value === null || value === undefined) return "until capture end";
  let ns = toNs(value);
  const sign = ns < 0n ? "-" : "";
  if (ns < 0n) ns = -ns;
  if (ns < 1_000n) return `${sign}${ns} ns`;
  if (ns < 1_000_000n) return `${sign}${(Number(ns / 1_000n) / 1_000).toFixed(3)} ms`;
  if (ns < 1_000_000_000n) return `${sign}${(Number(ns / 1_000_000n) / 1_000).toFixed(3)} s`;
  const wholeSeconds = ns / 1_000_000_000n;
  const fraction = Number((ns % 1_000_000_000n) / 1_000_000n) / 1_000;
  if (wholeSeconds < 60n) return `${sign}${(Number(wholeSeconds) + fraction).toFixed(3)} s`;
  const minutes = wholeSeconds / 60n;
  return `${sign}${minutes}m ${wholeSeconds % 60n}s`;
}

function formatOffset(value, precision = 3) {
  const delta = toNs(value) - state.viewStartNs;
  const sign = delta < 0n ? "-" : "+";
  const abs = delta < 0n ? -delta : delta;
  const seconds = abs / 1_000_000_000n;
  const fraction = String(abs % 1_000_000_000n).padStart(9, "0").slice(0, precision);
  return `${sign}${seconds}${precision ? `.${fraction}` : ""} s`;
}

function titleCase(value) {
  return String(value ?? "unknown")
    .replaceAll("_", " ")
    .replaceAll("-", " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function formatValue(value) {
  if (value === null) return "null";
  if (value === undefined) return "unknown";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function formatBytes(bytes) {
  const value = Number(bytes || 0);
  if (value < 1024) return `${value} B`;
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KiB`;
  return `${(value / 1024 ** 2).toFixed(1)} MiB`;
}

function stableColor(key) {
  let hash = 0;
  for (const char of String(key ?? "unknown")) hash = (hash * 31 + char.charCodeAt(0)) >>> 0;
  return PALETTE[hash % PALETTE.length];
}

function layerConfig(layer) {
  const key = layer || "unknown";
  if (!state.layerMeta.has(key)) {
    state.layerMeta.set(key, { label: titleCase(key), color: stableColor(key) });
  }
  return state.layerMeta.get(key);
}

function humanLayer(layer) {
  return layerConfig(layer).label;
}

function resourceKindDescriptor(kind) {
  const descriptors = state.dataset?.kind_descriptors || state.dataset?.schema?.resource_kinds || [];
  return descriptors.find((item) => String(item.kind || item.resource_kind || item.type) === String(kind)) || null;
}

function humanResourceType(kind) {
  const descriptor = resourceKindDescriptor(kind);
  const fallback = titleCase(String(kind || "unknown").toLowerCase());
  const configured = descriptor?.display_name || descriptor?.label;
  if (configured && configured !== fallback) return configured;
  return String(kind || "unknown").split(/[_-]+/).map((token) => {
    const upper = token.toUpperCase();
    return RESOURCE_TYPE_ACRONYMS.get(upper) || titleCase(token.toLowerCase());
  }).join(" ");
}

function normalizeResourceIcon(raw) {
  if (!raw || typeof raw !== "object") return null;
  const path = String(raw.path || "").trim();
  if (!path || path.length > 4096 || !/^[MmZzLlHhVvCcSsQqTtAa0-9eE,.+\-\s]+$/.test(path)) return null;
  const sourceBox = Array.isArray(raw.view_box)
    ? raw.view_box
    : String(raw.view_box || "0 0 24 24").trim().split(/[\s,]+/);
  const viewBox = sourceBox.map(Number);
  if (viewBox.length !== 4 || viewBox.some((value) => !Number.isFinite(value)) || viewBox[2] <= 0 || viewBox[3] <= 0) return null;
  const renderMode = raw.render_mode ?? "stroke";
  if (renderMode !== "stroke" && renderMode !== "fill") return null;
  const strokeWidth = Number(raw.stroke_width ?? 1.8);
  if (!Number.isFinite(strokeWidth) || strokeWidth < 0.25 || strokeWidth > 8) return null;
  return { path, viewBox, renderMode, strokeWidth };
}

function resourceIconDescriptor(record, kind) {
  const candidate = record?.icon ?? record?.presentation?.icon ?? record?.resource?.icon ?? resourceKindDescriptor(kind)?.icon;
  return normalizeResourceIcon(candidate);
}

function resourceIconMarkup(record, kind, extraClass = "") {
  const icon = resourceIconDescriptor(record, kind);
  if (!icon) return "";
  const classes = ["resource-kind-icon", `icon-${icon.renderMode}`, extraClass].filter(Boolean).join(" ");
  return `<svg class="${classes}" viewBox="${icon.viewBox.join(" ")}" style="--resource-icon-stroke-width:${icon.strokeWidth}" aria-hidden="true" focusable="false"><path d="${escapeHtml(icon.path)}"></path></svg>`;
}

function layerColor(layer) {
  return layerConfig(layer).color;
}

function showToast(message) {
  const toast = byId("toast");
  if (!toast) return;
  toast.textContent = message;
  toast.classList.add("visible");
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => toast.classList.remove("visible"), 2200);
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`;
    try {
      const body = await response.json();
      detail = body.detail || body.error?.message || detail;
    } catch (_error) {
      // Keep the HTTP status when the body is not JSON.
    }
    throw new Error(detail);
  }
  return response.json();
}

function revisionPath(suffix) {
  return `/v1/revisions/${encodeURIComponent(state.dataset.demo.revision_id)}/${suffix}`;
}

function eventSubject(event) {
  return event?.subjects?.[0] || event?.subject || {};
}

function eventTime(event) {
  return toNs(event?.time_ns ?? event?.timestamp_ns ?? event?.start_ns, state.viewStartNs);
}

function sourceRecordUid(record) {
  return String(record?.source_record_uid || record?.record_uid || record?.id || "");
}

function sourceRecordTime(record) {
  return toNs(record?.time_ns ?? record?.timestamp_ns, state.viewStartNs);
}

function sourceTypeDescriptor(sourceType) {
  return state.sourceRecordTypes.get(String(sourceType || "unknown")) || {
    source_type: String(sourceType || "unknown"),
    label: titleCase(sourceType || "unknown"),
    color: stableColor(sourceType || "unknown"),
  };
}

function isCtfSourceRecord(record) {
  return String(record?.source_type || "").toLowerCase() === "ctf";
}

function normalizedLogEntryId(eventUid) {
  return "event:" + String(eventUid);
}

function sourceLogEntryId(recordUid) {
  return "source:" + String(recordUid);
}

function sourceRecordMatchesEvent(record) {
  return Boolean(record?.matched_event_uid);
}

function statusValues(event) {
  const result = event?.attributes?.result || event?.result || {};
  return Object.entries(result).filter(([key]) => /status$/i.test(key));
}

function eventFailed(event) {
  if (event?.failure === true || event?.failed === true) return true;
  const outcome = String(event?.outcome ?? "").toLowerCase();
  if (["failure", "failed", "error", "rejected"].includes(outcome)) return true;
  return statusValues(event).some(([, value]) => !["ok", "success", "accepted"].includes(String(value).toLowerCase()));
}

function eventChangesState(event) {
  if (event?.state_changed !== undefined) return Boolean(event.state_changed);
  if (eventFailed(event)) return false;
  return !["observe", "read", "noop"].includes(String(event?.action ?? event?.operation ?? "").toLowerCase());
}

function eventStatus(event) {
  if (eventFailed(event)) return "status unchanged";
  if (event?.resulting_status) return String(event.resulting_status);
  const properties = event?.attributes?.properties || event?.properties || {};
  const result = event?.attributes?.result || event?.result || {};
  for (const key of ["program_state", "status", "after", "state", "oper_state", "routeStatus", "bridgeStatus", "driverStatus"]) {
    if (properties[key] !== undefined) return String(properties[key]);
    if (result[key] !== undefined) return String(result[key]);
  }
  return titleCase(event?.effect_type || event?.action || event?.operation || "active");
}

function resourceIdOf(record) {
  if (!record) return null;
  if (typeof record === "string") return record;
  const direct = record.resource_id ?? record.resource_uid ?? record.resource ?? record.id;
  if (direct && typeof direct !== "object") return String(direct);
  const layer = record.layer || "unknown";
  const kind = record.kind || record.type || record.resource_type || "RESOURCE";
  const key = record.key;
  if (key && typeof key === "object") {
    return `${layer}/${kind}/${Object.values(key).map(String).join("/")}`;
  }
  return null;
}

function resourceKind(record, resourceId = "") {
  if (record?.kind || record?.type || record?.resource_type) {
    return String(record.kind || record.type || record.resource_type);
  }
  return String(resourceId).split("/")[1] || "RESOURCE";
}

function resourceLayer(record, resourceId = "") {
  return record?.layer || String(resourceId).split("/")[0] || "unknown";
}

function resourceLabel(record, resourceId = "") {
  return String(record?.label || record?.display_name || record?.name || resourceId.split("/").slice(-2).join("/") || resourceId);
}

function presentationTags(record) {
  const tags = record?.presentation_tags ?? record?.presentation?.tags ?? record?.resource?.presentation_tags ?? [];
  return new Set(Array.isArray(tags) ? tags.map(String) : String(tags || "").split(/[ ,]+/).filter(Boolean));
}

function isCompact(record) {
  const tags = presentationTags(record);
  return tags.has("compact") || tags.has("connector");
}

function registerResource(record, preferredId = null) {
  const id = preferredId || resourceIdOf(record);
  if (!id) return null;
  const existing = state.resourceById.get(id);
  const incoming = record || {};
  const merged = existing
    ? existing === incoming
      ? existing
      : { ...existing, ...incoming, resource_id: id }
    : incoming.resource_id === id
      ? incoming
      : { ...incoming, resource_id: id };
  state.resourceById.set(id, merged);
  state.resourceAliases.set(id.toLowerCase(), id);
  const keyValues = Object.values(merged.key || {}).map((value) => String(value).toLowerCase());
  for (const value of keyValues) state.resourceAliases.set(`${resourceLayer(merged, id)}::${value}`, id);
  return id;
}

function canonicalResourceForSubject(subject, event) {
  const direct = subject?.resource_id || subject?.resource_uid || subject?.canonical_id || subject?.resource;
  if (direct && typeof direct !== "object") return String(direct);
  const layer = subject?.layer || event?.layer || "unknown";
  const raw = String(subject?.raw_key || subject?.key || event?.resource_id || event?.resource || event?.event_type || "unknown");
  const exact = state.resourceAliases.get(raw.toLowerCase()) || state.resourceAliases.get(`${layer}::${raw.toLowerCase()}`);
  if (exact) return exact;
  const tokens = raw.toLowerCase().split(/[^a-z0-9:.]+|:/).filter(Boolean);
  const candidates = [...state.resourceById.entries()].filter(([id, record]) => {
    if (resourceLayer(record, id) !== layer) return false;
    const values = Object.values(record.key || {}).map((value) => String(value).toLowerCase());
    return values.length > 0 && values.every((value) => tokens.includes(value));
  });
  if (candidates.length === 1) return candidates[0][0];
  const kind = subject?.kind || event?.resource_kind || event?.kind || "RESOURCE";
  return `${layer}/${kind}/${raw}`;
}

function eventResourceRefs(event) {
  const direct = event?.affected_resources || event?.resource_ids;
  if (Array.isArray(direct) && direct.length) return direct.map((item) => resourceIdOf(item) || String(item));
  const subjects = Array.isArray(event?.subjects) && event.subjects.length ? event.subjects : [eventSubject(event)];
  return [...new Set(subjects.map((subject) => canonicalResourceForSubject(subject, event)).filter(Boolean))];
}

function normalizeMark(raw, lane) {
  const event = raw?.event || state.eventByUid.get(raw?.event_uid || raw?.event_id) || raw || {};
  const uid = String(raw?.event_uid || raw?.event_id || event.event_uid || event.event_id || `${lane.laneId}:${eventTime(event)}`);
  if (event && Object.keys(event).length) state.eventByUid.set(uid, { ...event, event_uid: uid });
  return {
    kind: "event",
    eventUid: uid,
    timeNs: toNs(raw?.time_ns ?? raw?.timestamp_ns ?? event.timestamp_ns ?? event.time_ns, state.viewStartNs),
    eventType: raw?.event_type || event.event_type || "event",
    action: raw?.action || raw?.operation || event.action || event.operation || "observe",
    outcome: raw?.outcome || event.outcome || (eventFailed(event) ? "failure" : "success"),
    label: raw?.label || event.label || titleCase(raw?.event_type || event.event_type || "event"),
    failure: raw?.failure ?? eventFailed(event),
    stateChanged: raw?.state_changed ?? eventChangesState(event),
    effectType: raw?.effect_type || event.effect_type || event.action || "event",
    durationToNextChangeNs: raw?.duration_to_next_change_ns === null || raw?.duration_to_next_change_ns === undefined
      ? null
      : toNs(raw.duration_to_next_change_ns),
    event,
    lane,
  };
}

function normalizeInterval(raw, kind, lane) {
  const startRaw = raw?.start_ns ?? raw?.valid_from_ns;
  const endRaw = raw?.end_ns ?? raw?.valid_to_ns;
  const startNs = startRaw === null || startRaw === undefined ? state.viewStartNs : toNs(startRaw, state.viewStartNs);
  const endNs = endRaw === null || endRaw === undefined ? state.viewEndNs : toNs(endRaw, state.viewEndNs);
  const properties = raw?.properties || raw?.state || {};
  const status = raw?.status || properties.status || properties.program_state || properties.oper_state || (kind === "lifecycle" ? "exists" : "active");
  return {
    kind,
    startNs,
    endNs,
    openStart: Boolean(raw?.open_start ?? startRaw === null),
    openEnd: Boolean(raw?.open_end ?? endRaw === null),
    status: String(status),
    statusClass: String(raw?.status_class || (String(status).toLowerCase().includes("fail") || String(status).toLowerCase().includes("error") ? "error" : "ok")),
    properties,
    startEventUid: raw?.start_event_uid || raw?.cause_event_uid || null,
    endEventUid: raw?.end_event_uid || null,
    durationNs: raw?.duration_ns === null || raw?.duration_ns === undefined ? endNs - startNs : toNs(raw.duration_ns),
    lane,
  };
}

function ensureLane(laneMap, config) {
  const resourceId = config.resourceId || config.laneId;
  if (!laneMap.has(resourceId)) {
    const resource = config.resource || state.resourceById.get(resourceId) || { resource_id: resourceId };
    laneMap.set(resourceId, {
      laneId: config.laneId || resourceId,
      resourceId,
      layer: config.layer || resourceLayer(resource, resourceId),
      kind: config.kind || resourceKind(resource, resourceId),
      label: config.label || resourceLabel(resource, resourceId),
      resource,
      tags: presentationTags(resource),
      lifecycle: [],
      statuses: [],
      marks: [],
      clusters: [],
    });
  }
  return laneMap.get(resourceId);
}

function deriveLaneIntervals(lane) {
  lane.marks.sort((a, b) => (a.timeNs < b.timeNs ? -1 : a.timeNs > b.timeNs ? 1 : 0));
  const changed = lane.marks.filter((mark) => mark.stateChanged && !mark.failure);
  lane.marks.forEach((mark) => {
    if (mark.durationToNextChangeNs !== null) return;
    const next = changed.find((candidate) => candidate.timeNs > mark.timeNs);
    mark.durationToNextChangeNs = next ? next.timeNs - mark.timeNs : state.viewEndNs - mark.timeNs;
  });

  if (!lane.lifecycle.length) {
    let open = null;
    for (const mark of lane.marks) {
      if (mark.failure) continue;
      const action = String(mark.action).toLowerCase();
      if (["create", "add", "insert"].includes(action) && open === null) open = mark;
      if (["delete", "remove", "destroy"].includes(action) && open !== null) {
        lane.lifecycle.push(normalizeInterval({ start_ns: open.timeNs, end_ns: mark.timeNs, start_event_uid: open.eventUid, end_event_uid: mark.eventUid }, "lifecycle", lane));
        open = null;
      }
    }
    if (open) lane.lifecycle.push(normalizeInterval({ start_ns: open.timeNs, end_ns: null, start_event_uid: open.eventUid, open_end: true }, "lifecycle", lane));
    if (!lane.lifecycle.length) lane.lifecycle.push(normalizeInterval({ start_ns: null, end_ns: null, open_start: true, open_end: true }, "lifecycle", lane));
  }

  if (!lane.statuses.length && changed.length) {
    changed.forEach((mark, index) => {
      const action = String(mark.action).toLowerCase();
      if (["delete", "remove", "destroy"].includes(action)) return;
      const next = changed.slice(index + 1).find((candidate) => candidate.timeNs > mark.timeNs);
      lane.statuses.push(normalizeInterval({
        start_ns: mark.timeNs,
        end_ns: next?.timeNs ?? null,
        status: eventStatus(mark.event),
        status_class: mark.failure ? "error" : "ok",
        properties: mark.event?.attributes?.properties || mark.event?.properties || {},
        start_event_uid: mark.eventUid,
      }, "status", lane));
    });
  }
  if (!lane.statuses.length) {
    const snapshot = lane.resource?.state || {};
    lane.statuses.push(normalizeInterval({ start_ns: null, end_ns: null, status: snapshot.status || snapshot.program_state || snapshot.oper_state || "observed", properties: snapshot }, "status", lane));
  }
}

function normalizeCluster(raw, lane) {
  const items = (raw?.items || raw?.events || [])
    .map((item) => normalizeMark(item, lane));
  const eventUids = raw?.event_uids || raw?.event_ids || items.map((item) => item.eventUid);
  const lookupItems = eventUids.map((uid) => lane.marks.find((mark) => mark.eventUid === uid)).filter(Boolean);
  const preview = items.length ? items : lookupItems;
  return {
    kind: "cluster",
    clusterId: String(raw?.cluster_id || `${lane.laneId}:${raw?.start_ns || preview[0]?.timeNs || "cluster"}`),
    lane,
    startNs: toNs(raw?.start_ns ?? preview[0]?.timeNs, state.viewStartNs),
    endNs: toNs(raw?.end_ns ?? preview.at(-1)?.timeNs, state.viewStartNs),
    count: Number(raw?.count ?? raw?.counts?.total ?? preview.length),
    failureCount: Number(raw?.failure_count ?? raw?.counts?.failure ?? preview.filter((item) => item.failure).length),
    eventUids: eventUids.map(String),
    items: preview,
  };
}

function normalizeSourceMark(raw, lane) {
  const uid = String(raw?.source_record_uid || raw?.record?.source_record_uid || "");
  const record = raw?.record || state.sourceRecordByUid.get(uid) || raw || {};
  if (uid && !state.sourceRecordByUid.has(uid)) state.sourceRecordByUid.set(uid, record);
  return {
    kind: "source-record",
    sourceRecordUid: uid,
    timeNs: sourceRecordTime(raw?.record ? raw.record : raw),
    sourceType: String(raw?.source_type || record.source_type || "unknown"),
    recordName: String(raw?.record_name || record.record_name || "record"),
    sourceName: String(raw?.source_name || record.source_name || "source"),
    message: String(raw?.message || record.message || ""),
    matchedEventUid: raw?.matched_event_uid || record.matched_event_uid || null,
    record,
    lane,
  };
}

function normalizeRecordLane(raw) {
  const lane = {
    laneId: String(raw?.lane_id || "source-records"),
    label: String(raw?.label || "Source records"),
    description: String(raw?.description || ""),
    pattern: String(raw?.pattern || ""),
    sourceTypes: (raw?.source_types || []).map(String),
    unmatchedOnly: Boolean(raw?.unmatched_only),
    caseSensitive: Boolean(raw?.case_sensitive),
    pluginDefined: Boolean(raw?.plugin_defined),
    recordCount: Number(raw?.record_count || 0),
    truncated: Boolean(raw?.truncated),
    marks: [],
  };
  lane.marks = (raw?.marks || []).map((mark) => normalizeSourceMark(mark, lane))
    .sort((left, right) => left.timeNs < right.timeNs ? -1 : left.timeNs > right.timeNs ? 1 : left.sourceRecordUid.localeCompare(right.sourceRecordUid));
  return lane;
}

function normalizeTimeline(payload) {
  const laneMap = new Map();
  const authoritativeServerLanes = Array.isArray(payload?.lanes);
  const rawLanes = payload?.lanes || state.dataset.timeline?.lanes || [];
  for (const raw of rawLanes) {
    const resource = raw.resource && typeof raw.resource === "object" ? raw.resource : null;
    const resourceId = raw.resource_id || resourceIdOf(resource) || raw.lane_id;
    if (!resourceId) continue;
    if (resource) registerResource(resource, resourceId);
    const lane = ensureLane(laneMap, {
      laneId: raw.lane_id,
      resourceId,
      resource,
      layer: raw.layer,
      kind: raw.kind,
      label: raw.label,
    });
    for (const interval of raw.lifecycle_intervals || raw.lifecycle || raw.existence_intervals || []) {
      lane.lifecycle.push(normalizeInterval(interval, "lifecycle", lane));
    }
    for (const interval of raw.status_intervals || raw.state_intervals || raw.intervals || []) {
      lane.statuses.push(normalizeInterval(interval, "status", lane));
    }
    for (const mark of raw.event_marks || raw.events || raw.marks || []) {
      lane.marks.push(normalizeMark(mark, lane));
    }
  }

  if (!authoritativeServerLanes) {
    for (const record of state.dataset.resources || []) {
      const id = registerResource(record);
      if (id) ensureLane(laneMap, { resourceId: id, resource: state.resourceById.get(id) });
    }

    for (const rawInterval of state.dataset.state_intervals || []) {
      const id = resourceIdOf(rawInterval) || rawInterval.resource;
      if (!id) continue;
      const lane = ensureLane(laneMap, { resourceId: id, resource: state.resourceById.get(id) });
      if (!lane.statuses.some((item) => item.startNs === toNs(rawInterval.valid_from_ns, state.viewStartNs))) {
        lane.statuses.push(normalizeInterval(rawInterval, "status", lane));
      }
    }

    for (const event of state.dataset.events || []) {
      const uid = String(event.event_uid || event.event_id);
      state.eventByUid.set(uid, event);
      for (const id of eventResourceRefs(event)) {
        const lane = ensureLane(laneMap, { resourceId: id, resource: state.resourceById.get(id), layer: eventSubject(event).layer });
        if (!lane.marks.some((mark) => mark.eventUid === uid)) lane.marks.push(normalizeMark(event, lane));
      }
    }
  }

  const clusters = payload?.clusters || state.dataset.timeline?.clusters || [];
  for (const raw of clusters) {
    const lane = [...laneMap.values()].find((item) => item.laneId === raw.lane_id || item.resourceId === raw.resource_id);
    if (lane) lane.clusters.push(normalizeCluster(raw, lane));
  }

  const lanes = [...laneMap.values()];
  lanes.forEach(deriveLaneIntervals);
  lanes.sort((a, b) => `${a.layer}/${a.kind}/${a.label}`.localeCompare(`${b.layer}/${b.kind}/${b.label}`));
  state.lanes = lanes;
  state.laneByResource = new Map(lanes.map((lane) => [lane.resourceId, lane]));
  state.recordLanes = (payload?.record_lanes || []).map(normalizeRecordLane);
}

function buildClientGlyphs(lane) {
  if (lane.clusters.length) {
    const collapsed = new Set(lane.clusters.flatMap((cluster) => cluster.eventUids));
    return [...lane.clusters, ...lane.marks.filter((mark) => !collapsed.has(mark.eventUid))]
      .sort((a, b) => ((a.timeNs || a.startNs) < (b.timeNs || b.startNs) ? -1 : 1));
  }
  const threshold = Math.max(7, 13 / state.trackWidth * 100);
  const result = [];
  let group = [];
  const flush = () => {
    if (group.length >= 3) {
      result.push(normalizeCluster({
        cluster_id: `client:${lane.laneId}:${group[0].eventUid}`,
        start_ns: group[0].timeNs,
        end_ns: group.at(-1).timeNs,
        count: group.length,
        failure_count: group.filter((mark) => mark.failure).length,
        event_uids: group.map((mark) => mark.eventUid),
      }, lane));
    } else result.push(...group);
    group = [];
  };
  for (const mark of lane.marks) {
    if (!group.length || timelinePercent(mark.timeNs) - timelinePercent(group.at(-1).timeNs) <= threshold) group.push(mark);
    else {
      flush();
      group.push(mark);
    }
  }
  flush();
  return result;
}

function rangeBounds() {
  if (state.rangeStartNs === null || state.rangeEndNs === null) return null;
  return state.rangeStartNs <= state.rangeEndNs
    ? [state.rangeStartNs, state.rangeEndNs]
    : [state.rangeEndNs, state.rangeStartNs];
}

function inSelectedRange(value) {
  const bounds = rangeBounds();
  if (!bounds) return false;
  const candidate = toNs(value);
  return candidate >= bounds[0] && candidate <= bounds[1];
}

function intersectsRange(start, end) {
  const bounds = rangeBounds();
  if (!bounds) return false;
  return toNs(start) <= bounds[1] && toNs(end) >= bounds[0];
}

function laneSelectedByMode(resourceId) {
  if (state.laneMode === "all") return true;
  if (state.laneMode === "selected") return resourceId === state.selectedResourceId;
  if (state.laneMode === "correlated") {
    return resourceId === state.selectedResourceId || state.correlatedResourceIds.has(resourceId);
  }
  return state.explicitLaneIds.has(resourceId);
}

function laneIsVisible(lane) {
  return state.activeLayers.has(lane.layer) && laneSelectedByMode(lane.resourceId);
}

function visibleTimelineLanes() {
  return state.lanes.filter(laneIsVisible);
}

function normalizedRelationshipSpan(raw) {
  const source = raw?.source || raw?.source_resource_id;
  const target = raw?.target || raw?.target_resource_id;
  if (!source || !target) return null;
  const startRaw = raw?.valid_from_ns ?? raw?.start_ns;
  const endRaw = raw?.valid_to_ns ?? raw?.end_ns;
  return {
    id: String(raw?.relationship_id || raw?.id || `${source}:${raw?.relation_type || raw?.type}:${target}:${startRaw ?? "open"}`),
    source: String(source),
    target: String(target),
    type: String(raw?.relation_type || raw?.type || "related"),
    quality: String(raw?.quality || "unknown"),
    temporalNote: raw?.temporal_note || null,
    startNs: startRaw === null || startRaw === undefined ? state.viewStartNs : toNs(startRaw, state.viewStartNs),
    endNs: endRaw === null || endRaw === undefined ? state.viewEndNs : toNs(endRaw, state.viewEndNs),
    openStart: startRaw === null || startRaw === undefined,
    openEnd: endRaw === null || endRaw === undefined,
  };
}

function temporalRelationshipSpans() {
  const serverSpans = [
    ...(state.timelinePayload?.relationship_intervals || []),
    ...(state.timelinePayload?.relationship_spans || []),
  ];
  // The server spans are already clipped to both endpoint lifecycles. Mixing
  // them with raw or point-in-time edges would draw a correlation before an
  // endpoint exists, so fixture intervals are only a transport fallback.
  const raw = serverSpans.length
    ? serverSpans
    : (state.dataset.relationship_intervals || []);
  const unique = new Map();
  raw.map(normalizedRelationshipSpan).filter(Boolean).forEach((item) => {
    const key = `${item.source}|${item.type}|${item.target}|${item.startNs}|${item.endNs}`;
    if (!unique.has(key) || unique.get(key).quality === "unknown") unique.set(key, item);
  });
  return [...unique.values()];
}

function relationshipGroupsForResource(resourceId, ancestry = new Set()) {
  const groups = new Map();
  temporalRelationshipSpans()
    .filter((edge) => edge.source === resourceId || edge.target === resourceId)
    .forEach((edge) => {
      const otherId = edge.source === resourceId ? edge.target : edge.source;
      const otherLane = state.laneByResource.get(otherId);
      if (ancestry.has(otherId) || !otherLane || !state.activeLayers.has(otherLane.layer)) return;
      const key = `${edge.source}|${edge.type}|${edge.target}|${edge.id}`;
      if (!groups.has(key)) groups.set(key, { key, source: edge.source, target: edge.target, type: edge.type, otherId, spans: [] });
      groups.get(key).spans.push(edge);
    });
  return [...groups.values()].sort((a, b) => {
    const aLane = state.laneByResource.get(a.otherId);
    const bLane = state.laneByResource.get(b.otherId);
    return (aLane?.label || a.otherId).localeCompare(bLane?.label || b.otherId) || a.type.localeCompare(b.type);
  });
}

function timelineTreeInstances(rootLanes) {
  const instances = [];
  const append = (lane, key, depth, ancestry, parentResourceId = null, relationship = null) => {
    const children = depth >= 6 ? [] : relationshipGroupsForResource(lane.resourceId, ancestry);
    const instance = { lane, key, depth, parentResourceId, relationship, hasChildren: children.length > 0 };
    instances.push(instance);
    if (!state.expandedTimelineTreeKeys.has(key)) return;
    for (const child of children) {
      const childLane = state.laneByResource.get(child.otherId);
      if (!childLane) continue;
      const childKey = `${key}>${child.key}`;
      append(childLane, childKey, depth + 1, new Set([...ancestry, child.otherId]), lane.resourceId, child);
    }
  };
  rootLanes.forEach((lane) => append(lane, `root:${lane.resourceId}`, 0, new Set([lane.resourceId])));
  return instances;
}

function relationshipRibbonsForLane(lane, instance) {
  if (state.correlationTimelineView !== "separate") return "";
  const parentId = instance?.parentResourceId || state.selectedResourceId;
  if (!parentId) return "";
  const candidates = instance?.relationship?.spans || temporalRelationshipSpans()
    .filter((edge) => lane.resourceId !== parentId
      && (edge.source === parentId || edge.target === parentId)
      && (edge.source === lane.resourceId || edge.target === lane.resourceId));
  return candidates
    .map((edge, index) => {
      const start = edge.startNs < state.viewStartNs ? state.viewStartNs : edge.startNs;
      const end = edge.endNs > state.viewEndNs ? state.viewEndNs : edge.endNs;
      if (end < state.viewStartNs || start > state.viewEndNs || end <= start) return "";
      const active = state.cursorNs >= start && (state.cursorNs < end || (edge.openEnd && state.cursorNs === end));
      const key = `relationship:${edge.id}:${instance?.key || lane.resourceId}`;
      state.hoverModels.set(key, { type: "relationship", edge, lane, otherId: parentId });
      const direction = edge.source === parentId ? "outgoing" : "incoming";
      return `<div class="relationship-ribbon ${direction} quality-${safeClass(edge.quality)}${active ? " active" : ""}${edge.temporalNote?.includes("without") ? " uncertain" : ""}${intersectsRange(start, end) ? " in-range" : ""}" data-hover-key="${escapeHtml(key)}" data-range-start-ns="${start}" data-range-end-ns="${end}" style="${barStyle({ startNs: start, endNs: end })};--ribbon-row:${index % 3}" title="${escapeHtml(`${edge.type} / ${parentId} / ${edge.quality}`)}"><span>${escapeHtml(edge.type)}</span></div>`;
    }).join("");
}

function combinedAssociationLane(trackWidth = state.trackWidth) {
  if (state.correlationTimelineView !== "combined" || !state.selectedResourceId || !state.correlationTimelineExpanded) return "";
  const spans = temporalRelationshipSpans()
    .filter((edge) => edge.source === state.selectedResourceId || edge.target === state.selectedResourceId)
    .map((edge) => ({
      ...edge,
      startNs: edge.startNs < state.viewStartNs ? state.viewStartNs : edge.startNs,
      endNs: edge.endNs > state.viewEndNs ? state.viewEndNs : edge.endNs,
      otherId: edge.source === state.selectedResourceId ? edge.target : edge.source,
      direction: edge.source === state.selectedResourceId ? "outgoing" : "incoming",
    }))
    .filter((edge) => edge.endNs > edge.startNs)
    .sort((a, b) => a.startNs < b.startNs ? -1 : a.startNs > b.startNs ? 1 : a.otherId.localeCompare(b.otherId));
  const bounds = rangeBounds();
  const rangeBand = bounds
    ? `<div class="range-band" style="left:${timelinePercent(bounds[0])}%;width:${Math.max(0, timelinePercent(bounds[1]) - timelinePercent(bounds[0]))}%"></div>`
    : '<div class="range-band" hidden></div>';
  const segments = spans.map((edge, index) => {
    const key = `relationship:${edge.id}:combined`;
    const other = state.resourceById.get(edge.otherId) || {};
    state.hoverModels.set(key, { type: "relationship", edge, lane: null, otherId: edge.otherId });
    const startBoundary = edge.openStart || edge.startNs === state.viewStartNs
      ? ""
      : `<span class="association-boundary add" style="left:${timelinePercent(edge.startNs)}%"></span>`;
    const endBoundary = edge.openEnd || edge.endNs === state.viewEndNs
      ? ""
      : `<span class="association-boundary remove" style="left:${timelinePercent(edge.endNs)}%"></span>`;
    return `<button class="association-segment ${edge.direction} quality-${safeClass(edge.quality)}${intersectsRange(edge.startNs, edge.endNs) ? " in-range" : ""}" type="button" data-hover-key="${escapeHtml(key)}" data-range-start-ns="${edge.startNs}" data-range-end-ns="${edge.endNs}" style="${barStyle(edge)};--association-row:${index % 3};--association-color:${layerColor(resourceLayer(other, edge.otherId))}"><span>${escapeHtml(resourceLabel(other, edge.otherId))}</span><small>${escapeHtml(titleCase(edge.type))}</small></button>${startBoundary}${endBoundary}`;
  }).join("");
  return `<div class="timeline-row correlation-combined-row" style="grid-template-columns:${LANE_WIDTH}px ${trackWidth}px;--layer-color:var(--violet)">
    <div class="lane-label association-lane-label"><span class="lane-dot" aria-hidden="true"></span><span class="lane-copy"><strong>Correlations</strong><span class="lane-meta"><span class="lane-type">${spans.length} intervals</span></span></span></div>
    <div class="lane-track association-track" data-resource-id="${escapeHtml(state.selectedResourceId)}">${rangeBand}${segments}</div>
  </div>`;
}

function safeClass(value) {
  return String(value || "unknown").toLowerCase().replace(/[^a-z0-9_-]+/g, "-");
}

function barStyle(interval) {
  const left = timelinePercent(interval.startNs);
  const right = timelinePercent(interval.endNs);
  return `left:${left}%;width:${Math.max(0.15, right - left)}%`;
}

function eventMarkClass(mark) {
  if (mark.failure) return "failure";
  const action = String(mark.action).toLowerCase();
  if (["create", "add", "insert"].includes(action)) return "create";
  if (["delete", "remove", "destroy"].includes(action)) return "delete";
  return "modify";
}

function hoverKey(kind, lane, id) {
  return `${kind}:${lane.laneId}:${id}`;
}

function renderRuler() {
  const ruler = byId("timeline-ruler");
  ruler.style.width = `${state.trackWidth}px`;
  ruler.style.minWidth = `${state.trackWidth}px`;
  const ticks = Array.from({ length: 7 }, (_, index) => {
    const ratio = index / 6;
    const timestamp = nsAtRatio(ratio);
    return `<div class="ruler-tick" style="left:${ratio * 100}%"><span>${escapeHtml(formatOffset(timestamp, 1))}</span></div>`;
  }).join("");
  ruler.innerHTML = `${ticks}<span class="timeline-hover-time" hidden aria-hidden="true"></span>`;
}

function eventDensityLane(trackWidth = state.trackWidth) {
  // Histogram resolution follows the zoom scale directly with no independent
  // cap: every 1x of timeline scale contributes another 180 temporal bins.
  const binCount = Math.max(1, Math.round(180 * state.zoom));
  const binCountBigInt = BigInt(binCount);
  const span = state.viewEndNs - state.viewStartNs + 1n;
  const bins = new Map();
  [...state.eventByUid.values()].forEach((event) => {
    const time = eventTime(event);
    if (time < state.viewStartNs || time > state.viewEndNs) return;
    const rawIndex = Number(((time - state.viewStartNs) * binCountBigInt) / span);
    const index = Math.max(0, Math.min(binCount - 1, rawIndex));
    if (!bins.has(index)) bins.set(index, { index, count: 0, failures: 0, events: [] });
    const bin = bins.get(index);
    bin.count += 1;
    if (eventFailed(event)) bin.failures += 1;
    bin.events.push(event);
  });
  const populatedBins = [...bins.values()];
  const maximum = Math.max(1, ...populatedBins.map((bin) => bin.count));
  const binSpan = span / binCountBigInt;
  const bars = populatedBins.map((bin) => {
    const startNs = state.viewStartNs + (span * BigInt(bin.index)) / binCountBigInt;
    const endNs = bin.index === binCount - 1
      ? state.viewEndNs
      : state.viewStartNs + (span * BigInt(bin.index + 1)) / binCountBigInt;
    const key = `density:${bin.index}:${binCount}`;
    const topTypes = new Map();
    bin.events.forEach((event) => {
      const type = event.event_type || event.label || "event";
      topTypes.set(type, (topTypes.get(type) || 0) + 1);
    });
    state.hoverModels.set(key, { type: "density", bin: { ...bin, startNs, endNs, binSpan, topTypes } });
    return `<button class="density-bin${bin.failures ? " has-failures" : ""}${intersectsRange(startNs, endNs) ? " in-range" : ""}" type="button" data-hover-key="${escapeHtml(key)}" data-range-start-ns="${startNs}" data-range-end-ns="${endNs}" style="left:${(bin.index / binCount) * 100}%;width:${100 / binCount}%;--density-height:${Math.max(4, (bin.count / maximum) * 46)}px;--failure-height:${(bin.failures / bin.count) * 100}%" aria-label="${bin.count} events from ${escapeHtml(formatOffset(startNs))} to ${escapeHtml(formatOffset(endNs))}"></button>`;
  }).join("");
  return `<div class="timeline-row density-row" data-density-bin-count="${binCount}" style="grid-template-columns:${LANE_WIDTH}px ${trackWidth}px;--layer-color:var(--cyan)">
    <div class="lane-label density-lane-label"><span class="density-icon" aria-hidden="true"></span><span class="lane-copy"><strong>Event density</strong><span class="lane-meta"><span class="lane-type">${state.eventByUid.size} events</span></span></span></div>
    <div class="lane-track density-track">${bars}</div>
  </div>`;
}

function buildSourceGlyphs(lane) {
  const result = [];
  let group = [];
  const flush = () => {
    if (group.length >= 3) {
      result.push({
        kind: "source-cluster",
        clusterId: "source-cluster:" + lane.laneId + ":" + group[0].sourceRecordUid,
        lane,
        startNs: group[0].timeNs,
        endNs: group.at(-1).timeNs,
        count: group.length,
        recordUids: group.map((mark) => mark.sourceRecordUid),
        items: group,
      });
    } else {
      result.push(...group);
    }
    group = [];
  };
  for (const mark of lane.marks) {
    const prior = group.at(-1);
    const pixelGap = prior
      ? Math.abs(ratioBetween(mark.timeNs) - ratioBetween(prior.timeNs)) * state.trackWidth
      : Number.POSITIVE_INFINITY;
    if (!group.length || (pixelGap <= 10 && group.length < 36)) group.push(mark);
    else {
      flush();
      group.push(mark);
    }
  }
  flush();
  return result;
}

function sourceRecordLanesHtml(trackWidth = state.trackWidth) {
  const bounds = rangeBounds();
  const rangeBand = bounds
    ? `<div class="range-band" style="left:${timelinePercent(bounds[0])}%;width:${Math.max(0, timelinePercent(bounds[1]) - timelinePercent(bounds[0]))}%"></div>`
    : '<div class="range-band" hidden></div>';
  return state.recordLanes.map((lane) => {
    const sourceTypes = lane.sourceTypes.length
      ? lane.sourceTypes.map((sourceType) => sourceTypeDescriptor(sourceType).label).join(", ")
      : "All retained sources";
    const color = lane.sourceTypes.length === 1
      ? sourceTypeDescriptor(lane.sourceTypes[0]).color
      : "#66b8ff";
    const glyphs = buildSourceGlyphs(lane).map((glyph) => {
      if (glyph.kind === "source-cluster") {
        const key = "source-cluster:" + lane.laneId + ":" + glyph.clusterId;
        state.hoverModels.set(key, { type: "source-cluster", cluster: glyph, lane });
        const selected = glyph.recordUids.includes(state.selectedSourceRecordUid);
        const time = glyph.startNs + (glyph.endNs - glyph.startNs) / 2n;
        return `<button class="source-record-mark cluster${selected ? " selected" : ""}${intersectsRange(glyph.startNs, glyph.endNs) ? " in-range" : ""}" data-hover-key="${escapeHtml(key)}" data-source-cluster-id="${escapeHtml(glyph.clusterId)}" data-last-source-record-uid="${escapeHtml(glyph.recordUids.at(-1) || "")}" data-range-start-ns="${glyph.startNs}" data-range-end-ns="${glyph.endNs}" style="left:${timelinePercent(time)}%;--source-color:${escapeHtml(color)}" type="button" aria-label="${glyph.count} collapsed source records"><span>${glyph.count}</span></button>`;
      }
      const key = "source-record:" + lane.laneId + ":" + glyph.sourceRecordUid;
      state.hoverModels.set(key, { type: "source-record", mark: glyph, lane });
      return `<button class="source-record-mark${glyph.matchedEventUid ? " matched" : " unmatched"}${glyph.sourceRecordUid === state.selectedSourceRecordUid ? " selected" : ""}${inSelectedRange(glyph.timeNs) ? " in-range" : ""}" data-source-record-uid="${escapeHtml(glyph.sourceRecordUid)}" data-hover-key="${escapeHtml(key)}" data-time-ns="${glyph.timeNs}" style="left:${timelinePercent(glyph.timeNs)}%;--source-color:${escapeHtml(color)}" type="button" aria-label="${escapeHtml(glyph.recordName + " at " + formatOffset(glyph.timeNs))}"></button>`;
    }).join("");
    const countCopy = lane.truncated
      ? lane.marks.length.toLocaleString() + " of " + lane.recordCount.toLocaleString()
      : lane.recordCount.toLocaleString();
    return `<div class="timeline-row source-record-row" style="grid-template-columns:${LANE_WIDTH}px ${trackWidth}px;--layer-color:${escapeHtml(color)}" data-source-lane-id="${escapeHtml(lane.laneId)}">
      <div class="lane-label source-record-lane-label">
        <span class="source-record-icon" aria-hidden="true"></span>
        <span class="lane-copy" title="${escapeHtml(lane.description || lane.pattern)}"><strong>${escapeHtml(lane.label)}</strong><span class="lane-meta"><span class="lane-type">${escapeHtml(sourceTypes)}</span><span class="lane-separator" aria-hidden="true">·</span><span class="lane-layer">${escapeHtml(countCopy)} records</span></span></span>
      </div>
      <div class="lane-track source-record-track" data-source-lane-id="${escapeHtml(lane.laneId)}">${rangeBand}${glyphs}</div>
    </div>`;
  }).join("");
}

function renderTimeline() {
  const content = byId("timeline-content");
  if (!content) return;
  const regularVisible = visibleTimelineLanes();
  const selectedLane = state.laneByResource.get(state.selectedResourceId);
  const visible = state.correlationTimelineView === "combined" && selectedLane
    ? [{ lane: selectedLane, key: `root:${selectedLane.resourceId}`, depth: 0, parentResourceId: null, relationship: null, hasChildren: relationshipGroupsForResource(selectedLane.resourceId, new Set([selectedLane.resourceId])).length > 0 }]
    : timelineTreeInstances(regularVisible);
  const trackWidth = Math.round(900 * state.zoom);
  state.trackWidth = trackWidth;
  content.style.width = `${LANE_WIDTH + trackWidth}px`;
  content.style.minWidth = `${LANE_WIDTH + trackWidth}px`;
  byId("timeline-frame").querySelector(".timeline-sticky").style.gridTemplateColumns = `${LANE_WIDTH}px ${trackWidth}px`;
  renderRuler();
  state.hoverModels.clear();
  const densityLane = eventDensityLane(trackWidth);
  const sourceLanes = sourceRecordLanesHtml(trackWidth);

  content.innerHTML = densityLane + sourceLanes + visible.map((instance) => {
    const lane = instance.lane;
    const compact = lane.tags.has("compact") || lane.tags.has("connector");
    const kindLabel = humanResourceType(lane.kind);
    const layerLabel = humanLayer(lane.layer);
    const lifecycle = lane.lifecycle.map((interval, index) => {
      const key = hoverKey("life", lane, index);
      state.hoverModels.set(key, { type: "interval", interval, lane });
      return `<button class="lifecycle-bar${interval.openStart ? " open-start" : ""}${interval.openEnd ? " open-end" : ""}${intersectsRange(interval.startNs, interval.endNs) ? " in-range" : ""}" data-hover-key="${escapeHtml(key)}" data-range-start-ns="${interval.startNs}" data-range-end-ns="${interval.endNs}" style="${barStyle(interval)}" type="button" aria-label="Lifecycle ${escapeHtml(formatOffset(interval.startNs))} to ${escapeHtml(formatOffset(interval.endNs))}"></button>`;
    }).join("");
    const statuses = lane.statuses.map((interval, index) => {
      const key = hoverKey("status", lane, index);
      state.hoverModels.set(key, { type: "interval", interval, lane });
      return `<button class="status-segment status-${safeClass(interval.statusClass)}${intersectsRange(interval.startNs, interval.endNs) ? " in-range" : ""}" data-hover-key="${escapeHtml(key)}" data-start-ns="${interval.startNs}" data-end-ns="${interval.endNs}" data-range-start-ns="${interval.startNs}" data-range-end-ns="${interval.endNs}" data-open-end="${interval.openEnd}" style="${barStyle(interval)};--segment-color:${escapeHtml(layerColor(lane.layer))}" type="button"><span>${escapeHtml(interval.status)}</span></button>`;
    }).join("");
    const glyphs = buildClientGlyphs(lane).map((glyph) => {
      if (glyph.kind === "cluster") {
        const key = hoverKey("cluster", lane, glyph.clusterId);
        state.hoverModels.set(key, { type: "cluster", cluster: glyph, lane });
        const selected = glyph.eventUids.includes(state.selectedEventUid);
        const time = glyph.startNs + (glyph.endNs - glyph.startNs) / 2n;
        const latest = [...glyph.items].sort((a, b) => a.timeNs < b.timeNs ? -1 : a.timeNs > b.timeNs ? 1 : 0).at(-1);
        const lastEventUid = latest?.eventUid || glyph.eventUids.at(-1) || "";
        return `<button class="event-mark cluster${glyph.failureCount ? " has-failure" : ""}${selected ? " selected" : ""}${intersectsRange(glyph.startNs, glyph.endNs) ? " in-range" : ""}" data-hover-key="${escapeHtml(key)}" data-cluster-id="${escapeHtml(glyph.clusterId)}" data-last-event-uid="${escapeHtml(lastEventUid)}" data-range-start-ns="${glyph.startNs}" data-range-end-ns="${glyph.endNs}" style="left:${timelinePercent(time)}%;--event-color:${glyph.failureCount ? "#ff6879" : layerColor(lane.layer)}" type="button" aria-label="${glyph.count} collapsed events"><span>${glyph.count}</span></button>`;
      }
      const key = hoverKey("event", lane, glyph.eventUid);
      state.hoverModels.set(key, { type: "event", mark: glyph, lane });
      return `<button class="event-mark ${eventMarkClass(glyph)}${glyph.eventUid === state.selectedEventUid ? " selected" : ""}${inSelectedRange(glyph.timeNs) ? " in-range" : ""}" data-event-uid="${escapeHtml(glyph.eventUid)}" data-hover-key="${escapeHtml(key)}" data-time-ns="${glyph.timeNs}" style="left:${timelinePercent(glyph.timeNs)}%;--event-color:${glyph.failure ? "#ff6879" : layerColor(lane.layer)}" type="button" aria-label="${escapeHtml(`${glyph.label} at ${formatOffset(glyph.timeNs)}`)}"></button>`;
    }).join("");
    const relationshipRibbons = relationshipRibbonsForLane(lane, instance);
    const bounds = rangeBounds();
    const rangeBand = bounds
      ? `<div class="range-band" style="left:${timelinePercent(bounds[0])}%;width:${Math.max(0, timelinePercent(bounds[1]) - timelinePercent(bounds[0]))}%"></div>`
      : '<div class="range-band" hidden></div>';
    const selectedResource = lane.resourceId === state.selectedResourceId;
    const correlatedResource = instance.depth > 0 || (!selectedResource && state.correlatedResourceIds.has(lane.resourceId));
    const expanded = state.correlationTimelineView === "combined"
      ? state.correlationTimelineExpanded
      : state.expandedTimelineTreeKeys.has(instance.key);
    const relationDirection = instance.relationship
      ? (instance.relationship.source === instance.parentResourceId ? "outgoing" : "incoming")
      : null;
    const treeGuides = instance.depth
      ? `<span class="lane-tree-guides" aria-hidden="true">${Array.from({ length: instance.depth }, (_, index) => `<i style="left:${17 + index * 14}px"></i>`).join("")}</span>`
      : "";
    const customIcon = resourceIconMarkup(lane.resource, lane.kind, "lane-resource-icon");
    return `<div class="timeline-row${compact ? " compact" : ""}${selectedResource ? " selected-resource" : ""}${correlatedResource ? " correlated-resource" : ""}${instance.depth ? " tree-child" : " tree-root"}" style="grid-template-columns:${LANE_WIDTH}px ${trackWidth}px;--layer-color:${layerColor(lane.layer)};--tree-indent:${instance.depth * 14}px;--tree-branch:${Math.max(0, instance.depth - 1) * 14 + 17}px" data-resource-id="${escapeHtml(lane.resourceId)}" data-tree-key="${escapeHtml(instance.key)}"${instance.parentResourceId ? ` data-parent-resource-id="${escapeHtml(instance.parentResourceId)}"` : ""}>
      <button class="lane-label" type="button" data-resource-id="${escapeHtml(lane.resourceId)}" data-tree-key="${escapeHtml(instance.key)}" ${instance.hasChildren ? `data-tree-expandable aria-expanded="${expanded}"` : ""}>
        ${treeGuides}
        <span class="lane-tree-toggle" aria-hidden="true"></span>
        ${customIcon || '<span class="lane-dot" aria-hidden="true"></span>'}
        <span class="lane-copy" title="${escapeHtml(`${lane.label} / ${kindLabel} / ${layerLabel}`)}"><strong>${escapeHtml(lane.label)}</strong><span class="lane-meta">${instance.relationship ? `<span class="lane-relation ${relationDirection}">${relationDirection === "outgoing" ? "→" : "←"} ${escapeHtml(titleCase(instance.relationship.type))}</span><span class="lane-separator" aria-hidden="true">·</span>` : ""}<span class="lane-type" title="Resource type: ${escapeHtml(kindLabel)}">${escapeHtml(kindLabel)}</span><span class="lane-separator" aria-hidden="true">·</span><span class="lane-layer">${escapeHtml(layerLabel)}</span></span></span>
        ${compact ? '<span class="compact-tag">connector</span>' : ""}
      </button>
      <div class="lane-track" data-resource-id="${escapeHtml(lane.resourceId)}">${rangeBand}${lifecycle}${statuses}${relationshipRibbons}${glyphs}</div>
    </div>`;
  }).join("") + combinedAssociationLane(trackWidth);

  if (!visible.length) {
    content.innerHTML = `${densityLane}${sourceLanes}<div class="timeline-empty" style="width:${LANE_WIDTH + trackWidth}px"><strong>No resource lanes selected</strong><span>Source-record lanes remain visible. Open Lanes to add resource timelines.</span></div>`;
  }

  const cursor = document.createElement("div");
  cursor.className = "timeline-cursor-line";
  cursor.style.left = `${LANE_WIDTH + ratioBetween(state.cursorNs) * state.trackWidth}px`;
  content.appendChild(cursor);
  const hoverLine = document.createElement("div");
  hoverLine.className = "timeline-hover-line";
  hoverLine.hidden = true;
  hoverLine.setAttribute("aria-hidden", "true");
  content.appendChild(hoverLine);
  bindTimelineInteractions();
  updateCursorVisual();
  updateRangeBands(rangeBounds(), false);
  if (visible.length && state.hoverGuideNs !== null) {
    showTimelineHoverAt(state.hoverGuideNs, state.hoverGuideClientX);
  }
  renderLanePicker();
  window.requestAnimationFrame(drawTimelineCorrelationOverlay);
}

function pointNsFromClientX(clientX, track) {
  const rect = track.getBoundingClientRect();
  return nsAtRatio((clientX - rect.left) / Math.max(1, rect.width));
}

function hideTimelineHoverLine() {
  state.hoverGuideNs = null;
  state.hoverGuideClientX = null;
  const line = document.querySelector(".timeline-hover-line");
  if (line) line.hidden = true;
  const timeLabel = byId("timeline-ruler")?.querySelector(".timeline-hover-time");
  if (timeLabel) timeLabel.hidden = true;
}

function showTimelineHoverAt(timeNs, clientX) {
  state.hoverGuideNs = timeNs;
  state.hoverGuideClientX = clientX;
  const content = byId("timeline-content");
  const line = content.querySelector(".timeline-hover-line");
  if (!line) return;
  line.style.left = `${LANE_WIDTH + ratioBetween(timeNs) * state.trackWidth}px`;
  line.dataset.timeNs = timeNs.toString();
  line.dataset.timeLabel = formatOffset(timeNs);
  const timeLabel = byId("timeline-ruler")?.querySelector(".timeline-hover-time");
  const scroll = byId("timeline-scroll");
  if (timeLabel) {
    timeLabel.textContent = line.dataset.timeLabel;
    timeLabel.style.left = `${ratioBetween(timeNs) * state.trackWidth}px`;
    timeLabel.dataset.labelAlign = "center";
    timeLabel.hidden = false;
  }
  const scrollRect = scroll.getBoundingClientRect();
  const labelAlign = scrollRect.right - clientX < 58
    ? "left"
    : clientX - scrollRect.left < 58 ? "right" : "center";
  if (timeLabel) timeLabel.dataset.labelAlign = labelAlign;
  line.hidden = false;
}

function updateTimelineHoverFromPointer(event) {
  const track = event.target.closest(".lane-track");
  const content = byId("timeline-content");
  if (state.brush || event.buttons !== 0 || !track || !content.contains(track)) {
    hideTimelineHoverLine();
    return;
  }
  showTimelineHoverAt(pointNsFromClientX(event.clientX, track), event.clientX);
}

function bindTimelineInteractions() {
  document.querySelectorAll(".lane-label[data-resource-id]").forEach((button) => {
    button.addEventListener("click", (event) => {
      if (event.ctrlKey || event.metaKey) {
        selectResource(button.dataset.resourceId);
        return;
      }
      if (!button.hasAttribute("data-tree-expandable")) return;
      if (state.correlationTimelineView === "combined") {
        state.correlationTimelineExpanded = !state.correlationTimelineExpanded;
      } else if (state.expandedTimelineTreeKeys.has(button.dataset.treeKey)) {
        state.expandedTimelineTreeKeys.delete(button.dataset.treeKey);
      } else {
        state.expandedTimelineTreeKeys.add(button.dataset.treeKey);
      }
      rerenderTimelinePreservingScroll();
    });
  });
  document.querySelectorAll(".event-mark[data-event-uid]").forEach((mark) => {
    mark.addEventListener("click", (event) => {
      event.stopPropagation();
      if (performance.now() < state.suppressTimelineClickUntil) return;
      const eventUid = mark.dataset.eventUid;
      const key = mark.dataset.hoverKey;
      const resourceId = mark.closest(".lane-track")?.dataset.resourceId || null;
      if (event.ctrlKey || event.metaKey) {
        event.preventDefault();
        jumpToNormalizedLog(eventUid, resourceId);
        return;
      }
      selectEvent(eventUid, true, resourceId);
      const replacement = [...document.querySelectorAll(".event-mark[data-event-uid]")]
        .find((item) => item.dataset.eventUid === eventUid && item.closest(".lane-track")?.dataset.resourceId === resourceId);
      showHover(key, replacement || mark, true);
    });
  });
  document.querySelectorAll(".event-mark[data-cluster-id]").forEach((mark) => {
    mark.addEventListener("click", (event) => {
      event.stopPropagation();
      if (performance.now() < state.suppressTimelineClickUntil) return;
      if ((event.ctrlKey || event.metaKey) && mark.dataset.lastEventUid) {
        event.preventDefault();
        jumpToNormalizedLog(mark.dataset.lastEventUid, mark.closest(".lane-track")?.dataset.resourceId || null);
        return;
      }
      showHover(mark.dataset.hoverKey, mark, true);
    });
  });
  document.querySelectorAll(".source-record-mark[data-source-record-uid]").forEach((mark) => {
    mark.addEventListener("click", (event) => {
      event.stopPropagation();
      if (performance.now() < state.suppressTimelineClickUntil) return;
      const recordUid = mark.dataset.sourceRecordUid;
      if (event.ctrlKey || event.metaKey) {
        event.preventDefault();
        jumpToSourceLog(recordUid);
        return;
      }
      selectSourceRecord(recordUid, true);
      showHover(mark.dataset.hoverKey, mark, true);
    });
  });
  document.querySelectorAll(".source-record-mark[data-source-cluster-id]").forEach((mark) => {
    mark.addEventListener("click", (event) => {
      event.stopPropagation();
      if (performance.now() < state.suppressTimelineClickUntil) return;
      if ((event.ctrlKey || event.metaKey) && mark.dataset.lastSourceRecordUid) {
        event.preventDefault();
        jumpToSourceLog(mark.dataset.lastSourceRecordUid);
        return;
      }
      showHover(mark.dataset.hoverKey, mark, true);
    });
  });
  document.querySelectorAll("[data-hover-key]").forEach((element) => bindHoverTarget(element));
}

function timelinePointerDown(event) {
  hideTimelineHoverLine();
  if (state.brush || event.button !== 0) return;
  const content = byId("timeline-content");
  const handle = event.target.closest("[data-range-handle]");
  const track = event.target.closest(".lane-track");
  if ((!track && !handle) || !content.contains(track || handle)) return;
  const mark = event.target.closest(".event-mark, .source-record-mark");
  if ((event.ctrlKey || event.metaKey) && mark) {
    const eventUid = mark.dataset.eventUid || mark.dataset.lastEventUid;
    const sourceRecordId = mark.dataset.sourceRecordUid || mark.dataset.lastSourceRecordUid;
    if (eventUid) {
      state.suppressTimelineClickUntil = performance.now() + 500;
      event.preventDefault();
      event.stopPropagation();
      jumpToNormalizedLog(eventUid, track?.dataset.resourceId || null);
      return;
    }
    if (sourceRecordId) {
      state.suppressTimelineClickUntil = performance.now() + 500;
      event.preventDefault();
      event.stopPropagation();
      jumpToSourceLog(sourceRecordId);
      return;
    }
  }
  const wantsRange = Boolean(handle) || event.shiftKey || state.rangeMode;
  const anchorNs = handle
    ? (handle.dataset.rangeHandle === "start" ? rangeBounds()[0] : rangeBounds()[1])
    : pointNsFromClientX(event.clientX, track);
  state.brush = {
    pointerId: event.pointerId,
    track,
    mode: handle ? "handle" : wantsRange ? "range" : "pending",
    boundary: handle?.dataset.rangeHandle || null,
    anchorNs,
    latestNs: anchorNs,
    startX: event.clientX,
    latestX: event.clientX,
    frameId: null,
    autoScrollFrameId: null,
    autoScrollVelocity: 0,
    startScrollLeft: byId("timeline-scroll").scrollLeft,
    priorRange: state.rangeStartNs === null ? null : [state.rangeStartNs, state.rangeEndNs],
    priorSummary: state.rangeSummary,
    target: mark ? {
      eventUid: mark.dataset.eventUid || null,
      clusterId: mark.dataset.clusterId || null,
      hoverKey: mark.dataset.hoverKey || null,
      resourceId: mark.closest(".lane-track")?.dataset.resourceId || null,
      sourceRecordUid: mark.dataset.sourceRecordUid || null,
      sourceClusterId: mark.dataset.sourceClusterId || null,
      element: mark,
    } : null,
  };
  if (wantsRange) {
    if (!handle) state.rangeStartNs = state.rangeEndNs = anchorNs;
    byId("timeline-frame").classList.add("is-brushing");
    updateRangePreview();
  }
  try { content.setPointerCapture(event.pointerId); } catch (_error) { /* Capture can race a cancelled pointer. */ }
  if (wantsRange) event.preventDefault();
}

function rangeMinimumNs() {
  const pixel = (state.viewEndNs - state.viewStartNs) / BigInt(Math.max(1, state.trackWidth));
  return pixel > 0n ? pixel : 1n;
}

function applyHandlePosition(brush) {
  const bounds = rangeBounds();
  if (!bounds) return;
  const minimum = rangeMinimumNs();
  if (brush.boundary === "start") {
    const latest = clampNs(brush.latestNs);
    state.rangeStartNs = latest > bounds[1] - minimum ? bounds[1] - minimum : latest;
    state.rangeEndNs = bounds[1];
  } else {
    const latest = clampNs(brush.latestNs);
    state.rangeStartNs = bounds[0];
    state.rangeEndNs = latest < bounds[0] + minimum ? bounds[0] + minimum : latest;
  }
  state.rangeStartNs = clampNs(state.rangeStartNs);
  state.rangeEndNs = clampNs(state.rangeEndNs);
}

function scheduleBrushFrame() {
  const brush = state.brush;
  if (!brush || brush.frameId !== null) return;
  brush.frameId = window.requestAnimationFrame(() => {
    if (!state.brush) return;
    state.brush.frameId = null;
    if (state.brush.mode === "range") {
      state.rangeStartNs = state.brush.anchorNs;
      state.rangeEndNs = state.brush.latestNs;
    } else if (state.brush.mode === "handle") applyHandlePosition(state.brush);
    else return;
    updateRangePreview();
  });
}

function brushNsFromClientX(brush, clientX) {
  if (brush.mode === "handle") {
    const scrollDelta = byId("timeline-scroll").scrollLeft - brush.startScrollLeft;
    const pixelDelta = clientX - brush.startX + scrollDelta;
    const scaledDelta = BigInt(Math.round(pixelDelta / Math.max(1, state.trackWidth) * 1_000_000));
    return clampNs(brush.anchorNs + ((state.viewEndNs - state.viewStartNs) * scaledDelta) / 1_000_000n);
  }
  return brush.track
    ? pointNsFromClientX(clientX, brush.track)
    : nsAtRatio((clientX - (byId("timeline-content").getBoundingClientRect().left + LANE_WIDTH)) / Math.max(1, state.trackWidth));
}

function stopBrushAutoScroll(brush) {
  if (brush?.autoScrollFrameId !== null) window.cancelAnimationFrame(brush.autoScrollFrameId);
  if (brush) {
    brush.autoScrollFrameId = null;
    brush.autoScrollVelocity = 0;
  }
}

function runBrushAutoScroll() {
  const brush = state.brush;
  if (!brush || !brush.autoScrollVelocity || !["range", "handle"].includes(brush.mode)) return;
  const scroll = byId("timeline-scroll");
  const before = scroll.scrollLeft;
  scroll.scrollLeft = Math.max(0, Math.min(scroll.scrollWidth - scroll.clientWidth, before + brush.autoScrollVelocity));
  if (scroll.scrollLeft === before) {
    stopBrushAutoScroll(brush);
    return;
  }
  brush.latestNs = brushNsFromClientX(brush, brush.latestX);
  scheduleBrushFrame();
  brush.autoScrollFrameId = window.requestAnimationFrame(runBrushAutoScroll);
}

function updateBrushAutoScroll(brush) {
  const scroll = byId("timeline-scroll");
  const rect = scroll.getBoundingClientRect();
  const edge = Math.min(32, rect.width / 4);
  const leftDepth = Math.max(0, rect.left + edge - brush.latestX);
  const rightDepth = Math.max(0, brush.latestX - (rect.right - edge));
  const direction = leftDepth > 0 ? -1 : rightDepth > 0 ? 1 : 0;
  const depth = Math.max(leftDepth, rightDepth);
  brush.autoScrollVelocity = direction * Math.max(2, Math.ceil(18 * Math.min(1, depth / edge)));
  if (!direction) {
    stopBrushAutoScroll(brush);
    return;
  }
  if (brush.autoScrollFrameId === null) brush.autoScrollFrameId = window.requestAnimationFrame(runBrushAutoScroll);
}

function timelinePointerMove(event) {
  const brush = state.brush;
  if (!brush) {
    updateTimelineHoverFromPointer(event);
    return;
  }
  hideTimelineHoverLine();
  if (event.pointerId !== brush.pointerId) return;
  brush.latestX = event.clientX;
  brush.latestNs = brushNsFromClientX(brush, event.clientX);
  if (brush.mode === "pending" && Math.abs(brush.latestX - brush.startX) >= 4) {
    brush.mode = "range";
    state.rangeStartNs = brush.anchorNs;
    state.rangeEndNs = brush.latestNs;
    state.suppressTimelineClickUntil = performance.now() + 400;
    byId("timeline-frame").classList.add("is-brushing");
  }
  if (brush.mode === "range" || brush.mode === "handle") {
    updateBrushAutoScroll(brush);
    scheduleBrushFrame();
    if (event.cancelable) event.preventDefault();
  }
}

function activateShortGestureTarget(target) {
  if (!target) return false;
  state.suppressTimelineClickUntil = performance.now() + 400;
  if (target.eventUid) {
    selectEvent(target.eventUid, true, target.resourceId);
    const replacement = [...document.querySelectorAll(".event-mark[data-event-uid]")]
      .find((item) => item.dataset.eventUid === target.eventUid && item.closest(".lane-track")?.dataset.resourceId === target.resourceId);
    showHover(target.hoverKey, replacement || target.element, true);
    return true;
  }
  if (target.clusterId) {
    const replacement = [...document.querySelectorAll(".event-mark[data-cluster-id]")]
      .find((item) => item.dataset.clusterId === target.clusterId && item.closest(".lane-track")?.dataset.resourceId === target.resourceId);
    showHover(target.hoverKey, replacement || target.element, true);
    return true;
  }
  if (target.sourceRecordUid) {
    selectSourceRecord(target.sourceRecordUid, true);
    const replacement = [...document.querySelectorAll(".source-record-mark[data-source-record-uid]")]
      .find((item) => item.dataset.sourceRecordUid === target.sourceRecordUid);
    showHover(target.hoverKey, replacement || target.element, true);
    return true;
  }
  if (target.sourceClusterId) {
    const replacement = [...document.querySelectorAll(".source-record-mark[data-source-cluster-id]")]
      .find((item) => item.dataset.sourceClusterId === target.sourceClusterId);
    showHover(target.hoverKey, replacement || target.element, true);
    return true;
  }
  return false;
}

function finishTimelinePointer(event, cancelled = false) {
  const brush = state.brush;
  if (!brush || (event?.pointerId !== undefined && event.pointerId !== brush.pointerId)) return;
  if (brush.frameId !== null) window.cancelAnimationFrame(brush.frameId);
  if (!cancelled && event?.clientX !== undefined) {
    brush.latestX = event.clientX;
    brush.latestNs = brushNsFromClientX(brush, event.clientX);
  }
  stopBrushAutoScroll(brush);
  state.brush = null;
  const content = byId("timeline-content");
  try {
    if (content.hasPointerCapture(brush.pointerId)) content.releasePointerCapture(brush.pointerId);
  } catch (_error) { /* The browser may already have released it. */ }
  byId("timeline-frame").classList.remove("is-brushing");

  if (cancelled) {
    if (brush.target) state.suppressTimelineClickUntil = performance.now() + 120;
    if (brush.priorRange) [state.rangeStartNs, state.rangeEndNs] = brush.priorRange;
    else state.rangeStartNs = state.rangeEndNs = null;
    state.rangeSummary = brush.priorSummary;
    updateRangeBands();
    syncRangeInputs();
    renderRangeSummary();
    return;
  }

  const moved = Math.abs(brush.latestX - brush.startX);
  if (brush.mode === "pending" && moved < 4) {
    if (!activateShortGestureTarget(brush.target)) setCursor(brush.latestNs);
    showTimelineHoverAt(brush.latestNs, brush.latestX);
    return;
  }

  if (brush.mode === "handle" && moved < 1) {
    [state.rangeStartNs, state.rangeEndNs] = brush.priorRange;
    state.rangeSummary = brush.priorSummary;
    updateRangeBands();
    syncRangeInputs();
    renderRangeSummary();
    return;
  }

  if (brush.mode === "pending") brush.mode = "range";
  if (brush.mode === "range") {
    state.rangeStartNs = brush.anchorNs;
    state.rangeEndNs = brush.latestNs;
  } else if (brush.mode === "handle") applyHandlePosition(brush);
  if ((brush.mode === "range" && moved < 4) || state.rangeStartNs === state.rangeEndNs) {
    const width = rangeMinimumNs();
    if (state.rangeStartNs + width <= state.viewEndNs) state.rangeEndNs = state.rangeStartNs + width;
    else state.rangeStartNs = state.rangeEndNs - width < state.viewStartNs ? state.viewStartNs : state.rangeEndNs - width;
  }
  const bounds = rangeBounds();
  [state.rangeStartNs, state.rangeEndNs] = bounds;
  state.rangeSummary = null;
  state.suppressTimelineClickUntil = performance.now() + 400;
  byId("clear-range").hidden = false;
  updateRangeBands();
  syncRangeInputs();
  requestRangeSummary();
}

function updateRangePreview() {
  updateRangeBands();
  syncRangeInputs();
  const bounds = rangeBounds();
  if (!bounds) return;
  byId("range-title").textContent = `${formatOffset(bounds[0])} to ${formatOffset(bounds[1])} / ${formatDuration(bounds[1] - bounds[0])}`;
  byId("range-facts").innerHTML = "<span>Release to summarize events and changes</span>";
  byId("range-diff").innerHTML = "<span>Range preview</span>";
}

function applyRangeHighlight(bounds) {
  const frame = byId("timeline-frame");
  frame.classList.toggle("has-range", Boolean(bounds));
  document.querySelectorAll(".event-mark[data-time-ns]").forEach((mark) => {
    const hit = Boolean(bounds) && toNs(mark.dataset.timeNs) >= bounds[0] && toNs(mark.dataset.timeNs) <= bounds[1];
    mark.classList.toggle("in-range", hit);
    mark.classList.toggle("out-of-range", Boolean(bounds) && !hit);
  });
  document.querySelectorAll("[data-range-start-ns][data-range-end-ns]").forEach((element) => {
    const hit = Boolean(bounds) && toNs(element.dataset.rangeStartNs) <= bounds[1] && toNs(element.dataset.rangeEndNs) >= bounds[0];
    element.classList.toggle("in-range", hit);
    element.classList.toggle("out-of-range", Boolean(bounds) && !hit);
  });
}

function updateRangeHandles(bounds) {
  const content = byId("timeline-content");
  const existing = new Map([...content.querySelectorAll(".range-boundary-handle")]
    .map((handle) => [handle.dataset.rangeHandle, handle]));
  if (!bounds) {
    existing.forEach((handle) => handle.remove());
    return;
  }
  const labels = [
    ["start", bounds[0], `Range start ${formatOffset(bounds[0])}`],
    ["end", bounds[1], `Range end ${formatOffset(bounds[1])}`],
  ];
  for (const [boundary, value, label] of labels) {
    let handle = existing.get(boundary);
    if (!handle) {
      handle = document.createElement("button");
      handle.type = "button";
      handle.className = `range-boundary-handle ${boundary}`;
      handle.dataset.rangeHandle = boundary;
      handle.innerHTML = `<span>${boundary === "start" ? "Start" : "End"}</span>`;
      content.appendChild(handle);
    }
    handle.style.left = `${LANE_WIDTH + ratioBetween(value) * state.trackWidth}px`;
    handle.style.height = `${Math.max(content.scrollHeight, 44)}px`;
    handle.setAttribute("role", "slider");
    handle.setAttribute("aria-label", label);
    handle.setAttribute("aria-valuemin", "0");
    handle.setAttribute("aria-valuemax", "1000000");
    handle.setAttribute("aria-valuenow", String(Math.round(ratioBetween(value) * 1_000_000)));
    handle.setAttribute("aria-valuetext", `${formatOffset(value)} from timeline start`);
    existing.delete(boundary);
  }
  existing.forEach((handle) => handle.remove());
}

function timelineHandleKeyDown(event) {
  const handle = event.target.closest("[data-range-handle]");
  if (!handle || !rangeBounds()) return;
  const direction = event.key === "ArrowLeft" || event.key === "ArrowDown" ? -1n
    : event.key === "ArrowRight" || event.key === "ArrowUp" ? 1n
      : null;
  if (direction === null && !["Home", "End"].includes(event.key)) return;
  event.preventDefault();
  const bounds = rangeBounds();
  const minimum = rangeMinimumNs();
  const step = minimum * (event.shiftKey ? 10n : 1n);
  if (handle.dataset.rangeHandle === "start") {
    const requested = event.key === "Home" ? state.viewStartNs
      : event.key === "End" ? bounds[1] - minimum
        : bounds[0] + direction * step;
    state.rangeStartNs = requested < state.viewStartNs ? state.viewStartNs : requested > bounds[1] - minimum ? bounds[1] - minimum : requested;
    state.rangeEndNs = bounds[1];
  } else {
    const requested = event.key === "End" ? state.viewEndNs
      : event.key === "Home" ? bounds[0] + minimum
        : bounds[1] + direction * step;
    state.rangeStartNs = bounds[0];
    state.rangeEndNs = requested > state.viewEndNs ? state.viewEndNs : requested < bounds[0] + minimum ? bounds[0] + minimum : requested;
  }
  state.rangeSummary = null;
  updateRangeBands();
  syncRangeInputs();
  requestRangeSummary();
}

function updateRangeBands(bounds = rangeBounds(), refreshEventLog = true) {
  document.querySelectorAll(".range-band").forEach((band) => {
    band.hidden = !bounds;
    if (!bounds) return;
    band.style.left = `${timelinePercent(bounds[0])}%`;
    band.style.width = `${Math.max(0, timelinePercent(bounds[1]) - timelinePercent(bounds[0]))}%`;
  });
  applyRangeHighlight(bounds);
  updateRangeHandles(bounds);
  if (refreshEventLog && !state.brush && state.dataset && byId("event-table-body")) {
    renderEventTable({ resetScroll: Boolean(bounds) });
  }
}

function updateCursorVisual() {
  const line = document.querySelector(".timeline-cursor-line");
  if (line) {
    line.style.left = `${LANE_WIDTH + ratioBetween(state.cursorNs) * state.trackWidth}px`;
    line.hidden = !state.cursorSelected;
  }
  const slider = byId("time-cursor");
  if (slider) slider.value = String(Math.round(ratioBetween(state.cursorNs) * 1_000_000));
  if (byId("cursor-time")) byId("cursor-time").textContent = !state.cursorSelected
    ? "capture (default)"
    : state.cursorNs === state.viewEndNs ? "capture" : formatOffset(state.cursorNs);
  document.querySelectorAll(".status-segment[data-start-ns]").forEach((segment) => {
    const active = state.cursorNs >= toNs(segment.dataset.startNs)
      && (state.cursorNs < toNs(segment.dataset.endNs) || (segment.dataset.openEnd === "true" && state.cursorNs === toNs(segment.dataset.endNs)));
    segment.classList.toggle("current", active);
  });
}

function setCursor(value, schedule = true, selected = true) {
  state.cursorNs = clampNs(value);
  state.cursorSelected = selected;
  updateCursorVisual();
  renderResourceTables();
  if (schedule) scheduleTemporalRefresh();
}

function graphDisplayTimeNs(graph = state.graph) {
  if (graph?.time_ns !== null && graph?.time_ns !== undefined) {
    return toNs(graph.time_ns, state.graphTimeNs ?? state.cursorNs);
  }
  return state.graphTimeNs ?? state.cursorNs;
}

function renderCorrelationTimeState() {
  const chip = byId("correlation-time");
  const panel = byId("dependency-graph");
  const stage = byId("graph-stage");
  if (!chip || !panel || !stage) return;
  const shownTimeNs = graphDisplayTimeNs();
  const requestedTimeNs = state.graphRequestedTimeNs ?? state.cursorNs;
  const stale = !state.graphPending && state.graphTimeNs !== null && shownTimeNs !== state.cursorNs;
  chip.classList.toggle("pending", state.graphPending);
  chip.classList.toggle("stale", stale);
  chip.textContent = state.graphPending
    ? `Updating to ${formatOffset(requestedTimeNs)}…`
    : `${stale ? "Showing" : "Selected moment"} · ${formatOffset(shownTimeNs)}`;
  panel.classList.toggle("is-time-pending", state.graphPending);
  stage.setAttribute("aria-busy", String(state.graphPending));
}

function markCorrelationPending(timestampNs = state.cursorNs) {
  state.graphRequestedTimeNs = clampNs(timestampNs);
  state.graphPending = true;
  closeCorrelationHover();
  renderCorrelationTimeState();
}

function scheduleTemporalRefresh() {
  window.clearTimeout(state.temporalTimer);
  markCorrelationPending(state.cursorNs);
  state.temporalTimer = window.setTimeout(() => {
    requestGraph();
    requestResources();
  }, 100);
}

function eventOrMark(uid) {
  const event = state.eventByUid.get(uid);
  if (event) return event;
  for (const lane of state.lanes) {
    const mark = lane.marks.find((item) => item.eventUid === uid);
    if (mark) return mark.event;
  }
  return null;
}

function selectEvent(eventUid, moveCursor = false, resourceId = null) {
  const event = eventOrMark(eventUid);
  if (!event) return;
  const eventResourceId = resourceId || eventResourceRefs(event)[0] || null;
  const focusResourceId = resourceId || (moveCursor ? eventResourceId : null);
  state.selectedEventUid = eventUid;
  state.selectedSourceRecordUid = null;
  state.selectedEventResourceId = eventResourceId;
  if (focusResourceId) {
    const focusChanged = state.selectedResourceId !== focusResourceId;
    state.selectedResourceId = focusResourceId;
    const record = state.resourceQuery?.items?.find((item) => item.resource_id === focusResourceId)
      || state.resourceById.get(focusResourceId);
    if (record) state.selectedResourceKind = record.kind || resourceKind(record, focusResourceId);
    if (focusChanged) {
      state.activeCorrelationEdges = [];
      state.correlatedResourceIds.clear();
    }
    if (isScaleMode() && !state.laneByResource.has(focusResourceId)) {
      state.laneMode = "custom";
      if (state.explicitLaneIds.size >= MAX_SCALE_TIMELINE_LANES) state.explicitLaneIds.delete(state.explicitLaneIds.values().next().value);
      state.explicitLaneIds.add(focusResourceId);
      refreshScaleTimeline();
    }
  }
  renderEventInspector(event);
  if (moveCursor) setCursor(eventTime(event));
  renderTimeline();
  renderEventTable();
  if (focusResourceId && !moveCursor) requestGraph();
}

function selectSourceRecord(recordUid, moveCursor = false) {
  const record = state.sourceRecordByUid.get(String(recordUid));
  if (!record) return;
  state.selectedSourceRecordUid = String(recordUid);
  state.selectedEventUid = null;
  state.selectedEventResourceId = null;
  renderSourceRecordInspector(record);
  if (moveCursor) setCursor(sourceRecordTime(record));
  renderTimeline();
  renderEventTable();
}

function navigationPulse(element) {
  if (!element) return;
  element.classList.remove("navigation-target");
  void element.offsetWidth;
  element.classList.add("navigation-target");
  window.setTimeout(() => element.classList.remove("navigation-target"), 1800);
}

function syncCorrelationTimelineButtons() {
  document.querySelectorAll("[data-correlation-view]").forEach((button) => {
    button.setAttribute("aria-pressed", String(button.dataset.correlationView === state.correlationTimelineView));
  });
}

function jumpToNormalizedLog(eventUid, resourceId = null) {
  const event = eventOrMark(eventUid);
  if (!event) return;
  byId("event-layer-filter").value = "";
  byId("event-search").value = "";
  selectEvent(eventUid, true, resourceId);
  jumpToLogEntry(normalizedLogEntryId(eventUid));
}

function jumpToSourceLog(recordUid) {
  const record = state.sourceRecordByUid.get(String(recordUid));
  if (!record) return;
  byId("event-layer-filter").value = "";
  byId("event-search").value = "";
  selectSourceRecord(recordUid, true);
  if (isCtfSourceRecord(record)) state.eventLogInclude.ctf = true;
  else state.eventLogInclude.external = true;
  syncEventLogIncludeControls();
  jumpToLogEntry(sourceLogEntryId(recordUid));
}

function sourceRecordLaneFor(recordUid) {
  return state.recordLanes.find((lane) => lane.marks.some((mark) => mark.sourceRecordUid === String(recordUid))) || null;
}

function regexEscape(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

async function ensureSourceRecordLane(record) {
  const uid = sourceRecordUid(record);
  let lane = sourceRecordLaneFor(uid);
  if (lane) return lane;
  if (state.recordLaneRules.length >= MAX_RECORD_LANES) {
    showToast("Remove a source-record lane before adding a jump lane.");
    return null;
  }
  const laneId = "jump-record-" + (++state.customRecordLaneSequence);
  state.recordLaneRules.push({
    lane_id: laneId,
    label: "Jump target · " + String(record.record_name || uid).slice(0, 72),
    pattern: regexEscape(uid),
    source_types: [String(record.source_type || "unknown")],
    unmatched_only: false,
    case_sensitive: true,
    plugin_defined: false,
    transient: true,
  });
  await requestTimeline();
  renderTimeline();
  renderLanePicker();
  lane = sourceRecordLaneFor(uid);
  return lane;
}

async function jumpSourceRecordToTimeline(recordUid) {
  const record = state.sourceRecordByUid.get(String(recordUid));
  if (!record) return;
  if (record.matched_event_uid && eventOrMark(String(record.matched_event_uid))) {
    await jumpToTimelineEvent(String(record.matched_event_uid));
    return;
  }
  const lane = await ensureSourceRecordLane(record);
  if (!lane) return;
  selectSourceRecord(recordUid, true);
  window.requestAnimationFrame(() => {
    const target = [...document.querySelectorAll(".source-record-mark[data-source-record-uid]")]
      .find((item) => item.dataset.sourceRecordUid === String(recordUid));
    const clusterModel = [...state.hoverModels.values()].find((model) => model.type === "source-cluster"
      && model.cluster.recordUids.includes(String(recordUid)));
    const clusterTarget = clusterModel
      ? [...document.querySelectorAll(".source-record-mark[data-source-cluster-id]")]
        .find((item) => item.dataset.sourceClusterId === clusterModel.cluster.clusterId)
      : null;
    const laneRow = document.querySelector('.timeline-row[data-source-lane-id="' + CSS.escape(lane.laneId) + '"]');
    const destination = target || clusterTarget || laneRow;
    if (!destination) return;
    destination.scrollIntoView({ behavior: "smooth", block: "center", inline: "center" });
    if (target || clusterTarget) destination.focus({ preventScroll: true });
    navigationPulse(destination);
  });
}

function eventLaneFor(eventUid) {
  return state.lanes.find((lane) => lane.marks.some((mark) => mark.eventUid === eventUid)) || null;
}

async function jumpToTimelineEvent(eventUid) {
  const event = eventOrMark(eventUid);
  if (!event) return;
  let lane = eventLaneFor(eventUid);
  const resourceId = lane?.resourceId || eventResourceRefs(event)[0] || null;
  if (isScaleMode() && resourceId && !lane) {
    state.laneMode = "custom";
    if (state.explicitLaneIds.size >= MAX_SCALE_TIMELINE_LANES) state.explicitLaneIds.delete(state.explicitLaneIds.values().next().value);
    state.explicitLaneIds.add(resourceId);
    await refreshScaleTimeline();
    lane = eventLaneFor(eventUid) || state.laneByResource.get(resourceId);
  }
  if (lane) {
    state.activeLayers.add(lane.layer);
    if (!laneSelectedByMode(lane.resourceId)) {
      if (state.laneMode !== "custom") state.explicitLaneIds = currentModeLaneIds();
      state.laneMode = "custom";
      state.explicitLaneIds.add(lane.resourceId);
    }
  }
  renderLayerToggles();
  selectEvent(eventUid, true, resourceId);
  window.requestAnimationFrame(() => {
    const mark = [...document.querySelectorAll(".event-mark[data-event-uid]")]
      .find((item) => item.dataset.eventUid === eventUid
        && (!resourceId || item.closest(".lane-track")?.dataset.resourceId === resourceId));
    const clusterModel = [...state.hoverModels.values()].find((model) => model.type === "cluster"
      && model.cluster.eventUids.includes(eventUid)
      && (!resourceId || model.lane?.resourceId === resourceId));
    const clusterMark = clusterModel
      ? [...document.querySelectorAll(".event-mark[data-cluster-id]")]
        .find((item) => item.dataset.clusterId === clusterModel.cluster.clusterId
          && (!resourceId || item.closest(".lane-track")?.dataset.resourceId === resourceId))
      : null;
    const eventTarget = mark || clusterMark;
    const row = resourceId
      ? [...document.querySelectorAll(".timeline-row[data-resource-id]")].find((item) => item.dataset.resourceId === resourceId)
      : null;
    const target = eventTarget || row;
    if (!target) return;
    target.scrollIntoView({ behavior: "smooth", block: "center", inline: "center" });
    if (eventTarget) eventTarget.focus({ preventScroll: true });
    navigationPulse(eventTarget || row);
  });
}

async function jumpToTimelineResource(resourceId) {
  if (!resourceId) return;
  if (isScaleMode() && !state.laneByResource.has(resourceId)) {
    state.laneMode = "custom";
    if (state.explicitLaneIds.size >= MAX_SCALE_TIMELINE_LANES) state.explicitLaneIds.delete(state.explicitLaneIds.values().next().value);
    state.explicitLaneIds.add(resourceId);
    await refreshScaleTimeline();
  }
  const lane = state.laneByResource.get(resourceId);
  if (lane) state.activeLayers.add(lane.layer);
  if (state.correlationTimelineView === "separate" && !laneSelectedByMode(resourceId)) {
    if (state.laneMode !== "custom") state.explicitLaneIds = currentModeLaneIds();
    state.laneMode = "custom";
    state.explicitLaneIds.add(resourceId);
  }
  renderLayerToggles();
  selectResource(resourceId);
  window.requestAnimationFrame(() => {
    const row = [...document.querySelectorAll(".timeline-row[data-resource-id]")]
      .find((item) => item.dataset.resourceId === resourceId);
    if (!row) return;
    row.scrollIntoView({ behavior: "smooth", block: "center", inline: "nearest" });
    row.querySelector(".lane-label")?.focus({ preventScroll: true });
    navigationPulse(row);
  });
}

function renderEventInspector(event) {
  const subject = eventSubject(event);
  const properties = event.attributes?.properties || event.properties || {};
  const result = event.attributes?.result || event.result || {};
  const uid = event.event_uid || event.event_id;
  const mark = state.lanes.flatMap((lane) => lane.marks)
    .find((item) => item.eventUid === uid && (!state.selectedEventResourceId || item.lane.resourceId === state.selectedEventResourceId))
    || state.lanes.flatMap((lane) => lane.marks).find((item) => item.eventUid === uid);
  const canonicalId = state.selectedEventResourceId || mark?.lane?.resourceId || subject.resource_id;
  const canonicalResource = canonicalId ? state.resourceById.get(canonicalId) : null;
  const resourceText = canonicalResource
    ? resourceLabel(canonicalResource, canonicalId)
    : mark?.lane?.label || subject.raw_key || "resource";
  const resourceLayerName = canonicalResource
    ? resourceLayer(canonicalResource, canonicalId)
    : subject.layer;
  byId("selected-event-title").textContent = titleCase(event.event_type || event.label || "event");
  byId("selected-event-summary").textContent = `${humanLayer(resourceLayerName)} / ${resourceText} / ${event.action || event.operation || "observe"} -> ${eventFailed(event) ? "failure" : event.outcome || "success"}`;
  const fields = [
    ["Time", `${formatOffset(eventTime(event))} (${eventTime(event)} ns)`],
    ["Operation", event.action || event.operation || "observe"],
    ["Outcome", eventFailed(event) ? "failure" : event.outcome || "success"],
    ["Resulting status", eventStatus(event)],
    ["Status duration", mark ? formatDuration(mark.durationToNextChangeNs) : "unknown"],
    ["Quality", event.quality || "unknown"],
    ["Properties", formatValue(properties)],
    ["Result", formatValue(result)],
  ];
  byId("selected-event-fields").innerHTML = fields.map(([key, value]) => `<dt>${escapeHtml(key)}</dt><dd>${escapeHtml(value)}</dd>`).join("");
  const evidence = event.evidence || {};
  byId("selected-event-evidence").innerHTML = `<strong>Evidence</strong><br>${escapeHtml(evidence.logical_path || "No source path")}<br><span>${escapeHtml(evidence.locator || "No locator")}</span>`;
}

function renderSourceRecordInspector(record) {
  const descriptor = sourceTypeDescriptor(record.source_type);
  const linked = record.matched_event_uid
    ? state.eventByUid.get(String(record.matched_event_uid))
    : null;
  byId("selected-event-title").textContent = titleCase(record.record_name || "source record");
  byId("selected-event-summary").textContent = descriptor.label + " / "
    + String(record.source_name || "source") + " / "
    + (record.matched_event_uid ? "linked to normalized event" : "unmatched");
  const fields = [
    ["Time", formatOffset(sourceRecordTime(record)) + " (" + sourceRecordTime(record) + " ns)"],
    ["Source type", descriptor.label],
    ["Source", record.source_name || "unknown"],
    ["Layer", humanLayer(record.layer || "unknown")],
    ["Normalization", record.matched_event_uid ? "matched" : "unmatched"],
    ["Linked event", linked ? String(linked.event_type || record.matched_event_uid) : record.matched_event_uid || "none"],
    ["Message", record.message || ""],
    ["Attributes", formatValue(record.attributes || {})],
  ];
  byId("selected-event-fields").innerHTML = fields
    .map(([key, value]) => `<dt>${escapeHtml(key)}</dt><dd>${escapeHtml(value)}</dd>`)
    .join("");
  byId("selected-event-evidence").innerHTML = `<strong>Retained source record</strong><br>${escapeHtml(sourceRecordUid(record))}<br><span>Plug-in decoded; core timestamped, indexed, and linked.</span>`;
}

function renderEmptyEventInspector() {
  byId("selected-event-title").textContent = "Choose a timeline mark";
  byId("selected-event-summary").textContent = "Properties, outcome and evidence will appear here.";
  byId("selected-event-fields").innerHTML = "";
  byId("selected-event-evidence").innerHTML = "";
}

function bindHoverTarget(element) {
  element.addEventListener("pointerenter", () => {
    window.clearTimeout(state.hoverCloseTimer);
    window.clearTimeout(state.hoverOpenTimer);
    state.hoverOpenTimer = window.setTimeout(() => showHover(element.dataset.hoverKey, element, false), HOVER_OPEN_DELAY_MS);
  });
  element.addEventListener("pointerleave", scheduleHoverClose);
  element.addEventListener("focus", () => showHover(element.dataset.hoverKey, element, false));
  element.addEventListener("blur", scheduleHoverClose);
}

function scheduleHoverClose() {
  window.clearTimeout(state.hoverOpenTimer);
  window.clearTimeout(state.hoverCloseTimer);
  if (state.hoverPinned) return;
  state.hoverCloseTimer = window.setTimeout(closeHover, HOVER_CLOSE_GRACE_MS);
}

function eventHoverHtml(mark, lane) {
  const event = mark.event || {};
  return `<div class="hover-heading"><div><span>${mark.failure ? "FAILED EVENT" : "EVENT"}</span><strong>${escapeHtml(mark.label)}</strong></div><button class="hover-close" type="button" aria-label="Close">x</button></div>
    <dl class="hover-facts">
      <dt>When</dt><dd>${escapeHtml(formatOffset(mark.timeNs))}<small>${mark.timeNs} ns</small></dd>
      <dt>Resource</dt><dd>${escapeHtml(lane.label)}<small>${escapeHtml(humanResourceType(lane.kind))}</small></dd>
      <dt>Operation</dt><dd>${escapeHtml(mark.action)}</dd>
      <dt>Outcome</dt><dd class="${mark.failure ? "failure-text" : "success-text"}">${escapeHtml(mark.failure ? "failed" : mark.outcome)}</dd>
      <dt>Result</dt><dd>${escapeHtml(mark.failure && !mark.stateChanged ? "No mutation; status unchanged" : eventStatus(event))}</dd>
      <dt>Duration</dt><dd>${escapeHtml(formatDuration(mark.durationToNextChangeNs))}<small>until next accepted state change</small></dd>
    </dl>`;
}

function clusterHoverHtml(cluster, lane) {
  const items = cluster.items.length ? cluster.items : cluster.eventUids.map((uid) => lane.marks.find((mark) => mark.eventUid === uid)).filter(Boolean);
  return `<div class="hover-heading"><div><span>COLLAPSED EVENTS</span><strong>${cluster.count} events${cluster.failureCount ? ` / ${cluster.failureCount} failed` : ""}</strong></div><button class="hover-close" type="button" aria-label="Close">x</button></div>
    <div class="cluster-window">${items.slice(0, 40).map((mark) => `<button type="button" class="cluster-event${mark.failure ? " failed" : ""}" data-cluster-event-uid="${escapeHtml(mark.eventUid)}"><span>${escapeHtml(formatOffset(mark.timeNs))}</span><strong>${escapeHtml(mark.label)}</strong><small>${escapeHtml(`${mark.action} / ${mark.failure ? "failed" : mark.outcome}`)}</small></button>`).join("") || '<p class="empty-cluster">Event details are available through the cluster expansion API.</p>'}</div>`;
}

function sourceRecordHoverHtml(mark) {
  const record = mark.record || {};
  const descriptor = sourceTypeDescriptor(mark.sourceType || record.source_type);
  return `<div class="hover-heading"><div><span>${mark.matchedEventUid ? "MATCHED SOURCE RECORD" : "UNMATCHED SOURCE RECORD"}</span><strong>${escapeHtml(mark.recordName)}</strong></div><button class="hover-close" type="button" aria-label="Close">x</button></div>
    <dl class="hover-facts">
      <dt>When</dt><dd>${escapeHtml(formatOffset(mark.timeNs))}<small>${mark.timeNs} ns</small></dd>
      <dt>Source</dt><dd>${escapeHtml(descriptor.label)}<small>${escapeHtml(mark.sourceName)}</small></dd>
      <dt>Layer</dt><dd>${escapeHtml(humanLayer(record.layer || "unknown"))}</dd>
      <dt>Normalization</dt><dd class="${mark.matchedEventUid ? "success-text" : "failure-text"}">${mark.matchedEventUid ? "matched" : "unmatched"}</dd>
      <dt>Linked event</dt><dd>${escapeHtml(mark.matchedEventUid || "none")}</dd>
      <dt>Message</dt><dd>${escapeHtml(mark.message || "No decoded message")}</dd>
    </dl>`;
}

function sourceClusterHoverHtml(cluster) {
  return `<div class="hover-heading"><div><span>COLLAPSED SOURCE RECORDS</span><strong>${cluster.count} records</strong></div><button class="hover-close" type="button" aria-label="Close">x</button></div>
    <div class="cluster-window">${cluster.items.map((mark) => `<button type="button" class="cluster-event${mark.matchedEventUid ? "" : " failed"}" data-cluster-source-record-uid="${escapeHtml(mark.sourceRecordUid)}"><span>${escapeHtml(formatOffset(mark.timeNs))}</span><strong>${escapeHtml(mark.recordName)}</strong><small>${escapeHtml(mark.sourceType + " / " + (mark.matchedEventUid ? "matched" : "unmatched"))}</small></button>`).join("")}</div>`;
}

function intervalHoverHtml(interval, lane) {
  return `<div class="hover-heading"><div><span>${interval.kind === "lifecycle" ? "RESOURCE LIFECYCLE" : "RESOURCE STATUS"}</span><strong>${escapeHtml(interval.status)}</strong></div><button class="hover-close" type="button" aria-label="Close">x</button></div>
    <dl class="hover-facts"><dt>Resource</dt><dd>${escapeHtml(lane.label)}<small>${escapeHtml(humanResourceType(lane.kind))}</small></dd><dt>Start</dt><dd>${escapeHtml(formatOffset(interval.startNs))}</dd><dt>End</dt><dd>${interval.openEnd ? "open" : escapeHtml(formatOffset(interval.endNs))}</dd><dt>Duration</dt><dd>${escapeHtml(formatDuration(interval.durationNs))}</dd><dt>State</dt><dd>${escapeHtml(formatValue(interval.properties))}</dd></dl>`;
}

function densityHoverHtml(bin) {
  const types = [...bin.topTypes.entries()].sort((a, b) => b[1] - a[1]).slice(0, 4);
  return `<div class="hover-heading"><div><span>EVENT DENSITY</span><strong>${bin.count} events${bin.failures ? ` / ${bin.failures} failed` : ""}</strong></div><button class="hover-close" type="button" aria-label="Close">x</button></div>
    <dl class="hover-facts">
      <dt>Start</dt><dd>${escapeHtml(formatOffset(bin.startNs))}</dd>
      <dt>End</dt><dd>${escapeHtml(formatOffset(bin.endNs))}</dd>
      <dt>Window</dt><dd>${escapeHtml(formatDuration(bin.endNs - bin.startNs))}</dd>
      <dt>Events</dt><dd>${bin.count}</dd>
      <dt>Failures</dt><dd class="${bin.failures ? "failure-text" : "success-text"}">${bin.failures}</dd>
      <dt>Top types</dt><dd>${types.length ? types.map(([type, count]) => `${escapeHtml(titleCase(type))} (${count})`).join("<br>") : "none"}</dd>
    </dl>`;
}

function relationshipHoverHtml(edge, otherId) {
  const other = state.resourceById.get(otherId) || {};
  const direction = edge.source === state.selectedResourceId ? "OUTGOING" : "INCOMING";
  return `<div class="hover-heading"><div><span>${direction} CORRELATION</span><strong>${escapeHtml(titleCase(edge.type))}</strong></div><button class="hover-close" type="button" aria-label="Close">x</button></div>
    <dl class="hover-facts">
      <dt>Resource</dt><dd>${escapeHtml(resourceLabel(other, otherId))}<small>${escapeHtml(humanResourceType(resourceKind(other, otherId)))}</small></dd>
      <dt>Start</dt><dd>${edge.openStart ? "open" : escapeHtml(formatOffset(edge.startNs))}</dd>
      <dt>End</dt><dd>${edge.openEnd ? "open" : escapeHtml(formatOffset(edge.endNs))}</dd>
      <dt>Duration</dt><dd>${escapeHtml(formatDuration(edge.endNs - edge.startNs))}</dd>
      <dt>Direction</dt><dd>${escapeHtml(`${edge.source} → ${edge.target}`)}</dd>
      <dt>Quality</dt><dd>${escapeHtml(edge.quality)}</dd>
    </dl>`;
}

function showHover(key, anchor, pin) {
  const model = state.hoverModels.get(key);
  if (!model) return;
  window.clearTimeout(state.hoverOpenTimer);
  window.clearTimeout(state.hoverCloseTimer);
  state.hoverKey = key;
  if (pin) state.hoverPinned = true;
  const card = byId("timeline-hover");
  card.classList.toggle("pinned", state.hoverPinned);
  card.innerHTML = model.type === "event"
    ? eventHoverHtml(model.mark, model.lane)
    : model.type === "cluster"
      ? clusterHoverHtml(model.cluster, model.lane)
      : model.type === "source-record"
        ? sourceRecordHoverHtml(model.mark)
        : model.type === "source-cluster"
          ? sourceClusterHoverHtml(model.cluster)
      : model.type === "relationship"
        ? relationshipHoverHtml(model.edge, model.otherId)
        : model.type === "density"
          ? densityHoverHtml(model.bin)
          : intervalHoverHtml(model.interval, model.lane);
  card.hidden = false;
  const rect = anchor.getBoundingClientRect();
  const width = Math.min(390, window.innerWidth - 24);
  const left = Math.max(12, Math.min(window.innerWidth - width - 12, rect.left + rect.width / 2 - width / 2));
  const estimatedHeight = Math.min(430, card.scrollHeight || 300);
  const below = rect.bottom + 10;
  const top = below + estimatedHeight < window.innerHeight ? below : Math.max(12, rect.top - estimatedHeight - 10);
  card.style.width = `${width}px`;
  card.style.left = `${left}px`;
  card.style.top = `${top}px`;
  card.querySelector(".hover-close")?.addEventListener("click", closeHover);
  card.querySelectorAll("[data-cluster-event-uid]").forEach((button) => {
    button.addEventListener("click", (event) => {
      if (event.ctrlKey || event.metaKey) {
        event.preventDefault();
        jumpToNormalizedLog(button.dataset.clusterEventUid, model.lane?.resourceId || null);
        return;
      }
      selectEvent(button.dataset.clusterEventUid, true, model.lane?.resourceId || null);
    });
  });
  card.querySelectorAll("[data-cluster-source-record-uid]").forEach((button) => {
    button.addEventListener("click", (event) => {
      if (event.ctrlKey || event.metaKey) {
        event.preventDefault();
        jumpToSourceLog(button.dataset.clusterSourceRecordUid);
        return;
      }
      selectSourceRecord(button.dataset.clusterSourceRecordUid, true);
    });
  });
}

function closeHover() {
  window.clearTimeout(state.hoverOpenTimer);
  window.clearTimeout(state.hoverCloseTimer);
  state.hoverPinned = false;
  state.hoverKey = null;
  const card = byId("timeline-hover");
  if (card) {
    card.hidden = true;
    card.classList.remove("pinned");
  }
}

function statusAtLane(lane, time) {
  const contains = (item) => time >= item.startNs && (time < item.endNs || (item.openEnd && time === item.endNs));
  const life = lane.lifecycle.find(contains);
  const status = lane.statuses.find(contains);
  return { exists: Boolean(life), status: status?.status || (life ? "exists" : "absent"), properties: status?.properties || {} };
}

function localRangeSummary() {
  const [start, end] = rangeBounds();
  const events = [...state.eventByUid.values()].filter((event) => {
    const time = eventTime(event);
    return time >= start && time <= end;
  });
  const affected = new Set(events.flatMap(eventResourceRefs));
  const relationshipChanges = (state.dataset.relationship_mutations || []).filter((item) => {
    const time = toNs(item.timestamp_ns ?? item.effective_time_ns ?? item.effective_at_ns, start - 1n);
    return time >= start && time <= end;
  });
  relationshipChanges.forEach((item) => {
    if (item.source || item.source_resource_id) affected.add(item.source || item.source_resource_id);
    if (item.target || item.target_resource_id) affected.add(item.target || item.target_resource_id);
  });
  const endpointDiff = [];
  for (const lane of state.lanes) {
    const before = statusAtLane(lane, start);
    const after = statusAtLane(lane, end);
    if (before.exists !== after.exists || before.status !== after.status || JSON.stringify(before.properties) !== JSON.stringify(after.properties)) {
      endpointDiff.push({ resource_id: lane.resourceId, label: lane.label, before: before.status, after: after.status });
    }
  }
  return {
    event_count: events.length,
    failure_count: events.filter(eventFailed).length,
    affected_resources: [...affected],
    status_segments: state.lanes.flatMap((lane) => lane.statuses).filter((item) => item.startNs <= end && item.endNs >= start).length,
    endpoint_diff: endpointDiff,
    relationship_changes: relationshipChanges,
  };
}

function normalizeCount(value) {
  if (Array.isArray(value)) return value.length;
  if (value && typeof value === "object") return Number(value.total ?? value.count ?? Object.keys(value).length);
  return Number(value || 0);
}

function formatRangeInput(value) {
  const delta = clampNs(value) - state.viewStartNs;
  const seconds = delta / 1_000_000_000n;
  const fraction = String(delta % 1_000_000_000n).padStart(9, "0").replace(/0+$/, "");
  return fraction ? `${seconds}.${fraction}` : `${seconds}`;
}

function parseRangeInput(value) {
  const match = String(value || "").trim().replace(/^\+/, "").match(/^(\d+)(?:\.(\d{0,9}))?$/);
  if (!match) throw new Error("Use seconds from the start of the timeline, with up to 9 decimal places.");
  const whole = BigInt(match[1]);
  const fraction = BigInt((match[2] || "").padEnd(9, "0") || "0");
  return clampNs(state.viewStartNs + whole * 1_000_000_000n + fraction);
}

function syncRangeInputs() {
  const bounds = rangeBounds();
  const start = byId("range-start-input");
  const end = byId("range-end-input");
  if (!start || !end) return;
  start.value = bounds ? formatRangeInput(bounds[0]) : "";
  end.value = bounds ? formatRangeInput(bounds[1]) : "";
}

function applyRangeEditor(event) {
  event?.preventDefault();
  const error = byId("range-error");
  try {
    const start = parseRangeInput(byId("range-start-input").value);
    const end = parseRangeInput(byId("range-end-input").value);
    if (end < start) throw new Error("End must be at or after start.");
    state.rangeStartNs = start;
    state.rangeEndNs = end;
    if (end === start) {
      const minimum = rangeMinimumNs();
      if (start + minimum <= state.viewEndNs) state.rangeEndNs = start + minimum;
      else state.rangeStartNs = start - minimum >= state.viewStartNs ? start - minimum : state.viewStartNs;
    }
    state.rangeSummary = null;
    error.textContent = "";
    byId("clear-range").hidden = false;
    updateRangeBands();
    syncRangeInputs();
    requestRangeSummary();
  } catch (rangeError) {
    error.textContent = rangeError.message;
  }
}

function conciseEndpointState(value) {
  if (!value || typeof value !== "object") return formatValue(value ?? "unknown");
  return value.status || value.status_value || (value.exists === false ? "absent" : value.exists === true ? "exists" : formatValue(value));
}

function endpointDiffItems(summary) {
  const diff = summary?.endpoint_diff;
  if (Array.isArray(diff)) return diff;
  if (!diff || typeof diff !== "object") return [];
  return diff.items || diff.changed || diff.resources || Object.entries(diff).map(([resource_id, value]) => ({ resource_id, ...(typeof value === "object" ? value : { change: value }) }));
}

function renderRangeSummary(draft = false) {
  const bounds = rangeBounds();
  if (!bounds) {
    byId("range-title").textContent = "Drag horizontally on any lane to select a period.";
    byId("range-facts").innerHTML = "";
    byId("range-diff").innerHTML = "";
    syncRangeInputs();
    return;
  }
  const summary = draft ? localRangeSummary() : state.rangeSummary || localRangeSummary();
  byId("range-title").textContent = `${formatOffset(bounds[0])} to ${formatOffset(bounds[1])} / ${formatDuration(bounds[1] - bounds[0])}`;
  const eventCount = summary.event_count ?? normalizeCount(summary.events);
  const failures = summary.failure_count ?? (Array.isArray(summary.events) ? summary.events.filter(eventFailed).length : 0);
  const resources = summary.affected_resource_count ?? normalizeCount(summary.affected_resources);
  const relations = summary.relationship_change_count ?? normalizeCount(summary.relationship_changes);
  byId("range-facts").innerHTML = `<span>${Number(eventCount).toLocaleString()} events</span><span class="failure-fact">${Number(failures).toLocaleString()} failed</span><span>${Number(resources).toLocaleString()} resources</span><span>${Number(relations).toLocaleString()} relationship changes</span>`;
  const diff = endpointDiffItems(summary);
  const relationshipChanges = Array.isArray(summary.relationship_changes) ? summary.relationship_changes : [];
  const diffHtml = diff.length
    ? `<strong>Endpoint diff</strong><div>${diff.slice(0, 8).map((item) => `<button type="button" data-resource-id="${escapeHtml(item.resource_id || item.id || "")}"><span>${escapeHtml(item.label || item.resource_id || item.id || "resource")}</span><code>${escapeHtml(conciseEndpointState(item.before ?? item.start_status))} -> ${escapeHtml(conciseEndpointState(item.after ?? item.end_status ?? item.change ?? "changed"))}</code></button>`).join("")}</div>`
    : "<span>No endpoint state difference.</span>";
  const relationshipHtml = relationshipChanges.length
    ? `<strong>Relationship changes</strong><div class="range-relationship-changes">${relationshipChanges.slice(0, 10).map((item) => {
      const source = item.source || item.source_resource_id || "resource";
      const target = item.target || item.target_resource_id || "resource";
      const operation = item.operation || item.effect_type || item.action || "changed";
      return `<button type="button" data-resource-id="${escapeHtml(source)}"><span>${escapeHtml(`${titleCase(operation)} ${item.relation_type || item.type || "relationship"}`)}</span><code>${escapeHtml(`${source} -> ${target}`)}</code></button>`;
    }).join("")}</div>`
    : "";
  byId("range-diff").innerHTML = diffHtml + relationshipHtml;
  byId("range-diff").querySelectorAll("[data-resource-id]").forEach((button) => button.addEventListener("click", () => selectResource(button.dataset.resourceId)));
}

async function requestRangeSummary() {
  const bounds = rangeBounds();
  if (!bounds) return;
  const requestId = ++state.rangeRequestId;
  state.rangeSummary = null;
  renderRangeSummary();
  try {
    const summary = await api(revisionPath("range/summary"), { method: "POST", body: JSON.stringify({ start_ns: bounds[0].toString(), end_ns: bounds[1].toString() }) });
    if (requestId !== state.rangeRequestId) return;
    state.rangeSummary = summary;
  } catch (_error) {
    if (requestId !== state.rangeRequestId || !rangeBounds()) return;
    state.rangeSummary = localRangeSummary();
  }
  renderRangeSummary();
}

function clearRangeSelection() {
  const hadRange = Boolean(rangeBounds());
  state.rangeStartNs = null;
  state.rangeEndNs = null;
  state.rangeSummary = null;
  state.rangeRequestId += 1;
  byId("clear-range").hidden = true;
  byId("range-error").textContent = "";
  updateRangeBands();
  renderRangeSummary();
  return hadRange;
}

function clearTimelineSelection({ announce = true } = {}) {
  const hover = byId("timeline-hover");
  const hadHover = Boolean(hover && !hover.hidden);
  const hadSelection = Boolean(rangeBounds()) || Boolean(state.selectedEventUid) || Boolean(state.selectedSourceRecordUid) || state.cursorSelected;
  closeHover();
  hideTimelineHoverLine();
  state.selectedEventUid = null;
  state.selectedEventResourceId = null;
  state.selectedSourceRecordUid = null;
  clearRangeSelection();
  window.clearTimeout(state.temporalTimer);
  setCursor(state.viewEndNs, false, false);
  rerenderTimelinePreservingScroll();
  renderEmptyEventInspector();
  renderEventTable();
  requestGraph();
  requestResources();
  if (announce && hadSelection) showToast("Timeline selection cleared.");
  return hadSelection || hadHover;
}

function handleEscapeKey(event) {
  if (event.key !== "Escape" || event.repeat || event.isComposing) return;
  closeCorrelationHover();
  const reviewOpen = byId("review-drawer").classList.contains("open");
  if (reviewOpen) {
    event.preventDefault();
    closeHover();
    closeReview();
    return;
  }
  if (state.brush) {
    event.preventDefault();
    finishTimelinePointer(null, true);
    closeHover();
    return;
  }
  const picker = byId("lane-picker");
  if (!picker.hidden) {
    event.preventDefault();
    picker.hidden = true;
    byId("lane-picker-toggle").setAttribute("aria-expanded", "false");
    return;
  }
  if (clearTimelineSelection()) event.preventDefault();
}

function scaleTimelineResourceIds() {
  if (!isScaleMode()) return [];
  if (state.laneMode === "all") return initialScaleLaneIds();
  if (state.laneMode === "selected") return state.selectedResourceId ? [state.selectedResourceId] : initialScaleLaneIds();
  if (state.laneMode === "correlated") {
    return [...new Set([state.selectedResourceId, ...state.correlatedResourceIds].filter(Boolean))]
      .slice(0, MAX_SCALE_TIMELINE_LANES);
  }
  return [...state.explicitLaneIds].slice(0, MAX_SCALE_TIMELINE_LANES);
}

async function requestTimeline() {
  const selectedRange = rangeBounds();
  const scaleResourceIds = scaleTimelineResourceIds();
  try {
    state.timelinePayload = await api(revisionPath("timeline/query"), {
      method: "POST",
      body: JSON.stringify({
        start_ns: state.viewStartNs.toString(),
        end_ns: state.viewEndNs.toString(),
        viewport_pixels: Math.round(window.innerWidth),
        max_glyphs: 3000,
        max_record_marks: 5000,
        record_lane_rules: state.recordLaneRules.map((rule) => ({
          lane_id: rule.lane_id,
          label: rule.label,
          description: rule.description || "",
          pattern: rule.pattern,
          source_types: rule.source_types || [],
          unmatched_only: Boolean(rule.unmatched_only),
          case_sensitive: Boolean(rule.case_sensitive),
          plugin_defined: Boolean(rule.plugin_defined),
        })),
        cursor_time_ns: state.cursorNs.toString(),
        range: selectedRange ? {
          start_ns: selectedRange[0].toString(),
          end_ns: selectedRange[1].toString(),
        } : null,
        resource_ids: isScaleMode() ? scaleResourceIds : undefined,
        allow_empty: isScaleMode() && state.laneMode === "custom" && scaleResourceIds.length === 0,
      }),
    });
  } catch (error) {
    showToast("Timeline query rejected: " + error.message);
    if (!state.timelinePayload) state.timelinePayload = { lanes: [], record_lanes: [] };
  }
  normalizeTimeline(state.timelinePayload);
}

function fallbackResourceItems() {
  const entries = isScaleMode()
    ? [...state.explicitLaneIds].map((id) => [id, state.resourceById.get(id)]).filter(([, record]) => record)
    : [...state.resourceById.entries()];
  return entries.slice(0, MAX_RESOURCE_ROWS).map(([id, record]) => {
    const lane = state.laneByResource.get(id);
    const temporal = lane ? statusAtLane(lane, state.cursorNs) : { exists: true, status: record.state?.status || record.state?.program_state || "observed", properties: record.state || {} };
    return {
      ...record,
      resource_id: id,
      kind: resourceKind(record, id),
      layer: resourceLayer(record, id),
      label: resourceLabel(record, id),
      exists: temporal.exists,
      status: temporal.status,
      status_class: String(temporal.status).match(/fail|error|down/i) ? "error" : "ok",
      state: temporal.properties,
    };
  });
}

async function requestResources() {
  const requestId = ++state.resourceRequestId;
  try {
    const payload = await api(revisionPath("resources/query"), {
      method: "POST",
      body: JSON.stringify({
        time_ns: state.cursorNs.toString(),
        kinds: isScaleMode() && state.selectedResourceKind ? [state.selectedResourceKind] : [],
        search: isScaleMode() ? (byId("resource-search")?.value || "").trim() : null,
        limit: MAX_RESOURCE_ROWS,
      }),
    });
    if (requestId !== state.resourceRequestId) return;
    state.resourceQuery = payload;
    for (const item of payload.items || []) registerResource(item, item.resource_id);
  } catch (_error) {
    if (requestId !== state.resourceRequestId) return;
    state.resourceQuery = { time_ns: state.cursorNs.toString(), items: fallbackResourceItems(), tables: [] };
  }
  renderResourceTables();
  renderPluginDashboards();
}

function presentationColumns(kind, items) {
  const tables = state.resourceQuery?.tables || [];
  const table = Array.isArray(tables)
    ? tables.find((item) => (item.kind || item.resource_kind || item.type) === kind)
    : tables[kind];
  if (table?.columns) return table.columns.map((column) => typeof column === "string" ? { key: column, label: titleCase(column) } : { key: column.key || column.field, label: column.label || titleCase(column.key || column.field) }).filter((item) => item.key).slice(0, 5);
  const counts = new Map();
  items.forEach((item) => Object.keys(item.state || item.properties || {}).forEach((key) => counts.set(key, (counts.get(key) || 0) + 1)));
  return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 4).map(([key]) => ({ key, label: titleCase(key) }));
}

function renderResourceTables() {
  const container = byId("resource-table-wrap");
  if (!container) return;
  const allItems = state.resourceQuery?.items || fallbackResourceItems();
  const groups = new Map();
  for (const item of allItems) {
    const id = item.resource_id || resourceIdOf(item);
    const kind = item.kind || resourceKind(item, id);
    if (!groups.has(kind)) groups.set(kind, []);
    groups.get(kind).push({ ...item, resource_id: id, kind });
  }
  const countsByKind = state.resourceQuery?.counts_by_kind || {};
  const kinds = (Object.keys(countsByKind).length ? Object.keys(countsByKind) : [...groups.keys()]).sort();
  if (!state.selectedResourceKind || !kinds.includes(state.selectedResourceKind)) state.selectedResourceKind = kinds[0] || null;
  byId("resource-type-tabs").innerHTML = kinds.map((kind) => `<button type="button" role="tab" data-kind="${escapeHtml(kind)}" aria-selected="${kind === state.selectedResourceKind}">${escapeHtml(titleCase(kind))}<span>${Number(countsByKind[kind] ?? groups.get(kind)?.length ?? 0).toLocaleString()}</span></button>`).join("");
  byId("resource-type-tabs").querySelectorAll("[data-kind]").forEach((button) => button.addEventListener("click", () => {
    state.selectedResourceKind = button.dataset.kind;
    if (isScaleMode()) requestResources();
    else renderResourceTables();
  }));
  const needle = (byId("resource-search")?.value || "").trim().toLowerCase();
  const kindItems = groups.get(state.selectedResourceKind) || [];
  const items = kindItems.filter((item) => !needle || JSON.stringify(item).toLowerCase().includes(needle)).slice(0, MAX_RESOURCE_ROWS);
  const columns = presentationColumns(state.selectedResourceKind, kindItems);
  const exactKindCount = Number(countsByKind[state.selectedResourceKind] ?? kindItems.length);
  byId("resource-table-summary").textContent = `${items.length.toLocaleString()} shown of ${exactKindCount.toLocaleString()} ${titleCase(state.selectedResourceKind || "resources")} at ${formatOffset(state.cursorNs)}${state.resourceQuery?.windowed ? " · server-windowed" : ""}`;
  if (!items.length) {
    container.innerHTML = '<div class="empty-state">No resources match this view.</div>';
    return;
  }
  container.innerHTML = `<table class="resource-table"><thead><tr><th>Resource</th><th>Layer</th><th>Exists</th><th>Status</th><th>Timeline</th>${columns.map((column) => `<th>${escapeHtml(column.label)}</th>`).join("")}</tr></thead><tbody>${items.map((item) => {
    const tags = presentationTags(item);
    const compact = tags.has("compact") || tags.has("connector");
    const current = item.resource_id === state.selectedResourceId;
    const values = item.state || item.properties || {};
    return `<tr data-resource-id="${escapeHtml(item.resource_id)}" class="${current ? "selected " : ""}${compact ? "resource-connector" : ""}" tabindex="0"><td><strong>${escapeHtml(item.label || resourceLabel(item, item.resource_id))}</strong><small>${escapeHtml(item.resource_id)}${compact ? " / connector" : ""}</small></td><td>${escapeHtml(humanLayer(item.layer))}</td><td>${item.exists === false ? "no" : "yes"}</td><td><span class="state-chip state-${safeClass(item.status_class)}">${escapeHtml(item.status || "unknown")}</span></td><td><button class="lane-visibility-toggle" type="button" data-lane-toggle="${escapeHtml(item.resource_id)}" aria-pressed="${laneSelectedByMode(item.resource_id)}">${laneSelectedByMode(item.resource_id) ? "Shown" : "Hidden"}</button></td>${columns.map((column) => `<td><code>${escapeHtml(formatValue(values[column.key]))}</code></td>`).join("")}</tr>`;
  }).join("")}</tbody></table>`;
  container.querySelectorAll("tr[data-resource-id]").forEach((row) => {
    const choose = () => selectResource(row.dataset.resourceId);
    row.addEventListener("click", choose);
    row.addEventListener("keydown", (event) => { if (event.key === "Enter" || event.key === " ") choose(); });
  });
  container.querySelectorAll("[data-lane-toggle]").forEach((button) => button.addEventListener("click", (event) => {
    event.stopPropagation();
    setExplicitLaneVisibility(button.dataset.laneToggle, button.getAttribute("aria-pressed") !== "true");
  }));
}

function dashboardDescriptors() {
  const descriptors = state.dataset?.schema?.dashboards
    || state.dataset?.dashboard_descriptors
    || [];
  return Array.isArray(descriptors)
    ? descriptors.filter((item) => item && item.dashboard_id)
    : [];
}

function initializeDashboardLayout(forceDefaults = false) {
  if (state.dashboardLayoutReady && !forceDefaults) return;
  const descriptors = dashboardDescriptors();
  const descriptorIds = descriptors.map((item) => String(item.dashboard_id));
  const allowedIds = new Set(descriptorIds);
  let saved = {};
  if (!forceDefaults) {
    try {
      saved = JSON.parse(localStorage.getItem(DASHBOARD_LAYOUT_STORAGE_KEY) || "{}");
    } catch (_error) {
      saved = {};
    }
  }
  const validUniqueIds = (values) => {
    const seen = new Set();
    return (Array.isArray(values) ? values : [])
      .map(String)
      .filter((id) => allowedIds.has(id) && !seen.has(id) && seen.add(id));
  };
  const savedOrder = validUniqueIds(saved.order);
  state.dashboardOrder = [
    ...savedOrder,
    ...descriptorIds.filter((id) => !savedOrder.includes(id)),
  ];
  state.openDashboardIds = new Set(
    Array.isArray(saved.open)
      ? validUniqueIds(saved.open)
      : descriptors.filter((item) => item.default_open).map((item) => String(item.dashboard_id)),
  );
  state.expandedDashboardIds = new Set(
    Array.isArray(saved.expanded)
      ? validUniqueIds(saved.expanded)
      : descriptors.filter((item) => item.default_expanded !== false).map((item) => String(item.dashboard_id)),
  );
  descriptors
    .filter((item) => item.collapsible === false)
    .forEach((item) => state.expandedDashboardIds.add(String(item.dashboard_id)));
  state.dashboardLayoutReady = true;
  saveDashboardLayout();
}

function saveDashboardLayout() {
  if (!state.dashboardLayoutReady) return;
  try {
    localStorage.setItem(DASHBOARD_LAYOUT_STORAGE_KEY, JSON.stringify({
      order: state.dashboardOrder,
      open: [...state.openDashboardIds],
      expanded: [...state.expandedDashboardIds],
    }));
  } catch (_error) {
    // The dashboard remains usable when browser storage is unavailable.
  }
}

function resetDashboardLayout() {
  try {
    localStorage.removeItem(DASHBOARD_LAYOUT_STORAGE_KEY);
  } catch (_error) {
    // Continue with in-memory defaults.
  }
  state.dashboardLayoutReady = false;
  initializeDashboardLayout(true);
  renderPluginDashboards();
  showToast("Dashboard layout reset.");
}

function toggleDashboardOpen(dashboardId) {
  if (state.openDashboardIds.has(dashboardId)) state.openDashboardIds.delete(dashboardId);
  else state.openDashboardIds.add(dashboardId);
  saveDashboardLayout();
  renderPluginDashboards();
}

function toggleDashboardExpanded(dashboardId) {
  const descriptor = dashboardDescriptors().find((item) => item.dashboard_id === dashboardId);
  if (!descriptor || descriptor.collapsible === false) return;
  if (state.expandedDashboardIds.has(dashboardId)) state.expandedDashboardIds.delete(dashboardId);
  else state.expandedDashboardIds.add(dashboardId);
  saveDashboardLayout();
  renderPluginDashboards();
}

function placeDashboard(dashboardId, targetId, beforeTarget) {
  if (!dashboardId || !targetId || dashboardId === targetId) return;
  const descriptor = dashboardDescriptors().find((item) => item.dashboard_id === dashboardId);
  if (!descriptor || descriptor.movable === false) return;
  const remaining = state.dashboardOrder.filter((id) => id !== dashboardId);
  const targetIndex = remaining.indexOf(targetId);
  if (targetIndex < 0) return;
  remaining.splice(targetIndex + (beforeTarget ? 0 : 1), 0, dashboardId);
  state.dashboardOrder = remaining;
  saveDashboardLayout();
  renderPluginDashboards();
}

function moveDashboard(dashboardId, direction) {
  const openIds = state.dashboardOrder.filter((id) => state.openDashboardIds.has(id));
  const sourceIndex = openIds.indexOf(dashboardId);
  const targetIndex = sourceIndex + direction;
  if (sourceIndex < 0 || targetIndex < 0 || targetIndex >= openIds.length) return;
  placeDashboard(dashboardId, openIds[targetIndex], direction < 0);
}

function dashboardFieldValue(item, field) {
  if (!field) return undefined;
  return String(field).split(".").reduce(
    (value, key) => (value === null || value === undefined ? undefined : value[key]),
    item,
  );
}

function dashboardComparable(value) {
  if (value === undefined) return "__undefined__";
  if (value === null) return "__null__";
  if (typeof value === "object") {
    try {
      return JSON.stringify(value);
    } catch (_error) {
      return String(value);
    }
  }
  return String(value);
}

function dashboardFilterMatches(item, filter) {
  const actual = dashboardFieldValue(item, filter.field);
  const expected = filter.value;
  const equals = (left, right) => dashboardComparable(left) === dashboardComparable(right);
  switch (filter.operator || "eq") {
    case "eq":
      return equals(actual, expected);
    case "not_eq":
      return !equals(actual, expected);
    case "in":
      return Array.isArray(expected) && expected.some((value) => equals(actual, value));
    case "not_in":
      return Array.isArray(expected) && !expected.some((value) => equals(actual, value));
    case "exists":
      return (actual !== null && actual !== undefined) === (expected === undefined ? true : Boolean(expected));
    case "contains": {
      if (Array.isArray(actual)) return actual.some((value) => equals(value, expected));
      const haystack = typeof actual === "object" ? dashboardComparable(actual) : String(actual ?? "");
      return haystack.toLowerCase().includes(String(expected ?? "").toLowerCase());
    }
    default:
      return false;
  }
}

function dashboardResourceRows(resourceKinds = [], includeAbsent = false) {
  const allowedKinds = new Set((resourceKinds || []).map(String));
  return (state.resourceQuery?.items || fallbackResourceItems())
    .map((item) => {
      const id = item.resource_id || resourceIdOf(item);
      return {
        ...item,
        resource_id: id,
        kind: item.kind || resourceKind(item, id),
        layer: item.layer || resourceLayer(item, id),
        label: item.label || resourceLabel(item, id),
        state: item.state || item.properties || {},
      };
    })
    .filter((item) => (!allowedKinds.size || allowedKinds.has(String(item.kind)))
      && (includeAbsent || item.exists !== false));
}

function dashboardStatisticResult(descriptor) {
  if (descriptor.scale_metric) {
    const value = String(descriptor.scale_metric).split(".").reduce(
      (current, key) => (current === null || current === undefined ? undefined : current[key]),
      state.dataset?.scale?.metrics,
    );
    return { value, matchingCount: Number(value ?? 0), sampleCount: Number(value ?? 0) };
  }
  const rows = dashboardResourceRows(
    descriptor.resource_kinds,
    descriptor.include_absent === true,
  ).filter((item) => (descriptor.filters || []).every(
    (filter) => dashboardFilterMatches(item, filter),
  ));
  const values = descriptor.field
    ? rows.map((item) => dashboardFieldValue(item, descriptor.field))
      .filter((value) => value !== null && value !== undefined)
    : [];
  const numericValues = values.map(Number).filter(Number.isFinite);
  let value = null;
  switch (descriptor.aggregation || "count") {
    case "count":
      value = rows.length;
      break;
    case "count_distinct":
      value = new Set(values.map(dashboardComparable)).size;
      break;
    case "sum":
      value = numericValues.reduce((total, item) => total + item, 0);
      break;
    case "average":
      value = numericValues.length
        ? numericValues.reduce((total, item) => total + item, 0) / numericValues.length
        : null;
      break;
    case "minimum":
      value = numericValues.length ? Math.min(...numericValues) : null;
      break;
    case "maximum":
      value = numericValues.length ? Math.max(...numericValues) : null;
      break;
    default:
      value = null;
  }
  return { value, matchingCount: rows.length, sampleCount: values.length };
}

function formatDashboardStatistic(result, descriptor) {
  if (result.value === null || result.value === undefined || Number.isNaN(result.value)) return "—";
  const precision = Math.max(0, Math.min(8, Number(descriptor.precision || 0)));
  const formatted = typeof result.value === "number"
    ? result.value.toLocaleString(undefined, {
      minimumFractionDigits: precision,
      maximumFractionDigits: precision,
    })
    : formatValue(result.value);
  return descriptor.unit ? `${formatted} ${descriptor.unit}` : formatted;
}

function renderDashboardStatistic(descriptor) {
  const result = dashboardStatisticResult(descriptor);
  const aggregation = titleCase(descriptor.aggregation || "count");
  return `<article class="dashboard-stat">
    <span>${escapeHtml(descriptor.label || descriptor.statistic_id)}</span>
    <strong>${escapeHtml(formatDashboardStatistic(result, descriptor))}</strong>
    <small>${escapeHtml(aggregation)} · ${result.matchingCount} matching at ${escapeHtml(formatOffset(state.cursorNs))}</small>
  </article>`;
}

function compareDashboardValues(left, right) {
  if (left === right) return 0;
  if (left === null || left === undefined) return 1;
  if (right === null || right === undefined) return -1;
  const leftNumber = Number(left);
  const rightNumber = Number(right);
  if (Number.isFinite(leftNumber) && Number.isFinite(rightNumber)) return leftNumber - rightNumber;
  return String(left).localeCompare(String(right), undefined, { numeric: true, sensitivity: "base" });
}

function formatDashboardCell(item, column) {
  const value = dashboardFieldValue(item, column.field);
  const valueFormat = column.value_format || "auto";
  if (valueFormat === "resource") {
    return `<button class="dashboard-resource-link" type="button" data-dashboard-resource-id="${escapeHtml(item.resource_id)}">
      <strong>${escapeHtml(value ?? item.label)}</strong>
      <small>${escapeHtml(item.resource_id)}</small>
    </button>`;
  }
  if (value === null || value === undefined || value === "") {
    return '<span class="dashboard-empty-value">—</span>';
  }
  if (valueFormat === "status") {
    const statusClass = column.field === "status"
      ? item.status_class
      : (String(value).match(/fail|error|down|withdraw|unresolved/i) ? "error" : "ok");
    return `<span class="state-chip state-${safeClass(statusClass || "unknown")}">${escapeHtml(value)}</span>`;
  }
  if (valueFormat === "boolean") return value ? "yes" : "no";
  if (valueFormat === "number") {
    const numeric = Number(value);
    return Number.isFinite(numeric)
      ? `<span class="dashboard-number">${escapeHtml(numeric.toLocaleString())}</span>`
      : '<span class="dashboard-empty-value">—</span>';
  }
  if (typeof value === "object") return `<code>${escapeHtml(formatValue(value))}</code>`;
  return escapeHtml(value);
}

function renderDashboardTable(descriptor) {
  const allRows = dashboardResourceRows(
    descriptor.resource_kinds,
    descriptor.include_absent === true,
  );
  const direction = descriptor.sort_direction === "descending" ? -1 : 1;
  const sortedRows = descriptor.sort_field
    ? [...allRows].sort((left, right) => direction * compareDashboardValues(
      dashboardFieldValue(left, descriptor.sort_field),
      dashboardFieldValue(right, descriptor.sort_field),
    ))
    : allRows;
  const limit = Math.max(1, Math.min(500, Number(descriptor.max_rows || 50)));
  const rows = sortedRows.slice(0, limit);
  const columns = Array.isArray(descriptor.columns) ? descriptor.columns : [];
  const body = rows.length
    ? rows.map((item) => `<tr class="${item.resource_id === state.selectedResourceId ? "selected" : ""}">
      ${columns.map((column) => `<td>${formatDashboardCell(item, column)}</td>`).join("")}
    </tr>`).join("")
    : `<tr><td colspan="${Math.max(1, columns.length)}" class="dashboard-table-empty">${escapeHtml(descriptor.empty_message || "No resources match this dashboard at the selected time.")}</td></tr>`;
  const countText = sortedRows.length > rows.length
    ? `Showing ${rows.length} of ${sortedRows.length}`
    : `${rows.length} resource${rows.length === 1 ? "" : "s"}`;
  return `<section class="dashboard-table-panel">
    <div class="dashboard-table-heading">
      <h4>${escapeHtml(descriptor.title || descriptor.table_id)}</h4>
      <span>${escapeHtml(countText)}</span>
    </div>
    <div class="dashboard-table-wrap">
      <table class="dashboard-table">
        <thead><tr>${columns.map((column) => `<th>${escapeHtml(column.label || titleCase(column.field))}</th>`).join("")}</tr></thead>
        <tbody>${body}</tbody>
      </table>
    </div>
  </section>`;
}

function renderPluginDashboards() {
  const index = byId("dashboard-index");
  const modules = byId("dashboard-modules");
  if (!index || !modules) return;
  initializeDashboardLayout();
  const descriptors = dashboardDescriptors();
  const descriptorById = new Map(descriptors.map((item) => [String(item.dashboard_id), item]));
  const orderedIds = state.dashboardOrder.filter((id) => descriptorById.has(id));
  if (!orderedIds.length) {
    index.innerHTML = '<span class="dashboard-index-empty">The active plug-in has not registered any dashboards.</span>';
    modules.innerHTML = "";
    return;
  }
  const openIds = orderedIds.filter((id) => state.openDashboardIds.has(id));
  index.innerHTML = `<div class="dashboard-index-tree">
    <div class="dashboard-index-root">
      <span class="dashboard-index-root-disclosure" aria-hidden="true"></span>
      <span class="dashboard-index-root-icon" aria-hidden="true"></span>
      <span class="dashboard-index-root-copy">
        <strong>Plug-in dashboard index</strong>
        <small>${orderedIds.length} registered ${orderedIds.length === 1 ? "module" : "modules"}</small>
      </span>
      <span class="dashboard-index-root-count">${openIds.length} open</span>
    </div>
    <ol class="dashboard-index-children">
      ${orderedIds.map((id, position) => {
    const descriptor = descriptorById.get(id);
    const open = state.openDashboardIds.has(id);
    return `<li class="dashboard-index-node ${open ? "is-open" : "is-closed"}">
        <button class="dashboard-index-tag" type="button" data-dashboard-open="${escapeHtml(id)}" aria-pressed="${open}" aria-controls="dashboard-module-${escapeHtml(id)}">
          <span class="dashboard-index-disclosure" aria-hidden="true"></span>
          <span class="dashboard-index-number">${String(position + 1).padStart(2, "0")}</span>
          <span class="dashboard-index-label">
            <strong>${escapeHtml(descriptor.title)}</strong>
            <span>${escapeHtml(id)}</span>
          </span>
          <span class="dashboard-index-state">${open ? "open" : "closed"}</span>
        </button>
      </li>`;
  }).join("")}
    </ol>
  </div>`;
  modules.innerHTML = openIds.map((id, openPosition) => {
    const descriptor = descriptorById.get(id);
    const expanded = descriptor.collapsible === false || state.expandedDashboardIds.has(id);
    const movable = descriptor.movable !== false;
    const position = orderedIds.indexOf(id);
    const statistics = descriptor.statistics || [];
    const tables = descriptor.tables || [];
    const body = expanded
      ? `<div class="plugin-dashboard-body" id="dashboard-body-${escapeHtml(id)}">
        ${statistics.length ? `<div class="dashboard-stat-grid">${statistics.map(renderDashboardStatistic).join("")}</div>` : ""}
        ${tables.length ? `<div class="dashboard-table-grid">${tables.map(renderDashboardTable).join("")}</div>` : ""}
      </div>`
      : "";
    return `<article class="plugin-dashboard-module ${expanded ? "" : "is-collapsed"}" id="dashboard-module-${escapeHtml(id)}" data-dashboard-id="${escapeHtml(id)}">
      <header class="plugin-dashboard-module-header">
        <div class="dashboard-module-identity">
          ${movable ? `<span class="dashboard-drag-handle" draggable="true" data-dashboard-drag="${escapeHtml(id)}" aria-hidden="true">Drag</span>` : ""}
          <div>
            <span class="dashboard-module-index">INDEX ${String(position + 1).padStart(2, "0")} · PLUG-IN MODULE</span>
            <h3>${escapeHtml(descriptor.title)}</h3>
            <p>${escapeHtml(descriptor.description || "")}</p>
          </div>
        </div>
        <div class="dashboard-module-actions">
          ${movable ? `<button type="button" data-dashboard-move="-1" data-dashboard-id="${escapeHtml(id)}" ${openPosition === 0 ? "disabled" : ""}>Move up</button>
          <button type="button" data-dashboard-move="1" data-dashboard-id="${escapeHtml(id)}" ${openPosition === openIds.length - 1 ? "disabled" : ""}>Move down</button>` : ""}
          ${descriptor.collapsible === false ? "" : `<button type="button" data-dashboard-expand="${escapeHtml(id)}" aria-expanded="${expanded}" aria-controls="dashboard-body-${escapeHtml(id)}">${expanded ? "Collapse" : "Expand"}</button>`}
          <button type="button" data-dashboard-close="${escapeHtml(id)}">Close</button>
        </div>
      </header>
      ${body}
    </article>`;
  }).join("");

  index.querySelectorAll("[data-dashboard-open]").forEach((button) => {
    button.addEventListener("click", () => toggleDashboardOpen(button.dataset.dashboardOpen));
  });
  modules.querySelectorAll("[data-dashboard-close]").forEach((button) => {
    button.addEventListener("click", () => toggleDashboardOpen(button.dataset.dashboardClose));
  });
  modules.querySelectorAll("[data-dashboard-expand]").forEach((button) => {
    button.addEventListener("click", () => toggleDashboardExpanded(button.dataset.dashboardExpand));
  });
  modules.querySelectorAll("[data-dashboard-move]").forEach((button) => {
    button.addEventListener("click", () => moveDashboard(
      button.dataset.dashboardId,
      Number(button.dataset.dashboardMove),
    ));
  });
  modules.querySelectorAll("[data-dashboard-resource-id]").forEach((button) => {
    button.addEventListener("click", () => selectResource(button.dataset.dashboardResourceId));
  });
  modules.querySelectorAll("[data-dashboard-drag]").forEach((handle) => {
    handle.addEventListener("dragstart", (event) => {
      state.draggedDashboardId = handle.dataset.dashboardDrag;
      event.dataTransfer.effectAllowed = "move";
      event.dataTransfer.setData("text/plain", state.draggedDashboardId);
      handle.closest(".plugin-dashboard-module")?.classList.add("is-dragging");
    });
    handle.addEventListener("dragend", () => {
      state.draggedDashboardId = null;
      modules.querySelectorAll(".plugin-dashboard-module").forEach((item) => {
        item.classList.remove("is-dragging", "drop-before", "drop-after");
      });
    });
  });
  modules.querySelectorAll(".plugin-dashboard-module").forEach((module) => {
    module.addEventListener("dragover", (event) => {
      if (!state.draggedDashboardId || state.draggedDashboardId === module.dataset.dashboardId) return;
      event.preventDefault();
      event.dataTransfer.dropEffect = "move";
      const before = event.clientY < module.getBoundingClientRect().top + module.getBoundingClientRect().height / 2;
      module.classList.toggle("drop-before", before);
      module.classList.toggle("drop-after", !before);
    });
    module.addEventListener("dragleave", (event) => {
      if (module.contains(event.relatedTarget)) return;
      module.classList.remove("drop-before", "drop-after");
    });
    module.addEventListener("drop", (event) => {
      if (!state.draggedDashboardId || state.draggedDashboardId === module.dataset.dashboardId) return;
      event.preventDefault();
      const before = module.classList.contains("drop-before");
      placeDashboard(state.draggedDashboardId, module.dataset.dashboardId, before);
      state.draggedDashboardId = null;
    });
  });
}

function localGraphAt(time) {
  const allIntervals = state.dataset.relationship_intervals || [];
  const intervalRelations = allIntervals.filter((item) => {
    const start = item.valid_from_ns === null || item.valid_from_ns === undefined ? state.viewStartNs : toNs(item.valid_from_ns);
    const end = item.valid_to_ns === null || item.valid_to_ns === undefined ? state.viewEndNs + 1n : toNs(item.valid_to_ns);
    return time >= start && time < end;
  });
  const intervalKeys = new Set(allIntervals.map((item) => `${item.source || item.source_resource_id}|${item.relation_type || item.type}|${item.target || item.target_resource_id}`));
  const carriedRelationships = (state.dataset.relationships || []).filter((item) => !intervalKeys.has(`${item.source || item.source_resource_id}|${item.relation_type || item.type}|${item.target || item.target_resource_id}`));
  const activeResourceIds = new Set(
    [...state.resourceById.keys()].filter((id) => {
      const lane = state.laneByResource.get(id);
      return lane ? statusAtLane(lane, time).exists : false;
    }),
  );
  const relationships = [...carriedRelationships, ...intervalRelations].filter((item) => {
    const source = item.source || item.source_resource_id;
    const target = item.target || item.target_resource_id;
    return activeResourceIds.has(source) && activeResourceIds.has(target);
  });
  const ids = new Set(relationships.flatMap((item) => [item.source || item.source_resource_id, item.target || item.target_resource_id]).filter(Boolean));
  const nodes = [...ids].map((id) => {
    const record = state.resourceById.get(id) || { resource_id: id };
    const temporal = state.laneByResource.has(id) ? statusAtLane(state.laneByResource.get(id), time) : { status: "unknown", properties: {} };
    return { id, label: resourceLabel(record, id), kind: resourceKind(record, id), layer: resourceLayer(record, id), status: temporal.status, state: temporal.properties, quality: record.quality || "unknown", complete_record: state.resourceById.has(id), presentation_tags: [...presentationTags(record)] };
  });
  return { nodes, edges: relationships.map((item, index) => ({ id: item.relationship_id || `edge-${index}`, source: item.source || item.source_resource_id, target: item.target || item.target_resource_id, type: item.type || item.relation_type || "related", quality: item.quality || "unknown" })), incomplete_node_count: nodes.filter((node) => !node.complete_record).length };
}

function updateCorrelationState(graph = normalizedGraph()) {
  state.activeCorrelationEdges = state.selectedResourceId
    ? graph.edges.filter((edge) => edge.source === state.selectedResourceId || edge.target === state.selectedResourceId)
    : [];
  state.correlatedResourceIds = new Set(state.activeCorrelationEdges.flatMap((edge) => [edge.source, edge.target]).filter((id) => id && id !== state.selectedResourceId));
}

function scopedGraph(graph) {
  if (state.graphShowFull || !state.selectedResourceId) {
    const connectedIds = new Set(graph.edges.flatMap((edge) => [edge.source, edge.target]));
    if (state.selectedResourceId) connectedIds.add(state.selectedResourceId);
    const nodes = graph.nodes.filter((node) => connectedIds.has(node.id));
    return { ...graph, nodes, hidden_isolated_count: Math.max(0, graph.nodes.length - nodes.length) };
  }
  const edges = graph.edges.filter((edge) => edge.source === state.selectedResourceId || edge.target === state.selectedResourceId);
  const ids = new Set([state.selectedResourceId, ...edges.flatMap((edge) => [edge.source, edge.target])]);
  return { ...graph, nodes: graph.nodes.filter((node) => ids.has(node.id)), edges };
}

function rerenderTimelinePreservingScroll() {
  const scroll = byId("timeline-scroll");
  const left = scroll?.scrollLeft || 0;
  const top = scroll?.scrollTop || 0;
  renderTimeline();
  if (scroll) {
    scroll.scrollLeft = left;
    scroll.scrollTop = top;
  }
}

async function requestGraph() {
  const requestId = ++state.graphRequestId;
  const requestedTimeNs = state.cursorNs;
  markCorrelationPending(requestedTimeNs);
  try {
    const resourceIds = !state.graphShowFull && state.selectedResourceId ? [state.selectedResourceId] : [];
    const graph = await api(revisionPath("graph/query"), { method: "POST", body: JSON.stringify({ time_ns: requestedTimeNs.toString(), resource_ids: resourceIds }) });
    if (requestId !== state.graphRequestId) return;
    state.graph = graph;
  } catch (_error) {
    if (requestId !== state.graphRequestId) return;
    state.graph = { ...localGraphAt(requestedTimeNs), time_ns: requestedTimeNs.toString() };
  }
  state.graphTimeNs = toNs(state.graph?.time_ns, requestedTimeNs);
  state.graphRequestedTimeNs = requestedTimeNs;
  state.graphPending = false;
  updateCorrelationState();
  renderCorrelationTimeState();
  renderGraph();
  if (isScaleMode() && state.laneMode === "correlated") await refreshScaleTimeline();
  else rerenderTimelinePreservingScroll();
}

function normalizedGraph() {
  const graph = state.graph || { nodes: [], edges: [] };
  const nodes = (graph.nodes || graph.resources || []).map((node) => {
    const id = node.id || node.resource_id;
    const record = state.resourceById.get(id) || node;
    return { ...node, id, label: node.label || resourceLabel(record, id), kind: node.kind || resourceKind(record, id), layer: node.layer || resourceLayer(record, id), presentation_tags: node.presentation_tags || [...presentationTags(record)] };
  });
  const edges = (graph.edges || graph.relationships || []).map((edge, index) => ({ ...edge, id: edge.id || edge.relationship_id || `edge-${index}`, source: edge.source || edge.source_resource_id, target: edge.target || edge.target_resource_id, type: edge.type || edge.relation_type || "related" }));
  return { ...graph, nodes, edges };
}

function graphNodeSort(a, b) {
  return humanLayer(a.layer).localeCompare(humanLayer(b.layer)) || a.label.localeCompare(b.label);
}

function focusGraphLayout(nodes, edges, selectedId) {
  const nodeById = new Map(nodes.map((node) => [node.id, node]));
  const incomingIds = [...new Set(edges.filter((edge) => edge.target === selectedId).map((edge) => edge.source))];
  const outgoingIds = [...new Set(edges.filter((edge) => edge.source === selectedId).map((edge) => edge.target))];
  const incoming = incomingIds.map((id) => nodeById.get(id)).filter(Boolean).sort(graphNodeSort);
  const incomingSet = new Set(incomingIds);
  const outgoing = outgoingIds
    .filter((id) => !incomingSet.has(id))
    .map((id) => nodeById.get(id))
    .filter(Boolean)
    .sort(graphNodeSort);
  const maxRows = Math.max(1, incoming.length, outgoing.length);
  const rowGap = 122;
  const headerHeight = 94;
  const height = Math.max(540, headerHeight + maxRows * rowGap + 58);
  const contentCenter = headerHeight + (height - headerHeight - 30) / 2;
  const positions = new Map();
  const placeColumn = (items, x) => {
    const start = contentCenter - ((items.length - 1) * rowGap) / 2;
    items.forEach((node, index) => positions.set(node.id, { x, y: ((start + index * rowGap) / height) * 100 }));
  };
  placeColumn(incoming, 15);
  placeColumn(outgoing, 85);
  const selected = nodeById.get(selectedId);
  if (selected) positions.set(selected.id, { x: 50, y: (contentCenter / height) * 100 });
  return {
    positions,
    height,
    mode: "focus",
    columns: [
      { x: 15, label: "Dependents", detail: "point to selected", count: incoming.length },
      { x: 50, label: "Selected resource", detail: "current focus", count: selected ? 1 : 0 },
      { x: 85, label: "Depends on / owns", detail: "selected points to", count: outgoing.length },
    ],
  };
}

function dependencyRankLayout(nodes, edges) {
  const nodeById = new Map(nodes.map((node) => [node.id, node]));
  const outgoing = new Map(nodes.map((node) => [node.id, []]));
  const incoming = new Map(nodes.map((node) => [node.id, []]));
  const indegree = new Map(nodes.map((node) => [node.id, 0]));
  edges.forEach((edge) => {
    if (!nodeById.has(edge.source) || !nodeById.has(edge.target) || edge.source === edge.target) return;
    outgoing.get(edge.source).push(edge.target);
    incoming.get(edge.target).push(edge.source);
    indegree.set(edge.target, indegree.get(edge.target) + 1);
  });
  const rank = new Map(nodes.map((node) => [node.id, 0]));
  const queue = nodes.filter((node) => indegree.get(node.id) === 0).sort(graphNodeSort);
  const visited = new Set();
  while (queue.length) {
    const node = queue.shift();
    if (visited.has(node.id)) continue;
    visited.add(node.id);
    outgoing.get(node.id).forEach((targetId) => {
      rank.set(targetId, Math.max(rank.get(targetId), rank.get(node.id) + 1));
      indegree.set(targetId, indegree.get(targetId) - 1);
      if (indegree.get(targetId) === 0) {
        queue.push(nodeById.get(targetId));
        queue.sort(graphNodeSort);
      }
    });
  }
  const lastAcyclicRank = Math.max(0, ...rank.values());
  nodes.filter((node) => !visited.has(node.id)).sort(graphNodeSort).forEach((node, index) => {
    rank.set(node.id, lastAcyclicRank + 1 + index);
  });
  const rankValues = [...new Set(rank.values())].sort((a, b) => a - b);
  const compressedRank = new Map(rankValues.map((value, index) => [value, index]));
  const groups = rankValues.map(() => []);
  nodes.forEach((node) => groups[compressedRank.get(rank.get(node.id))].push(node));
  groups.forEach((group) => group.sort(graphNodeSort));
  const rankById = new Map();
  groups.forEach((group, groupIndex) => group.forEach((node) => rankById.set(node.id, groupIndex)));
  const adjacency = new Map(nodes.map((node) => [node.id, new Set([...(incoming.get(node.id) || []), ...(outgoing.get(node.id) || [])])]));
  const reorder = (groupIndex, neighborDirection) => {
    const order = new Map();
    groups.forEach((group) => group.forEach((node, index) => order.set(node.id, index)));
    const score = (node) => {
      const neighborPositions = [...adjacency.get(node.id)]
        .filter((id) => neighborDirection * (rankById.get(id) - groupIndex) > 0)
        .map((id) => order.get(id))
        .filter(Number.isFinite);
      return neighborPositions.length
        ? neighborPositions.reduce((sum, value) => sum + value, 0) / neighborPositions.length
        : order.get(node.id);
    };
    groups[groupIndex].sort((a, b) => score(a) - score(b) || graphNodeSort(a, b));
  };
  for (let pass = 0; pass < 6; pass += 1) {
    for (let index = 1; index < groups.length; index += 1) reorder(index, -1);
    for (let index = groups.length - 2; index >= 0; index -= 1) reorder(index, 1);
  }
  const maxRows = Math.max(1, ...groups.map((group) => group.length));
  const rowGap = 138;
  const headerHeight = 92;
  const height = Math.max(620, headerHeight + maxRows * rowGap + 50);
  const positions = new Map();
  groups.forEach((group, groupIndex) => {
    const x = groups.length === 1 ? 50 : 10 + (80 * groupIndex) / (groups.length - 1);
    const start = headerHeight + ((maxRows - group.length) * rowGap) / 2 + rowGap / 2;
    group.forEach((node, rowIndex) => positions.set(node.id, { x, y: ((start + rowIndex * rowGap) / height) * 100 }));
  });
  return {
    positions,
    height,
    mode: "full",
    columns: groups.map((group, index) => ({
      x: groups.length === 1 ? 50 : 10 + (80 * index) / (groups.length - 1),
      label: groups.length === 1 ? "Correlated resources" : index === 0 ? "Sources" : index === groups.length - 1 ? "Targets" : "Dependency step " + index,
      detail: group.length + (group.length === 1 ? " resource" : " resources"),
      count: group.length,
    })),
  };
}

function graphLayout(graph) {
  if (!state.graphShowFull && state.selectedResourceId) {
    return focusGraphLayout(graph.nodes, graph.edges, state.selectedResourceId);
  }
  return dependencyRankLayout(graph.nodes, graph.edges);
}

function correlationHoverCard() {
  let card = byId("correlation-hover");
  if (card) return card;
  card = document.createElement("div");
  card.id = "correlation-hover";
  card.className = "timeline-hover correlation-info-hover";
  card.hidden = true;
  card.addEventListener("pointerenter", () => window.clearTimeout(showCorrelationHover.closeTimer));
  card.addEventListener("pointerleave", scheduleCorrelationHoverClose);
  document.body.appendChild(card);
  return card;
}

function showCorrelationHover(anchor, html) {
  window.clearTimeout(showCorrelationHover.closeTimer);
  const card = correlationHoverCard();
  card.innerHTML = html;
  card.hidden = false;
  card.style.width = `${Math.min(440, window.innerWidth - 24)}px`;
  const rect = anchor.getBoundingClientRect();
  const width = card.getBoundingClientRect().width;
  const height = Math.min(430, card.scrollHeight || 250);
  card.style.left = `${Math.max(12, Math.min(window.innerWidth - width - 12, rect.left + rect.width / 2 - width / 2))}px`;
  card.style.top = `${rect.bottom + height + 10 < window.innerHeight ? rect.bottom + 8 : Math.max(12, rect.top - height - 8)}px`;
}

function scheduleCorrelationHoverClose() {
  window.clearTimeout(showCorrelationHover.closeTimer);
  showCorrelationHover.closeTimer = window.setTimeout(() => {
    const card = byId("correlation-hover");
    if (card) card.hidden = true;
  }, 320);
}

function closeCorrelationHover() {
  window.clearTimeout(showCorrelationHover.closeTimer);
  const card = byId("correlation-hover");
  if (card) card.hidden = true;
}

function bindCorrelationHover(element, htmlFactory) {
  element.addEventListener("pointerenter", () => showCorrelationHover(element, htmlFactory()));
  element.addEventListener("pointerleave", scheduleCorrelationHoverClose);
  element.addEventListener("focus", () => showCorrelationHover(element, htmlFactory()));
  element.addEventListener("blur", scheduleCorrelationHoverClose);
}

function graphNodeHoverHtml(node, graph) {
  const graphTimeNs = graphDisplayTimeNs(graph);
  const incoming = graph.edges.filter((edge) => edge.target === node.id);
  const outgoing = graph.edges.filter((edge) => edge.source === node.id);
  const role = node.id === state.selectedResourceId
    ? "Selected focus"
    : incoming.some((edge) => edge.source === state.selectedResourceId)
      ? "Outgoing target"
      : outgoing.some((edge) => edge.target === state.selectedResourceId) ? "Incoming dependent" : "Connected resource";
  const properties = node.state || node.properties || {};
  const entries = [
    ["Resource ID", node.id],
    ["Type", node.kind || resourceKind(node, node.id)],
    ["Layer", humanLayer(node.layer || resourceLayer(node, node.id))],
    ["Exists", node.exists ?? true],
    ["Status", node.status_value || node.status || "unknown"],
    ["At time", formatOffset(graphTimeNs)],
    ["Presentation", [...presentationTags(node)].join(", ") || "default"],
    ...Object.entries(properties).map(([key, value]) => [titleCase(key), value]),
    ["Correlation role", role],
    ["Relations", `${outgoing.length} outgoing / ${incoming.length} incoming`],
    ["Quality", node.quality || "unknown"],
  ];
  return `<div class="hover-heading"><div><span>RESOURCE STATE · ${escapeHtml(node.quality || "unknown")}</span><strong>${escapeHtml(node.label)}</strong></div></div>
    <dl class="hover-facts resource-state-hover-facts">
      ${entries.map(([key, value]) => `<dt>${escapeHtml(key)}</dt><dd>${escapeHtml(formatValue(value))}</dd>`).join("")}
    </dl>
    ${node.complete_record === false ? '<div class="resource-hover-warning"><strong>Incomplete normalized record</strong><span>This resource exists only as a relationship endpoint in the current fixture.</span></div>' : ""}`;
}

function graphEdgeHoverHtml(edge, nodes) {
  const graphTimeNs = graphDisplayTimeNs();
  const source = nodes.get(edge.source);
  const target = nodes.get(edge.target);
  const start = edge.valid_from_ns === null || edge.valid_from_ns === undefined ? "open" : formatOffset(toNs(edge.valid_from_ns));
  const end = edge.valid_to_ns === null || edge.valid_to_ns === undefined ? "open" : formatOffset(toNs(edge.valid_to_ns));
  return `<div class="hover-heading"><div><span>RELATIONSHIP</span><strong>${escapeHtml(titleCase(edge.type))}</strong></div></div>
    <dl class="hover-facts">
      <dt>Source</dt><dd>${escapeHtml(source?.label || edge.source)}<small>${escapeHtml(edge.source)}</small></dd>
      <dt>Target</dt><dd>${escapeHtml(target?.label || edge.target)}<small>${escapeHtml(edge.target)}</small></dd>
      <dt>Direction</dt><dd>${escapeHtml(`${edge.source} → ${edge.target}`)}</dd>
      <dt>Validity</dt><dd>${escapeHtml(start)} to ${escapeHtml(end)}</dd>
      <dt>At time</dt><dd>${escapeHtml(formatOffset(graphTimeNs))}</dd>
      <dt>Quality</dt><dd>${escapeHtml(edge.quality || "unknown")}<small>${escapeHtml(edge.provenance || "unknown provenance")}</small></dd>
    </dl>`;
}

function renderCorrelationList(graph) {
  const container = byId("correlation-list");
  const graphTimeNs = graphDisplayTimeNs(graph);
  const nodes = new Map(graph.nodes.map((node) => [node.id, node]));
  const resourceName = (id) => nodes.get(id)?.label || resourceLabel(state.resourceById.get(id), id);
  const resourceDetails = (id) => {
    const node = nodes.get(id) || state.resourceById.get(id) || {};
    return `${humanResourceType(node.kind || resourceKind(node, id))} / ${humanLayer(node.layer || resourceLayer(node, id))}`;
  };
  const renderItems = (edges, direction) => edges.slice(0, 30).map((edge) => {
    const otherId = direction === "outgoing" ? edge.target : edge.source;
    const arrow = direction === "outgoing" ? "→" : "←";
    const directionCopy = direction === "outgoing"
      ? "Selected resource points to this resource"
      : "This resource points to the selected resource";
    return `<details class="correlation-item ${direction}">
      <summary>
        <span class="correlation-direction" aria-hidden="true">${arrow}</span>
        <span class="correlation-resource"><strong>${escapeHtml(resourceName(otherId))}</strong><small>${escapeHtml(resourceDetails(otherId))}</small></span>
        <span class="correlation-relation" tabindex="0" data-correlation-edge-id="${escapeHtml(edge.id)}">${escapeHtml(titleCase(edge.type))}</span>
      </summary>
      <div class="correlation-item-body">
        <span>${escapeHtml(directionCopy)}</span>
        <code>${escapeHtml(`${edge.source} → ${edge.target}`)}</code>
        <span>Quality: ${escapeHtml(edge.quality || "unknown")}${edge.provenance ? ` / ${escapeHtml(edge.provenance)}` : ""}</span>
        <button type="button" data-resource-id="${escapeHtml(otherId)}">Ctrl-click to timeline</button>
      </div>
    </details>`;
  }).join("");
  const renderGroup = (kind, title, description, edges) => `<details class="correlation-group ${kind}" open>
    <summary><span><strong>${escapeHtml(title)}</strong><small>${escapeHtml(description)}</small></span><b>${edges.length}</b></summary>
    <div class="correlation-items">${renderItems(edges, kind) || '<p>No resources in this direction at the selected time.</p>'}</div>
  </details>`;

  if (!state.selectedResourceId) {
    container.innerHTML = `<div class="correlation-heading"><strong>Active relationships</strong><span>${graph.edges.length} at ${escapeHtml(formatOffset(graphTimeNs))}</span></div><div class="correlation-rows">${graph.edges.slice(0, 30).map((edge) => `<div><button type="button" data-resource-id="${escapeHtml(edge.source)}">${escapeHtml(resourceName(edge.source))}</button><span tabindex="0" data-correlation-edge-id="${escapeHtml(edge.id)}">${escapeHtml(titleCase(edge.type))} →</span><button type="button" data-resource-id="${escapeHtml(edge.target)}">${escapeHtml(resourceName(edge.target))}</button></div>`).join("") || '<p>No active relationship is visible at this time.</p>'}</div>`;
  } else {
    const outgoing = graph.edges.filter((edge) => edge.source === state.selectedResourceId);
    const incoming = graph.edges.filter((edge) => edge.target === state.selectedResourceId);
    container.innerHTML = `<div class="correlation-heading"><strong>Relationship index</strong><span>${outgoing.length + incoming.length} at ${escapeHtml(formatOffset(graphTimeNs))}</span></div>
      <div class="correlation-root"><span>Selected focus</span><strong>${escapeHtml(resourceName(state.selectedResourceId))}</strong><code>${escapeHtml(state.selectedResourceId)}</code></div>
      <div class="correlation-groups">
        ${renderGroup("outgoing", "Depends on / owns", "Selected resource points to these targets", outgoing)}
        ${renderGroup("incoming", "Dependents", "These resources point to the selected resource", incoming)}
      </div>`;
  }
  container.querySelectorAll("[data-resource-id]").forEach((button) => {
    button.addEventListener("click", (event) => {
      if (event.ctrlKey || event.metaKey) {
        event.preventDefault();
        jumpToTimelineResource(button.dataset.resourceId);
      }
    });
    const node = nodes.get(button.dataset.resourceId);
    if (node) bindCorrelationHover(button, () => graphNodeHoverHtml(node, graph));
  });
  const edges = new Map(graph.edges.map((edge) => [String(edge.id), edge]));
  container.querySelectorAll("[data-correlation-edge-id]").forEach((tag) => {
    const edge = edges.get(tag.dataset.correlationEdgeId);
    if (edge) bindCorrelationHover(tag, () => graphEdgeHoverHtml(edge, nodes));
  });
}

function syncGraphScopeButton() {
  const button = byId("graph-scope-toggle");
  if (!button) return;
  button.disabled = !state.selectedResourceId;
  button.textContent = !state.selectedResourceId
    ? "All correlations"
    : state.graphShowFull ? "Focus selected" : "Show all correlations";
}

function graphColumnHeadingsHtml(layout) {
  return '<div class="graph-column-headings" aria-hidden="true">' + layout.columns.map((column) => (
    '<span class="graph-column-heading" style="left:' + column.x + '%">'
      + '<strong>' + escapeHtml(column.label) + '<b>' + column.count + '</b></strong>'
      + '<small>' + escapeHtml(column.detail) + '</small>'
      + '</span>'
  )).join("") + "</div>";
}

function graphEdgeGeometry(edge, positions, height, stageWidth, edgeIndex) {
  const source = positions.get(edge.source);
  const target = positions.get(edge.target);
  if (!source || !target) return null;
  const sourceX = (source.x / 100) * stageWidth;
  const targetX = (target.x / 100) * stageWidth;
  const sourceY = (source.y / 100) * height;
  const targetY = (target.y / 100) * height;
  const horizontalDirection = Math.sign(targetX - sourceX);
  if (!horizontalDirection) {
    const side = sourceX < stageWidth / 2 ? 1 : -1;
    const nodeEdge = sourceX + side * 96;
    const gutter = Math.max(24, Math.min(stageWidth - 24, nodeEdge + side * (42 + (edgeIndex % 4) * 16)));
    return {
      path: "M " + nodeEdge + " " + sourceY + " C " + gutter + " " + sourceY + ", " + gutter + " " + targetY + ", " + nodeEdge + " " + targetY,
      labelX: gutter,
      labelY: (sourceY + targetY) / 2 - 9,
    };
  }
  const halfNode = Math.min(102, Math.max(68, stageWidth * 0.068));
  const sourceEdgeX = sourceX + horizontalDirection * halfNode;
  const targetEdgeX = targetX - horizontalDirection * halfNode;
  const middleX = (sourceEdgeX + targetEdgeX) / 2;
  const labelOffset = ((edgeIndex % 3) - 1) * 9;
  return {
    path: "M " + sourceEdgeX + " " + sourceY + " C " + middleX + " " + sourceY + ", " + middleX + " " + targetY + ", " + targetEdgeX + " " + targetY,
    labelX: middleX,
    labelY: (sourceY + targetY) / 2 - 10 + labelOffset,
  };
}

function setGraphInspection(stage, graph, resourceId) {
  stage.classList.toggle("is-inspecting", Boolean(resourceId));
  const edgeIds = new Set();
  const nodeIds = new Set(resourceId ? [resourceId] : []);
  if (resourceId) {
    graph.edges.forEach((edge) => {
      if (edge.source !== resourceId && edge.target !== resourceId) return;
      edgeIds.add(String(edge.id));
      nodeIds.add(edge.source);
      nodeIds.add(edge.target);
    });
  }
  stage.querySelectorAll(".graph-node").forEach((node) => {
    node.classList.toggle("is-active", nodeIds.has(node.dataset.resourceId));
  });
  stage.querySelectorAll("[data-graph-edge-id]").forEach((edge) => {
    edge.classList.toggle("is-active", edgeIds.has(edge.dataset.graphEdgeId));
  });
}

function renderGraph() {
  const fullGraph = normalizedGraph();
  const graphTimeNs = graphDisplayTimeNs(fullGraph);
  renderCorrelationTimeState();
  syncGraphScopeButton();
  updateCorrelationState(fullGraph);
  const graph = scopedGraph(fullGraph);
  const stage = byId("graph-stage");
  if (!graph.nodes.length) {
    stage.innerHTML = '<div class="empty-state">No correlated resources exist at this time.</div>';
    stage.style.minHeight = "220px";
    byId("graph-legend").innerHTML = "";
    byId("graph-note").textContent = state.selectedResourceId
      ? `The selected resource does not exist at ${formatOffset(graphTimeNs)}. Show the full graph to inspect other active resources.`
      : `0 resources / 0 time-valid relationships / selected moment ${formatOffset(graphTimeNs)}.`;
    byId("correlation-list").innerHTML = `<div class="correlation-heading"><strong>No active correlation</strong><span>${escapeHtml(formatOffset(graphTimeNs))}</span></div><p class="correlation-empty-message">${state.selectedResourceId ? "The selected focus is outside its lifecycle at this moment." : "No resource relationships are active at this moment."}</p>`;
    return;
  }
  const layout = graphLayout(graph);
  const { positions, height } = layout;
  const layers = [...new Set(graph.nodes.map((node) => node.layer || "unknown"))];
  stage.style.minHeight = `${height}px`;
  stage.classList.remove("mode-focus", "mode-full", "is-inspecting");
  stage.classList.add(`mode-${layout.mode}`);
  byId("graph-legend").innerHTML = layers.map((layer) => `<span style="color:${layerColor(layer)}">${escapeHtml(humanLayer(layer))}</span>`).join("");
  const svg = `<svg class="graph-edge-layer" viewBox="0 0 1000 ${height}" preserveAspectRatio="none" aria-hidden="true"><defs><marker id="arrowhead" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto"><path d="M0,0 L7,3.5 L0,7 Z" fill="#557283"></path></marker></defs>${graph.edges.map((edge) => {
    const source = positions.get(edge.source); const target = positions.get(edge.target);
    if (!source || !target) return "";
    const x1 = source.x * 10; const x2 = target.x * 10; const y1 = source.y / 100 * height; const y2 = target.y / 100 * height; const mid = (x1 + x2) / 2;
    const direction = edge.source === state.selectedResourceId ? " outgoing" : edge.target === state.selectedResourceId ? " incoming" : "";
    return `<path class="graph-edge${direction}${edge.temporal_note ? " dynamic" : ""}" d="M ${x1} ${y1} C ${mid} ${y1}, ${mid} ${y2}, ${x2} ${y2}"><title>${escapeHtml(`${edge.source} → ${edge.target} / ${edge.type} / ${edge.quality || "unknown"}`)}</title></path><text class="graph-edge-label${direction}" data-correlation-edge-id="${escapeHtml(edge.id)}" x="${mid}" y="${(y1 + y2) / 2 - 4}">${escapeHtml(edge.type)}</text>`;
  }).join("")}</svg>`;
  const nodeHtml = graph.nodes.map((node) => {
    const position = positions.get(node.id); const compact = isCompact(node); const selected = node.id === state.selectedResourceId;
    const outgoingTarget = graph.edges.some((edge) => edge.source === state.selectedResourceId && edge.target === node.id);
    const incomingSource = graph.edges.some((edge) => edge.target === state.selectedResourceId && edge.source === node.id);
    const role = selected ? "focus" : incomingSource ? "dependent" : outgoingTarget ? "dependency" : "";
    const roleLabel = role === "dependent" ? "Dependent" : role === "dependency" ? "Depends on / owned" : role === "focus" ? "Selected" : "";
    const customIcon = resourceIconMarkup(node, node.kind, "graph-resource-icon");
    return `<button class="graph-node${compact ? " compact" : ""}${String(node.status).match(/error|fail|down/i) ? " error" : ""}${selected ? " selected" : ""}${role ? ` role-${role}` : ""}" type="button" data-resource-id="${escapeHtml(node.id)}" style="left:${position.x}%;top:${position.y}%;--node-color:${layerColor(node.layer)}">${roleLabel ? `<span class="node-role">${escapeHtml(roleLabel)}</span>` : ""}<span class="graph-node-kindline">${customIcon}<span class="node-kind">${escapeHtml(`${humanLayer(node.layer)} / ${node.kind}`)}</span></span><strong>${escapeHtml(node.label)}</strong><small class="node-status">${escapeHtml(node.status_value || node.status || "unknown")}${node.complete_record === false ? " / endpoint only" : ""}</small></button>`;
  }).join("");
  stage.innerHTML = graphColumnHeadingsHtml(layout) + svg + nodeHtml;
  const stageWidth = Math.max(1, stage.clientWidth);
  const edgeLayer = stage.querySelector(".graph-edge-layer");
  if (edgeLayer) edgeLayer.setAttribute("viewBox", "0 0 " + stageWidth + " " + height);
  const edgePaths = [...stage.querySelectorAll(".graph-edge")];
  const edgeLabels = [...stage.querySelectorAll(".graph-edge-label")];
  graph.edges.forEach((edge, index) => {
    const geometry = graphEdgeGeometry(edge, positions, height, stageWidth, index);
    const path = edgePaths[index];
    const label = edgeLabels[index];
    if (!geometry || !path || !label) return;
    path.setAttribute("d", geometry.path);
    path.dataset.graphEdgeId = String(edge.id);
    label.setAttribute("x", String(geometry.labelX));
    label.setAttribute("y", String(geometry.labelY));
    label.dataset.graphEdgeId = String(edge.id);
  });
  if (layout.mode === "full" && state.selectedResourceId) {
    const focusEdgeIds = new Set();
    const focusNodeIds = new Set([state.selectedResourceId]);
    graph.edges.forEach((edge) => {
      if (edge.source !== state.selectedResourceId && edge.target !== state.selectedResourceId) return;
      focusEdgeIds.add(String(edge.id));
      focusNodeIds.add(edge.source);
      focusNodeIds.add(edge.target);
    });
    stage.querySelectorAll(".graph-node").forEach((node) => {
      node.classList.toggle("graph-context", !focusNodeIds.has(node.dataset.resourceId));
    });
    [...edgePaths, ...edgeLabels].forEach((edge) => {
      edge.classList.toggle("graph-context", !focusEdgeIds.has(edge.dataset.graphEdgeId));
    });
  }
  const graphNodes = new Map(graph.nodes.map((node) => [node.id, node]));
  stage.querySelectorAll(".graph-node").forEach((button) => {
    button.addEventListener("click", (event) => {
      if (event.ctrlKey || event.metaKey) {
        event.preventDefault();
        jumpToTimelineResource(button.dataset.resourceId);
      }
    });
    const node = graphNodes.get(button.dataset.resourceId);
    if (node) {
      bindCorrelationHover(button, () => graphNodeHoverHtml(node, graph));
      button.addEventListener("pointerenter", () => setGraphInspection(stage, graph, node.id));
      button.addEventListener("pointerleave", () => setGraphInspection(stage, graph, null));
      button.addEventListener("focus", () => setGraphInspection(stage, graph, node.id));
      button.addEventListener("blur", () => setGraphInspection(stage, graph, null));
    }
  });
  const graphEdges = new Map(graph.edges.map((edge) => [String(edge.id), edge]));
  stage.querySelectorAll("[data-correlation-edge-id]").forEach((tag) => {
    const edge = graphEdges.get(tag.dataset.correlationEdgeId);
    if (edge) bindCorrelationHover(tag, () => graphEdgeHoverHtml(edge, graphNodes));
  });
  const hiddenCopy = graph.hidden_isolated_count
    ? ` ${graph.hidden_isolated_count} active resources without a current relationship are omitted.`
    : "";
  const directionCopy = layout.mode === "focus"
    ? " Left-side resources point to the selected resource; the selected resource points to the right side."
    : " Arrows run from source to target by dependency step. Hover a resource to isolate its immediate connections and reveal relationship types.";
  byId("graph-note").textContent = `${graph.nodes.length} correlated resources / ${graph.edges.length} time-valid relationships / selected moment ${formatOffset(graphTimeNs)}.${hiddenCopy}${directionCopy}`;
  renderCorrelationList(graph);
}

function drawTimelineCorrelationOverlay() {
  const content = byId("timeline-content");
  content.querySelector(".timeline-correlation-overlay")?.remove();
  if (state.correlationTimelineView !== "separate" || !state.selectedResourceId || !state.activeCorrelationEdges.length) return;
  const rows = [...content.querySelectorAll(".timeline-row[data-resource-id]")];
  const selectedRow = rows.find((row) => row.dataset.resourceId === state.selectedResourceId && row.classList.contains("tree-root"))
    || rows.find((row) => row.dataset.resourceId === state.selectedResourceId);
  if (!selectedRow) return;
  const rowById = new Map();
  rows.forEach((row) => {
    const directlyAppended = row.dataset.parentResourceId === state.selectedResourceId;
    if (directlyAppended || !rowById.has(row.dataset.resourceId)) rowById.set(row.dataset.resourceId, row);
  });
  const cursorX = LANE_WIDTH + ratioBetween(state.cursorNs) * state.trackWidth;
  const paths = [];
  const labels = [];
  let visibleIndex = 0;
  for (const edge of state.activeCorrelationEdges) {
    const otherId = edge.source === state.selectedResourceId ? edge.target : edge.source;
    const otherRow = rowById.get(otherId);
    if (!otherRow) continue;
    const y1 = selectedRow.offsetTop + selectedRow.offsetHeight / 2;
    const y2 = otherRow.offsetTop + otherRow.offsetHeight / 2;
    const x = cursorX + ((visibleIndex % 5) - 2) * 5;
    const controlX = x + (visibleIndex % 2 ? 26 : -26);
    paths.push(`<path class="timeline-correlation-link quality-${safeClass(edge.quality)}${edge.temporal_note?.includes("without") ? " uncertain" : ""}" d="M ${x} ${y1} C ${controlX} ${y1}, ${controlX} ${y2}, ${x} ${y2}"></path>`);
    labels.push(`<text x="${controlX}" y="${(y1 + y2) / 2 - 4}">${escapeHtml(edge.type)}</text>`);
    visibleIndex += 1;
  }
  if (!paths.length) return;
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("class", "timeline-correlation-overlay");
  svg.setAttribute("width", String(content.scrollWidth));
  svg.setAttribute("height", String(content.scrollHeight));
  svg.setAttribute("viewBox", `0 0 ${content.scrollWidth} ${content.scrollHeight}`);
  svg.innerHTML = paths.join("") + labels.join("");
  content.appendChild(svg);
}

function selectResource(resourceId) {
  if (!resourceId) return;
  const focusChanged = state.selectedResourceId !== resourceId;
  state.selectedResourceId = resourceId;
  const record = state.resourceQuery?.items?.find((item) => item.resource_id === resourceId) || state.resourceById.get(resourceId);
  if (record) state.selectedResourceKind = record.kind || resourceKind(record, resourceId);
  if (focusChanged) {
    state.activeCorrelationEdges = [];
    state.correlatedResourceIds.clear();
  }
  if (isScaleMode() && !state.laneByResource.has(resourceId)) {
    state.laneMode = "custom";
    if (state.explicitLaneIds.size >= MAX_SCALE_TIMELINE_LANES) state.explicitLaneIds.delete(state.explicitLaneIds.values().next().value);
    state.explicitLaneIds.add(resourceId);
    refreshScaleTimeline();
  }
  markCorrelationPending(state.cursorNs);
  rerenderTimelinePreservingScroll();
  renderResourceTables();
  renderPluginDashboards();
  if (state.graph) renderGraph();
  requestGraph();
}

function selectGraphNode(nodeId) {
  selectResource(nodeId);
}

function renderLayerToggles() {
  const container = byId("layer-toggles");
  container.innerHTML = [...state.layerMeta.keys()].map((layer) => `<button class="layer-toggle" type="button" data-layer="${escapeHtml(layer)}" aria-pressed="${state.activeLayers.has(layer)}" style="--layer-color:${layerColor(layer)}">${escapeHtml(humanLayer(layer))}</button>`).join("");
  container.querySelectorAll(".layer-toggle").forEach((button) => button.addEventListener("click", () => {
    const layer = button.dataset.layer;
    if (state.activeLayers.has(layer) && state.activeLayers.size === 1) return showToast("Keep at least one layer visible.");
    if (state.activeLayers.has(layer)) state.activeLayers.delete(layer); else state.activeLayers.add(layer);
    renderLayerToggles(); renderTimeline();
  }));
}

function currentModeLaneIds() {
  return new Set(state.lanes.filter((lane) => laneSelectedByMode(lane.resourceId)).map((lane) => lane.resourceId));
}

async function refreshScaleTimeline() {
  await requestTimeline();
  state.lanes.forEach((lane) => {
    layerConfig(lane.layer);
    state.activeLayers.add(lane.layer);
  });
  renderLayerToggles();
  renderTimeline();
  renderResourceTables();
}

function setLaneMode(mode) {
  if (["selected", "correlated"].includes(mode) && !state.selectedResourceId) {
    showToast("Select a resource first.");
    return;
  }
  state.laneMode = mode;
  if (mode === "all") {
    state.explicitLaneIds = new Set(isScaleMode() ? initialScaleLaneIds() : state.lanes.map((lane) => lane.resourceId));
    if (isScaleMode()) showToast("Showing representative lanes from the 100K catalog. Search Lanes to add any resource.");
  }
  if (mode === "custom" && !state.explicitLaneIds.size) state.explicitLaneIds = currentModeLaneIds();
  if (isScaleMode()) refreshScaleTimeline();
  else {
    renderTimeline();
    renderResourceTables();
  }
}

function setExplicitLaneVisibility(resourceId, visible) {
  if (state.laneMode !== "custom") state.explicitLaneIds = currentModeLaneIds();
  state.laneMode = "custom";
  if (isScaleMode() && visible && !state.explicitLaneIds.has(resourceId) && state.explicitLaneIds.size >= MAX_SCALE_TIMELINE_LANES) {
    showToast(`A full-scale timeline can show up to ${MAX_SCALE_TIMELINE_LANES} lanes at once.`);
    return;
  }
  if (visible) state.explicitLaneIds.add(resourceId);
  else state.explicitLaneIds.delete(resourceId);
  if (isScaleMode()) refreshScaleTimeline();
  else {
    renderTimeline();
    renderResourceTables();
  }
}

function validateRecordLanePattern(pattern) {
  const value = String(pattern || "");
  if (!value || value.length > MAX_RECORD_PATTERN_LENGTH) {
    return "Regex must contain 1 to " + MAX_RECORD_PATTERN_LENGTH + " characters.";
  }
  if (value.includes("(?") || /\\[1-9]/.test(value)) {
    return "Lookarounds, regex extensions, and backreferences are not supported.";
  }
  if (/\([^)]*[*+{][^)]*\)\s*(?:[*+]|\{\d+(?:,\d*)?\})/.test(value)
    || /(?:[*+]|\{\d+(?:,\d*)?\})\s*(?:[*+]|\{\d+(?:,\d*)?\})/.test(value)) {
    return "Repeated quantifiers are not supported.";
  }
  try {
    new RegExp(value);
  } catch (error) {
    return "Invalid regex: " + error.message;
  }
  return "";
}

async function refreshRecordLanes() {
  await requestTimeline();
  renderTimeline();
}

function setRecordLanePreset(laneId, enabled) {
  const preset = state.recordLanePresets.find((item) => String(item.lane_id) === String(laneId));
  if (!preset) return;
  state.recordLaneRules = state.recordLaneRules.filter((rule) => String(rule.lane_id) !== String(laneId));
  if (enabled) {
    if (state.recordLaneRules.length >= MAX_RECORD_LANES) {
      showToast("A timeline can show up to " + MAX_RECORD_LANES + " source-record lanes.");
      renderRecordLaneManager();
      return;
    }
    state.recordLaneRules.push({ ...preset, plugin_defined: true });
  }
  refreshRecordLanes();
}

function removeRecordLane(laneId) {
  state.recordLaneRules = state.recordLaneRules.filter((rule) => String(rule.lane_id) !== String(laneId));
  refreshRecordLanes();
}

function renderRecordLaneManager() {
  const list = byId("record-lane-list");
  if (!list) return;
  byId("record-lane-count").textContent = state.recordLaneRules.length + " / " + MAX_RECORD_LANES;
  const activeIds = new Set(state.recordLaneRules.map((rule) => String(rule.lane_id)));
  const presetRows = state.recordLanePresets.map((preset) => `<label class="record-lane-item preset">
    <input type="checkbox" data-record-lane-preset="${escapeHtml(preset.lane_id)}" ${activeIds.has(String(preset.lane_id)) ? "checked" : ""} />
    <span><strong>${escapeHtml(preset.label)}</strong><small>${escapeHtml((preset.unmatched_only ? "unmatched · " : "") + preset.pattern)}</small></span>
    <i>plug-in</i>
  </label>`).join("");
  const customRows = state.recordLaneRules
    .filter((rule) => !rule.plugin_defined)
    .map((rule) => `<div class="record-lane-item custom">
      <span class="record-lane-active-dot" aria-hidden="true"></span>
      <span><strong>${escapeHtml(rule.label)}</strong><small>${escapeHtml((rule.unmatched_only ? "unmatched · " : "") + rule.pattern)}</small></span>
      <button type="button" data-remove-record-lane="${escapeHtml(rule.lane_id)}" aria-label="Remove ${escapeHtml(rule.label)}">Remove</button>
    </div>`).join("");
  list.innerHTML = presetRows + customRows || '<p class="lane-picker-empty">No source-record lane presets are available.</p>';
  list.querySelectorAll("[data-record-lane-preset]").forEach((input) => {
    input.addEventListener("change", () => setRecordLanePreset(input.dataset.recordLanePreset, input.checked));
  });
  list.querySelectorAll("[data-remove-record-lane]").forEach((button) => {
    button.addEventListener("click", () => removeRecordLane(button.dataset.removeRecordLane));
  });
  const sourceSelect = byId("record-lane-source");
  const selected = sourceSelect.value;
  sourceSelect.innerHTML = '<option value="">All retained sources</option>' + [...state.sourceRecordTypes.values()]
    .map((descriptor) => `<option value="${escapeHtml(descriptor.source_type)}">${escapeHtml(descriptor.label)}</option>`)
    .join("");
  sourceSelect.value = state.sourceRecordTypes.has(selected) ? selected : "";
}

function addRecordLane(event) {
  event.preventDefault();
  const label = byId("record-lane-label").value.trim();
  const pattern = byId("record-lane-pattern").value.trim();
  const error = validateRecordLanePattern(pattern);
  const errorBox = byId("record-lane-error");
  if (!label) {
    errorBox.textContent = "Give the lane a name.";
    return;
  }
  if (error) {
    errorBox.textContent = error;
    return;
  }
  if (state.recordLaneRules.length >= MAX_RECORD_LANES) {
    errorBox.textContent = "Remove a lane before adding another.";
    return;
  }
  const sourceType = byId("record-lane-source").value;
  state.recordLaneRules.push({
    lane_id: "custom-record-" + (++state.customRecordLaneSequence),
    label,
    pattern,
    source_types: sourceType ? [sourceType] : [],
    unmatched_only: byId("record-lane-unmatched").checked,
    case_sensitive: false,
    plugin_defined: false,
  });
  errorBox.textContent = "";
  byId("record-lane-form").reset();
  refreshRecordLanes();
}

function renderLanePicker() {
  const list = byId("lane-picker-list");
  if (!list) return;
  const visibleCount = visibleTimelineLanes().length;
  const combined = state.correlationTimelineView === "combined" && state.selectedResourceId;
  const catalog = isScaleMode() ? state.resourceCatalogLanes : state.lanes;
  byId("visible-lane-count").textContent = (combined ? "2 combined" : `${visibleCount} / ${catalog.length.toLocaleString()}`)
    + " · " + state.recordLaneRules.length + " logs";
  byId("lane-picker-toggle").disabled = false;
  byId("lane-picker-toggle").title = combined
    ? "Switch to Separate to choose canonical lanes"
    : state.correlatedResourceIds.size
      ? `${state.correlatedResourceIds.size} resources correlate with the selected resource at ${formatOffset(state.cursorNs)}`
      : "Choose which canonical resource lanes to display";
  const needle = state.laneFilterText.trim().toLowerCase();
  const matching = catalog.filter((candidate) => {
    if (!needle) return true;
    const resourceId = candidate.resourceId || resourceIdOf(candidate);
    return [
      candidate.label || resourceLabel(candidate, resourceId),
      resourceId,
      candidate.kind || resourceKind(candidate, resourceId),
      candidate.layer || resourceLayer(candidate, resourceId),
    ].join(" ").toLowerCase().includes(needle);
  });
  const filtered = matching
    .slice(0, isScaleMode() ? MAX_LANE_PICKER_ROWS : matching.length)
    .map((candidate) => {
      if (candidate.resourceId) return candidate;
      const resourceId = resourceIdOf(candidate);
      return {
        resourceId,
        label: resourceLabel(candidate, resourceId),
        kind: resourceKind(candidate, resourceId),
        layer: resourceLayer(candidate, resourceId),
        resource: candidate,
      };
    });
  const groups = new Map();
  filtered.forEach((lane) => {
    if (!groups.has(lane.kind)) groups.set(lane.kind, []);
    groups.get(lane.kind).push(lane);
  });
  const windowNote = isScaleMode() && matching.length > filtered.length
    ? `<p class="lane-picker-empty">Showing ${filtered.length.toLocaleString()} of ${matching.length.toLocaleString()} matches. Refine the search to reach another resource.</p>`
    : "";
  list.innerHTML = windowNote + ([...groups.entries()].map(([kind, lanes]) => `<fieldset><legend>${escapeHtml(titleCase(kind))}<span>${lanes.length}</span></legend>${lanes.map((lane) => `<label><input type="checkbox" data-lane-resource-id="${escapeHtml(lane.resourceId)}" ${laneSelectedByMode(lane.resourceId) ? "checked" : ""}><span><strong>${escapeHtml(lane.label)}</strong><small>${escapeHtml(`${humanLayer(lane.layer)} / ${lane.resourceId}`)}</small></span>${state.correlatedResourceIds.has(lane.resourceId) ? '<i>related</i>' : ""}</label>`).join("")}</fieldset>`).join("") || '<p class="lane-picker-empty">No resources match this search.</p>');
  list.querySelectorAll("[data-lane-resource-id]").forEach((input) => input.addEventListener("change", () => setExplicitLaneVisibility(input.dataset.laneResourceId, input.checked)));
  document.querySelectorAll("[data-lane-action]").forEach((button) => {
    button.disabled = Boolean(
      combined
      || (["selected", "correlated"].includes(button.dataset.laneAction) && !state.selectedResourceId),
    );
  });
  renderRecordLaneManager();
}

function fillSummary() {
  const dataset = state.dataset;
  const revision = dataset.demo?.revision_id || "synthetic";
  const matchedEventCount = Number(
    dataset.demo?.matched_event_count ?? dataset.demo?.event_count ?? 0,
  );
  byId("revision-id").textContent = isScaleMode()
    ? `${revision} · ${matchedEventCount.toLocaleString()} matched events · ${Number(dataset.demo.resource_count || 0).toLocaleString()} resources`
    : revision;
  byId("disclosure-text").textContent = dataset.demo?.disclosure || "Synthetic review fixture.";
  byId("gap-count").textContent = dataset.gaps?.length || 0;
  byId("metric-artifacts").textContent = dataset.summary?.parse?.artifacts ?? dataset.inventory?.members?.length ?? 0;
  byId("metric-parse").textContent = `${dataset.summary?.parse?.errors ?? 0} parse errors / ${dataset.summary?.parse?.skipped ?? 0} skipped`;
  byId("metric-fail").textContent = dataset.summary?.consistency?.fail ?? (dataset.findings || []).filter((item) => item.result === "fail").length;
  byId("metric-consistency").textContent = `${dataset.summary?.consistency?.pass ?? 0} pass / ${dataset.summary?.consistency?.unknown ?? 0} unknown`;
  byId("metric-exact").textContent = dataset.coverage?.exact_outputs ?? "-";
  byId("metric-coverage").textContent = `${dataset.coverage?.best_effort_outputs ?? 0} best effort`;
  byId("metric-unknown").textContent = dataset.coverage?.unknown_outputs ?? 0;
}

function renderIncidentSummary() {
  const failures = [...state.eventByUid.values()].filter(eventFailed);
  const selected = (failures.length ? failures : [...state.eventByUid.values()].slice(-2)).slice(0, 3);
  byId("incident-chain").innerHTML = `<div class="chain-heading"><span>Highlighted event chain</span><span class="chain-latency">${selected.length} observations</span></div>${selected.map((event, index) => {
    const subject = eventSubject(event); const uid = event.event_uid || event.event_id;
    return `${index ? '<div class="chain-arrow" aria-hidden="true">down</div>' : ""}<button class="chain-node" style="--chain-color:${layerColor(subject.layer)}" data-event-uid="${escapeHtml(uid)}" type="button"><span>${escapeHtml(humanLayer(subject.layer))}</span><strong>${escapeHtml(subject.raw_key || event.event_type)}</strong><small>${escapeHtml(`${event.action || event.operation || "event"} / ${eventFailed(event) ? "failed" : event.outcome || "success"}`)}</small></button>`;
  }).join("")}`;
  byId("incident-chain").querySelectorAll("[data-event-uid]").forEach((button) => button.addEventListener("click", () => { selectEvent(button.dataset.eventUid, true); byId("timeline").scrollIntoView({ behavior: "smooth", block: "start" }); }));
}

function renderFindings() {
  const findings = state.dataset.findings || [];
  const counts = { pass: 0, fail: 0, unknown: 0 };
  findings.forEach((finding) => { counts[finding.result] = (counts[finding.result] || 0) + 1; });
  byId("finding-summary").innerHTML = ["pass", "fail", "unknown"].map((result) => `<span class="${result}">${counts[result]} ${result}</span>`).join("");
  byId("findings-grid").innerHTML = findings.map((finding) => `<article class="finding-card"><span class="finding-result ${escapeHtml(finding.result)}">${escapeHtml(finding.result)}</span><div><h3>${escapeHtml(titleCase(finding.rule_id))}</h3><p>${escapeHtml(finding.summary)}</p><code>${escapeHtml((finding.resources || []).join(" / "))}</code></div></article>`).join("") || '<div class="empty-state">No consistency findings in this fixture.</div>';
}

function renderInventory() {
  const inventory = state.dataset.inventory || { members: [] };
  const nested = inventory.members.filter((item) => item.kind === "nested-archive").length;
  byId("inventory-summary").textContent = `${inventory.archive || "fixture"} / ${formatBytes(inventory.compressed_size)} / ${inventory.members.length} top-level files / ${nested} nested archives`;
  byId("inventory-tree").innerHTML = inventory.members.map((item) => `<div class="inventory-item"><span>${escapeHtml(item.path)}</span><small>${escapeHtml(`${item.kind} / ${formatBytes(item.size)}`)}</small></div>`).join("");
}

function explanationSteps(node, depth = 0, result = []) {
  if (!node) return result;
  result.push({ depth, text: [titleCase(node.kind), node.resource || node.resource_id, node.state ? `state=${node.state}` : null, node.relation_type].filter(Boolean).join(" / ") });
  for (const child of node.children || []) explanationSteps(child, depth + 1, result);
  return result;
}

async function resolveRoute(event) {
  event?.preventDefault();
  const form = byId("route-form");
  const data = new FormData(form);
  const result = byId("route-result");
  result.innerHTML = '<div class="empty-state">Resolving fixture response...</div>';
  try {
    const payload = await api(revisionPath("routes/resolve"), { method: "POST", body: JSON.stringify({ destination: data.get("destination"), basis_kind: data.get("basis_kind"), time_ns: state.cursorNs.toString() }) });
    const steps = explanationSteps(payload.explanation);
    result.innerHTML = `<div class="route-answer"><div><span>Matched prefix</span><strong>${escapeHtml(payload.matched_prefix || "unknown")}</strong></div><div><span>Next hop</span><strong>${escapeHtml(payload.next_hops?.join(", ") || payload.branches?.map((item) => item.next_hop).join(", ") || "unknown")}</strong></div><div><span>Egress</span><strong>${escapeHtml(payload.egress_interfaces?.join(", ") || payload.branches?.map((item) => item.egress_interface_resource_id).join(", ") || "unknown")}</strong></div></div><ol class="route-path">${steps.map((step) => `<li style="margin-left:${step.depth * 12}px">${escapeHtml(step.text)}</li>`).join("")}</ol><p class="panel-footnote">${escapeHtml(`${payload.basis?.kind || payload.basis_kind || "fixture"} / ${payload.quality || "unknown"}`)}</p>`;
  } catch (error) {
    result.innerHTML = `<div class="empty-state">${escapeHtml(error.message)}</div>`;
  }
}

function filteredEvents() {
  const layer = byId("event-layer-filter").value;
  const needle = byId("event-search").value.trim().toLowerCase();
  const source = isScaleMode()
    ? (state.dataset.events || [])
    : [...state.eventByUid.values()];
  const filtered = !layer && !needle
    ? source
    : source.filter((event) => (
      (!layer || eventSubject(event).layer === layer)
      && (!needle || JSON.stringify(event).toLowerCase().includes(needle))
    ));
  if (isScaleMode()) return filtered;
  return filtered.sort((left, right) => {
    const leftTime = eventTime(left);
    const rightTime = eventTime(right);
    if (leftTime !== rightTime) return leftTime < rightTime ? -1 : 1;
    return String(left.event_uid || left.event_id).localeCompare(String(right.event_uid || right.event_id));
  });
}

function filteredSourceRecords() {
  const layer = byId("event-layer-filter").value;
  const needle = byId("event-search").value.trim().toLowerCase();
  return state.sourceRecords.filter((record) => {
    const included = isCtfSourceRecord(record)
      ? state.eventLogInclude.ctf
      : state.eventLogInclude.external;
    if (!included) return false;
    if (layer && String(record.layer || "unknown") !== layer) return false;
    if (!needle) return true;
    return [
      record.source_record_uid,
      record.source_type,
      record.source_name,
      record.layer,
      record.record_name,
      record.message,
      record.matched_event_uid,
    ].join(" ").toLowerCase().includes(needle);
  });
}

function isSourceLogEntry(entry) {
  return entry?.source_record_uid !== undefined;
}

function logEntryId(entry) {
  return isSourceLogEntry(entry)
    ? sourceLogEntryId(sourceRecordUid(entry))
    : normalizedLogEntryId(entry.event_uid || entry.event_id);
}

function logEntryTime(entry) {
  return isSourceLogEntry(entry) ? sourceRecordTime(entry) : eventTime(entry);
}

function mergeLogEntries(events, sourceRecords) {
  const normalized = state.eventLogInclude.normalized ? events : [];
  const retained = sourceRecords;
  if (!normalized.length) return retained;
  if (!retained.length) return normalized;
  const merged = [];
  let eventIndex = 0;
  let sourceIndex = 0;
  while (eventIndex < normalized.length || sourceIndex < retained.length) {
    const eventEntry = normalized[eventIndex];
    const sourceEntry = retained[sourceIndex];
    const eventTimeNs = eventEntry ? eventTime(eventEntry) : null;
    const sourceTimeNs = sourceEntry ? sourceRecordTime(sourceEntry) : null;
    if (!sourceEntry || (eventEntry && (
      eventTimeNs < sourceTimeNs
      || (
        eventTimeNs === sourceTimeNs
        && normalizedLogEntryId(eventEntry.event_uid || eventEntry.event_id)
          .localeCompare(sourceLogEntryId(sourceRecordUid(sourceEntry))) <= 0
      )
    ))) {
      merged.push(eventEntry);
      eventIndex += 1;
    } else {
      merged.push(sourceEntry);
      sourceIndex += 1;
    }
  }
  return merged;
}

function renderEventLayerFilter() {
  const select = byId("event-layer-filter");
  const selected = select.value;
  select.innerHTML = '<option value="">All layers</option>' + [...state.layerMeta.keys()].map((layer) => `<option value="${escapeHtml(layer)}">${escapeHtml(humanLayer(layer))}</option>`).join("");
  select.value = state.layerMeta.has(selected) ? selected : "";
}

function renderEventRow(event, rangeMembership = null) {
  const subject = eventSubject(event);
  const uid = String(event.event_uid || event.event_id);
  const classes = ["event-row"];
  if (uid === state.selectedEventUid) classes.push("selected");
  if (rangeMembership === "inside") classes.push("range-included");
  return `<tr data-log-entry-id="${escapeHtml(normalizedLogEntryId(uid))}" data-event-uid="${escapeHtml(uid)}" data-range-membership="${rangeMembership || "none"}" class="${classes.join(" ")}" tabindex="0"><td>${escapeHtml(formatOffset(eventTime(event)))}</td><td><span class="log-stream-kind normalized">Normalized</span><small>${escapeHtml(humanLayer(subject.layer))}</small></td><td><code>${escapeHtml(event.event_type || event.label)}</code></td><td><code>${escapeHtml(subject.raw_key || eventResourceRefs(event)[0] || "unknown")}</code></td><td>${escapeHtml(event.action || event.operation || "observe")}</td><td><span class="outcome ${eventFailed(event) ? "failure" : "success"}">${eventFailed(event) ? "failure" : escapeHtml(event.outcome || "success")}</span></td></tr>`;
}

function renderSourceRecordRow(record, rangeMembership = null) {
  const uid = sourceRecordUid(record);
  const descriptor = sourceTypeDescriptor(record.source_type);
  const classes = ["event-row", "source-log-row"];
  if (uid === state.selectedSourceRecordUid) classes.push("selected");
  if (rangeMembership === "inside") classes.push("range-included");
  const matched = Boolean(record.matched_event_uid);
  return `<tr data-log-entry-id="${escapeHtml(sourceLogEntryId(uid))}" data-source-record-uid="${escapeHtml(uid)}" data-range-membership="${rangeMembership || "none"}" class="${classes.join(" ")}" tabindex="0" style="--source-color:${escapeHtml(descriptor.color || stableColor(record.source_type))}"><td>${escapeHtml(formatOffset(sourceRecordTime(record)))}</td><td><span class="log-stream-kind source">${escapeHtml(descriptor.label)}</span><small>${escapeHtml(humanLayer(record.layer || "unknown"))}</small></td><td><code>${escapeHtml(record.record_name || "record")}</code><small>${escapeHtml(record.source_name || "source")}</small></td><td class="source-message" title="${escapeHtml(record.message || "")}">${escapeHtml(record.message || "No decoded message")}</td><td><span class="source-match ${matched ? "matched" : "unmatched"}">${matched ? "matched" : "unmatched"}</span>${matched ? `<small>${escapeHtml(record.matched_event_uid)}</small>` : ""}</td><td><span class="outcome ${matched ? "success" : "unmatched"}">${escapeHtml(record.source_type || "source")}</span></td></tr>`;
}

function renderEventGroup(kind, title, detail) {
  return `<tr class="event-range-group ${kind}"><th colspan="6" scope="rowgroup"><span>${escapeHtml(title)}</span><small>${escapeHtml(detail)}</small></th></tr>`;
}

function virtualEventLogRows(length, rowAt) {
  return {
    length,
    slice(start, end) {
      const rows = [];
      const safeStart = Math.max(0, Math.trunc(start));
      const safeEnd = Math.min(length, Math.trunc(end));
      for (let index = safeStart; index < safeEnd; index += 1) {
        rows.push(rowAt(index));
      }
      return rows;
    },
  };
}

function rebuildEventLogRows({ resetScroll = false } = {}) {
  const events = state.eventLogInclude.normalized ? filteredEvents() : [];
  const sourceRecords = filteredSourceRecords();
  const entries = mergeLogEntries(events, sourceRecords);
  const bounds = rangeBounds();
  state.eventLogIndexById = new Map();

  if (!entries.length) {
    state.eventLogRows = virtualEventLogRows(1, () => ({
      kind: "empty",
      message: "No normalized or retained source records match these filters.",
    }));
  } else if (!bounds) {
    const group = {
      kind: "group",
      groupKind: "windowed-events",
      title: "Visible stream",
      detail: entries.length.toLocaleString() + " matching records · virtualized scrolling",
    };
    entries.forEach((entry, index) => {
      state.eventLogIndexById.set(logEntryId(entry), index + 1);
    });
    state.eventLogRows = virtualEventLogRows(
      entries.length + 1,
      (index) => index === 0
        ? group
        : { kind: "entry", entry: entries[index - 1], membership: null },
    );
  } else {
    const included = [];
    const excluded = [];
    entries.forEach((entry) => (
      inSelectedRange(logEntryTime(entry)) ? included : excluded
    ).push(entry));
    const selectedBodyRows = Math.max(1, included.length);
    const outsideGroupIndex = 1 + selectedBodyRows;
    const totalRows = outsideGroupIndex + (excluded.length ? 1 + excluded.length : 0);
    const selectedGroup = {
      kind: "group",
      groupKind: "selected-period",
      title: "Selected period",
      detail: formatOffset(bounds[0]) + " to " + formatOffset(bounds[1]) + " · "
        + included.length.toLocaleString() + " matching "
        + (included.length === 1 ? "record" : "records"),
    };
    const outsideGroup = {
      kind: "group",
      groupKind: "other-events",
      title: "Other records",
      detail: excluded.length.toLocaleString() + " outside the selected period",
    };
    included.forEach((entry, index) => {
      state.eventLogIndexById.set(logEntryId(entry), index + 1);
    });
    excluded.forEach((entry, index) => {
      state.eventLogIndexById.set(logEntryId(entry), outsideGroupIndex + index + 1);
    });
    state.eventLogRows = virtualEventLogRows(totalRows, (index) => {
      if (index === 0) return selectedGroup;
      if (included.length && index <= included.length) {
        return { kind: "entry", entry: included[index - 1], membership: "inside" };
      }
      if (!included.length && index === 1) {
        return {
          kind: "empty",
          message: "No visible records in the selected period match the current filters.",
        };
      }
      if (index === outsideGroupIndex) return outsideGroup;
      return {
        kind: "entry",
        entry: excluded[index - outsideGroupIndex - 1],
        membership: "outside",
      };
    });
  }

  const normalizedCount = events.length;
  const sourceCount = sourceRecords.length;
  byId("event-log-status").textContent = entries.length.toLocaleString() + " records · "
    + normalizedCount.toLocaleString() + " normalized · "
    + sourceCount.toLocaleString() + " retained";
  const scroll = byId("event-log-scroll");
  if (resetScroll && scroll) scroll.scrollTop = 0;
}

function renderEventLogRow(row) {
  if (row.kind === "group") return renderEventGroup(row.groupKind, row.title, row.detail);
  if (row.kind === "empty") {
    return `<tr class="event-range-empty"><td colspan="6">${escapeHtml(row.message)}</td></tr>`;
  }
  return isSourceLogEntry(row.entry)
    ? renderSourceRecordRow(row.entry, row.membership)
    : renderEventRow(row.entry, row.membership);
}

function bindVisibleEventLogRows() {
  const body = byId("event-table-body");
  body.querySelectorAll("tr[data-event-uid]").forEach((row) => {
    const choose = () => selectEvent(row.dataset.eventUid, true);
    row.addEventListener("click", (event) => {
      if (event.ctrlKey || event.metaKey) {
        event.preventDefault();
        jumpToTimelineEvent(row.dataset.eventUid);
        return;
      }
      choose();
    });
    row.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        choose();
      }
    });
  });
  body.querySelectorAll("tr[data-source-record-uid]").forEach((row) => {
    const choose = () => selectSourceRecord(row.dataset.sourceRecordUid, true);
    row.addEventListener("click", (event) => {
      if (event.ctrlKey || event.metaKey) {
        event.preventDefault();
        jumpSourceRecordToTimeline(row.dataset.sourceRecordUid);
        return;
      }
      choose();
    });
    row.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        choose();
      }
    });
  });
}

function renderEventTableWindow() {
  const scroll = byId("event-log-scroll");
  const body = byId("event-table-body");
  if (!scroll || !body) return;
  const total = state.eventLogRows.length;
  const visibleRows = Math.max(1, Math.ceil(scroll.clientHeight / EVENT_LOG_ROW_HEIGHT));
  const start = Math.max(0, Math.floor(scroll.scrollTop / EVENT_LOG_ROW_HEIGHT) - EVENT_LOG_OVERSCAN);
  const end = Math.min(total, start + visibleRows + EVENT_LOG_OVERSCAN * 2);
  const topHeight = start * EVENT_LOG_ROW_HEIGHT;
  const bottomHeight = Math.max(0, (total - end) * EVENT_LOG_ROW_HEIGHT);
  const topSpacer = topHeight
    ? `<tr class="event-log-spacer" aria-hidden="true"><td colspan="6" style="height:${topHeight}px"></td></tr>`
    : "";
  const bottomSpacer = bottomHeight
    ? `<tr class="event-log-spacer" aria-hidden="true"><td colspan="6" style="height:${bottomHeight}px"></td></tr>`
    : "";
  body.innerHTML = topSpacer
    + state.eventLogRows.slice(start, end).map(renderEventLogRow).join("")
    + bottomSpacer;
  bindVisibleEventLogRows();
}

function renderEventTable(options = {}) {
  rebuildEventLogRows(options);
  renderEventTableWindow();
}

function scheduleEventLogWindow() {
  if (state.eventLogRenderFrame !== null) return;
  state.eventLogRenderFrame = window.requestAnimationFrame(() => {
    state.eventLogRenderFrame = null;
    renderEventTableWindow();
  });
}

function syncEventLogIncludeControls() {
  byId("event-include-normalized").checked = state.eventLogInclude.normalized;
  byId("event-include-ctf").checked = state.eventLogInclude.ctf;
  byId("event-include-external").checked = state.eventLogInclude.external;
}

function jumpToLogEntry(entryId) {
  if (entryId.startsWith("event:")) state.eventLogInclude.normalized = true;
  if (entryId.startsWith("source:")) {
    const record = state.sourceRecordByUid.get(entryId.slice("source:".length));
    if (record && isCtfSourceRecord(record)) state.eventLogInclude.ctf = true;
    else if (record) state.eventLogInclude.external = true;
  }
  syncEventLogIncludeControls();
  byId("event-layer-filter").value = "";
  byId("event-search").value = "";
  renderEventTable();
  const index = state.eventLogIndexById.get(entryId);
  if (index === undefined) {
    showToast("The target record is not available in this retained stream.");
    return;
  }
  const scroll = byId("event-log-scroll");
  scroll.scrollTop = Math.max(
    0,
    index * EVENT_LOG_ROW_HEIGHT - (scroll.clientHeight - EVENT_LOG_ROW_HEIGHT) / 2,
  );
  renderEventTableWindow();
  byId("event-log").scrollIntoView({ behavior: "smooth", block: "nearest" });
  window.requestAnimationFrame(() => window.requestAnimationFrame(() => {
    const row = [...byId("event-table-body").querySelectorAll("tr[data-log-entry-id]")]
      .find((item) => item.dataset.logEntryId === entryId);
    if (!row) return;
    row.focus({ preventScroll: true });
    navigationPulse(row);
  }));
}

function loadReview() {
  try {
    const saved = JSON.parse(localStorage.getItem(REVIEW_STORAGE_KEY) || "{}");
    return { selected: Array.isArray(saved.selected) ? saved.selected : [], notes: typeof saved.notes === "string" ? saved.notes : "" };
  } catch (_error) { return { selected: [], notes: "" }; }
}

function saveReview() {
  const selected = [...document.querySelectorAll('.gap-item input[type="checkbox"]:checked')].map((input) => input.value);
  localStorage.setItem(REVIEW_STORAGE_KEY, JSON.stringify({ selected, notes: byId("review-notes").value }));
}

function renderReview() {
  const saved = loadReview();
  byId("gap-list").innerHTML = (state.dataset.gaps || []).map((gap) => `<label class="gap-item"><input type="checkbox" value="${escapeHtml(gap.id)}" ${saved.selected.includes(gap.id) ? "checked" : ""}><span><strong>${escapeHtml(gap.title)}</strong><small>${escapeHtml(`${gap.area} / ${gap.detail}`)}</small></span><span class="gap-status">${escapeHtml(gap.status)}</span></label>`).join("");
  byId("review-prompts").innerHTML = `<strong>Questions for reviewers</strong><ul>${(state.dataset.review_prompts || []).map((prompt) => `<li>${escapeHtml(prompt)}</li>`).join("")}</ul>`;
  byId("review-notes").value = saved.notes;
  byId("gap-list").querySelectorAll("input").forEach((input) => input.addEventListener("change", saveReview));
  byId("review-notes").addEventListener("input", saveReview);
}

function openReview() { byId("review-drawer").classList.add("open"); byId("review-drawer").setAttribute("aria-hidden", "false"); byId("drawer-scrim").hidden = false; document.body.classList.add("drawer-open"); byId("close-review").focus(); }
function closeReview() { byId("review-drawer").classList.remove("open"); byId("review-drawer").setAttribute("aria-hidden", "true"); byId("drawer-scrim").hidden = true; document.body.classList.remove("drawer-open"); }

function reviewText() {
  const saved = loadReview();
  const selected = (state.dataset.gaps || []).filter((gap) => saved.selected.includes(gap.id));
  return ["Router State Lab - design review", `Fixture: ${state.dataset.demo.revision_id} (synthetic)`, "", "Prioritized gaps:", ...(selected.length ? selected.map((gap) => `- [${gap.area}] ${gap.title}: ${gap.detail}`) : ["- None selected yet"]), "", "Reviewer notes:", saved.notes.trim() || "(none)"].join("\n");
}

async function copyReview() {
  const text = reviewText();
  try { await navigator.clipboard.writeText(text); }
  catch (_error) { const area = document.createElement("textarea"); area.value = text; area.style.position = "fixed"; area.style.opacity = "0"; document.body.appendChild(area); area.select(); document.execCommand("copy"); area.remove(); }
  showToast("Review summary copied.");
}

function resetTimelineView() {
  state.zoom = 1;
  state.rangeStartNs = null;
  state.rangeEndNs = null;
  state.rangeSummary = null;
  state.laneMode = isScaleMode() ? "custom" : "all";
  state.correlationTimelineExpanded = true;
  state.expandedTimelineTreeKeys.clear();
  state.explicitLaneIds = new Set(isScaleMode() ? initialScaleLaneIds() : state.lanes.map((lane) => lane.resourceId));
  state.activeLayers = new Set(state.layerMeta.keys());
  byId("timeline-zoom").value = "1";
  byId("timeline-scroll").scrollLeft = 0;
  byId("clear-range").hidden = true;
  renderLayerToggles();
  renderRangeSummary();
  if (isScaleMode()) refreshScaleTimeline();
  else renderTimeline();
  setCursor(state.viewEndNs, true, false);
}

function bindControls() {
  byId("timeline-zoom").addEventListener("input", (event) => {
    const zoom = Number(event.target.value);
    if (!Number.isFinite(zoom) || zoom < 1) return;
    if (state.brush) finishTimelinePointer(null, true);
    state.zoom = zoom;
    renderTimeline();
  });
  byId("range-mode").addEventListener("click", () => { state.rangeMode = !state.rangeMode; byId("range-mode").setAttribute("aria-pressed", String(state.rangeMode)); byId("range-mode").textContent = state.rangeMode ? "Range brush on" : "Range brush"; byId("timeline-frame").classList.toggle("range-mode", state.rangeMode); });
  byId("clear-range").addEventListener("click", clearRangeSelection);
  byId("reset-view").addEventListener("click", resetTimelineView);
  byId("time-cursor").addEventListener("input", (event) => setCursor(nsAtRatio(Number(event.target.value) / 1_000_000)));
  byId("timeline-scroll").addEventListener("wheel", (event) => { if (!(event.ctrlKey || event.metaKey)) return; event.preventDefault(); if (state.brush) finishTimelinePointer(null, true); state.zoom = Math.max(1, event.deltaY > 0 ? state.zoom / 1.25 : state.zoom * 1.25); byId("timeline-zoom").value = String(Number(state.zoom.toFixed(4))); renderTimeline(); }, { passive: false });
  byId("timeline-scroll").addEventListener("scroll", () => { hideTimelineHoverLine(); byId("timeline-ruler").style.transform = `translateX(${-byId("timeline-scroll").scrollLeft}px)`; });
  byId("resource-search").addEventListener("input", () => {
    if (!isScaleMode()) return renderResourceTables();
    window.clearTimeout(state.resourceSearchTimer);
    state.resourceSearchTimer = window.setTimeout(requestResources, 180);
  });
  byId("reset-dashboard-layout").addEventListener("click", resetDashboardLayout);
  byId("range-editor").addEventListener("submit", applyRangeEditor);
  const timelineContent = byId("timeline-content");
  timelineContent.addEventListener("pointerdown", timelinePointerDown);
  timelineContent.addEventListener("pointermove", timelinePointerMove);
  timelineContent.addEventListener("pointerleave", hideTimelineHoverLine);
  timelineContent.addEventListener("pointerup", (event) => finishTimelinePointer(event, false));
  timelineContent.addEventListener("pointercancel", (event) => finishTimelinePointer(event, true));
  timelineContent.addEventListener("lostpointercapture", (event) => finishTimelinePointer(event, true));
  timelineContent.addEventListener("keydown", timelineHandleKeyDown);
  window.addEventListener("blur", () => finishTimelinePointer(null, true));
  window.addEventListener("resize", () => {
    window.clearTimeout(bindControls.graphResizeTimer);
    bindControls.graphResizeTimer = window.setTimeout(() => {
      if (state.graph) renderGraph();
    }, 120);
  }, { passive: true });
  byId("lane-picker-toggle").addEventListener("click", () => {
    const picker = byId("lane-picker");
    picker.hidden = !picker.hidden;
    byId("lane-picker-toggle").setAttribute("aria-expanded", String(!picker.hidden));
    if (!picker.hidden) byId("lane-filter").focus();
  });
  byId("close-lane-picker").addEventListener("click", () => { byId("lane-picker").hidden = true; byId("lane-picker-toggle").setAttribute("aria-expanded", "false"); });
  byId("lane-filter").addEventListener("input", (event) => { state.laneFilterText = event.target.value; renderLanePicker(); });
  byId("record-lane-form").addEventListener("submit", addRecordLane);
  document.querySelectorAll("[data-lane-action]").forEach((button) => button.addEventListener("click", () => {
    const action = button.dataset.laneAction;
    if (action === "none") {
      state.laneMode = "custom";
      state.explicitLaneIds.clear();
      if (isScaleMode()) refreshScaleTimeline();
      else {
        renderTimeline();
        renderResourceTables();
      }
    } else setLaneMode(action);
  }));
  document.querySelectorAll("[data-correlation-view]").forEach((button) => button.addEventListener("click", () => {
    state.correlationTimelineView = button.dataset.correlationView;
    syncCorrelationTimelineButtons();
    rerenderTimelinePreservingScroll();
  }));
  byId("graph-scope-toggle").addEventListener("click", () => {
    if (!state.selectedResourceId) return;
    state.graphShowFull = !state.graphShowFull;
    syncGraphScopeButton();
    requestGraph();
  });
  byId("route-form").addEventListener("submit", resolveRoute);
  byId("route-form").querySelector("select").addEventListener("change", resolveRoute);
  byId("event-layer-filter").addEventListener("change", () => renderEventTable({ resetScroll: true }));
  byId("event-search").addEventListener("input", () => renderEventTable({ resetScroll: true }));
  byId("event-log-scroll").addEventListener("scroll", scheduleEventLogWindow, { passive: true });
  [
    ["event-include-normalized", "normalized"],
    ["event-include-ctf", "ctf"],
    ["event-include-external", "external"],
  ].forEach(([id, key]) => byId(id).addEventListener("change", (event) => {
    state.eventLogInclude[key] = event.target.checked;
    renderEventTable({ resetScroll: true });
  }));
  ["open-review", "open-review-footer"].forEach((id) => byId(id).addEventListener("click", openReview));
  byId("close-review").addEventListener("click", closeReview); byId("drawer-scrim").addEventListener("click", closeReview);
  ["copy-review", "copy-review-top"].forEach((id) => byId(id).addEventListener("click", copyReview));
  byId("clear-review").addEventListener("click", () => { localStorage.removeItem(REVIEW_STORAGE_KEY); renderReview(); showToast("Review selections cleared."); });
  const hover = byId("timeline-hover");
  hover.addEventListener("pointerenter", () => window.clearTimeout(state.hoverCloseTimer));
  hover.addEventListener("pointerleave", scheduleHoverClose);
  document.addEventListener("keydown", handleEscapeKey);
}

function discoverPresentation() {
  const descriptors = state.dataset.presentation?.layers || state.dataset.layers || [];
  if (Array.isArray(descriptors)) descriptors.forEach((item) => state.layerMeta.set(item.id || item.layer, { label: item.label || titleCase(item.id || item.layer), color: item.color || stableColor(item.id || item.layer) }));
  else Object.entries(descriptors).forEach(([key, item]) => state.layerMeta.set(key, { label: item.label || titleCase(key), color: item.color || stableColor(key) }));
  const layers = new Set(state.layerMeta.keys());
  if (!isScaleMode()) {
    (state.dataset.resources || []).forEach((item) => layers.add(resourceLayer(item, resourceIdOf(item))));
    (state.dataset.events || []).forEach((item) => layers.add(eventSubject(item).layer || "unknown"));
  }
  state.sourceRecords.forEach((item) => layers.add(item.layer || "unknown"));
  state.lanes.forEach((lane) => layers.add(lane.layer));
  layers.forEach(layerConfig);
  state.activeLayers = new Set(layers);
}

async function initialize() {
  try {
    state.dataset = await api("/api/demo");
    state.sourceRecordTypes = new Map(
      (state.dataset.source_record_descriptors || state.dataset.schema?.source_record_types || [])
        .map((descriptor) => [String(descriptor.source_type), descriptor]),
    );
    state.sourceRecords = [...(state.dataset.source_records || [])]
      .sort((left, right) => {
        const leftTime = sourceRecordTime(left);
        const rightTime = sourceRecordTime(right);
        return leftTime < rightTime ? -1 : leftTime > rightTime ? 1 : sourceRecordUid(left).localeCompare(sourceRecordUid(right));
      });
    state.sourceRecordByUid = new Map(
      state.sourceRecords.map((record) => [sourceRecordUid(record), record]),
    );
    state.recordLanePresets = [
      ...(state.dataset.record_lane_presets || state.dataset.schema?.record_lane_presets || []),
    ];
    state.recordLaneRules = state.recordLanePresets
      .filter((preset) => preset.default_enabled)
      .slice(0, MAX_RECORD_LANES)
      .map((preset) => ({ ...preset, plugin_defined: true }));
    for (const record of state.dataset.resources || []) registerResource(record);
    state.resourceCatalogLanes = state.dataset.resources || [];
    for (const event of state.dataset.events || []) state.eventByUid.set(String(event.event_uid || event.event_id), event);
    const times = isScaleMode() ? [] : [...state.eventByUid.values()].map(eventTime);
    state.viewStartNs = toNs(state.dataset.demo.timeline_start_ns, times.length ? times.reduce((a, b) => a < b ? a : b) : 0n);
    state.viewEndNs = toNs(state.dataset.demo.timeline_end_ns ?? state.dataset.demo.capture_ns, times.length ? times.reduce((a, b) => a > b ? a : b) : state.viewStartNs + 1n);
    if (state.viewEndNs <= state.viewStartNs) state.viewEndNs = state.viewStartNs + 1n;
    state.cursorNs = clampNs(toNs(state.dataset.demo.capture_ns, state.viewEndNs));
    if (isScaleMode()) {
      state.laneMode = "custom";
      state.explicitLaneIds = new Set(initialScaleLaneIds());
    }
    await requestTimeline();
    if (!isScaleMode()) state.explicitLaneIds = new Set(state.lanes.map((lane) => lane.resourceId));
    discoverPresentation();
    initializeDashboardLayout();
    fillSummary(); renderIncidentSummary(); renderLayerToggles(); renderTimeline(); renderRangeSummary(); renderFindings(); renderInventory(); renderReview(); renderEventLayerFilter(); syncEventLogIncludeControls(); renderEventTable(); renderPluginDashboards(); bindControls();
    let incident = null;
    for (const candidate of state.eventByUid.values()) {
      incident = candidate;
      if (eventFailed(candidate)) {
        break;
      }
    }
    if (incident) selectEvent(String(incident.event_uid || incident.event_id), isScaleMode());
    await Promise.allSettled([requestGraph(), requestResources(), resolveRoute()]);
  } catch (error) {
    document.querySelector("main").innerHTML = `<section class="section-wrap"><div class="panel empty-state"><h1>Demo fixture could not load</h1><p>${escapeHtml(error.message)}</p></div></section>`;
  }
}

initialize();
