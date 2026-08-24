// Pure, executable view-model decisions shared by the browser workspaces.
//
// Keep DOM access, request dispatch, and plug-in interpretation in the page
// entry points. These helpers only normalize generic core response shapes so
// production code and node:test exercise the same behavior.

const STATUS_CLASS_PRESENTATION = new Map([
  ["absent", { health: "warning", className: "is-absent" }],
  ["degraded", { health: "warning", className: "is-degraded" }],
  ["error", { health: "error", className: "is-error" }],
  ["healthy", { health: "good", className: "is-healthy" }],
  ["unknown", { health: "warning", className: "is-unknown" }],
]);
const DASHBOARD_EQUALITY_MAX_DEPTH = 16;
const DASHBOARD_EQUALITY_MAX_CONTAINER_ITEMS = 1_024;
const DASHBOARD_EQUALITY_MAX_UNITS = 4_096;
const DASHBOARD_EQUALITY_MAX_ATOM_UNITS = 65_536;
const DASHBOARD_EQUALITY_MAX_INTEGER_BITS = 4_096;

function virtualScrollScale(rowCount, rowHeight, maximumHeight, viewportHeight) {
  exactBoundedInteger(rowCount, "rowCount");
  exactBoundedInteger(rowHeight, "rowHeight", { minimum: 1 });
  exactBoundedInteger(maximumHeight, "maximumHeight", { minimum: 1 });
  exactBoundedInteger(viewportHeight, "viewportHeight");
  if (rowCount * rowHeight <= maximumHeight) return rowHeight;
  return Math.max(
    Number.EPSILON,
    (maximumHeight - Math.min(viewportHeight, maximumHeight - 1))
      / Math.max(1, rowCount - 1),
  );
}

export function virtualScrollWindow({
  rowCount,
  rowHeight,
  maximumHeight,
  viewportHeight,
  scrollTop,
  overscan = 0,
}) {
  exactBoundedInteger(viewportHeight, "viewportHeight");
  exactBoundedInteger(overscan, "overscan");
  const scale = virtualScrollScale(
    rowCount,
    rowHeight,
    maximumHeight,
    viewportHeight,
  );
  const totalHeight = Math.min(rowCount * rowHeight, maximumHeight);
  const visibleRows = Math.max(1, Math.ceil(viewportHeight / rowHeight));
  const boundedScrollTop = Math.max(
    0,
    Math.min(Number(scrollTop) || 0, Math.max(0, totalHeight - viewportHeight)),
  );
  const anchor = Math.min(
    Math.max(0, rowCount - 1),
    Math.floor(boundedScrollTop / scale),
  );
  const windowSize = visibleRows + overscan * 2;
  const start = Math.max(0, Math.min(
    Math.max(0, rowCount - windowSize),
    anchor - overscan,
  ));
  const end = Math.min(rowCount, start + windowSize);
  const rowsBeforeAnchor = Math.max(0, anchor - start);
  const topHeight = Math.max(
    0,
    Math.min(totalHeight, boundedScrollTop - rowsBeforeAnchor * rowHeight),
  );
  const renderedHeight = (end - start) * rowHeight;
  return {
    start,
    end,
    topHeight,
    bottomHeight: Math.max(0, totalHeight - topHeight - renderedHeight),
    totalHeight,
    scale,
  };
}

export function virtualScrollTopForIndex({
  index,
  rowCount,
  rowHeight,
  maximumHeight,
  viewportHeight,
}) {
  exactBoundedInteger(index, "index");
  exactBoundedInteger(viewportHeight, "viewportHeight");
  const scale = virtualScrollScale(
    rowCount,
    rowHeight,
    maximumHeight,
    viewportHeight,
  );
  const totalHeight = Math.min(rowCount * rowHeight, maximumHeight);
  const target = rowCount * rowHeight <= maximumHeight
    ? index * scale - (viewportHeight - rowHeight) / 2
    : index * scale;
  return Math.max(0, Math.min(Math.max(0, totalHeight - viewportHeight), target));
}

function exactBoundedInteger(value, label, { minimum = 0 } = {}) {
  if (!Number.isSafeInteger(value) || value < minimum) {
    throw new TypeError(`${label} must be a safe integer greater than or equal to ${minimum}`);
  }
  return value;
}

export function controlPlaneCollectionPageDecision({
  payload,
  offset,
  requestedLimit,
  accumulatedCount,
  maximumCount,
}) {
  exactBoundedInteger(offset, "offset");
  exactBoundedInteger(requestedLimit, "requestedLimit", { minimum: 1 });
  exactBoundedInteger(accumulatedCount, "accumulatedCount");
  exactBoundedInteger(maximumCount, "maximumCount", { minimum: 1 });
  if (!payload || typeof payload !== "object" || !Array.isArray(payload.items)) {
    throw new TypeError("control-plane collection response must contain an items array");
  }
  if (payload.items.length > requestedLimit) {
    throw new RangeError("control-plane collection page exceeds the requested limit");
  }
  const totalCount = accumulatedCount + payload.items.length;
  if (!Number.isSafeInteger(totalCount) || totalCount > maximumCount) {
    throw new RangeError("control-plane collection exceeds the client safety cap");
  }
  const rawNextOffset = payload.next_offset;
  if (rawNextOffset === null || rawNextOffset === undefined) {
    return {
      complete: true,
      capExceeded: false,
      nextOffset: null,
      totalCount,
    };
  }
  exactBoundedInteger(rawNextOffset, "next_offset");
  if (rawNextOffset <= offset || payload.items.length === 0) {
    throw new RangeError("control-plane collection next_offset does not advance");
  }
  return {
    complete: false,
    capExceeded: totalCount >= maximumCount,
    nextOffset: rawNextOffset,
    totalCount,
  };
}

export function durableReportMemberValidation(members, maximumRevisions = 128) {
  exactBoundedInteger(maximumRevisions, "maximumRevisions", { minimum: 1 });
  if (!Array.isArray(members) || members.length === 0) {
    return {
      valid: false,
      memberCount: Array.isArray(members) ? members.length : 0,
      reason: "empty",
    };
  }
  const revisionIds = members.map((member) => (
    member && typeof member === "object"
      ? String(member.revision_id || "")
      : ""
  ));
  if (revisionIds.some((revisionId) => !revisionId)) {
    return { valid: false, memberCount: members.length, reason: "invalid" };
  }
  if (new Set(revisionIds).size !== revisionIds.length) {
    return { valid: false, memberCount: members.length, reason: "duplicate" };
  }
  if (revisionIds.length > maximumRevisions) {
    return { valid: false, memberCount: members.length, reason: "oversized" };
  }
  return { valid: true, memberCount: members.length, reason: null };
}

export function durableReportRequestBody(scope) {
  if (!scope || typeof scope !== "object") {
    throw new TypeError("report scope is required");
  }
  const id = typeof scope.id === "string" ? scope.id.trim() : "";
  if (!id) throw new TypeError("report scope id is required");
  if (scope.kind === "revision") return { revision_ids: [id] };
  if (scope.kind === "session") return { session_id: id };
  if (scope.kind === "snapshot") return { snapshot_id: id };
  throw new TypeError("unsupported report scope kind");
}

export function durableMutationDisposition(error) {
  return error?.ambiguous === true ? "retain" : "discard";
}

export function authoritativeTopologyLink(link) {
  if (!link || typeof link !== "object") return false;
  if (link.typed_federation !== true) return true;
  return link.resolution === "matched"
    && link.federation_complete === true
    && link.federation_truncated === false;
}

export function topologyResolutionLabel(resolution) {
  return {
    ambiguous: "Multiple candidate remote endpoints",
    conflict: "Conflicting remote endpoints",
    incomplete: "Incomplete federation evidence",
    mixed: "Mixed federation outcomes",
    unresolved: "No compatible remote endpoint",
  }[String(resolution || "unresolved")] || "Unresolved federation outcome";
}

export function durableReviewControlAvailability({
  ready,
  writable,
  journalBlocked = false,
  connecting,
  markerBusy,
  correlationBusy,
  reportBusy,
  selectionReady,
}) {
  const writeBusy = connecting || markerBusy || correlationBusy || reportBusy;
  const durableReadOnly = ready && !writable;
  return {
    connectDisabled: writeBusy,
    reportDisabled: !ready || reportBusy || markerBusy || correlationBusy,
    reportScopeDisabled: !ready || reportBusy || markerBusy || correlationBusy,
    markerDisabled: !selectionReady || writeBusy || durableReadOnly || journalBlocked,
    correlationDisabled: !selectionReady || !writable || writeBusy || journalBlocked,
    durableReadOnly,
    journalBlocked,
  };
}

function normalizedEnum(value) {
  if (value === null || value === undefined || typeof value === "object") return "";
  return String(value).trim().toLowerCase().replace(/[\s-]+/g, "_");
}

function declaredStatusClass(value, { includeStatus = false } = {}) {
  const candidates = [
    value?.condition_class,
    value?.status_class,
    value?.health_class,
    includeStatus ? value?.status : null,
  ];
  const declared = candidates.find(
    (candidate) => candidate !== null
      && candidate !== undefined
      && typeof candidate !== "object"
      && String(candidate).trim(),
  );
  if (declared === undefined) return null;
  const statusClass = normalizedEnum(declared);
  return STATUS_CLASS_PRESENTATION.has(statusClass) ? statusClass : "unknown";
}

export function declaredHealthPresentation(value, options = {}) {
  const statusClass = declaredStatusClass(value, options);
  if (statusClass === null) return null;
  return (
    STATUS_CLASS_PRESENTATION.get(statusClass)
    || STATUS_CLASS_PRESENTATION.get("unknown")
  ).health;
}

export function statusClassPresentation(value, options = {}) {
  const statusClass = declaredStatusClass(value, options) || "unknown";
  return (
    STATUS_CLASS_PRESENTATION.get(statusClass)
    || STATUS_CLASS_PRESENTATION.get("unknown")
  ).className;
}

export function stateChipClassName(value, options = {}) {
  return `state-chip ${statusClassPresentation(value, options)}`;
}

export function statusSegmentClassName(value, options = {}) {
  return `status-segment ${statusClassPresentation(value, options)}`;
}

function timelineBigInt(value) {
  if (value === null || value === undefined || value === "") return null;
  try {
    return BigInt(String(value));
  } catch (_error) {
    return null;
  }
}

function unavailableReconstructionTimeline() {
  return {
    available: false,
    basisKind: "unknown",
    coordinateKind: "unknown",
    axisStartNs: null,
    axisEndNs: null,
    valueNs: null,
    clampedValueNs: null,
    positionPercent: null,
    clamped: false,
  };
}

export function reconstructionTimelineModel({
  basisKind,
  valueNs,
  startNs,
  endNs,
  captureNs,
} = {}) {
  const rawKind = String(basisKind || "");
  const relative = new Set([
    "relative_to_watermark",
    "relative_capture_vector",
    "mixed_capture_vector",
  ]).has(rawKind);
  if (!relative && rawKind !== "absolute_time") {
    return unavailableReconstructionTimeline();
  }

  const start = timelineBigInt(startNs);
  const end = timelineBigInt(endNs);
  const value = timelineBigInt(valueNs);
  if (start === null || end === null || value === null || start > end) {
    return unavailableReconstructionTimeline();
  }

  let axisStart = start;
  let axisEnd = end;
  let normalizedKind = "absolute_time";
  let coordinateKind = "absolute_time";
  if (relative) {
    const capture = timelineBigInt(captureNs) ?? end;
    axisStart = start - capture;
    axisEnd = 0n;
    normalizedKind = "relative_to_watermark";
    coordinateKind = "relative_offset";
    if (axisStart > axisEnd) return unavailableReconstructionTimeline();
  }

  const clampedValue = value < axisStart
    ? axisStart
    : value > axisEnd ? axisEnd : value;
  const span = axisEnd - axisStart;
  const positionUnits = span === 0n
    ? 500_000n
    : ((clampedValue - axisStart) * 1_000_000n) / span;

  return {
    available: true,
    basisKind: normalizedKind,
    coordinateKind,
    axisStartNs: axisStart.toString(),
    axisEndNs: axisEnd.toString(),
    valueNs: value.toString(),
    clampedValueNs: clampedValue.toString(),
    positionPercent: Number(positionUnits) / 10_000,
    clamped: value !== clampedValue,
  };
}

export function reconstructionTimelineValueAtPosition(model, positionUnits) {
  if (!model?.available) return null;
  if (
    (typeof positionUnits !== "number" || !Number.isInteger(positionUnits))
    && (typeof positionUnits !== "string" || !/^-?\d+$/.test(positionUnits))
  ) {
    return null;
  }
  const numericPosition = Number(positionUnits);
  if (!Number.isSafeInteger(numericPosition)) return null;
  const axisStart = timelineBigInt(model.axisStartNs);
  const axisEnd = timelineBigInt(model.axisEndNs);
  if (axisStart === null || axisEnd === null || axisStart > axisEnd) return null;
  const clampedPosition = Math.max(0, Math.min(1_000_000, Math.round(numericPosition)));
  const value = axisStart
    + ((axisEnd - axisStart) * BigInt(clampedPosition)) / 1_000_000n;
  return value.toString();
}

export function routeEndpointSeedValue(raw, kind) {
  if (raw === undefined || raw === null) return "";
  if (typeof raw !== "object") return String(raw);
  const idField = kind === "source" ? "source_id" : "destination_id";
  return String(
    raw[idField]
    ?? raw.endpoint_id
    ?? raw.resource_id
    ?? raw.node_id
    ?? raw.value
    ?? raw.address
    ?? raw.prefix
    ?? raw.label
    ?? "",
  );
}

export function graphStatusClass(node) {
  if (typeof node?.status_class === "string" && node.status_class) {
    return node.status_class;
  }
  if (typeof node?.status === "string" && node.status) return node.status;
  return "unknown";
}

export function routePayloadBranches(payload) {
  const declared = Array.isArray(payload?.branches)
    ? payload.branches.filter((item) => item && typeof item === "object")
    : [];
  if (declared.length) {
    return declared.map((item, index) => ({
      id: String(item.branch_id ?? item.next_hop_id ?? `branch-${index + 1}`),
      nextHop: item.next_hop ?? item.node_id ?? item.next_hop_id ?? null,
      egress: item.egress_interface_resource_id ?? item.egress_interface ?? item.via ?? null,
      active: item.active === true ? true : item.active === false ? false : null,
      result: String(
        item.result
        ?? item.disposition
        ?? item.status
        ?? (item.active === true ? "active" : item.active === false ? "inactive" : "unknown"),
      ),
    }));
  }
  const nextHops = Array.isArray(payload?.next_hops) ? payload.next_hops : [];
  const egress = Array.isArray(payload?.egress_interfaces) ? payload.egress_interfaces : [];
  return Array.from(
    { length: Math.max(nextHops.length, egress.length) },
    (_, index) => ({
      id: `declared-${index + 1}`,
      nextHop: nextHops[index] ?? null,
      egress: egress[index] ?? null,
      active: null,
      result: "activity unknown",
    }),
  );
}

export function routePayloadForwardingPresentation(payload) {
  const branches = routePayloadBranches(payload);
  const active = branches.filter((item) => item.active === true);
  const activityUnknown = branches.filter((item) => item.active === null);
  const forwarding = active.length ? active : activityUnknown;
  const unique = (values) => [...new Set(values
    .filter((value) => value !== null && value !== undefined && value !== "")
    .map(String))];
  const nextHops = unique(forwarding.map((item) => item.nextHop));
  const egress = unique(forwarding.map((item) => item.egress));
  const scope = active.length
    ? `${active.length} active`
    : activityUnknown.length
      ? `${activityUnknown.length} declared; activity unknown`
      : "no active branch";
  return {
    branches,
    nextHopText: nextHops.length ? nextHops.join(", ") : "Not returned",
    egressText: egress.length ? egress.join(", ") : "Not returned",
    scope,
    emptyMessage: branches.length
      ? ""
      : "No forwarding branches returned. The core does not infer local delivery from an empty result.",
  };
}

export function dashboardFieldLookup(item, field) {
  if (!field) return { found: false, value: undefined };
  const parts = String(field).split(".");
  const descend = (value, path) => {
    let current = value;
    for (const key of path) {
      if (
        current === null
        || current === undefined
        || typeof current !== "object"
        || !Object.prototype.hasOwnProperty.call(current, key)
      ) {
        return { found: false, value: undefined };
      }
      current = current[key];
    }
    return { found: true, value: current };
  };
  const direct = descend(item, parts);
  if (direct.found || parts.length > 1) return direct;

  const name = parts[0];
  const resource = item?.resource && typeof item.resource === "object"
    ? item.resource
    : null;
  for (const scope of [item?.state, item?.key, resource?.state, resource?.key]) {
    const nested = descend(scope, [name]);
    if (nested.found) return nested;
  }
  return { found: false, value: undefined };
}

export function dashboardFieldValue(item, field) {
  const result = dashboardFieldLookup(item, field);
  return result.found ? result.value : undefined;
}

export function dashboardRowIncluded(item, resourceKinds = [], includeAbsent = false) {
  const allowedKinds = new Set((resourceKinds || []).map(String));
  return (!allowedKinds.size || allowedKinds.has(String(item?.kind)))
    && (includeAbsent || item?.exists === true);
}

function dashboardStringWithinBound(value) {
  let units = 0;
  for (const _character of value) {
    units += 1;
    if (units > DASHBOARD_EQUALITY_MAX_ATOM_UNITS) return false;
  }
  return true;
}

function dashboardComparableInner(value, context, depth) {
  if (depth > DASHBOARD_EQUALITY_MAX_DEPTH) return null;
  context.units += 1;
  if (context.units > DASHBOARD_EQUALITY_MAX_UNITS) return null;

  if (value === null) return "null";
  if (typeof value === "boolean") return `boolean:${value ? "true" : "false"}`;
  if (typeof value === "bigint") {
    const magnitude = value < 0n ? -value : value;
    if (magnitude !== 0n && magnitude.toString(2).length > DASHBOARD_EQUALITY_MAX_INTEGER_BITS) {
      return null;
    }
    return `integer:${value.toString()}`;
  }
  if (typeof value === "number") {
    if (Number.isNaN(value)) return "number:nan";
    if (value === Infinity) return "number:infinity";
    if (value === -Infinity) return "number:-infinity";
    // Python float equality treats signed zero as equal. The JSON transport
    // erases the Python int/float distinction, so browser comparison uses one
    // number tag while preserving that signed-zero rule.
    return `number:${String(value)}`;
  }
  if (typeof value === "string") {
    return dashboardStringWithinBound(value)
      ? `string:${JSON.stringify(value)}`
      : null;
  }
  if (typeof value !== "object" || value === undefined) return null;
  if (context.active.has(value)) return null;

  if (Array.isArray(value)) {
    if (value.length > DASHBOARD_EQUALITY_MAX_CONTAINER_ITEMS) return null;
    context.active.add(value);
    try {
      const items = [];
      for (let index = 0; index < value.length; index += 1) {
        const item = dashboardComparableInner(value[index], context, depth + 1);
        if (item === null) return null;
        items.push(item);
      }
      return `sequence:[${items.join(",")}]`;
    } finally {
      context.active.delete(value);
    }
  }

  const prototype = Object.getPrototypeOf(value);
  if (
    (prototype !== Object.prototype && prototype !== null)
    || Object.getOwnPropertySymbols(value).length
  ) {
    return null;
  }
  const keys = Object.keys(value);
  if (keys.length > DASHBOARD_EQUALITY_MAX_CONTAINER_ITEMS) return null;
  context.active.add(value);
  try {
    const entries = [];
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, "value")) {
        return null;
      }
      const keyToken = dashboardComparableInner(key, context, depth + 1);
      const valueToken = dashboardComparableInner(descriptor.value, context, depth + 1);
      if (keyToken === null || valueToken === null) return null;
      entries.push(`${keyToken}:${valueToken}`);
    }
    entries.sort();
    return `mapping:{${entries.join(",")}}`;
  } finally {
    context.active.delete(value);
  }
}

export function dashboardComparable(value) {
  try {
    return dashboardComparableInner(value, { active: new WeakSet(), units: 0 }, 0);
  } catch (_error) {
    // Plug-in-owned browser values are untrusted. A getter, proxy, or other
    // exotic local object must fail closed just like an unsupported backend
    // dashboard value rather than taking down the dashboard renderer.
    return null;
  }
}

export function dashboardFilterMatches(item, filter) {
  const actual = dashboardFieldLookup(item, filter.field);
  const expected = filter.value;
  const compare = (left, right) => {
    const leftKey = dashboardComparable(left);
    const rightKey = dashboardComparable(right);
    return {
      valid: leftKey !== null && rightKey !== null,
      equal: leftKey !== null && rightKey !== null && leftKey === rightKey,
    };
  };
  switch (filter.operator || "eq") {
    case "eq":
      return actual.found && compare(actual.value, expected).equal;
    case "not_eq": {
      if (!actual.found) return false;
      const result = compare(actual.value, expected);
      return result.valid && !result.equal;
    }
    case "in":
    case "not_in": {
      if (!actual.found || !Array.isArray(expected)) return false;
      const actualKey = dashboardComparable(actual.value);
      const candidateKeys = expected.map(dashboardComparable);
      if (actualKey === null || candidateKeys.some((key) => key === null)) return false;
      const included = candidateKeys.includes(actualKey);
      return filter.operator === "in" ? included : !included;
    }
    case "exists":
      return actual.found === (
        expected === null || expected === undefined ? true : Boolean(expected)
      );
    case "contains": {
      if (!actual.found) return false;
      if (Array.isArray(actual.value)) {
        const expectedKey = dashboardComparable(expected);
        if (expectedKey === null) return false;
        return actual.value.some((value) => {
          const valueKey = dashboardComparable(value);
          return valueKey !== null && valueKey === expectedKey;
        });
      }
      if (typeof actual.value === "string" && typeof expected === "string") {
        return actual.value.toLowerCase().includes(expected.toLowerCase());
      }
      if (actual.value && typeof actual.value === "object" && typeof expected === "string") {
        const comparable = dashboardComparable(actual.value);
        return comparable !== null
          && comparable.toLowerCase().includes(expected.toLowerCase());
      }
      return false;
    }
    default:
      throw new Error(`Unsupported dashboard filter operator: ${filter.operator}`);
  }
}

export function dashboardStatisticEvaluation(rows, descriptor) {
  const matching = rows.filter((item) => (descriptor.filters || []).every(
    (filter) => dashboardFilterMatches(item, filter),
  ));
  const values = descriptor.field
    ? matching.map((item) => dashboardFieldLookup(item, descriptor.field))
      .filter((result) => result.found)
      .map((result) => result.value)
    : [];
  const aggregation = descriptor.aggregation || "count";
  if (aggregation === "count") {
    return {
      value: matching.length,
      matchingCount: matching.length,
      sampleCount: matching.length,
    };
  }
  if (aggregation === "count_distinct") {
    const comparisonKeys = values.map(dashboardComparable)
      .filter((value) => value !== null);
    return {
      value: new Set(comparisonKeys).size,
      matchingCount: matching.length,
      sampleCount: comparisonKeys.length,
    };
  }
  if (["sum", "average", "minimum", "maximum"].includes(aggregation)) {
    const numericValues = values.filter(
      (value) => typeof value === "number" && Number.isFinite(value),
    );
    let value = null;
    if (aggregation === "sum") {
      value = numericValues.reduce((total, item) => total + item, 0);
    } else if (numericValues.length && aggregation === "average") {
      value = numericValues.reduce((total, item) => total + item, 0)
        / numericValues.length;
    } else if (numericValues.length && aggregation === "minimum") {
      value = Math.min(...numericValues);
    } else if (numericValues.length && aggregation === "maximum") {
      value = Math.max(...numericValues);
    }
    return {
      value,
      matchingCount: matching.length,
      sampleCount: numericValues.length,
    };
  }
  throw new Error(`Unsupported dashboard aggregation: ${aggregation}`);
}

export function dashboardDescriptorErrorMessage(payload) {
  const errors = Array.isArray(payload?.descriptor_errors)
    ? payload.descriptor_errors.filter((item) => item && typeof item === "object")
    : [];
  if (!errors.length) return "";
  return errors.slice(0, 3).map((item) => {
    const path = typeof item.path === "string" && item.path ? `${item.path}: ` : "";
    return `${path}${String(item.message || item.code || "invalid dashboard descriptor")}`;
  }).join("; ");
}

function normalizeCount(value) {
  if (Array.isArray(value)) return value.length;
  if (value && typeof value === "object") {
    return Number(value.total ?? value.count ?? Object.keys(value).length);
  }
  return Number(value || 0);
}

function rangeTruncationFlags(summary) {
  const raw = summary?.truncated;
  if (raw === true) {
    return {
      events: true,
      affected_resources: true,
      status_segments: true,
      endpoint_diff: true,
      relationship_changes: true,
    };
  }
  return raw && typeof raw === "object" ? raw : {};
}

export function rangeSummaryFacts(summary, { fallbackFailureCount = 0 } = {}) {
  const eventCount = Number(summary?.event_count ?? normalizeCount(summary?.events));
  const failureCount = Number(summary?.failure_count ?? fallbackFailureCount);
  const affectedResourceCount = Number(
    summary?.affected_resource_count ?? normalizeCount(summary?.affected_resources),
  );
  const relationshipChangeCount = Number(
    summary?.relationship_change_count ?? normalizeCount(summary?.relationship_changes),
  );
  const truncation = rangeTruncationFlags(summary);
  const evaluatedEndpointCount = Number(
    summary?.endpoint_diff_evaluated_count ?? affectedResourceCount,
  );
  return {
    eventCount,
    failureCount,
    affectedResourceCount,
    relationshipChangeCount,
    evaluatedEndpointCount,
    omittedEndpointCount: Math.max(0, affectedResourceCount - evaluatedEndpointCount),
    truncation,
    truncatedKinds: Object.entries(truncation)
      .filter(([, value]) => value === true)
      .map(([key]) => key),
  };
}

export function replaceAbortController(previous, createController = () => new AbortController()) {
  previous?.abort();
  return createController();
}
