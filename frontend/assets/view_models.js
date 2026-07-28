// Pure, executable view-model decisions shared by the browser workspaces.
//
// Keep DOM access, request dispatch, and plug-in interpretation in the page
// entry points. These helpers only normalize generic core response shapes so
// production code and node:test exercise the same behavior.

const HEALTH_PRESENTATION = new Map([
  ["healthy", "good"],
  ["good", "good"],
  ["usable", "good"],
  ["degraded", "warning"],
  ["warning", "warning"],
  ["absent", "warning"],
  ["unknown", "warning"],
  ["unusable", "error"],
  ["error", "error"],
]);

function normalizedEnum(value) {
  if (value === null || value === undefined || typeof value === "object") return "";
  return String(value).trim().toLowerCase().replace(/[\s-]+/g, "_");
}

export function declaredHealthPresentation(value, { includeStatus = false } = {}) {
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
  return HEALTH_PRESENTATION.get(normalizedEnum(declared)) || "warning";
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

export function dashboardComparable(value) {
  if (value === undefined) return "missing";
  if (value === null) return "null";
  if (typeof value === "boolean") return `boolean:${value ? "true" : "false"}`;
  if (typeof value === "number") {
    if (Number.isNaN(value)) return "number:nan";
    if (value === Infinity) return "number:infinity";
    if (value === -Infinity) return "number:-infinity";
    return `number:${Object.is(value, -0) ? "-0" : String(value)}`;
  }
  if (typeof value === "string") return `string:${JSON.stringify(value)}`;
  if (Array.isArray(value)) {
    return `sequence:[${value.map((item) => dashboardComparable(item)).join(",")}]`;
  }
  if (typeof value === "object") {
    return `mapping:{${Object.keys(value).sort().map(
      (key) => `${JSON.stringify(key)}:${dashboardComparable(value[key])}`,
    ).join(",")}}`;
  }
  return `${typeof value}:${String(value)}`;
}

export function dashboardFilterMatches(item, filter) {
  const actual = dashboardFieldLookup(item, filter.field);
  const expected = filter.value;
  const equals = (left, right) => dashboardComparable(left) === dashboardComparable(right);
  switch (filter.operator || "eq") {
    case "eq":
      return actual.found && equals(actual.value, expected);
    case "not_eq":
      return actual.found && !equals(actual.value, expected);
    case "in":
      return actual.found
        && Array.isArray(expected)
        && expected.some((value) => equals(actual.value, value));
    case "not_in":
      return actual.found
        && Array.isArray(expected)
        && !expected.some((value) => equals(actual.value, value));
    case "exists":
      return actual.found === (
        expected === null || expected === undefined ? true : Boolean(expected)
      );
    case "contains": {
      if (!actual.found) return false;
      if (Array.isArray(actual.value)) {
        return actual.value.some((value) => equals(value, expected));
      }
      if (typeof actual.value === "string" && typeof expected === "string") {
        return actual.value.toLowerCase().includes(expected.toLowerCase());
      }
      if (actual.value && typeof actual.value === "object" && typeof expected === "string") {
        return dashboardComparable(actual.value)
          .toLowerCase()
          .includes(expected.toLowerCase());
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
    return {
      value: new Set(values.map(dashboardComparable)).size,
      matchingCount: matching.length,
      sampleCount: values.length,
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
