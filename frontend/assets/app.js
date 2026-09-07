import {
  api,
  byId,
  createAnalysisLoadProgressController,
  escapeHtml,
  renderAnalysisLoadProgress,
  safeClass,
  titleCase,
  toBigInt as toNs,
} from "./shared.js";
import {
  dashboardDescriptorErrorMessage,
  dashboardFieldValue,
  dashboardFilterMatches,
  dashboardRowIncluded,
  dashboardStatisticEvaluation,
  controlPlaneCollectionPageDecision,
  durableMutationDisposition,
  durableReportMemberValidation,
  durableReportRequestBody,
  durableReviewControlAvailability,
  graphStatusClass,
  rangeSummaryFacts,
  replaceAbortController,
  routePayloadForwardingPresentation,
  stateChipClassName,
  statusClassPresentation,
  resourceExistenceLabel,
  relationshipPresencePresentation,
  statusSegmentClassName,
  virtualScrollTopForIndex,
  virtualScrollWindow,
} from "./view_models.js";
import {
  timelineDensityBinBounds,
  timelineDensityBinIndex,
  timelineHalfOpenIntervalVisible,
  timelineInclusiveIntervalVisible,
  timelineRatioForTime,
  timelineTimeAtRatio,
  timelineWindowForRange,
  timelineWindowForZoom,
  timelineZoomStep,
} from "./timeline_viewport.js";
import {
  eventChangesState,
  eventEffects,
  eventFailed,
  eventMarkClass,
  normalizedEventOutcome,
  resourceEffectStatusClass,
} from "./timeline_models.js";
import {
  ControlPlaneRequestError,
  DurableReviewJournalCapacityError,
  DurableReviewJournalError,
  StaleDurableReviewConnectionError,
  awaitCurrentDurableReview,
  beginReviewOperation,
  buildDurableAnnotationMarkerIndex,
  completePendingReviewMutation,
  discardPendingReviewMutationsForScope,
  durableConditionalRequestOptions,
  durableCreationRequestOptions,
  durableMutationPayloadIdentity,
  durableMutationScopeKey,
  durableReadPostRequestOptions,
  durableReviewScopesEqual,
  durableReviewTokenMatches,
  loadPendingReviewMutations,
  finishReviewOperation,
  listAllDurableAnnotations,
  listControlPlaneCollection,
  loadThenCommitConfirmedState,
  loadDurableReviewConfig,
  reconcileControlPlaneVersionConflict,
  reconcilePendingReviewMutations,
  resetPendingReviewMutations,
  reservePendingReviewMutation,
  requestDurableReview,
  savePendingReviewMutations,
  saveDurableReviewConfig as persistDurableReviewConfig,
} from "./durable_review_controller.js";

const PALETTE = ["#52e0c4", "#a58bff", "#f5b85b", "#66b8ff", "#ff8eb5", "#9bd66f", "#df9dff"];
const REVIEW_STORAGE_KEY = "router-state-lab-review-v2";
const DURABLE_REVIEW_STORAGE_KEY = "router-state-lab-durable-review-scope-v1";
const DURABLE_REVIEW_PENDING_STORAGE_KEY = "router-state-lab-durable-review-pending-v1";
const DASHBOARD_LAYOUT_STORAGE_KEY_PREFIX = "router-state-lab-plugin-dashboards-v2";
const TIMELINE_LANE_WIDTH = 280;
const COMPACT_TIMELINE_LANE_WIDTH = 210;
const MIN_TIMELINE_TRACK_WIDTH = 700;
const HOVER_OPEN_DELAY_MS = 150;
const HOVER_CLOSE_GRACE_MS = 380;
const CLUSTER_DETAIL_PAGE_SIZE = 100;
const EVENT_LOG_ROW_HEIGHT = 44;
const EVENT_LOG_MAX_SCROLL_HEIGHT = 8_000_000;
const EVENT_LOG_OVERSCAN = 10;
const EVENT_LOG_PAGE_SIZE = 120;
const EVENT_LOG_PAGE_CACHE_LIMIT = 12;
const EVENT_LOG_FILTER_DELAY_MS = 220;
const MAX_EVENT_LOG_SELECTION_RANGES = 128;
const MAX_EVENT_LOG_SELECTION_ITEMS = 5000;
const DURABLE_REVIEW_PAGE_SIZE = 5000;
const MAX_DURABLE_REVIEW_RECORDS = 20000;
const CONTROL_PLANE_REQUEST_TIMEOUT_MS = 30_000;
const CONTROL_PLANE_REPORT_TIMEOUT_MS = 60_000;
const MAX_PENDING_REVIEW_MUTATIONS = 128;
const MAX_TOTAL_PENDING_REVIEW_MUTATIONS = 256;
const CONTROL_PLANE_COLLECTION_PAGE_SIZE = 5_000;
const MAX_CONTROL_PLANE_COLLECTION_RECORDS = 20_000;
const MAX_DURABLE_REPORT_REVISIONS = 128;
const DENSITY_PAGE_CACHE_LIMIT = 12;
const MAX_RESOURCE_ROWS = 500;
const MAX_LANE_PICKER_ROWS = 300;
const MAX_SCALE_TIMELINE_LANES = 100;
const MAX_RECORD_LANES = 8;
const MAX_RECORD_PATTERN_LENGTH = 160;
const MAX_TOPOLOGY_RESOURCE_ROWS = 80;
const MAX_TOPOLOGY_CONNECTIVITY_ROWS = 80;
const MAX_TOPOLOGY_CHANGE_ROWS = 100;
const MAX_TOPOLOGY_NODE_ROWS = 48;
const MAX_TIMELINE_TREE_DEPTH = 6;
const MAX_CORRELATION_RENDER_NODES = 31;
const TIMELINE_BASE_TRACK_WIDTH = 900;
const TIMELINE_VIEW_HISTORY_LIMIT = 50;
const TIMELINE_WHEEL_HISTORY_DELAY_MS = 180;
const CORRELATION_LIST_PAGE_SIZE = 30;
const TOPOLOGY_HISTORY_WINDOW_NS = 120_000_000_000n;
const state = {
  dataset: null,
  timelinePayload: null,
  timelineRequestId: 0,
  timelineAbortController: null,
  lanes: [],
  resourceCatalogLanes: [],
  laneByResource: new Map(),
  resourceById: new Map(),
  eventByUid: new Map(),
  eventDetailByUid: new Map(),
  eventDetailRequests: new Map(),
  failureIncidentPreview: [],
  sourceRecords: [],
  sourceRecordByUid: new Map(),
  sourceRecordGroups: new Map(),
  sourceRecordTypes: new Map(),
  recordLanePresets: [],
  recordLaneRules: [],
  recordLanes: [],
  selectedSourceRecordUid: null,
  eventLogInclude: {
    normalized: true,
  },
  includedSourceRecordGroups: new Set(),
  eventLogRows: [],
  eventLogIndexById: new Map(),
  eventLogSelectableCount: 0,
  eventLogVirtualIndexBySelectionIndex: [],
  eventLogRenderFrame: null,
  eventLogFilterTimer: null,
  eventLogServerKey: null,
  eventLogServerQueryId: 0,
  eventLogServerItems: new Map(),
  eventLogServerPages: new Map(),
  eventLogServerRequests: new Map(),
  eventLogOwnedEvents: new Map(),
  eventLogOwnedSources: new Map(),
  eventLogServerSummary: null,
  eventLogServerError: null,
  eventLogLocateRequestId: 0,
  eventLogSelectionRanges: [],
  eventLogSelectionQueryKey: null,
  eventLogSelectionAnchor: null,
  eventLogSelectionFocus: null,
  eventLogSelectionRequestId: 0,
  eventLogSelectionCache: null,
  eventLogDrag: null,
  eventLogSuppressClickUntil: 0,
  eventLogHoverModels: new Map(),
  timelineEntryProjections: new Map(),
  hiddenTimelineEntryIds: new Set(),
  hiddenEventProjectionsByResource: new Map(),
  markedTimelineEntryIds: new Set(),
  localMarkedTimelineEntryIds: new Set(),
  durableReview: {
    status: "local",
    config: null,
    catalogRevisionId: "",
    revisions: [],
    sessions: [],
    snapshots: [],
    reportScope: null,
    canWrite: false,
    annotations: new Map(),
    annotationIdsByEntry: new Map(),
    markedEntryIds: new Set(),
    pendingCorrelationSubjects: [],
    pendingMutations: new Map(),
    pendingJournalBlocked: false,
    pendingJournalError: "",
    pendingJournalRecovery: "",
    operations: new Map(),
    connectionSequence: 0,
    detail: "Add the four scope values to persist markers and correlations.",
  },
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
  rangeAbortController: null,
  zoom: 1,
  trackWidth: 900,
  timelineWindowStartNs: 0n,
  timelineWindowEndNs: 1n,
  timelineContext: null,
  timelineContextReturnFocus: null,
  timelineContextOriginWasTimeline: false,
  timelineWheelFrameId: null,
  timelineWheelTargetZoom: null,
  timelineWheelAnchorNs: null,
  timelineWheelAnchorClientX: null,
  timelineWheelBurstActive: false,
  timelineWheelMode: null,
  timelineWheelHistoryTimer: null,
  timelinePanFrameId: null,
  timelinePanDeltaPx: 0,
  timelineWindowRequestTimer: null,
  timelineViewHistory: [],
  timelineViewHistoryIndex: -1,
  timelineViewHistoryTimer: null,
  timelineViewRestoring: false,
  selectedEventUid: null,
  selectedEventResourceId: null,
  selectedResourceId: null,
  selectedResourceKind: null,
  selectedResourceViewId: null,
  resourceBundleExpansion: new Map(),
  resourceBundleDetailExpansion: new Map(),
  resourceTableSelectionReady: false,
  laneMode: "all",
  explicitLaneIds: new Set(),
  hiddenTimelineResourceIds: new Set(),
  laneFilterText: "",
  graph: null,
  graphShowFull: false,
  graphPinnedInspection: null,
  correlationPanelExpanded: true,
  correlationSectionInView: false,
  correlationSectionFocused: false,
  correlationSectionObserver: null,
  correlationTimelineView: "separate",
  correlationTimelineExpanded: true,
  expandedTimelineTreeKeys: new Set(),
  activeCorrelationEdges: [],
  correlatedResourceIds: new Set(),
  resourceQuery: null,
  graphRequestId: 0,
  graphAbortController: null,
  graphTimeNs: null,
  graphRequestedTimeNs: null,
  graphPending: false,
  correlationListLimit: CORRELATION_LIST_PAGE_SIZE,
  timelineExpansion: null,
  resourceRequestId: 0,
  resourceAbortController: null,
  resourceRequestedTimeNs: null,
  resourceReturnedTimeNs: null,
  resourcePending: false,
  resourceOffset: 0,
  resourceSearchTimer: null,
  dashboardOrder: [],
  openDashboardIds: new Set(),
  expandedDashboardIds: new Set(),
  dashboardLayoutReady: false,
  draggedDashboardId: null,
  dashboardQuery: null,
  dashboardQueryError: null,
  dashboardRequestId: 0,
  dashboardAbortController: null,
  dashboardRequestedTimeNs: null,
  dashboardReturnedTimeNs: null,
  dashboardPending: false,
  topologyCapabilities: null,
  topologyQuery: null,
  topologyRequestId: 0,
  topologyAbortController: null,
  topologyQueryPending: false,
  topologyUsingFallback: false,
  topologyTimer: null,
  temporalTimer: null,
  routeRequestId: 0,
  routeAbortController: null,
  hoverModels: new Map(),
  hoverOpenTimer: null,
  hoverCloseTimer: null,
  hoverPinned: false,
  hoverKey: null,
  hoverGuideNs: null,
  hoverGuideClientX: null,
  densityRenderTimer: null,
  densityRequestTimer: null,
  densityRequestId: 0,
  densityPendingKey: null,
  densityPageCache: new Map(),
  densityLocalCache: null,
  densityErrorKey: null,
};

const analysisLoadProgress = createAnalysisLoadProgressController({
  fetchSnapshot: () => api("/v1/analysis-load", { cache: "no-store" }),
  render: (snapshot) => renderAnalysisLoadProgress(
    byId("analysis-load-progress"),
    snapshot,
  ),
});

async function analysisRuntimeApi(path, options = {}) {
  const lease = analysisLoadProgress.begin();
  try {
    return await api(path, options);
  } finally {
    analysisLoadProgress.end(lease);
  }
}

function beginLatestRequest(controllerKey) {
  const controller = replaceAbortController(state[controllerKey]);
  state[controllerKey] = controller;
  return controller;
}

function finishLatestRequest(controllerKey, controller) {
  if (state[controllerKey] === controller) state[controllerKey] = null;
}

function requestWasAborted(error, controller) {
  return controller?.signal.aborted || error?.name === "AbortError";
}

function abortLatestRequests(...controllerKeys) {
  controllerKeys.forEach((key) => {
    state[key]?.abort();
    state[key] = null;
  });
}

function workspaceMetadata(dataset = state.dataset) {
  const metadata = dataset?.workspace;
  return metadata && typeof metadata === "object" ? metadata : {};
}

function workspaceNodeId() {
  const workspace = workspaceMetadata();
  return String(
    workspace.node_id
    || navigationContext.nodeId
    || state.dataset?.node_id
    || "local-node",
  );
}

const navigationContext = (() => {
  const params = new URLSearchParams(window.location.search);
  const rawTime = params.get("time_ns");
  return {
    memberId: params.get("member_id") || "",
    nodeId: params.get("node_id") || "",
    revisionId: params.get("revision_id") || "",
    resourceId: params.get("resource_id") || "",
    contextId: params.get("context_id") || "",
    basisKind: params.get("basis_kind") || "",
    basisOffsetNs: params.get("basis_offset_ns") || params.get("offset_ns") || "",
    clockDomain: params.get("clock_domain") || "",
    clockPolicy: params.get("clock_policy") || "",
    pluginSetId: params.get("plugin_set_id") || "",
    pluginId: params.get("plugin_id") || "",
    projectionId: params.get("projection_id") || "",
    perspectiveId: params.get("status_perspective_id") || "",
    timeNs: rawTime && /^-?\d+$/.test(rawTime) ? rawTime : "",
    returnTo: params.get("return_to") || "",
    focusAvailable: false,
  };
})();

function safeLocalNavigationTarget(value, fallback = "/") {
  if (!value) return fallback;
  try {
    const target = new URL(value, window.location.origin);
    if (target.origin !== window.location.origin) return fallback;
    target.pathname = "/";
    return `${target.pathname}${target.search}${target.hash}`;
  } catch (_error) {
    return fallback;
  }
}

function hasTopologyNavigationContext() {
  return Boolean(navigationContext.contextId || navigationContext.memberId || navigationContext.nodeId || navigationContext.returnTo);
}

function bootstrapDatasetPath() {
  if (!navigationContext.nodeId) return "/v1/workspace";
  const target = new URL(`/v1/nodes/${encodeURIComponent(navigationContext.nodeId)}/workspace`, window.location.origin);
  const parameters = {
    plugin_set_id: navigationContext.pluginSetId,
    plugin_id: navigationContext.pluginId,
    projection_id: navigationContext.projectionId,
    status_perspective_id: navigationContext.perspectiveId,
    basis_kind: navigationContext.basisKind,
    basis_offset_ns: navigationContext.basisOffsetNs,
    time_ns: navigationContext.timeNs,
    clock_domain: navigationContext.clockDomain,
    clock_policy: navigationContext.clockPolicy,
  };
  Object.entries(parameters).forEach(([key, value]) => {
    if (value !== "" && value !== null && value !== undefined) target.searchParams.set(key, value);
  });
  return `${target.pathname}${target.search}`;
}

function topologyLocalMember() {
  const nodes = state.topologyCapabilities?.nodes || [];
  return nodes.find((node) => node?.resources_available !== false) || nodes[0] || null;
}

function navigationTargetsLoadedMember() {
  if (!hasTopologyNavigationContext()) return true;
  // The immutable analysis revision is authoritative. A topology assembly may
  // use a member/node alias that differs from the dump manifest's display ID.
  if (navigationContext.revisionId) {
    return navigationContext.revisionId === String(workspaceMetadata().revision_id || "");
  }
  const localNode = topologyLocalMember();
  const localNodeId = localNode ? topologyNodeId(localNode) : "";
  const localMemberId = String(localNode?.member_id || localNode?.topology_member_id || "");
  if (navigationContext.memberId && localMemberId && navigationContext.memberId !== localMemberId) return false;
  if (navigationContext.nodeId && localNodeId && navigationContext.nodeId !== localNodeId) return false;
  return true;
}

function renderTopologyNavigationBanner() {
  if (!hasTopologyNavigationContext()) return;
  let banner = byId("topology-navigation-context");
  if (!banner) {
    banner = document.createElement("aside");
    banner.id = "topology-navigation-context";
    banner.className = "topology-navigation-context";
    banner.setAttribute("aria-live", "polite");
    document.querySelector(".disclosure")?.insertAdjacentElement("afterend", banner);
  }
  const local = navigationTargetsLoadedMember();
  const localNode = topologyLocalMember();
  const resourcePresent = navigationContext.resourceId && state.resourceById.has(navigationContext.resourceId);
  navigationContext.focusAvailable = Boolean(local && (!navigationContext.resourceId || resourcePresent));
  const basis = navigationContext.basisKind === "relative_to_watermark"
    ? `relative capture context${navigationContext.basisOffsetNs ? ` (${formatDuration(navigationContext.basisOffsetNs)})` : ""}; opened at its resolved time`
    : navigationContext.timeNs ? `resolved time ${navigationContext.timeNs} ns` : "topology query context";
  const availability = navigationContext.focusAvailable
    ? navigationContext.resourceId ? "The scoped resource is available in this loaded revision." : "The member revision is loaded."
    : local
      ? "The referenced resource is not present in this loaded revision; no local resource was selected."
      : `This workspace contains ${localNode ? topologyNodeId(localNode) : "a different member"}; the referenced member is topology-only here, so its local timeline is not being implied.`;
  const returnHref = safeLocalNavigationTarget(navigationContext.returnTo);
  banner.classList.toggle("is-warning", !navigationContext.focusAvailable);
  banner.innerHTML = `<div><span class="inspector-kicker">MULTI-NODE CONTEXT</span><strong>${escapeHtml(navigationContext.nodeId || navigationContext.memberId || "selected member")}</strong><small>${escapeHtml(`${basis} · ${availability}`)}</small></div><div class="topology-navigation-tags">${navigationContext.pluginSetId ? `<code>${escapeHtml(navigationContext.pluginSetId)}</code>` : ""}${navigationContext.projectionId ? `<code>${escapeHtml(navigationContext.projectionId)}</code>` : ""}${navigationContext.perspectiveId ? `<code>${escapeHtml(navigationContext.perspectiveId)}</code>` : ""}${navigationContext.contextId ? `<code>context ${escapeHtml(navigationContext.contextId)}</code>` : ""}</div><a href="${escapeHtml(returnHref)}">Back to multi-node topology</a>`;
}

function updateFabricNavigationLink() {
  const link = byId("open-fabric");
  if (!link || !state.dataset) return;
  if (hasTopologyNavigationContext() && navigationContext.returnTo) {
    link.href = safeLocalNavigationTarget(navigationContext.returnTo);
    return;
  }
  const target = new URL("/", window.location.origin);
  target.searchParams.set("time_ns", state.cursorNs.toString());
  target.searchParams.set("basis_kind", "absolute_time");
  target.searchParams.set("clock_policy", navigationContext.clockPolicy || "strict");
  const localNode = topologyLocalMember();
  if (localNode) {
    const nodeId = topologyNodeId(localNode);
    const memberId = String(localNode.member_id || localNode.topology_member_id || nodeId);
    target.searchParams.set("focus_member", memberId);
    target.searchParams.set("focus_node", nodeId);
  }
  if (state.selectedResourceId) target.searchParams.set("focus_resource", state.selectedResourceId);
  link.href = `${target.pathname}${target.search}#fabric`;
}

function isScaleMode() {
  const workspace = workspaceMetadata();
  return Boolean(
    workspace.scale_mode
    || workspace.large_dataset,
  );
}

function usesServerWindowedHistory() {
  return !isTopologyNodeSnapshot()
    && state.dataset?.history_transport?.mode === "server-windowed";
}

function isNodeWorkspace() {
  const workspace = workspaceMetadata();
  return workspace.scope === "node"
    || workspace.workspace_kind === "node"
    || Boolean(navigationContext.nodeId);
}

function isTopologyNodeSnapshot() {
  const workspace = workspaceMetadata();
  return Boolean(
    workspace.history_mode === "point-in-time"
    || workspace.workspace_kind === "point-in-time-snapshot"
    || workspace.capabilities?.historical_state === false,
  );
}

function topologyNodeSnapshotLabel() {
  const workspace = workspaceMetadata();
  const node = state.dataset?.node_snapshot?.node || topologyLocalMember();
  return String(
    workspace.node_label
    || node?.label
    || node?.display_name
    || node?.node_id
    || workspace.label
    || navigationContext.nodeId
    || "selected node",
  );
}

function nodeSnapshotUnavailableMarkup(title, detail) {
  return `<div class="empty-state">
    <span class="inspector-kicker">NOT SUPPLIED BY THE MEMBER PLUG-IN</span>
    <strong>${escapeHtml(title)}</strong>
    <p>${escapeHtml(detail)}</p>
  </div>`;
}

function renderWorkspaceIdentity() {
  if (!isNodeWorkspace()) return;
  const memberLabel = topologyNodeSnapshotLabel();
  const workspace = workspaceMetadata();
  const resourceCount = Number(workspace.resource_count || state.resourceById.size || 0);
  const eventCount = Number(
    workspace.matched_event_count
    ?? workspace.event_count
    ?? state.dataset?.event_count
    ?? 0,
  );
  const disclosureLabel = document.querySelector(".disclosure strong");
  const heroTitle = document.querySelector(".hero-copy h1");
  const heroDescription = document.querySelector(".hero-copy > p:not(.eyebrow)");
  const primaryAction = document.querySelector(".hero-copy .primary-action");
  if (disclosureLabel) disclosureLabel.textContent = "Node analysis workspace.";
  if (heroTitle) {
    heroTitle.textContent = eventCount > 0
      ? `Inspect ${memberLabel} across ${eventCount.toLocaleString()} events.`
      : `Inspect ${memberLabel} across its available state history.`;
  }
  if (heroDescription) {
    heroDescription.textContent = `This node workspace contains ${resourceCount.toLocaleString()} plug-in-projected ${resourceCount === 1 ? "resource" : "resources"}. Historical state, retained logs, correlations, findings, and dashboards are shown when advertised by this node's runtime capabilities.`;
  }
  if (primaryAction) {
    primaryAction.textContent = "Inspect member resources";
    primaryAction.setAttribute("href", "#resource-tables");
  }
  document.title = `${memberLabel} · Router State Lab`;
}

function initialScaleLaneIds() {
  return (workspaceMetadata().initial_resource_ids || [])
    .map(canonicalResourceId)
    .filter(Boolean)
    .slice(0, MAX_SCALE_TIMELINE_LANES);
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
  if (end <= start) return 0;
  return timelineRatioForTime({ timeNs: toNs(value), startNs: start, endNs: end });
}

function nsAtRatio(ratio) {
  return timelineTimeAtRatio({
    ratio: Math.max(0, Math.min(1, ratio)),
    startNs: state.viewStartNs,
    endNs: state.viewEndNs,
  });
}

function timelineWindowBounds() {
  const start = state.timelineWindowStartNs < state.viewStartNs
    ? state.viewStartNs
    : state.timelineWindowStartNs;
  const end = state.timelineWindowEndNs > state.viewEndNs
    ? state.viewEndNs
    : state.timelineWindowEndNs;
  return end > start ? [start, end] : [state.viewStartNs, state.viewEndNs];
}

function timelineNsAtLocalRatio(ratio) {
  const [startNs, endNs] = timelineWindowBounds();
  return timelineTimeAtRatio({
    ratio: Math.max(0, Math.min(1, ratio)),
    startNs,
    endNs,
  });
}

function timelinePercent(value) {
  const [startNs, endNs] = timelineWindowBounds();
  return timelineRatioForTime({
    timeNs: toNs(value),
    startNs,
    endNs,
    clamp: false,
  }) * 100;
}

function timelinePointVisible(value) {
  const [startNs, endNs] = timelineWindowBounds();
  const candidate = toNs(value);
  return candidate >= startNs && candidate <= endNs;
}

function timelineIntervalVisible(start, end) {
  const [startNs, endNs] = timelineWindowBounds();
  // Resource state, lifecycle, and relationship intervals are half-open.
  // An interval ending exactly at the viewport start must not leave a false
  // minimum-width sliver beside the interval that begins there.
  return timelineHalfOpenIntervalVisible({
    intervalStartNs: toNs(start),
    intervalEndNs: toNs(end),
    startNs,
    endNs,
  });
}

function timelinePointIntervalVisible(start, end) {
  const [startNs, endNs] = timelineWindowBounds();
  return timelineInclusiveIntervalVisible({
    intervalStartNs: toNs(start),
    intervalEndNs: toNs(end),
    startNs,
    endNs,
  });
}

function timelinePhysicalTrackWidth() {
  const width = (byId("timeline-scroll")?.clientWidth || 0) - timelineLaneWidth();
  return Math.max(
    MIN_TIMELINE_TRACK_WIDTH,
    Math.round(width > 0 ? width : TIMELINE_BASE_TRACK_WIDTH),
  );
}

function timelineLaneWidth() {
  return window.matchMedia?.("(max-width: 760px)").matches
    ? COMPACT_TIMELINE_LANE_WIDTH
    : TIMELINE_LANE_WIDTH;
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

function offsetPrecisionForSpan(value) {
  let span = toNs(value);
  if (span < 0n) span = -span;
  let precision = 1;
  let thresholdNs = 100_000_000n;
  while (precision < 9 && span < thresholdNs) {
    precision += 1;
    thresholdNs /= 10n;
  }
  return precision;
}

function visibleTimelineOffsetPrecision() {
  const [startNs, endNs] = timelineWindowBounds();
  const tickSpan = (endNs - startNs) / 6n;
  return offsetPrecisionForSpan(tickSpan > 0n ? tickSpan : 1n);
}

function canonicalResourceId(value) {
  return typeof value === "string" && value.length ? value : null;
}

function typedValueTag(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const tag = value.$rda ?? value.type;
  return typeof tag === "string" && tag.length ? tag : null;
}

function typedValuePayload(value) {
  if (!value || typeof value !== "object") return undefined;
  if (Object.prototype.hasOwnProperty.call(value, "value")) return value.value;
  if (Object.prototype.hasOwnProperty.call(value, "bytes")) return value.bytes;
  if (Object.prototype.hasOwnProperty.call(value, "data")) return value.data;
  if (Object.prototype.hasOwnProperty.call(value, "$bytes")) return value.$bytes;
  return undefined;
}

function readableTypeLabel(tag) {
  const normalized = String(tag || "typed value").replace(/^rda[.:/-]?/i, "");
  const aliases = new Map([
    ["uuid", "UUID"],
    ["ipv4", "IPv4"],
    ["ipv6", "IPv6"],
    ["opaque_uint", "opaque integer"],
    ["bytes", "bytes"],
    ["byte_array", "bytes"],
  ]);
  return aliases.get(normalized.toLowerCase()) || normalized.replaceAll("_", " ");
}

function readableTypedValue(value, seen = new Set(), depth = 0) {
  if (value === null) return "null";
  if (value === undefined) return "unknown";
  if (typeof value === "bigint") return value.toString();
  if (typeof value !== "object") return String(value);
  if (seen.has(value)) return "[circular]";
  if (depth >= 8) return "{...}";
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      return `[${value.map((item) => readableTypedValue(item, seen, depth + 1)).join(", ")}]`;
    }
    const tag = typedValueTag(value);
    const payload = typedValuePayload(value);
    if (tag && payload !== undefined) {
      return `${readableTypeLabel(tag)}: ${readableTypedValue(payload, seen, depth + 1)}`;
    }
    if (Object.prototype.hasOwnProperty.call(value, "$bytes")) {
      return `bytes: ${readableTypedValue(value.$bytes, seen, depth + 1)}`;
    }
    const entries = Object.keys(value).sort().map(
      (key) => `${key}=${readableTypedValue(value[key], seen, depth + 1)}`,
    );
    return `{${entries.join(", ")}}`;
  } finally {
    seen.delete(value);
  }
}

function formatValue(value) {
  return readableTypedValue(value);
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

function safePresentationColor(value, identity = "unknown") {
  return typeof value === "string" && /^#[0-9A-Fa-f]{6}$/.test(value)
    ? value
    : stableColor(identity);
}

function layerConfig(layer) {
  const key = String(layer || "unknown");
  if (!state.layerMeta.has(key)) {
    state.layerMeta.set(key, { label: titleCase(key), color: stableColor(key) });
  }
  const configured = state.layerMeta.get(key) || {};
  return {
    ...configured,
    label: typeof configured.label === "string" && configured.label
      ? configured.label
      : titleCase(key),
    color: safePresentationColor(configured.color, key),
  };
}

function humanLayer(layer) {
  return layerConfig(layer).label;
}

function resourceKindDescriptor(kind) {
  const descriptors = state.dataset?.kind_descriptors || state.dataset?.schema?.resource_kinds || [];
  return descriptors.find((item) => String(item.kind || item.resource_kind || item.type) === String(kind)) || null;
}

function relationshipTypeDescriptors() {
  const descriptors = state.dataset?.relationship_descriptors
    || state.dataset?.schema?.relationship_types
    || state.dataset?.relationship_type_descriptors
    || [];
  return Array.isArray(descriptors) ? descriptors : [];
}

function relationshipTypeDescriptor(relationType) {
  if (typeof relationType !== "string" || !relationType) return null;
  return relationshipTypeDescriptors().find(
    (item) => item && String(item.relation_type ?? item.type ?? "") === relationType,
  ) || null;
}

function relationshipPresentation(relationType) {
  const rawType = typeof relationType === "string" && relationType ? relationType : null;
  const descriptor = relationshipTypeDescriptor(rawType);
  const configuredLabel = typeof descriptor?.label === "string" && descriptor.label.trim()
    ? descriptor.label.trim()
    : null;
  return {
    rawType,
    descriptor,
    known: Boolean(descriptor),
    label: configuredLabel || "Unknown relationship",
    displayLabel: configuredLabel || (rawType ? `Unknown relationship (${rawType})` : "Unknown relationship"),
    directed: descriptor ? descriptor.directed !== false : null,
    structural: descriptor?.structural === true,
  };
}

function relationshipDisplayLabel(relationType) {
  return relationshipPresentation(relationType).displayLabel;
}

function relationshipDirectionSymbol(relationType, direction = "outgoing") {
  if (relationshipPresentation(relationType).directed !== true) return "–";
  return direction === "incoming" ? "←" : "→";
}

function causalLinkDisplayLabel(linkType, descriptorByType = new Map()) {
  const rawType = typeof linkType === "string" && linkType ? linkType : null;
  const descriptor = rawType ? descriptorByType.get(rawType) : null;
  if (typeof descriptor?.label === "string" && descriptor.label.trim()) return descriptor.label.trim();
  return rawType ? `Unknown causal link (${rawType})` : "Unknown causal link";
}

function humanResourceType(kind) {
  const descriptor = resourceKindDescriptor(kind);
  const configured = descriptor?.display_name || descriptor?.label;
  if (typeof configured === "string" && configured.trim()) {
    return configured.trim();
  }
  // Kind IDs are opaque plug-in identifiers.  If a descriptor is missing,
  // preserve the ID verbatim instead of teaching the core router acronyms.
  return String(kind || "unknown");
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

function revisionPath(suffix) {
  const revisionId = workspaceMetadata().revision_id;
  if (!revisionId) throw new Error("Workspace metadata did not declare revision_id.");
  return `/v1/revisions/${encodeURIComponent(revisionId)}/${suffix}`;
}

function durableReviewConfigFromInputs() {
  const values = {
    tenantId: byId("durable-review-tenant")?.value.trim() || "",
    projectId: byId("durable-review-project")?.value.trim() || "",
    workspaceId: byId("durable-review-workspace")?.value.trim() || "",
    principalId: byId("durable-review-principal")?.value.trim() || "",
  };
  return Object.values(values).every(Boolean) ? values : null;
}

function savedDurableReviewConfig() {
  return loadDurableReviewConfig(localStorage, DURABLE_REVIEW_STORAGE_KEY);
}

function saveDurableReviewConfig(config) {
  // A blocked localStorage must not disable the explicit in-memory scope.
  persistDurableReviewConfig(localStorage, DURABLE_REVIEW_STORAGE_KEY, config);
}

function populateDurableReviewInputs(config) {
  if (!config) return;
  byId("durable-review-tenant").value = config.tenantId;
  byId("durable-review-project").value = config.projectId;
  byId("durable-review-workspace").value = config.workspaceId;
  byId("durable-review-principal").value = config.principalId;
}

function durableReviewScopePath(config = state.durableReview.config) {
  if (!config) throw new Error("Durable review is not configured.");
  return `/v1/control-plane/projects/${encodeURIComponent(config.projectId)}/workspaces/${encodeURIComponent(config.workspaceId)}`;
}

function durableReviewConnectionToken() {
  const config = state.durableReview.config;
  const catalogRevisionId = state.durableReview.catalogRevisionId;
  if (!config || !catalogRevisionId) return null;
  return Object.freeze({
    sequence: state.durableReview.connectionSequence,
    tenantId: config.tenantId,
    projectId: config.projectId,
    workspaceId: config.workspaceId,
    principalId: config.principalId,
    catalogRevisionId,
  });
}

function durableReviewTokenConfig(token) {
  if (!token) throw new StaleDurableReviewConnectionError();
  return {
    tenantId: token.tenantId,
    projectId: token.projectId,
    workspaceId: token.workspaceId,
    principalId: token.principalId,
  };
}

function durableReviewTokenIsCurrent(token, { requireReady = true } = {}) {
  return durableReviewTokenMatches(token, {
    sequence: state.durableReview.connectionSequence,
    config: state.durableReview.config,
    catalogRevisionId: state.durableReview.catalogRevisionId,
    status: state.durableReview.status,
  }, { requireReady });
}

async function controlPlaneRequest(path, {
  method = "GET",
  body = null,
  mutate = null,
  responseType = "json",
  headers = {},
  reviewConfig = state.durableReview.config,
  timeoutMs = CONTROL_PLANE_REQUEST_TIMEOUT_MS,
} = {}) {
  return requestDurableReview(path, {
    config: reviewConfig,
    method,
    body,
    mutate,
    responseType,
    headers,
    timeoutMs,
    fetchImpl: (...values) => window.fetch(...values),
    createAbortController: () => new AbortController(),
    setTimer: (...values) => window.setTimeout(...values),
    clearTimer: (value) => window.clearTimeout(value),
  });
}

async function listAllControlPlaneCollection(path, {
  reviewConfig,
  connectionSequence = null,
  label = "control-plane collection",
  maximumRecords = MAX_CONTROL_PLANE_COLLECTION_RECORDS,
} = {}) {
  const assertCurrentConnection = () => {
    if (
      connectionSequence !== null
      && connectionSequence !== state.durableReview.connectionSequence
    ) {
      throw new StaleDurableReviewConnectionError();
    }
  };
  return listControlPlaneCollection(path, {
    request: (target) => controlPlaneRequest(target, { reviewConfig }),
    origin: window.location.origin,
    pageDecision: controlPlaneCollectionPageDecision,
    pageSize: CONTROL_PLANE_COLLECTION_PAGE_SIZE,
    maximumRecords,
    assertCurrent: assertCurrentConnection,
    label,
  });
}

function isDurableReviewReady() {
  return state.durableReview.status === "ready"
    && Boolean(state.durableReview.catalogRevisionId)
    && Boolean(state.durableReview.config);
}

function isDurableReviewWritable() {
  return isDurableReviewReady()
    && state.durableReview.canWrite === true
    && state.durableReview.pendingJournalBlocked !== true;
}

function durableReviewUnavailable(error) {
  return error instanceof ControlPlaneRequestError
    && [0, 401, 503].includes(error.status);
}

function durableReviewOperationBusy(name) {
  return state.durableReview.operations.has(name);
}

function beginDurableReviewOperation(name, conflicts = [name]) {
  const owner = beginReviewOperation(
    state.durableReview.operations,
    name,
    conflicts,
    () => randomIdempotencyKey(`ui-${name}`),
  );
  if (!owner) return null;
  syncDurableReviewControls();
  return owner;
}

function finishDurableReviewOperation(name, owner) {
  if (!finishReviewOperation(state.durableReview.operations, name, owner)) return;
  syncDurableReviewControls();
}

function pendingJournalOptions() {
  return {
    maximumEntries: MAX_TOTAL_PENDING_REVIEW_MUTATIONS,
    maximumPerScopeEntries: MAX_PENDING_REVIEW_MUTATIONS,
  };
}

function restorePendingMutationMap(snapshot) {
  state.durableReview.pendingMutations.clear();
  snapshot.forEach((value, key) => {
    state.durableReview.pendingMutations.set(key, value);
  });
}

function blockPendingMutationJournal(error, recovery = "all") {
  state.durableReview.pendingJournalBlocked = true;
  state.durableReview.pendingJournalError = String(
    error?.message || "The unresolved mutation journal is unavailable.",
  ).slice(0, 512);
  state.durableReview.pendingJournalRecovery = recovery;
  syncDurableReviewControls();
}

function clearPendingMutationJournalBlock() {
  state.durableReview.pendingJournalBlocked = false;
  state.durableReview.pendingJournalError = "";
  state.durableReview.pendingJournalRecovery = "";
}

function recoverPendingMutationCapacity(scopeKey = "") {
  if (state.durableReview.pendingJournalRecovery === "global") {
    if (state.durableReview.pendingMutations.size < MAX_TOTAL_PENDING_REVIEW_MUTATIONS) {
      clearPendingMutationJournalBlock();
    }
    return;
  }
  if (state.durableReview.pendingJournalRecovery !== "scope" || !scopeKey) return;
  const scopeCount = [...state.durableReview.pendingMutations.values()].filter(
    (pending) => pending?.scopeKey === scopeKey,
  ).length;
  if (scopeCount < MAX_PENDING_REVIEW_MUTATIONS) {
    clearPendingMutationJournalBlock();
  }
}

function persistPendingMutationJournal() {
  return savePendingReviewMutations(
    localStorage,
    DURABLE_REVIEW_PENDING_STORAGE_KEY,
    state.durableReview.pendingMutations,
    pendingJournalOptions(),
  );
}

async function pendingDurableReviewMutation(token, kind, payload, idPrefix) {
  if (state.durableReview.pendingJournalBlocked) {
    throw new DurableReviewJournalError(
      state.durableReview.pendingJournalError
      || "Reset the unresolved mutation journal before writing.",
    );
  }
  const payloadIdentity = await durableMutationPayloadIdentity(payload);
  if (!durableReviewTokenIsCurrent(token)) {
    throw new StaleDurableReviewConnectionError();
  }
  const priorSize = state.durableReview.pendingMutations.size;
  let pending;
  try {
    pending = reservePendingReviewMutation(
      state.durableReview.pendingMutations,
      token,
      kind,
      payloadIdentity,
      idPrefix,
      {
        maximumEntries: MAX_PENDING_REVIEW_MUTATIONS,
        maximumTotalEntries: MAX_TOTAL_PENDING_REVIEW_MUTATIONS,
        createId: randomIdempotencyKey,
      },
    );
  } catch (error) {
    if (error instanceof DurableReviewJournalCapacityError) {
      blockPendingMutationJournal(error, error.capacity);
    }
    throw error;
  }
  if (state.durableReview.pendingMutations.size !== priorSize) {
    try {
      persistPendingMutationJournal();
    } catch (error) {
      completePendingReviewMutation(state.durableReview.pendingMutations, pending);
      blockPendingMutationJournal(error);
      throw error;
    }
  }
  return pending;
}

function completeDurableReviewMutation(pending) {
  const snapshot = new Map(state.durableReview.pendingMutations);
  const removed = completePendingReviewMutation(
    state.durableReview.pendingMutations,
    pending,
  );
  if (!removed) return false;
  try {
    persistPendingMutationJournal();
  } catch (error) {
    restorePendingMutationMap(snapshot);
    blockPendingMutationJournal(error);
    return false;
  }
  return true;
}

function reconcilePendingDurableReviewMutations(
  connectionToken,
  { annotations = [], report = null } = {},
) {
  if (!durableReviewTokenIsCurrent(connectionToken)) return;
  const scopeKey = durableMutationScopeKey(connectionToken);
  const annotationIds = new Set(
    annotations.map((item) => String(item?.annotation_id || "")).filter(Boolean),
  );
  const correlationIds = new Set(
    (report?.correlations?.manual_event_correlations || [])
      .map((item) => String(
        item?.correlation?.correlation_id || item?.correlation_id || "",
      ))
      .filter(Boolean),
  );
  const snapshot = new Map(state.durableReview.pendingMutations);
  const reconciled = reconcilePendingReviewMutations(
    state.durableReview.pendingMutations,
    scopeKey,
    { annotationIds, correlationIds },
  );
  if (!reconciled) return;
  try {
    persistPendingMutationJournal();
  } catch (error) {
    restorePendingMutationMap(snapshot);
    blockPendingMutationJournal(error);
    return;
  }
  recoverPendingMutationCapacity(scopeKey);
}

function syncDurableReviewControls() {
  const status = byId("durable-review-state");
  const detail = byId("durable-review-detail");
  if (!status || !detail) return;
  const labels = {
    local: "Browser-only markers",
    connecting: "Connecting",
    ready: "Durable review connected",
    error: "Browser-only fallback",
  };
  const ready = isDurableReviewReady();
  const serverWritable = ready && state.durableReview.canWrite === true;
  const journalBlocked = state.durableReview.pendingJournalBlocked === true;
  const connecting = durableReviewOperationBusy("connect");
  const markerBusy = durableReviewOperationBusy("marker");
  const correlationBusy = durableReviewOperationBusy("correlation");
  const reportBusy = durableReviewOperationBusy("report");
  const selectionCount = eventLogSelectionCount();
  const selectionOverLimit = selectionCount > MAX_EVENT_LOG_SELECTION_ITEMS
    || state.eventLogSelectionRanges.length > MAX_EVENT_LOG_SELECTION_RANGES;
  const selectionActionReady = selectionCount > 0 && !selectionOverLimit;
  const availability = durableReviewControlAvailability({
    ready,
    writable: serverWritable,
    journalBlocked,
    connecting,
    markerBusy,
    correlationBusy,
    reportBusy,
    selectionReady: selectionActionReady,
  });
  status.dataset.state = journalBlocked
    ? "error"
    : ready && !serverWritable
    ? "readonly"
    : state.durableReview.status;
  status.textContent = journalBlocked
    ? "Mutation journal needs attention"
    : ready && !serverWritable
    ? "Durable review read only"
    : labels[state.durableReview.status] || labels.local;
  detail.textContent = journalBlocked
    ? `${state.durableReview.pendingJournalError} ${state.durableReview.pendingJournalRecovery === "scope"
      ? "Discard the connected scope's unresolved writes or reset all scopes before another durable write."
      : "Explicitly reset unresolved writes across all scopes before another durable write."}`
    : state.durableReview.detail;
  const connect = byId("durable-review-connect");
  if (connect) {
    connect.disabled = availability.connectDisabled;
    connect.setAttribute("aria-busy", String(connecting));
  }
  ["durable-review-tenant", "durable-review-project", "durable-review-workspace", "durable-review-principal"]
    .forEach((id) => {
      const control = byId(id);
      if (control) control.disabled = availability.connectDisabled;
    });
  ["durable-review-copy-report", "durable-review-download-report"].forEach((id) => {
    const control = byId(id);
    if (!control) return;
    control.disabled = availability.reportDisabled;
    control.setAttribute("aria-busy", String(reportBusy));
  });
  byId("durable-review-report-scope").disabled = availability.reportScopeDisabled;
  const discardJournal = byId("durable-review-discard-pending");
  const connectionToken = durableReviewConnectionToken();
  const currentScopeKey = connectionToken
    ? durableMutationScopeKey(connectionToken)
    : "";
  const currentScopePendingCount = currentScopeKey
    ? [...state.durableReview.pendingMutations.values()].filter(
      (pending) => pending?.scopeKey === currentScopeKey,
    ).length
    : 0;
  if (discardJournal) {
    discardJournal.disabled = connecting
      || markerBusy
      || correlationBusy
      || reportBusy
      || currentScopePendingCount === 0;
    discardJournal.textContent = "Discard unresolved scope writes";
    discardJournal.title = currentScopePendingCount
      ? `Discard ${currentScopePendingCount.toLocaleString()} unresolved writes for the connected scope. Server-side outcomes are not changed.`
      : "The connected scope has no unresolved writes.";
  }
  const resetJournal = byId("durable-review-reset-pending");
  if (resetJournal) {
    resetJournal.disabled = connecting
      || markerBusy
      || correlationBusy
      || reportBusy
      || (!journalBlocked && state.durableReview.pendingMutations.size === 0);
    resetJournal.title = "Forget every unresolved browser identity across every review scope. Server-side outcomes are not changed.";
  }
  ["event-selection-mark", "event-selection-unmark"].forEach((id) => {
    const control = byId(id);
    if (!control) return;
    control.disabled = availability.markerDisabled;
    control.setAttribute("aria-busy", String(markerBusy));
    control.title = journalBlocked
      ? "Reset or reconcile the unresolved mutation journal before writing."
      : availability.durableReadOnly
      ? "This durable review identity is read only. Use browser-only mode for local markers."
      : selectionOverLimit
        ? `Actions support at most ${MAX_EVENT_LOG_SELECTION_ITEMS.toLocaleString()} rows across ${MAX_EVENT_LOG_SELECTION_RANGES} ranges.`
        : "";
  });
  const correlate = byId("event-selection-correlate");
  if (correlate) {
    correlate.disabled = availability.correlationDisabled;
    correlate.setAttribute("aria-busy", String(correlationBusy));
    correlate.title = journalBlocked
      ? "Reset or reconcile the unresolved mutation journal before writing."
      : ready && !serverWritable
      ? "This durable review identity is read only."
      : !ready
        ? "Connect an explicit writable durable review scope to create a correlation."
        : selectionOverLimit
          ? `Actions support at most ${MAX_EVENT_LOG_SELECTION_ITEMS.toLocaleString()} rows across ${MAX_EVENT_LOG_SELECTION_RANGES} ranges.`
          : "";
  }
}

function selectedDurableReportScope() {
  const option = byId("durable-review-report-scope")?.selectedOptions?.[0];
  if (!option?.dataset.kind || !option.dataset.id) {
    return state.durableReview.catalogRevisionId
      ? { kind: "revision", id: state.durableReview.catalogRevisionId }
      : null;
  }
  return { kind: option.dataset.kind, id: option.dataset.id };
}

function syncDurableReportScopeNote() {
  const note = byId("durable-review-scope-note");
  if (!note) return;
  const selected = selectedDurableReportScope();
  if (!selected) {
    note.textContent = "Connect to select an immutable revision or a multi-revision session.";
    return;
  }
  if (selected.kind === "session") {
    const session = state.durableReview.sessions.find(
      (item) => String(item.session_id) === selected.id,
    );
    const memberCount = Array.isArray(session?.members) ? session.members.length : 0;
    note.textContent = `AI report resolves the current membership of live session ${selected.id} (${memberCount.toLocaleString()} immutable ${memberCount === 1 ? "revision" : "revisions"} as last loaded). Choose a snapshot for a reproducible frozen revision vector. This page still renders only the active node revision.`;
    return;
  }
  if (selected.kind === "snapshot") {
    const snapshot = state.durableReview.snapshots.find(
      (item) => String(item.snapshot_id) === selected.id,
    );
    const memberCount = Array.isArray(snapshot?.members) ? snapshot.members.length : 0;
    note.textContent = `AI report uses immutable snapshot ${selected.id} from session ${snapshot?.session_id || "unknown"} version ${snapshot?.session_version ?? "unknown"} (${memberCount.toLocaleString()} ${memberCount === 1 ? "revision" : "revisions"}).`;
    return;
  }
  const active = selected.id === state.durableReview.catalogRevisionId;
  note.textContent = active
    ? "AI report and row subjects use this page's exact active catalog revision."
    : `AI report uses immutable revision ${selected.id}. This page does not render or create subjects for that other revision.`;
}

function renderDurableReportScopes() {
  const select = byId("durable-review-report-scope");
  if (!select) return;
  const prior = state.durableReview.reportScope;
  select.replaceChildren();
  const revisionGroup = document.createElement("optgroup");
  revisionGroup.label = "Immutable revisions";
  state.durableReview.revisions.forEach((revision) => {
    const revisionId = String(revision.revision_id || "");
    if (!revisionId) return;
    const option = document.createElement("option");
    option.dataset.kind = "revision";
    option.dataset.id = revisionId;
    option.value = `revision:${revisionId}`;
    const active = revisionId === state.durableReview.catalogRevisionId;
    const source = String(revision.metadata?.source_revision_id || revisionId);
    option.textContent = `${active ? "Active page - " : ""}${revision.node_id || "node"} - ${source}`;
    revisionGroup.appendChild(option);
  });
  if (revisionGroup.children.length) select.appendChild(revisionGroup);
  const validationSuffix = (validation) => {
    if (validation.valid) return "";
    if (validation.reason === "oversized") {
      return ` (exceeds ${MAX_DURABLE_REPORT_REVISIONS}-revision report limit)`;
    }
    if (validation.reason === "duplicate") return " (duplicate revisions)";
    if (validation.reason === "invalid") return " (invalid member)";
    return " (empty)";
  };
  const snapshotGroup = document.createElement("optgroup");
  snapshotGroup.label = "Immutable session snapshots";
  state.durableReview.snapshots.forEach((snapshot) => {
    const snapshotId = String(snapshot.snapshot_id || "");
    if (!snapshotId) return;
    const validation = durableReportMemberValidation(
      snapshot.members,
      MAX_DURABLE_REPORT_REVISIONS,
    );
    const option = document.createElement("option");
    option.dataset.kind = "snapshot";
    option.dataset.id = snapshotId;
    option.value = `snapshot:${snapshotId}`;
    option.textContent = `${snapshot.session_id || "session"} v${snapshot.session_version ?? "?"} snapshot - ${validation.memberCount} ${validation.memberCount === 1 ? "revision" : "revisions"}${validationSuffix(validation)}`;
    option.disabled = !validation.valid;
    snapshotGroup.appendChild(option);
  });
  if (snapshotGroup.children.length) select.appendChild(snapshotGroup);
  const sessionGroup = document.createElement("optgroup");
  sessionGroup.label = "Live multi-revision sessions";
  state.durableReview.sessions.forEach((session) => {
    const sessionId = String(session.session_id || "");
    if (!sessionId) return;
    const members = Array.isArray(session.members) ? session.members : [];
    const validation = durableReportMemberValidation(
      members,
      MAX_DURABLE_REPORT_REVISIONS,
    );
    const option = document.createElement("option");
    option.dataset.kind = "session";
    option.dataset.id = sessionId;
    option.value = `session:${sessionId}`;
    option.textContent = `${session.label || sessionId} - ${validation.memberCount} ${validation.memberCount === 1 ? "revision" : "revisions"}${validationSuffix(validation)}`;
    option.disabled = !validation.valid;
    sessionGroup.appendChild(option);
  });
  if (sessionGroup.children.length) select.appendChild(sessionGroup);
  const available = [...select.options].filter((option) => !option.disabled);
  const preferred = available.find(
    (option) => option.dataset.kind === prior?.kind && option.dataset.id === prior?.id,
  ) || available.find(
    (option) => option.dataset.kind === "revision"
      && option.dataset.id === state.durableReview.catalogRevisionId,
  ) || available[0];
  if (preferred) {
    preferred.selected = true;
    state.durableReview.reportScope = {
      kind: preferred.dataset.kind,
      id: preferred.dataset.id,
    };
  } else {
    const option = document.createElement("option");
    option.textContent = "No reportable revisions, snapshots, or sessions";
    select.appendChild(option);
    state.durableReview.reportScope = null;
  }
  syncDurableReportScopeNote();
}

function setDurableReviewStatus(status, detail) {
  state.durableReview.status = status;
  state.durableReview.detail = detail;
  syncDurableReviewControls();
}

function clearDurableReviewMarkers() {
  for (const entryId of state.durableReview.markedEntryIds) {
    if (!state.localMarkedTimelineEntryIds.has(entryId)) {
      state.markedTimelineEntryIds.delete(entryId);
    }
    forgetTimelineEntryProjection(entryId);
  }
  state.durableReview.annotations.clear();
  state.durableReview.annotationIdsByEntry.clear();
  state.durableReview.markedEntryIds.clear();
}

function entryIdForReviewSubject(subject) {
  if (subject?.kind === "event" && subject.subject_id) {
    return normalizedLogEntryId(String(subject.subject_id));
  }
  if (subject?.kind === "source_record" && subject.subject_id) {
    return sourceLogEntryId(String(subject.subject_id));
  }
  return "";
}

function reviewSubjectKey(subject) {
  return [
    String(subject?.revision_id || ""),
    String(subject?.kind || ""),
    String(subject?.subject_id || ""),
    String(subject?.start_ns ?? ""),
    String(subject?.end_ns ?? ""),
  ].join("\u001f");
}

function exactReviewSubject(item) {
  const kind = String(item?.stream_kind || "event");
  const uid = String(item?.uid || "");
  if (!uid || !["event", "source"].includes(kind)) return null;
  return {
    revision_id: state.durableReview.catalogRevisionId,
    kind: kind === "source" ? "source_record" : "event",
    subject_id: uid,
  };
}

function rememberDurableAnnotation(
  annotation,
  connectionToken = durableReviewConnectionToken(),
) {
  if (!durableReviewTokenIsCurrent(connectionToken)) return false;
  const projection = buildDurableAnnotationMarkerIndex(
    [annotation],
    connectionToken.catalogRevisionId,
    entryIdForReviewSubject,
  );
  projection.annotations.forEach((value, annotationId) => {
    state.durableReview.annotations.set(annotationId, value);
  });
  projection.annotationIdsByEntry.forEach((annotationIds, entryId) => {
    if (!state.durableReview.annotationIdsByEntry.has(entryId)) {
      state.durableReview.annotationIdsByEntry.set(entryId, new Set());
    }
    annotationIds.forEach(
      (annotationId) => state.durableReview.annotationIdsByEntry.get(entryId).add(annotationId),
    );
  });
  projection.markedEntryIds.forEach((entryId) => {
    state.durableReview.markedEntryIds.add(entryId);
    state.markedTimelineEntryIds.add(entryId);
  });
  return true;
}

function durableReportValidationMessage(label, validation) {
  if (validation.reason === "oversized") {
    return `${label} contains ${validation.memberCount.toLocaleString()} revisions; this UI supports at most ${MAX_DURABLE_REPORT_REVISIONS.toLocaleString()} per report.`;
  }
  if (validation.reason === "duplicate") {
    return `${label} contains duplicate revisions and is not reportable.`;
  }
  if (validation.reason === "invalid") {
    return `${label} contains an invalid revision member.`;
  }
  return `${label} contains no revision members.`;
}

async function validateDurableReportScope(reportScope, connectionToken) {
  if (reportScope.kind === "revision") return reportScope;
  const config = durableReviewTokenConfig(connectionToken);
  let record;
  if (reportScope.kind === "session") {
    record = await awaitCurrentDurableReview(
      () => controlPlaneRequest(
        `${durableReviewScopePath(config)}/sessions/${encodeURIComponent(reportScope.id)}`,
        { reviewConfig: config },
      ),
      () => durableReviewTokenIsCurrent(connectionToken),
    );
    const index = state.durableReview.sessions.findIndex(
      (item) => String(item.session_id || "") === reportScope.id,
    );
    if (index >= 0) state.durableReview.sessions[index] = record;
  } else if (reportScope.kind === "snapshot") {
    record = state.durableReview.snapshots.find(
      (item) => String(item.snapshot_id || "") === reportScope.id,
    );
  } else {
    throw new Error("Unsupported durable report scope.");
  }
  const validation = durableReportMemberValidation(
    record?.members,
    MAX_DURABLE_REPORT_REVISIONS,
  );
  if (!validation.valid) {
    if (reportScope.kind === "session") renderDurableReportScopes();
    throw new Error(
      durableReportValidationMessage(
        reportScope.kind === "session"
          ? `Live session ${reportScope.id}`
          : `Snapshot ${reportScope.id}`,
        validation,
      ),
    );
  }
  if (reportScope.kind === "session") syncDurableReportScopeNote();
  return reportScope;
}

async function durableCorrelationReport(
  format = "json",
  scopeOverride = null,
  connectionToken = durableReviewConnectionToken(),
) {
  if (!durableReviewTokenIsCurrent(connectionToken)) {
    throw new Error("Connect a durable review scope before generating a report.");
  }
  const config = durableReviewTokenConfig(connectionToken);
  const target = new URL(
    `${durableReviewScopePath(config)}/correlation-report`,
    window.location.origin,
  );
  target.searchParams.set("format", format);
  const reportScope = scopeOverride || selectedDurableReportScope();
  if (!reportScope) throw new Error("Select a report revision, snapshot, or session.");
  const isCurrent = () => durableReviewTokenIsCurrent(connectionToken);
  const validatedScope = await awaitCurrentDurableReview(
    () => validateDurableReportScope(reportScope, connectionToken),
    isCurrent,
  );
  return awaitCurrentDurableReview(
    () => controlPlaneRequest(`${target.pathname}${target.search}`, {
      ...durableReadPostRequestOptions({
        body: durableReportRequestBody(validatedScope),
      }),
      responseType: format === "markdown" ? "text" : "json",
      reviewConfig: config,
      timeoutMs: CONTROL_PLANE_REPORT_TIMEOUT_MS,
    }),
    isCurrent,
  );
}

function hydrateDurableReviewProjections(report, connectionToken) {
  if (!durableReviewTokenIsCurrent(connectionToken)) return false;
  const observations = report?.observations || {};
  const events = Array.isArray(observations.events) ? observations.events : [];
  const sources = Array.isArray(observations.source_records)
    ? observations.source_records
    : [];
  events.forEach((entry) => {
    const uid = String(entry.event_uid || entry.event_id || "");
    const entryId = normalizedLogEntryId(uid);
    if (!uid || !state.durableReview.markedEntryIds.has(entryId)) return;
    rememberTimelineEntryProjection({
      entry_id: entryId,
      stream_kind: "event",
      uid,
      timestamp_ns: String(entry.time_ns ?? entry.timestamp_ns ?? entry.start_ns ?? "0"),
      resource_ids: eventResourceRefs(entry),
      entry,
    });
  });
  sources.forEach((entry) => {
    const uid = sourceRecordUid(entry);
    const entryId = sourceLogEntryId(uid);
    if (!uid || !state.durableReview.markedEntryIds.has(entryId)) return;
    rememberTimelineEntryProjection({
      entry_id: entryId,
      stream_kind: "source",
      uid,
      timestamp_ns: String(entry.time_ns ?? entry.timestamp_ns ?? "0"),
      resource_ids: [],
      entry,
    });
  });
  return true;
}

async function loadDurableReviewAnnotations(
  connectionToken = durableReviewConnectionToken(),
) {
  if (!durableReviewTokenIsCurrent(connectionToken)) return false;
  const config = durableReviewTokenConfig(connectionToken);
  const isCurrent = () => durableReviewTokenIsCurrent(connectionToken);
  const result = await loadThenCommitConfirmedState(
    () => awaitCurrentDurableReview(
      () => listAllDurableAnnotations(
        `${durableReviewScopePath(config)}/annotations`,
        {
          request: (target) => controlPlaneRequest(target, { reviewConfig: config }),
          origin: window.location.origin,
          isCurrent,
          pageSize: DURABLE_REVIEW_PAGE_SIZE,
          maximumRecords: MAX_DURABLE_REVIEW_RECORDS,
        },
      ),
      isCurrent,
    ),
    (confirmed) => {
      // A timeout, abort, malformed page, or repeated watermark conflict never
      // enters this commit and therefore leaves the last confirmed truth intact.
      const projection = buildDurableAnnotationMarkerIndex(
        confirmed.items,
        connectionToken.catalogRevisionId,
        entryIdForReviewSubject,
      );
      clearDurableReviewMarkers();
      state.durableReview.annotations = projection.annotations;
      state.durableReview.annotationIdsByEntry = projection.annotationIdsByEntry;
      state.durableReview.markedEntryIds = projection.markedEntryIds;
      projection.markedEntryIds.forEach((entryId) => {
        state.markedTimelineEntryIds.add(entryId);
      });
    },
  );
  reconcilePendingDurableReviewMutations(connectionToken, {
    annotations: result.items,
  });
  let correlationCount = null;
  let projectionWarning = "";
  try {
    const report = await awaitCurrentDurableReview(
      () => durableCorrelationReport("json", {
        kind: "revision",
        id: connectionToken.catalogRevisionId,
      }, connectionToken),
      isCurrent,
    );
    hydrateDurableReviewProjections(report, connectionToken);
    reconcilePendingDurableReviewMutations(connectionToken, { report });
    const declaredCount = Number(report?.summary?.manual_correlation_count);
    if (Number.isSafeInteger(declaredCount) && declaredCount >= 0) {
      correlationCount = declaredCount;
    }
  } catch (error) {
    if (!durableReviewTokenIsCurrent(connectionToken)) return false;
    const reason = String(error?.message || "unknown report error")
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, 240);
    projectionWarning = ` Report projection warning: ${reason}. Durable row markers remain exact, but unloaded timeline projections and the manual-correlation count may be incomplete.`;
  }
  if (!durableReviewTokenIsCurrent(connectionToken)) return false;
  rerenderTimelinePreservingScroll();
  renderEventTableWindow();
  const markerCount = state.durableReview.markedEntryIds.size;
  const countCopy = `${markerCount.toLocaleString()} durable ${markerCount === 1 ? "marker" : "markers"}`;
  const correlationCopy = correlationCount === null
    ? ""
    : `; ${correlationCount.toLocaleString()} manual ${correlationCount === 1 ? "correlation" : "correlations"}`;
  const accessCopy = state.durableReview.canWrite
    ? ""
    : "Read-only durable connection; marker and correlation writes are disabled. ";
  state.durableReview.detail = `${accessCopy}${countCopy}${correlationCopy} for active page revision ${connectionToken.catalogRevisionId}. Report scope is selected separately.${projectionWarning}`;
  return true;
}

async function connectDurableReview({ quiet = false } = {}) {
  // Correlation subjects are captured under the previously active scope.
  // Never carry that mutable dialog state through any reconnect attempt.
  closeManualCorrelationDialog();
  const config = durableReviewConfigFromInputs();
  if (!config) {
    state.durableReview.connectionSequence += 1;
    state.durableReview.config = null;
    state.durableReview.catalogRevisionId = "";
    state.durableReview.revisions = [];
    state.durableReview.sessions = [];
    state.durableReview.snapshots = [];
    state.durableReview.reportScope = null;
    state.durableReview.canWrite = false;
    clearDurableReviewMarkers();
    renderDurableReportScopes();
    setDurableReviewStatus(
      "local",
      "Add the four scope values to persist markers and correlations.",
    );
    if (!quiet) byId("durable-review-setup").open = true;
    return;
  }
  const operationOwner = beginDurableReviewOperation(
    "connect",
    ["connect", "marker", "correlation", "report"],
  );
  if (!operationOwner) {
    if (!quiet) showToast("Wait for the current durable review action to finish.");
    return;
  }
  const previousConnection = {
    token: durableReviewConnectionToken(),
    config: state.durableReview.config,
    catalogRevisionId: state.durableReview.catalogRevisionId,
    revisions: state.durableReview.revisions,
    sessions: state.durableReview.sessions,
    snapshots: state.durableReview.snapshots,
    reportScope: state.durableReview.reportScope,
  };
  const requestedPreviousScope = previousConnection.token
    ? {
      ...config,
      catalogRevisionId: previousConnection.token.catalogRevisionId,
    }
    : null;
  let preservePreviousOnFailure = durableReviewScopesEqual(
    previousConnection.token,
    requestedPreviousScope,
  );
  const sequence = ++state.durableReview.connectionSequence;
  state.durableReview.config = config;
  saveDurableReviewConfig(config);
  state.durableReview.catalogRevisionId = "";
  state.durableReview.revisions = [];
  state.durableReview.sessions = [];
  state.durableReview.snapshots = [];
  state.durableReview.canWrite = false;
  if (!preservePreviousOnFailure) clearDurableReviewMarkers();
  setDurableReviewStatus("connecting", "Validating tenant, project, workspace, and revision...");
  try {
    const context = await controlPlaneRequest("/v1/control-plane/context", {
      reviewConfig: config,
    });
    if (sequence !== state.durableReview.connectionSequence) return;
    const workspaces = await listAllControlPlaneCollection(
      `/v1/control-plane/projects/${encodeURIComponent(config.projectId)}/workspaces`,
      {
        reviewConfig: config,
        connectionSequence: sequence,
        label: "Workspace catalog",
      },
    );
    if (!workspaces.some(
      (item) => String(item.workspace_id) === config.workspaceId,
    )) {
      throw new ControlPlaneRequestError(
        "The explicit workspace is not present in this project.",
        404,
      );
    }
    const [revisions, sessions, snapshots] = await Promise.all([
      listAllControlPlaneCollection(`${durableReviewScopePath(config)}/revisions`, {
        reviewConfig: config,
        connectionSequence: sequence,
        label: "Revision catalog",
      }),
      listAllControlPlaneCollection(`${durableReviewScopePath(config)}/sessions`, {
        reviewConfig: config,
        connectionSequence: sequence,
        label: "Session catalog",
      }),
      listAllControlPlaneCollection(`${durableReviewScopePath(config)}/snapshots`, {
        reviewConfig: config,
        connectionSequence: sequence,
        label: "Session snapshot catalog",
      }),
    ]);
    const sourceRevisionId = String(workspaceMetadata().revision_id || "");
    const direct = revisions.filter(
      (item) => String(item.revision_id || "") === sourceRevisionId,
    );
    let matches = direct.length ? direct : revisions.filter(
      (item) => String(item.metadata?.source_revision_id || "") === sourceRevisionId,
    );
    if (matches.length > 1) {
      const nodeId = workspaceNodeId();
      const nodeMatches = matches.filter(
        (item) => String(item.node_id || "") === nodeId,
      );
      if (nodeMatches.length) matches = nodeMatches;
    }
    if (matches.length !== 1) {
      throw new ControlPlaneRequestError(
        matches.length
          ? "This node revision maps to multiple catalog revisions in the explicit workspace."
          : "This node revision is not published in the explicit workspace.",
        409,
      );
    }
    if (sequence !== state.durableReview.connectionSequence) return;
    state.durableReview.catalogRevisionId = String(matches[0].revision_id);
    state.durableReview.revisions = revisions;
    state.durableReview.sessions = sessions;
    state.durableReview.snapshots = snapshots;
    state.durableReview.canWrite = context?.can_write === true;
    const candidateScope = {
      ...config,
      catalogRevisionId: state.durableReview.catalogRevisionId,
    };
    preservePreviousOnFailure = durableReviewScopesEqual(
      previousConnection.token,
      candidateScope,
    );
    if (!preservePreviousOnFailure) clearDurableReviewMarkers();
    state.durableReview.status = "ready";
    renderDurableReportScopes();
    const connectionToken = durableReviewConnectionToken();
    if (!connectionToken) throw new StaleDurableReviewConnectionError();
    const loaded = await loadDurableReviewAnnotations(connectionToken);
    if (!loaded || !durableReviewTokenIsCurrent(connectionToken)) return;
    setDurableReviewStatus("ready", state.durableReview.detail);
    renderEventLogSelectionToolbar();
    if (!quiet) {
      showToast(
        state.durableReview.canWrite
          ? "Durable review connected to the exact catalog revision."
          : "Durable review connected read-only; report actions remain available.",
      );
    }
  } catch (error) {
    if (sequence !== state.durableReview.connectionSequence) return;
    const unavailable = durableReviewUnavailable(error);
    if (preservePreviousOnFailure && previousConnection.token) {
      state.durableReview.config = previousConnection.config;
      state.durableReview.catalogRevisionId = previousConnection.catalogRevisionId;
      state.durableReview.revisions = previousConnection.revisions;
      state.durableReview.sessions = previousConnection.sessions;
      state.durableReview.snapshots = previousConnection.snapshots;
      state.durableReview.reportScope = previousConnection.reportScope;
      // Preserve the last confirmed projection, but never preserve an old
      // authorization decision after a failed context/scope refresh.
      state.durableReview.canWrite = false;
      renderDurableReportScopes();
      setDurableReviewStatus(
        "error",
        `${unavailable ? "Control plane unavailable" : "Scope refresh failed"}: ${error.message}. Showing the last confirmed durable markers for this same scope.`,
      );
    } else {
      clearDurableReviewMarkers();
      state.durableReview.catalogRevisionId = "";
      state.durableReview.revisions = [];
      state.durableReview.sessions = [];
      state.durableReview.snapshots = [];
      state.durableReview.reportScope = null;
      state.durableReview.canWrite = false;
      renderDurableReportScopes();
      setDurableReviewStatus(
        "error",
        `${unavailable ? "Control plane unavailable" : "Scope could not connect"}: ${error.message}. Markers remain browser-only.`,
      );
    }
    renderEventLogSelectionToolbar();
    if (!quiet) showToast("Durable review could not connect: " + error.message);
  } finally {
    finishDurableReviewOperation("connect", operationOwner);
  }
}

function disconnectDurableReview() {
  state.durableReview.connectionSequence += 1;
  state.durableReview.operations.clear();
  closeManualCorrelationDialog();
  try {
    localStorage.removeItem(DURABLE_REVIEW_STORAGE_KEY);
  } catch (_error) {
    // The in-memory disconnect still applies when storage is unavailable.
  }
  state.durableReview.config = null;
  state.durableReview.catalogRevisionId = "";
  state.durableReview.revisions = [];
  state.durableReview.sessions = [];
  state.durableReview.snapshots = [];
  state.durableReview.reportScope = null;
  state.durableReview.canWrite = false;
  clearDurableReviewMarkers();
  renderDurableReportScopes();
  setDurableReviewStatus(
    "local",
    "Browser-only markers are active. Submit the explicit scope to reconnect.",
  );
  rerenderTimelinePreservingScroll();
  renderEventTableWindow();
  renderEventLogSelectionToolbar();
  showToast("Durable review disconnected; local markers remain.");
}

function discardPendingDurableReviewMutations() {
  const snapshot = new Map(state.durableReview.pendingMutations);
  const connectionToken = durableReviewConnectionToken();
  if (!connectionToken) {
    showToast("Connect the review scope whose unresolved writes should be discarded.");
    return;
  }
  let discarded = 0;
  try {
    discarded = discardPendingReviewMutationsForScope(
      state.durableReview.pendingMutations,
      connectionToken,
    );
    persistPendingMutationJournal();
  } catch (error) {
    restorePendingMutationMap(snapshot);
    blockPendingMutationJournal(error);
    showToast("Could not reset unresolved durable writes: " + error.message);
    return;
  }
  recoverPendingMutationCapacity(durableMutationScopeKey(connectionToken));
  state.durableReview.detail = discarded
    ? `Explicitly discarded ${discarded.toLocaleString()} unresolved durable ${discarded === 1 ? "write" : "writes"}. Server-side outcomes were not changed.`
    : "The unresolved durable mutation journal is empty.";
  syncDurableReviewControls();
  renderEventLogSelectionToolbar();
  showToast(state.durableReview.detail);
}

function resetAllPendingDurableReviewMutations() {
  const warning = "Reset unresolved writes for every review scope in this browser? This forgets retry identities only; it cannot undo server-side outcomes.";
  if (!window.confirm(warning)) return;
  const snapshot = new Map(state.durableReview.pendingMutations);
  let discarded;
  try {
    discarded = resetPendingReviewMutations(
      localStorage,
      DURABLE_REVIEW_PENDING_STORAGE_KEY,
      state.durableReview.pendingMutations,
    );
  } catch (error) {
    restorePendingMutationMap(snapshot);
    blockPendingMutationJournal(error);
    showToast("Could not reset unresolved durable writes: " + error.message);
    return;
  }
  clearPendingMutationJournalBlock();
  state.durableReview.detail = discarded
    ? `Explicitly reset ${discarded.toLocaleString()} unresolved durable ${discarded === 1 ? "write" : "writes"} across all browser scopes. Server-side outcomes were not changed.`
    : "The unresolved durable mutation journal is empty.";
  syncDurableReviewControls();
  renderEventLogSelectionToolbar();
  showToast(state.durableReview.detail);
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

function sourceRecordMatchedEventUids(record) {
  const plural = Array.isArray(record?.matched_event_uids)
    ? record.matched_event_uids.map(String).filter(Boolean)
    : [];
  const singular = record?.matched_event_uid ? [String(record.matched_event_uid)] : [];
  return [...new Set([...plural, ...singular])];
}

function sourceTypeDescriptor(sourceType) {
  const key = String(sourceType || "unknown");
  const descriptor = state.sourceRecordTypes.get(key) || {
    source_type: String(sourceType || "unknown"),
    label: titleCase(sourceType || "unknown"),
    color: stableColor(sourceType || "unknown"),
  };
  return {
    ...descriptor,
    color: safePresentationColor(descriptor.color, key),
  };
}

function sourceDescriptorStreamGroup(descriptor, sourceType = descriptor?.source_type) {
  const declared = descriptor?.stream_group;
  if (typeof declared === "string" && declared.trim()) return declared.trim();
  // Older plug-ins remain usable without teaching the core domain-specific
  // group names: each ungrouped source type gets one private implicit group.
  return `source-type:${String(sourceType || "unknown")}`;
}

function ensureSourceRecordGroup(descriptor, sourceType = descriptor?.source_type) {
  const groupId = sourceDescriptorStreamGroup(descriptor, sourceType);
  if (!state.sourceRecordGroups.has(groupId)) {
    const explicit = typeof descriptor?.stream_group === "string"
      && descriptor.stream_group.trim();
    state.sourceRecordGroups.set(groupId, {
      group_id: groupId,
      label: explicit ? titleCase(groupId) : String(descriptor?.label || titleCase(sourceType || "unknown")),
      description: explicit
        ? "Compatibility group declared by the plug-in source type."
        : `Retained ${String(descriptor?.label || sourceType || "unknown")} records.`,
      default_included: false,
      implicit: true,
    });
  }
  return groupId;
}

function sourceRecordStreamGroup(record) {
  const sourceType = String(record?.source_type || "unknown");
  return ensureSourceRecordGroup(sourceTypeDescriptor(sourceType), sourceType);
}

function includeSourceRecordGroup(record) {
  state.includedSourceRecordGroups.add(sourceRecordStreamGroup(record));
}

function includeAllSourceRecordGroups() {
  state.sourceRecordGroups.forEach((_descriptor, groupId) => {
    state.includedSourceRecordGroups.add(groupId);
  });
}

function initializeSourceRecordGroups() {
  const descriptors = state.dataset.source_record_group_descriptors
    || state.dataset.schema?.source_record_groups
    || [];
  state.sourceRecordGroups = new Map(
    descriptors
      .filter((descriptor) => descriptor?.group_id)
      .map((descriptor) => [String(descriptor.group_id), descriptor]),
  );
  state.sourceRecordTypes.forEach((descriptor) => ensureSourceRecordGroup(descriptor));
  state.sourceRecords.forEach((record) => {
    const sourceType = String(record?.source_type || "unknown");
    ensureSourceRecordGroup(sourceTypeDescriptor(sourceType), sourceType);
  });
  state.includedSourceRecordGroups = new Set(
    [...state.sourceRecordGroups.values()]
      .filter((descriptor) => descriptor.default_included === true)
      .map((descriptor) => String(descriptor.group_id)),
  );
}

function selectedEventLogSourceTypes() {
  return [...state.sourceRecordTypes.values()]
    .filter((descriptor) => {
      const group = ensureSourceRecordGroup(descriptor);
      return state.includedSourceRecordGroups.has(group);
    })
    .map((descriptor) => String(descriptor.source_type))
    .filter(Boolean);
}

function normalizedLogEntryId(eventUid) {
  return "event:" + String(eventUid);
}

function sourceLogEntryId(recordUid) {
  return "source:" + String(recordUid);
}

function eventStatus(event, resourceId = null) {
  if (event?.resulting_status !== undefined && event.resulting_status !== null) {
    return formatValue(event.resulting_status);
  }
  const effects = eventEffects(event);
  const effect = resourceId
    ? resourceEffectFor(event, resourceId)
    : effects.length === 1 ? effects[0] : null;
  const condition = resourceEffectCondition(effect, resourceId || effectResourceId(effect));
  return condition === null || condition === undefined ? "unknown" : formatValue(condition);
}

function resourceIdOf(record) {
  if (!record) return null;
  if (typeof record === "string") return canonicalResourceId(record);
  const direct = record.resource_id ?? record.resource_uid ?? record.resource ?? record.id;
  return canonicalResourceId(direct);
}

function resourceKind(record, _resourceId = "") {
  if (record?.kind || record?.type || record?.resource_type) {
    const kind = record.kind || record.type || record.resource_type;
    return typeof kind === "string" && kind ? kind : "UNKNOWN";
  }
  return "UNKNOWN";
}

function resourceLayer(record, _resourceId = "") {
  return typeof record?.layer === "string" && record.layer ? record.layer : "unknown";
}

function resourceLabel(record, resourceId = "") {
  const label = record?.label ?? record?.display_name ?? record?.name;
  if (label !== null && label !== undefined && label !== "") return formatValue(label);
  return canonicalResourceId(resourceId) || "unknown resource";
}

function presentationTags(record) {
  const kind = resourceKind(record, resourceIdOf(record) || "");
  const descriptorTags = resourceKindDescriptor(kind)?.presentation_tags ?? [];
  const recordTags = record?.presentation_tags ?? record?.presentation?.tags ?? record?.resource?.presentation_tags ?? [];
  const normalize = (tags) => Array.isArray(tags)
    ? tags.map(String)
    : String(tags || "").split(/[ ,]+/).filter(Boolean);
  return new Set([...normalize(descriptorTags), ...normalize(recordTags)]);
}

function isCompact(record) {
  const tags = presentationTags(record);
  return tags.has("compact") || tags.has("connector");
}

function registerResource(record, preferredId = null) {
  const id = canonicalResourceId(preferredId) || resourceIdOf(record);
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
  return id;
}

function canonicalResourceForSubject(subject, event) {
  const direct = subject?.resource_id ?? subject?.resource_uid ?? subject?.canonical_id ?? subject?.resource;
  return canonicalResourceId(direct)
    || canonicalResourceId(event?.resource_id)
    || canonicalResourceId(event?.resource_uid)
    || canonicalResourceId(event?.resource)
    || null;
}

function eventResourceRefs(event) {
  const direct = event?.affected_resources || event?.resource_ids;
  if (Array.isArray(direct) && direct.length) return direct.map(resourceIdOf).filter(Boolean);
  const subjects = Array.isArray(event?.subjects) && event.subjects.length ? event.subjects : [eventSubject(event)];
  return [...new Set(subjects.map((subject) => canonicalResourceForSubject(subject, event)).filter(Boolean))];
}

function effectResourceId(effect) {
  const identifier = effect?.resource_id ?? effect?.resource_uid ?? effect?.resource;
  return canonicalResourceId(identifier);
}

function resourceEffectFor(event, resourceId) {
  if (!resourceId) return null;
  return eventEffects(event).find((effect) => effectResourceId(effect) === String(resourceId)) || null;
}

function resourceEffectState(effect) {
  if (!effect) return null;
  return effect.after ?? effect.resulting_state ?? effect.state ?? effect.properties ?? null;
}

function resourceEffectCondition(effect, resourceId = effectResourceId(effect)) {
  if (!effect) return null;
  // The plug-in owns condition semantics.  Prefer its normalized mutation
  // condition (including an explicitly supplied null/unknown) before reading
  // the descriptor-declared field from the mutation's after-state.
  if (Object.prototype.hasOwnProperty.call(effect, "condition")) return effect.condition;
  const stateValue = resourceEffectState(effect);
  if (stateValue === null || stateValue === undefined) return null;
  if (typeof stateValue !== "object") return null;
  const record = resourceId ? state.resourceById.get(resourceId) : null;
  const kind = effect?.kind || record?.kind || "UNKNOWN";
  const field = resourceKindDescriptor(kind)?.condition_field;
  return field ? dashboardFieldValue(stateValue, field) ?? null : null;
}

function normalizeMark(raw, lane) {
  const event = raw?.event || state.eventByUid.get(raw?.event_uid || raw?.event_id) || raw || {};
  const uid = String(raw?.event_uid || raw?.event_id || event.event_uid || event.event_id || `${lane.laneId}:${eventTime(event)}`);
  if (event && Object.keys(event).length) {
    state.eventByUid.set(uid, { ...event, event_uid: uid });
    state.densityLocalCache = null;
  }
  const effect = raw?.resource_effect || raw?.effect || resourceEffectFor(event, lane.resourceId);
  return {
    kind: "event",
    eventUid: uid,
    timeNs: toNs(raw?.time_ns ?? raw?.timestamp_ns ?? event.timestamp_ns ?? event.time_ns, state.viewStartNs),
    eventType: raw?.event_type || event.event_type || "event",
    action: raw?.operation || raw?.action || event.action || event.operation || effect?.effect_type || "unknown",
    outcome: normalizedEventOutcome({
      outcome: raw?.outcome ?? event.outcome,
      failure: raw?.failure ?? event.failure,
      failed: event.failed,
    }),
    label: raw?.label || event.label || titleCase(raw?.event_type || event.event_type || "event"),
    failure: raw?.failure === true || eventFailed(event),
    stateChanged: effect?.state_changed ?? raw?.state_changed ?? eventChangesState(event),
    effectType: effect?.effect_type || raw?.effect_type || event.effect_type || "unknown",
    durationToNextChangeNs: raw?.duration_to_next_change_ns === null || raw?.duration_to_next_change_ns === undefined
      ? null
      : toNs(raw.duration_to_next_change_ns),
    event,
    effect,
    lane,
  };
}

function normalizeInterval(raw, kind, lane) {
  const startRaw = raw?.start_ns ?? raw?.valid_from_ns;
  const endRaw = raw?.end_ns ?? raw?.valid_to_ns;
  const startNs = startRaw === null || startRaw === undefined ? state.viewStartNs : toNs(startRaw, state.viewStartNs);
  const endNs = endRaw === null || endRaw === undefined ? state.viewEndNs : toNs(endRaw, state.viewEndNs);
  const properties = raw?.properties || raw?.state || {};
  const conditionField = resourceKindDescriptor(lane?.kind)?.condition_field;
  const declaredCondition = conditionField ? dashboardFieldValue(properties, conditionField) : undefined;
  const status = raw?.status ?? declaredCondition ?? (kind === "lifecycle" ? "exists" : "unknown");
  return {
    kind,
    startNs,
    endNs,
    openStart: Boolean(raw?.open_start ?? startRaw === null),
    openEnd: Boolean(raw?.open_end ?? endRaw === null),
    status: String(status),
    statusClass: typeof raw?.status_class === "string" && raw.status_class ? raw.status_class : "unknown",
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
  // A failed operation is not proof that no mutation occurred.  The plug-in's
  // explicit per-resource state_changed/effect declaration is authoritative.
  const changed = lane.marks.filter((mark) => mark.stateChanged === true);
  lane.marks.forEach((mark) => {
    if (mark.durationToNextChangeNs !== null) return;
    const next = changed.find((candidate) => candidate.timeNs > mark.timeNs);
    mark.durationToNextChangeNs = next ? next.timeNs - mark.timeNs : state.viewEndNs - mark.timeNs;
  });

  if (!lane.lifecycle.length) {
    let open = null;
    for (const mark of lane.marks) {
      if (mark.stateChanged !== true) continue;
      const effectType = String(mark.effectType || "unknown").toLowerCase();
      if (["created", "create"].includes(effectType) && open === null) open = mark;
      if (["deleted", "delete"].includes(effectType) && open !== null) {
        lane.lifecycle.push(normalizeInterval({ start_ns: open.timeNs, end_ns: mark.timeNs, start_event_uid: open.eventUid, end_event_uid: mark.eventUid }, "lifecycle", lane));
        open = null;
      }
    }
    if (open) lane.lifecycle.push(normalizeInterval({ start_ns: open.timeNs, end_ns: null, start_event_uid: open.eventUid, open_end: true }, "lifecycle", lane));
    if (!lane.lifecycle.length) lane.lifecycle.push(normalizeInterval({ start_ns: null, end_ns: null, open_start: true, open_end: true }, "lifecycle", lane));
  }

  if (!lane.statuses.length && changed.length) {
    changed.forEach((mark, index) => {
      if (["deleted", "delete"].includes(String(mark.effectType || "unknown").toLowerCase())) return;
      const next = changed.slice(index + 1).find((candidate) => candidate.timeNs > mark.timeNs);
      lane.statuses.push(normalizeInterval({
        start_ns: mark.timeNs,
        end_ns: next?.timeNs ?? null,
        status: resourceEffectCondition(mark.effect, lane.resourceId) ?? eventStatus(mark.event, lane.resourceId),
        status_class: resourceEffectStatusClass(mark.effect, mark.event),
        properties: resourceEffectState(mark.effect) || {},
        start_event_uid: mark.eventUid,
      }, "status", lane));
    });
  }
  if (!lane.statuses.length) {
    const snapshot = lane.resource?.state || {};
    const conditionField = resourceKindDescriptor(lane.kind)?.condition_field;
    const condition = conditionField ? dashboardFieldValue(snapshot, conditionField) : undefined;
    lane.statuses.push(normalizeInterval({
      start_ns: null,
      end_ns: null,
      status: condition ?? "unknown",
      status_class: lane.resource?.status_class || snapshot.status_class || "unknown",
      properties: snapshot,
    }, "status", lane));
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
    serverBacked: raw?.scrollable === true
      || typeof raw?.detail_truncated === "boolean"
      || raw?.detail_count !== undefined,
    detailTruncated: Boolean(raw?.detail_truncated),
    detailItems: [],
    detailHydrated: false,
    detailLoading: false,
    detailError: null,
    detailNextOffset: null,
    detailRetryOffset: 0,
    detailTotal: Number(raw?.count ?? raw?.counts?.total ?? preview.length),
    detailRequestId: 0,
  };
}

function normalizeSourceMark(raw, lane) {
  const uid = String(raw?.source_record_uid || raw?.record?.source_record_uid || "");
  const record = raw?.record || state.sourceRecordByUid.get(uid) || raw || {};
  const matchedEventUids = sourceRecordMatchedEventUids({
    ...record,
    matched_event_uid: raw?.matched_event_uid ?? record.matched_event_uid,
    matched_event_uids: raw?.matched_event_uids ?? record.matched_event_uids,
  });
  if (uid && !state.sourceRecordByUid.has(uid)) state.sourceRecordByUid.set(uid, record);
  return {
    kind: "source-record",
    sourceRecordUid: uid,
    timeNs: sourceRecordTime(raw?.record ? raw.record : raw),
    sourceType: String(raw?.source_type || record.source_type || "unknown"),
    recordName: String(raw?.record_name || record.record_name || "record"),
    sourceName: String(raw?.source_name || record.source_name || "source"),
    message: String(raw?.message || record.message || ""),
    matchedEventUid: matchedEventUids[0] || null,
    matchedEventUids,
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
  state.timelineExpansion = payload?.relationship_history_expansion || null;
  const laneMap = new Map();
  const authoritativeServerLanes = Array.isArray(payload?.lanes);
  const rawLanes = payload?.lanes || state.dataset.timeline?.lanes || [];
  for (const raw of rawLanes) {
    const resource = raw.resource && typeof raw.resource === "object" ? raw.resource : null;
    const resourceId = canonicalResourceId(raw.resource_id) || resourceIdOf(resource) || canonicalResourceId(raw.lane_id);
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

function timelineExpansionNoticeHtml(trackWidth = state.trackWidth) {
  const expansion = state.timelineExpansion;
  if (!expansion?.truncated) return "";
  const droppedIds = new Set([
    ...(expansion.dropped_base_ids || []),
    ...(expansion.dropped_root_ids || []),
    ...(expansion.dropped_resource_ids || []),
  ].map(String));
  const laneLimit = Number(expansion.lane_limit || state.lanes.length);
  const omittedCopy = droppedIds.size
    ? `${droppedIds.size.toLocaleString()} related resources were omitted`
    : "additional related resources were omitted";
  return `<div class="timeline-expansion-notice" style="grid-template-columns:${timelineLaneWidth()}px ${trackWidth}px" role="status">
    <strong>Relationship expansion is bounded</strong>
    <span>${Math.min(state.lanes.length, laneLimit).toLocaleString()} lanes are loaded; ${omittedCopy}. Refine the focused resource or lane search to inspect them.</span>
  </div>`;
}

function rebuildHiddenEventProjectionIndex() {
  const index = new Map();
  for (const entryId of state.hiddenTimelineEntryIds) {
    if (!entryId.startsWith("event:")) continue;
    const projection = state.timelineEntryProjections.get(entryId);
    if (!projection) continue;
    projection.resourceIds.forEach((resourceId) => {
      if (!index.has(resourceId)) index.set(resourceId, []);
      index.get(resourceId).push(projection);
    });
  }
  state.hiddenEventProjectionsByResource = index;
}

function hiddenEventProjectionsForLane(lane) {
  return state.hiddenEventProjectionsByResource.get(lane.resourceId) || [];
}

function adjustedTimelineCluster(cluster, lane) {
  const hidden = new Map();
  hiddenEventProjectionsForLane(lane).forEach((projection) => {
    if (projection.timeNs >= cluster.startNs && projection.timeNs <= cluster.endNs) {
      hidden.set(projection.uid, projection);
    }
  });
  cluster.eventUids.forEach((uid) => {
    const entryId = normalizedLogEntryId(uid);
    if (state.hiddenTimelineEntryIds.has(entryId)) {
      hidden.set(uid, state.timelineEntryProjections.get(entryId));
    }
  });
  if (!hidden.size) return cluster;
  const items = cluster.items.filter((mark) => !hidden.has(mark.eventUid));
  const eventUids = cluster.eventUids.filter((uid) => !hidden.has(uid));
  const hiddenFailures = [...hidden.values()].filter(
    (projection) => projection?.entry && eventFailed(projection.entry),
  ).length;
  return {
    ...cluster,
    count: Math.max(0, cluster.count - hidden.size),
    detailTotal: Math.max(0, Number(cluster.detailTotal ?? cluster.count) - hidden.size),
    failureCount: Math.max(0, cluster.failureCount - hiddenFailures),
    items,
    eventUids,
    hiddenCount: hidden.size,
  };
}

function buildClientGlyphs(lane) {
  const visibleMarks = lane.marks.filter(
    (mark) => timelinePointVisible(mark.timeNs)
      && !state.hiddenTimelineEntryIds.has(normalizedLogEntryId(mark.eventUid)),
  );
  if (lane.clusters.length) {
    const [windowStartNs, windowEndNs] = timelineWindowBounds();
    // Server clusters belong to the window that produced them. During the
    // debounced refresh after zoom/pan, exact clusters are valid only when
    // wholly contained by the current window. Preserve any visible preview
    // events from partially overlapping clusters and draw a clipped, dashed
    // placeholder so a slow or failed replacement query never leaves a blank
    // region or renders the old midpoint off-screen.
    const containedClusters = lane.clusters.filter(
      (cluster) => cluster.startNs >= windowStartNs && cluster.endNs <= windowEndNs,
    );
    const staleClusters = lane.clusters.filter(
      (cluster) => cluster.endNs >= windowStartNs
        && cluster.startNs <= windowEndNs
        && (cluster.startNs < windowStartNs || cluster.endNs > windowEndNs),
    );
    const stalePreviewMarks = staleClusters.flatMap((cluster) => cluster.items)
      .filter((mark) => timelinePointVisible(mark.timeNs)
        && !state.hiddenTimelineEntryIds.has(normalizedLogEntryId(mark.eventUid)));
    const marksByUid = new Map();
    [...visibleMarks, ...stalePreviewMarks].forEach((mark) => marksByUid.set(mark.eventUid, mark));
    const collapsed = new Set(containedClusters.flatMap((cluster) => cluster.eventUids));
    const stalePlaceholders = staleClusters.map((cluster) => adjustedTimelineCluster({
      ...cluster,
      clusterId: `${cluster.clusterId}:stale:${windowStartNs}:${windowEndNs}`,
      startNs: cluster.startNs < windowStartNs ? windowStartNs : cluster.startNs,
      endNs: cluster.endNs > windowEndNs ? windowEndNs : cluster.endNs,
      eventUids: cluster.eventUids.filter((uid) => marksByUid.has(uid)),
      items: cluster.items.filter((mark) => timelinePointVisible(mark.timeNs)),
      staleWindow: true,
      serverBacked: false,
      detailTruncated: false,
    }, lane)).filter((cluster) => cluster.count > 0);
    return [
      ...containedClusters.map((cluster) => adjustedTimelineCluster(cluster, lane))
        .filter((cluster) => cluster.count > 0),
      ...stalePlaceholders,
      ...[...marksByUid.values()].filter((mark) => !collapsed.has(mark.eventUid)),
    ].sort((a, b) => {
      const left = a.timeNs ?? a.startNs;
      const right = b.timeNs ?? b.startNs;
      return left < right ? -1 : left > right ? 1 : 0;
    });
  }
  // Cluster the exact logical window by a stable screen-space distance.
  const threshold = Math.max(0.000001, 13 / Math.max(1, state.trackWidth) * 100);
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
  for (const mark of visibleMarks) {
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
  // Status/lifecycle/relationship validity is half-open: [start, end).
  // A record ending exactly at the selected start must not be highlighted
  // alongside the record that begins at that transition.
  return toNs(start) < bounds[1] && toNs(end) > bounds[0];
}

function inclusiveIntervalIntersectsRange(start, end) {
  const bounds = rangeBounds();
  if (!bounds) return false;
  return toNs(start) <= bounds[1] && toNs(end) >= bounds[0];
}

function resourceHiddenFromTimeline(resourceId) {
  resourceId = canonicalResourceId(resourceId);
  return Boolean(resourceId && state.hiddenTimelineResourceIds.has(resourceId));
}

function laneSelectedByMode(resourceId) {
  resourceId = canonicalResourceId(resourceId);
  if (!resourceId || resourceHiddenFromTimeline(resourceId)) return false;
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
  const presence = relationshipPresencePresentation(raw || {});
  if (presence.present === false) return null;
  const source = canonicalResourceId(raw?.source) || canonicalResourceId(raw?.source_resource_id);
  const target = canonicalResourceId(raw?.target) || canonicalResourceId(raw?.target_resource_id);
  if (!source || !target) return null;
  const startRaw = raw?.valid_from_ns ?? raw?.start_ns;
  const endRaw = raw?.valid_to_ns ?? raw?.end_ns;
  const relationType = typeof (raw?.relation_type ?? raw?.type) === "string"
    ? (raw.relation_type ?? raw.type)
    : null;
  const presentation = relationshipPresentation(relationType);
  return {
    id: typeof (raw?.relationship_id ?? raw?.id) === "string"
      ? (raw.relationship_id ?? raw.id)
      : `relationship:${source}:${relationType || "unknown"}:${target}:${startRaw ?? "open"}`,
    source,
    target,
    type: relationType || "unknown",
    relationshipLabel: presentation.displayLabel,
    relationshipKnown: presentation.known,
    directed: presentation.directed,
    structural: presentation.structural,
    ...presence,
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
  // endpoint exists, so workspace intervals are only a transport fallback.
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
      if (
        ancestry.has(otherId)
        || resourceHiddenFromTimeline(otherId)
        || !otherLane
        || !state.activeLayers.has(otherLane.layer)
      ) return;
      // One tree row represents one relationship identity across time.
      // Its changing validity intervals are rendered as multiple ribbons;
      // interval IDs must not duplicate the same child lane.
      const key = `${edge.source}|${edge.type}|${edge.target}`;
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
    const availableChildren = relationshipGroupsForResource(lane.resourceId, ancestry);
    const truncatedChildren = depth >= MAX_TIMELINE_TREE_DEPTH && availableChildren.length > 0;
    const children = truncatedChildren ? [] : availableChildren;
    const instance = {
      lane,
      key,
      depth,
      parentResourceId,
      relationship,
      hasChildren: children.length > 0,
      truncatedChildren,
      omittedChildCount: truncatedChildren ? availableChildren.length : 0,
    };
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
      if (end <= start || !timelineIntervalVisible(start, end)) return "";
      const active = state.cursorNs >= start && (state.cursorNs < end || (edge.openEnd && state.cursorNs === end));
      const key = `relationship:${edge.id}:${instance?.key || lane.resourceId}`;
      state.hoverModels.set(key, {
        type: "relationship",
        edge,
        lane,
        otherId: parentId,
        relativeToId: parentId,
      });
      const direction = edge.source === parentId ? "outgoing" : "incoming";
      return `<button type="button" class="relationship-ribbon ${direction} quality-${safeClass(edge.quality)}${active ? " active" : ""}${edge.temporalNote?.includes("without") ? " uncertain" : ""}${intersectsRange(start, end) ? " in-range" : ""}" data-hover-key="${escapeHtml(key)}" data-range-start-ns="${start}" data-range-end-ns="${end}" style="${barStyle({ startNs: start, endNs: end })};--ribbon-row:${index % 3}" aria-label="${escapeHtml(`${relationshipDisplayLabel(edge.type)} / ${parentId} / ${edge.quality}`)}"><span>${escapeHtml(relationshipDisplayLabel(edge.type))}</span></button>`;
    }).join("");
}

function combinedAssociationLane(trackWidth = state.trackWidth) {
  if (
    state.correlationTimelineView !== "combined"
    || !state.selectedResourceId
    || resourceHiddenFromTimeline(state.selectedResourceId)
    || !state.correlationTimelineExpanded
  ) return "";
  const spans = temporalRelationshipSpans()
    .filter((edge) => edge.source === state.selectedResourceId || edge.target === state.selectedResourceId)
    .map((edge) => ({
      ...edge,
      startNs: edge.startNs < state.viewStartNs ? state.viewStartNs : edge.startNs,
      endNs: edge.endNs > state.viewEndNs ? state.viewEndNs : edge.endNs,
      otherId: edge.source === state.selectedResourceId ? edge.target : edge.source,
      direction: edge.source === state.selectedResourceId ? "outgoing" : "incoming",
    }))
    .filter((edge) => (
      edge.endNs > edge.startNs
      && timelineIntervalVisible(edge.startNs, edge.endNs)
      && !resourceHiddenFromTimeline(edge.otherId)
    ))
    .sort((a, b) => a.startNs < b.startNs ? -1 : a.startNs > b.startNs ? 1 : a.otherId.localeCompare(b.otherId));
  const bounds = rangeBounds();
  const rangeBand = timelineRangeBandHtml(bounds);
  const segments = spans.map((edge, index) => {
    const key = `relationship:${edge.id}:combined`;
    const other = state.resourceById.get(edge.otherId) || {};
    state.hoverModels.set(key, {
      type: "relationship",
      edge,
      lane: null,
      otherId: edge.otherId,
      relativeToId: state.selectedResourceId,
    });
    const startBoundary = edge.openStart || edge.startNs === state.viewStartNs || !timelinePointVisible(edge.startNs)
      ? ""
      : `<span class="association-boundary add" style="left:${timelinePercent(edge.startNs)}%"></span>`;
    const endBoundary = edge.openEnd || edge.endNs === state.viewEndNs || !timelinePointVisible(edge.endNs)
      ? ""
      : `<span class="association-boundary remove" style="left:${timelinePercent(edge.endNs)}%"></span>`;
    return `<button class="association-segment ${edge.direction} quality-${safeClass(edge.quality)}${intersectsRange(edge.startNs, edge.endNs) ? " in-range" : ""}" type="button" data-hover-key="${escapeHtml(key)}" data-range-start-ns="${edge.startNs}" data-range-end-ns="${edge.endNs}" style="${barStyle(edge)};--association-row:${index % 3};--association-color:${layerColor(resourceLayer(other, edge.otherId))}"><span>${escapeHtml(resourceLabel(other, edge.otherId))}</span><small>${escapeHtml(relationshipDisplayLabel(edge.type))}</small></button>${startBoundary}${endBoundary}`;
  }).join("");
  return `<div class="timeline-row correlation-combined-row" style="grid-template-columns:${timelineLaneWidth()}px ${trackWidth}px;--layer-color:var(--violet)">
    <div class="lane-label association-lane-label"><span class="lane-dot" aria-hidden="true"></span><span class="lane-copy"><strong>Correlations</strong><span class="lane-meta"><span class="lane-type">${spans.length} intervals</span></span></span></div>
    <div class="lane-track association-track" data-resource-id="${escapeHtml(state.selectedResourceId)}">${rangeBand}${segments}</div>
  </div>`;
}

function barStyle(interval, { inclusiveEndpoints = false } = {}) {
  const left = timelinePercent(interval.startNs);
  const right = timelinePercent(interval.endNs);
  if (inclusiveEndpoints ? (right < 0 || left > 100) : (right <= 0 || left >= 100)) {
    return "display:none";
  }
  const clippedLeft = Math.max(0, left);
  const clippedRight = Math.min(100, right);
  const width = Math.max(0.15, clippedRight - clippedLeft);
  const renderedLeft = inclusiveEndpoints ? Math.min(clippedLeft, 100 - width) : clippedLeft;
  return `left:${renderedLeft}%;width:${width}%`;
}

function timelineIntervalPercentGeometry(start, end) {
  const [windowStartNs, windowEndNs] = timelineWindowBounds();
  const rawStart = toNs(start);
  const rawEnd = toNs(end);
  const intervalStart = rawStart <= rawEnd ? rawStart : rawEnd;
  const intervalEnd = rawStart <= rawEnd ? rawEnd : rawStart;
  if (intervalEnd < windowStartNs || intervalStart > windowEndNs) return null;
  const clippedStart = intervalStart < windowStartNs ? windowStartNs : intervalStart;
  const clippedEnd = intervalEnd > windowEndNs ? windowEndNs : intervalEnd;
  const left = Math.max(0, Math.min(100, timelinePercent(clippedStart)));
  const right = Math.max(left, Math.min(100, timelinePercent(clippedEnd)));
  return { left, width: right - left };
}

function timelineRangeBandHtml(bounds) {
  if (!bounds) return '<div class="range-band" hidden></div>';
  const geometry = timelineIntervalPercentGeometry(bounds[0], bounds[1]);
  return geometry
    ? `<div class="range-band" style="left:${geometry.left}%;width:${geometry.width}%"></div>`
    : '<div class="range-band" hidden></div>';
}

function hoverKey(kind, lane, id) {
  return `${kind}:${lane.laneId}:${id}`;
}

function renderRuler() {
  const ruler = byId("timeline-ruler");
  ruler.style.width = `${state.trackWidth}px`;
  ruler.style.minWidth = `${state.trackWidth}px`;
  const precision = visibleTimelineOffsetPrecision();
  const ticks = Array.from({ length: 7 }, (_, index) => {
    const ratio = index / 6;
    const timestamp = timelineNsAtLocalRatio(ratio);
    return `<div class="ruler-tick" style="left:${ratio * 100}%"><span>${escapeHtml(formatOffset(timestamp, precision))}</span></div>`;
  }).join("");
  ruler.innerHTML = `${ticks}<span class="timeline-hover-time" hidden aria-hidden="true"></span>`;
}

function densityRenderWindow(binCount, trackWidth) {
  const [windowStartNs, windowEndNs] = timelineWindowBounds();
  // Event timestamps and histogram bins both use the inclusive capture domain
  // [viewStartNs, viewEndNs]. Map the containing bin for each visible endpoint,
  // then make the end index exclusive. Mixing this with a half-open duration
  // drops the bin that owns an exact visible endpoint in tiny/deep windows.
  const visibleStart = timelineDensityBinIndex({
    timeNs: windowStartNs,
    startNs: state.viewStartNs,
    endNs: state.viewEndNs,
    binCount,
  });
  const visibleEnd = Math.min(binCount, timelineDensityBinIndex({
    timeNs: windowEndNs,
    startNs: state.viewStartNs,
    endNs: state.viewEndNs,
    binCount,
  }) + 1);
  const visibleCount = Math.max(1, visibleEnd - visibleStart);
  const overscan = Math.max(12, Math.ceil(visibleCount * 0.75));
  return {
    start: Math.max(0, visibleStart - overscan),
    end: Math.min(binCount, visibleEnd + overscan),
    visibleStart,
    visibleEnd,
  };
}

function displayedHistoryEventCount() {
  const workspace = workspaceMetadata();
  return Number(
    workspace.matched_event_count
    ?? workspace.event_count
    ?? state.eventByUid.size,
  );
}

function densityBinHeight(count) {
  // Absolute logarithmic height keeps the same count visually stable while
  // horizontally panning between independently loaded density pages.
  return Math.max(4, Math.min(46, 4 + Math.log2(Math.max(0, count) + 1) * 5));
}

function localDensityHistogram(binCount) {
  const key = `${state.viewStartNs}:${state.viewEndNs}:${binCount}:${state.eventByUid.size}`;
  if (state.densityLocalCache?.key === key) return state.densityLocalCache.bins;
  const bins = new Map();
  for (const event of state.eventByUid.values()) {
    const time = eventTime(event);
    if (time < state.viewStartNs || time > state.viewEndNs) continue;
    const index = timelineDensityBinIndex({
      timeNs: time,
      startNs: state.viewStartNs,
      endNs: state.viewEndNs,
      binCount,
    });
    if (!bins.has(index)) bins.set(index, {
      index,
      count: 0,
      failures: 0,
      topTypes: new Map(),
    });
    const bin = bins.get(index);
    bin.count += 1;
    if (eventFailed(event)) bin.failures += 1;
    const type = event.event_type || event.label || "event";
    bin.topTypes.set(type, (bin.topTypes.get(type) || 0) + 1);
  }
  state.densityLocalCache = { key, bins };
  return bins;
}

function densityServerQuery(binCount, renderWindow) {
  return {
    key: `${state.viewStartNs}:${state.viewEndNs}:${binCount}:${renderWindow.start}:${renderWindow.end}`,
    binCount,
    globalStart: renderWindow.start,
    globalEnd: renderWindow.end,
    startNs: state.viewStartNs,
    endNs: state.viewEndNs,
  };
}

function cachedDensityPage(query) {
  for (const [key, page] of state.densityPageCache) {
    if (page.binCount !== query.binCount
      || page.globalStart > query.globalStart
      || page.globalEnd < query.globalEnd) continue;
    state.densityPageCache.delete(key);
    state.densityPageCache.set(key, page);
    return page;
  }
  return null;
}

function normalizeDensityPage(payload, query) {
  const bins = (payload?.bins || []).map((raw) => {
    const startNs = toNs(raw.start_ns, query.startNs);
    const endNs = toNs(raw.end_ns, query.endNs);
    // Paged responses retain the immutable global bin index. Adjacent and
    // overlapping pages therefore use identical boundaries even when the
    // inclusive capture span is not evenly divisible by the resolution.
    const index = Math.max(0, Math.min(
      query.binCount - 1,
      Number(raw.index || 0),
    ));
    return {
      index,
      startNs,
      endNs,
      count: Number(raw.count || 0),
      failures: Number(raw.failure_count ?? raw.failures ?? 0),
      topTypes: new Map((raw.top_types || []).map((item) => [
        String(item.event_type || item.type || "event"),
        Number(item.count || 0),
      ])),
    };
  }).filter((bin) => bin.count > 0);
  return {
    key: query.key,
    binCount: query.binCount,
    globalStart: query.globalStart,
    globalEnd: query.globalEnd,
    totalCount: Number(payload?.total_count ?? displayedHistoryEventCount()),
    bins,
  };
}

function rememberDensityPage(page) {
  state.densityPageCache.delete(page.key);
  state.densityPageCache.set(page.key, page);
  while (state.densityPageCache.size > DENSITY_PAGE_CACHE_LIMIT) {
    state.densityPageCache.delete(state.densityPageCache.keys().next().value);
  }
}

function scheduleDensityPageRequest(query) {
  if (cachedDensityPage(query) || state.densityPendingKey === query.key) return;
  window.clearTimeout(state.densityRequestTimer);
  const requestId = ++state.densityRequestId;
  state.densityPendingKey = query.key;
  state.densityErrorKey = null;
  state.densityRequestTimer = window.setTimeout(async () => {
    try {
      const payload = await analysisRuntimeApi(revisionPath("events/density/query"), {
        method: "POST",
        body: JSON.stringify({
          start_ns: query.startNs.toString(),
          end_ns: query.endNs.toString(),
          bin_count: query.binCount,
          bin_start_index: query.globalStart,
          bin_end_index: query.globalEnd,
        }),
      });
      if (requestId !== state.densityRequestId) return;
      rememberDensityPage(normalizeDensityPage(payload, query));
      state.densityPendingKey = null;
      refreshDensityLaneForScroll();
    } catch (_error) {
      if (requestId !== state.densityRequestId) return;
      state.densityPendingKey = null;
      state.densityErrorKey = query.key;
      refreshDensityLaneForScroll();
    }
  }, 40);
}

function eventDensityLane(trackWidth = state.trackWidth) {
  // Logical histogram resolution follows zoom without a ceiling. Only the
  // visible logical bins (plus overscan) become DOM nodes, so an arbitrarily
  // large zoom cannot create one button per event and freeze the browser.
  for (const key of state.hoverModels.keys()) {
    if (String(key).startsWith("density:")) state.hoverModels.delete(key);
  }
  const captureSlots = state.viewEndNs - state.viewStartNs + 1n;
  const maximumUsefulBins = Number(
    captureSlots > BigInt(Number.MAX_SAFE_INTEGER)
      ? BigInt(Number.MAX_SAFE_INTEGER)
      : captureSlots,
  );
  const requestedBins = 180 * state.zoom;
  const binCount = Math.max(1, Math.min(
    maximumUsefulBins,
    Number.isFinite(requestedBins) ? Math.round(requestedBins) : maximumUsefulBins,
  ));
  const renderWindow = densityRenderWindow(binCount, trackWidth);
  const bins = new Map();
  let loading = false;
  let failed = false;
  let sourceBins;
  if (usesServerWindowedHistory()) {
    const query = densityServerQuery(binCount, renderWindow);
    const page = cachedDensityPage(query);
    sourceBins = page?.bins || [];
    loading = !page && state.densityErrorKey !== query.key;
    failed = !page && state.densityErrorKey === query.key;
    if (!page && !failed) scheduleDensityPageRequest(query);
  } else {
    sourceBins = localDensityHistogram(binCount).values();
  }
  for (const bin of sourceBins) {
    const index = bin.index;
    if (index < renderWindow.start || index >= renderWindow.end) continue;
    bins.set(index, bin);
  }
  const populatedBins = [...bins.values()];
  const bars = populatedBins.map((bin) => {
    const fallbackBounds = timelineDensityBinBounds({
      index: bin.index,
      startNs: state.viewStartNs,
      endNs: state.viewEndNs,
      binCount,
    });
    const startNs = bin.startNs ?? fallbackBounds.startNs;
    const endNs = bin.endNs ?? fallbackBounds.endNs;
    // Density intervals describe inclusive point populations. Overscan may
    // include the bin immediately before the exact logical viewport; reject
    // it using its real inclusive end before projecting end+1 for width.
    if (!timelinePointIntervalVisible(startNs, endNs)) return "";
    const endExclusiveNs = endNs + 1n;
    const key = `density:${bin.index}:${binCount}`;
    const topTypes = bin.topTypes instanceof Map ? bin.topTypes : new Map();
    state.hoverModels.set(key, { type: "density", bin: { ...bin, startNs, endNs, topTypes } });
    const precision = offsetPrecisionForSpan(endExclusiveNs - startNs);
    return `<button class="density-bin${bin.failures ? " has-failures" : ""}${inclusiveIntervalIntersectsRange(startNs, endNs) ? " in-range" : ""}" type="button" data-hover-key="${escapeHtml(key)}" data-range-start-ns="${startNs}" data-range-end-ns="${endNs}" data-range-semantics="inclusive" style="${barStyle({ startNs, endNs: endExclusiveNs }, { inclusiveEndpoints: true })};--density-height:${densityBinHeight(bin.count)}px;--failure-height:${bin.count ? (bin.failures / bin.count) * 100 : 0}%" aria-label="${bin.count} events from ${escapeHtml(formatOffset(startNs, precision))} to ${escapeHtml(formatOffset(endNs, precision))}"></button>`;
  }).join("");
  const transportState = loading ? " · loading visible bins"
    : failed ? " · density unavailable"
      : usesServerWindowedHistory() ? " · server-windowed" : "";
  return `<div class="timeline-row density-row" data-density-bin-count="${binCount}" data-density-window-start="${renderWindow.start}" data-density-window-end="${renderWindow.end}" style="grid-template-columns:${timelineLaneWidth()}px ${trackWidth}px;--layer-color:var(--cyan)">
    <div class="lane-label density-lane-label"><span class="density-icon" aria-hidden="true"></span><span class="lane-copy"><strong>Event density</strong><span class="lane-meta"><span class="lane-type">${displayedHistoryEventCount().toLocaleString()} events · ${binCount.toLocaleString()} logical bins${transportState}</span></span></span></div>
    <div class="lane-track density-track">${bars}</div>
  </div>`;
}

function refreshDensityLaneForScroll() {
  const current = byId("timeline-content")?.querySelector(".density-row");
  if (!current) return;
  const focusDescriptor = timelineFocusDescriptor();
  const template = document.createElement("template");
  template.innerHTML = eventDensityLane(state.trackWidth).trim();
  const replacement = template.content.firstElementChild;
  if (!replacement) return;
  current.replaceWith(replacement);
  replacement.querySelectorAll("[data-hover-key]").forEach(bindHoverTarget);
  restoreTimelineFocusDescriptor(focusDescriptor);
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
  for (const mark of lane.marks.filter(
    (item) => timelinePointVisible(item.timeNs)
      && !state.hiddenTimelineEntryIds.has(sourceLogEntryId(item.sourceRecordUid)),
  )) {
    const prior = group.at(-1);
    const pixelGap = prior
      ? Math.abs(timelinePercent(mark.timeNs) - timelinePercent(prior.timeNs)) / 100 * state.trackWidth
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

function pointClusterRangeState(items, bounds = rangeBounds()) {
  const points = (items || []).filter((item) => item?.timeNs !== null && item?.timeNs !== undefined);
  const count = bounds
    ? points.filter((item) => item.timeNs >= bounds[0] && item.timeNs <= bounds[1]).length
    : 0;
  return {
    count,
    total: points.length,
    className: count && count === points.length ? " in-range" : count ? " partial-range" : "",
  };
}

function sourceRecordLanesHtml(trackWidth = state.trackWidth) {
  const bounds = rangeBounds();
  const rangeBand = timelineRangeBandHtml(bounds);
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
        const rangeState = pointClusterRangeState(glyph.items, bounds);
        const rangeDescription = rangeState.count
          ? `; ${rangeState.count} of ${rangeState.total} records are in the selected range`
          : "";
        return `<button class="source-record-mark cluster${selected ? " selected" : ""}${rangeState.className}" data-hover-key="${escapeHtml(key)}" data-source-cluster-id="${escapeHtml(glyph.clusterId)}" data-last-source-record-uid="${escapeHtml(glyph.recordUids.at(-1) || "")}" data-range-start-ns="${glyph.startNs}" data-range-end-ns="${glyph.endNs}" style="left:${timelinePercent(time)}%;--source-color:${escapeHtml(color)}" type="button" aria-label="${glyph.count} collapsed source records${rangeDescription}"><span>${glyph.count}</span></button>`;
      }
      const key = "source-record:" + lane.laneId + ":" + glyph.sourceRecordUid;
      state.hoverModels.set(key, { type: "source-record", mark: glyph, lane });
      return `<button class="source-record-mark${glyph.matchedEventUid ? " matched" : " unmatched"}${glyph.sourceRecordUid === state.selectedSourceRecordUid ? " selected" : ""}${inSelectedRange(glyph.timeNs) ? " in-range" : ""}" data-source-record-uid="${escapeHtml(glyph.sourceRecordUid)}" data-hover-key="${escapeHtml(key)}" data-time-ns="${glyph.timeNs}" style="left:${timelinePercent(glyph.timeNs)}%;--source-color:${escapeHtml(color)}" type="button" aria-label="${escapeHtml(glyph.recordName + " at " + formatOffset(glyph.timeNs, visibleTimelineOffsetPrecision()))}"></button>`;
    }).join("");
    const countCopy = lane.truncated
      ? lane.marks.length.toLocaleString() + " of " + lane.recordCount.toLocaleString()
      : lane.recordCount.toLocaleString();
    return `<div class="timeline-row source-record-row" style="grid-template-columns:${timelineLaneWidth()}px ${trackWidth}px;--layer-color:${escapeHtml(color)}" data-source-lane-id="${escapeHtml(lane.laneId)}">
      <div class="lane-label source-record-lane-label">
        <span class="source-record-icon" aria-hidden="true"></span>
        <span class="lane-copy" title="${escapeHtml(lane.description || lane.pattern)}"><strong>${escapeHtml(lane.label)}</strong><span class="lane-meta"><span class="lane-type">${escapeHtml(sourceTypes)}</span><span class="lane-separator" aria-hidden="true">·</span><span class="lane-layer">${escapeHtml(countCopy)} records</span></span></span>
      </div>
      <div class="lane-track source-record-track" data-source-lane-id="${escapeHtml(lane.laneId)}">${rangeBand}${glyphs}</div>
    </div>`;
  }).join("");
}

function annotationProjectionLabel(projection) {
  const entry = projection.entry || {};
  return projection.streamKind === "source"
    ? String(entry.record_name || "source record")
    : String(entry.event_type || entry.label || "event");
}

function buildAnnotationGlyphs(projections) {
  const result = [];
  let group = [];
  const flush = () => {
    if (group.length >= 3) {
      result.push({
        kind: "annotation-cluster",
        items: group,
        startNs: group[0].timeNs,
        endNs: group.at(-1).timeNs,
      });
    } else {
      result.push(...group);
    }
    group = [];
  };
  projections.forEach((projection) => {
    const prior = group.at(-1);
    const pixelGap = prior
      ? Math.abs(timelinePercent(projection.timeNs) - timelinePercent(prior.timeNs)) / 100
        * state.trackWidth
      : Number.POSITIVE_INFINITY;
    if (!group.length || (pixelGap <= 10 && group.length < 64)) group.push(projection);
    else {
      flush();
      group.push(projection);
    }
  });
  flush();
  return result;
}

function annotationClusterHoverHtml(items) {
  return `<div class="hover-heading"><div><span>REVIEW MARKERS</span><strong>${items.length.toLocaleString()} marked items</strong></div><button class="hover-close" type="button" aria-label="Close">x</button></div>
    <div class="cluster-window">${items.slice(0, 200).map((projection) => `<button type="button" class="cluster-event${state.hiddenTimelineEntryIds.has(projection.entryId) ? " timeline-hidden" : ""}" data-annotation-entry-id="${escapeHtml(projection.entryId)}"><span>${escapeHtml(formatOffset(projection.timeNs, visibleTimelineOffsetPrecision()))}</span><strong>${escapeHtml(annotationProjectionLabel(projection))}</strong><small>${escapeHtml(projection.entryId)}${state.hiddenTimelineEntryIds.has(projection.entryId) ? " / underlying mark hidden" : ""}</small></button>`).join("")}${items.length > 200 ? `<p class="cluster-detail-state">${(items.length - 200).toLocaleString()} additional markers are collapsed.</p>` : ""}</div>`;
}

function reviewMarkerLaneHtml(trackWidth = state.trackWidth) {
  const allMarked = [...state.markedTimelineEntryIds]
    .map((entryId) => state.timelineEntryProjections.get(entryId))
    .filter(Boolean)
    .sort((left, right) => (
      left.timeNs < right.timeNs ? -1 : left.timeNs > right.timeNs ? 1 : left.entryId.localeCompare(right.entryId)
    ));
  if (!allMarked.length) return "";
  const marked = allMarked.filter((projection) => timelinePointVisible(projection.timeNs));
  const glyphs = buildAnnotationGlyphs(marked).map((glyph, index) => {
    if (glyph.kind === "annotation-cluster") {
      const key = `annotation-cluster:${index}:${glyph.startNs}`;
      const last = glyph.items[glyph.items.length - 1];
      const hiddenInCluster = glyph.items.filter(
        (projection) => state.hiddenTimelineEntryIds.has(projection.entryId),
      ).length;
      const lastJump = last?.streamKind === "source"
        ? `data-last-source-record-uid="${escapeHtml(last.uid)}"`
        : last
          ? `data-last-event-uid="${escapeHtml(last.uid)}"`
          : "";
      state.hoverModels.set(key, {
        type: "annotation-cluster",
        items: glyph.items,
      });
      const time = glyph.startNs + (glyph.endNs - glyph.startNs) / 2n;
      return `<button class="review-marker cluster${hiddenInCluster ? " has-hidden" : ""}" type="button" data-hover-key="${escapeHtml(key)}" data-range-start-ns="${glyph.startNs}" data-range-end-ns="${glyph.endNs}" data-range-semantics="inclusive" ${lastJump} style="left:${timelinePercent(time)}%" aria-label="${glyph.items.length} review markers${hiddenInCluster ? `; ${hiddenInCluster} underlying marks hidden` : ""}"><span>${glyph.items.length}</span></button>`;
    }
    const key = `review-marker:${glyph.entryId}`;
    const jump = glyph.streamKind === "source"
      ? `data-source-record-uid="${escapeHtml(glyph.uid)}"`
      : `data-event-uid="${escapeHtml(glyph.uid)}"`;
    state.hoverModels.set(key, eventLogHoverModel(glyph.entry));
    const hiddenClass = state.hiddenTimelineEntryIds.has(glyph.entryId)
      ? " underlying-hidden"
      : "";
    return `<button class="review-marker ${glyph.streamKind}${hiddenClass}" type="button" data-hover-key="${escapeHtml(key)}" data-log-entry-id="${escapeHtml(glyph.entryId)}" data-time-ns="${glyph.timeNs}" ${jump} style="left:${timelinePercent(glyph.timeNs)}%" aria-label="${escapeHtml(`Marked ${annotationProjectionLabel(glyph)} at ${formatOffset(glyph.timeNs, visibleTimelineOffsetPrecision())}${hiddenClass ? "; underlying mark hidden" : ""}`)}"><span aria-hidden="true">&#9733;</span></button>`;
  }).join("");
  const hiddenCount = allMarked.filter(
    (projection) => state.hiddenTimelineEntryIds.has(projection.entryId),
  ).length;
  const markerCountCopy = `${marked.length.toLocaleString()} visible / ${allMarked.length.toLocaleString()} marked`
    + (hiddenCount ? ` / ${hiddenCount.toLocaleString()} hidden` : "");
  return `<div class="timeline-row review-marker-row" style="grid-template-columns:${timelineLaneWidth()}px ${trackWidth}px;--layer-color:var(--amber)">
    <div class="lane-label review-marker-lane-label"><span class="review-marker-icon" aria-hidden="true">&#9733;</span><span class="lane-copy"><strong>Review markers</strong><span class="lane-meta"><span class="lane-type">${markerCountCopy}</span></span></span></div>
    <div class="lane-track review-marker-track">${glyphs}</div>
  </div>`;
}

function timelineFocusDescriptor(element = document.activeElement) {
  const content = byId("timeline-content");
  if (!(element instanceof HTMLElement) || !content?.contains(element)) return null;
  const row = element.closest(".timeline-row");
  const identity = [
    "logEntryId",
    "clusterId",
    "sourceClusterId",
    "eventUid",
    "sourceRecordUid",
    "hoverKey",
    "treeKey",
    "rangeHandle",
    "laneCloseResourceId",
  ].find((property) => element.dataset[property]);
  if (!identity) return null;
  return {
    property: identity,
    value: element.dataset[identity],
    resourceId: row?.dataset.resourceId || null,
    sourceLaneId: row?.dataset.sourceLaneId || null,
  };
}

function timelineElementForFocusDescriptor(descriptor) {
  const content = byId("timeline-content");
  if (!content || !descriptor) return null;
  const candidates = [...content.querySelectorAll("button, [tabindex]")];
  return candidates.find((element) => (
    element.dataset[descriptor.property] === descriptor.value
    && (!descriptor.resourceId || element.closest(".timeline-row")?.dataset.resourceId === descriptor.resourceId)
    && (!descriptor.sourceLaneId || element.closest(".timeline-row")?.dataset.sourceLaneId === descriptor.sourceLaneId)
  )) || null;
}

function restoreTimelineFocusDescriptor(descriptor) {
  if (!descriptor) return;
  window.requestAnimationFrame(() => {
    // A user-initiated focus move after the render wins over this repair.
    if (document.activeElement && document.activeElement !== document.body
      && document.activeElement !== document.documentElement) return;
    (timelineElementForFocusDescriptor(descriptor) || byId("timeline-scroll"))
      ?.focus({ preventScroll: true });
  });
}

function renderTimeline() {
  const content = byId("timeline-content");
  if (!content) return;
  const focusDescriptor = timelineFocusDescriptor();
  const regularVisible = visibleTimelineLanes();
  const selectedLane = resourceHiddenFromTimeline(state.selectedResourceId)
    ? null
    : state.laneByResource.get(state.selectedResourceId);
  const visible = state.correlationTimelineView === "combined"
    ? selectedLane
      ? [{ lane: selectedLane, key: `root:${selectedLane.resourceId}`, depth: 0, parentResourceId: null, relationship: null, hasChildren: relationshipGroupsForResource(selectedLane.resourceId, new Set([selectedLane.resourceId])).length > 0 }]
      : []
    : timelineTreeInstances(regularVisible);
  // Logical zoom changes the exact visible time window. The physical track
  // stays viewport-sized so Chromium never clamps a multi-billion-pixel CSS
  // surface and corrupts pointer anchoring at deep zoom.
  const trackWidth = timelinePhysicalTrackWidth();
  const laneWidth = timelineLaneWidth();
  state.trackWidth = trackWidth;
  content.style.width = `${laneWidth + trackWidth}px`;
  content.style.minWidth = `${laneWidth + trackWidth}px`;
  byId("timeline-frame").querySelector(".timeline-sticky").style.gridTemplateColumns = `${laneWidth}px ${trackWidth}px`;
  renderRuler();
  state.hoverModels.clear();
  rebuildHiddenEventProjectionIndex();
  const densityLane = eventDensityLane(trackWidth);
  const expansionNotice = timelineExpansionNoticeHtml(trackWidth);
  const sourceLanes = sourceRecordLanesHtml(trackWidth);
  const reviewMarkers = reviewMarkerLaneHtml(trackWidth);

  content.innerHTML = expansionNotice + densityLane + reviewMarkers + sourceLanes + visible.map((instance) => {
    const lane = instance.lane;
    const compact = lane.tags.has("compact") || lane.tags.has("connector");
    const kindLabel = humanResourceType(lane.kind);
    const layerLabel = humanLayer(lane.layer);
    const bounds = rangeBounds();
    const lifecycle = lane.lifecycle.map((interval, index) => ({ interval, index })).filter(
      ({ interval }) => timelineIntervalVisible(interval.startNs, interval.endNs),
    ).map(({ interval, index }) => {
      const key = hoverKey("life", lane, index);
      state.hoverModels.set(key, { type: "interval", interval, lane });
      return `<button class="lifecycle-bar${interval.openStart ? " open-start" : ""}${interval.openEnd ? " open-end" : ""}${intersectsRange(interval.startNs, interval.endNs) ? " in-range" : ""}" data-hover-key="${escapeHtml(key)}" data-range-start-ns="${interval.startNs}" data-range-end-ns="${interval.endNs}" style="${barStyle(interval)}" type="button" aria-label="Lifecycle ${escapeHtml(formatOffset(interval.startNs, visibleTimelineOffsetPrecision()))} to ${escapeHtml(formatOffset(interval.endNs, visibleTimelineOffsetPrecision()))}"></button>`;
    }).join("");
    const statuses = lane.statuses.map((interval, index) => ({ interval, index })).filter(
      ({ interval }) => timelineIntervalVisible(interval.startNs, interval.endNs),
    ).map(({ interval, index }) => {
      const key = hoverKey("status", lane, index);
      state.hoverModels.set(key, { type: "interval", interval, lane });
      return `<button class="${statusSegmentClassName({ status_class: interval.statusClass })}${intersectsRange(interval.startNs, interval.endNs) ? " in-range" : ""}" data-hover-key="${escapeHtml(key)}" data-start-ns="${interval.startNs}" data-end-ns="${interval.endNs}" data-range-start-ns="${interval.startNs}" data-range-end-ns="${interval.endNs}" data-open-end="${interval.openEnd}" style="${barStyle(interval)};--segment-color:${escapeHtml(layerColor(lane.layer))}" type="button"><span>${escapeHtml(interval.status)}</span></button>`;
    }).join("");
    const glyphs = buildClientGlyphs(lane).filter((glyph) => (
      glyph.kind === "cluster"
        ? timelinePointIntervalVisible(glyph.startNs, glyph.endNs)
        : timelinePointVisible(glyph.timeNs)
    )).map((glyph) => {
      if (glyph.kind === "cluster") {
        const key = hoverKey("cluster", lane, glyph.clusterId);
        state.hoverModels.set(key, { type: "cluster", cluster: glyph, lane });
        const selected = glyph.eventUids.includes(state.selectedEventUid);
        const time = glyph.startNs + (glyph.endNs - glyph.startNs) / 2n;
        const latest = [...glyph.items].sort((a, b) => a.timeNs < b.timeNs ? -1 : a.timeNs > b.timeNs ? 1 : 0).at(-1);
        const lastEventUid = latest?.eventUid || glyph.eventUids.at(-1) || "";
        const clusterItems = glyph.items.length
          ? glyph.items
          : glyph.eventUids.map((uid) => lane.marks.find((mark) => mark.eventUid === uid)).filter(Boolean);
        const rangeState = pointClusterRangeState(clusterItems, bounds);
        const rangeDescription = rangeState.count
          ? `; ${rangeState.count} of ${rangeState.total} events are in the selected range`
          : "";
        const staleCopy = glyph.staleWindow
          ? "; previous viewport overlap shown while exact events refresh"
          : "";
        return `<button class="event-mark cluster${glyph.staleWindow ? " stale-window" : ""}${glyph.failureCount ? " has-failure" : ""}${selected ? " selected" : ""}${rangeState.className}" data-hover-key="${escapeHtml(key)}" data-cluster-id="${escapeHtml(glyph.clusterId)}" data-last-event-uid="${escapeHtml(lastEventUid)}" data-range-start-ns="${glyph.startNs}" data-range-end-ns="${glyph.endNs}" style="left:${timelinePercent(time)}%;--event-color:${glyph.failureCount ? "#ff6879" : layerColor(lane.layer)}" type="button" aria-label="${glyph.count} collapsed events${rangeDescription}${staleCopy}"><span>${glyph.staleWindow ? "~" : ""}${glyph.count}</span></button>`;
      }
      const key = hoverKey("event", lane, glyph.eventUid);
      state.hoverModels.set(key, { type: "event", mark: glyph, lane });
      return `<button class="event-mark ${eventMarkClass(glyph)}${glyph.eventUid === state.selectedEventUid ? " selected" : ""}${inSelectedRange(glyph.timeNs) ? " in-range" : ""}" data-event-uid="${escapeHtml(glyph.eventUid)}" data-hover-key="${escapeHtml(key)}" data-time-ns="${glyph.timeNs}" style="left:${timelinePercent(glyph.timeNs)}%;--event-color:${glyph.failure ? "#ff6879" : layerColor(lane.layer)}" type="button" aria-label="${escapeHtml(`${glyph.label} at ${formatOffset(glyph.timeNs, visibleTimelineOffsetPrecision())}`)}"></button>`;
    }).join("");
    const relationshipRibbons = relationshipRibbonsForLane(lane, instance);
    const rangeBand = timelineRangeBandHtml(bounds);
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
    return `<div class="timeline-row${compact ? " compact" : ""}${selectedResource ? " selected-resource" : ""}${correlatedResource ? " correlated-resource" : ""}${instance.depth ? " tree-child" : " tree-root"}" style="grid-template-columns:${laneWidth}px ${trackWidth}px;--layer-color:${layerColor(lane.layer)};--tree-indent:${instance.depth * 14}px;--tree-branch:${Math.max(0, instance.depth - 1) * 14 + 17}px" data-resource-id="${escapeHtml(lane.resourceId)}" data-tree-key="${escapeHtml(instance.key)}"${instance.parentResourceId ? ` data-parent-resource-id="${escapeHtml(instance.parentResourceId)}"` : ""}${instance.relationship ? ` data-relationship-type="${escapeHtml(instance.relationship.type)}"` : ""}>
      <div class="resource-lane-label-shell">
        <button class="lane-close" type="button" data-lane-close-resource-id="${escapeHtml(lane.resourceId)}" aria-label="${escapeHtml(`Hide ${lane.label} from Resource timeline`)}" title="Hide from Resource timeline"><span aria-hidden="true">&times;</span></button>
        <button class="lane-label" type="button" data-resource-id="${escapeHtml(lane.resourceId)}" data-tree-key="${escapeHtml(instance.key)}" ${instance.hasChildren ? `data-tree-expandable aria-expanded="${expanded}"` : ""}>
        ${treeGuides}
        <span class="lane-tree-toggle" aria-hidden="true"></span>
        ${customIcon || '<span class="lane-dot" aria-hidden="true"></span>'}
        <span class="lane-copy" title="${escapeHtml(`${lane.label} / ${kindLabel} / ${layerLabel}`)}"><strong>${escapeHtml(lane.label)}</strong><span class="lane-meta">${instance.relationship ? `<span class="lane-relation ${relationDirection}">${relationshipDirectionSymbol(instance.relationship.type, relationDirection)} ${escapeHtml(relationshipDisplayLabel(instance.relationship.type))}</span><span class="lane-separator" aria-hidden="true">·</span>` : ""}<span class="lane-type" title="Resource type: ${escapeHtml(kindLabel)}">${escapeHtml(kindLabel)}</span><span class="lane-separator" aria-hidden="true">·</span><span class="lane-layer">${escapeHtml(layerLabel)}</span></span></span>
        ${instance.truncatedChildren ? `<span class="tree-depth-note" title="${instance.omittedChildCount} deeper relationship branches omitted">+${instance.omittedChildCount} deeper</span>` : ""}
        ${compact ? '<span class="compact-tag">connector</span>' : ""}
        </button>
      </div>
      <div class="lane-track" data-resource-id="${escapeHtml(lane.resourceId)}">${rangeBand}${lifecycle}${statuses}${relationshipRibbons}${glyphs}</div>
    </div>`;
  }).join("") + combinedAssociationLane(trackWidth);

  if (!visible.length) {
    content.innerHTML = `${densityLane}${reviewMarkers}${sourceLanes}<div class="timeline-empty" style="width:${laneWidth + trackWidth}px"><strong>No resource lanes selected</strong><span>Source-record and review-marker lanes remain visible. Open Lanes to add resource timelines.</span></div>`;
  }

  const cursor = document.createElement("div");
  cursor.className = "timeline-cursor-line";
  cursor.style.left = `${laneWidth + Math.max(0, Math.min(100, timelinePercent(state.cursorNs))) / 100 * state.trackWidth}px`;
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
  updateTimelineCommandAvailability();
  restoreTimelineFocusDescriptor(focusDescriptor);
  window.requestAnimationFrame(drawTimelineCorrelationOverlay);
}

function pointNsFromClientX(clientX, track) {
  const rect = track.getBoundingClientRect();
  return timelineNsAtLocalRatio((clientX - rect.left) / Math.max(1, rect.width));
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
  line.style.left = `${timelineLaneWidth() + timelinePercent(timeNs) / 100 * state.trackWidth}px`;
  line.dataset.timeNs = timeNs.toString();
  line.dataset.timeLabel = formatOffset(timeNs, visibleTimelineOffsetPrecision());
  const timeLabel = byId("timeline-ruler")?.querySelector(".timeline-hover-time");
  const scroll = byId("timeline-scroll");
  if (timeLabel) {
    timeLabel.textContent = line.dataset.timeLabel;
    timeLabel.style.left = `${timelinePercent(timeNs) / 100 * state.trackWidth}px`;
    timeLabel.dataset.labelAlign = "center";
    timeLabel.hidden = false;
  }
  const scrollRect = scroll.getBoundingClientRect();
  const visibleTrackLeft = Math.min(scrollRect.right, scrollRect.left + timelineLaneWidth());
  const labelAlign = scrollRect.right - clientX < 58
    ? "left"
    : clientX - visibleTrackLeft < 58 ? "right" : "center";
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
  const timeline = byId("timeline-content");
  if (!timeline) return;
  timeline.querySelectorAll("[data-lane-close-resource-id]").forEach((button) => {
    button.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      closeHover();
      closeCorrelationHover();
      setExplicitLaneVisibility(button.dataset.laneCloseResourceId, false);
    });
  });
  timeline.querySelectorAll(".lane-label[data-resource-id]").forEach((button) => {
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
  timeline.querySelectorAll(".event-mark[data-event-uid]").forEach((mark) => {
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
      const replacement = [...timeline.querySelectorAll(".event-mark[data-event-uid]")]
        .find((item) => item.dataset.eventUid === eventUid && item.closest(".lane-track")?.dataset.resourceId === resourceId);
      showHover(key, replacement || mark, true);
    });
  });
  timeline.querySelectorAll(".event-mark[data-cluster-id]").forEach((mark) => {
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
  timeline.querySelectorAll(".source-record-mark[data-source-record-uid]").forEach((mark) => {
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
  timeline.querySelectorAll(".source-record-mark[data-source-cluster-id]").forEach((mark) => {
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
  timeline.querySelectorAll(".review-marker[data-hover-key]").forEach((mark) => {
    mark.addEventListener("click", (event) => {
      event.stopPropagation();
      if (performance.now() < state.suppressTimelineClickUntil) return;
      const entryId = mark.dataset.logEntryId;
      const hoverKey = mark.dataset.hoverKey;
      if (entryId) {
        const projection = state.timelineEntryProjections.get(entryId);
        if (projection?.streamKind === "source") selectSourceRecord(projection.uid, true);
        else if (projection) selectEvent(projection.uid, true);
      }
      const replacement = entryId
        ? timeline.querySelector(
          `.review-marker[data-log-entry-id="${CSS.escape(entryId)}"]`,
        )
        : mark;
      showHover(hoverKey, replacement || mark, true);
    });
  });
  timeline.querySelectorAll("[data-hover-key]").forEach((element) => bindHoverTarget(element));
}

function timelinePointerDown(event) {
  hideTimelineHoverLine();
  if (state.brush || event.button !== 0) return;
  const content = byId("timeline-content");
  const handle = event.target.closest("[data-range-handle]");
  const track = event.target.closest(".lane-track");
  if ((!track && !handle) || !content.contains(track || handle)) return;
  const mark = event.target.closest(".event-mark, .source-record-mark, .review-marker");
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
    mode: handle ? "handle" : wantsRange ? "range" : "pending",
    boundary: handle?.dataset.rangeHandle || null,
    anchorNs,
    latestNs: anchorNs,
    startX: event.clientX,
    latestX: event.clientX,
    frameId: null,
    autoScrollFrameId: null,
    autoScrollVelocity: 0,
    priorViewport: timelineViewportSnapshot(),
    viewportChanged: false,
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
  const [windowStartNs, windowEndNs] = timelineWindowBounds();
  const pixel = (windowEndNs - windowStartNs) / BigInt(Math.max(1, state.trackWidth));
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
  const scroll = byId("timeline-scroll");
  const scrollRect = scroll.getBoundingClientRect();
  const trackLeft = scrollRect.left + timelineLaneWidth() - scroll.scrollLeft;
  return timelineNsAtLocalRatio(
    (clientX - trackLeft) / Math.max(1, state.trackWidth),
  );
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
  if (!brush.viewportChanged) rememberTimelineView();
  const moved = panTimelineViewportByPixels(brush.autoScrollVelocity, {
    recordHistory: false,
    fromWheel: true,
  });
  if (!moved) {
    stopBrushAutoScroll(brush);
    return;
  }
  brush.viewportChanged = true;
  brush.latestNs = brushNsFromClientX(brush, brush.latestX);
  scheduleBrushFrame();
  brush.autoScrollFrameId = window.requestAnimationFrame(runBrushAutoScroll);
}

function updateBrushAutoScroll(brush) {
  const scroll = byId("timeline-scroll");
  const rect = scroll.getBoundingClientRect();
  const visibleTrackLeft = Math.min(rect.right, rect.left + timelineLaneWidth());
  const visibleTrackWidth = Math.max(1, rect.right - visibleTrackLeft);
  const edge = Math.min(32, visibleTrackWidth / 4);
  const leftDepth = Math.max(0, visibleTrackLeft + edge - brush.latestX);
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

function finishBrushViewportNavigation(brush, cancelled) {
  if (!brush.viewportChanged) return;
  if (cancelled) {
    invalidatePendingTimelineWindowRequest();
    state.zoom = brush.priorViewport.zoom;
    state.timelineWindowStartNs = brush.priorViewport.startNs;
    state.timelineWindowEndNs = brush.priorViewport.endNs;
    byId("timeline-zoom").value = timelineZoomControlValue(state.zoom);
    renderTimeline();
    updateTimelineCommandAvailability();
  } else {
    rememberTimelineView();
  }
  scheduleTimelineWindowRefresh();
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
  if (target.hoverKey) {
    showHover(target.hoverKey, target.element, true);
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
    finishBrushViewportNavigation(brush, true);
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
    finishBrushViewportNavigation(brush, true);
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
  finishBrushViewportNavigation(brush, false);
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
  document.querySelectorAll(".event-mark[data-time-ns], .source-record-mark[data-time-ns]").forEach((mark) => {
    const hit = Boolean(bounds) && toNs(mark.dataset.timeNs) >= bounds[0] && toNs(mark.dataset.timeNs) <= bounds[1];
    mark.classList.toggle("in-range", hit);
    mark.classList.toggle("out-of-range", Boolean(bounds) && !hit);
  });
  document.querySelectorAll(".event-mark.cluster[data-hover-key], .source-record-mark.cluster[data-hover-key]").forEach((element) => {
    const model = state.hoverModels.get(element.dataset.hoverKey);
    const rangeState = pointClusterRangeState(model?.cluster?.items || [], bounds);
    element.classList.toggle("in-range", Boolean(bounds) && rangeState.count === rangeState.total && rangeState.count > 0);
    element.classList.toggle("partial-range", Boolean(bounds) && rangeState.count > 0 && rangeState.count < rangeState.total);
    element.classList.toggle("out-of-range", Boolean(bounds) && rangeState.count === 0);
    const noun = element.classList.contains("source-record-mark") ? "source records" : "events";
    const rangeCopy = bounds && rangeState.count
      ? `; ${rangeState.count} of ${rangeState.total} ${noun} are in the selected range`
      : "";
    element.setAttribute("aria-label", `${rangeState.total} collapsed ${noun}${rangeCopy}`);
  });
  document.querySelectorAll("[data-range-start-ns][data-range-end-ns]:not(.event-mark.cluster):not(.source-record-mark.cluster)").forEach((element) => {
    const hit = Boolean(bounds) && (
      element.dataset.rangeSemantics === "inclusive"
        ? inclusiveIntervalIntersectsRange(element.dataset.rangeStartNs, element.dataset.rangeEndNs)
        : intersectsRange(element.dataset.rangeStartNs, element.dataset.rangeEndNs)
    );
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
    const percent = timelinePercent(value);
    handle.hidden = percent < 0 || percent > 100;
    handle.style.left = `${timelineLaneWidth() + Math.max(0, Math.min(100, percent)) / 100 * state.trackWidth}px`;
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
    const geometry = bounds ? timelineIntervalPercentGeometry(bounds[0], bounds[1]) : null;
    band.hidden = !geometry;
    if (!geometry) return;
    band.style.left = `${geometry.left}%`;
    band.style.width = `${geometry.width}%`;
  });
  applyRangeHighlight(bounds);
  updateRangeHandles(bounds);
  if (refreshEventLog && !state.brush && state.dataset && byId("event-table-body")) {
    renderEventTable({ resetScroll: Boolean(bounds) });
  }
  updateTimelineCommandAvailability();
}

function updateCursorVisual() {
  const line = document.querySelector(".timeline-cursor-line");
  if (line) {
    const percent = timelinePercent(state.cursorNs);
    line.style.left = `${timelineLaneWidth() + Math.max(0, Math.min(100, percent)) / 100 * state.trackWidth}px`;
    line.hidden = !state.cursorSelected || percent < 0 || percent > 100;
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
  state.resourceOffset = 0;
  updateCursorVisual();
  updateFabricNavigationLink();
  markResourcesPending(state.cursorNs);
  markDashboardsPending(state.cursorNs);
  scheduleTopologyRefreshFromCursor();
  updateTimelineCommandAvailability();
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
  abortLatestRequests(
    "graphAbortController",
    "resourceAbortController",
    "dashboardAbortController",
  );
  markCorrelationPending(state.cursorNs);
  state.temporalTimer = window.setTimeout(() => {
    requestGraph();
    requestResources();
    requestDashboards();
  }, 100);
}

function eventOrMark(uid) {
  const event = state.eventDetailByUid.get(uid) || state.eventByUid.get(uid);
  if (event) return event;
  for (const lane of state.lanes) {
    const mark = lane.marks.find((item) => item.eventUid === uid);
    if (mark) return mark.event;
  }
  return null;
}

function hydrateEventDetail(eventUid, detail) {
  const uid = String(eventUid);
  const normalized = { ...(state.eventByUid.get(uid) || {}), ...(detail || {}), event_uid: uid };
  state.eventDetailByUid.set(uid, normalized);
  state.eventByUid.set(uid, normalized);
  state.densityLocalCache = null;
  state.lanes.forEach((lane) => lane.marks.forEach((mark) => {
    if (mark.eventUid !== uid) return;
    const effect = resourceEffectFor(normalized, lane.resourceId);
    mark.event = normalized;
    mark.effect = effect;
    mark.action = effect?.effect_type || normalized.action || normalized.operation || mark.action;
    mark.outcome = normalizedEventOutcome(normalized);
    mark.failure = eventFailed(normalized);
    mark.stateChanged = effect?.state_changed ?? normalized.state_changed ?? mark.stateChanged;
    mark.effectType = effect?.effect_type || normalized.effect_type || mark.effectType;
    mark.label = normalized.display_name || normalized.label || titleCase(normalized.event_type || mark.eventType);
  }));
  return normalized;
}

function requestEventDetail(eventUid) {
  const uid = String(eventUid || "");
  if (!uid) return Promise.resolve(null);
  if (state.eventDetailByUid.has(uid)) return Promise.resolve(state.eventDetailByUid.get(uid));
  if (isTopologyNodeSnapshot()) return Promise.resolve(eventOrMark(uid));
  if (state.eventDetailRequests.has(uid)) return state.eventDetailRequests.get(uid);
  const request = api(revisionPath(`events/${encodeURIComponent(uid)}`))
    .then((detail) => hydrateEventDetail(uid, detail))
    .catch(() => eventOrMark(uid))
    .finally(() => state.eventDetailRequests.delete(uid));
  state.eventDetailRequests.set(uid, request);
  return request;
}

function selectEvent(eventUid, moveCursor = false, resourceId = null) {
  const event = eventOrMark(eventUid);
  if (!event) return;
  const eventResourceId = resourceId || eventResourceRefs(event)[0] || null;
  const focusResourceId = resourceId || (moveCursor ? eventResourceId : null);
  state.selectedEventUid = eventUid;
  state.selectedSourceRecordUid = null;
  state.selectedEventResourceId = eventResourceId;
  pruneServerEventLogOwnedCaches();
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
  requestEventDetail(eventUid).then((detail) => {
    if (!detail || state.selectedEventUid !== eventUid) return;
    renderEventInspector(detail);
    rerenderTimelinePreservingScroll();
  });
}

function selectSourceRecord(recordUid, moveCursor = false) {
  const record = state.sourceRecordByUid.get(String(recordUid));
  if (!record) return;
  state.selectedSourceRecordUid = String(recordUid);
  state.selectedEventUid = null;
  state.selectedEventResourceId = null;
  pruneServerEventLogOwnedCaches();
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
  includeSourceRecordGroup(record);
  syncEventLogIncludeControls();
  jumpToLogEntry(sourceLogEntryId(recordUid));
}

function sourceRecordLaneFor(recordUid) {
  const uid = String(recordUid);
  return state.recordLanes.find((lane) => (
    lane.marks.some((mark) => mark.sourceRecordUid === uid)
      || lane.clusters.some((cluster) => cluster.recordUids.includes(uid))
  )) || null;
}

function regexEscape(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function moveTimelineWindowToReveal(timeNs) {
  const targetNs = clampNs(timeNs);
  const [startNs, endNs] = timelineWindowBounds();
  const duration = endNs - startNs;
  const margin = duration > 20n ? duration / 20n : 0n;
  if (targetNs >= startNs + margin && targetNs <= endNs - margin) return false;
  return applyTimelineZoom(state.zoom, {
    anchorNs: targetNs,
    announce: false,
  });
}

async function refreshTimelineForNavigation() {
  window.clearTimeout(state.timelineWindowRequestTimer);
  state.timelineWindowRequestTimer = null;
  const updated = await requestTimeline();
  if (!updated) return false;
  renderTimeline();
  return true;
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
  const movedViewport = moveTimelineWindowToReveal(sourceRecordTime(record));
  if (movedViewport) await refreshTimelineForNavigation();
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
    (laneRow || destination).scrollIntoView({ behavior: "smooth", block: "center", inline: "nearest" });
    if (target || clusterTarget) destination.focus({ preventScroll: true });
    navigationPulse(destination);
  });
}

function eventLaneFor(eventUid) {
  return state.lanes.find((lane) => (
    lane.marks.some((mark) => mark.eventUid === eventUid)
      || lane.clusters.some((cluster) => cluster.eventUids.includes(eventUid))
  )) || null;
}

async function jumpToTimelineEvent(eventUid) {
  const event = eventOrMark(eventUid);
  if (!event) return;
  let lane = eventLaneFor(eventUid);
  const resourceId = lane?.resourceId || eventResourceRefs(event)[0] || null;
  if (resourceId) state.hiddenTimelineResourceIds.delete(resourceId);
  let addedScaleLane = false;
  if (isScaleMode() && resourceId && !lane) {
    state.laneMode = "custom";
    if (state.explicitLaneIds.size >= MAX_SCALE_TIMELINE_LANES) state.explicitLaneIds.delete(state.explicitLaneIds.values().next().value);
    state.explicitLaneIds.add(resourceId);
    addedScaleLane = true;
  }
  const movedViewport = moveTimelineWindowToReveal(eventTime(event));
  // The server's bounded cluster preview guarantees the selected event. Pin
  // the target before the navigation query so a middle event in a million-row
  // cluster remains focusable after the exact logical window is returned.
  state.selectedEventUid = eventUid;
  state.selectedSourceRecordUid = null;
  state.selectedEventResourceId = resourceId;
  if (movedViewport || addedScaleLane || !lane) {
    await refreshTimelineForNavigation();
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
    (row || target).scrollIntoView({ behavior: "smooth", block: "center", inline: "nearest" });
    if (eventTarget) eventTarget.focus({ preventScroll: true });
    navigationPulse(eventTarget || row);
  });
}

async function jumpToTimelineResource(resourceId) {
  resourceId = canonicalResourceId(resourceId);
  if (!resourceId) return;
  state.hiddenTimelineResourceIds.delete(resourceId);
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

function eventEffectMarkup(event, selectedResourceId = null) {
  const effects = eventEffects(event);
  const affected = [...new Set([
    ...eventResourceRefs(event),
    ...effects.map(effectResourceId).filter(Boolean),
  ])];
  const effectRows = effects.map((effect) => {
    const resourceId = effectResourceId(effect) || "unknown resource";
    const record = state.resourceById.get(resourceId);
    const kind = effect.kind || record?.kind || "UNKNOWN";
    const selected = resourceId === selectedResourceId;
    const condition = resourceEffectCondition(effect, resourceId);
    const before = effect.before;
    const after = resourceEffectState(effect);
    return `<article class="event-effect${selected ? " selected" : ""}">
      <header><strong>${escapeHtml(effect.effect_type || "effect")}</strong><span>${selected ? "selected lane" : escapeHtml(humanResourceType(kind))}</span></header>
      <code>${escapeHtml(resourceId)}</code>
      <dl>
        <dt>State changed</dt><dd>${effect.state_changed === undefined ? "unknown" : effect.state_changed ? "yes" : "no"}</dd>
        ${condition === null || condition === undefined ? "" : `<dt>Condition</dt><dd>${escapeHtml(formatValue(condition))}</dd>`}
        ${before === undefined ? "" : `<dt>Before</dt><dd>${escapeHtml(formatValue(before))}</dd>`}
        ${after === null || after === undefined ? "" : `<dt>After</dt><dd>${escapeHtml(formatValue(after))}</dd>`}
      </dl>
    </article>`;
  }).join("");
  const affectedMarkup = affected.length
    ? `<div class="event-affected-resources"><strong>Affected resources (${affected.length})</strong>${affected.map((id) => `<code>${escapeHtml(id)}</code>`).join("")}</div>`
    : '<div class="event-affected-resources"><strong>Affected resources</strong><span>None declared by the plug-in.</span></div>';
  return `${affectedMarkup}${effects.length ? `<details class="event-effects" open><summary>${effects.length} normalized resource effect${effects.length === 1 ? "" : "s"}</summary><div>${effectRows}</div></details>` : ""}`;
}

function eventOutcomeText(event) {
  return normalizedEventOutcome(event);
}

function eventOutcomeCssClass(event) {
  const outcome = normalizedEventOutcome(event);
  return outcome === "failure" ? "failure-text" : outcome === "success" ? "success-text" : "";
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
  const selectedEffect = resourceEffectFor(event, canonicalId);
  const selectedCondition = resourceEffectCondition(selectedEffect, canonicalId);
  const operation = selectedEffect?.effect_type || event.action || event.operation || "observe";
  byId("selected-event-title").textContent = titleCase(event.event_type || event.label || "event");
  byId("selected-event-summary").textContent = `${humanLayer(resourceLayerName)} / ${resourceText} / ${operation} -> ${eventOutcomeText(event)}`;
  const fields = [
    ["Time", `${formatOffset(eventTime(event))} (${eventTime(event)} ns)`],
    ["Operation", operation],
    ["Outcome", eventOutcomeText(event)],
    ["Resulting status", formatValue(selectedCondition ?? eventStatus(event, canonicalId))],
    ["Status duration", mark ? formatDuration(mark.durationToNextChangeNs) : "unknown"],
    ["Quality", event.quality || "unknown"],
    ["Properties", formatValue(properties)],
    ["Result", formatValue(result)],
  ];
  byId("selected-event-fields").innerHTML = fields.map(([key, value]) => `<dt>${escapeHtml(key)}</dt><dd>${escapeHtml(value)}</dd>`).join("");
  const evidence = event.evidence || {};
  byId("selected-event-evidence").innerHTML = `<div class="event-evidence-source"><strong>Evidence</strong><br>${escapeHtml(evidence.logical_path || "No source path")}<br><span>${escapeHtml(evidence.locator || "No locator")}</span></div>${eventEffectMarkup(event, canonicalId)}`;
}

function renderSourceRecordInspector(record) {
  const descriptor = sourceTypeDescriptor(record.source_type);
  const matchedEventUids = sourceRecordMatchedEventUids(record);
  const linked = matchedEventUids.length
    ? state.eventByUid.get(matchedEventUids[0])
    : null;
  byId("selected-event-title").textContent = titleCase(record.record_name || "source record");
  byId("selected-event-summary").textContent = descriptor.label + " / "
    + String(record.source_name || "source") + " / "
    + (matchedEventUids.length ? "linked to normalized event" : "unmatched");
  const fields = [
    ["Time", formatOffset(sourceRecordTime(record)) + " (" + sourceRecordTime(record) + " ns)"],
    ["Source type", descriptor.label],
    ["Source", record.source_name || "unknown"],
    ["Layer", humanLayer(record.layer || "unknown")],
    ["Normalization", matchedEventUids.length ? "matched" : "unmatched"],
    ["Linked events", linked && matchedEventUids.length === 1
      ? String(linked.event_type || matchedEventUids[0])
      : matchedEventUids.join(", ") || "none"],
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

function eventHoverHtml(mark, lane, occurrenceLanes = [lane]) {
  const event = mark.event || {};
  const condition = resourceEffectCondition(mark.effect, lane.resourceId);
  const effectState = resourceEffectState(mark.effect);
  const result = mark.failure && mark.stateChanged === false
    ? "No mutation; status unchanged"
    : condition ?? eventStatus(event, lane.resourceId);
  const occurrences = (occurrenceLanes || []).filter(Boolean);
  const occurrenceDetail = occurrences.length > 1
    ? `<dt>Timeline occurrences</dt><dd>${occurrences.length} resource lanes<small>${escapeHtml(occurrences.map((item) => item.label).join(", "))}</small></dd>`
    : occurrences.length
      ? ""
      : "<dt>Timeline</dt><dd>Not in the loaded lanes<small>Use Reveal in timeline to load its resource lane.</small></dd>";
  return `<div class="hover-heading"><div><span>${mark.failure ? "FAILED EVENT" : "EVENT"}</span><strong>${escapeHtml(mark.label)}</strong></div><button class="hover-close" type="button" aria-label="Close">x</button></div>
    <dl class="hover-facts">
      <dt>When</dt><dd>${escapeHtml(formatOffset(mark.timeNs))}<small>${mark.timeNs} ns</small></dd>
      <dt>Resource</dt><dd>${escapeHtml(lane.label)}<small>${escapeHtml(humanResourceType(lane.kind))}</small></dd>
      <dt>Operation</dt><dd>${escapeHtml(mark.action)}</dd>
      <dt>Outcome</dt><dd class="${eventOutcomeCssClass({ outcome: mark.outcome })}">${escapeHtml(mark.outcome)}</dd>
      <dt>Result</dt><dd>${escapeHtml(formatValue(result))}${effectState === null || effectState === undefined ? "" : `<small>${escapeHtml(formatValue(effectState))}</small>`}</dd>
      <dt>Duration</dt><dd>${escapeHtml(formatDuration(mark.durationToNextChangeNs))}<small>until next accepted state change</small></dd>
      ${occurrenceDetail}
    </dl>`;
}

function clusterHoverHtml(cluster, lane) {
  const preview = cluster.items.length
    ? cluster.items
    : cluster.eventUids.map((uid) => lane.marks.find((mark) => mark.eventUid === uid)).filter(Boolean);
  const items = cluster.detailHydrated ? cluster.detailItems : preview;
  const total = Number.isFinite(cluster.detailTotal) ? cluster.detailTotal : cluster.count;
  const progress = cluster.detailHydrated || cluster.detailLoading
    ? `<small class="cluster-detail-progress">${items.length.toLocaleString()} of ${total.toLocaleString()} exact events loaded</small>`
    : cluster.detailTruncated
      ? `<small class="cluster-detail-progress">Showing a bounded preview while exact events load</small>`
      : "";
  let detailControl = "";
  if (cluster.detailLoading) {
    detailControl = '<p class="cluster-detail-state" role="status">Loading exact events…</p>';
  } else if (cluster.detailError) {
    detailControl = `<div class="cluster-detail-state error"><span>${escapeHtml(cluster.detailError)}</span><button type="button" data-cluster-detail-offset="${cluster.detailRetryOffset}">Retry</button></div>`;
  } else if (cluster.detailNextOffset !== null) {
    detailControl = `<button class="cluster-load-more" type="button" data-cluster-detail-offset="${cluster.detailNextOffset}">Load more events</button>`;
  } else if (cluster.detailTruncated && cluster.serverBacked && !isTopologyNodeSnapshot()) {
    detailControl = '<button class="cluster-load-more" type="button" data-cluster-detail-offset="0">Load exact events</button>';
  }
  const staleNotice = cluster.staleWindow
    ? '<p class="cluster-detail-state">This clipped marker overlaps the previous viewport. Visible preview events are retained while the exact window refreshes.</p>'
    : "";
  return `<div class="hover-heading"><div><span>COLLAPSED EVENTS</span><strong>${total} events${cluster.failureCount ? ` / ${cluster.failureCount} failed` : ""}${cluster.hiddenCount ? ` / ${cluster.hiddenCount} hidden` : ""}</strong>${progress}</div><button class="hover-close" type="button" aria-label="Close">x</button></div>
    ${staleNotice}<div class="cluster-window">${items.map((mark) => `<button type="button" class="cluster-event${mark.failure ? " failed" : ""}${inSelectedRange(mark.timeNs) ? " in-range" : ""}" data-cluster-event-uid="${escapeHtml(mark.eventUid)}"><span>${escapeHtml(formatOffset(mark.timeNs))}</span><strong>${escapeHtml(mark.label)}</strong><small>${escapeHtml(`${mark.action} / ${mark.failure ? "failed" : mark.outcome}${rangeBounds() ? (inSelectedRange(mark.timeNs) ? " / in selected range" : " / outside selected range") : ""}`)}</small></button>`).join("") || '<p class="empty-cluster">No event detail was returned for this cluster.</p>'}${detailControl}</div>`;
}

function clusterDetailRequestAvailable(cluster) {
  return Boolean(
    cluster?.serverBacked
    && !isTopologyNodeSnapshot()
    && (cluster.detailTruncated || cluster.detailNextOffset !== null),
  );
}

function refreshOpenClusterHover(key, cluster, lane) {
  if (state.hoverKey !== key) return;
  const model = state.hoverModels.get(key);
  if (!model || model.type !== "cluster" || model.cluster !== cluster) return;
  const card = byId("timeline-hover");
  if (!card || card.hidden) return;
  const scrollTop = card.querySelector(".cluster-window")?.scrollTop || 0;
  card.innerHTML = clusterHoverHtml(cluster, lane);
  bindHoverCardActions(card, model, key);
  const windowElement = card.querySelector(".cluster-window");
  if (windowElement) windowElement.scrollTop = scrollTop;
}

function requestClusterDetail(key, cluster, lane, requestedOffset = 0) {
  if (!clusterDetailRequestAvailable(cluster) || cluster.detailLoading) return Promise.resolve(false);
  const offset = Number(requestedOffset);
  if (!Number.isInteger(offset) || offset < 0) return Promise.resolve(false);
  const requestId = ++cluster.detailRequestId;
  cluster.detailLoading = true;
  cluster.detailError = null;
  cluster.detailRetryOffset = offset;
  refreshOpenClusterHover(key, cluster, lane);
  return api(revisionPath("timeline/clusters/detail"), {
    method: "POST",
    body: JSON.stringify({
      resource_id: lane.resourceId,
      start_ns: cluster.startNs.toString(),
      end_ns: cluster.endNs.toString(),
      offset,
      limit: CLUSTER_DETAIL_PAGE_SIZE,
    }),
  }).then((payload) => {
    if (requestId !== cluster.detailRequestId) return false;
    if (!payload || !Array.isArray(payload.items)) throw new Error("Cluster detail response is missing items");
    const page = payload.items
      .map((item) => normalizeMark(item, lane))
      .filter((mark) => (
        !state.hiddenTimelineEntryIds.has(normalizedLogEntryId(mark.eventUid))
      ));
    const merged = offset === 0 ? page : [...cluster.detailItems, ...page];
    const seen = new Set();
    cluster.detailItems = merged.filter((mark) => {
      if (!mark.eventUid || seen.has(mark.eventUid)) return false;
      seen.add(mark.eventUid);
      return true;
    });
    cluster.eventUids = [...new Set([
      ...cluster.eventUids.filter(
        (uid) => !state.hiddenTimelineEntryIds.has(normalizedLogEntryId(uid)),
      ),
      ...cluster.detailItems.map((mark) => mark.eventUid),
    ])];
    cluster.detailHydrated = true;
    cluster.detailTotal = Math.max(
      0,
      Number(payload.total_count ?? cluster.detailTotal ?? cluster.count)
        - Number(cluster.hiddenCount || 0),
    );
    cluster.detailNextOffset = payload.next_offset === null || payload.next_offset === undefined
      ? null
      : Number(payload.next_offset);
    cluster.detailTruncated = Boolean(payload.truncated);
    cluster.detailError = null;
    return true;
  }).catch((error) => {
    if (requestId !== cluster.detailRequestId) return false;
    cluster.detailError = `Could not load event details: ${error.message}`;
    return false;
  }).finally(() => {
    if (requestId !== cluster.detailRequestId) return;
    cluster.detailLoading = false;
    refreshOpenClusterHover(key, cluster, lane);
  });
}

function sourceRecordHoverHtml(mark) {
  const record = mark.record || {};
  const descriptor = sourceTypeDescriptor(mark.sourceType || record.source_type);
  const matchedEventUids = mark.matchedEventUids?.length
    ? mark.matchedEventUids
    : sourceRecordMatchedEventUids(record);
  const matched = matchedEventUids.length > 0;
  return `<div class="hover-heading"><div><span>${matched ? "MATCHED SOURCE RECORD" : "UNMATCHED SOURCE RECORD"}</span><strong>${escapeHtml(mark.recordName)}</strong></div><button class="hover-close" type="button" aria-label="Close">x</button></div>
    <dl class="hover-facts">
      <dt>When</dt><dd>${escapeHtml(formatOffset(mark.timeNs))}<small>${mark.timeNs} ns</small></dd>
      <dt>Source</dt><dd>${escapeHtml(descriptor.label)}<small>${escapeHtml(mark.sourceName)}</small></dd>
      <dt>Layer</dt><dd>${escapeHtml(humanLayer(record.layer || "unknown"))}</dd>
      <dt>Normalization</dt><dd class="${matched ? "success-text" : "failure-text"}">${matched ? "matched" : "unmatched"}</dd>
      <dt>Linked events</dt><dd>${escapeHtml(matchedEventUids.length ? matchedEventUids.join(", ") : "none")}</dd>
      <dt>Message</dt><dd>${escapeHtml(mark.message || "No decoded message")}</dd>
    </dl>`;
}

function sourceClusterHoverHtml(cluster) {
  return `<div class="hover-heading"><div><span>COLLAPSED SOURCE RECORDS</span><strong>${cluster.count} records</strong></div><button class="hover-close" type="button" aria-label="Close">x</button></div>
    <div class="cluster-window">${cluster.items.map((mark) => {
    const selected = inSelectedRange(mark.timeNs);
    return `<button type="button" class="cluster-event${mark.matchedEventUid ? "" : " failed"}${selected ? " in-range" : ""}" data-cluster-source-record-uid="${escapeHtml(mark.sourceRecordUid)}"><span>${escapeHtml(formatOffset(mark.timeNs))}</span><strong>${escapeHtml(mark.recordName)}</strong><small>${escapeHtml(mark.sourceType + " / " + (mark.matchedEventUid ? "matched" : "unmatched") + (selected ? " / in selected range" : ""))}</small></button>`;
  }).join("")}</div>`;
}

function intervalHoverHtml(interval, lane) {
  return `<div class="hover-heading"><div><span>${interval.kind === "lifecycle" ? "RESOURCE LIFECYCLE" : "RESOURCE STATUS"}</span><strong>${escapeHtml(interval.status)}</strong></div><button class="hover-close" type="button" aria-label="Close">x</button></div>
    <dl class="hover-facts"><dt>Resource</dt><dd>${escapeHtml(lane.label)}<small>${escapeHtml(humanResourceType(lane.kind))}</small></dd><dt>Start</dt><dd>${escapeHtml(formatOffset(interval.startNs))}</dd><dt>End</dt><dd>${interval.openEnd ? "open" : escapeHtml(formatOffset(interval.endNs))}</dd><dt>Duration</dt><dd>${escapeHtml(formatDuration(interval.durationNs))}</dd><dt>State</dt><dd>${escapeHtml(formatValue(interval.properties))}</dd></dl>`;
}

function densityHoverHtml(bin) {
  const types = [...bin.topTypes.entries()].sort((a, b) => b[1] - a[1]).slice(0, 4);
  const inclusiveDurationNs = bin.endNs - bin.startNs + 1n;
  const precision = offsetPrecisionForSpan(inclusiveDurationNs);
  return `<div class="hover-heading"><div><span>EVENT DENSITY</span><strong>${bin.count} events${bin.failures ? ` / ${bin.failures} failed` : ""}</strong></div><button class="hover-close" type="button" aria-label="Close">x</button></div>
    <dl class="hover-facts">
      <dt>Start</dt><dd>${escapeHtml(formatOffset(bin.startNs, precision))}</dd>
      <dt>End</dt><dd>${escapeHtml(formatOffset(bin.endNs, precision))}</dd>
      <dt>Window</dt><dd>${escapeHtml(formatDuration(inclusiveDurationNs))}</dd>
      <dt>Events</dt><dd>${bin.count}</dd>
      <dt>Failures</dt><dd class="${bin.failures ? "failure-text" : "success-text"}">${bin.failures}</dd>
      <dt>Top types</dt><dd>${types.length ? types.map(([type, count]) => `${escapeHtml(titleCase(type))} (${count})`).join("<br>") : "none"}</dd>
    </dl>`;
}

function relationshipHoverHtml(edge, otherId, relativeToId = state.selectedResourceId) {
  const other = state.resourceById.get(otherId) || {};
  const presentation = relationshipPresentation(edge.type);
  const direction = presentation.directed === true
    ? (edge.source === relativeToId ? "OUTGOING" : "INCOMING")
    : "ENDPOINT";
  return `<div class="hover-heading"><div><span>${direction} CORRELATION</span><strong>${escapeHtml(presentation.displayLabel)}</strong></div><button class="hover-close" type="button" aria-label="Close">x</button></div>
    <dl class="hover-facts">
      <dt>Resource</dt><dd>${escapeHtml(resourceLabel(other, otherId))}<small>${escapeHtml(humanResourceType(resourceKind(other, otherId)))}</small></dd>
      <dt>Start</dt><dd>${edge.openStart ? "open" : escapeHtml(formatOffset(edge.startNs))}</dd>
      <dt>End</dt><dd>${edge.openEnd ? "open" : escapeHtml(formatOffset(edge.endNs))}</dd>
      <dt>Duration</dt><dd>${escapeHtml(formatDuration(edge.endNs - edge.startNs))}</dd>
      <dt>${presentation.directed === true ? "Direction" : "Endpoints"}</dt><dd>${escapeHtml(`${edge.source} ${presentation.directed === true ? "→" : "—"} ${edge.target}`)}</dd>
      ${presentation.known ? "" : `<dt>Raw type</dt><dd>${escapeHtml(presentation.rawType || "not supplied")}</dd>`}
      <dt>Quality</dt><dd>${escapeHtml(edge.quality)}</dd>
    </dl>`;
}

function bindHoverCardActions(card, model, key) {
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
  card.querySelectorAll("[data-annotation-entry-id]").forEach((button) => {
    button.addEventListener("click", () => {
      const projection = state.timelineEntryProjections.get(
        button.dataset.annotationEntryId,
      );
      if (!projection) return;
      if (projection.streamKind === "source") {
        selectSourceRecord(projection.uid, true);
      } else {
        selectEvent(projection.uid, true);
      }
    });
  });
  if (model.type === "cluster") {
    card.querySelector("[data-cluster-detail-offset]")?.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      requestClusterDetail(key, model.cluster, model.lane, event.currentTarget.dataset.clusterDetailOffset);
    });
  }
}

function showHover(key, anchor, pin) {
  if (!pin && state.hoverPinned) return;
  const model = state.hoverModels.get(key) || state.eventLogHoverModels.get(key);
  if (!model) return;
  window.clearTimeout(state.hoverOpenTimer);
  window.clearTimeout(state.hoverCloseTimer);
  state.hoverKey = key;
  if (pin) state.hoverPinned = true;
  const card = byId("timeline-hover");
  card.classList.toggle("pinned", state.hoverPinned);
  card.innerHTML = model.type === "event"
    ? eventHoverHtml(model.mark, model.lane, model.occurrenceLanes)
    : model.type === "cluster"
      ? clusterHoverHtml(model.cluster, model.lane)
      : model.type === "source-record"
        ? sourceRecordHoverHtml(model.mark)
      : model.type === "source-cluster"
          ? sourceClusterHoverHtml(model.cluster)
        : model.type === "annotation-cluster"
          ? annotationClusterHoverHtml(model.items)
      : model.type === "relationship"
        ? relationshipHoverHtml(model.edge, model.otherId, model.relativeToId)
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
  bindHoverCardActions(card, model, key);
  if (model.type === "cluster"
      && clusterDetailRequestAvailable(model.cluster)
      && !model.cluster.detailHydrated
      && !model.cluster.detailLoading
      && !model.cluster.detailError) {
    requestClusterDetail(key, model.cluster, model.lane, 0);
  }
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
  return {
    exists: Boolean(life),
    status: status?.status || (life ? "exists" : "absent"),
    statusClass: status?.statusClass || (life ? "unknown" : "absent"),
    properties: status?.properties || {},
  };
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
    status_segments: state.lanes.flatMap((lane) => lane.statuses).filter((item) => item.startNs < end && item.endNs > start).length,
    endpoint_diff: endpointDiff,
    relationship_changes: relationshipChanges,
  };
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
    return true;
  } catch (rangeError) {
    error.textContent = rangeError.message;
    return false;
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
  const facts = rangeSummaryFacts(summary, {
    fallbackFailureCount: Array.isArray(summary.events)
      ? summary.events.filter(eventFailed).length
      : 0,
  });
  const truncatedKinds = facts.truncatedKinds.map(titleCase);
  const endpointScope = `${facts.evaluatedEndpointCount.toLocaleString()} of ${facts.affectedResourceCount.toLocaleString()} endpoint states evaluated`;
  byId("range-facts").innerHTML = `<span>${facts.eventCount.toLocaleString()} events</span><span class="failure-fact">${facts.failureCount.toLocaleString()} failed</span><span>${facts.affectedResourceCount.toLocaleString()} resources</span><span>${facts.relationshipChangeCount.toLocaleString()} relationship changes</span><span class="${facts.truncation.endpoint_diff ? "bounded-fact" : ""}">${escapeHtml(endpointScope)}${facts.truncation.endpoint_diff ? " / bounded" : ""}</span>${truncatedKinds.length ? `<span class="bounded-fact" title="${escapeHtml(`Bounded detail arrays: ${truncatedKinds.join(", ")}`)}">${truncatedKinds.length} detail sets truncated</span>` : ""}`;
  const diff = endpointDiffItems(summary);
  const relationshipChanges = Array.isArray(summary.relationship_changes) ? summary.relationship_changes : [];
  const endpointScopeNote = facts.truncation.endpoint_diff
    ? `<p class="range-scope-note">Endpoint comparison is bounded: ${escapeHtml(endpointScope)}${facts.omittedEndpointCount ? `; ${facts.omittedEndpointCount.toLocaleString()} affected resources were not evaluated` : ""}.</p>`
    : "";
  const diffHtml = diff.length
    ? `<strong>Endpoint diff</strong><div>${diff.slice(0, 8).map((item) => {
      const resourceId = canonicalResourceId(item.resource_id) || canonicalResourceId(item.id);
      const label = item.label ?? resourceId ?? "unidentified resource";
      const content = `<span>${escapeHtml(formatValue(label))}</span><code>${escapeHtml(conciseEndpointState(item.before ?? item.start_status))} -> ${escapeHtml(conciseEndpointState(item.after ?? item.end_status ?? item.change ?? "changed"))}</code>`;
      return resourceId ? `<button type="button" data-resource-id="${escapeHtml(resourceId)}">${content}</button>` : `<span>${content}</span>`;
    }).join("")}</div>${endpointScopeNote}`
    : facts.truncation.endpoint_diff
      ? `<span>No endpoint state difference was found in the evaluated subset.</span>${endpointScopeNote}`
      : "<span>No endpoint state difference.</span>";
  const relationshipHtml = relationshipChanges.length
    ? `<strong>Relationship changes</strong><div class="range-relationship-changes">${relationshipChanges.slice(0, 10).map((item) => {
      const source = canonicalResourceId(item.source) || canonicalResourceId(item.source_resource_id);
      const target = canonicalResourceId(item.target) || canonicalResourceId(item.target_resource_id);
      const operation = item.operation || item.effect_type || item.action || "changed";
      const relationType = typeof (item.relation_type ?? item.type) === "string" ? (item.relation_type ?? item.type) : null;
      const content = `<span>${escapeHtml(`${titleCase(operation)} ${relationshipDisplayLabel(relationType)}`)}</span><code>${escapeHtml(`${source || "unknown endpoint"} — ${target || "unknown endpoint"}`)}</code>`;
      return source ? `<button type="button" data-resource-id="${escapeHtml(source)}">${content}</button>` : `<span>${content}</span>`;
    }).join("")}</div>`
    : "";
  byId("range-diff").innerHTML = diffHtml + relationshipHtml;
  byId("range-diff").querySelectorAll("[data-resource-id]").forEach((button) => button.addEventListener("click", () => selectResource(button.dataset.resourceId)));
}

async function requestRangeSummary() {
  const bounds = rangeBounds();
  if (!bounds) return;
  const requestId = ++state.rangeRequestId;
  abortLatestRequests("rangeAbortController");
  state.rangeSummary = null;
  renderRangeSummary();
  if (isTopologyNodeSnapshot()) {
    // Member workspaces carry only their local plug-in projection. Never leak
    // into an unscoped revision for a range summary.
    state.rangeSummary = localRangeSummary();
    renderRangeSummary();
    return requestId === state.rangeRequestId;
  }
  const controller = beginLatestRequest("rangeAbortController");
  try {
    const summary = await analysisRuntimeApi(revisionPath("range/summary"), {
      method: "POST",
      signal: controller.signal,
      body: JSON.stringify({ start_ns: bounds[0].toString(), end_ns: bounds[1].toString() }),
    });
    if (requestId !== state.rangeRequestId) return;
    state.rangeSummary = summary;
  } catch (error) {
    if (requestWasAborted(error, controller)) return;
    if (requestId !== state.rangeRequestId || !rangeBounds()) return;
    state.rangeSummary = localRangeSummary();
  }
  finishLatestRequest("rangeAbortController", controller);
  renderRangeSummary();
}

function clearRangeSelection({ refreshEventLog = true } = {}) {
  const hadRange = Boolean(rangeBounds());
  state.rangeStartNs = null;
  state.rangeEndNs = null;
  state.rangeSummary = null;
  state.rangeRequestId += 1;
  abortLatestRequests("rangeAbortController");
  byId("clear-range").hidden = true;
  byId("range-error").textContent = "";
  updateRangeBands(null, refreshEventLog);
  renderRangeSummary();
  updateTimelineCommandAvailability();
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
  requestDashboards();
  if (announce && hadSelection) showToast("Timeline selection cleared.");
  return hadSelection || hadHover;
}

function handleEscapeKey(event) {
  if (event.defaultPrevented || event.key !== "Escape" || event.repeat || event.isComposing) return;
  closeCorrelationHover();
  if (closeTimelineContextMenu({ restoreFocus: true })) {
    event.preventDefault();
    return;
  }
  const correlationDialog = byId("correlation-dialog");
  if (correlationDialog?.open) {
    event.preventDefault();
    closeManualCorrelationDialog();
    return;
  }
  if (state.eventLogDrag) {
    event.preventDefault();
    finishEventLogDrag(null, true);
    return;
  }
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
  if (
    eventLogSelectionCount()
    && (
      document.activeElement?.closest?.("#event-log")
      || document.activeElement?.closest?.("#event-selection-toolbar")
    )
  ) {
    event.preventDefault();
    clearEventLogSelection({ announce: true });
    return;
  }
  if (clearPinnedGraphInspection()) {
    event.preventDefault();
    return;
  }
  if (byId("timeline-content")?.contains(document.activeElement)) {
    byId("timeline-scroll")?.focus({ preventScroll: true });
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
  const requestId = ++state.timelineRequestId;
  abortLatestRequests("timelineAbortController");
  if (isTopologyNodeSnapshot()) {
    state.timelinePayload = null;
    normalizeTimeline(null);
    return requestId === state.timelineRequestId;
  }
  const controller = beginLatestRequest("timelineAbortController");
  const [windowStartNs, windowEndNs] = timelineWindowBounds();
  const selectedRange = rangeBounds();
  const scaleResourceIds = scaleTimelineResourceIds();
  const selectedRelationshipRoot = canonicalResourceId(state.selectedResourceId);
  const relationshipHistoryRoots = isScaleMode()
    && selectedRelationshipRoot
    && !resourceHiddenFromTimeline(selectedRelationshipRoot)
    ? [selectedRelationshipRoot]
    : undefined;
  try {
    const payload = await analysisRuntimeApi(revisionPath("timeline/query"), {
      method: "POST",
      signal: controller.signal,
      body: JSON.stringify({
        start_ns: windowStartNs.toString(),
        end_ns: windowEndNs.toString(),
        viewport_pixels: timelinePhysicalTrackWidth(),
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
        relationship_history_roots: relationshipHistoryRoots,
        selected_event_uid: state.selectedEventUid || undefined,
        allow_empty: isScaleMode() && state.laneMode === "custom" && scaleResourceIds.length === 0,
      }),
    });
    if (requestId !== state.timelineRequestId) return false;
    state.timelinePayload = payload;
  } catch (error) {
    if (requestWasAborted(error, controller)) return false;
    if (requestId !== state.timelineRequestId) return false;
    showToast("Timeline query rejected: " + error.message);
    if (!state.timelinePayload) state.timelinePayload = { lanes: [], record_lanes: [] };
  }
  finishLatestRequest("timelineAbortController", controller);
  normalizeTimeline(state.timelinePayload);
  return true;
}

function invalidatePendingTimelineWindowRequest() {
  // A response is valid only for the exact logical window that requested it.
  // Invalidate immediately on every mutation rather than waiting for the
  // debounced replacement request, which could let an older response commit.
  state.timelineRequestId += 1;
  abortLatestRequests("timelineAbortController");
}

function scheduleTimelineWindowRefresh(delayMs = 140) {
  if (!state.dataset || isTopologyNodeSnapshot()) return;
  window.clearTimeout(state.timelineWindowRequestTimer);
  state.timelineWindowRequestTimer = window.setTimeout(async () => {
    state.timelineWindowRequestTimer = null;
    if (isScaleMode()) {
      await refreshScaleTimeline();
      return;
    }
    if (await requestTimeline()) renderTimeline();
  }, delayMs);
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
      status_class: temporal.statusClass || "unknown",
      state: temporal.properties,
    };
  });
}

function resourceTableViewDescriptors() {
  const descriptors = state.dataset?.schema?.resource_table_views
    || state.dataset?.resource_table_view_descriptors
    || [];
  return Array.isArray(descriptors)
    ? descriptors.filter((item) => item && item.view_id)
    : [];
}

function initializeResourceTableView() {
  if (state.resourceTableSelectionReady) return;
  const descriptors = resourceTableViewDescriptors();
  const selected = descriptors.find((item) => item.default_selected) || null;
  state.selectedResourceViewId = selected ? String(selected.view_id) : null;
  state.resourceTableSelectionReady = true;
}

function resourceDisplayTimeNs(payload = state.resourceQuery) {
  if (payload?.time_ns !== null && payload?.time_ns !== undefined) {
    return toNs(payload.time_ns, state.resourceReturnedTimeNs ?? state.cursorNs);
  }
  return state.resourceReturnedTimeNs ?? state.cursorNs;
}

function resourceTimeSummary() {
  const shown = resourceDisplayTimeNs();
  const requested = state.resourceRequestedTimeNs ?? state.cursorNs;
  if (state.resourcePending) {
    return state.resourceQuery
      ? `showing ${formatOffset(shown)} \u00b7 updating to ${formatOffset(requested)}`
      : `loading ${formatOffset(requested)}`;
  }
  return shown === state.cursorNs
    ? `at ${formatOffset(shown)}`
    : `showing ${formatOffset(shown)} \u00b7 selected moment ${formatOffset(state.cursorNs)}`;
}

function markResourcesPending(timestampNs = state.cursorNs) {
  state.resourceRequestedTimeNs = clampNs(timestampNs);
  state.resourcePending = true;
  refreshResourceTimePresentation();
}

function settleResourceRequest(payload, requestedTimeNs) {
  state.resourceReturnedTimeNs = toNs(payload?.time_ns, requestedTimeNs);
  state.resourcePending = false;
  refreshResourceTimePresentation();
}

function refreshResourceTimePresentation() {
  const wrap = byId("resource-table-wrap");
  if (wrap) {
    wrap.setAttribute("aria-busy", String(state.resourcePending));
    wrap.classList.toggle("is-time-pending", state.resourcePending);
  }
  const time = byId("resource-table-summary")?.querySelector("[data-resource-time-summary]");
  if (!time) return;
  time.textContent = resourceTimeSummary();
  time.classList.toggle("pending", state.resourcePending);
}

async function requestResources() {
  const requestId = ++state.resourceRequestId;
  const viewId = state.selectedResourceViewId;
  const requestedTimeNs = state.cursorNs;
  abortLatestRequests("resourceAbortController");
  markResourcesPending(requestedTimeNs);
  if (isTopologyNodeSnapshot()) {
    state.resourceQuery = {
      time_ns: requestedTimeNs.toString(),
      view_id: null,
      view: null,
      bundles: [],
      items: fallbackResourceItems(),
      tables: [],
      snapshot_only: true,
    };
    settleResourceRequest(state.resourceQuery, requestedTimeNs);
    renderResourceTables();
    return;
  }
  const controller = beginLatestRequest("resourceAbortController");
  try {
    const payload = await analysisRuntimeApi(revisionPath("resources/query"), {
      method: "POST",
      signal: controller.signal,
      body: JSON.stringify({
        time_ns: requestedTimeNs.toString(),
        view_id: viewId || undefined,
        kinds: !viewId && state.selectedResourceKind ? [state.selectedResourceKind] : [],
        search: isScaleMode() || viewId ? (byId("resource-search")?.value || "").trim() : null,
        limit: MAX_RESOURCE_ROWS,
        offset: state.resourceOffset,
      }),
    });
    if (requestId !== state.resourceRequestId) return;
    state.resourceQuery = payload;
    for (const item of payload.items || []) registerResource(item, item.resource_id);
  } catch (error) {
    if (requestWasAborted(error, controller)) return;
    if (requestId !== state.resourceRequestId) return;
    state.resourceQuery = {
      time_ns: requestedTimeNs.toString(),
      view_id: viewId,
      view: resourceTableViewDescriptors().find((item) => item.view_id === viewId) || null,
      bundles: [],
      items: fallbackResourceItems(),
      tables: [],
      query_error: error.message,
    };
  }
  finishLatestRequest("resourceAbortController", controller);
  settleResourceRequest(state.resourceQuery, requestedTimeNs);
  renderResourceTables();
}

function resourceTableFieldLabel(field, source = "auto") {
  const fieldLabel = String(field || "value")
    .split(".")
    .map((part) => titleCase(part))
    .join(" / ");
  if (source === "key") return `Key \u00b7 ${fieldLabel}`;
  if (source === "state") return `State \u00b7 ${fieldLabel}`;
  return fieldLabel;
}

function normalizeResourceTableColumn(column, source = "auto") {
  const descriptor = typeof column === "string" ? { field: column } : { ...(column || {}) };
  const field = descriptor.field || descriptor.key;
  if (!field) return null;
  return {
    ...descriptor,
    field: String(field),
    key: String(descriptor.key || field),
    source,
    label: descriptor.label || resourceTableFieldLabel(field, source),
  };
}

function resourceTableFieldValue(item, column) {
  const field = column.field || column.key;
  const temporalState = item.state || item.properties || {};
  const resourceRecord = item.resource && typeof item.resource === "object"
    ? item.resource
    : {};
  const resourceKey = resourceRecord.key || item.key || {};
  if (column.source === "key") return dashboardFieldValue(resourceKey, field);
  if (column.source === "state") return dashboardFieldValue(temporalState, field);

  const direct = dashboardFieldValue(item, field);
  if (direct !== undefined) return direct;
  const stateValue = dashboardFieldValue(temporalState, field);
  if (stateValue !== undefined) return stateValue;
  return dashboardFieldValue(resourceKey, field);
}

function formatResourceTableCell(item, column) {
  const value = resourceTableFieldValue(item, column);
  if (value === null || value === undefined || value === "") {
    return '<span class="dashboard-empty-value">\u2014</span>';
  }
  return `<code>${escapeHtml(formatValue(value))}</code>`;
}

function presentationColumns(kind, items) {
  const tables = state.resourceQuery?.tables || [];
  const table = Array.isArray(tables)
    ? tables.find((item) => (item.kind || item.resource_kind || item.type) === kind)
    : tables[kind];
  if (Array.isArray(table?.columns) && table.columns.length) {
    return table.columns
      .map((column) => normalizeResourceTableColumn(column))
      .filter(Boolean);
  }
  const descriptor = table?.descriptor || {};
  const keyFields = Array.isArray(descriptor.key_fields) ? descriptor.key_fields : [];
  const stateFields = Array.isArray(descriptor.default_table_fields)
    ? descriptor.default_table_fields
    : [];
  if (keyFields.length || stateFields.length) {
    return [
      ...keyFields.map((field) => normalizeResourceTableColumn(field, "key")),
      ...stateFields.map((field) => normalizeResourceTableColumn(field, "state")),
    ].filter(Boolean);
  }
  const counts = new Map();
  items.forEach((item) => Object.keys(item.state || item.properties || {}).forEach((key) => counts.set(key, (counts.get(key) || 0) + 1)));
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 4)
    .map(([key]) => normalizeResourceTableColumn(key, "state"));
}

function resourceBundleRows(bundles, descriptor) {
  const rows = [];
  const defaultDepth = Math.max(0, Number(descriptor.default_expanded_depth || 0));
  const walk = (node, parentPath, siblingIndex, siblingCount, continuationDepths) => {
    const item = node.resource || {};
    const resourceId = canonicalResourceId(item.resource_id) || resourceIdOf(item);
    const relationId = node.relationship?.relationship_id
      || `${node.relationship?.type || "root"}:${resourceId}`;
    const path = parentPath
      ? `${parentPath}>${relationId}:${siblingIndex}`
      : `${descriptor.view_id}:root:${resourceId}`;
    const children = Array.isArray(node.children) ? node.children : [];
    const hasChildren = Number(node.child_count || children.length) > 0;
    const expanded = state.resourceBundleExpansion.has(path)
      ? state.resourceBundleExpansion.get(path)
      : Number(node.depth || 0) < defaultDepth;
    const depth = Number(node.depth || 0);
    const hasNextSibling = Boolean(parentPath) && siblingIndex < siblingCount - 1;
    const hasVisibleChildren = expanded && children.length > 0;
    rows.push({
      node,
      item,
      resourceId,
      path,
      depth,
      hasChildren,
      hasVisibleChildren,
      hasNextSibling,
      continuationDepths,
      expanded,
    });
    if (hasVisibleChildren) {
      const childContinuationDepths = hasNextSibling && depth > 0
        ? [...continuationDepths, depth]
        : continuationDepths;
      children.forEach((child, index) => (
        walk(child, path, index, children.length, childContinuationDepths)
      ));
    }
  };
  (bundles || []).forEach((bundle, index) => walk(bundle, "", index, 1, []));
  return rows;
}

function resourceBundleGuide(depth, role) {
  const guideDepth = Math.max(0, Math.floor(Number(depth) || 0));
  return `<span class="resource-bundle-guide resource-bundle-guide-${role}" style="--bundle-guide-depth:${guideDepth}"></span>`;
}

function resourceBundleRowGuides(row) {
  const guides = row.continuationDepths
    .map((depth) => resourceBundleGuide(depth, "through"));
  if (row.depth > 0) {
    guides.push(resourceBundleGuide(
      row.depth,
      row.hasNextSibling ? "incoming continues" : "incoming",
    ));
  }
  if (row.hasVisibleChildren) {
    guides.push(resourceBundleGuide(row.depth + 1, "child"));
  }
  return guides.length
    ? `<span class="resource-bundle-guides" aria-hidden="true">${guides.join("")}</span>`
    : "";
}

function resourceBundleDetailGuides(row) {
  const depths = new Set(row.continuationDepths);
  if (row.hasNextSibling && row.depth > 0) depths.add(row.depth);
  if (row.hasVisibleChildren) depths.add(row.depth + 1);
  const guides = [...depths]
    .sort((left, right) => left - right)
    .map((depth) => resourceBundleGuide(depth, "through"));
  return guides.length
    ? `<span class="resource-bundle-guides" aria-hidden="true">${guides.join("")}</span>`
    : "";
}

function resourceBundleInterval(node, item) {
  const relationship = node.relationship || {};
  const start = relationship.valid_from_ns ?? item.valid_from_ns;
  const end = relationship.valid_to_ns ?? item.valid_to_ns;
  const startText = start === null || start === undefined
    ? "capture start"
    : formatOffset(toNs(start));
  const endText = end === null || end === undefined
    ? "open"
    : formatOffset(toNs(end));
  return {
    label: `${startText} → ${endText}`,
    temporary: relationship.valid_to_ns !== null
      && relationship.valid_to_ns !== undefined,
    exact: `${start ?? "unbounded"} .. ${end ?? "unbounded"}`,
  };
}

function resourceBundleColumnApplies(column, node, item) {
  const resourceId = canonicalResourceId(item.resource_id) || resourceIdOf(item);
  const kind = String(item.kind || resourceKind(item, resourceId));
  const depth = Number(node.depth || 0);
  const relationType = typeof node.relationship?.type === "string" ? node.relationship.type : "";
  const rawKinds = column.resource_kinds || column.kinds;
  const allowedKinds = Array.isArray(rawKinds) ? rawKinds : [];
  const allowedDepths = Array.isArray(column.depths) ? column.depths : [];
  const allowedRelations = Array.isArray(column.relation_types) ? column.relation_types : [];
  return (!allowedKinds.length || allowedKinds.map(String).includes(kind))
    && (!allowedDepths.length || allowedDepths.map(Number).includes(depth))
    && (!allowedRelations.length || allowedRelations.map(String).includes(relationType));
}

function resourceBundleDetailColumns(descriptor, node, item) {
  const resourceId = canonicalResourceId(item.resource_id) || resourceIdOf(item);
  const kind = item.kind || resourceKind(item, resourceId);
  const kindDescriptor = resourceKindDescriptor(kind) || {};
  const viewColumns = Array.isArray(descriptor.columns)
    ? descriptor.columns.map((column) => normalizeResourceTableColumn(column)).filter(Boolean)
    : [];
  const kindColumns = [
    ...(Array.isArray(kindDescriptor.key_fields) ? kindDescriptor.key_fields : [])
      .map((field) => normalizeResourceTableColumn(field, "key")),
    ...(Array.isArray(kindDescriptor.default_table_fields) ? kindDescriptor.default_table_fields : [])
      .map((field) => normalizeResourceTableColumn(field, "state")),
  ].filter(Boolean);
  const seen = new Set();
  return [...viewColumns, ...kindColumns].filter((column) => {
    if (!resourceBundleColumnApplies(column, node, item)) return false;
    const field = column.source === "key"
      ? `key.${column.field}`
      : column.source === "state" ? `state.${column.field}` : column.field;
    if (seen.has(field)) return false;
    seen.add(field);
    const value = resourceTableFieldValue(item, column);
    return value !== null && value !== undefined && value !== "";
  }).slice(0, 12);
}

function resourceBundleDetailFacts(descriptor, node, item) {
  const resourceId = canonicalResourceId(item.resource_id) || resourceIdOf(item);
  const kind = item.kind || resourceKind(item, resourceId);
  const relationship = node.relationship || null;
  const relationPresentation = relationshipPresentation(relationship?.type);
  const interval = resourceBundleInterval(node, item);
  const facts = [
    ["Resource ID", resourceId],
    ["Type", humanResourceType(kind)],
    ["Layer", humanLayer(item.layer || resourceLayer(item, resourceId))],
    ["Status", item.status || "unknown"],
    ["View role", relationship ? (node.relation_label || relationPresentation.displayLabel) : `${descriptor.label} root`],
    ["Active interval", interval.label],
  ];
  if (relationship) {
    facts.push(
      ["Relationship", relationPresentation.displayLabel],
      [relationPresentation.directed === true ? "Direction" : "Endpoints", `${relationship.source || "unknown"} ${relationPresentation.directed === true ? "→" : "—"} ${relationship.target || "unknown"}`],
      ["Relationship quality", relationship.quality || "unknown"],
    );
  }
  for (const column of resourceBundleDetailColumns(descriptor, node, item)) {
    facts.push([column.label, resourceTableFieldValue(item, column)]);
  }
  return facts;
}

function resourceBundleHoverHtml(descriptor, node, item) {
  const resourceId = canonicalResourceId(item.resource_id) || resourceIdOf(item);
  const kind = item.kind || resourceKind(item, resourceId);
  const role = node.relationship
    ? (node.relation_label || relationshipDisplayLabel(node.relationship.type))
    : `${descriptor.label} root`;
  return `<div class="hover-heading"><div><span>${escapeHtml(descriptor.label)} · ${escapeHtml(role)}</span><strong>${escapeHtml(item.label || resourceLabel(item, resourceId))}</strong></div></div>
    <dl class="hover-facts resource-bundle-hover-facts">
      ${resourceBundleDetailFacts(descriptor, node, item).map(([label, value]) => `<dt>${escapeHtml(label)}</dt><dd>${escapeHtml(formatValue(value))}</dd>`).join("")}
    </dl>
    <div class="resource-bundle-hover-note">Fields and relationship roles are declared by the active plug-in for ${escapeHtml(humanResourceType(kind))}.</div>`;
}

function resourceBundleDetailMarkup(descriptor, node, item) {
  const relationship = node.relationship || null;
  return `<div class="resource-bundle-detail-panel">
    <div class="resource-bundle-detail-heading">
      <strong>${escapeHtml(relationship ? (node.relation_label || relationshipDisplayLabel(relationship.type)) : `${descriptor.label} root`)}</strong>
      <span>${escapeHtml(relationship ? relationshipDisplayLabel(relationship.type) : descriptor.view_id)}</span>
    </div>
    <dl class="resource-bundle-detail-facts">
      ${resourceBundleDetailFacts(descriptor, node, item).map(([label, value]) => `<div><dt>${escapeHtml(label)}</dt><dd>${escapeHtml(formatValue(value))}</dd></div>`).join("")}
    </dl>
  </div>`;
}

function resourcePageDetails(payload = state.resourceQuery || {}) {
  const offset = Math.max(0, Number(payload.offset || 0));
  const returned = Math.max(0, Number(payload.returned_count ?? payload.bundles?.length ?? payload.items?.length ?? 0));
  const total = Math.max(returned, Number(payload.matched_count ?? payload.count ?? returned));
  const pageSize = Math.max(1, Number(payload.limit || returned || MAX_RESOURCE_ROWS));
  const nextOffset = payload.next_offset === null || payload.next_offset === undefined
    ? null
    : Math.max(0, Number(payload.next_offset));
  return {
    offset,
    returned,
    total,
    first: returned ? offset + 1 : 0,
    last: Math.min(total, offset + returned),
    previousOffset: offset > 0 ? Math.max(0, offset - pageSize) : null,
    nextOffset,
  };
}

function resourcePaginationMarkup(payload = state.resourceQuery || {}) {
  const page = resourcePageDetails(payload);
  if (page.previousOffset === null && page.nextOffset === null) return "";
  return `<nav class="resource-table-pagination" aria-label="Resource table pages">
    <span>Showing ${page.first.toLocaleString()}–${page.last.toLocaleString()} of ${page.total.toLocaleString()}</span>
    <div>
      <button type="button" data-resource-page-offset="${page.previousOffset ?? ""}" ${page.previousOffset === null ? "disabled" : ""}>Previous</button>
      <button type="button" data-resource-page-offset="${page.nextOffset ?? ""}" ${page.nextOffset === null ? "disabled" : ""}>Next</button>
    </div>
  </nav>`;
}

function bindResourcePagination(container) {
  container.querySelectorAll("[data-resource-page-offset]").forEach((button) => {
    button.addEventListener("click", () => {
      if (button.disabled || button.dataset.resourcePageOffset === "") return;
      state.resourceOffset = Math.max(0, Number(button.dataset.resourcePageOffset));
      container.scrollLeft = 0;
      container.scrollTop = 0;
      requestResources();
      byId("resource-table-summary")?.scrollIntoView({ block: "nearest" });
    });
  });
}

function laneVisibilityCheckbox(resourceId, label) {
  const visible = laneSelectedByMode(resourceId);
  const accessibleLabel = `Show ${label || resourceId} in Resource timeline`;
  return `<input class="lane-visibility-toggle" type="checkbox" data-lane-toggle="${escapeHtml(resourceId)}"${visible ? " checked" : ""} aria-label="${escapeHtml(accessibleLabel)}" title="${escapeHtml(accessibleLabel)}">`;
}

function bindLaneVisibilityCheckboxes(container, { closeHover = false } = {}) {
  container.querySelectorAll('input[type="checkbox"][data-lane-toggle]').forEach((checkbox) => checkbox.addEventListener("click", (event) => {
    event.stopPropagation();
    if (closeHover) closeCorrelationHover();
    const resourceId = checkbox.dataset.laneToggle;
    if (!setExplicitLaneVisibility(resourceId, checkbox.checked)) {
      checkbox.checked = laneSelectedByMode(resourceId);
    }
  }));
}

function renderResourceBundleTable(container, descriptor) {
  const payload = state.resourceQuery || {};
  const bundles = payload.view_id === descriptor.view_id ? (payload.bundles || []) : [];
  const rows = resourceBundleRows(bundles, descriptor);
  const columns = Array.isArray(descriptor.columns) ? descriptor.columns : [];
  const rootCount = Number(payload.matched_count ?? payload.count ?? 0);
  const returnedRoots = Number(payload.returned_count ?? bundles.length);
  const visibleNodeCount = rows.length;
  const queryError = payload.query_error ? ` · query failed: ${payload.query_error}` : "";
  const page = resourcePageDetails(payload);
  const pageCopy = page.returned ? `${page.first.toLocaleString()}–${page.last.toLocaleString()}` : "0";
  byId("resource-table-summary").innerHTML = `${escapeHtml(`${pageCopy} of ${rootCount.toLocaleString()} bundles shown \u00b7 ${visibleNodeCount.toLocaleString()} visible resources`)} <span data-resource-time-summary class="${state.resourcePending ? "pending" : ""}">${escapeHtml(resourceTimeSummary())}</span>${escapeHtml(` \u00b7 ${descriptor.description || "plug-in relationship view"}${queryError}`)}`;
  if (!bundles.length) {
    container.innerHTML = `<div class="empty-state">${escapeHtml(payload.query_error ? "The bundled resource query failed." : "No active resource bundles match this moment and search.")}</div>${resourcePaginationMarkup(payload)}`;
    bindResourcePagination(container);
    return;
  }
  const body = rows.map((row) => {
    const {
      node,
      item,
      resourceId,
      path,
      depth,
      hasChildren,
      expanded,
    } = row;
    const kind = item.kind || resourceKind(item, resourceId);
    const interval = resourceBundleInterval(node, item);
    const current = resourceId === state.selectedResourceId;
    const relationType = node.relationship?.type;
    const relationLabel = depth
      ? (node.relation_label || relationshipDisplayLabel(relationType))
      : "bundle root";
    const truncated = Number(node.truncated_child_count || 0);
    const icon = resourceIconMarkup(item.resource || item, kind, "resource-bundle-icon");
    const tags = presentationTags(item);
    const compact = tags.has("compact") || tags.has("connector");
    const detailExpanded = state.resourceBundleDetailExpansion.get(path) === true;
    return `<tr class="resource-bundle-row depth-${depth}${current ? " selected" : ""}${compact ? " resource-connector" : ""}" data-resource-id="${escapeHtml(resourceId)}" data-bundle-path="${escapeHtml(path)}" tabindex="0" style="--bundle-depth:${depth}">
      <td class="resource-bundle-tree-cell">
        ${resourceBundleRowGuides(row)}
        <div class="resource-bundle-node">
          ${hasChildren
            ? `<button class="resource-bundle-disclosure" type="button" data-bundle-toggle="${escapeHtml(path)}" aria-expanded="${expanded}" aria-label="${expanded ? "Collapse" : "Expand"} ${escapeHtml(item.label || resourceLabel(item, resourceId))}"></button>`
            : '<span class="resource-bundle-disclosure-placeholder" aria-hidden="true"></span>'}
          ${icon}
          <button class="resource-bundle-resource" type="button" data-bundle-resource="${escapeHtml(resourceId)}">
            <strong>${escapeHtml(item.label || resourceLabel(item, resourceId))}</strong>
            <small>${escapeHtml(resourceId)}</small>
          </button>
          <span class="resource-bundle-kind">${escapeHtml(humanResourceType(kind))}</span>
          <button class="resource-bundle-details-toggle" type="button" data-bundle-details="${escapeHtml(path)}" aria-expanded="${detailExpanded}">${detailExpanded ? "Hide details" : "Details"}</button>
        </div>
        <div class="resource-bundle-relation">
          <span>${escapeHtml(relationLabel)}</span>
          ${interval.temporary ? '<em>temporary</em>' : ""}
          ${truncated ? `<em>+${truncated} bounded</em>` : ""}
        </div>
      </td>
      <td><span class="resource-kind-label">${escapeHtml(humanResourceType(kind))}</span></td>
      <td><span class="${stateChipClassName(item)}">${escapeHtml(item.status || "unknown")}</span></td>
      <td><span class="resource-bundle-validity${interval.temporary ? " temporary" : ""}" title="${escapeHtml(interval.exact)}">${escapeHtml(interval.label)}</span></td>
      <td class="resource-timeline-toggle-cell">${laneVisibilityCheckbox(resourceId, item.label || resourceLabel(item, resourceId))}</td>
      ${columns.map((column) => `<td>${resourceBundleColumnApplies(column, node, item) ? formatDashboardCell(item, column) : '<span class="dashboard-empty-value">not applicable</span>'}</td>`).join("")}
    </tr>
    ${detailExpanded ? `<tr class="resource-bundle-detail-row" style="--bundle-depth:${depth}"><td class="resource-bundle-detail-cell" colspan="${5 + columns.length}">${resourceBundleDetailGuides(row)}${resourceBundleDetailMarkup(descriptor, node, item)}</td></tr>` : ""}`;
  }).join("");
  container.innerHTML = `<table class="resource-table resource-bundle-table">
    <thead><tr><th>Bundled resource</th><th>Type</th><th>Status</th><th>Active interval</th><th class="resource-timeline-toggle-heading">Timeline</th>${columns.map((column) => `<th>${escapeHtml(column.label || titleCase(column.field))}</th>`).join("")}</tr></thead>
    <tbody>${body}</tbody>
  </table>${resourcePaginationMarkup(payload)}`;
  container.querySelectorAll("[data-bundle-toggle]").forEach((button) => button.addEventListener("click", (event) => {
    event.stopPropagation();
    state.resourceBundleExpansion.set(
      button.dataset.bundleToggle,
      button.getAttribute("aria-expanded") !== "true",
    );
    closeCorrelationHover();
    renderResourceTables();
  }));
  container.querySelectorAll("[data-bundle-resource]").forEach((button) => button.addEventListener("click", (event) => {
    event.stopPropagation();
    closeCorrelationHover();
    selectResource(button.dataset.bundleResource);
  }));
  container.querySelectorAll("[data-bundle-details]").forEach((button) => button.addEventListener("click", (event) => {
    event.stopPropagation();
    state.resourceBundleDetailExpansion.set(
      button.dataset.bundleDetails,
      button.getAttribute("aria-expanded") !== "true",
    );
    closeCorrelationHover();
    renderResourceTables();
  }));
  const bundleRowsByPath = new Map(rows.map((item) => [item.path, item]));
  container.querySelectorAll("tr[data-resource-id]").forEach((row) => {
    const bundleRow = bundleRowsByPath.get(row.dataset.bundlePath);
    if (bundleRow) bindCorrelationHover(
      row,
      () => resourceBundleHoverHtml(descriptor, bundleRow.node, bundleRow.item),
    );
    row.addEventListener("click", () => {
      closeCorrelationHover();
      selectResource(row.dataset.resourceId);
    });
    row.addEventListener("keydown", (event) => {
      if (event.target !== row || (event.key !== "Enter" && event.key !== " ")) return;
      event.preventDefault();
      closeCorrelationHover();
      selectResource(row.dataset.resourceId);
    });
  });
  bindLaneVisibilityCheckboxes(container, { closeHover: true });
  bindResourcePagination(container);
}

function renderResourceTables() {
  const container = byId("resource-table-wrap");
  if (!container) return;
  initializeResourceTableView();
  const viewDescriptors = resourceTableViewDescriptors();
  const activeView = viewDescriptors.find((item) => String(item.view_id) === state.selectedResourceViewId) || null;
  const allItems = state.resourceQuery?.items || fallbackResourceItems();
  const groups = new Map();
  for (const item of allItems) {
    const id = canonicalResourceId(item.resource_id) || resourceIdOf(item);
    const kind = item.kind || resourceKind(item, id);
    if (!groups.has(kind)) groups.set(kind, []);
    groups.get(kind).push({ ...item, resource_id: id, kind });
  }
  const countsByKind = state.resourceQuery?.counts_by_kind || {};
  const kinds = (Object.keys(countsByKind).length ? Object.keys(countsByKind) : [...groups.keys()]).sort();
  const resourceSearchActive = Boolean((byId("resource-search")?.value || "").trim());
  if (!activeView && !state.selectedResourceKind) {
    state.selectedResourceKind = kinds[0] || null;
  } else if (
    !activeView
    && !resourceSearchActive
    && kinds.length
    && !kinds.includes(state.selectedResourceKind)
  ) {
    state.selectedResourceKind = kinds[0];
  }
  const viewTabs = viewDescriptors.map((descriptor) => {
    const current = descriptor.view_id === state.selectedResourceViewId;
    const count = current && state.resourceQuery?.view_id === descriptor.view_id
      ? Number(state.resourceQuery.matched_count ?? state.resourceQuery.count ?? 0)
      : (descriptor.root_kinds || []).reduce((total, kind) => total + Number(countsByKind[kind] || 0), 0);
    return `<button class="resource-view-tab" type="button" role="tab" data-resource-view="${escapeHtml(descriptor.view_id)}" aria-selected="${current}">${escapeHtml(descriptor.label)}<span>${count.toLocaleString()}</span></button>`;
  }).join("");
  const kindTabs = kinds.map((kind) => `<button type="button" role="tab" data-kind="${escapeHtml(kind)}" aria-selected="${!activeView && kind === state.selectedResourceKind}">${escapeHtml(humanResourceType(kind))}<span>${Number(countsByKind[kind] ?? groups.get(kind)?.length ?? 0).toLocaleString()}</span></button>`).join("");
  byId("resource-type-tabs").innerHTML = viewTabs + kindTabs;
  byId("resource-type-tabs").querySelectorAll("[data-resource-view]").forEach((button) => button.addEventListener("click", () => {
    state.selectedResourceViewId = button.dataset.resourceView;
    state.selectedResourceKind = null;
    state.resourceOffset = 0;
    state.resourceTableSelectionReady = true;
    requestResources();
  }));
  byId("resource-type-tabs").querySelectorAll("[data-kind]").forEach((button) => button.addEventListener("click", () => {
    state.selectedResourceViewId = null;
    state.selectedResourceKind = button.dataset.kind;
    state.resourceOffset = 0;
    state.resourceTableSelectionReady = true;
    requestResources();
  }));
  if (activeView) {
    renderResourceBundleTable(container, activeView);
    return;
  }
  const needle = (byId("resource-search")?.value || "").trim().toLowerCase();
  const kindItems = groups.get(state.selectedResourceKind) || [];
  const items = kindItems.filter((item) => !needle || JSON.stringify(item).toLowerCase().includes(needle)).slice(0, MAX_RESOURCE_ROWS);
  const columns = presentationColumns(state.selectedResourceKind, kindItems);
  const exactKindCount = Number(countsByKind[state.selectedResourceKind] ?? kindItems.length);
  const page = resourcePageDetails(state.resourceQuery);
  const pageCopy = page.returned ? `${page.first.toLocaleString()}–${page.last.toLocaleString()}` : "0";
  byId("resource-table-summary").innerHTML = `${escapeHtml(`${pageCopy} of ${exactKindCount.toLocaleString()} ${humanResourceType(state.selectedResourceKind || "resources")} shown`)} <span data-resource-time-summary class="${state.resourcePending ? "pending" : ""}">${escapeHtml(resourceTimeSummary())}</span>${state.resourceQuery?.windowed ? " \u00b7 server-windowed" : ""}`;
  if (!items.length) {
    container.innerHTML = `<div class="empty-state">No resources match this view.</div>${resourcePaginationMarkup(state.resourceQuery)}`;
    bindResourcePagination(container);
    return;
  }
  container.innerHTML = `<table class="resource-table"><thead><tr><th>Resource</th><th>Layer</th><th>Exists</th><th>Status</th><th class="resource-timeline-toggle-heading">Timeline</th>${columns.map((column) => `<th>${escapeHtml(column.label)}</th>`).join("")}</tr></thead><tbody>${items.map((item) => {
    const tags = presentationTags(item);
    const compact = tags.has("compact") || tags.has("connector");
    const current = item.resource_id === state.selectedResourceId;
    return `<tr data-resource-id="${escapeHtml(item.resource_id)}" class="${current ? "selected " : ""}${compact ? "resource-connector" : ""}" tabindex="0"><td><strong>${escapeHtml(item.label || resourceLabel(item, item.resource_id))}</strong><small>${escapeHtml(item.resource_id)}${compact ? " / connector" : ""}</small></td><td>${escapeHtml(humanLayer(item.layer))}</td><td>${resourceExistenceLabel(item.exists, { brief: true })}</td><td><span class="${stateChipClassName(item)}">${escapeHtml(item.status || "unknown")}</span></td><td class="resource-timeline-toggle-cell">${laneVisibilityCheckbox(item.resource_id, item.label || resourceLabel(item, item.resource_id))}</td>${columns.map((column) => `<td>${formatResourceTableCell(item, column)}</td>`).join("")}</tr>`;
  }).join("")}</tbody></table>${resourcePaginationMarkup(state.resourceQuery)}`;
  container.querySelectorAll("tr[data-resource-id]").forEach((row) => {
    const choose = () => selectResource(row.dataset.resourceId);
    row.addEventListener("click", choose);
    row.addEventListener("keydown", (event) => {
      if (event.key !== "Enter" && event.key !== " ") return;
      event.preventDefault();
      choose();
    });
  });
  bindLaneVisibilityCheckboxes(container);
  bindResourcePagination(container);
}

function dashboardDescriptors() {
  const descriptors = state.dataset?.schema?.dashboards
    || state.dataset?.dashboard_descriptors
    || [];
  return Array.isArray(descriptors)
    ? descriptors.filter((item) => item && item.dashboard_id)
    : [];
}

function dashboardNeedsPointInTimeQuery(descriptor) {
  if (!descriptor) return false;
  const statistics = Array.isArray(descriptor.statistics) ? descriptor.statistics : [];
  const tables = Array.isArray(descriptor.tables) ? descriptor.tables : [];
  return Boolean(
    tables.length
    || statistics.some((item) => String(item?.aggregation || "count") !== "precomputed" && !item?.scale_metric),
  );
}

function dashboardQueryIds() {
  return dashboardDescriptors()
    .filter((descriptor) => state.openDashboardIds.has(String(descriptor.dashboard_id)))
    .filter(dashboardNeedsPointInTimeQuery)
    .map((descriptor) => String(descriptor.dashboard_id));
}

function dashboardResultFor(dashboardId) {
  return (state.dashboardQuery?.dashboards || [])
    .find((item) => String(item.dashboard_id) === String(dashboardId)) || null;
}

function dashboardDisplayTimeNs() {
  return state.dashboardReturnedTimeNs ?? state.cursorNs;
}

function dashboardTimeSummary() {
  const shown = dashboardDisplayTimeNs();
  const requested = state.dashboardRequestedTimeNs ?? state.cursorNs;
  if (isTopologyNodeSnapshot()) return `member snapshot at ${formatOffset(state.cursorNs)}`;
  if (state.dashboardPending) {
    return state.dashboardQuery
      ? `showing ${formatOffset(shown)} · updating to ${formatOffset(requested)}`
      : `loading ${formatOffset(requested)}`;
  }
  return shown === state.cursorNs
    ? `authoritative population at ${formatOffset(shown)}`
    : `showing ${formatOffset(shown)} · selected moment ${formatOffset(state.cursorNs)}`;
}

function markDashboardsPending(timestampNs = state.cursorNs) {
  state.dashboardRequestedTimeNs = clampNs(timestampNs);
  state.dashboardPending = !isTopologyNodeSnapshot() && dashboardQueryIds().length > 0;
  refreshDashboardTimePresentation();
}

function settleDashboardRequest(payload, requestedTimeNs) {
  state.dashboardQuery = payload;
  state.dashboardQueryError = dashboardDescriptorErrorMessage(payload);
  state.dashboardReturnedTimeNs = toNs(payload?.time_ns, requestedTimeNs);
  state.dashboardPending = false;
  refreshDashboardTimePresentation();
}

function refreshDashboardTimePresentation() {
  const modules = byId("dashboard-modules");
  if (modules) {
    modules.setAttribute("aria-busy", String(state.dashboardPending));
    modules.classList.toggle("is-time-pending", state.dashboardPending);
  }
  const status = byId("dashboard-time-status");
  if (!status) return;
  status.textContent = dashboardTimeSummary();
  status.classList.toggle("pending", state.dashboardPending);
}

async function requestDashboards() {
  const requestId = ++state.dashboardRequestId;
  const requestedTimeNs = state.cursorNs;
  const dashboardIds = dashboardQueryIds();
  abortLatestRequests("dashboardAbortController");
  state.dashboardQueryError = null;
  markDashboardsPending(requestedTimeNs);

  // An explicitly bounded topology-member snapshot is evaluated locally. It
  // must never query an unscoped revision. Its declared dashboards are
  // evaluated from the complete local snapshot by the rendering helpers.
  if (isTopologyNodeSnapshot()) {
    settleDashboardRequest({
      time_ns: requestedTimeNs.toString(),
      dashboards: [],
      local_member_snapshot: true,
    }, requestedTimeNs);
    renderPluginDashboards();
    return;
  }

  if (!dashboardIds.length) {
    settleDashboardRequest({
      time_ns: requestedTimeNs.toString(),
      dashboards: [],
      population_count: null,
    }, requestedTimeNs);
    renderPluginDashboards();
    return;
  }

  const controller = beginLatestRequest("dashboardAbortController");
  try {
    const payload = await analysisRuntimeApi(revisionPath("dashboards/query"), {
      method: "POST",
      signal: controller.signal,
      body: JSON.stringify({
        time_ns: requestedTimeNs.toString(),
        dashboard_ids: dashboardIds,
      }),
    });
    if (requestId !== state.dashboardRequestId) return;
    settleDashboardRequest(payload, requestedTimeNs);
  } catch (error) {
    if (requestWasAborted(error, controller)) return;
    if (requestId !== state.dashboardRequestId) return;
    state.dashboardQueryError = error.message;
    state.dashboardReturnedTimeNs = state.dashboardQuery
      ? toNs(state.dashboardQuery.time_ns, state.dashboardReturnedTimeNs ?? requestedTimeNs)
      : null;
    state.dashboardPending = false;
  }
  finishLatestRequest("dashboardAbortController", controller);
  renderPluginDashboards();
}

function dashboardLayoutStorageKey() {
  const revision = String(workspaceMetadata().revision_id || "unknown-revision");
  const schemaIdentity = dashboardDescriptors()
    .map((item) => String(item.dashboard_id))
    .sort()
    .join("|");
  let hash = 2166136261;
  for (const character of `${revision}|${schemaIdentity}`) {
    hash ^= character.charCodeAt(0);
    hash = Math.imul(hash, 16777619) >>> 0;
  }
  return `${DASHBOARD_LAYOUT_STORAGE_KEY_PREFIX}:${encodeURIComponent(revision)}:${hash.toString(16)}`;
}

function initializeDashboardLayout(forceDefaults = false) {
  if (state.dashboardLayoutReady && !forceDefaults) return;
  const descriptors = dashboardDescriptors();
  const descriptorIds = descriptors.map((item) => String(item.dashboard_id));
  const allowedIds = new Set(descriptorIds);
  let saved = {};
  if (!forceDefaults) {
    try {
      saved = JSON.parse(localStorage.getItem(dashboardLayoutStorageKey()) || "{}");
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
    localStorage.setItem(dashboardLayoutStorageKey(), JSON.stringify({
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
    localStorage.removeItem(dashboardLayoutStorageKey());
  } catch (_error) {
    // Continue with in-memory defaults.
  }
  state.dashboardLayoutReady = false;
  initializeDashboardLayout(true);
  requestDashboards();
  renderPluginDashboards();
  showToast("Dashboard layout reset.");
}

function toggleDashboardOpen(dashboardId) {
  if (state.openDashboardIds.has(dashboardId)) state.openDashboardIds.delete(dashboardId);
  else state.openDashboardIds.add(dashboardId);
  saveDashboardLayout();
  requestDashboards();
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

function dashboardResourceRows(resourceKinds = [], includeAbsent = false) {
  if (!isTopologyNodeSnapshot()) return [];
  const rowsById = new Map();
  // Node-workspace dashboards may use the complete local member snapshot. Do
  // not use resourceQuery here: that is a bounded table window, not a
  // dashboard population.
  for (const item of state.dataset?.resources || []) {
    const id = canonicalResourceId(item.resource_id) || resourceIdOf(item);
    if (!id) continue;
    const lane = state.laneByResource.get(id);
    const temporal = lane
      ? statusAtLane(lane, state.cursorNs)
      : {
        exists: item.exists === true ? true : item.exists === false ? false : null,
        status: item.status || item.state?.status || item.state?.program_state || "observed",
        statusClass: item.status_class || "unknown",
        properties: item.state || item.properties || {},
      };
    rowsById.set(id, {
      ...item,
      resource_id: id,
      kind: item.kind || resourceKind(item, id),
      layer: item.layer || resourceLayer(item, id),
      label: item.label || resourceLabel(item, id),
      exists: temporal.exists,
      status: temporal.status,
      status_class: temporal.statusClass || item.status_class || "unknown",
      state: temporal.properties || {},
    });
  }
  return [...rowsById.values()]
    .filter((item) => dashboardRowIncluded(item, resourceKinds, includeAbsent));
}

function dashboardStatisticResult(descriptor, dashboardId) {
  if (descriptor.scale_metric) {
    const value = String(descriptor.scale_metric).split(".").reduce(
      (current, key) => (current === null || current === undefined ? undefined : current[key]),
      state.dataset?.scale?.metrics,
    );
    return {
      value,
      matchingCount: Number(value ?? 0),
      sampleCount: Number(value ?? 0),
      source: "plugin_precomputed",
    };
  }
  if (!isTopologyNodeSnapshot()) {
    const result = dashboardResultFor(dashboardId)?.statistics
      ?.find((item) => String(item.statistic_id) === String(descriptor.statistic_id));
    return result
      ? {
        value: result.value,
        matchingCount: Number(result.matching_count || 0),
        sampleCount: Number(result.sample_count || 0),
        source: "authoritative_query",
      }
      : {
        value: null,
        matchingCount: 0,
        sampleCount: 0,
        source: state.dashboardPending ? "pending" : "unavailable",
      };
  }
  const rows = dashboardResourceRows(
    descriptor.resource_kinds,
    descriptor.include_absent === true,
  );
  const evaluation = dashboardStatisticEvaluation(rows, descriptor);
  return {
    ...evaluation,
    source: "local_member_snapshot",
  };
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

function renderDashboardStatistic(descriptor, dashboardId) {
  // Resource tables retain resourceTimeSummary(); dashboards intentionally use
  // their independent authoritative dashboardTimeSummary() request state.
  const result = dashboardStatisticResult(descriptor, dashboardId);
  const aggregation = titleCase(descriptor.aggregation || "count");
  let attribution;
  if (result.source === "plugin_precomputed") {
    attribution = "Plug-in-precomputed archive metric · not point-in-time";
  } else if (result.source === "pending") {
    attribution = `Loading authoritative population · ${dashboardTimeSummary()}`;
  } else if (result.source === "unavailable") {
    attribution = state.dashboardQueryError
      ? `Authoritative query failed · ${state.dashboardQueryError}`
      : "Authoritative point-in-time result was not returned";
  } else {
    const samples = String(descriptor.aggregation || "count") === "count"
      ? ""
      : ` · ${result.sampleCount} samples`;
    attribution = `${aggregation} · ${result.matchingCount} matching${samples} · ${dashboardTimeSummary()}`;
  }
  return `<article class="dashboard-stat">
    <span>${escapeHtml(descriptor.label || descriptor.statistic_id)}</span>
    <strong>${escapeHtml(formatDashboardStatistic(result, descriptor))}</strong>
    <small>${escapeHtml(attribution)}</small>
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
    const declaredStatusClass = column.status_class_field
      ? dashboardFieldValue(item, column.status_class_field)
      : undefined;
    const statusClass = declaredStatusClass
      ?? (column.field === "status" ? item.status_class : "unknown");
    return `<span class="${stateChipClassName({ status_class: statusClass || "unknown" })}">${escapeHtml(value)}</span>`;
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

function renderDashboardTable(descriptor, dashboardId) {
  let rows = [];
  let totalCount = 0;
  let truncated = false;
  let unavailableMessage = null;
  if (isTopologyNodeSnapshot()) {
    const allRows = dashboardResourceRows(
      descriptor.resource_kinds,
      descriptor.include_absent === true,
    ).filter((item) => (descriptor.filters || []).every(
      (filter) => dashboardFilterMatches(item, filter),
    ));
    const direction = descriptor.sort_direction === "descending" ? -1 : 1;
    const sortedRows = descriptor.sort_field
      ? [...allRows].sort((left, right) => direction * compareDashboardValues(
        dashboardFieldValue(left, descriptor.sort_field),
        dashboardFieldValue(right, descriptor.sort_field),
      ))
      : allRows;
    const limit = Math.max(1, Math.min(500, Number(descriptor.max_rows || 50)));
    rows = sortedRows.slice(0, limit);
    totalCount = sortedRows.length;
    truncated = totalCount > rows.length;
  } else {
    const result = dashboardResultFor(dashboardId)?.tables
      ?.find((item) => String(item.table_id) === String(descriptor.table_id));
    if (result) {
      rows = Array.isArray(result.items) ? result.items : [];
      totalCount = Number(result.total_count ?? rows.length);
      truncated = Boolean(result.truncated || totalCount > rows.length);
    } else {
      unavailableMessage = state.dashboardPending
        ? "Loading the authoritative point-in-time population…"
        : state.dashboardQueryError
          ? `Dashboard query failed: ${state.dashboardQueryError}`
          : "The authoritative point-in-time table was not returned.";
    }
  }
  const columns = Array.isArray(descriptor.columns) ? descriptor.columns : [];
  const body = rows.length
    ? rows.map((item) => `<tr data-dashboard-resource-row="${escapeHtml(item.resource_id || "")}" class="${item.resource_id === state.selectedResourceId ? "selected" : ""}">
      ${columns.map((column) => `<td>${formatDashboardCell(item, column)}</td>`).join("")}
    </tr>`).join("")
    : `<tr><td colspan="${Math.max(1, columns.length)}" class="dashboard-table-empty">${escapeHtml(unavailableMessage || descriptor.empty_message || "No resources match this dashboard at the selected time.")}</td></tr>`;
  const countText = truncated
    ? `Showing ${rows.length} of ${totalCount}`
    : `${rows.length} resource${rows.length === 1 ? "" : "s"}`;
  return `<section class="dashboard-table-panel">
    <div class="dashboard-table-heading">
      <h4>${escapeHtml(descriptor.title || descriptor.table_id)}</h4>
      <span>${escapeHtml(`${countText} · ${dashboardTimeSummary()}`)}</span>
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
  modules.setAttribute("aria-busy", String(state.dashboardPending));
  modules.classList.toggle("is-time-pending", state.dashboardPending);
  refreshDashboardTimePresentation();
  initializeDashboardLayout();
  const descriptors = dashboardDescriptors();
  const descriptorById = new Map(descriptors.map((item) => [String(item.dashboard_id), item]));
  const orderedIds = state.dashboardOrder.filter((id) => descriptorById.has(id));
  const resetButton = byId("reset-dashboard-layout");
  if (resetButton) resetButton.disabled = !orderedIds.length;
  if (!orderedIds.length) {
    if (isTopologyNodeSnapshot()) {
      index.innerHTML = '<span class="dashboard-index-empty">0 dashboard descriptors registered for this member snapshot.</span>';
      modules.innerHTML = nodeSnapshotUnavailableMarkup(
        "Resource dashboards were not supplied",
        "Dashboard modules are plug-in-defined. The selected topology-member plug-ins supplied resource state and correlations, but no dashboard descriptors for this snapshot.",
      );
    } else {
      index.innerHTML = '<span class="dashboard-index-empty">The active plug-in has not registered any dashboards.</span>';
      modules.innerHTML = "";
    }
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
  const queryErrorMarkup = state.dashboardQueryError
    ? `<div class="empty-state dashboard-query-error" role="alert">
        <strong>Dashboard descriptor unavailable</strong>
        <span>${escapeHtml(state.dashboardQueryError)}</span>
      </div>`
    : "";
  modules.innerHTML = `${queryErrorMarkup}${openIds.map((id, openPosition) => {
    const descriptor = descriptorById.get(id);
    const expanded = descriptor.collapsible === false || state.expandedDashboardIds.has(id);
    const movable = descriptor.movable !== false;
    const position = orderedIds.indexOf(id);
    const statistics = descriptor.statistics || [];
    const tables = descriptor.tables || [];
    const body = expanded
      ? `<div class="plugin-dashboard-body" id="dashboard-body-${escapeHtml(id)}">
        ${statistics.length ? `<div class="dashboard-stat-grid">${statistics.map((item) => renderDashboardStatistic(item, id)).join("")}</div>` : ""}
        ${tables.length ? `<div class="dashboard-table-grid">${tables.map((item) => renderDashboardTable(item, id)).join("")}</div>` : ""}
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
  }).join("")}`;

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

function refreshDashboardSelectionPresentation() {
  byId("dashboard-modules")?.querySelectorAll("[data-dashboard-resource-row]").forEach((row) => {
    row.classList.toggle("selected", row.dataset.dashboardResourceRow === state.selectedResourceId);
  });
}

function relationshipTransportKey(item) {
  const source = canonicalResourceId(item?.source) || canonicalResourceId(item?.source_resource_id);
  const target = canonicalResourceId(item?.target) || canonicalResourceId(item?.target_resource_id);
  const type = typeof (item?.relation_type ?? item?.type) === "string"
    ? (item.relation_type ?? item.type)
    : "unknown";
  return source && target ? `${source}|${type}|${target}` : null;
}

function localGraphAt(time) {
  const allIntervals = state.dataset.relationship_intervals || [];
  const intervalRelations = allIntervals.filter((item) => {
    const start = item.valid_from_ns === null || item.valid_from_ns === undefined ? state.viewStartNs : toNs(item.valid_from_ns);
    const end = item.valid_to_ns === null || item.valid_to_ns === undefined ? state.viewEndNs + 1n : toNs(item.valid_to_ns);
    return time >= start && time < end;
  });
  const intervalKeys = new Set(allIntervals.map(relationshipTransportKey).filter(Boolean));
  const carriedRelationships = (state.dataset.relationships || []).filter((item) => {
    const key = relationshipTransportKey(item);
    return key && !intervalKeys.has(key);
  });
  const activeResourceIds = new Set(
    [...state.resourceById.keys()].filter((id) => {
      const lane = state.laneByResource.get(id);
      return lane ? statusAtLane(lane, time).exists : false;
    }),
  );
  const relationships = [...carriedRelationships, ...intervalRelations].filter((item) => {
    const source = item.source || item.source_resource_id;
    const target = item.target || item.target_resource_id;
    return relationshipPresencePresentation(item).present !== false
      && activeResourceIds.has(source) && activeResourceIds.has(target);
  });
  const ids = new Set(relationships.flatMap((item) => [
    canonicalResourceId(item.source) || canonicalResourceId(item.source_resource_id),
    canonicalResourceId(item.target) || canonicalResourceId(item.target_resource_id),
  ]).filter(Boolean));
  const nodes = [...ids].map((id) => {
    const record = state.resourceById.get(id) || { resource_id: id };
    const temporal = state.laneByResource.has(id) ? statusAtLane(state.laneByResource.get(id), time) : { status: "unknown", statusClass: "unknown", properties: {} };
    return { id, label: resourceLabel(record, id), kind: resourceKind(record, id), layer: resourceLayer(record, id), status: temporal.status, status_class: temporal.statusClass, state: temporal.properties, quality: record.quality || "unknown", complete_record: state.resourceById.has(id), presentation_tags: [...presentationTags(record)] };
  });
  return {
    nodes,
    edges: relationships.map((item, index) => {
      const type = typeof (item.type ?? item.relation_type) === "string" ? (item.type ?? item.relation_type) : "unknown";
      const presentation = relationshipPresentation(type);
      return {
        id: typeof item.relationship_id === "string" ? item.relationship_id : `edge-${index}`,
        source: canonicalResourceId(item.source) || canonicalResourceId(item.source_resource_id),
        target: canonicalResourceId(item.target) || canonicalResourceId(item.target_resource_id),
        type,
        relationship_label: presentation.displayLabel,
        relationship_known: presentation.known,
        directed: presentation.directed,
        structural: presentation.structural,
        ...relationshipPresencePresentation(item),
      };
    }).filter((edge) => edge.source && edge.target),
    incomplete_node_count: nodes.filter((node) => !node.complete_record).length,
  };
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

function boundedCorrelationGraph(graph) {
  const totalNodes = graph.nodes.length;
  const totalEdges = graph.edges.length;
  if (totalNodes <= MAX_CORRELATION_RENDER_NODES) {
    return {
      ...graph,
      display_truncated: false,
      display_total_nodes: totalNodes,
      display_total_edges: totalEdges,
    };
  }
  const nodeById = new Map(graph.nodes.map((node) => [node.id, node]));
  const degree = new Map(graph.nodes.map((node) => [node.id, 0]));
  graph.edges.forEach((edge) => {
    degree.set(edge.source, (degree.get(edge.source) || 0) + 1);
    degree.set(edge.target, (degree.get(edge.target) || 0) + 1);
  });
  const chosen = new Set();
  const add = (id) => {
    if (chosen.size >= MAX_CORRELATION_RENDER_NODES || !nodeById.has(id)) return;
    chosen.add(id);
  };
  if (state.selectedResourceId) {
    add(state.selectedResourceId);
    const incoming = graph.edges
      .filter((edge) => edge.target === state.selectedResourceId)
      .map((edge) => edge.source)
      .sort((left, right) => graphNodeSort(nodeById.get(left), nodeById.get(right)));
    const outgoing = graph.edges
      .filter((edge) => edge.source === state.selectedResourceId)
      .map((edge) => edge.target)
      .sort((left, right) => graphNodeSort(nodeById.get(left), nodeById.get(right)));
    for (let index = 0; chosen.size < MAX_CORRELATION_RENDER_NODES && (index < incoming.length || index < outgoing.length); index += 1) {
      if (index < incoming.length) add(incoming[index]);
      if (index < outgoing.length) add(outgoing[index]);
    }
  }
  const ranked = [...graph.nodes].sort((left, right) => (
    (degree.get(right.id) || 0) - (degree.get(left.id) || 0)
    || graphNodeSort(left, right)
  ));
  ranked.forEach((node) => add(node.id));
  const nodes = graph.nodes.filter((node) => chosen.has(node.id));
  const edges = graph.edges.filter((edge) => chosen.has(edge.source) && chosen.has(edge.target));
  return {
    ...graph,
    nodes,
    edges,
    display_truncated: true,
    display_total_nodes: totalNodes,
    display_total_edges: totalEdges,
  };
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
  abortLatestRequests("graphAbortController");
  state.correlationListLimit = CORRELATION_LIST_PAGE_SIZE;
  markCorrelationPending(requestedTimeNs);
  if (isTopologyNodeSnapshot()) {
    state.graph = { ...localGraphAt(requestedTimeNs), time_ns: requestedTimeNs.toString(), snapshot_only: true };
    state.graphTimeNs = requestedTimeNs;
    state.graphRequestedTimeNs = requestedTimeNs;
    state.graphPending = false;
    updateCorrelationState();
    renderCorrelationTimeState();
    renderGraph();
    rerenderTimelinePreservingScroll();
    return;
  }
  const controller = beginLatestRequest("graphAbortController");
  try {
    const resourceIds = state.graphShowFull
      ? []
      : state.selectedResourceId ? [state.selectedResourceId] : [];
    const graph = await analysisRuntimeApi(revisionPath("graph/query"), {
      method: "POST",
      signal: controller.signal,
      body: JSON.stringify({
        time_ns: requestedTimeNs.toString(),
        resource_ids: resourceIds,
        depth: state.graphShowFull ? 20 : 3,
        max_nodes: 500,
      }),
    });
    if (requestId !== state.graphRequestId) return;
    state.graph = graph;
  } catch (error) {
    if (requestWasAborted(error, controller)) return;
    if (requestId !== state.graphRequestId) return;
    state.graph = { ...localGraphAt(requestedTimeNs), time_ns: requestedTimeNs.toString() };
  }
  finishLatestRequest("graphAbortController", controller);
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
    const id = canonicalResourceId(node.id) || canonicalResourceId(node.resource_id);
    if (!id) return null;
    const record = state.resourceById.get(id) || node;
    // The graph endpoint uses `status` for the normalized class and
    // `status_value` for the plug-in-owned condition.  Normalize that transport
    // shape once so renderers do not miss failure highlighting.
    const statusClass = graphStatusClass(node);
    return {
      ...node,
      id,
      label: node.label || resourceLabel(record, id),
      kind: node.kind || resourceKind(record, id),
      layer: node.layer || resourceLayer(record, id),
      status_class: statusClass,
      presentation_tags: node.presentation_tags || [...presentationTags(record)],
    };
  }).filter(Boolean);
  const edges = (graph.edges || graph.relationships || []).map((edge, index) => {
    const presence = relationshipPresencePresentation(edge);
    if (presence.present === false) return null;
    const source = canonicalResourceId(edge.source) || canonicalResourceId(edge.source_resource_id);
    const target = canonicalResourceId(edge.target) || canonicalResourceId(edge.target_resource_id);
    if (!source || !target) return null;
    const type = typeof (edge.type ?? edge.relation_type) === "string" ? (edge.type ?? edge.relation_type) : "unknown";
    const presentation = relationshipPresentation(type);
    return {
      ...edge,
      ...presence,
      id: typeof (edge.id ?? edge.relationship_id) === "string" ? (edge.id ?? edge.relationship_id) : `edge-${index}`,
      source,
      target,
      type,
      relationship_label: presentation.displayLabel,
      relationship_known: presentation.known,
      directed: presentation.directed,
      structural: presentation.structural,
    };
  }).filter(Boolean);
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

function showCorrelationHover(anchor, html, { pinned = false } = {}) {
  window.clearTimeout(showCorrelationHover.closeTimer);
  const card = correlationHoverCard();
  card.innerHTML = html;
  card.hidden = false;
  card.dataset.pinned = String(pinned);
  card.style.width = `${Math.min(440, window.innerWidth - 24)}px`;
  const rect = anchor.getBoundingClientRect();
  const width = card.getBoundingClientRect().width;
  const height = Math.min(430, card.scrollHeight || 250);
  const margin = 12;
  const gap = 8;
  const clampLeft = (value) => Math.max(margin, Math.min(window.innerWidth - width - margin, value));
  const clampTop = (value) => Math.max(margin, Math.min(window.innerHeight - height - margin, value));
  const centeredLeft = clampLeft(rect.left + rect.width / 2 - width / 2);
  const belowTop = rect.bottom + gap;
  const aboveTop = rect.top - height - gap;
  if (belowTop + height <= window.innerHeight - margin) {
    card.style.left = `${centeredLeft}px`;
    card.style.top = `${belowTop}px`;
  } else if (aboveTop >= margin) {
    card.style.left = `${centeredLeft}px`;
    card.style.top = `${aboveTop}px`;
  } else if (rect.right + gap + width <= window.innerWidth - margin) {
    card.style.left = `${rect.right + gap}px`;
    card.style.top = `${clampTop(rect.top + rect.height / 2 - height / 2)}px`;
  } else {
    card.style.left = `${Math.max(margin, rect.left - width - gap)}px`;
    card.style.top = `${clampTop(rect.top + rect.height / 2 - height / 2)}px`;
  }
}

function scheduleCorrelationHoverClose() {
  window.clearTimeout(showCorrelationHover.closeTimer);
  if (byId("correlation-hover")?.dataset.pinned === "true") return;
  showCorrelationHover.closeTimer = window.setTimeout(() => {
    const card = byId("correlation-hover");
    if (card) card.hidden = true;
  }, 320);
}

function closeCorrelationHover() {
  window.clearTimeout(showCorrelationHover.closeTimer);
  const card = byId("correlation-hover");
  if (card) {
    card.dataset.pinned = "false";
    card.hidden = true;
  }
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
      ? "Outgoing endpoint"
      : outgoing.some((edge) => edge.target === state.selectedResourceId) ? "Incoming endpoint" : "Connected resource";
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
    ${node.complete_record === false ? '<div class="resource-hover-warning"><strong>Incomplete normalized record</strong><span>This resource exists only as a relationship endpoint in the current workspace.</span></div>' : ""}`;
}

function graphEdgeHoverHtml(edge, nodes) {
  const graphTimeNs = graphDisplayTimeNs();
  const source = nodes.get(edge.source);
  const target = nodes.get(edge.target);
  const start = edge.valid_from_ns === null || edge.valid_from_ns === undefined ? "open" : formatOffset(toNs(edge.valid_from_ns));
  const end = edge.valid_to_ns === null || edge.valid_to_ns === undefined ? "open" : formatOffset(toNs(edge.valid_to_ns));
  const presentation = relationshipPresentation(edge.type);
  return `<div class="hover-heading"><div><span>RELATIONSHIP</span><strong>${escapeHtml(presentation.displayLabel)}</strong></div></div>
    <dl class="hover-facts">
      <dt>Source</dt><dd>${escapeHtml(source?.label || edge.source)}<small>${escapeHtml(edge.source)}</small></dd>
      <dt>Target</dt><dd>${escapeHtml(target?.label || edge.target)}<small>${escapeHtml(edge.target)}</small></dd>
      <dt>${presentation.directed === true ? "Direction" : "Endpoints"}</dt><dd>${escapeHtml(`${edge.source} ${presentation.directed === true ? "→" : "—"} ${edge.target}`)}</dd>
      ${presentation.known ? "" : `<dt>Raw type</dt><dd>${escapeHtml(presentation.rawType || "not supplied")}</dd>`}
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
  const renderItems = (edges, direction) => edges.slice(0, state.correlationListLimit).map((edge) => {
    const otherId = direction === "outgoing" ? edge.target : edge.source;
    const presentation = relationshipPresentation(edge.type);
    const arrow = presentation.directed === true ? (direction === "outgoing" ? "→" : "←") : "–";
    const directionCopy = presentation.directed === true
      ? (direction === "outgoing" ? "Selected resource is the declared source" : "Selected resource is the declared target")
      : "Connected relationship endpoint; direction semantics were not declared";
    return `<details class="correlation-item ${direction}">
      <summary>
        <span class="correlation-direction" aria-hidden="true">${arrow}</span>
        <span class="correlation-resource"><strong>${escapeHtml(resourceName(otherId))}</strong><small>${escapeHtml(resourceDetails(otherId))}</small></span>
        <span class="correlation-relation" tabindex="0" data-correlation-edge-id="${escapeHtml(edge.id)}">${escapeHtml(presentation.displayLabel)}</span>
      </summary>
      <div class="correlation-item-body">
        <span>${escapeHtml(directionCopy)}</span>
        <code>${escapeHtml(`${edge.source} ${presentation.directed === true ? "→" : "—"} ${edge.target}`)}</code>
        <span>Quality: ${escapeHtml(edge.quality || "unknown")}${edge.provenance ? ` / ${escapeHtml(edge.provenance)}` : ""}</span>
        <button type="button" data-resource-id="${escapeHtml(otherId)}">Ctrl-click to timeline</button>
      </div>
    </details>`;
  }).join("");
  const moreControl = (edges) => edges.length > state.correlationListLimit
    ? `<div class="correlation-list-more"><span>Showing ${state.correlationListLimit.toLocaleString()} of ${edges.length.toLocaleString()}</span><button type="button" data-correlation-show-more>Show ${Math.min(CORRELATION_LIST_PAGE_SIZE, edges.length - state.correlationListLimit).toLocaleString()} more</button></div>`
    : "";
  const renderGroup = (kind, title, description, edges) => `<details class="correlation-group ${kind}" open>
    <summary><span><strong>${escapeHtml(title)}</strong><small>${escapeHtml(description)}</small></span><b>${edges.length}</b></summary>
    <div class="correlation-items">${renderItems(edges, kind) || '<p>No resources in this direction at the selected time.</p>'}${moreControl(edges)}</div>
  </details>`;

  if (!state.selectedResourceId) {
    container.innerHTML = `<div class="correlation-heading"><strong>Active relationships</strong><span>${graph.edges.length} at ${escapeHtml(formatOffset(graphTimeNs))}</span></div><div class="correlation-rows">${graph.edges.slice(0, state.correlationListLimit).map((edge) => { const presentation = relationshipPresentation(edge.type); return `<div><button type="button" data-resource-id="${escapeHtml(edge.source)}">${escapeHtml(resourceName(edge.source))}</button><span tabindex="0" data-correlation-edge-id="${escapeHtml(edge.id)}">${escapeHtml(presentation.displayLabel)} ${presentation.directed === true ? "→" : "—"}</span><button type="button" data-resource-id="${escapeHtml(edge.target)}">${escapeHtml(resourceName(edge.target))}</button></div>`; }).join("") || '<p>No active relationship is visible at this time.</p>'}${moreControl(graph.edges)}</div>`;
  } else {
    const outgoing = graph.edges.filter((edge) => edge.source === state.selectedResourceId);
    const incoming = graph.edges.filter((edge) => edge.target === state.selectedResourceId);
    container.innerHTML = `<div class="correlation-heading"><strong>Relationship index</strong><span>${outgoing.length + incoming.length} at ${escapeHtml(formatOffset(graphTimeNs))}</span></div>
      <div class="correlation-root"><span>Selected focus</span><strong>${escapeHtml(resourceName(state.selectedResourceId))}</strong><code>${escapeHtml(state.selectedResourceId)}</code></div>
      <div class="correlation-groups">
        ${renderGroup("outgoing", "Declared source endpoints", "Selected resource is the source endpoint", outgoing)}
        ${renderGroup("incoming", "Declared target endpoints", "Selected resource is the target endpoint", incoming)}
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
  container.querySelectorAll("[data-correlation-show-more]").forEach((button) => {
    button.addEventListener("click", () => {
      state.correlationListLimit += CORRELATION_LIST_PAGE_SIZE;
      closeCorrelationHover();
      renderCorrelationList(graph);
    });
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

function syncCorrelationPanel() {
  const panel = byId("dependency-graph");
  const content = byId("dependency-graph-content");
  const button = byId("correlation-panel-toggle");
  if (!panel || !content || !button) return;
  const expanded = state.correlationPanelExpanded;
  content.hidden = !expanded;
  panel.classList.toggle("is-collapsed", !expanded);
  button.setAttribute("aria-expanded", String(expanded));
  button.textContent = expanded ? "Collapse correlation" : "Expand correlation";
}

function syncCorrelationBackToTop() {
  const button = byId("correlation-back-to-top");
  if (!button) return;
  button.hidden = !state.correlationPanelExpanded
    || !(state.correlationSectionInView || state.correlationSectionFocused);
}

function bindCorrelationPanelControls() {
  const panel = byId("dependency-graph");
  const toggle = byId("correlation-panel-toggle");
  const backToTop = byId("correlation-back-to-top");
  if (!panel || !toggle || !backToTop) return;

  toggle.addEventListener("click", () => {
    state.correlationPanelExpanded = !state.correlationPanelExpanded;
    syncCorrelationPanel();
    syncCorrelationBackToTop();
    if (!state.correlationPanelExpanded) closeCorrelationHover();
    if (state.correlationPanelExpanded && state.graph) {
      window.requestAnimationFrame(renderGraph);
    }
  });
  backToTop.addEventListener("click", () => {
    const reducedMotion = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
    window.scrollTo({ top: 0, behavior: reducedMotion ? "auto" : "smooth" });
    document.querySelector(".brand")?.focus({ preventScroll: true });
  });
  panel.addEventListener("focusin", () => {
    state.correlationSectionFocused = true;
    syncCorrelationBackToTop();
  });
  panel.addEventListener("focusout", () => window.requestAnimationFrame(() => {
    state.correlationSectionFocused = panel.contains(document.activeElement);
    syncCorrelationBackToTop();
  }));

  if ("IntersectionObserver" in window) {
    state.correlationSectionObserver = new IntersectionObserver(([entry]) => {
      state.correlationSectionInView = Boolean(entry?.isIntersecting);
      syncCorrelationBackToTop();
    }, { threshold: 0 });
    state.correlationSectionObserver.observe(panel);
  } else {
    state.correlationSectionInView = true;
  }
  syncCorrelationPanel();
  syncCorrelationBackToTop();
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

function validGraphInspection(graph, inspection) {
  if (!inspection?.kind || inspection.id === null || inspection.id === undefined) return null;
  const id = String(inspection.id);
  if (inspection.kind === "resource") {
    return graph.nodes.some((node) => node.id === id) ? { kind: "resource", id } : null;
  }
  if (inspection.kind === "edge") {
    return graph.edges.some((edge) => String(edge.id) === id) ? { kind: "edge", id } : null;
  }
  return null;
}

function setGraphInspection(stage, graph, inspection) {
  const activeInspection = validGraphInspection(graph, inspection);
  const pinnedInspection = validGraphInspection(graph, state.graphPinnedInspection);
  stage.classList.toggle("is-inspecting", Boolean(activeInspection));
  stage.classList.toggle("has-pinned-inspection", Boolean(pinnedInspection));
  const edgeIds = new Set();
  const nodeIds = new Set();
  if (activeInspection?.kind === "resource") {
    nodeIds.add(activeInspection.id);
    graph.edges.forEach((edge) => {
      if (edge.source !== activeInspection.id && edge.target !== activeInspection.id) return;
      edgeIds.add(String(edge.id));
      nodeIds.add(edge.source);
      nodeIds.add(edge.target);
    });
  } else if (activeInspection?.kind === "edge") {
    const edge = graph.edges.find((item) => String(item.id) === activeInspection.id);
    if (edge) {
      edgeIds.add(String(edge.id));
      nodeIds.add(edge.source);
      nodeIds.add(edge.target);
    }
  }
  stage.querySelectorAll(".graph-node").forEach((node) => {
    node.classList.toggle("is-active", nodeIds.has(node.dataset.resourceId));
    const pinned = pinnedInspection?.kind === "resource"
      && pinnedInspection.id === node.dataset.resourceId;
    node.classList.toggle("is-pinned", pinned);
    node.setAttribute("aria-pressed", String(pinned));
  });
  stage.querySelectorAll("[data-graph-edge-id]").forEach((edge) => {
    edge.classList.toggle("is-active", edgeIds.has(edge.dataset.graphEdgeId));
    const pinned = pinnedInspection?.kind === "edge"
      && pinnedInspection.id === edge.dataset.graphEdgeId;
    edge.classList.toggle("is-pinned", pinned);
    if (edge.classList.contains("graph-edge-label")) {
      edge.setAttribute("aria-pressed", String(pinned));
    }
  });
}

function pinGraphInspection(stage, graph, inspection, anchor, html) {
  const nextInspection = validGraphInspection(graph, inspection);
  if (!nextInspection) return;
  state.graphPinnedInspection = nextInspection;
  setGraphInspection(stage, graph, nextInspection);
  showCorrelationHover(anchor, html, { pinned: true });
}

function clearPinnedGraphInspection({ closeCard = true } = {}) {
  const hadInspection = Boolean(state.graphPinnedInspection);
  state.graphPinnedInspection = null;
  const stage = byId("graph-stage");
  if (stage) {
    stage.classList.remove("is-inspecting", "has-pinned-inspection");
    stage.querySelectorAll(".is-active, .is-pinned").forEach((element) => {
      element.classList.remove("is-active", "is-pinned");
      if (
        element.classList.contains("graph-node")
        || element.classList.contains("graph-edge-label")
      ) {
        element.setAttribute("aria-pressed", "false");
      }
    });
  }
  if (closeCard) closeCorrelationHover();
  return hadInspection;
}

function bindGraphStageInspectionClear() {
  const stage = byId("graph-stage");
  if (!stage) return;
  stage.addEventListener("click", (event) => {
    if (event.target.closest(".graph-node, [data-graph-edge-id]")) return;
    clearPinnedGraphInspection();
  });
}

function renderGraph() {
  closeCorrelationHover();
  const fullGraph = normalizedGraph();
  const graphTimeNs = graphDisplayTimeNs(fullGraph);
  renderCorrelationTimeState();
  syncGraphScopeButton();
  updateCorrelationState(fullGraph);
  const scoped = scopedGraph(fullGraph);
  const graph = boundedCorrelationGraph(scoped);
  const stage = byId("graph-stage");
  if (!graph.nodes.length) {
    state.graphPinnedInspection = null;
    closeCorrelationHover();
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
  const svg = `<svg class="graph-edge-layer" viewBox="0 0 1000 ${height}" preserveAspectRatio="none" role="group" aria-label="Correlation relationships"><defs><marker id="arrowhead" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto"><path d="M0,0 L7,3.5 L0,7 Z" fill="#557283"></path></marker></defs>${graph.edges.map((edge) => {
    const source = positions.get(edge.source); const target = positions.get(edge.target);
    if (!source || !target) return "";
    const x1 = source.x * 10; const x2 = target.x * 10; const y1 = source.y / 100 * height; const y2 = target.y / 100 * height; const mid = (x1 + x2) / 2;
    const direction = edge.source === state.selectedResourceId ? " outgoing" : edge.target === state.selectedResourceId ? " incoming" : "";
    const presentation = relationshipPresentation(edge.type);
    const relationClass = presentation.directed === true ? " directed" : presentation.directed === false ? " undirected" : " direction-unknown";
    const edgeTitle = `${edge.source} ${presentation.directed === true ? "→" : "—"} ${edge.target} / ${presentation.displayLabel} / ${edge.quality || "unknown"}`;
    const edgeActionLabel = `Inspect ${presentation.displayLabel} relationship between ${edge.source} and ${edge.target}`;
    return `<path class="graph-edge${direction}${relationClass}${edge.temporal_note ? " dynamic" : ""}" aria-hidden="true" d="M ${x1} ${y1} C ${mid} ${y1}, ${mid} ${y2}, ${x2} ${y2}"><title>${escapeHtml(edgeTitle)}</title></path><text class="graph-edge-label${direction}" data-correlation-edge-id="${escapeHtml(edge.id)}" x="${mid}" y="${(y1 + y2) / 2 - 4}" tabindex="0" role="button" aria-label="${escapeHtml(edgeActionLabel)}">${escapeHtml(presentation.displayLabel)}</text>`;
  }).join("")}</svg>`;
  const nodeHtml = graph.nodes.map((node) => {
    const position = positions.get(node.id); const compact = isCompact(node); const selected = node.id === state.selectedResourceId;
    const outgoingTarget = graph.edges.some((edge) => edge.source === state.selectedResourceId && edge.target === node.id);
    const incomingSource = graph.edges.some((edge) => edge.target === state.selectedResourceId && edge.source === node.id);
    const role = selected ? "focus" : incomingSource ? "incoming" : outgoingTarget ? "outgoing" : "";
    const roleLabel = role === "incoming" ? "Incoming endpoint" : role === "outgoing" ? "Outgoing endpoint" : role === "focus" ? "Selected" : "";
    const customIcon = resourceIconMarkup(node, node.kind, "graph-resource-icon");
    const statusClass = typeof node.status_class === "string" ? node.status_class : "unknown";
    return `<button class="graph-node${compact ? " compact" : ""}${statusClass === "error" ? " error" : ""}${selected ? " selected" : ""}${role ? ` role-${role}` : ""}" type="button" data-resource-id="${escapeHtml(node.id)}" style="left:${position.x}%;top:${position.y}%;--node-color:${layerColor(node.layer)}">${roleLabel ? `<span class="node-role">${escapeHtml(roleLabel)}</span>` : ""}<span class="graph-node-kindline">${customIcon}<span class="node-kind">${escapeHtml(`${humanLayer(node.layer)} / ${node.kind}`)}</span></span><strong>${escapeHtml(node.label)}</strong><small class="node-status">${escapeHtml(node.status_value || node.status || "unknown")}${node.complete_record === false ? " / endpoint only" : ""}</small></button>`;
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
  const retainedInspection = validGraphInspection(graph, state.graphPinnedInspection);
  if (state.graphPinnedInspection && !retainedInspection) {
    state.graphPinnedInspection = null;
    closeCorrelationHover();
  }
  stage.querySelectorAll(".graph-node").forEach((button) => {
    button.addEventListener("click", (event) => {
      if (event.ctrlKey || event.metaKey) {
        event.preventDefault();
        jumpToTimelineResource(button.dataset.resourceId);
        return;
      }
      event.preventDefault();
      event.stopPropagation();
      const node = graphNodes.get(button.dataset.resourceId);
      if (node) {
        pinGraphInspection(
          stage,
          graph,
          { kind: "resource", id: node.id },
          button,
          graphNodeHoverHtml(node, graph),
        );
      }
    });
    const node = graphNodes.get(button.dataset.resourceId);
    if (node) {
      bindCorrelationHover(button, () => graphNodeHoverHtml(node, graph));
      button.addEventListener("pointerenter", () => setGraphInspection(stage, graph, { kind: "resource", id: node.id }));
      button.addEventListener("pointerleave", () => setGraphInspection(stage, graph, state.graphPinnedInspection));
      button.addEventListener("focus", () => setGraphInspection(stage, graph, { kind: "resource", id: node.id }));
      button.addEventListener("blur", () => setGraphInspection(stage, graph, state.graphPinnedInspection));
    }
  });
  const graphEdges = new Map(graph.edges.map((edge) => [String(edge.id), edge]));
  stage.querySelectorAll("[data-graph-edge-id]").forEach((element) => {
    const edge = graphEdges.get(element.dataset.graphEdgeId);
    if (!edge) return;
    const inspection = { kind: "edge", id: String(edge.id) };
    bindCorrelationHover(element, () => graphEdgeHoverHtml(edge, graphNodes));
    element.addEventListener("pointerenter", () => setGraphInspection(stage, graph, inspection));
    element.addEventListener("pointerleave", () => setGraphInspection(stage, graph, state.graphPinnedInspection));
    element.addEventListener("focus", () => setGraphInspection(stage, graph, inspection));
    element.addEventListener("blur", () => setGraphInspection(stage, graph, state.graphPinnedInspection));
    element.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      pinGraphInspection(
        stage,
        graph,
        inspection,
        element,
        graphEdgeHoverHtml(edge, graphNodes),
      );
    });
    element.addEventListener("keydown", (event) => {
      if (event.key !== "Enter" && event.key !== " ") return;
      event.preventDefault();
      event.stopPropagation();
      pinGraphInspection(
        stage,
        graph,
        inspection,
        element,
        graphEdgeHoverHtml(edge, graphNodes),
      );
    });
  });
  setGraphInspection(stage, graph, retainedInspection);
  const hiddenCopy = graph.hidden_isolated_count
    ? ` ${graph.hidden_isolated_count} active resources without a current relationship are omitted.`
    : "";
  const truncationCopy = graph.truncated
    ? ` Server result capped at ${Number(graph.max_nodes || graph.display_total_nodes || graph.nodes.length).toLocaleString()} resources; refine or focus to inspect omitted relationships.`
    : "";
  const displayCopy = graph.display_truncated
    ? ` Canvas bounded to ${graph.nodes.length.toLocaleString()} of ${graph.display_total_nodes.toLocaleString()} resources and ${graph.edges.length.toLocaleString()} of ${graph.display_total_edges.toLocaleString()} relationships; the index below remains pageable across the full response.`
    : "";
  const directionCopy = layout.mode === "focus"
    ? " Left-side resources are declared source endpoints; the selected resource is the declared source for right-side endpoints. Plug-in descriptors decide whether those relationships are directional."
    : " Directed arrows appear only when the plug-in relationship descriptor declares direction.";
  const inspectionCopy = " Hover to preview a resource or relationship; click to keep it highlighted. Press Esc or click empty canvas to clear.";
  byId("graph-note").textContent = `${graph.nodes.length} visible correlated resources / ${graph.edges.length} visible time-valid relationships / selected moment ${formatOffset(graphTimeNs)}.${hiddenCopy}${truncationCopy}${displayCopy}${directionCopy}${inspectionCopy}`;
  renderCorrelationList(scoped);
}

function drawTimelineCorrelationOverlay() {
  const content = byId("timeline-content");
  content.querySelector(".timeline-correlation-overlay")?.remove();
  if (state.correlationTimelineView !== "separate" || !state.selectedResourceId || !state.activeCorrelationEdges.length) return;
  const rows = [...content.querySelectorAll(".timeline-row[data-resource-id]")];
  const selectedRow = rows.find((row) => row.dataset.resourceId === state.selectedResourceId && row.classList.contains("tree-root"))
    || rows.find((row) => row.dataset.resourceId === state.selectedResourceId);
  if (!selectedRow) return;
  const rowsById = new Map();
  rows.forEach((row) => {
    if (!rowsById.has(row.dataset.resourceId)) rowsById.set(row.dataset.resourceId, []);
    rowsById.get(row.dataset.resourceId).push(row);
  });
  const cursorPercent = timelinePercent(state.cursorNs);
  if (cursorPercent < 0 || cursorPercent > 100) return;
  const cursorX = timelineLaneWidth() + cursorPercent / 100 * state.trackWidth;
  const paths = [];
  const labels = [];
  let visibleIndex = 0;
  for (const edge of state.activeCorrelationEdges) {
    const otherId = edge.source === state.selectedResourceId ? edge.target : edge.source;
    const candidates = rowsById.get(otherId) || [];
    const otherRow = candidates.find((row) => (
      row.dataset.parentResourceId === state.selectedResourceId
      && row.dataset.relationshipType === edge.type
    )) || candidates.find((row) => row.dataset.parentResourceId === state.selectedResourceId)
      || candidates[0];
    if (!otherRow) continue;
    const y1 = selectedRow.offsetTop + selectedRow.offsetHeight / 2;
    const y2 = otherRow.offsetTop + otherRow.offsetHeight / 2;
    const x = cursorX + ((visibleIndex % 5) - 2) * 5;
    const controlX = x + (visibleIndex % 2 ? 26 : -26);
    paths.push(`<path class="timeline-correlation-link quality-${safeClass(edge.quality)}${edge.temporal_note?.includes("without") ? " uncertain" : ""}" d="M ${x} ${y1} C ${controlX} ${y1}, ${controlX} ${y2}, ${x} ${y2}"></path>`);
    labels.push(`<text x="${controlX}" y="${(y1 + y2) / 2 - 4}">${escapeHtml(relationshipDisplayLabel(edge.type))}</text>`);
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
  resourceId = canonicalResourceId(resourceId);
  if (!resourceId) return;
  const focusChanged = state.selectedResourceId !== resourceId;
  const previousKind = state.selectedResourceKind;
  state.selectedResourceId = resourceId;
  const record = state.resourceQuery?.items?.find((item) => item.resource_id === resourceId) || state.resourceById.get(resourceId);
  if (record) state.selectedResourceKind = record.kind || resourceKind(record, resourceId);
  if (!state.selectedResourceViewId && previousKind !== state.selectedResourceKind) {
    state.resourceOffset = 0;
    // The generic query is kind-scoped. Invalidate/reissue it through the
    // existing abort/latest-response controller; bundle selections stay put.
    requestResources();
  }
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
  refreshDashboardSelectionPresentation();
  if (state.graph) renderGraph();
  requestGraph();
  updateFabricNavigationLink();
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
  if (mode !== "custom") state.hiddenTimelineResourceIds.clear();
  state.laneMode = mode;
  if (mode === "all") {
    state.explicitLaneIds = new Set(isScaleMode() ? initialScaleLaneIds() : state.lanes.map((lane) => lane.resourceId));
    if (isScaleMode()) showToast("Showing representative lanes from the full resource catalog. Search Lanes to add any resource.");
  }
  if (mode === "custom" && !state.explicitLaneIds.size) state.explicitLaneIds = currentModeLaneIds();
  if (isScaleMode()) refreshScaleTimeline();
  else {
    renderTimeline();
    renderResourceTables();
  }
}

function setExplicitLaneVisibility(resourceId, visible) {
  resourceId = canonicalResourceId(resourceId);
  if (!resourceId) return false;
  if (state.laneMode !== "custom") state.explicitLaneIds = currentModeLaneIds();
  if (isScaleMode() && visible && !state.explicitLaneIds.has(resourceId) && state.explicitLaneIds.size >= MAX_SCALE_TIMELINE_LANES) {
    showToast(`A large-dataset timeline can show up to ${MAX_SCALE_TIMELINE_LANES} lanes at once.`);
    return false;
  }
  state.laneMode = "custom";
  if (visible) {
    state.hiddenTimelineResourceIds.delete(resourceId);
    state.explicitLaneIds.add(resourceId);
  } else {
    state.hiddenTimelineResourceIds.add(resourceId);
    state.explicitLaneIds.delete(resourceId);
  }
  renderTimeline();
  renderResourceTables();
  if (isScaleMode()) void refreshScaleTimeline();
  return true;
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
  const combinedMode = state.correlationTimelineView === "combined";
  const combined = combinedMode
    && state.selectedResourceId
    && !resourceHiddenFromTimeline(state.selectedResourceId);
  const hasCombinedAssociationLane = Boolean(
    combined
    && state.correlationTimelineExpanded
    && temporalRelationshipSpans().some((edge) => (
      edge.source === state.selectedResourceId || edge.target === state.selectedResourceId
    )),
  );
  const combinedLaneCount = combined ? 1 + Number(hasCombinedAssociationLane) : 0;
  const catalog = isScaleMode() ? state.resourceCatalogLanes : state.lanes;
  byId("visible-lane-count").textContent = (combinedMode ? `${combinedLaneCount} combined` : `${visibleCount} / ${catalog.length.toLocaleString()}`)
    + " · " + state.recordLaneRules.length + " logs";
  byId("lane-picker-toggle").disabled = false;
  byId("lane-picker-toggle").title = combinedMode
    ? combined
      ? "Switch to Separate to choose canonical lanes"
      : "The focused combined resource is hidden. Restore it in Resource tables or switch to Separate."
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
  const workspace = workspaceMetadata(dataset);
  const revision = workspace.revision_id || workspace.workspace_id || dataset.revision_id || "workspace";
  const matchedEventCount = Number(
    workspace.matched_event_count
    ?? workspace.event_count
    ?? dataset.event_count
    ?? state.eventByUid.size,
  );
  const resourceCount = Number(workspace.resource_count ?? state.resourceById.size);
  byId("revision-id").textContent = (isScaleMode() || isNodeWorkspace())
    ? `${revision} · ${matchedEventCount.toLocaleString()} matched events · ${resourceCount.toLocaleString()} resources`
    : revision;
  byId("disclosure-text").textContent = workspace.disclosure || "Analysis workspace loaded.";
  byId("gap-count").textContent = dataset.gaps?.length || 0;
  byId("metric-artifacts").textContent = dataset.summary?.parse?.artifacts ?? dataset.inventory?.members?.length ?? 0;
  byId("metric-parse").textContent = `${dataset.summary?.parse?.errors ?? 0} parse errors / ${dataset.summary?.parse?.skipped ?? 0} skipped`;
  byId("metric-fail").textContent = dataset.summary?.consistency?.fail ?? (dataset.findings || []).filter((item) => item.result === "fail").length;
  byId("metric-consistency").textContent = `${dataset.summary?.consistency?.pass ?? 0} pass / ${dataset.summary?.consistency?.unknown ?? 0} unknown`;
  byId("metric-exact").textContent = dataset.coverage?.exact_outputs ?? "-";
  byId("metric-coverage").textContent = `${dataset.coverage?.best_effort_outputs ?? 0} best effort`;
  byId("metric-unknown").textContent = dataset.coverage?.unknown_outputs ?? 0;
  renderWorkspaceIdentity();
}

function incidentCausalPath() {
  const descriptors = state.dataset?.causal_link_descriptors
    || state.dataset?.schema?.causal_link_types
    || [];
  const descriptorByType = new Map(
    (Array.isArray(descriptors) ? descriptors : [])
      .filter((item) => item?.link_type)
      .map((item) => [String(item.link_type), item]),
  );
  const links = (Array.isArray(state.dataset?.causal_links) ? state.dataset.causal_links : [])
    .map((link) => ({
      ...link,
      source: String(link.source_event_uid || link.source || ""),
      target: String(link.target_event_uid || link.target || ""),
    }))
    .filter((link) => link.source && link.target
      && state.eventByUid.has(link.source) && state.eventByUid.has(link.target));
  if (!links.length) return { events: [], links: [], descriptorByType };

  const incoming = new Set(links.map((link) => link.target));
  const roots = links.filter((link) => !incoming.has(link.source));
  const candidates = roots.length ? roots : links;
  candidates.sort((left, right) => {
    const leftTime = eventTime(state.eventByUid.get(left.source));
    const rightTime = eventTime(state.eventByUid.get(right.source));
    if (leftTime !== rightTime) return leftTime < rightTime ? -1 : 1;
    return left.source.localeCompare(right.source) || String(left.link_type || "").localeCompare(String(right.link_type || ""));
  });
  const outgoing = new Map();
  links.forEach((link) => {
    if (!outgoing.has(link.source)) outgoing.set(link.source, []);
    outgoing.get(link.source).push(link);
  });
  outgoing.forEach((items) => items.sort((left, right) => {
    const leftTime = eventTime(state.eventByUid.get(left.target));
    const rightTime = eventTime(state.eventByUid.get(right.target));
    if (leftTime !== rightTime) return leftTime < rightTime ? -1 : 1;
    return left.target.localeCompare(right.target) || String(left.link_type || "").localeCompare(String(right.link_type || ""));
  }));

  const pathEvents = [state.eventByUid.get(candidates[0].source)];
  const pathLinks = [];
  const visited = new Set([candidates[0].source]);
  let current = candidates[0].source;
  while (pathEvents.length < 4) {
    const link = (outgoing.get(current) || []).find((item) => !visited.has(item.target));
    if (!link) break;
    pathLinks.push(link);
    visited.add(link.target);
    pathEvents.push(state.eventByUid.get(link.target));
    current = link.target;
  }
  return { events: pathEvents.filter(Boolean), links: pathLinks, descriptorByType };
}

async function requestFailureIncidentPreview() {
  const deterministicFailures = () => [...state.eventByUid.values()]
    .filter(eventFailed)
    .sort((left, right) => {
      const leftTime = eventTime(left);
      const rightTime = eventTime(right);
      if (leftTime !== rightTime) return leftTime < rightTime ? -1 : 1;
      return String(left.event_uid || left.event_id || "").localeCompare(String(right.event_uid || right.event_id || ""));
    })
    .slice(0, 3);
  if (!usesServerWindowedHistory()) {
    state.failureIncidentPreview = deterministicFailures();
    return state.failureIncidentPreview;
  }
  try {
    const payload = await analysisRuntimeApi(revisionPath("events?outcome=failure&limit=3"));
    const events = (Array.isArray(payload?.items) ? payload.items : [])
      .slice()
      .sort((left, right) => {
        const leftTime = eventTime(left);
        const rightTime = eventTime(right);
        if (leftTime !== rightTime) return leftTime < rightTime ? -1 : 1;
        return String(left.event_uid || left.event_id || "").localeCompare(String(right.event_uid || right.event_id || ""));
      })
      .slice(0, 3);
    events.forEach((event) => {
      const uid = String(event?.event_uid || event?.event_id || "");
      if (uid) state.eventByUid.set(uid, { ...event, event_uid: uid });
    });
    state.failureIncidentPreview = events;
  } catch (_error) {
    // The incident preview is optional; timeline and event-log queries remain
    // usable when a plug-in supplies no failure preview.
    state.failureIncidentPreview = deterministicFailures();
  }
  return state.failureIncidentPreview;
}

function renderIncidentSummary() {
  const causalPath = incidentCausalPath();
  const explicitPath = causalPath.events.length > 1 && causalPath.links.length > 0;
  const selected = explicitPath
    ? causalPath.events
    : state.failureIncidentPreview.slice(0, 3);
  if (isTopologyNodeSnapshot() && !selected.length) {
    byId("incident-chain").innerHTML = nodeSnapshotUnavailableMarkup(
      "Event history is unavailable for this member snapshot",
      "The selected device plug-in supplied current resource state and local correlations, but no creation, modification, failure, or deletion events for this topology moment.",
    );
    return;
  }
  const heading = explicitPath ? "Plug-in declared causal path" : "Highlighted failures (unordered)";
  const bodyClass = explicitPath ? "incident-causal-path" : "incident-failure-list";
  byId("incident-chain").innerHTML = `<div class="chain-heading"><span>${heading}</span><span class="chain-latency">${selected.length} observations</span></div><div class="${bodyClass}" aria-label="${heading}">${selected.map((event, index) => {
    const subject = eventSubject(event); const uid = event.event_uid || event.event_id;
    const link = index ? causalPath.links[index - 1] : null;
    const arrow = explicitPath && link
      ? `<div class="chain-arrow"><span>${escapeHtml(causalLinkDisplayLabel(link.link_type, causalPath.descriptorByType))}</span><small>${escapeHtml(link.quality || link.provenance || "plug-in declared")}</small></div>`
      : "";
    return `${arrow}<button class="chain-node" style="--chain-color:${layerColor(subject.layer)}" data-event-uid="${escapeHtml(uid)}" type="button"><span>${escapeHtml(humanLayer(subject.layer))}</span><strong>${escapeHtml(formatValue(subject.raw_key ?? event.event_type))}</strong><small>${escapeHtml(`${event.action || event.operation || "event"} / ${eventOutcomeText(event)}`)}</small><time>${escapeHtml(formatOffset(eventTime(event)))}</time><code title="${escapeHtml(uid)}">${escapeHtml(uid)}</code></button>`;
  }).join("")}</div>`;
  byId("incident-chain").querySelectorAll("[data-event-uid]").forEach((button) => button.addEventListener("click", () => { selectEvent(button.dataset.eventUid, true); byId("timeline").scrollIntoView({ behavior: "smooth", block: "start" }); }));
}

function renderFindings() {
  const findings = state.dataset.findings || [];
  const counts = { pass: 0, fail: 0, unknown: 0 };
  findings.forEach((finding) => { counts[finding.result] = (counts[finding.result] || 0) + 1; });
  if (isTopologyNodeSnapshot() && !findings.length) {
    byId("finding-summary").innerHTML = '<span class="unknown">not supplied</span>';
    byId("findings-grid").innerHTML = nodeSnapshotUnavailableMarkup(
      "No consistency report was supplied",
      "This is not a zero-finding result. The topology-member plug-ins did not provide cross-layer consistency findings in this point-in-time projection.",
    );
    return;
  }
  byId("finding-summary").innerHTML = ["pass", "fail", "unknown"].map((result) => `<span class="${result}">${counts[result]} ${result}</span>`).join("");
  byId("findings-grid").innerHTML = findings.map((finding) => `<article class="finding-card"><span class="finding-result ${escapeHtml(finding.result)}">${escapeHtml(finding.result)}</span><div><h3>${escapeHtml(titleCase(finding.rule_id))}</h3><p>${escapeHtml(finding.summary)}</p><code>${escapeHtml((finding.resources || []).join(" / "))}</code></div></article>`).join("") || '<div class="empty-state">No consistency findings in this workspace.</div>';
}

function firstArray(...values) {
  return values.find((value) => Array.isArray(value)) || [];
}

function topologyProjectionId(item) {
  return String(item?.projection_id ?? item?.id ?? item?.name ?? "");
}

function topologyPerspectiveId(item) {
  return String(item?.status_perspective_id ?? item?.perspective_id ?? item?.layer_id ?? item?.id ?? item?.name ?? "");
}

function topologyNodeId(item) {
  return String(item?.node_id ?? item?.id ?? item?.name ?? "");
}

function fallbackTopologyCapabilities() {
  const nodeMap = new Map();
  for (const resource of state.resourceById.values()) {
    const nodeId = String(resource.node_id ?? resource.node ?? resource.device_id ?? "");
    if (nodeId && !nodeMap.has(nodeId)) nodeMap.set(nodeId, { node_id: nodeId, label: nodeId });
  }
  const declaredNodes = firstArray(
    state.dataset?.topology_nodes,
    state.dataset?.nodes,
    state.dataset?.schema?.topology_nodes,
  );
  declaredNodes.forEach((item) => {
    const nodeId = topologyNodeId(item);
    if (nodeId) nodeMap.set(nodeId, item);
  });
  if (!nodeMap.size) {
    const nodeId = workspaceNodeId();
    nodeMap.set(nodeId, { node_id: nodeId, label: topologyNodeSnapshotLabel() });
  }

  const layers = [...state.layerMeta.entries()].map(([layerId, descriptor]) => ({
    status_perspective_id: layerId,
    layer_id: layerId,
    label: descriptor.label || humanLayer(layerId),
    description: "Resource status reported by this layer.",
  }));
  if (!layers.length) layers.push({ status_perspective_id: "observed", layer_id: "observed", label: "Observed status" });

  return {
    projections: [{
      projection_id: "resource-relationships",
      label: "Resource relationships",
      description: "Generic time-valid resources and relationships retained by the core.",
    }],
    status_perspectives: layers,
    nodes: [...nodeMap.values()].slice(0, MAX_TOPOLOGY_NODE_ROWS),
    defaults: {
      projection_id: "resource-relationships",
      status_perspective_id: topologyPerspectiveId(layers[0]),
      clock_policy: "strict",
    },
    time_bounds: {
      start_ns: state.viewStartNs.toString(),
      end_ns: state.viewEndNs.toString(),
    },
    capability_source: "frontend_fallback",
  };
}

function normalizeTopologyCapabilities(raw) {
  const fallback = fallbackTopologyCapabilities();
  const projections = firstArray(
    raw?.projections,
    raw?.topology_projections,
    raw?.providers,
    raw?.schema?.topology_projections,
  ).filter((item) => topologyProjectionId(item));
  const perspectives = firstArray(
    raw?.status_perspectives,
    raw?.perspectives,
    raw?.status_layers,
    raw?.schema?.status_perspectives,
  ).filter((item) => topologyPerspectiveId(item));
  const nodes = firstArray(raw?.nodes, raw?.node_descriptors, raw?.scope?.nodes)
    .filter((item) => topologyNodeId(item))
    .slice(0, MAX_TOPOLOGY_NODE_ROWS);
  return {
    ...raw,
    projections: projections.length ? projections : fallback.projections,
    status_perspectives: perspectives.length ? perspectives : fallback.status_perspectives,
    nodes: nodes.length ? nodes : fallback.nodes,
    defaults: { ...fallback.defaults, ...(raw?.defaults || {}) },
    time_bounds: raw?.time_bounds || fallback.time_bounds,
    capability_source: raw?.capability_source || raw?.source || fallback.capability_source,
  };
}

async function requestTopologyCapabilities() {
  let raw = state.dataset?.topology_capabilities || state.dataset?.schema?.topology || {
    projections: state.dataset?.schema?.topology_projections,
    status_perspectives: state.dataset?.schema?.status_perspectives,
    nodes: state.dataset?.topology_nodes || state.dataset?.nodes,
    defaults: state.dataset?.topology_defaults,
    capability_source: "workspace_schema",
  };
  if (!isTopologyNodeSnapshot()) {
    try {
      raw = await analysisRuntimeApi(revisionPath("topology/capabilities"));
    } catch (_error) {
      // A local projection keeps the frontend reviewable while the versioned API is implemented.
    }
  }
  state.topologyCapabilities = normalizeTopologyCapabilities(raw || {});
  renderTopologyControls();
}

function renderTopologyControlNotes() {
  const capabilities = state.topologyCapabilities;
  if (!capabilities) return;
  const projectionId = byId("topology-projection")?.value;
  const perspectiveId = byId("topology-perspective")?.value;
  const projection = capabilities.projections.find((item) => topologyProjectionId(item) === projectionId);
  const perspective = capabilities.status_perspectives.find((item) => topologyPerspectiveId(item) === perspectiveId);
  if (byId("topology-projection-note")) {
    byId("topology-projection-note").textContent = projection?.description || "Plug-in-defined connectivity semantics";
  }
  if (byId("topology-perspective-note")) {
    byId("topology-perspective-note").textContent = perspective?.description
      || `${perspective?.layer_id ? `${humanLayer(perspective.layer_id)} layer` : "Selected layer"} supplying operational state`;
  }
}

function syncTopologyTimeEditors() {
  const basisKind = byId("topology-basis-kind")?.value || "absolute_time";
  if (byId("topology-absolute-editor")) byId("topology-absolute-editor").hidden = basisKind !== "absolute_time";
  if (byId("topology-relative-editor")) byId("topology-relative-editor").hidden = basisKind !== "relative_to_watermark";
}

function renderTopologyPerspectiveOptions(preferredPerspective = "") {
  const capabilities = state.topologyCapabilities;
  const projectionId = byId("topology-projection")?.value;
  const perspectiveSelect = byId("topology-perspective");
  if (!capabilities || !perspectiveSelect) return;
  const projection = capabilities.projections.find((item) => topologyProjectionId(item) === projectionId);
  const supportedIds = new Set(firstArray(
    projection?.supported_status_perspective_ids,
    projection?.status_perspective_ids,
    projection?.perspectives,
  ).map((item) => typeof item === "object" ? topologyPerspectiveId(item) : String(item)));
  const perspectives = supportedIds.size
    ? capabilities.status_perspectives.filter((item) => supportedIds.has(topologyPerspectiveId(item)))
    : capabilities.status_perspectives;
  perspectiveSelect.innerHTML = perspectives.map((item) => {
    const id = topologyPerspectiveId(item);
    const layer = item.layer_id && String(item.layer_id) !== id ? ` / ${humanLayer(item.layer_id)}` : "";
    return `<option value="${escapeHtml(id)}">${escapeHtml(`${item.label || item.display_name || titleCase(id)}${layer}`)}</option>`;
  }).join("");
  const defaultPerspective = projection?.default_status_perspective_id
    || capabilities.defaults.status_perspective_id
    || topologyPerspectiveId(perspectives[0]);
  perspectiveSelect.value = perspectives.some((item) => topologyPerspectiveId(item) === preferredPerspective)
    ? preferredPerspective
    : defaultPerspective;
}

function renderTopologyControls() {
  const capabilities = state.topologyCapabilities;
  const projectionSelect = byId("topology-projection");
  const perspectiveSelect = byId("topology-perspective");
  if (!capabilities || !projectionSelect || !perspectiveSelect) return;
  const previousProjection = projectionSelect.value || navigationContext.projectionId;
  const previousPerspective = perspectiveSelect.value || navigationContext.perspectiveId;
  projectionSelect.innerHTML = capabilities.projections.map((item) => {
    const id = topologyProjectionId(item);
    return `<option value="${escapeHtml(id)}">${escapeHtml(item.label || item.display_name || titleCase(id))}</option>`;
  }).join("");
  projectionSelect.value = capabilities.projections.some((item) => topologyProjectionId(item) === previousProjection)
    ? previousProjection
    : capabilities.defaults.projection_id || topologyProjectionId(capabilities.projections[0]);
  renderTopologyPerspectiveOptions(previousPerspective);
  byId("topology-clock-policy").value = navigationContext.clockPolicy || capabilities.defaults.clock_policy || "strict";
  // A relative cross-node query is opened at the exact resolved member time. Reapplying
  // its watermark offset here could drift if a newer dump arrived after reconstruction.
  if (navigationContext.timeNs) byId("topology-basis-kind").value = "absolute_time";
  if (!byId("topology-absolute-time").value) byId("topology-absolute-time").value = state.cursorNs.toString();
  if (!byId("topology-absolute-clock-domain").value) {
    byId("topology-absolute-clock-domain").value = capabilities.defaults.absolute_clock_domain
      || workspaceMetadata().capture_clock_domain
      || "utc";
  }
  renderTopologyControlNotes();
  syncTopologyTimeEditors();
  renderTopologyNavigationBanner();
  updateFabricNavigationLink();
}

function parseSignedSecondsNs(value) {
  const match = String(value ?? "").trim().match(/^([+-]?)(\d+)(?:\.(\d{0,9}))?$/);
  if (!match) throw new Error("Use signed seconds with up to 9 decimal places, for example -5 or -0.250.");
  const magnitude = BigInt(match[2]) * 1_000_000_000n
    + BigInt((match[3] || "").padEnd(9, "0") || "0");
  return match[1] === "-" ? -magnitude : magnitude;
}

function topologyRequestBody() {
  const projectionId = byId("topology-projection").value;
  const perspectiveId = byId("topology-perspective").value;
  const basisKind = byId("topology-basis-kind").value;
  let basis;
  if (basisKind === "absolute_time") {
    const raw = byId("topology-absolute-time").value.trim();
    if (!/^[+-]?\d+$/.test(raw)) throw new Error("Absolute time must be an integer nanosecond timestamp.");
    basis = {
      kind: "absolute_time",
      clock_domain: byId("topology-absolute-clock-domain").value.trim() || "utc",
      time_ns: BigInt(raw).toString(),
      clock_policy: byId("topology-clock-policy").value,
    };
  } else {
    const clockPolicy = byId("topology-clock-policy").value;
    const offsetNs = parseSignedSecondsNs(byId("topology-relative-seconds").value);
    if (offsetNs > 0n) throw new Error("A watermark-relative time must be zero or in the past.");
    basis = {
      kind: "relative_to_watermark",
      offset_ns: offsetNs.toString(),
      clock_policy: clockPolicy,
      scopes: (state.topologyCapabilities?.nodes || []).map((node) => ({
        node_id: topologyNodeId(node),
        status_perspective_id: perspectiveId,
        topology_projection_id: projectionId,
      })),
    };
  }
  const basisTimeNs = basis.kind === "absolute_time"
    ? toNs(basis.time_ns, state.cursorNs)
    : state.viewEndNs + toNs(basis.offset_ns, 0n);
  const changeStartNs = basisTimeNs - TOPOLOGY_HISTORY_WINDOW_NS > state.viewStartNs
    ? basisTimeNs - TOPOLOGY_HISTORY_WINDOW_NS
    : state.viewStartNs;
  return {
    projection_id: projectionId,
    status_perspective_id: perspectiveId,
    ...(navigationContext.nodeId ? { node_ids: [navigationContext.nodeId] } : {}),
    ...(navigationContext.memberId ? { member_id: navigationContext.memberId } : {}),
    ...(navigationContext.contextId ? { navigation_context_id: navigationContext.contextId } : {}),
    basis,
    clock_policy: byId("topology-clock-policy").value,
    include: ["resources", "relationships", "inferred_connectivity", "changes"],
    limit: MAX_TOPOLOGY_RESOURCE_ROWS,
    resource_limit: MAX_TOPOLOGY_RESOURCE_ROWS,
    connectivity_limit: MAX_TOPOLOGY_CONNECTIVITY_ROWS,
    change_start_ns: changeStartNs.toString(),
    change_limit: MAX_TOPOLOGY_CHANGE_ROWS,
  };
}

function localTopologyEvents(resolvedTimeNs) {
  const candidates = [];
  const seen = new Set();
  const add = (event) => {
    const id = String(event?.event_uid || event?.event_id || "");
    if (!id || seen.has(id) || eventTime(event) > resolvedTimeNs) return;
    seen.add(id);
    candidates.push(event);
  };
  const events = state.dataset?.events || [];
  events.slice(Math.max(0, events.length - 5000)).forEach(add);
  state.lanes.forEach((lane) => lane.marks.forEach((mark) => add(mark.event)));
  candidates.sort((left, right) => eventTime(left) > eventTime(right) ? -1 : eventTime(left) < eventTime(right) ? 1 : 0);
  return candidates.slice(0, MAX_TOPOLOGY_CHANGE_ROWS).map((event) => {
    const subject = eventSubject(event);
    const properties = event?.attributes?.properties || event?.properties || {};
    return {
      change_id: event.event_uid || event.event_id,
      time_ns: eventTime(event).toString(),
      node_id: subject.node_id || event.node_id || workspaceNodeId(),
      change_type: event.effect_type || event.action || event.operation || "status_change",
      subject_id: canonicalResourceForSubject(subject, event),
      before: properties.before ?? properties.previous_status,
      after: properties.after ?? properties.status ?? eventStatus(event),
      cause_event_id: event.event_uid || event.event_id,
      quality: event.quality || "unknown",
    };
  });
}

function localTopologyQuery(request, apiError = null) {
  const requested = request.basis.kind === "absolute_time"
    ? toNs(request.basis.time_ns, state.cursorNs)
    : state.viewEndNs + toNs(request.basis.offset_ns, 0n);
  const resolvedTimeNs = requested < state.viewStartNs
    ? state.viewStartNs
    : requested > state.viewEndNs ? state.viewEndNs : requested;
  const selectedFirst = state.selectedResourceId ? [state.selectedResourceId] : [];
  const resourceIds = [...new Set([...selectedFirst, ...state.resourceById.keys()])]
    .slice(0, MAX_TOPOLOGY_RESOURCE_ROWS);
  const defaultNodeId = topologyNodeId(state.topologyCapabilities?.nodes?.[0]) || workspaceNodeId();
  const resources = resourceIds.map((resourceId) => {
    const record = state.resourceById.get(resourceId) || { resource_id: resourceId };
    const lane = state.laneByResource.get(resourceId);
    const temporal = lane
      ? statusAtLane(lane, resolvedTimeNs)
      : { exists: true, status: record.status || record.state?.status || "observed", properties: record.state || record.properties || {} };
    return {
      resource_id: resourceId,
      label: resourceLabel(record, resourceId),
      kind: resourceKind(record, resourceId),
      node_id: record.node_id || record.node || defaultNodeId,
      layer_id: resourceLayer(record, resourceId),
      exists: temporal.exists,
      status: temporal.status,
      properties: temporal.properties,
      quality: record.quality || "unknown",
    };
  });
  const graph = localGraphAt(resolvedTimeNs);
  const relationships = graph.edges.slice(0, MAX_TOPOLOGY_CONNECTIVITY_ROWS).map((edge) => ({
    relationship_id: edge.id,
    source_resource_id: edge.source,
    target_resource_id: edge.target,
    relation_type: edge.type,
    status: "active",
    quality: edge.quality,
    inferred: Boolean(edge.inferred),
  }));
  const nodeTimes = (state.topologyCapabilities?.nodes || [{ node_id: defaultNodeId }]).map((node) => {
    const nodeId = topologyNodeId(node);
    const uncertaintyNs = toNs(node.clock_uncertainty_ns ?? node.uncertainty_ns, 0n);
    const clockStatus = node.clock_status || node.status || "resolved";
    return {
      node_id: nodeId,
      label: node.label || node.display_name || nodeId,
      status: clockStatus,
      local_time_ns: (resolvedTimeNs + toNs(node.clock_offset_ns, 0n)).toString(),
      absolute_min_ns: (resolvedTimeNs - uncertaintyNs).toString(),
      absolute_max_ns: (resolvedTimeNs + uncertaintyNs).toString(),
      uncertainty_ns: uncertaintyNs.toString(),
      mapping_method: node.clock_mapping_method || "capture clock",
      watermark_ns: state.viewEndNs.toString(),
    };
  });
  return {
    projection_id: request.projection_id,
    status_perspective_id: request.status_perspective_id,
    clock_policy: request.clock_policy,
    resolved_basis: {
      ...request.basis,
      requested_time_ns: requested.toString(),
      resolved_time_ns: resolvedTimeNs.toString(),
      scope_end_ns: state.viewEndNs.toString(),
      label: request.basis.kind === "absolute_time" ? "Absolute time" : "Relative capture vector",
    },
    node_times: nodeTimes,
    resources,
    relationships: relationships.filter((item) => !item.inferred),
    inferred_connectivity: relationships.filter((item) => item.inferred),
    changes: localTopologyEvents(resolvedTimeNs),
    completeness: {
      complete: false,
      limitations: [
        "Frontend fallback: the versioned topology API was unavailable.",
        "Only currently loaded resources and relationships are projected.",
        ...(requested !== resolvedTimeNs ? ["Requested time was clamped to the loaded capture range."] : []),
      ],
    },
    source: "frontend_fallback",
    api_error: apiError,
  };
}

function topologyResultResources(payload = state.topologyQuery) {
  return firstArray(payload?.resources, payload?.items, payload?.snapshot?.resources, payload?.status?.resources)
    .slice(0, MAX_TOPOLOGY_RESOURCE_ROWS);
}

function topologyResultRelationships(payload = state.topologyQuery) {
  return firstArray(payload?.relationships, payload?.snapshot?.relationships, payload?.graph?.relationships, payload?.graph?.edges)
    .slice(0, MAX_TOPOLOGY_CONNECTIVITY_ROWS)
    .map((item) => ({ ...item, inferred: Boolean(item.inferred) }));
}

function topologyResultInferred(payload = state.topologyQuery) {
  return firstArray(payload?.inferred_connectivity, payload?.connectivity, payload?.inferred_links, payload?.snapshot?.inferred_connectivity)
    .slice(0, MAX_TOPOLOGY_CONNECTIVITY_ROWS)
    .map((item) => ({ ...item, inferred: true }));
}

function topologyResultChanges(payload = state.topologyQuery) {
  return firstArray(payload?.changes, payload?.history?.changes, payload?.change_stream?.items)
    .slice(0, MAX_TOPOLOGY_CHANGE_ROWS);
}

function topologyResultNodeTimes(payload = state.topologyQuery) {
  return firstArray(payload?.node_times, payload?.resolved_nodes, payload?.resolved_basis?.node_times, payload?.capture_vector?.nodes)
    .slice(0, MAX_TOPOLOGY_NODE_ROWS);
}

function topologyObjectPreview(value, limit = 4) {
  if (value === null || value === undefined || value === "") return "unknown";
  if (Array.isArray(value)) return value.slice(0, limit).map((item) => topologyObjectPreview(item, 2)).join(", ") + (value.length > limit ? ` +${value.length - limit}` : "");
  if (typeof value !== "object") return String(value);
  const entries = Object.entries(value).slice(0, limit);
  const text = entries.map(([key, item]) => `${key}=${typeof item === "object" ? topologyObjectPreview(item, 2) : item}`).join("; ");
  return text + (Object.keys(value).length > limit ? "; ..." : "");
}

function topologyTimeLabel(value) {
  if (value === null || value === undefined || value === "") return "open";
  const ns = toNs(value);
  const epochSeconds = ns / 1_000_000_000n;
  if (epochSeconds >= 946_684_800n && epochSeconds <= 7_258_118_400n) {
    const millis = Number(ns / 1_000_000n);
    const date = new Date(millis);
    if (!Number.isNaN(date.getTime())) return `${date.toISOString()} / ${ns} ns`;
  }
  if (ns >= state.viewStartNs && ns <= state.viewEndNs) return `${formatOffset(ns)} / ${ns} ns`;
  return `${ns} ns`;
}

function topologyValidityLabel(item) {
  const start = item?.valid_from_ns ?? item?.validity?.start_ns ?? item?.validity?.from_ns;
  const end = item?.valid_to_ns ?? item?.validity?.end_ns ?? item?.validity?.to_ns;
  if (start === undefined && end === undefined) return "not supplied";
  return `${start === null || start === undefined ? "capture start" : topologyTimeLabel(start)} -> ${end === null || end === undefined ? "open" : topologyTimeLabel(end)}`;
}

function topologyReferenceId(value) {
  if (typeof value === "string") return canonicalResourceId(value);
  if (!value || typeof value !== "object") return null;
  return canonicalResourceId(value.resource_id)
    || canonicalResourceId(value.canonical_id)
    || canonicalResourceId(value.id)
    || null;
}

function topologyReferenceLabel(value) {
  if (value === null || value === undefined) return "unknown";
  const canonicalId = topologyReferenceId(value);
  if (canonicalId) return canonicalId;
  if (typeof value !== "object") return formatValue(value);
  const display = value.display ?? value.label ?? value.matcher_id ?? value.topology_node_id ?? value.node_id;
  return display === null || display === undefined ? formatValue(value) : formatValue(display);
}

function topologyBasisSummary(payload) {
  const basis = payload?.resolved_basis || payload?.basis || {};
  if (["relative_to_watermark", "relative_to_scope_end", "relative_capture_vector"].includes(basis.kind)) {
    const offset = basis.offset_ns ?? basis.requested?.offset_ns ?? 0;
    const simultaneity = basis.simultaneity === "not_implied"
      ? " Per-node times are a capture vector, not a simultaneous snapshot."
      : "";
    return `${basis.label || "Relative capture vector"}; ${formatDuration(offset)} from each selected layer watermark.${simultaneity}`;
  }
  const resolved = basis.resolved_time_ns ?? basis.requested_time_ns ?? basis.time_ns
    ?? basis.requested?.time_ns ?? basis.requested?.timestamp_ns;
  return resolved !== undefined ? `Absolute request resolved around ${topologyTimeLabel(resolved)}.` : "Resolved basis supplied by the topology provider.";
}

function renderTopologyQueryState() {
  const target = byId("topology-query-state");
  const button = document.querySelector(".topology-run-query");
  if (!target || !button) return;
  button.disabled = state.topologyQueryPending;
  button.textContent = state.topologyQueryPending ? "Reconstructing..." : "Reconstruct topology";
  if (state.topologyQueryPending) {
    target.innerHTML = '<span class="topology-state-chip"><strong>Querying</strong> per-node temporal status...</span>';
    return;
  }
  const payload = state.topologyQuery;
  if (!payload) {
    target.innerHTML = '<div class="empty-state">Choose a projection, status perspective, and time basis.</div>';
    return;
  }
  const projection = state.topologyCapabilities?.projections.find((item) => topologyProjectionId(item) === (payload.projection_id || byId("topology-projection").value));
  const perspective = state.topologyCapabilities?.status_perspectives.find((item) => topologyPerspectiveId(item) === (payload.status_perspective_id || byId("topology-perspective").value));
  const completeness = payload.completeness || {};
  const limitations = firstArray(completeness.limitations, payload.limitations);
  if (completeness.remote_status_note) limitations.push(completeness.remote_status_note);
  if (completeness.incomplete_nodes?.length) {
    limitations.push(`Incomplete node status: ${completeness.incomplete_nodes.join(", ")}`);
  }
  target.innerHTML = [
    `<span class="topology-state-chip">Projection <strong>${escapeHtml(projection?.label || payload.projection_id || "unknown")}</strong></span>`,
    `<span class="topology-state-chip">Status <strong>${escapeHtml(perspective?.label || payload.status_perspective_id || "unknown")}</strong></span>`,
    `<span class="topology-state-chip">Clock <strong>${escapeHtml(payload.clock_policy || byId("topology-clock-policy").value)}</strong></span>`,
    `<span class="topology-state-chip ${state.topologyUsingFallback ? "is-warning" : ""}">Source <strong>${escapeHtml(state.topologyUsingFallback ? "local fallback" : payload.source || "versioned API")}</strong></span>`,
    `<span class="topology-state-chip ${completeness.complete === false ? "is-warning" : ""}">Coverage <strong>${escapeHtml(completeness.complete === true ? "complete" : completeness.complete === false ? "partial" : "not declared")}</strong></span>`,
    ...limitations.slice(0, 3).map((item) => `<span class="topology-state-chip is-warning">${escapeHtml(item)}</span>`),
  ].join("");
}

function renderTopologyNodeTimes() {
  const nodeTimes = topologyResultNodeTimes();
  byId("topology-basis-summary").textContent = state.topologyQuery ? topologyBasisSummary(state.topologyQuery) : "No topology query has run.";
  byId("topology-node-times").innerHTML = nodeTimes.map((item) => {
    const nodeId = topologyNodeId(item);
    const status = item.resolution || item.status || item.resolution_status || item.clock_status || item.reason_code || item.quality || "unknown";
    const localTime = item.local_time_ns ?? item.resolved_local_time_ns ?? item.time_ns;
    const localMinimum = item.local_min_ns ?? item.local_range?.min_ns;
    const localMaximum = item.local_max_ns ?? item.local_range?.max_ns;
    const minimum = item.absolute_min_ns ?? item.absolute_range?.min_ns;
    const maximum = item.absolute_max_ns ?? item.absolute_range?.max_ns;
    const uncertainty = item.uncertainty_ns ?? item.clock_uncertainty_ns
      ?? (minimum !== undefined && maximum !== undefined ? (toNs(maximum) - toNs(minimum)) / 2n : undefined);
    const localLabel = localTime !== undefined
      ? topologyTimeLabel(localTime)
      : localMinimum !== undefined || localMaximum !== undefined
        ? `${localMinimum === undefined ? "unknown" : topologyTimeLabel(localMinimum)} -> ${localMaximum === undefined ? "unknown" : topologyTimeLabel(localMaximum)}`
        : "unknown";
    const absoluteWindow = minimum !== undefined || maximum !== undefined
      ? `${minimum === undefined ? "unknown" : topologyTimeLabel(minimum)} -> ${maximum === undefined ? "unknown" : topologyTimeLabel(maximum)}`
      : "Absolute mapping not supplied";
    const statusClass = item.status_class ?? item.resolution_class ?? item.tone ?? "unknown";
    return `<article class="topology-node-time ${statusClassPresentation({ status_class: statusClass })}">
      <header><strong>${escapeHtml(item.label || item.display_name || nodeId || "Unnamed node")}</strong><span>${escapeHtml(titleCase(status))}</span></header>
      <code>${escapeHtml(`local ${localLabel}${item.local_clock_domain || item.clock_domain ? ` / ${item.local_clock_domain || item.clock_domain}` : ""}`)}</code>
      <small>${escapeHtml(absoluteWindow)}</small>
      <small>${escapeHtml(`${item.mapping_method || item.clock_mapping_method || "mapping unknown"} / ${item.mapping_quality || item.quality || "quality unknown"} / uncertainty ${uncertainty === undefined ? "unknown" : formatDuration(uncertainty)}`)}</small>
      <small>${escapeHtml(item.resources_available === false ? "Topology/clock observation only; resource state unavailable" : "Resource state available")}</small>
      ${item.watermark_ns === undefined ? "" : `<small>${escapeHtml(`layer watermark ${topologyTimeLabel(item.watermark_ns)}`)}</small>`}
    </article>`;
  }).join("") || '<div class="topology-empty-list">No per-node clock resolution was returned. The snapshot cannot be treated as synchronized.</div>';
}

function renderTopologySummary() {
  const resources = topologyResultResources();
  const relationships = topologyResultRelationships();
  const inferred = topologyResultInferred();
  const changes = topologyResultChanges();
  const nodeTimes = topologyResultNodeTimes();
  const existing = resources.filter((item) => item.exists === true || String(item.exists).toLowerCase() === "true").length;
  const unresolvedNodes = nodeTimes.filter((item) => !["exact", "bounded", "local_exact"].includes(String(item.resolution || item.status || item.resolution_status || item.clock_status))).length;
  const cards = [
    ["Resources returned", resources.length, `${existing} explicitly exist at this basis`],
    ["Graph records", relationships.length + inferred.length, `${inferred.length} explicitly inferred`],
    ["Node clocks", nodeTimes.length, `${unresolvedNodes} ambiguous or unaligned`],
    ["Historical changes", changes.length, "bounded replay window"],
  ];
  byId("topology-summary-grid").innerHTML = cards.map(([label, value, note]) => `<article class="topology-summary-card"><span>${escapeHtml(label)}</span><strong>${escapeHtml(Number(value).toLocaleString())}</strong><small>${escapeHtml(note)}</small></article>`).join("");
}

function renderTopologyResources() {
  const resources = topologyResultResources();
  const total = state.topologyQuery?.counts?.resources?.total_count
    ?? state.topologyQuery?.counts?.resource_count
    ?? state.topologyQuery?.completeness?.resources?.total_count
    ?? state.topologyQuery?.resource_count
    ?? resources.length;
  const truncated = state.topologyQuery?.completeness?.resources?.truncated;
  byId("topology-resource-count").textContent = `${resources.length.toLocaleString()} shown / ${Number(total).toLocaleString()} matching${truncated ? " / page truncated" : ""}`;
  byId("topology-resource-body").innerHTML = resources.slice(0, MAX_TOPOLOGY_RESOURCE_ROWS).map((item) => {
    const reference = item.resource_id ?? item.id ?? item.resource;
    const id = topologyReferenceId(reference);
    const displayId = topologyReferenceLabel(reference);
    const statusValue = item.status?.value ?? item.status ?? item.operational_status ?? item.state?.status ?? "unknown";
    const exists = resourceExistenceLabel(item.exists);
    const properties = item.properties ?? item.status?.properties ?? item.state;
    return `<tr>
      <td>${id ? `<button class="topology-resource-button" type="button" data-topology-resource="${escapeHtml(id)}"><strong>${escapeHtml(item.label || item.display_name || displayId)}</strong><code title="${escapeHtml(id)}">${escapeHtml(id)}</code></button>` : `<span class="topology-resource-button"><strong>${escapeHtml(item.label || item.display_name || "Unidentified resource")}</strong><code>${escapeHtml(displayId)}</code></span>`}</td>
      <td class="topology-cell-stack"><strong>${escapeHtml(item.node_id || item.node || "node unknown")}</strong><small>${escapeHtml(`${item.status_layer || item.layer_id || item.layer || "status layer unknown"}${item.native_layer && item.native_layer !== (item.status_layer || item.layer_id || item.layer) ? ` status / ${item.native_layer} identity` : ""}`)}</small></td>
      <td class="topology-cell-stack"><span class="topology-status ${statusClassPresentation({ status_class: item.status_class ?? item.status?.status_class ?? "unknown" })}">${escapeHtml(`${exists} / ${topologyObjectPreview(statusValue, 2)}`)}</span><code title="${escapeHtml(topologyObjectPreview(properties, 8))}">${escapeHtml(topologyObjectPreview(properties))}</code></td>
      <td class="topology-cell-stack"><code title="${escapeHtml(topologyValidityLabel(item))}">${escapeHtml(topologyValidityLabel(item))}</code></td>
      <td class="topology-cell-stack"><strong>${escapeHtml(item.quality || item.confidence || "unknown")}</strong><small>${escapeHtml(`${firstArray(item.evidence, item.evidence_refs).length} evidence refs`)}</small></td>
    </tr>`;
  }).join("") || '<tr><td class="topology-empty-row" colspan="5">No resources were returned for this projection, status perspective, and time.</td></tr>';
  byId("topology-resource-body").querySelectorAll("[data-topology-resource]").forEach((button) => {
    button.addEventListener("click", () => selectResource(button.dataset.topologyResource));
  });
}

function renderTopologyConnectivity() {
  const relationships = topologyResultRelationships();
  const inferred = topologyResultInferred();
  const records = [...inferred, ...relationships].slice(0, MAX_TOPOLOGY_CONNECTIVITY_ROWS);
  const countedRelationships = state.topologyQuery?.counts?.relationships?.total_count;
  const countedInferred = state.topologyQuery?.counts?.inferred_connectivity?.total_count;
  const total = countedRelationships !== undefined || countedInferred !== undefined
    ? Number(countedRelationships || 0) + Number(countedInferred || 0)
    : state.topologyQuery?.counts?.connectivity_count
    ?? state.topologyQuery?.connectivity_count
    ?? inferred.length + relationships.length;
  const truncated = state.topologyQuery?.completeness?.relationships?.truncated;
  byId("topology-connectivity-count").textContent = `${records.length.toLocaleString()} shown / ${Number(total).toLocaleString()} matching${truncated ? " / page truncated" : ""}`;
  byId("topology-connectivity-body").innerHTML = records.map((item) => {
    const source = topologyReferenceLabel(item.source_resource_id ?? item.source ?? item.from ?? item.endpoint_a);
    const target = topologyReferenceLabel(item.target_resource_id ?? item.target ?? item.to ?? item.match_reference ?? item.endpoint_b);
    const relation = item.relation_type || item.type || item.kind || item.inference?.rule_id || "related";
    const relationPresentation = relationshipPresentation(typeof relation === "string" ? relation : null);
    const status = item.operational?.status ?? item.status?.value ?? item.status ?? item.state
      ?? (item.present === true ? "present" : item.present === false ? "absent" : "unknown");
    const statusDetail = item.operational?.reason && item.operational.reason !== status
      ? `${status} / ${item.operational.reason}`
      : status;
    const evidenceCount = firstArray(item.evidence, item.evidence_refs, item.source_resources, item.status_sources).length;
    return `<tr>
      <td><div class="topology-connection"><code title="${escapeHtml(source)}">${escapeHtml(source)}</code><span>${relationPresentation.directed === true ? "→" : "—"}</span><code title="${escapeHtml(target)}">${escapeHtml(target)}</code></div></td>
      <td><div class="topology-relationship-kind"><strong>${escapeHtml(relationPresentation.displayLabel)}</strong>${item.inferred ? '<span class="topology-inferred-tag">inferred</span>' : ""}</div></td>
      <td><span class="topology-status ${statusClassPresentation({ status_class: item.status_class ?? item.operational?.status_class ?? item.status?.status_class ?? "unknown" })}">${escapeHtml(topologyObjectPreview(statusDetail, 2))}</span></td>
      <td class="topology-cell-stack"><code title="${escapeHtml(topologyValidityLabel(item))}">${escapeHtml(topologyValidityLabel(item))}</code><small>${escapeHtml(`${item.quality || item.confidence || "quality unknown"} / ${evidenceCount} evidence refs`)}</small></td>
    </tr>`;
  }).join("") || '<tr><td class="topology-empty-row" colspan="4">No relationships or inferred connectivity were active at this basis.</td></tr>';
}

function renderTopologyChanges() {
  const changes = topologyResultChanges().slice(0, MAX_TOPOLOGY_CHANGE_ROWS);
  const total = state.topologyQuery?.counts?.changes?.total_count
    ?? state.topologyQuery?.counts?.changes?.minimum_total_count
    ?? state.topologyQuery?.counts?.change_count
    ?? state.topologyQuery?.change_count
    ?? changes.length;
  const totalIsExact = state.topologyQuery?.counts?.changes?.total_count_is_exact !== false;
  const truncated = state.topologyQuery?.completeness?.changes_truncated;
  byId("topology-change-count").textContent = `${changes.length.toLocaleString()} shown / ${totalIsExact ? "" : "at least "}${Number(total).toLocaleString()} matching${truncated ? " / page truncated" : ""}`;
  byId("topology-change-list").innerHTML = changes.map((item) => {
    const time = item.time_ns ?? item.effective_time_ns ?? item.absolute_min_ns ?? item.local_time_ns;
    const relationshipSubject = [item.source, item.target].filter(Boolean).map(topologyReferenceLabel).join(" -> ");
    const subject = topologyReferenceLabel(item.subject_id ?? item.resource_id ?? item.relationship_id ?? item.subject
      ?? (item.resource_ids?.length ? item.resource_ids.join(", ") : relationshipSubject || undefined));
    const before = topologyObjectPreview(item.before ?? item.previous ?? item.old_value ?? item.operation ?? "event", 3);
    const applied = item.applied === true ? "applied" : item.applied === false ? "not applied" : undefined;
    const after = topologyObjectPreview(item.after ?? item.current ?? item.new_value ?? item.outcome ?? applied ?? "recorded", 3);
    return `<article class="topology-change">
      <div><strong>${escapeHtml(time === undefined ? "time unknown" : topologyTimeLabel(time))}</strong><small>${escapeHtml(item.node_id || item.node || "node unknown")}</small></div>
      <div><strong>${escapeHtml(titleCase(item.change_type || item.change_kind || item.operation || item.type || "change"))}</strong><small title="${escapeHtml(subject)}">${escapeHtml(subject)}</small></div>
      <code title="${escapeHtml(`${before} -> ${after}`)}">${escapeHtml(before)} <span class="topology-change-arrow">-&gt;</span> ${escapeHtml(after)}</code>
      <div><strong>${escapeHtml(item.quality || item.confidence || "unknown")}</strong><small>${escapeHtml(item.cause_event_id || item.event_uid ? `cause ${item.cause_event_id || item.event_uid}` : item.mapping_method || "cause not supplied")}</small></div>
    </article>`;
  }).join("") || '<div class="topology-empty-list">No historical status or connectivity changes were returned around this basis.</div>';
}

function renderTopologyResults() {
  renderTopologyQueryState();
  renderTopologyNodeTimes();
  renderTopologySummary();
  renderTopologyResources();
  renderTopologyConnectivity();
  renderTopologyChanges();
}

async function requestTopology(event) {
  event?.preventDefault();
  const errorTarget = byId("topology-query-error");
  let request;
  try {
    request = topologyRequestBody();
    errorTarget.textContent = "";
  } catch (error) {
    errorTarget.textContent = error.message;
    return;
  }
  abortLatestRequests("topologyAbortController");
  const requestId = ++state.topologyRequestId;
  state.topologyQueryPending = true;
  renderTopologyQueryState();
  let payload;
  let usingFallback = false;
  if (isTopologyNodeSnapshot()) {
    payload = localTopologyQuery(request, "bounded node snapshot");
    usingFallback = true;
  } else {
    const controller = beginLatestRequest("topologyAbortController");
    try {
      payload = await analysisRuntimeApi(revisionPath("topology/query"), {
        method: "POST",
        signal: controller.signal,
        body: JSON.stringify(request),
      });
    } catch (error) {
      if (requestWasAborted(error, controller)) return;
      payload = localTopologyQuery(request, error.message);
      usingFallback = true;
      if (requestId === state.topologyRequestId) {
        errorTarget.textContent = `Topology API unavailable; showing bounded local reconstruction (${error.message}).`;
      }
    }
    finishLatestRequest("topologyAbortController", controller);
  }
  if (requestId !== state.topologyRequestId) return;
  state.topologyQuery = payload;
  state.topologyUsingFallback = usingFallback;
  state.topologyQueryPending = false;
  renderTopologyResults();
}

function scheduleTopologyRefreshFromCursor() {
  const input = byId("topology-absolute-time");
  const basis = byId("topology-basis-kind");
  const follow = byId("topology-follow-cursor");
  if (!input || !basis || !follow || !follow.checked || basis.value !== "absolute_time") return;
  input.value = state.cursorNs.toString();
  if (!state.topologyCapabilities) return;
  window.clearTimeout(state.topologyTimer);
  state.topologyTimer = window.setTimeout(() => requestTopology(), 260);
}

function renderInventory() {
  const inventory = state.dataset.inventory || { members: [] };
  const members = Array.isArray(inventory.members) ? inventory.members : [];
  if (isTopologyNodeSnapshot() && !members.length) {
    byId("inventory-summary").textContent = `${topologyNodeSnapshotLabel()} · bounded node snapshot`;
    byId("inventory-tree").innerHTML = nodeSnapshotUnavailableMarkup(
      "Archive inventory is not part of this snapshot",
      "The topology-member plug-ins returned projected resource state, not the member's original dump archive or container manifest.",
    );
    return;
  }
  const nested = members.filter((item) => item.kind === "nested-archive").length;
  const declaredSize = inventory.compressed_size ?? members.reduce(
    (total, item) => total + Number(item.size ?? item.uncompressed_size ?? item.compressed_size ?? 0),
    0,
  );
  byId("inventory-summary").textContent = `${inventory.archive || inventory.label || inventory.mode || "workspace input"} / ${formatBytes(declaredSize)} / ${members.length} top-level files / ${nested} nested archives`;
  byId("inventory-tree").innerHTML = members.map((item) => {
    const path = item.path || item.logical_path || item.artifact_id || "unnamed artifact";
    const kind = item.kind || item.media_type || "file";
    const size = item.size ?? item.uncompressed_size ?? item.compressed_size ?? 0;
    return `<div class="inventory-item"><span>${escapeHtml(path)}</span><small>${escapeHtml(`${kind} / ${formatBytes(size)}`)}</small></div>`;
  }).join("");
}

function explanationSteps(node, depth = 0, result = []) {
  if (!node) return result;
  const relation = node.relation_type === null || node.relation_type === undefined
    ? null
    : relationshipDisplayLabel(typeof node.relation_type === "string" ? node.relation_type : null);
  result.push({ depth, text: [
    humanResourceType(typeof node.kind === "string" ? node.kind : "UNKNOWN"),
    formatValue(node.resource ?? node.resource_id),
    node.state === null || node.state === undefined ? null : `state=${formatValue(node.state)}`,
    relation,
  ].filter(Boolean).join(" / ") });
  for (const child of node.children || []) explanationSteps(child, depth + 1, result);
  return result;
}

function routeResolutionCapability() {
  const direct = state.dataset?.route_resolution;
  if (direct && typeof direct === "object") return direct;
  const snapshot = state.dataset?.node_snapshot?.route_resolution;
  return snapshot && typeof snapshot === "object" ? snapshot : null;
}

function configureRouteControls() {
  const capability = routeResolutionCapability();
  const routeSelect = byId("route-choice");
  const basisSelect = byId("route-basis");
  const submit = byId("route-resolve");
  const result = byId("route-result");
  const routes = Array.isArray(capability?.routes) ? capability.routes : [];
  const bases = Array.isArray(capability?.basis_kinds) ? capability.basis_kinds : [];
  routeSelect.replaceChildren();
  basisSelect.replaceChildren();

  for (const route of routes) {
    const routeId = String(route?.route_id || "");
    if (!routeId) continue;
    const option = document.createElement("option");
    option.value = routeId;
    const context = [route?.vrf, route?.route_type].filter(Boolean).join(" / ");
    option.textContent = `${route?.label || route?.destination || routeId}${context ? ` · ${context}` : ""}`;
    routeSelect.append(option);
  }
  for (const basis of bases) {
    const basisKind = String(basis?.basis_kind || "");
    if (!basisKind) continue;
    const option = document.createElement("option");
    option.value = basisKind;
    option.textContent = String(basis?.label || basisKind);
    basisSelect.append(option);
  }

  if (
    capability?.default_route_id
    && [...routeSelect.options].some(
      (option) => option.value === capability.default_route_id
    )
  ) {
    routeSelect.value = capability.default_route_id;
  }
  if (
    capability?.default_basis_kind
    && [...basisSelect.options].some(
      (option) => option.value === capability.default_basis_kind
    )
  ) {
    basisSelect.value = capability.default_basis_kind;
  }
  const available = capability?.plugin_defined === true
    && capability?.scope === "node"
    && routeSelect.options.length > 0
    && basisSelect.options.length > 0;
  routeSelect.disabled = !available;
  basisSelect.disabled = !available;
  submit.disabled = !available;
  if (!available) {
    routeSelect.append(new Option("No route projection advertised", ""));
    basisSelect.append(new Option("No basis advertised", ""));
    result.innerHTML = '<div class="empty-state">This node plug-in did not advertise a route-resolution projection.</div>';
    result.setAttribute("aria-busy", "false");
  }
}

function selectedRouteDescriptor() {
  const capability = routeResolutionCapability();
  const routeId = String(byId("route-choice")?.value || "");
  return (capability?.routes || []).find(
    (item) => String(item?.route_id || "") === routeId
  ) || null;
}

function localNodeRouteResponse(requestContext) {
  const capability = state.dataset?.node_snapshot?.route_resolution;
  const nodeId = String(
    state.dataset?.node_snapshot?.node?.node_id
    || navigationContext.nodeId
    || "",
  );
  if (!capability
    || capability.plugin_defined !== true
    || capability.scope !== "node"
    || String(capability.node_id || "") !== nodeId
    || !Array.isArray(capability.responses)) return null;
  const match = capability.responses.find((item) => {
    const request = item?.request || {};
    return String(request.route_id || "") === requestContext.routeId
      && String(request.basis_kind || "") === requestContext.basisKind
      && String(request.time_ns || "") === requestContext.timeNs.toString();
  });
  return match?.response && typeof match.response === "object" ? match.response : null;
}

function renderRoutePayload(result, payload, requestContext) {
  const steps = explanationSteps(payload.explanation);
  const returnedBasis = payload.basis?.kind || payload.basis_kind || requestContext.basisKind || "unknown basis";
  const returnedTime = payload.time_ns ?? payload.basis?.time_ns;
  const returnedTimeCopy = returnedTime === null || returnedTime === undefined
    ? `requested at ${formatOffset(requestContext.timeNs)}`
    : `returned for ${formatOffset(toNs(returnedTime, requestContext.timeNs))}`;
  const forwarding = routePayloadForwardingPresentation(payload);
  const resultValue = String(payload.result ?? payload.disposition ?? "unknown");
  const branchMarkup = forwarding.branches.length
    ? `<div class="route-branch-list"><strong>Plug-in-declared branches</strong>${forwarding.branches.map((branch) => {
      const stateLabel = branch.active === true ? "active" : branch.active === false ? "inactive / not forwarding" : branch.result;
      return `<div class="route-branch is-${branch.active === true ? "active" : branch.active === false ? "inactive" : "unknown"}"><span>${escapeHtml(branch.nextHop ?? "next hop not returned")}</span><code>${escapeHtml(branch.egress ?? "egress not returned")}</code><em>${escapeHtml(stateLabel)}</em></div>`;
    }).join("")}</div>`
    : '<div class="route-branch-list is-empty"><strong>No forwarding branches returned</strong><span>The core does not infer local delivery from an empty result.</span></div>';
  result.innerHTML = `<div class="route-request-attribution"><strong>${escapeHtml(requestContext.routeLabel || "Plug-in route")}</strong><span>${escapeHtml(titleCase(returnedBasis))} · ${escapeHtml(returnedTimeCopy)} · result ${escapeHtml(titleCase(resultValue))}</span></div><div class="route-answer"><div><span>Matched destination</span><strong>${escapeHtml(payload.matched_prefix ?? "Not returned")}</strong></div><div><span>Forwarding next hop</span><strong>${escapeHtml(forwarding.nextHopText)}</strong><small>${escapeHtml(forwarding.scope)}</small></div><div><span>Forwarding egress</span><strong>${escapeHtml(forwarding.egressText)}</strong><small>${escapeHtml(forwarding.scope)}</small></div></div>${branchMarkup}<ol class="route-path">${steps.map((step) => `<li style="margin-left:${step.depth * 12}px">${escapeHtml(step.text)}</li>`).join("")}</ol><p class="panel-footnote">${escapeHtml(`${returnedBasis} / ${payload.quality || "unknown"} / ${resultValue}`)}</p>`;
  result.setAttribute("aria-busy", "false");
}

async function resolveRoute(event) {
  event?.preventDefault();
  abortLatestRequests("routeAbortController");
  const form = byId("route-form");
  const data = new FormData(form);
  const result = byId("route-result");
  const requestId = ++state.routeRequestId;
  const route = selectedRouteDescriptor();
  const requestContext = {
    routeId: String(data.get("route_id") || ""),
    routeLabel: String(route?.label || route?.destination || ""),
    basisKind: String(data.get("basis_kind") || ""),
    timeNs: state.cursorNs,
  };
  if (!requestContext.routeId || !requestContext.basisKind) {
    result.setAttribute("aria-busy", "false");
    result.innerHTML = '<div class="empty-state">No plug-in route and basis are available for this node.</div>';
    return;
  }
  if (isTopologyNodeSnapshot()) {
    const localPayload = localNodeRouteResponse(requestContext);
    if (localPayload) {
      renderRoutePayload(result, localPayload, requestContext);
    } else {
      result.setAttribute("aria-busy", "false");
      result.innerHTML = nodeSnapshotUnavailableMarkup(
        "Route resolution was not supplied",
        "The core will not call the global revision resolver for a topology-member snapshot. A member plug-in must explicitly supply a node-scoped route-resolution capability and matching response.",
      );
    }
    return;
  }
  result.setAttribute("aria-busy", "true");
  result.innerHTML = `<div class="empty-state">Resolving ${escapeHtml(requestContext.routeLabel || "plug-in route")} using ${escapeHtml(titleCase(requestContext.basisKind || "selected basis"))} at ${escapeHtml(formatOffset(requestContext.timeNs))}…</div>`;
  const controller = beginLatestRequest("routeAbortController");
  try {
    const payload = await analysisRuntimeApi(revisionPath("routes/resolve"), {
      method: "POST",
      signal: controller.signal,
      body: JSON.stringify({
        route_id: requestContext.routeId,
        basis_kind: requestContext.basisKind,
        time_ns: requestContext.timeNs.toString(),
      }),
    });
    if (requestId !== state.routeRequestId) return;
    // renderRoutePayload computes returnedTimeCopy from this exact request.
    renderRoutePayload(result, payload, requestContext);
  } catch (error) {
    if (requestWasAborted(error, controller)) return;
    if (requestId !== state.routeRequestId) return;
    result.innerHTML = `<div class="empty-state"><strong>Route resolution failed for ${escapeHtml(requestContext.routeLabel || "the selected route")}</strong><span>${escapeHtml(titleCase(requestContext.basisKind || "selected basis"))} at ${escapeHtml(formatOffset(requestContext.timeNs))}</span><br>${escapeHtml(error.message)}</div>`;
    result.setAttribute("aria-busy", "false");
  }
  finishLatestRequest("routeAbortController", controller);
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
    if (!state.includedSourceRecordGroups.has(sourceRecordStreamGroup(record))) return false;
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

function normalizeEventLogSelectionRanges(ranges) {
  const normalized = (ranges || [])
    .map((range) => {
      const start = Math.max(0, Math.trunc(Number(range?.[0] ?? range?.start)));
      const end = Math.max(0, Math.trunc(Number(range?.[1] ?? range?.end)));
      return start <= end ? [start, end] : [end, start];
    })
    .filter(([start, end]) => Number.isSafeInteger(start) && Number.isSafeInteger(end))
    .sort((left, right) => left[0] - right[0] || left[1] - right[1]);
  const merged = [];
  normalized.forEach(([start, end]) => {
    const prior = merged.at(-1);
    if (!prior || start > prior[1] + 1) merged.push([start, end]);
    else prior[1] = Math.max(prior[1], end);
  });
  return merged;
}

function eventLogSelectionCount(ranges = state.eventLogSelectionRanges) {
  return ranges.reduce((total, [start, end]) => total + end - start + 1, 0);
}

function eventLogSelectionIncludes(index, ranges = state.eventLogSelectionRanges) {
  const value = Number(index);
  if (!Number.isSafeInteger(value) || index === null || index === "") return false;
  return ranges.some(([start, end]) => value >= start && value <= end);
}

function addEventLogSelectionRange(ranges, start, end) {
  return normalizeEventLogSelectionRanges([...(ranges || []), [start, end]]);
}

function removeEventLogSelectionRange(ranges, start, end) {
  const low = Math.min(start, end);
  const high = Math.max(start, end);
  const result = [];
  for (const [rangeStart, rangeEnd] of ranges || []) {
    if (rangeEnd < low || rangeStart > high) {
      result.push([rangeStart, rangeEnd]);
      continue;
    }
    if (rangeStart < low) result.push([rangeStart, low - 1]);
    if (rangeEnd > high) result.push([high + 1, rangeEnd]);
  }
  return normalizeEventLogSelectionRanges(result);
}

function eventLogSelectionSignature() {
  return JSON.stringify({
    query: state.eventLogSelectionQueryKey,
    ranges: state.eventLogSelectionRanges,
  });
}

function clearEventLogSelection({ render = true, announce = false } = {}) {
  const count = eventLogSelectionCount();
  finishEventLogDrag(null, false);
  state.eventLogSelectionRanges = [];
  state.eventLogSelectionAnchor = null;
  state.eventLogSelectionFocus = null;
  state.eventLogSelectionCache = null;
  state.eventLogSelectionRequestId += 1;
  if (render) {
    renderEventLogSelectionToolbar();
    renderEventTableWindow();
  }
  if (announce && count) showToast("Event-log selection cleared.");
  return Boolean(count);
}

function setEventLogSelectionRanges(ranges, {
  anchor = state.eventLogSelectionAnchor,
  focus = state.eventLogSelectionFocus,
  render = true,
} = {}) {
  state.eventLogSelectionRanges = normalizeEventLogSelectionRanges(ranges);
  state.eventLogSelectionAnchor = Number.isSafeInteger(Number(anchor)) ? Number(anchor) : null;
  state.eventLogSelectionFocus = Number.isSafeInteger(Number(focus)) ? Number(focus) : null;
  state.eventLogSelectionCache = null;
  state.eventLogSelectionRequestId += 1;
  if (render) {
    renderEventLogSelectionToolbar();
    renderEventTableWindow();
  }
}

function applyEventLogSelectionGesture(index, {
  additive = false,
  extend = false,
  toggle = false,
  render = true,
} = {}) {
  const target = Math.max(0, Math.trunc(Number(index)));
  const anchor = extend && state.eventLogSelectionAnchor !== null
    ? state.eventLogSelectionAnchor
    : target;
  let ranges = additive ? state.eventLogSelectionRanges : [];
  if (toggle) {
    ranges = eventLogSelectionIncludes(target, ranges)
      ? removeEventLogSelectionRange(ranges, target, target)
      : addEventLogSelectionRange(ranges, target, target);
  } else {
    ranges = addEventLogSelectionRange(ranges, anchor, target);
  }
  setEventLogSelectionRanges(ranges, {
    anchor: extend && state.eventLogSelectionAnchor !== null
      ? state.eventLogSelectionAnchor
      : target,
    focus: target,
    render,
  });
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

function eventLogHoverModel(entry) {
  if (isSourceLogEntry(entry)) {
    const uid = sourceRecordUid(entry);
    const lane = sourceRecordLaneFor(uid) || {
      laneId: `log-source:${uid}`,
      label: sourceTypeDescriptor(entry.source_type).label,
      marks: [],
    };
    return {
      type: "source-record",
      mark: normalizeSourceMark(entry, lane),
      lane,
    };
  }
  const uid = String(entry?.event_uid || entry?.event_id || "");
  const occurrenceLanes = state.lanes.filter(
    (lane) => lane.marks.some((mark) => mark.eventUid === uid),
  );
  const resourceId = eventResourceRefs(entry)[0] || "unresolved";
  const record = state.resourceById.get(resourceId);
  const lane = occurrenceLanes[0] || {
    laneId: `log-event:${uid}`,
    resourceId,
    resource: record,
    layer: eventSubject(entry).layer || resourceLayer(record, resourceId),
    kind: resourceKind(record, resourceId),
    label: record ? resourceLabel(record, resourceId) : resourceId,
    marks: [],
    lifecycle: [],
    statuses: [],
    clusters: [],
  };
  return {
    type: "event",
    mark: normalizeMark(entry, lane),
    lane,
    occurrenceLanes,
  };
}

function registerVisibleEventLogHoverModels() {
  state.eventLogHoverModels.clear();
  byId("event-table-body")?.querySelectorAll("tr[data-log-entry-id]").forEach((row) => {
    const entry = row.dataset.sourceRecordUid
      ? state.sourceRecordByUid.get(row.dataset.sourceRecordUid)
      : state.eventByUid.get(row.dataset.eventUid);
    if (!entry) return;
    state.eventLogHoverModels.set(row.dataset.hoverKey, eventLogHoverModel(entry));
    bindHoverTarget(row);
  });
}

function renderEventRow(event, rangeMembership = null, selectionIndex = null) {
  const subject = eventSubject(event);
  const subjectKey = subject.raw_key ?? eventResourceRefs(event)[0] ?? "unknown";
  const uid = String(event.event_uid || event.event_id);
  const entryId = normalizedLogEntryId(uid);
  const classes = ["event-row"];
  if (uid === state.selectedEventUid) classes.push("active");
  if (eventLogSelectionIncludes(selectionIndex)) classes.push("batch-selected");
  if (state.hiddenTimelineEntryIds.has(entryId)) classes.push("timeline-hidden");
  if (state.markedTimelineEntryIds.has(entryId)) classes.push("timeline-marked");
  if (rangeMembership === "inside") classes.push("range-included");
  const selected = eventLogSelectionIncludes(selectionIndex);
  return `<tr data-log-entry-id="${escapeHtml(entryId)}" data-event-uid="${escapeHtml(uid)}" data-selection-index="${selectionIndex}" data-hover-key="${escapeHtml(`log:${entryId}`)}" data-range-membership="${rangeMembership || "none"}" class="${classes.join(" ")}" tabindex="${state.eventLogSelectionFocus === selectionIndex ? "0" : "-1"}" aria-selected="${selected}" aria-rowindex="${Number(selectionIndex) + 2}"><td>${escapeHtml(formatOffset(eventTime(event)))}</td><td><span class="log-stream-kind normalized">Normalized</span><small>${escapeHtml(humanLayer(subject.layer))}</small></td><td><code>${escapeHtml(event.event_type || event.label)}</code></td><td><code>${escapeHtml(formatValue(subjectKey))}</code></td><td>${escapeHtml(event.action || event.operation || "observe")}</td><td><span class="outcome ${eventFailed(event) ? "failure" : "success"}">${eventFailed(event) ? "failure" : escapeHtml(event.outcome || "success")}</span></td></tr>`;
}

function renderSourceRecordRow(record, rangeMembership = null, selectionIndex = null) {
  const uid = sourceRecordUid(record);
  const entryId = sourceLogEntryId(uid);
  const descriptor = sourceTypeDescriptor(record.source_type);
  const classes = ["event-row", "source-log-row"];
  if (uid === state.selectedSourceRecordUid) classes.push("active");
  if (eventLogSelectionIncludes(selectionIndex)) classes.push("batch-selected");
  if (state.hiddenTimelineEntryIds.has(entryId)) classes.push("timeline-hidden");
  if (state.markedTimelineEntryIds.has(entryId)) classes.push("timeline-marked");
  if (rangeMembership === "inside") classes.push("range-included");
  const matchedEventUids = sourceRecordMatchedEventUids(record);
  const matched = matchedEventUids.length > 0;
  const selected = eventLogSelectionIncludes(selectionIndex);
  return `<tr data-log-entry-id="${escapeHtml(entryId)}" data-source-record-uid="${escapeHtml(uid)}" data-selection-index="${selectionIndex}" data-hover-key="${escapeHtml(`log:${entryId}`)}" data-range-membership="${rangeMembership || "none"}" class="${classes.join(" ")}" tabindex="${state.eventLogSelectionFocus === selectionIndex ? "0" : "-1"}" aria-selected="${selected}" aria-rowindex="${Number(selectionIndex) + 2}" style="--source-color:${escapeHtml(descriptor.color || stableColor(record.source_type))}"><td>${escapeHtml(formatOffset(sourceRecordTime(record)))}</td><td><span class="log-stream-kind source">${escapeHtml(descriptor.label)}</span><small>${escapeHtml(humanLayer(record.layer || "unknown"))}</small></td><td><code>${escapeHtml(record.record_name || "record")}</code><small>${escapeHtml(record.source_name || "source")}</small></td><td class="source-message">${escapeHtml(record.message || "No decoded message")}</td><td><span class="source-match ${matched ? "matched" : "unmatched"}">${matched ? "matched" : "unmatched"}</span>${matched ? `<small>${escapeHtml(matchedEventUids.join(", "))}</small>` : ""}</td><td><span class="outcome ${matched ? "success" : "unmatched"}">${escapeHtml(record.source_type || "source")}</span></td></tr>`;
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

function serverHistorySourceCount() {
  return Number(
    state.dataset?.history_transport?.source_records?.total_count
    ?? workspaceMetadata().source_record_count
    ?? 0,
  );
}

function serverEventLogRequestBody(offset = 0, locate = null) {
  const layer = byId("event-layer-filter")?.value || "";
  const search = byId("event-search")?.value?.trim() || "";
  const bounds = rangeBounds();
  return {
    include_normalized: state.eventLogInclude.normalized,
    source_types: selectedEventLogSourceTypes(),
    layers: layer ? [layer] : [],
    search,
    ...(bounds ? {
      start_ns: bounds[0].toString(),
      end_ns: bounds[1].toString(),
    } : {}),
    offset,
    limit: EVENT_LOG_PAGE_SIZE,
    ...(locate ? { locate } : {}),
  };
}

function serverEventLogQueryKey() {
  const body = serverEventLogRequestBody(0);
  delete body.offset;
  delete body.limit;
  return JSON.stringify(body);
}

function bindEventLogSelectionToQuery(queryKey) {
  if (state.eventLogSelectionQueryKey === queryKey) return false;
  const hadSelection = eventLogSelectionCount() > 0;
  finishEventLogDrag(null, false);
  state.eventLogSelectionQueryKey = queryKey;
  state.eventLogSelectionRanges = [];
  state.eventLogSelectionAnchor = null;
  state.eventLogSelectionFocus = null;
  state.eventLogSelectionCache = null;
  state.eventLogSelectionRequestId += 1;
  renderEventLogSelectionToolbar();
  if (hadSelection) showToast("Event-log selection cleared because the stream order changed.");
  return hadSelection;
}

function serverEventLogLayout() {
  const summary = state.eventLogServerSummary;
  const hasRange = Boolean(rangeBounds());
  if (!summary) return { length: 1, hasRange, loading: true };
  const totalCount = Math.max(0, Number(summary.totalCount || 0));
  const insideCount = hasRange ? Math.max(0, Number(summary.insideCount || 0)) : 0;
  const outsideCount = hasRange
    ? Math.max(0, Number(summary.outsideCount ?? totalCount - insideCount))
    : totalCount;
  if (!totalCount) return { length: 1, hasRange, totalCount, insideCount, outsideCount };
  if (!hasRange) return {
    length: totalCount + 1,
    hasRange,
    totalCount,
    insideCount,
    outsideCount,
  };
  const selectedBodyRows = Math.max(1, insideCount);
  const outsideGroupIndex = 1 + selectedBodyRows;
  return {
    length: outsideGroupIndex + (outsideCount ? 1 + outsideCount : 0),
    hasRange,
    totalCount,
    insideCount,
    outsideCount,
    outsideGroupIndex,
  };
}

function serverEventLogDataIndexAtRow(rowIndex, layout = serverEventLogLayout()) {
  if (layout.loading || !layout.totalCount) return null;
  if (!layout.hasRange) return rowIndex > 0 ? rowIndex - 1 : null;
  if (rowIndex > 0 && layout.insideCount && rowIndex <= layout.insideCount) return rowIndex - 1;
  if (layout.outsideCount && rowIndex > layout.outsideGroupIndex) {
    return layout.insideCount + rowIndex - layout.outsideGroupIndex - 1;
  }
  return null;
}

function serverEventLogVirtualRowForDataIndex(dataIndex, layout = serverEventLogLayout()) {
  if (!layout.hasRange) return dataIndex + 1;
  if (dataIndex < layout.insideCount) return dataIndex + 1;
  return layout.outsideGroupIndex + 1 + dataIndex - layout.insideCount;
}

function serverEventLogRowAt(rowIndex) {
  const layout = serverEventLogLayout();
  if (layout.loading) {
    return { kind: "loading", message: "Loading the visible history window…" };
  }
  if (!layout.totalCount) {
    return {
      kind: "empty",
      message: state.eventLogServerError
        ? `History query failed: ${state.eventLogServerError}`
        : "No normalized or retained source records match these filters.",
    };
  }
  if (!layout.hasRange && rowIndex === 0) {
    return {
      kind: "group",
      groupKind: "windowed-events",
      title: "Visible stream",
      detail: `${layout.totalCount.toLocaleString()} matching records · exact server-windowed scrolling`,
    };
  }
  if (layout.hasRange && rowIndex === 0) {
    const bounds = rangeBounds();
    return {
      kind: "group",
      groupKind: "selected-period",
      title: "Selected period",
      detail: `${formatOffset(bounds[0])} to ${formatOffset(bounds[1])} · ${layout.insideCount.toLocaleString()} matching ${layout.insideCount === 1 ? "record" : "records"}`,
    };
  }
  if (layout.hasRange && !layout.insideCount && rowIndex === 1) {
    return {
      kind: "empty",
      message: "No visible records in the selected period match the current filters.",
    };
  }
  if (layout.hasRange && layout.outsideCount && rowIndex === layout.outsideGroupIndex) {
    return {
      kind: "group",
      groupKind: "other-events",
      title: "Other records",
      detail: `${layout.outsideCount.toLocaleString()} outside the selected period`,
    };
  }
  const dataIndex = serverEventLogDataIndexAtRow(rowIndex, layout);
  if (dataIndex === null) return { kind: "loading", message: "Loading history row…" };
  return state.eventLogServerItems.get(dataIndex)
    || { kind: "loading", message: "Loading history page…" };
}

function rebuildServerEventLogIndex() {
  const layout = serverEventLogLayout();
  state.eventLogIndexById = new Map();
  for (const [dataIndex, row] of state.eventLogServerItems) {
    if (row?.kind !== "entry") continue;
    state.eventLogIndexById.set(
      logEntryId(row.entry),
      serverEventLogVirtualRowForDataIndex(dataIndex, layout),
    );
  }
}

function setServerEventLogRows() {
  const layout = serverEventLogLayout();
  state.eventLogSelectableCount = Number(layout.totalCount || 0);
  state.eventLogVirtualIndexBySelectionIndex = [];
  state.eventLogRows = virtualEventLogRows(layout.length, serverEventLogRowAt);
  rebuildServerEventLogIndex();
  const status = byId("event-log-status");
  if (!status) return;
  if (!state.eventLogServerSummary) {
    status.textContent = `${displayedHistoryEventCount().toLocaleString()} normalized · ${serverHistorySourceCount().toLocaleString()} retained · loading visible page`;
  } else {
    status.textContent = `${layout.totalCount.toLocaleString()} matching records · exact server-windowed history`;
  }
}

function registerServerEventLogItem(raw, fallbackIndex) {
  const streamKind = String(raw?.stream_kind || "event");
  const suppliedEntry = raw?.entry || raw?.event || raw?.record || {};
  const dataIndex = Math.max(0, Number(raw?.display_index ?? fallbackIndex));
  const membership = raw?.membership === "inside" || raw?.in_selected_range === true
    ? "inside"
    : raw?.membership === "outside" || raw?.in_selected_range === false ? "outside" : null;
  let entry = suppliedEntry;
  if (streamKind === "source" || suppliedEntry.source_record_uid !== undefined) {
    const uid = sourceRecordUid(suppliedEntry) || String(raw?.uid || "");
    entry = { ...suppliedEntry, source_record_uid: uid };
    if (uid && (!state.sourceRecordByUid.has(uid) || state.eventLogOwnedSources.has(uid))) {
      state.sourceRecordByUid.set(uid, entry);
      state.eventLogOwnedSources.set(uid, entry);
    }
  } else {
    const uid = String(suppliedEntry.event_uid || suppliedEntry.event_id || raw?.uid || "");
    entry = { ...suppliedEntry, event_uid: uid };
    if (uid && (!state.eventByUid.has(uid) || state.eventLogOwnedEvents.has(uid))) {
      state.eventByUid.set(uid, entry);
      state.eventLogOwnedEvents.set(uid, entry);
    }
  }
  state.eventLogServerItems.set(dataIndex, {
    kind: "entry",
    entry,
    membership,
    selectionIndex: dataIndex,
  });
  return dataIndex;
}

function pruneServerEventLogOwnedCaches() {
  if (!state.eventLogOwnedEvents.size && !state.eventLogOwnedSources.size) return;
  const loadedEvents = new Set();
  const loadedSources = new Set();
  for (const row of state.eventLogServerItems.values()) {
    if (row?.kind !== "entry") continue;
    if (isSourceLogEntry(row.entry)) loadedSources.add(sourceRecordUid(row.entry));
    else loadedEvents.add(String(row.entry?.event_uid || row.entry?.event_id || ""));
  }
  const timelineEvents = new Set();
  const timelineSources = new Set();
  for (const lane of [...state.lanes, ...state.recordLanes]) {
    for (const mark of lane.marks || []) {
      if (mark.kind === "source-record" && mark.sourceRecordUid) {
        timelineSources.add(String(mark.sourceRecordUid));
      } else if (mark.eventUid) {
        timelineEvents.add(String(mark.eventUid));
      }
    }
  }
  for (const [uid, owned] of state.eventLogOwnedEvents) {
    if (loadedEvents.has(uid)
      || timelineEvents.has(uid)
      || uid === state.selectedEventUid
      || state.timelineEntryProjections.has(normalizedLogEntryId(uid))
      || state.eventDetailByUid.has(uid)
      || state.eventDetailRequests.has(uid)) continue;
    if (state.eventByUid.get(uid) === owned) state.eventByUid.delete(uid);
    state.eventLogOwnedEvents.delete(uid);
  }
  for (const [uid, owned] of state.eventLogOwnedSources) {
    if (loadedSources.has(uid)
      || timelineSources.has(uid)
      || uid === state.selectedSourceRecordUid
      || state.timelineEntryProjections.has(sourceLogEntryId(uid))) continue;
    if (state.sourceRecordByUid.get(uid) === owned) state.sourceRecordByUid.delete(uid);
    state.eventLogOwnedSources.delete(uid);
  }
}

function rememberServerEventLogPage(offset, indices) {
  const replacedIndices = state.eventLogServerPages.get(offset) || [];
  const nextIndices = new Set(indices);
  replacedIndices.forEach((index) => {
    if (!nextIndices.has(index)) state.eventLogServerItems.delete(index);
  });
  state.eventLogServerPages.delete(offset);
  state.eventLogServerPages.set(offset, indices);
  while (state.eventLogServerPages.size > EVENT_LOG_PAGE_CACHE_LIMIT) {
    const oldestOffset = state.eventLogServerPages.keys().next().value;
    const oldestIndices = state.eventLogServerPages.get(oldestOffset) || [];
    state.eventLogServerPages.delete(oldestOffset);
    oldestIndices.forEach((index) => state.eventLogServerItems.delete(index));
  }
  pruneServerEventLogOwnedCaches();
}

function applyServerEventLogPayload(payload, requestedOffset, queryId) {
  if (queryId !== state.eventLogServerQueryId) return false;
  const counts = payload?.counts || {};
  const totalCount = Number(payload?.total_count ?? counts.total ?? 0);
  const insideCount = Number(payload?.inside_count ?? counts.inside ?? counts.selected ?? 0);
  const outsideCount = Number(payload?.outside_count ?? counts.outside ?? Math.max(0, totalCount - insideCount));
  state.eventLogServerSummary = {
    totalCount,
    insideCount,
    outsideCount,
    returnedCount: Number(payload?.returned_count ?? (payload?.items || []).length),
  };
  state.eventLogServerError = null;
  const actualOffset = Math.max(0, Number(payload?.offset ?? requestedOffset));
  const indices = (payload?.items || []).map((item, index) => (
    registerServerEventLogItem(item, actualOffset + index)
  ));
  rememberServerEventLogPage(actualOffset, indices);
  setServerEventLogRows();
  return true;
}

function requestServerEventLogPage(offset = 0) {
  const safeOffset = Math.max(0, Math.trunc(offset));
  const queryId = state.eventLogServerQueryId;
  if (state.eventLogServerPages.has(safeOffset)) return Promise.resolve(null);
  if (state.eventLogServerRequests.has(safeOffset)) return state.eventLogServerRequests.get(safeOffset);
  const request = analysisRuntimeApi(revisionPath("event-log/query"), {
    method: "POST",
    body: JSON.stringify(serverEventLogRequestBody(safeOffset)),
  }).then((payload) => {
    if (!applyServerEventLogPayload(payload, safeOffset, queryId)) return null;
    renderEventTableWindow();
    return payload;
  }).catch((error) => {
    if (queryId !== state.eventLogServerQueryId) return null;
    state.eventLogServerError = error.message;
    if (!state.eventLogServerSummary) {
      state.eventLogServerSummary = { totalCount: 0, insideCount: 0, outsideCount: 0 };
    }
    setServerEventLogRows();
    renderEventTableWindow();
    return null;
  }).finally(() => {
    if (queryId === state.eventLogServerQueryId) state.eventLogServerRequests.delete(safeOffset);
  });
  state.eventLogServerRequests.set(safeOffset, request);
  return request;
}

function ensureServerEventLogPages(startRow, endRow) {
  const layout = serverEventLogLayout();
  if (layout.loading || !layout.totalCount) return;
  const dataIndexes = [];
  for (let rowIndex = startRow; rowIndex < endRow; rowIndex += 1) {
    const dataIndex = serverEventLogDataIndexAtRow(rowIndex, layout);
    if (dataIndex !== null) dataIndexes.push(dataIndex);
  }
  if (!dataIndexes.length) return;
  const firstPage = Math.floor(Math.min(...dataIndexes) / EVENT_LOG_PAGE_SIZE) * EVENT_LOG_PAGE_SIZE;
  const lastPage = Math.floor(Math.max(...dataIndexes) / EVENT_LOG_PAGE_SIZE) * EVENT_LOG_PAGE_SIZE;
  for (let offset = firstPage; offset <= lastPage; offset += EVENT_LOG_PAGE_SIZE) {
    requestServerEventLogPage(offset);
  }
}

function prepareServerEventLogQuery({ resetScroll = false, requestFirstPage = true } = {}) {
  const key = serverEventLogQueryKey();
  bindEventLogSelectionToQuery(key);
  const changed = key !== state.eventLogServerKey;
  if (changed) {
    state.eventLogServerKey = key;
    state.eventLogServerQueryId += 1;
    state.eventLogServerItems = new Map();
    state.eventLogServerPages = new Map();
    state.eventLogServerRequests = new Map();
    pruneServerEventLogOwnedCaches();
    state.eventLogServerSummary = null;
    state.eventLogServerError = null;
    setServerEventLogRows();
  }
  const scroll = byId("event-log-scroll");
  if (resetScroll && scroll) scroll.scrollTop = 0;
  if ((changed || !state.eventLogServerSummary) && requestFirstPage) requestServerEventLogPage(0);
  return changed;
}

function rebuildEventLogRows({ resetScroll = false } = {}) {
  if (usesServerWindowedHistory()) {
    prepareServerEventLogQuery({ resetScroll });
    return;
  }
  bindEventLogSelectionToQuery(serverEventLogQueryKey());
  const events = state.eventLogInclude.normalized ? filteredEvents() : [];
  const sourceRecords = filteredSourceRecords();
  const entries = mergeLogEntries(events, sourceRecords);
  state.eventLogSelectableCount = entries.length;
  state.eventLogVirtualIndexBySelectionIndex = [];
  const bounds = rangeBounds();
  const historyStreamsNotSupplied = Boolean(
    isTopologyNodeSnapshot()
    && !(state.dataset?.events || []).length
    && !state.sourceRecords.length,
  );
  state.eventLogIndexById = new Map();

  if (!entries.length) {
    state.eventLogRows = virtualEventLogRows(1, () => ({
      kind: "empty",
      message: historyStreamsNotSupplied
        ? "Event history and retained CTF/non-CTF records were not supplied by this topology-member plug-in snapshot."
        : "No normalized or retained source records match these filters.",
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
      state.eventLogVirtualIndexBySelectionIndex[index] = index + 1;
    });
    state.eventLogRows = virtualEventLogRows(
      entries.length + 1,
      (index) => index === 0
        ? group
        : {
          kind: "entry",
          entry: entries[index - 1],
          membership: null,
          selectionIndex: index - 1,
        },
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
      state.eventLogVirtualIndexBySelectionIndex[index] = index + 1;
    });
    excluded.forEach((entry, index) => {
      state.eventLogIndexById.set(logEntryId(entry), outsideGroupIndex + index + 1);
      state.eventLogVirtualIndexBySelectionIndex[included.length + index] = outsideGroupIndex + index + 1;
    });
    state.eventLogRows = virtualEventLogRows(totalRows, (index) => {
      if (index === 0) return selectedGroup;
      if (included.length && index <= included.length) {
        return {
          kind: "entry",
          entry: included[index - 1],
          membership: "inside",
          selectionIndex: index - 1,
        };
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
        selectionIndex: included.length + index - outsideGroupIndex - 1,
      };
    });
  }

  const normalizedCount = events.length;
  const sourceCount = sourceRecords.length;
  byId("event-log-status").textContent = historyStreamsNotSupplied
    ? "History streams not supplied by member plug-ins"
    : entries.length.toLocaleString() + " records · "
      + normalizedCount.toLocaleString() + " normalized · "
      + sourceCount.toLocaleString() + " retained";
  const scroll = byId("event-log-scroll");
  if (resetScroll && scroll) scroll.scrollTop = 0;
}

function renderEventLogRow(row) {
  if (row.kind === "group") return renderEventGroup(row.groupKind, row.title, row.detail);
  if (row.kind === "empty" || row.kind === "loading") {
    return `<tr class="event-range-empty"><td colspan="6">${escapeHtml(row.message)}</td></tr>`;
  }
  return isSourceLogEntry(row.entry)
    ? renderSourceRecordRow(row.entry, row.membership, row.selectionIndex)
    : renderEventRow(row.entry, row.membership, row.selectionIndex);
}

function focusEventLogEntry(row, moveCursor = false) {
  if (row.dataset.sourceRecordUid) {
    selectSourceRecord(row.dataset.sourceRecordUid, moveCursor);
  } else if (row.dataset.eventUid) {
    selectEvent(row.dataset.eventUid, moveCursor);
  }
}

function revealEventLogEntry(row) {
  if (row.dataset.sourceRecordUid) {
    jumpSourceRecordToTimeline(row.dataset.sourceRecordUid);
  } else if (row.dataset.eventUid) {
    jumpToTimelineEvent(row.dataset.eventUid);
  }
}

function visibleEventLogRowAtPoint(clientX, clientY) {
  const direct = document.elementFromPoint(clientX, clientY)
    ?.closest?.("tr[data-selection-index]");
  if (direct) return direct;
  const rows = [...byId("event-table-body").querySelectorAll("tr[data-selection-index]")];
  return rows.find((row) => {
    const rect = row.getBoundingClientRect();
    return clientY >= rect.top && clientY <= rect.bottom;
  }) || (clientY < byId("event-log-scroll").getBoundingClientRect().top
    ? rows[0]
    : rows.at(-1));
}

function eventLogDragRanges(drag, targetIndex) {
  const anchor = drag.extend && drag.anchor !== null ? drag.anchor : drag.startIndex;
  const base = drag.additive ? drag.baseRanges : [];
  return addEventLogSelectionRange(base, anchor, targetIndex);
}

function runEventLogDragAutoScroll() {
  const drag = state.eventLogDrag;
  if (!drag?.active) return;
  const host = byId("event-log-scroll");
  const rect = host.getBoundingClientRect();
  const edge = 34;
  const distance = drag.lastClientY < rect.top + edge
    ? drag.lastClientY - (rect.top + edge)
    : drag.lastClientY > rect.bottom - edge
      ? drag.lastClientY - (rect.bottom - edge)
      : 0;
  if (distance) {
    host.scrollTop += Math.sign(distance) * Math.max(5, Math.min(24, Math.abs(distance)));
    renderEventTableWindow();
    const row = visibleEventLogRowAtPoint(drag.lastClientX, drag.lastClientY);
    const index = Number(row?.dataset.selectionIndex);
    if (Number.isSafeInteger(index) && index !== drag.lastIndex) {
      drag.lastIndex = index;
      setEventLogSelectionRanges(eventLogDragRanges(drag, index), {
        anchor: drag.extend && drag.anchor !== null ? drag.anchor : drag.startIndex,
        focus: index,
        render: true,
      });
    }
  }
  drag.animationFrame = window.requestAnimationFrame(runEventLogDragAutoScroll);
}

function eventLogPointerDown(event) {
  if (event.pointerType === "touch" || event.button !== 0 || !event.isPrimary) return;
  const row = event.target.closest("tr[data-selection-index]");
  if (!row || event.target.closest("button, a, input, select, textarea")) return;
  const startIndex = Number(row.dataset.selectionIndex);
  if (!Number.isSafeInteger(startIndex)) return;
  const host = byId("event-log-scroll");
  state.eventLogDrag = {
    pointerId: event.pointerId,
    startIndex,
    lastIndex: startIndex,
    anchor: state.eventLogSelectionAnchor,
    baseFocus: state.eventLogSelectionFocus,
    baseRanges: state.eventLogSelectionRanges.map((range) => [...range]),
    additive: event.ctrlKey || event.metaKey,
    extend: event.shiftKey,
    startX: event.clientX,
    startY: event.clientY,
    lastClientX: event.clientX,
    lastClientY: event.clientY,
    active: false,
    animationFrame: null,
  };
  host.setPointerCapture?.(event.pointerId);
}

function eventLogPointerMove(event) {
  const drag = state.eventLogDrag;
  if (!drag || event.pointerId !== drag.pointerId) return;
  drag.lastClientX = event.clientX;
  drag.lastClientY = event.clientY;
  if (!drag.active && Math.hypot(
    event.clientX - drag.startX,
    event.clientY - drag.startY,
  ) < 5) return;
  if (!drag.active) {
    drag.active = true;
    byId("event-log-scroll").classList.add("is-selecting");
    setEventLogSelectionRanges(eventLogDragRanges(drag, drag.startIndex), {
      anchor: drag.extend && drag.anchor !== null ? drag.anchor : drag.startIndex,
      focus: drag.startIndex,
      render: true,
    });
    drag.animationFrame = window.requestAnimationFrame(runEventLogDragAutoScroll);
  }
  event.preventDefault();
  const row = visibleEventLogRowAtPoint(event.clientX, event.clientY);
  const index = Number(row?.dataset.selectionIndex);
  if (!Number.isSafeInteger(index) || index === drag.lastIndex) return;
  drag.lastIndex = index;
  setEventLogSelectionRanges(eventLogDragRanges(drag, index), {
    anchor: drag.extend && drag.anchor !== null ? drag.anchor : drag.startIndex,
    focus: index,
    render: true,
  });
}

function finishEventLogDrag(event = null, cancelled = false) {
  const drag = state.eventLogDrag;
  if (!drag) return false;
  if (event && event.pointerId !== undefined && event.pointerId !== drag.pointerId) return false;
  const host = byId("event-log-scroll");
  if (drag.animationFrame !== null) window.cancelAnimationFrame(drag.animationFrame);
  state.eventLogDrag = null;
  if (host?.hasPointerCapture?.(drag.pointerId)) host.releasePointerCapture(drag.pointerId);
  host?.classList.remove("is-selecting");
  if (drag.active) {
    state.eventLogSuppressClickUntil = performance.now() + 280;
    if (cancelled) {
      setEventLogSelectionRanges(drag.baseRanges, {
        anchor: drag.anchor,
        focus: drag.baseFocus,
        render: true,
      });
    } else {
      renderEventLogSelectionToolbar();
    }
  }
  return drag.active;
}

function bindVisibleEventLogRows() {
  const body = byId("event-table-body");
  body.querySelectorAll("tr[data-selection-index]").forEach((row) => {
    const selectionIndex = Number(row.dataset.selectionIndex);
    row.addEventListener("click", (event) => {
      if (performance.now() < state.eventLogSuppressClickUntil) {
        event.preventDefault();
        return;
      }
      const additive = event.ctrlKey || event.metaKey;
      const extend = event.shiftKey;
      applyEventLogSelectionGesture(selectionIndex, {
        additive,
        extend,
        toggle: additive && !extend,
        render: false,
      });
      if (!additive && !extend) focusEventLogEntry(row, true);
      else {
        renderEventLogSelectionToolbar();
        renderEventTableWindow();
      }
    });
    row.addEventListener("dblclick", (event) => {
      event.preventDefault();
      revealEventLogEntry(row);
    });
    row.addEventListener("keydown", (event) => {
      if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
        event.preventDefault();
        revealEventLogEntry(row);
        return;
      }
      if (event.key === "ArrowDown" || event.key === "ArrowUp") {
        event.preventDefault();
        const maximum = Math.max(0, state.eventLogSelectableCount - 1);
        const next = Math.max(
          0,
          Math.min(maximum, selectionIndex + (event.key === "ArrowDown" ? 1 : -1)),
        );
        applyEventLogSelectionGesture(next, {
          additive: event.ctrlKey || event.metaKey,
          extend: event.shiftKey,
          toggle: false,
        });
        focusEventLogSelectionIndex(next);
        return;
      }
      if (event.key === " " && (event.ctrlKey || event.metaKey)) {
        event.preventDefault();
        applyEventLogSelectionGesture(selectionIndex, {
          additive: true,
          toggle: true,
        });
        return;
      }
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        applyEventLogSelectionGesture(selectionIndex);
        focusEventLogEntry(row, true);
      }
    });
  });
  registerVisibleEventLogHoverModels();
}

function renderEventTableWindow() {
  const scroll = byId("event-log-scroll");
  const body = byId("event-table-body");
  if (!scroll || !body) return;
  if (state.hoverKey?.startsWith("log:") && !state.hoverPinned) closeHover();
  state.eventLogHoverModels.clear();
  const total = state.eventLogRows.length;
  const windowModel = virtualScrollWindow({
    rowCount: total,
    rowHeight: EVENT_LOG_ROW_HEIGHT,
    maximumHeight: EVENT_LOG_MAX_SCROLL_HEIGHT,
    viewportHeight: scroll.clientHeight,
    scrollTop: scroll.scrollTop,
    overscan: EVENT_LOG_OVERSCAN,
  });
  const { start, end, topHeight, bottomHeight } = windowModel;
  if (usesServerWindowedHistory()) ensureServerEventLogPages(start, end);
  const topSpacer = topHeight
    ? `<tr class="event-log-spacer" aria-hidden="true"><td colspan="6" style="height:${topHeight}px"></td></tr>`
    : "";
  const bottomSpacer = bottomHeight
    ? `<tr class="event-log-spacer" aria-hidden="true"><td colspan="6" style="height:${bottomHeight}px"></td></tr>`
    : "";
  body.innerHTML = topSpacer
    + state.eventLogRows.slice(start, end).map(renderEventLogRow).join("")
    + bottomSpacer;
  const table = body.closest("table");
  if (table) {
    table.setAttribute("aria-multiselectable", "true");
    table.setAttribute("aria-rowcount", String(
      Math.max(1, Number(state.eventLogServerSummary?.totalCount || total)) + 1,
    ));
  }
  const focusedRow = state.eventLogSelectionFocus === null
    ? null
    : body.querySelector(
      `tr[data-selection-index="${state.eventLogSelectionFocus}"]`,
    );
  if (!focusedRow) {
    body.querySelector("tr[data-selection-index]")?.setAttribute("tabindex", "0");
  }
  bindVisibleEventLogRows();
}

function renderEventTable(options = {}) {
  rebuildEventLogRows(options);
  renderEventTableWindow();
  renderEventLogSelectionToolbar();
}

function eventLogCopyActionLabel() {
  const cached = state.eventLogSelectionCache;
  return cached?.signature === eventLogSelectionSignature()
    && cached.payload?.copy_action_label
    ? String(cached.payload.copy_action_label)
    : "Copy plug-in text";
}

function renderEventLogSelectionToolbar() {
  const toolbar = byId("event-selection-toolbar");
  if (!toolbar) return;
  const count = eventLogSelectionCount();
  const rangeCount = state.eventLogSelectionRanges.length;
  const overLimit = count > MAX_EVENT_LOG_SELECTION_ITEMS
    || rangeCount > MAX_EVENT_LOG_SELECTION_RANGES;
  toolbar.hidden = count === 0;
  byId("event-selection-count").textContent = count
    ? `${count.toLocaleString()} selected`
    : "No rows selected";
  byId("event-selection-copy").textContent = eventLogCopyActionLabel();
  toolbar.querySelectorAll("button").forEach((button) => {
    const isClear = button.id === "event-selection-clear";
    button.disabled = count === 0 || (overLimit && !isClear);
    button.title = overLimit && !isClear
      ? `Actions support at most ${MAX_EVENT_LOG_SELECTION_ITEMS.toLocaleString()} rows across ${MAX_EVENT_LOG_SELECTION_RANGES} ranges.`
      : "";
  });
  if (count) {
    const detail = `${rangeCount} contiguous ${rangeCount === 1 ? "range" : "ranges"} in this filtered stream`;
    byId("event-selection-detail").textContent = overLimit
      ? `${detail}; narrow the selection to ${MAX_EVENT_LOG_SELECTION_ITEMS.toLocaleString()} rows / ${MAX_EVENT_LOG_SELECTION_RANGES} ranges for actions`
      : detail;
  } else {
    byId("event-selection-detail").textContent = "";
  }
  syncDurableReviewControls();
}

function eventLogSelectionRequestBody() {
  const body = serverEventLogRequestBody(0);
  delete body.offset;
  delete body.limit;
  delete body.locate;
  return {
    ...body,
    selection_ranges: state.eventLogSelectionRanges.map(([start, end]) => ({
      start,
      end,
    })),
  };
}

function rememberTimelineEntryProjection(item) {
  const kind = String(item.stream_kind || "event");
  const uid = String(item.uid || "");
  const entryId = String(item.entry_id || `${kind}:${uid}`);
  const entry = item.entry && typeof item.entry === "object"
    ? item.entry
    : {};
  const normalizedEntry = kind === "source"
    ? { ...entry, source_record_uid: sourceRecordUid(entry) || uid }
    : { ...entry, event_uid: String(entry.event_uid || entry.event_id || uid) };
  if (kind === "source") {
    if (!state.sourceRecordByUid.has(uid)) {
      state.sourceRecordByUid.set(uid, normalizedEntry);
      state.eventLogOwnedSources.set(uid, normalizedEntry);
    }
  } else {
    if (!state.eventByUid.has(uid)) {
      state.eventByUid.set(uid, normalizedEntry);
      state.eventLogOwnedEvents.set(uid, normalizedEntry);
    }
  }
  const projection = {
    entryId,
    streamKind: kind,
    uid,
    timeNs: toNs(item.timestamp_ns, logEntryTime(normalizedEntry)),
    resourceIds: (item.resource_ids || []).map(String),
    entry: normalizedEntry,
  };
  state.timelineEntryProjections.set(entryId, projection);
  return projection;
}

function forgetTimelineEntryProjection(entryId) {
  if (
    state.hiddenTimelineEntryIds.has(entryId)
    || state.markedTimelineEntryIds.has(entryId)
  ) return;
  state.timelineEntryProjections.delete(entryId);
}

async function resolveEventLogSelection() {
  const count = eventLogSelectionCount();
  if (!count) throw new Error("Select at least one event-log row.");
  if (
    count > MAX_EVENT_LOG_SELECTION_ITEMS
    || state.eventLogSelectionRanges.length > MAX_EVENT_LOG_SELECTION_RANGES
  ) {
    throw new Error(
      `Actions support at most ${MAX_EVENT_LOG_SELECTION_ITEMS.toLocaleString()} rows across ${MAX_EVENT_LOG_SELECTION_RANGES} ranges.`,
    );
  }
  const signature = eventLogSelectionSignature();
  if (state.eventLogSelectionCache?.signature === signature) {
    return state.eventLogSelectionCache.payload;
  }
  const requestId = ++state.eventLogSelectionRequestId;
  const payload = await analysisRuntimeApi(revisionPath("event-log/selection"), {
    method: "POST",
    body: JSON.stringify(eventLogSelectionRequestBody()),
  });
  if (
    requestId !== state.eventLogSelectionRequestId
    || signature !== eventLogSelectionSignature()
  ) {
    throw new Error("The event-log selection changed while the action was resolving.");
  }
  state.eventLogSelectionCache = { signature, payload };
  if (payload.copy_action_label) {
    const copyButton = byId("event-selection-copy");
    if (copyButton) copyButton.textContent = String(payload.copy_action_label);
  }
  return payload;
}

async function writeClipboardText(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch (_error) {
    const area = document.createElement("textarea");
    area.value = text;
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.appendChild(area);
    area.select();
    document.execCommand("copy");
    area.remove();
  }
}

async function copyEventLogSelectionText() {
  try {
    const payload = await resolveEventLogSelection();
    const copy = payload.copy || {};
    const fragments = (copy.items || []).map((item) => String(item.text || ""));
    if (!fragments.length) {
      showToast("The selected rows have no plug-in text projection.");
      return;
    }
    await writeClipboardText(fragments.join("\n"));
    const suffix = copy.omitted_count
      ? `; ${Number(copy.omitted_count).toLocaleString()} unavailable`
      : copy.truncated ? "; bounded by the copy quota" : "";
    showToast(`Copied ${fragments.length.toLocaleString()} plug-in text ${fragments.length === 1 ? "item" : "items"}${suffix}.`);
  } catch (error) {
    showToast("Could not copy selection: " + error.message);
  }
}

function applyLocalMarkerSelection(items, marked) {
  items.forEach((item) => {
    const projection = rememberTimelineEntryProjection(item);
    if (marked) {
      state.localMarkedTimelineEntryIds.add(projection.entryId);
      state.markedTimelineEntryIds.add(projection.entryId);
    } else {
      state.localMarkedTimelineEntryIds.delete(projection.entryId);
      if (state.durableReview.markedEntryIds.has(projection.entryId)) {
        state.markedTimelineEntryIds.add(projection.entryId);
      } else {
        state.markedTimelineEntryIds.delete(projection.entryId);
      }
      forgetTimelineEntryProjection(projection.entryId);
    }
  });
}

function uniqueReviewSubjects(items, { eventsOnly = false } = {}) {
  const byKey = new Map();
  items.forEach((item) => {
    const subject = exactReviewSubject(item);
    if (!subject || (eventsOnly && subject.kind !== "event")) return;
    byKey.set(reviewSubjectKey(subject), subject);
  });
  return [...byKey.values()];
}

function randomIdempotencyKey(prefix) {
  const nonce = typeof globalThis.crypto?.randomUUID === "function"
    ? globalThis.crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  return `${prefix}-${nonce}`;
}

async function durableReviewRecord(
  collection,
  recordId,
  connectionToken,
) {
  const config = durableReviewTokenConfig(connectionToken);
  try {
    return await awaitCurrentDurableReview(
      () => controlPlaneRequest(
        `${durableReviewScopePath(config)}/${collection}/${encodeURIComponent(recordId)}`,
        { reviewConfig: config },
      ),
      () => durableReviewTokenIsCurrent(connectionToken),
    );
  } catch (error) {
    if (error instanceof ControlPlaneRequestError && error.status === 404) {
      return null;
    }
    throw error;
  }
}

async function createDurableMarkerAnnotation(items, connectionToken) {
  if (!durableReviewTokenIsCurrent(connectionToken) || !isDurableReviewWritable()) {
    throw new StaleDurableReviewConnectionError();
  }
  const config = durableReviewTokenConfig(connectionToken);
  const subjects = uniqueReviewSubjects(items).filter((subject) => {
    const entryId = entryIdForReviewSubject(subject);
    return !state.durableReview.annotationIdsByEntry.has(entryId);
  });
  if (!subjects.length) return 0;
  const requestBody = {
    kind: "marker",
    subjects,
    title: `Timeline review marker (${subjects.length})`,
    body: "Selected in the normalized event log.",
    tags: ["single-node-ui", "timeline-marker"],
  };
  const pending = await pendingDurableReviewMutation(
    connectionToken,
    "timeline-marker",
    requestBody,
    "annotation",
  );
  let annotation;
  try {
    annotation = await controlPlaneRequest(
      `${durableReviewScopePath(config)}/annotations`,
      durableCreationRequestOptions({
        idempotencyKey: pending.idempotencyKey,
        body: {
          ...requestBody,
          annotation_id: pending.recordId,
        },
        reviewConfig: config,
      }),
    );
  } catch (error) {
    if (durableMutationDisposition(error) === "discard") {
      completeDurableReviewMutation(pending);
      throw error;
    }
    try {
      annotation = await durableReviewRecord(
        "annotations",
        pending.recordId,
        connectionToken,
      );
    } catch (_reconciliationError) {
      throw error;
    }
    if (!annotation) throw error;
  }
  completeDurableReviewMutation(pending);
  if (!durableReviewTokenIsCurrent(connectionToken)) return subjects.length;
  rememberDurableAnnotation(annotation, connectionToken);
  subjects.forEach((subject) => {
    const entryId = entryIdForReviewSubject(subject);
    state.localMarkedTimelineEntryIds.delete(entryId);
  });
  return subjects.length;
}

async function removeDurableMarkerAnnotations(items, connectionToken) {
  if (!durableReviewTokenIsCurrent(connectionToken) || !isDurableReviewWritable()) {
    throw new StaleDurableReviewConnectionError();
  }
  const config = durableReviewTokenConfig(connectionToken);
  const selectedSubjects = uniqueReviewSubjects(items);
  const selectedKeys = new Set(selectedSubjects.map(reviewSubjectKey));
  const selectedEntryIds = new Set(
    selectedSubjects.map(entryIdForReviewSubject).filter(Boolean),
  );
  const affected = [...state.durableReview.annotations.values()].filter(
    (annotation) => annotation.kind === "marker"
      && (annotation.subjects || []).some(
        (subject) => selectedKeys.has(reviewSubjectKey(subject)),
      ),
  );
  try {
    for (const annotation of affected) {
      const remaining = (annotation.subjects || []).filter(
        (subject) => !selectedKeys.has(reviewSubjectKey(subject)),
      );
      const path = `${durableReviewScopePath(config)}/annotations/${encodeURIComponent(annotation.annotation_id)}`;
      if (remaining.length) {
        await controlPlaneRequest(path, durableConditionalRequestOptions({
          method: "PATCH",
          version: annotation.version,
          body: { subjects: remaining },
          reviewConfig: config,
        }));
      } else {
        await controlPlaneRequest(path, durableConditionalRequestOptions({
          method: "DELETE",
          version: annotation.version,
          reviewConfig: config,
        }));
      }
    }
  } catch (error) {
    let reconciled = false;
    try {
      reconciled = await loadDurableReviewAnnotations(connectionToken);
    } catch (_reconciliationError) {
      // Preserve the last known durable state when reconciliation is unavailable.
    }
    if (
      reconciled
      && [...selectedEntryIds].every(
        (entryId) => !state.durableReview.markedEntryIds.has(entryId),
      )
    ) {
      return selectedKeys.size;
    }
    throw error;
  }
  if (!durableReviewTokenIsCurrent(connectionToken)) {
    return selectedKeys.size;
  }
  items.forEach((item) => {
    const subject = exactReviewSubject(item);
    if (!subject) return;
    state.localMarkedTimelineEntryIds.delete(entryIdForReviewSubject(subject));
  });
  try {
    await loadDurableReviewAnnotations(connectionToken);
  } catch (_reloadError) {
    if (durableReviewTokenIsCurrent(connectionToken)) {
      for (const entryId of selectedEntryIds) {
        state.durableReview.markedEntryIds.delete(entryId);
        state.durableReview.annotationIdsByEntry.delete(entryId);
        if (!state.localMarkedTimelineEntryIds.has(entryId)) {
          state.markedTimelineEntryIds.delete(entryId);
        }
        forgetTimelineEntryProjection(entryId);
      }
      state.durableReview.detail = "Markers were removed durably. The full annotation index will refresh on reconnect.";
      rerenderTimelinePreservingScroll();
      renderEventTableWindow();
      syncDurableReviewControls();
    }
  }
  return selectedKeys.size;
}

async function applyDurableMarkerAction(items, marked, connectionToken) {
  try {
    return marked
      ? await createDurableMarkerAnnotation(items, connectionToken)
      : await removeDurableMarkerAnnotations(items, connectionToken);
  } catch (error) {
    await reconcileControlPlaneVersionConflict(error, {
      isCurrent: () => durableReviewTokenIsCurrent(connectionToken),
      reload: () => loadDurableReviewAnnotations(connectionToken),
    });
    throw error;
  }
}

async function createDurableCorrelation(
  subjects,
  linkType,
  rationale,
  connectionToken,
) {
  if (!durableReviewTokenIsCurrent(connectionToken) || !isDurableReviewWritable()) {
    throw new StaleDurableReviewConnectionError();
  }
  const config = durableReviewTokenConfig(connectionToken);
  const requestBody = {
    subjects,
    edges: subjects.slice(0, -1).map((_subject, index) => ({
      source_ordinal: index,
      target_ordinal: index + 1,
      link_type: linkType,
      directed: true,
    })),
    rationale,
    tags: ["manual", "single-node-ui"],
  };
  const pending = await pendingDurableReviewMutation(
    connectionToken,
    "manual-correlation",
    requestBody,
    "correlation",
  );
  let correlation;
  try {
    correlation = await controlPlaneRequest(
      `${durableReviewScopePath(config)}/correlations`,
      durableCreationRequestOptions({
        idempotencyKey: pending.idempotencyKey,
        body: {
          ...requestBody,
          correlation_id: pending.recordId,
        },
        reviewConfig: config,
      }),
    );
  } catch (error) {
    if (durableMutationDisposition(error) === "discard") {
      completeDurableReviewMutation(pending);
      throw error;
    }
    try {
      correlation = await durableReviewRecord(
        "correlations",
        pending.recordId,
        connectionToken,
      );
    } catch (_reconciliationError) {
      throw error;
    }
    if (!correlation) throw error;
  }
  completeDurableReviewMutation(pending);
  if (durableReviewTokenIsCurrent(connectionToken)) {
    try {
      await loadDurableReviewAnnotations(connectionToken);
    } catch (_reloadError) {
      state.durableReview.detail = "Correlation saved. Marker and correlation counts will refresh on reconnect.";
      syncDurableReviewControls();
    }
  }
  return correlation;
}

async function openManualCorrelationDialog() {
  if (!isDurableReviewWritable()) {
    byId("durable-review-setup").open = true;
    showToast(
      state.durableReview.pendingJournalBlocked
        ? "Reset the unresolved mutation journal before creating a correlation."
        : isDurableReviewReady()
        ? "This durable review identity is read only."
        : "Connect a writable durable review scope before creating a correlation.",
    );
    return;
  }
  try {
    const payload = await resolveEventLogSelection();
    const subjects = uniqueReviewSubjects(payload.items || [], { eventsOnly: true });
    if (subjects.length < 2) {
      throw new Error("Select at least two normalized events; source records are not correlation endpoints.");
    }
    if (subjects.length > 1024) {
      throw new Error("A manual correlation supports at most 1,024 exact event subjects.");
    }
    state.durableReview.pendingCorrelationSubjects = subjects;
    const ignored = (payload.items || []).length - subjects.length;
    byId("correlation-selection-summary").textContent = `${subjects.length.toLocaleString()} exact events will be connected in displayed order${ignored > 0 ? `; ${ignored.toLocaleString()} source or duplicate ${ignored === 1 ? "row is" : "rows are"} excluded` : ""}.`;
    byId("correlation-dialog").showModal();
    byId("correlation-link-type").focus();
  } catch (error) {
    showToast("Could not prepare correlation: " + error.message);
  }
}

function closeManualCorrelationDialog() {
  const dialog = byId("correlation-dialog");
  if (dialog.open) dialog.close();
  state.durableReview.pendingCorrelationSubjects = [];
}

async function saveManualCorrelation(event) {
  event.preventDefault();
  const subjects = state.durableReview.pendingCorrelationSubjects;
  if (!isDurableReviewWritable() || subjects.length < 2) {
    closeManualCorrelationDialog();
    showToast("The durable review scope or event selection changed.");
    return;
  }
  const linkType = byId("correlation-link-type").value.trim();
  const rationale = byId("correlation-rationale").value.trim();
  if (!linkType) {
    byId("correlation-link-type").focus();
    return;
  }
  const operationOwner = beginDurableReviewOperation(
    "correlation",
    ["connect", "marker", "correlation", "report"],
  );
  if (!operationOwner) {
    showToast("Wait for the current durable review write to finish.");
    return;
  }
  const connectionToken = durableReviewConnectionToken();
  if (!connectionToken) {
    finishDurableReviewOperation("correlation", operationOwner);
    closeManualCorrelationDialog();
    return;
  }
  const submit = byId("correlation-submit");
  submit.disabled = true;
  submit.setAttribute("aria-busy", "true");
  try {
    await createDurableCorrelation(
      subjects,
      linkType,
      rationale,
      connectionToken,
    );
    if (!durableReviewTokenIsCurrent(connectionToken)) return;
    closeManualCorrelationDialog();
    byId("correlation-rationale").value = "";
    showToast(`Saved a durable correlation across ${subjects.length.toLocaleString()} events.`);
  } catch (error) {
    if (error?.ambiguous && durableReviewTokenIsCurrent(connectionToken)) {
      state.durableReview.detail = "Correlation outcome is uncertain. Retry without changing the form to reuse the same operation identity, or reconnect to reconcile it.";
      syncDurableReviewControls();
    } else if (
      durableReviewUnavailable(error)
      && durableReviewTokenIsCurrent(connectionToken)
    ) {
      setDurableReviewStatus(
        "error",
        `Control plane unavailable: ${error.message}. Correlations require a durable connection.`,
      );
    }
    showToast("Could not save correlation: " + error.message);
  } finally {
    submit.disabled = false;
    submit.setAttribute("aria-busy", "false");
    finishDurableReviewOperation("correlation", operationOwner);
  }
}

async function copyDurableCorrelationReport() {
  const operationOwner = beginDurableReviewOperation(
    "report",
    ["connect", "marker", "correlation", "report"],
  );
  if (!operationOwner) return;
  const connectionToken = durableReviewConnectionToken();
  try {
    const markdown = await durableCorrelationReport(
      "markdown",
      null,
      connectionToken,
    );
    if (!durableReviewTokenIsCurrent(connectionToken)) return;
    await writeClipboardText(markdown);
    showToast("Copied the AI-friendly correlation report.");
  } catch (error) {
    showToast("Could not copy correlation report: " + error.message);
  } finally {
    finishDurableReviewOperation("report", operationOwner);
  }
}

async function downloadDurableCorrelationReport() {
  const operationOwner = beginDurableReviewOperation(
    "report",
    ["connect", "marker", "correlation", "report"],
  );
  if (!operationOwner) return;
  const connectionToken = durableReviewConnectionToken();
  try {
    const markdown = await durableCorrelationReport(
      "markdown",
      null,
      connectionToken,
    );
    if (!durableReviewTokenIsCurrent(connectionToken)) return;
    const blob = new Blob([markdown], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    const reportScope = selectedDurableReportScope();
    const safeScope = String(reportScope?.id || state.durableReview.catalogRevisionId)
      .replace(/[^a-zA-Z0-9._-]+/g, "-")
      .slice(0, 120);
    anchor.download = `correlation-report-${safeScope || "review"}.md`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 0);
    showToast("Downloaded the AI-friendly correlation report.");
  } catch (error) {
    showToast("Could not download correlation report: " + error.message);
  } finally {
    finishDurableReviewOperation("report", operationOwner);
  }
}

async function applyEventLogTimelineAction(action) {
  const durableMarkerAction = ["mark", "unmark"].includes(action);
  const operationOwner = durableMarkerAction
    ? beginDurableReviewOperation(
      "marker",
      ["connect", "marker", "correlation", "report"],
    )
    : null;
  if (durableMarkerAction && !operationOwner) {
    showToast("Wait for the current review write to finish.");
    return;
  }
  const durableAtStart = durableMarkerAction && isDurableReviewReady();
  const writableAtStart = durableMarkerAction && isDurableReviewWritable();
  const connectionToken = writableAtStart
    ? durableReviewConnectionToken()
    : null;
  try {
    if (durableAtStart && !writableAtStart) {
      throw new Error(
        state.durableReview.pendingJournalBlocked
          ? "Reset the unresolved mutation journal before another durable write."
          : "This durable review identity is read only.",
      );
    }
    const payload = await resolveEventLogSelection();
    const items = payload.items || [];
    if (writableAtStart) {
      if (!durableReviewTokenIsCurrent(connectionToken)) {
        throw new StaleDurableReviewConnectionError();
      }
      try {
        await applyDurableMarkerAction(
          items,
          action === "mark",
          connectionToken,
        );
        if (!durableReviewTokenIsCurrent(connectionToken)) {
          throw new StaleDurableReviewConnectionError();
        }
      } catch (error) {
        if (error?.ambiguous && durableReviewTokenIsCurrent(connectionToken)) {
          state.durableReview.detail = "Marker outcome is uncertain. The last confirmed durable markers remain visible; retry to reuse the same operation identity or reconnect to reconcile.";
          syncDurableReviewControls();
        } else if (
          durableReviewUnavailable(error)
          && durableReviewTokenIsCurrent(connectionToken)
        ) {
          setDurableReviewStatus(
            "error",
            `Control plane unavailable: ${error.message}. The last confirmed durable markers remain visible.`,
          );
        }
        throw error;
      }
    } else if (action === "mark") {
      applyLocalMarkerSelection(items, true);
    } else if (action === "unmark") {
      applyLocalMarkerSelection(items, false);
    }
    items.forEach((item) => {
      const entryId = String(
        item.entry_id || `${String(item.stream_kind || "event")}:${String(item.uid || "")}`,
      );
      if (action === "hide") {
        const projection = rememberTimelineEntryProjection(item);
        state.hiddenTimelineEntryIds.add(projection.entryId);
      }
      if (action === "show") state.hiddenTimelineEntryIds.delete(entryId);
      if (
        action === "mark"
        && (
          state.localMarkedTimelineEntryIds.has(entryId)
          || state.durableReview.markedEntryIds.has(entryId)
        )
      ) {
        state.markedTimelineEntryIds.add(entryId);
      }
      if (
        action === "unmark"
        && !state.localMarkedTimelineEntryIds.has(entryId)
        && !state.durableReview.markedEntryIds.has(entryId)
      ) {
        state.markedTimelineEntryIds.delete(entryId);
      }
      forgetTimelineEntryProjection(entryId);
    });
    pruneServerEventLogOwnedCaches();
    rerenderTimelinePreservingScroll();
    renderEventTableWindow();
    const verb = {
      hide: "Hidden",
      show: "Shown",
      mark: "Marked",
      unmark: "Unmarked",
    }[action];
    showToast(`${verb} ${items.length.toLocaleString()} selected ${items.length === 1 ? "item" : "items"} in the timeline.`);
  } catch (error) {
    showToast("Could not update timeline items: " + error.message);
  } finally {
    if (operationOwner) {
      finishDurableReviewOperation("marker", operationOwner);
    }
  }
}

async function revealFocusedEventLogSelection() {
  try {
    const payload = await resolveEventLogSelection();
    const focus = state.eventLogSelectionFocus;
    const item = (payload.items || []).find(
      (candidate) => Number(candidate.display_index) === focus,
    ) || payload.items?.[0];
    if (!item) return;
    const projection = rememberTimelineEntryProjection(item);
    if (projection.streamKind === "source") {
      await jumpSourceRecordToTimeline(projection.uid);
    } else {
      await jumpToTimelineEvent(projection.uid);
    }
    forgetTimelineEntryProjection(projection.entryId);
    pruneServerEventLogOwnedCaches();
  } catch (error) {
    showToast("Could not reveal selection: " + error.message);
  }
}

function scheduleEventLogWindow() {
  if (state.eventLogRenderFrame !== null) return;
  state.eventLogRenderFrame = window.requestAnimationFrame(() => {
    state.eventLogRenderFrame = null;
    renderEventTableWindow();
  });
}

function renderSourceRecordGroupControls() {
  const host = byId("event-source-group-controls");
  host.innerHTML = [...state.sourceRecordGroups.values()].map((descriptor) => {
    const groupId = String(descriptor.group_id);
    const label = String(descriptor.label || titleCase(groupId));
    const description = String(descriptor.description || label);
    return `<label title="${escapeHtml(description)}">`
      + `<input type="checkbox" data-source-group-id="${escapeHtml(groupId)}" />`
      + `${escapeHtml(label)}</label>`;
  }).join("");
}

function syncEventLogIncludeControls() {
  byId("event-include-normalized").checked = state.eventLogInclude.normalized;
  renderSourceRecordGroupControls();
  byId("event-source-group-controls")
    .querySelectorAll("input[data-source-group-id]")
    .forEach((input) => {
      input.checked = state.includedSourceRecordGroups.has(input.dataset.sourceGroupId);
    });
}

function focusServerEventLogTarget(entryId, virtualIndex) {
  const scroll = byId("event-log-scroll");
  scroll.scrollTop = virtualScrollTopForIndex({
    index: virtualIndex,
    rowCount: state.eventLogRows.length,
    rowHeight: EVENT_LOG_ROW_HEIGHT,
    maximumHeight: EVENT_LOG_MAX_SCROLL_HEIGHT,
    viewportHeight: scroll.clientHeight,
  });
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

function focusEventLogSelectionIndex(selectionIndex) {
  const maximum = Math.max(0, state.eventLogSelectableCount - 1);
  const index = Math.max(0, Math.min(maximum, Math.trunc(Number(selectionIndex))));
  const scroll = byId("event-log-scroll");
  const virtualIndex = usesServerWindowedHistory()
    ? serverEventLogVirtualRowForDataIndex(index)
    : state.eventLogVirtualIndexBySelectionIndex[index] ?? index + 1;
  scroll.scrollTop = virtualScrollTopForIndex({
    index: virtualIndex,
    rowCount: state.eventLogRows.length,
    rowHeight: EVENT_LOG_ROW_HEIGHT,
    maximumHeight: EVENT_LOG_MAX_SCROLL_HEIGHT,
    viewportHeight: scroll.clientHeight,
  });
  renderEventTableWindow();
  window.requestAnimationFrame(() => {
    const row = byId("event-table-body")
      .querySelector(`tr[data-selection-index="${index}"]`);
    row?.focus({ preventScroll: true });
  });
}

async function locateServerEventLogEntry(entryId) {
  const source = entryId.startsWith("source:");
  const uid = entryId.slice(source ? "source:".length : "event:".length);
  if (!uid) return;
  if (source) {
    const record = state.sourceRecordByUid.get(uid);
    if (record) {
      includeSourceRecordGroup(record);
    } else {
      // The source type is not known until the locate response arrives.
      includeAllSourceRecordGroups();
    }
  } else {
    state.eventLogInclude.normalized = true;
  }
  syncEventLogIncludeControls();
  byId("event-layer-filter").value = "";
  byId("event-search").value = "";
  prepareServerEventLogQuery({ requestFirstPage: false });
  const queryId = state.eventLogServerQueryId;
  const locateRequestId = ++state.eventLogLocateRequestId;
  try {
    const payload = await analysisRuntimeApi(revisionPath("event-log/query"), {
      method: "POST",
      body: JSON.stringify(serverEventLogRequestBody(0, {
        kind: source ? "source" : "event",
        uid,
      })),
    });
    if (queryId !== state.eventLogServerQueryId || locateRequestId !== state.eventLogLocateRequestId) return;
    applyServerEventLogPayload(payload, 0, queryId);
    const dataIndex = payload?.located_display_index;
    if (dataIndex === null || dataIndex === undefined) {
      renderEventTableWindow();
      showToast("The target record is not available in this retained stream.");
      return;
    }
    const safeDataIndex = Math.max(0, Number(dataIndex));
    const pageOffset = Math.floor(safeDataIndex / EVENT_LOG_PAGE_SIZE) * EVENT_LOG_PAGE_SIZE;
    if (!state.eventLogServerItems.has(safeDataIndex)) await requestServerEventLogPage(pageOffset);
    if (queryId !== state.eventLogServerQueryId || locateRequestId !== state.eventLogLocateRequestId) return;
    const virtualIndex = serverEventLogVirtualRowForDataIndex(safeDataIndex);
    focusServerEventLogTarget(entryId, virtualIndex);
  } catch (error) {
    if (queryId !== state.eventLogServerQueryId || locateRequestId !== state.eventLogLocateRequestId) return;
    showToast(`Could not locate the target record: ${error.message}`);
  }
}

function jumpToLogEntry(entryId) {
  if (usesServerWindowedHistory()) {
    locateServerEventLogEntry(entryId);
    return;
  }
  if (entryId.startsWith("event:")) state.eventLogInclude.normalized = true;
  if (entryId.startsWith("source:")) {
    const record = state.sourceRecordByUid.get(entryId.slice("source:".length));
    if (record) includeSourceRecordGroup(record);
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
  scroll.scrollTop = virtualScrollTopForIndex({
    index,
    rowCount: state.eventLogRows.length,
    rowHeight: EVENT_LOG_ROW_HEIGHT,
    maximumHeight: EVENT_LOG_MAX_SCROLL_HEIGHT,
    viewportHeight: scroll.clientHeight,
  });
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
  byId("gap-list").innerHTML = (state.dataset.gaps || []).map((gap) => {
    const area = gap.area || "Runtime";
    const detail = gap.detail || gap.description || "No additional detail supplied.";
    return `<label class="gap-item"><input type="checkbox" value="${escapeHtml(gap.id)}" ${saved.selected.includes(gap.id) ? "checked" : ""}><span><strong>${escapeHtml(gap.title || gap.id || "Unspecified gap")}</strong><small>${escapeHtml(`${area} / ${detail}`)}</small></span><span class="gap-status">${escapeHtml(gap.status || "open")}</span></label>`;
  }).join("");
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
  const workspace = workspaceMetadata();
  const workspaceLabel = workspace.label || workspace.revision_id || workspace.workspace_id || "current workspace";
  return ["Router State Lab - design review", `Workspace: ${workspaceLabel}`, "", "Prioritized gaps:", ...(selected.length ? selected.map((gap) => `- [${gap.area || "Runtime"}] ${gap.title || gap.id || "Unspecified gap"}: ${gap.detail || gap.description || "No additional detail supplied."}`) : ["- None selected yet"]), "", "Reviewer notes:", saved.notes.trim() || "(none)"].join("\n");
}

async function copyReview() {
  const text = reviewText();
  try { await navigator.clipboard.writeText(text); }
  catch (_error) { const area = document.createElement("textarea"); area.value = text; area.style.position = "fixed"; area.style.opacity = "0"; document.body.appendChild(area); area.select(); document.execCommand("copy"); area.remove(); }
  showToast("Review summary copied.");
}

function initializeDurableReviewSetup() {
  const config = savedDurableReviewConfig();
  populateDurableReviewInputs(config);
  state.durableReview.config = config;
  let journalDetail = "";
  try {
    state.durableReview.pendingMutations = loadPendingReviewMutations(
      localStorage,
      DURABLE_REVIEW_PENDING_STORAGE_KEY,
      pendingJournalOptions(),
    );
    state.durableReview.pendingJournalBlocked = false;
    state.durableReview.pendingJournalError = "";
    state.durableReview.pendingJournalRecovery = "";
    if (state.durableReview.pendingMutations.size) {
      journalDetail = ` ${state.durableReview.pendingMutations.size.toLocaleString()} unresolved durable ${state.durableReview.pendingMutations.size === 1 ? "write was" : "writes were"} restored for reconciliation.`;
    }
  } catch (error) {
    state.durableReview.pendingMutations = new Map();
    state.durableReview.pendingJournalBlocked = true;
    state.durableReview.pendingJournalError = String(error.message).slice(0, 512);
    state.durableReview.pendingJournalRecovery = "all";
    journalDetail = ` ${state.durableReview.pendingJournalError}`;
  }
  setDurableReviewStatus(
    "local",
    config
      ? `Saved explicit scope found; connecting without blocking the local workspace.${journalDetail}`
      : `Add the four scope values to persist markers and correlations.${journalDetail}`,
  );
}

function timelineZoomControlValue(zoom) {
  if (!Number.isFinite(zoom)) return "1";
  return zoom >= 1_000_000
    ? zoom.toExponential(5)
    : Number(zoom.toPrecision(6)).toString();
}

function timelineViewportSnapshot() {
  return {
    zoom: state.zoom,
    startNs: state.timelineWindowStartNs,
    endNs: state.timelineWindowEndNs,
  };
}

function timelineViewSnapshotsEqual(left, right) {
  return Boolean(left && right)
    && Math.abs(left.zoom - right.zoom) <= Number.EPSILON * Math.max(1, left.zoom, right.zoom)
    && left.startNs === right.startNs
    && left.endNs === right.endNs;
}

function updateTimelineCommandAvailability() {
  const priorFocus = document.activeElement;
  const bounds = rangeBounds();
  const [windowStartNs, windowEndNs] = timelineWindowBounds();
  const earlier = byId("timeline-pan-earlier");
  const later = byId("timeline-pan-later");
  const windowReadout = byId("timeline-window-readout");
  if (earlier) earlier.disabled = windowStartNs <= state.viewStartNs;
  if (later) later.disabled = windowEndNs >= state.viewEndNs;
  if (windowReadout) {
    const precision = visibleTimelineOffsetPrecision();
    windowReadout.textContent = `${formatOffset(windowStartNs, precision)} – ${formatOffset(windowEndNs, precision)}`;
  }
  const hasCenter = Boolean(bounds) || state.cursorSelected;
  const back = byId("timeline-view-back");
  const forward = byId("timeline-view-forward");
  const zoomOut = byId("timeline-zoom-out");
  const zoomSelection = byId("timeline-zoom-selection");
  const center = byId("timeline-center");
  if (back) back.disabled = state.timelineViewHistoryIndex <= 0;
  if (forward) forward.disabled = state.timelineViewHistoryIndex < 0
    || state.timelineViewHistoryIndex >= state.timelineViewHistory.length - 1;
  if (zoomOut) zoomOut.disabled = state.zoom <= 1;
  if (zoomSelection) zoomSelection.disabled = !bounds;
  if (center) center.disabled = !hasCenter;
  syncTimelineToolbarTabStop();
  // Keep keyboard focus usable when a pan button reaches its capture boundary.
  if (priorFocus && (priorFocus === earlier || priorFocus === later) && priorFocus.disabled) {
    const opposite = priorFocus === earlier ? later : earlier;
    (opposite && !opposite.disabled ? opposite : byId("timeline-scroll"))
      ?.focus({ preventScroll: true });
  }
  if (
    priorFocus instanceof HTMLButtonElement
    && priorFocus.closest("#timeline-viewport-controls")
    && priorFocus.disabled
  ) {
    timelineToolbarItems().find((item) => item.tabIndex === 0 && !item.disabled)
      ?.focus({ preventScroll: true });
  }
}

function timelineToolbarItems() {
  // Keep the editable zoom input in the ordinary Tab sequence. The buttons
  // form the roving-focus subset; otherwise the input's native arrow editing
  // and the toolbar's arrow navigation make each other unreachable.
  return [...(byId("timeline-viewport-controls")?.querySelectorAll("button") || [])];
}

function syncTimelineToolbarTabStop(preferred = null) {
  const items = timelineToolbarItems();
  if (!items.length) return;
  const current = preferred && items.includes(preferred) && !preferred.disabled
    ? preferred
    : items.find((item) => item.tabIndex === 0 && !item.disabled)
      || items.find((item) => !item.disabled);
  items.forEach((item) => { item.tabIndex = item === current ? 0 : -1; });
}

function timelineToolbarKeyDown(event) {
  if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
  // Let number/text controls keep their native caret, increment, Home, and
  // End behavior. Tab exits the composite toolbar from the editable control.
  if (event.target.matches?.("input, textarea, [contenteditable='true']")) return;
  const items = timelineToolbarItems().filter((item) => !item.disabled);
  if (!items.length) return;
  const currentIndex = Math.max(0, items.indexOf(event.target));
  const nextIndex = event.key === "Home" ? 0
    : event.key === "End" ? items.length - 1
      : event.key === "ArrowLeft"
        ? (currentIndex - 1 + items.length) % items.length
        : (currentIndex + 1) % items.length;
  event.preventDefault();
  const nextItem = items[nextIndex];
  syncTimelineToolbarTabStop(nextItem);
  nextItem.focus({ preventScroll: true });
  const toolbar = byId("timeline-viewport-controls");
  const toolbarRect = toolbar.getBoundingClientRect();
  const itemRect = nextItem.getBoundingClientRect();
  if (itemRect.left < toolbarRect.left) toolbar.scrollLeft -= toolbarRect.left - itemRect.left;
  else if (itemRect.right > toolbarRect.right) toolbar.scrollLeft += itemRect.right - toolbarRect.right;
}

function rememberTimelineView({ replace = false } = {}) {
  if (state.timelineViewRestoring) return;
  const snapshot = timelineViewportSnapshot();
  const current = state.timelineViewHistory[state.timelineViewHistoryIndex];
  if (timelineViewSnapshotsEqual(current, snapshot)) {
    updateTimelineCommandAvailability();
    return;
  }
  if (replace && state.timelineViewHistoryIndex >= 0) {
    state.timelineViewHistory[state.timelineViewHistoryIndex] = snapshot;
  } else {
    if (state.timelineViewHistoryIndex < state.timelineViewHistory.length - 1) {
      state.timelineViewHistory.splice(state.timelineViewHistoryIndex + 1);
    }
    state.timelineViewHistory.push(snapshot);
    if (state.timelineViewHistory.length > TIMELINE_VIEW_HISTORY_LIMIT) {
      state.timelineViewHistory.shift();
    }
    state.timelineViewHistoryIndex = state.timelineViewHistory.length - 1;
  }
  updateTimelineCommandAvailability();
}

function scheduleTimelineViewHistory() {
  window.clearTimeout(state.timelineViewHistoryTimer);
  state.timelineViewHistoryTimer = window.setTimeout(
    () => rememberTimelineView(),
    TIMELINE_WHEEL_HISTORY_DELAY_MS,
  );
}

function cancelScheduledTimelineZoom({ commitHistory = false } = {}) {
  const hadBurst = state.timelineWheelBurstActive;
  if (state.timelineWheelFrameId !== null) {
    window.cancelAnimationFrame(state.timelineWheelFrameId);
  }
  if (state.timelinePanFrameId !== null) {
    window.cancelAnimationFrame(state.timelinePanFrameId);
  }
  window.clearTimeout(state.timelineWheelHistoryTimer);
  state.timelineWheelFrameId = null;
  state.timelineWheelTargetZoom = null;
  state.timelineWheelAnchorNs = null;
  state.timelineWheelAnchorClientX = null;
  state.timelinePanFrameId = null;
  state.timelinePanDeltaPx = 0;
  state.timelineWheelBurstActive = false;
  state.timelineWheelMode = null;
  state.timelineWheelHistoryTimer = null;
  if (commitHistory && hadBurst) rememberTimelineView();
}

function beginTimelineWheelBurst(mode) {
  if (state.timelineWheelBurstActive && state.timelineWheelMode !== mode) {
    finishTimelineWheelBurst();
  }
  if (!state.timelineWheelBurstActive) {
    state.timelineWheelBurstActive = true;
    rememberTimelineView();
  }
  state.timelineWheelMode = mode;
}

function scheduleTimelineWheelBurstFinish() {
  window.clearTimeout(state.timelineWheelHistoryTimer);
  state.timelineWheelHistoryTimer = window.setTimeout(
    finishTimelineWheelBurst,
    TIMELINE_WHEEL_HISTORY_DELAY_MS,
  );
}

function settlePendingTimelineWheelFrames() {
  const targetZoom = state.timelineWheelTargetZoom;
  const anchorNs = state.timelineWheelAnchorNs;
  const anchorClientX = state.timelineWheelAnchorClientX;
  const panDeltaPx = state.timelinePanDeltaPx;
  if (state.timelineWheelFrameId !== null) {
    window.cancelAnimationFrame(state.timelineWheelFrameId);
  }
  if (state.timelinePanFrameId !== null) {
    window.cancelAnimationFrame(state.timelinePanFrameId);
  }
  state.timelineWheelFrameId = null;
  state.timelineWheelTargetZoom = null;
  state.timelinePanFrameId = null;
  state.timelinePanDeltaPx = 0;
  if (targetZoom !== null) {
    applyTimelineZoom(targetZoom, {
      anchorNs,
      anchorClientX,
      recordHistory: false,
      fromWheel: true,
    });
  }
  if (panDeltaPx !== 0) {
    panTimelineViewportByPixels(panDeltaPx, {
      recordHistory: false,
      fromWheel: true,
    });
  }
}

function finishTimelineWheelBurst() {
  window.clearTimeout(state.timelineWheelHistoryTimer);
  state.timelineWheelHistoryTimer = null;
  if (!state.timelineWheelBurstActive) return;
  // Timers may run while requestAnimationFrame is throttled in a background
  // tab. Settle queued work before committing the burst's final history view.
  settlePendingTimelineWheelFrames();
  state.timelineWheelBurstActive = false;
  state.timelineWheelMode = null;
  state.timelineWheelAnchorNs = null;
  state.timelineWheelAnchorClientX = null;
  rememberTimelineView();
  scheduleTimelineWindowRefresh();
}

function restoreTimelineView(index) {
  const relativeOffset = index - state.timelineViewHistoryIndex;
  cancelScheduledTimelineZoom({ commitHistory: true });
  index = state.timelineViewHistoryIndex + relativeOffset;
  if (index < 0 || index >= state.timelineViewHistory.length) return false;
  const snapshot = state.timelineViewHistory[index];
  state.timelineViewRestoring = true;
  state.timelineViewHistoryIndex = index;
  invalidatePendingTimelineWindowRequest();
  state.zoom = snapshot.zoom;
  state.timelineWindowStartNs = snapshot.startNs;
  state.timelineWindowEndNs = snapshot.endNs;
  byId("timeline-zoom").value = timelineZoomControlValue(snapshot.zoom);
  renderTimeline();
  byId("timeline-scroll").scrollLeft = 0;
  byId("timeline-ruler").style.transform = "translateX(0)";
  state.timelineViewRestoring = false;
  scheduleTimelineWindowRefresh();
  updateTimelineCommandAvailability();
  return true;
}

function visibleTimelineCenterNs() {
  const [startNs, endNs] = timelineWindowBounds();
  return startNs + (endNs - startNs) / 2n;
}

function selectedTimelineCenterNs() {
  const bounds = rangeBounds();
  if (bounds) return bounds[0] + (bounds[1] - bounds[0]) / 2n;
  return state.cursorSelected ? state.cursorNs : visibleTimelineCenterNs();
}

function applyTimelineZoom(rawValue, {
  announce = false,
  anchorNs = null,
  anchorClientX = null,
  anchorOffsetPx = null,
  recordHistory = true,
  fromWheel = false,
  windowOverride = null,
} = {}) {
  const control = byId("timeline-zoom");
  const zoom = Number(rawValue);
  if (
    !Number.isFinite(zoom)
    || zoom < 1
  ) {
    const normalized = Number.isFinite(state.zoom) && state.zoom >= 1 ? state.zoom : 1;
    state.zoom = normalized;
    control.value = timelineZoomControlValue(normalized);
    control.setAttribute("aria-invalid", "true");
    if (announce) showToast("Zoom must be 1 or greater and remain representable by this browser.");
    return false;
  }
  if (!fromWheel) cancelScheduledTimelineZoom({ commitHistory: recordHistory });
  if (state.brush) finishTimelinePointer(null, true);
  const scroll = byId("timeline-scroll");
  const scrollRect = scroll.getBoundingClientRect();
  const temporalViewportWidth = timelinePhysicalTrackWidth();
  const effectiveAnchorNs = anchorNs === null ? visibleTimelineCenterNs() : clampNs(anchorNs);
  const effectiveAnchorOffset = anchorOffsetPx === null
    ? anchorClientX === null
      ? temporalViewportWidth / 2
      : Math.max(0, Math.min(
        temporalViewportWidth,
        anchorClientX - scrollRect.left - timelineLaneWidth() + scroll.scrollLeft,
      ))
    : Math.max(0, Math.min(temporalViewportWidth, anchorOffsetPx));
  let viewport;
  try {
    viewport = windowOverride || timelineWindowForZoom({
      zoom,
      anchorNs: effectiveAnchorNs,
      anchorOffsetRatio: effectiveAnchorOffset / temporalViewportWidth,
      startNs: state.viewStartNs,
      endNs: state.viewEndNs,
    });
  } catch (_error) {
    control.setAttribute("aria-invalid", "true");
    if (announce) showToast("That zoom cannot be represented by this browser viewport.");
    return false;
  }
  if (
    Math.abs(state.zoom - viewport.zoom) <= Number.EPSILON * Math.max(1, state.zoom, viewport.zoom)
    && state.timelineWindowStartNs === viewport.startNs
    && state.timelineWindowEndNs === viewport.endNs
  ) {
    control.value = timelineZoomControlValue(viewport.zoom);
    control.setAttribute("aria-invalid", "false");
    updateTimelineCommandAvailability();
    return true;
  }
  if (recordHistory) rememberTimelineView();
  if (!fromWheel) scheduleTimelineWindowRefresh();
  invalidatePendingTimelineWindowRequest();
  state.zoom = viewport.zoom;
  state.timelineWindowStartNs = viewport.startNs;
  state.timelineWindowEndNs = viewport.endNs;
  control.value = timelineZoomControlValue(viewport.zoom);
  control.setAttribute("aria-invalid", "false");
  const retainedScrollLeft = scroll.scrollLeft;
  renderTimeline();
  scroll.scrollLeft = Math.min(
    retainedScrollLeft,
    Math.max(0, scroll.scrollWidth - scroll.clientWidth),
  );
  byId("timeline-ruler").style.transform = `translateX(${-scroll.scrollLeft}px)`;
  if (recordHistory) rememberTimelineView();
  updateTimelineCommandAvailability();
  return true;
}

function zoomTimelineBy(direction, {
  anchorNs = null,
  anchorClientX = null,
  announce = true,
  recordHistory = true,
} = {}) {
  try {
    return applyTimelineZoom(timelineZoomStep(state.zoom, direction), {
      announce,
      anchorNs: anchorNs ?? selectedTimelineCenterNs(),
      anchorClientX,
      recordHistory,
    });
  } catch (_error) {
    if (announce) showToast("That zoom step cannot be represented by this browser.");
    return false;
  }
}

function fitTimelineCapture({ announce = true } = {}) {
  const changed = applyTimelineZoom(1, {
    announce,
    anchorNs: state.viewStartNs,
    anchorOffsetPx: 0,
  });
  if (changed && announce) showToast("Complete capture fitted; selections and lanes were preserved.");
  return changed;
}

function centerTimelineAt(timeNs = selectedTimelineCenterNs(), { announce = true } = {}) {
  const changed = applyTimelineZoom(state.zoom, {
    announce,
    anchorNs: timeNs,
  });
  if (changed && announce) showToast(`Centered ${formatOffset(timeNs)}.`);
  return changed;
}

function zoomToSelectedRange({ announce = true } = {}) {
  const bounds = rangeBounds();
  if (!bounds) {
    if (announce) showToast("Select a duration before zooming to it.");
    return false;
  }
  let viewport;
  try {
    viewport = timelineWindowForRange({
      rangeStartNs: bounds[0],
      rangeEndNs: bounds[1],
      startNs: state.viewStartNs,
      endNs: state.viewEndNs,
    });
  } catch (_error) {
    if (announce) showToast("The selected duration cannot be represented by this browser viewport.");
    return false;
  }
  const centerNs = bounds[0] + (bounds[1] - bounds[0]) / 2n;
  const changed = applyTimelineZoom(viewport.zoom, {
    announce,
    anchorNs: centerNs,
    windowOverride: viewport,
  });
  if (changed && announce) showToast(`Selected duration fitted at ${formatDuration(bounds[1] - bounds[0])}.`);
  return changed;
}

function selectVisibleTimelineRange() {
  const [startNs, endNs] = timelineWindowBounds();
  state.rangeStartNs = startNs;
  state.rangeEndNs = endNs;
  state.rangeSummary = null;
  byId("clear-range").hidden = false;
  updateRangeBands();
  syncRangeInputs();
  requestRangeSummary();
}

function setTimelineRangeBoundary(boundary, timeNs) {
  const value = clampNs(timeNs);
  const bounds = rangeBounds();
  const minimum = rangeMinimumNs();
  if (boundary === "start") {
    const candidateEnd = bounds?.[1]
      ?? (state.cursorSelected && state.cursorNs > value ? state.cursorNs : value + minimum);
    state.rangeStartNs = value;
    state.rangeEndNs = candidateEnd <= value ? value + minimum : candidateEnd;
  } else {
    const candidateStart = bounds?.[0]
      ?? (state.cursorSelected && state.cursorNs < value ? state.cursorNs : value - minimum);
    state.rangeStartNs = candidateStart >= value ? value - minimum : candidateStart;
    state.rangeEndNs = value;
  }
  state.rangeStartNs = clampNs(state.rangeStartNs);
  state.rangeEndNs = clampNs(state.rangeEndNs);
  if (state.rangeStartNs === state.rangeEndNs) {
    if (state.rangeEndNs + minimum <= state.viewEndNs) state.rangeEndNs += minimum;
    else if (state.rangeStartNs - minimum >= state.viewStartNs) state.rangeStartNs -= minimum;
  }
  [state.rangeStartNs, state.rangeEndNs] = rangeBounds();
  state.rangeSummary = null;
  byId("clear-range").hidden = false;
  updateRangeBands();
  syncRangeInputs();
  requestRangeSummary();
}

function panTimelineViewport(direction) {
  return panTimelineViewportByPixels(
    Number(direction) * timelinePhysicalTrackWidth() / 10,
  );
}

function panTimelineViewportByPixels(deltaPx, {
  recordHistory = true,
  fromWheel = false,
} = {}) {
  if (!Number.isFinite(deltaPx) || deltaPx === 0) return false;
  if (!fromWheel) cancelScheduledTimelineZoom({ commitHistory: recordHistory });
  const [startNs, endNs] = timelineWindowBounds();
  const duration = endNs - startNs;
  const ratio = Math.min(1, Math.abs(deltaPx) / timelinePhysicalTrackWidth());
  let step = timelineTimeAtRatio({ ratio, startNs: 0n, endNs: duration });
  if (step <= 0n) step = 1n;
  const requestedStart = startNs + (deltaPx < 0 ? -step : step);
  const maximumStart = state.viewEndNs - duration;
  const nextStart = requestedStart < state.viewStartNs
    ? state.viewStartNs
    : requestedStart > maximumStart ? maximumStart : requestedStart;
  if (nextStart === startNs) return false;
  if (recordHistory) rememberTimelineView();
  invalidatePendingTimelineWindowRequest();
  state.timelineWindowStartNs = nextStart;
  state.timelineWindowEndNs = nextStart + duration;
  renderTimeline();
  if (recordHistory) rememberTimelineView();
  if (!fromWheel) scheduleTimelineWindowRefresh();
  return true;
}

function timelineInteractionTarget(element) {
  const mark = element?.closest?.("[data-hover-key]");
  if (!mark) return null;
  const resourceId = mark.closest(".lane-track")?.dataset.resourceId || null;
  const entryId = mark.dataset.logEntryId || null;
  const projection = entryId ? state.timelineEntryProjections.get(entryId) : null;
  const isEventCluster = mark.classList.contains("event-mark") && mark.classList.contains("cluster");
  const isSourceCluster = mark.classList.contains("source-record-mark") && mark.classList.contains("cluster");
  return {
    eventUid: isEventCluster ? null : mark.dataset.eventUid || (projection?.streamKind === "event" ? projection.uid : null),
    clusterId: isEventCluster ? mark.dataset.clusterId || null : null,
    sourceRecordUid: isSourceCluster ? null : mark.dataset.sourceRecordUid || (projection?.streamKind === "source" ? projection.uid : null),
    sourceClusterId: isSourceCluster ? mark.dataset.sourceClusterId || null : null,
    revealEventUid: mark.dataset.eventUid || mark.dataset.lastEventUid || (projection?.streamKind === "event" ? projection.uid : null),
    revealSourceRecordUid: mark.dataset.sourceRecordUid || mark.dataset.lastSourceRecordUid || (projection?.streamKind === "source" ? projection.uid : null),
    hoverKey: mark.dataset.hoverKey || null,
    resourceId,
    element: mark,
  };
}

function timelineContextFromTarget(element, clientX = null) {
  const content = byId("timeline-content");
  if (!element || !content.contains(element)) return null;
  const track = element.closest?.(".lane-track");
  const row = element.closest?.(".timeline-row");
  const resourceId = track?.dataset.resourceId
    || row?.dataset.resourceId
    || element.closest?.("[data-resource-id]")?.dataset.resourceId
    || null;
  if (!track && !row) return null;
  const timedElement = element.closest?.("[data-time-ns], [data-range-start-ns][data-range-end-ns]");
  const exactTime = timedElement?.dataset.timeNs !== undefined
    ? clampNs(timedElement.dataset.timeNs)
    : timedElement?.dataset.rangeStartNs !== undefined
      ? clampNs(
        toNs(timedElement.dataset.rangeStartNs)
        + (toNs(timedElement.dataset.rangeEndNs) - toNs(timedElement.dataset.rangeStartNs)) / 2n,
      )
      : null;
  const timeNs = track && Number.isFinite(clientX)
    ? pointNsFromClientX(clientX, track)
    : exactTime ?? selectedTimelineCenterNs();
  return {
    timeNs,
    clientX: Number.isFinite(clientX) ? clientX : null,
    resourceId,
    target: timelineInteractionTarget(element),
  };
}

function timelineContextMenuItems() {
  return [...byId("timeline-context-menu").querySelectorAll("[data-timeline-action]")]
    .filter((button) => !button.hidden && !button.disabled);
}

function syncTimelineContextMenu(context = state.timelineContext) {
  const menu = byId("timeline-context-menu");
  if (!menu || !context) return;
  byId("timeline-context-time").textContent = formatOffset(
    context.timeNs,
    visibleTimelineOffsetPrecision(),
  );
  const resource = context.resourceId ? state.resourceById.get(context.resourceId) : null;
  byId("timeline-context-resource").textContent = context.resourceId
    ? resourceLabel(resource, context.resourceId)
    : "All timeline lanes";
  const resourceActions = new Set(["focus-resource", "hide-lane"]);
  menu.querySelectorAll("[data-timeline-action]").forEach((button) => {
    const action = button.dataset.timelineAction;
    if (action === "inspect") button.hidden = !context.target?.hoverKey;
    if (action === "reveal-log") button.hidden = !(
      context.target?.revealEventUid || context.target?.revealSourceRecordUid
    );
    if (resourceActions.has(action)) button.hidden = !context.resourceId;
    if (action === "zoom-selection" || action === "copy-range") button.disabled = !rangeBounds();
    if (action === "previous-view") button.disabled = state.timelineViewHistoryIndex <= 0;
    if (action === "next-view") button.disabled = state.timelineViewHistoryIndex < 0
      || state.timelineViewHistoryIndex >= state.timelineViewHistory.length - 1;
    if (action === "zoom-out") button.disabled = state.zoom <= 1;
  });
}

function closeTimelineContextMenu({ restoreFocus = false } = {}) {
  const menu = byId("timeline-context-menu");
  if (!menu || menu.hidden) return false;
  menu.hidden = true;
  byId("timeline-actions")?.setAttribute("aria-expanded", "false");
  const returnFocus = state.timelineContextReturnFocus;
  const originWasTimeline = state.timelineContextOriginWasTimeline;
  state.timelineContext = null;
  state.timelineContextReturnFocus = null;
  state.timelineContextOriginWasTimeline = false;
  if (restoreFocus) {
    const target = returnFocus?.isConnected
      ? returnFocus
      : originWasTimeline
        ? byId("timeline-scroll")
        : byId("timeline-actions") || byId("timeline-scroll");
    target?.focus({ preventScroll: true });
  }
  return true;
}

function restoreTimelineContextActionFocus(returnFocus, originWasTimeline) {
  window.requestAnimationFrame(() => {
    const target = originWasTimeline
      ? byId("timeline-scroll")
      : returnFocus?.isConnected
      ? returnFocus
      : byId("timeline-actions") || byId("timeline-scroll");
    target?.focus({ preventScroll: true });
  });
}

function positionTimelineContextMenu(clientX, clientY) {
  const menu = byId("timeline-context-menu");
  const margin = 8;
  const rect = menu.getBoundingClientRect();
  menu.style.left = `${Math.max(margin, Math.min(clientX, window.innerWidth - rect.width - margin))}px`;
  menu.style.top = `${Math.max(margin, Math.min(clientY, window.innerHeight - rect.height - margin))}px`;
}

function openTimelineContextMenu({
  element = null,
  clientX = null,
  clientY = null,
  context = null,
  keyboard = false,
} = {}) {
  const menu = byId("timeline-context-menu");
  const resolved = context || timelineContextFromTarget(element, clientX);
  if (!menu || !resolved) return false;
  closeHover();
  closeCorrelationHover();
  state.timelineContext = resolved;
  state.timelineContextOriginWasTimeline = Boolean(element?.closest?.("#timeline-content"));
  const focusableElement = element?.closest?.(
    "button, input, select, textarea, a[href], [tabindex]:not([tabindex='-1'])",
  );
  state.timelineContextReturnFocus = focusableElement instanceof HTMLElement
    ? focusableElement
    : document.activeElement instanceof HTMLElement
      && document.activeElement !== document.body
      && !menu.contains(document.activeElement)
      ? document.activeElement
      : byId("timeline-scroll");
  syncTimelineContextMenu(resolved);
  menu.hidden = false;
  menu.scrollTop = 0;
  byId("timeline-actions")?.setAttribute("aria-expanded", "true");
  const anchorRect = element?.getBoundingClientRect?.();
  const x = Number.isFinite(clientX) ? clientX : anchorRect ? anchorRect.left + Math.min(anchorRect.width / 2, 24) : window.innerWidth / 2;
  const y = Number.isFinite(clientY) ? clientY : anchorRect ? anchorRect.bottom + 4 : window.innerHeight / 2;
  positionTimelineContextMenu(x, y);
  const firstItem = timelineContextMenuItems()[0];
  firstItem?.focus({ preventScroll: true });
  firstItem?.scrollIntoView({ block: "nearest", inline: "nearest" });
  return true;
}

async function activateTimelineContextAction(action) {
  const context = state.timelineContext;
  if (!context) return;
  const target = context.target;
  const returnFocus = state.timelineContextReturnFocus;
  const originWasTimeline = state.timelineContextOriginWasTimeline;
  closeTimelineContextMenu();
  if (action === "inspect") {
    activateShortGestureTarget(target);
  } else if (action === "reveal-log") {
    if (target?.revealEventUid) jumpToNormalizedLog(target.revealEventUid, target.resourceId);
    else if (target?.revealSourceRecordUid) jumpToSourceLog(target.revealSourceRecordUid);
  } else if (action === "focus-resource" && context.resourceId) {
    selectResource(context.resourceId);
  } else if (action === "hide-lane" && context.resourceId) {
    setExplicitLaneVisibility(context.resourceId, false);
  } else if (action === "select-moment") {
    setCursor(context.timeNs);
  } else if (action === "range-start") {
    setTimelineRangeBoundary("start", context.timeNs);
  } else if (action === "range-end") {
    setTimelineRangeBoundary("end", context.timeNs);
  } else if (action === "select-visible") {
    selectVisibleTimelineRange();
  } else if (action === "zoom-in") {
    zoomTimelineBy("in", { anchorNs: context.timeNs, anchorClientX: context.clientX });
  } else if (action === "zoom-out") {
    zoomTimelineBy("out", { anchorNs: context.timeNs, anchorClientX: context.clientX });
  } else if (action === "center") {
    centerTimelineAt(context.timeNs);
  } else if (action === "zoom-selection") {
    zoomToSelectedRange();
  } else if (action === "previous-view") {
    restoreTimelineView(state.timelineViewHistoryIndex - 1);
  } else if (action === "next-view") {
    restoreTimelineView(state.timelineViewHistoryIndex + 1);
  } else if (action === "fit") {
    fitTimelineCapture();
  } else if (action === "copy-time") {
    await writeClipboardText(`${formatOffset(context.timeNs, visibleTimelineOffsetPrecision())}\t${context.timeNs} ns`);
    showToast("Timeline timestamp copied.");
  } else if (action === "copy-range") {
    const bounds = rangeBounds();
    if (bounds) {
      await writeClipboardText(`${formatOffset(bounds[0])}\t${formatOffset(bounds[1])}\t${formatDuration(bounds[1] - bounds[0])}`);
      showToast("Selected timeline range copied.");
    }
  } else if (action === "clear-selection") {
    clearTimelineSelection();
  }
  // Reveal intentionally transfers focus to the normalized log. Every other
  // action restores either the live origin or a stable timeline control after
  // any synchronous innerHTML replacement performed by renderTimeline().
  if (action !== "reveal-log") restoreTimelineContextActionFocus(returnFocus, originWasTimeline);
}

function timelineContextTabDestination(returnFocus, originWasTimeline, backwards) {
  const origin = returnFocus?.isConnected
    ? returnFocus
    : originWasTimeline
      ? byId("timeline-scroll")
      : byId("timeline-actions") || byId("timeline-scroll");
  const focusable = [...document.querySelectorAll(
    'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
  )].filter((element) => (
    element instanceof HTMLElement
    && !element.closest("[hidden]")
    && element.getClientRects().length > 0
  ));
  const originIndex = focusable.indexOf(origin);
  if (originIndex < 0) return origin;
  return focusable[originIndex + (backwards ? -1 : 1)] || origin;
}

function timelineContextMenuKeyDown(event) {
  const menu = byId("timeline-context-menu");
  if (menu.hidden) return;
  const items = timelineContextMenuItems();
  const currentIndex = items.indexOf(document.activeElement);
  let nextIndex = null;
  if (event.key === "ArrowDown") nextIndex = currentIndex < 0 ? 0 : (currentIndex + 1) % items.length;
  else if (event.key === "ArrowUp") nextIndex = currentIndex < 0 ? items.length - 1 : (currentIndex - 1 + items.length) % items.length;
  else if (event.key === "Home") nextIndex = 0;
  else if (event.key === "End") nextIndex = items.length - 1;
  else if (event.key === "Escape") {
    event.preventDefault();
    closeTimelineContextMenu({ restoreFocus: true });
    return;
  } else if (["Enter", " "].includes(event.key) && document.activeElement?.matches?.("[data-timeline-action]")) {
    event.preventDefault();
    document.activeElement.click();
    return;
  } else if (event.key === "Tab") {
    event.preventDefault();
    const returnFocus = state.timelineContextReturnFocus;
    const originWasTimeline = state.timelineContextOriginWasTimeline;
    closeTimelineContextMenu();
    timelineContextTabDestination(returnFocus, originWasTimeline, event.shiftKey)
      ?.focus({ preventScroll: true });
    return;
  } else return;
  event.preventDefault();
  const nextItem = items[nextIndex];
  nextItem?.focus({ preventScroll: true });
  nextItem?.scrollIntoView({ block: "nearest", inline: "nearest" });
}

function timelineViewportKeyDown(event) {
  if (event.defaultPrevented || event.isComposing) return;
  const directionKey = ["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown"].includes(event.key);
  if (event.repeat && !directionKey) return;
  if (event.target.closest?.("input, textarea, select, [contenteditable]:not([contenteditable='false'])")) return;
  // Endpoint handles and sliders own their arrows; do not turn range editing
  // into viewport navigation when the event bubbles through the timeline.
  if (directionKey && event.target.closest?.("[data-range-handle], [role='slider']")) return;
  if (directionKey && state.brush) {
    event.preventDefault();
    return;
  }
  if (event.key === "ContextMenu" || (event.shiftKey && event.key === "F10")) {
    event.preventDefault();
    const element = event.target === byId("timeline-scroll")
      ? byId("timeline-content").querySelector(".lane-track") || byId("timeline-content")
      : event.target;
    openTimelineContextMenu({ element, keyboard: true });
    return;
  }
  const retainStableFocus = () => {
    if (byId("timeline-content")?.contains(event.target)) {
      byId("timeline-scroll")?.focus({ preventScroll: true });
    }
  };
  if (event.altKey && !event.ctrlKey && !event.metaKey && !event.shiftKey && event.key === "ArrowLeft") {
    event.preventDefault();
    retainStableFocus();
    restoreTimelineView(state.timelineViewHistoryIndex - 1);
    return;
  }
  if (event.altKey && !event.ctrlKey && !event.metaKey && !event.shiftKey && event.key === "ArrowRight") {
    event.preventDefault();
    retainStableFocus();
    restoreTimelineView(state.timelineViewHistoryIndex + 1);
    return;
  }
  if (directionKey && (event.ctrlKey || event.metaKey || event.altKey || event.shiftKey)) return;
  if (["+", "="].includes(event.key)) {
    event.preventDefault();
    retainStableFocus();
    zoomTimelineBy("in");
  } else if (["-", "_"].includes(event.key)) {
    event.preventDefault();
    retainStableFocus();
    zoomTimelineBy("out");
  } else if (event.key === "0") {
    event.preventDefault();
    retainStableFocus();
    fitTimelineCapture();
  } else if (event.key.toLowerCase() === "z" || (event.key === "Enter" && event.target === byId("timeline-scroll"))) {
    if (!rangeBounds()) return;
    event.preventDefault();
    retainStableFocus();
    zoomToSelectedRange();
  } else if (event.key.toLowerCase() === "c") {
    if (!state.cursorSelected && !rangeBounds()) return;
    event.preventDefault();
    retainStableFocus();
    centerTimelineAt();
  } else if (event.key === "ArrowLeft") {
    event.preventDefault();
    retainStableFocus();
    if (event.repeat) scheduleTimelinePan(-timelinePhysicalTrackWidth() / 10);
    else panTimelineViewport(-1);
  } else if (event.key === "ArrowRight") {
    event.preventDefault();
    retainStableFocus();
    if (event.repeat) scheduleTimelinePan(timelinePhysicalTrackWidth() / 10);
    else panTimelineViewport(1);
  } else if (event.key === "ArrowUp" || event.key === "ArrowDown") {
    event.preventDefault();
    retainStableFocus();
    const scroll = byId("timeline-scroll");
    scroll.scrollTop += (event.key === "ArrowUp" ? -1 : 1) * Math.max(40, scroll.clientHeight / 10);
  }
}

function timelineContextMenuRequested(event) {
  if (!event.target.closest?.("#timeline-content")) return;
  const context = timelineContextFromTarget(event.target, event.clientX);
  if (!context) return;
  event.preventDefault();
  event.stopPropagation();
  openTimelineContextMenu({
    element: event.target,
    clientX: event.clientX,
    clientY: event.clientY,
    context,
  });
}

function timelineWheel(event) {
  // Pointer brushing owns horizontal navigation until it completes. Native
  // wheel input during pointer capture otherwise races the brush's exact
  // BigInt anchor and can detach the selected endpoint from the pointer.
  if (state.brush) {
    event.preventDefault();
    return;
  }
  if (event.ctrlKey || event.metaKey) {
    const track = event.target.closest?.(".lane-track")
      || byId("timeline-content").querySelector(".lane-track");
    const anchorNs = track
      ? pointNsFromClientX(event.clientX, track)
      : visibleTimelineCenterNs();
    event.preventDefault();
    scheduleTimelineZoom(event, { anchorNs });
    return;
  }
  const deltaUnit = event.deltaMode === WheelEvent.DOM_DELTA_LINE ? 16
    : event.deltaMode === WheelEvent.DOM_DELTA_PAGE ? byId("timeline-scroll").clientWidth
      : 1;
  const horizontalDelta = Math.abs(event.deltaX) > Math.abs(event.deltaY)
    ? event.deltaX * deltaUnit
    : event.shiftKey ? event.deltaY * deltaUnit : 0;
  if (!Number.isFinite(horizontalDelta) || horizontalDelta === 0) return;
  event.preventDefault();
  scheduleTimelinePan(horizontalDelta);
}

function scheduleTimelinePan(deltaPx) {
  closeTimelineContextMenu();
  beginTimelineWheelBurst("pan");
  state.timelinePanDeltaPx += deltaPx;
  if (state.timelinePanFrameId === null) {
    state.timelinePanFrameId = window.requestAnimationFrame(() => {
      state.timelinePanFrameId = null;
      const pendingDeltaPx = state.timelinePanDeltaPx;
      state.timelinePanDeltaPx = 0;
      panTimelineViewportByPixels(pendingDeltaPx, {
        recordHistory: false,
        fromWheel: true,
      });
    });
  }
  scheduleTimelineWheelBurstFinish();
}

function scheduleTimelineZoom(event, { anchorNs = null } = {}) {
  if (!(event.ctrlKey || event.metaKey)) return false;
  const deltaUnit = event.deltaMode === WheelEvent.DOM_DELTA_LINE ? 16
    : event.deltaMode === WheelEvent.DOM_DELTA_PAGE ? byId("timeline-scroll").clientHeight
      : 1;
  const delta = event.deltaY * deltaUnit;
  if (!Number.isFinite(delta) || delta === 0) return false;
  event.preventDefault();
  closeTimelineContextMenu();
  beginTimelineWheelBurst("zoom");
  const baseZoom = state.timelineWheelTargetZoom ?? state.zoom;
  const factor = Math.exp(Math.min(1.2, Math.max(0.0001, Math.abs(delta) * 0.002)));
  try {
    state.timelineWheelTargetZoom = timelineZoomStep(baseZoom, delta < 0 ? "in" : "out", factor);
  } catch (_error) {
    finishTimelineWheelBurst();
    showToast("That zoom step cannot be represented by this browser.");
    return true;
  }
  state.timelineWheelAnchorNs = anchorNs ?? visibleTimelineCenterNs();
  state.timelineWheelAnchorClientX = event.clientX;
  if (state.timelineWheelFrameId === null) {
    state.timelineWheelFrameId = window.requestAnimationFrame(() => {
      state.timelineWheelFrameId = null;
      const targetZoom = state.timelineWheelTargetZoom;
      state.timelineWheelTargetZoom = null;
      applyTimelineZoom(targetZoom, {
        anchorNs: state.timelineWheelAnchorNs,
        anchorClientX: state.timelineWheelAnchorClientX,
        recordHistory: false,
        fromWheel: true,
      });
    });
  }
  scheduleTimelineWheelBurstFinish();
  return true;
}

function resetTimelineView() {
  cancelScheduledTimelineZoom({ commitHistory: true });
  rememberTimelineView();
  closeTimelineContextMenu();
  invalidatePendingTimelineWindowRequest();
  state.zoom = 1;
  state.timelineWindowStartNs = state.viewStartNs;
  state.timelineWindowEndNs = state.viewEndNs;
  clearRangeSelection({ refreshEventLog: false });
  state.laneMode = isScaleMode() ? "custom" : "all";
  state.correlationTimelineExpanded = true;
  state.expandedTimelineTreeKeys.clear();
  state.hiddenTimelineResourceIds.clear();
  state.explicitLaneIds = new Set(isScaleMode() ? initialScaleLaneIds() : state.lanes.map((lane) => lane.resourceId));
  state.activeLayers = new Set(state.layerMeta.keys());
  byId("timeline-zoom").value = "1";
  byId("timeline-scroll").scrollLeft = 0;
  byId("clear-range").hidden = true;
  renderLayerToggles();
  renderRangeSummary();
  renderEventTable({ resetScroll: true });
  if (isScaleMode()) refreshScaleTimeline();
  else {
    renderTimeline();
    scheduleTimelineWindowRefresh();
  }
  setCursor(state.viewEndNs, true, false);
  rememberTimelineView();
}

function bindTimelineStickyHeader() {
  const frame = byId("timeline-frame");
  const topbar = document.querySelector(".topbar");
  if (!frame || !topbar) return;
  const updateOffset = () => {
    frame.style.setProperty("--timeline-sticky-top", `${topbar.getBoundingClientRect().height}px`);
  };
  updateOffset();
  // CSS owns sticking/release. Observe only header resizing, not page scroll,
  // so wrapping navigation or font changes cannot cover the time ruler.
  if (typeof window.ResizeObserver === "function") {
    const observer = new window.ResizeObserver(updateOffset);
    observer.observe(topbar);
    window.addEventListener("pagehide", () => observer.disconnect());
    window.addEventListener("pageshow", () => {
      observer.observe(topbar);
      updateOffset();
    });
  } else {
    window.addEventListener("resize", updateOffset, { passive: true });
  }
}

function bindControls() {
  bindTimelineStickyHeader();
  bindCorrelationPanelControls();
  bindGraphStageInspectionClear();
  const timelineScroll = byId("timeline-scroll");
  const timelineContent = byId("timeline-content");
  const timelineMenu = byId("timeline-context-menu");
  const timelineToolbar = byId("timeline-viewport-controls");
  syncTimelineToolbarTabStop();
  timelineToolbar.addEventListener("keydown", timelineToolbarKeyDown);
  timelineToolbar.addEventListener("focusin", (event) => {
    if (event.target.matches?.("button")) syncTimelineToolbarTabStop(event.target);
  });
  byId("timeline-zoom").addEventListener("input", (event) => {
    applyTimelineZoom(event.target.value, { announce: true });
  });
  byId("timeline-pan-earlier").addEventListener("click", () => panTimelineViewport(-1));
  byId("timeline-pan-later").addEventListener("click", () => panTimelineViewport(1));
  byId("timeline-view-back").addEventListener("click", () => {
    restoreTimelineView(state.timelineViewHistoryIndex - 1);
  });
  byId("timeline-view-forward").addEventListener("click", () => {
    restoreTimelineView(state.timelineViewHistoryIndex + 1);
  });
  byId("timeline-zoom-out").addEventListener("click", () => zoomTimelineBy("out"));
  byId("timeline-zoom-in").addEventListener("click", () => zoomTimelineBy("in"));
  byId("timeline-zoom-selection").addEventListener("click", () => zoomToSelectedRange());
  byId("timeline-center").addEventListener("click", () => centerTimelineAt());
  byId("timeline-fit").addEventListener("click", () => fitTimelineCapture());
  byId("range-mode").addEventListener("click", () => { state.rangeMode = !state.rangeMode; byId("range-mode").setAttribute("aria-pressed", String(state.rangeMode)); byId("range-mode").textContent = state.rangeMode ? "Range brush on" : "Range brush"; byId("timeline-frame").classList.toggle("range-mode", state.rangeMode); });
  byId("clear-range").addEventListener("click", clearRangeSelection);
  byId("reset-view").addEventListener("click", resetTimelineView);
  byId("time-cursor").addEventListener("input", (event) => setCursor(nsAtRatio(Number(event.target.value) / 1_000_000)));
  byId("timeline-scroll").addEventListener("wheel", timelineWheel, { passive: false });
  timelineScroll.addEventListener("scroll", () => {
    hideTimelineHoverLine();
    closeTimelineContextMenu();
    byId("timeline-ruler").style.transform = `translateX(${-timelineScroll.scrollLeft}px)`;
    window.clearTimeout(state.densityRenderTimer);
    state.densityRenderTimer = window.setTimeout(refreshDensityLaneForScroll, 80);
    scheduleTimelineViewHistory();
  }, { passive: true });
  byId("resource-search").addEventListener("input", () => {
    state.resourceOffset = 0;
    if (!isScaleMode() && !state.selectedResourceViewId) return renderResourceTables();
    window.clearTimeout(state.resourceSearchTimer);
    state.resourceSearchTimer = window.setTimeout(requestResources, 180);
  });
  byId("reset-dashboard-layout").addEventListener("click", resetDashboardLayout);
  byId("range-editor").addEventListener("submit", applyRangeEditor);
  byId("range-zoom").addEventListener("click", (event) => {
    if (applyRangeEditor(event)) zoomToSelectedRange();
  });
  timelineContent.addEventListener("pointerdown", timelinePointerDown);
  timelineContent.addEventListener("pointermove", timelinePointerMove);
  timelineContent.addEventListener("pointerleave", hideTimelineHoverLine);
  timelineContent.addEventListener("pointerup", (event) => finishTimelinePointer(event, false));
  timelineContent.addEventListener("pointercancel", (event) => finishTimelinePointer(event, true));
  timelineContent.addEventListener("lostpointercapture", (event) => finishTimelinePointer(event, true));
  timelineContent.addEventListener("keydown", timelineViewportKeyDown);
  timelineContent.addEventListener("keydown", timelineHandleKeyDown);
  timelineContent.addEventListener("contextmenu", timelineContextMenuRequested);
  timelineScroll.addEventListener("keydown", timelineViewportKeyDown);
  byId("timeline-pan-controls").addEventListener("keydown", timelineViewportKeyDown);
  byId("timeline-context-menu").addEventListener("keydown", timelineContextMenuKeyDown);
  timelineMenu.addEventListener("click", (event) => {
    const actionButton = event.target.closest?.("[data-timeline-action]");
    if (!actionButton || actionButton.disabled) return;
    event.preventDefault();
    event.stopPropagation();
    activateTimelineContextAction(actionButton.dataset.timelineAction).catch((error) => {
      showToast(`Timeline action failed: ${error.message}`);
    });
  });
  byId("timeline-actions").addEventListener("click", (event) => {
    if (!timelineMenu.hidden) {
      closeTimelineContextMenu({ restoreFocus: true });
      return;
    }
    const button = event.currentTarget;
    openTimelineContextMenu({
      element: button,
      keyboard: true,
      context: {
        timeNs: selectedTimelineCenterNs(),
        clientX: null,
        resourceId: state.selectedResourceId,
        target: null,
      },
    });
  });
  document.addEventListener("pointerdown", (event) => {
    if (timelineMenu.hidden || timelineMenu.contains(event.target) || byId("timeline-actions").contains(event.target)) return;
    closeTimelineContextMenu();
  });
  window.addEventListener("blur", () => {
    finishTimelinePointer(null, true);
    finishEventLogDrag(null, true);
    closeTimelineContextMenu();
  });
  window.addEventListener("resize", () => {
    closeTimelineContextMenu();
    window.clearTimeout(bindControls.timelineResizeTimer);
    bindControls.timelineResizeTimer = window.setTimeout(() => {
      if (state.dataset && timelinePhysicalTrackWidth() !== state.trackWidth) renderTimeline();
    }, 120);
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
  byId("topology-query-form").addEventListener("submit", requestTopology);
  byId("topology-projection").addEventListener("change", () => {
    renderTopologyPerspectiveOptions();
    renderTopologyControlNotes();
    requestTopology();
  });
  byId("topology-perspective").addEventListener("change", () => {
    renderTopologyControlNotes();
    requestTopology();
  });
  byId("topology-basis-kind").addEventListener("change", () => {
    syncTopologyTimeEditors();
    if (byId("topology-basis-kind").value === "absolute_time" && byId("topology-follow-cursor").checked) {
      byId("topology-absolute-time").value = state.cursorNs.toString();
    }
    requestTopology();
  });
  byId("topology-clock-policy").addEventListener("change", () => requestTopology());
  byId("topology-use-selected-time").addEventListener("click", () => {
    byId("topology-absolute-time").value = state.cursorNs.toString();
    requestTopology();
  });
  byId("topology-follow-cursor").addEventListener("change", (event) => {
    if (event.target.checked) scheduleTopologyRefreshFromCursor();
  });
  byId("route-form").addEventListener("submit", resolveRoute);
  byId("route-form").querySelectorAll("select").forEach(
    (control) => control.addEventListener("change", resolveRoute)
  );
  byId("event-layer-filter").addEventListener("change", () => renderEventTable({ resetScroll: true }));
  byId("event-search").addEventListener("input", () => {
    if (!usesServerWindowedHistory()) {
      renderEventTable({ resetScroll: true });
      return;
    }
    window.clearTimeout(state.eventLogFilterTimer);
    state.eventLogFilterTimer = window.setTimeout(
      () => renderEventTable({ resetScroll: true }),
      EVENT_LOG_FILTER_DELAY_MS,
    );
  });
  const eventLogScroll = byId("event-log-scroll");
  eventLogScroll.addEventListener("scroll", scheduleEventLogWindow, { passive: true });
  eventLogScroll.addEventListener("pointerdown", eventLogPointerDown);
  eventLogScroll.addEventListener("pointermove", eventLogPointerMove);
  eventLogScroll.addEventListener("pointerup", (event) => finishEventLogDrag(event, false));
  eventLogScroll.addEventListener("pointercancel", (event) => finishEventLogDrag(event, true));
  eventLogScroll.addEventListener("lostpointercapture", (event) => finishEventLogDrag(event, true));
  byId("event-include-normalized").addEventListener("change", (event) => {
    state.eventLogInclude.normalized = event.target.checked;
    renderEventTable({ resetScroll: true });
  });
  byId("event-source-group-controls").addEventListener("change", (event) => {
    const groupId = event.target?.dataset?.sourceGroupId;
    if (!groupId) return;
    if (event.target.checked) state.includedSourceRecordGroups.add(groupId);
    else state.includedSourceRecordGroups.delete(groupId);
    renderEventTable({ resetScroll: true });
  });
  byId("event-selection-reveal").addEventListener("click", revealFocusedEventLogSelection);
  byId("event-selection-copy").addEventListener("click", copyEventLogSelectionText);
  byId("event-selection-hide").addEventListener("click", () => applyEventLogTimelineAction("hide"));
  byId("event-selection-show").addEventListener("click", () => applyEventLogTimelineAction("show"));
  byId("event-selection-mark").addEventListener("click", () => applyEventLogTimelineAction("mark"));
  byId("event-selection-unmark").addEventListener("click", () => applyEventLogTimelineAction("unmark"));
  byId("event-selection-correlate").addEventListener("click", openManualCorrelationDialog);
  byId("event-selection-clear").addEventListener("click", () => clearEventLogSelection({ announce: true }));
  byId("durable-review-form").addEventListener("submit", (event) => {
    event.preventDefault();
    connectDurableReview();
  });
  byId("durable-review-local").addEventListener("click", disconnectDurableReview);
  byId("durable-review-discard-pending").addEventListener(
    "click",
    discardPendingDurableReviewMutations,
  );
  byId("durable-review-reset-pending").addEventListener(
    "click",
    resetAllPendingDurableReviewMutations,
  );
  byId("durable-review-copy-report").addEventListener("click", copyDurableCorrelationReport);
  byId("durable-review-download-report").addEventListener("click", downloadDurableCorrelationReport);
  byId("durable-review-report-scope").addEventListener("change", () => {
    state.durableReview.reportScope = selectedDurableReportScope();
    syncDurableReportScopeNote();
  });
  byId("correlation-form").addEventListener("submit", saveManualCorrelation);
  ["correlation-cancel", "correlation-cancel-icon"].forEach(
    (id) => byId(id).addEventListener("click", closeManualCorrelationDialog),
  );
  byId("correlation-dialog").addEventListener("close", () => {
    state.durableReview.pendingCorrelationSubjects = [];
  });
  ["open-review", "open-review-footer"].forEach((id) => byId(id).addEventListener("click", openReview));
  byId("close-review").addEventListener("click", closeReview); byId("drawer-scrim").addEventListener("click", closeReview);
  ["copy-review", "copy-review-top"].forEach((id) => byId(id).addEventListener("click", copyReview));
  byId("clear-review").addEventListener("click", () => { localStorage.removeItem(REVIEW_STORAGE_KEY); renderReview(); showToast("Review selections cleared."); });
  const hover = byId("timeline-hover");
  hover.addEventListener("pointerenter", () => window.clearTimeout(state.hoverCloseTimer));
  hover.addEventListener("pointerleave", scheduleHoverClose);
  document.addEventListener("keydown", handleEscapeKey);
  rememberTimelineView();
}

function discoverPresentation() {
  const descriptors = state.dataset.presentation?.layers || state.dataset.layers || [];
  if (Array.isArray(descriptors)) {
    descriptors
      .filter((item) => item && typeof item === "object")
      .forEach((item) => {
        const key = String(item.id || item.layer || "unknown");
        state.layerMeta.set(key, {
          label: typeof item.label === "string" && item.label ? item.label : titleCase(key),
          color: safePresentationColor(item.color, key),
        });
      });
  } else if (descriptors && typeof descriptors === "object") {
    Object.entries(descriptors).forEach(([rawKey, rawItem]) => {
      const key = String(rawKey || "unknown");
      const item = rawItem && typeof rawItem === "object" ? rawItem : {};
      state.layerMeta.set(key, {
        label: typeof item.label === "string" && item.label ? item.label : titleCase(key),
        color: safePresentationColor(item.color, key),
      });
    });
  }
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
    state.dataset = await analysisRuntimeApi(bootstrapDatasetPath());
    initializeDurableReviewSetup();
    const workspace = workspaceMetadata();
    const timeBounds = workspace.time_bounds && typeof workspace.time_bounds === "object"
      ? workspace.time_bounds
      : {};
    initializeResourceTableView();
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
    initializeSourceRecordGroups();
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
    const declaredStartNs = workspace.timeline_start_ns ?? timeBounds.start_ns;
    const declaredEndNs = workspace.timeline_end_ns ?? timeBounds.end_ns;
    const declaredCaptureNs = workspace.capture_ns ?? timeBounds.capture_ns ?? declaredEndNs;
    state.viewStartNs = toNs(declaredStartNs, times.length ? times.reduce((a, b) => a < b ? a : b) : 0n);
    state.viewEndNs = toNs(declaredEndNs ?? declaredCaptureNs, times.length ? times.reduce((a, b) => a > b ? a : b) : state.viewStartNs + 1n);
    if (state.viewEndNs <= state.viewStartNs) state.viewEndNs = state.viewStartNs + 1n;
    state.timelineWindowStartNs = state.viewStartNs;
    state.timelineWindowEndNs = state.viewEndNs;
    state.zoom = 1;
    state.cursorNs = clampNs(toNs(navigationContext.timeNs || declaredCaptureNs, state.viewEndNs));
    state.cursorSelected = Boolean(navigationContext.timeNs);
    if (isScaleMode()) {
      state.laneMode = "custom";
      state.explicitLaneIds = new Set(initialScaleLaneIds());
    }
    await requestTimeline();
    await requestFailureIncidentPreview();
    if (!isScaleMode()) state.explicitLaneIds = new Set(state.lanes.map((lane) => lane.resourceId));
    discoverPresentation();
    await requestTopologyCapabilities();
    renderTopologyNavigationBanner();
    initializeDashboardLayout();
    markDashboardsPending(state.cursorNs);
    fillSummary(); renderIncidentSummary(); renderLayerToggles(); renderTimeline(); renderRangeSummary(); renderFindings(); renderTopologyResults(); renderInventory(); configureRouteControls(); renderReview(); renderEventLayerFilter(); syncEventLogIncludeControls(); renderEventTable(); renderPluginDashboards(); bindControls();
    if (state.durableReview.config) void connectDurableReview({ quiet: true });
    let incident = null;
    for (const candidate of state.eventByUid.values()) {
      incident = candidate;
      if (eventFailed(candidate)) {
        break;
      }
    }
    const linkedResourceId = navigationContext.resourceId
      && navigationTargetsLoadedMember()
      && state.resourceById.has(navigationContext.resourceId)
      ? navigationContext.resourceId
      : "";
    const initialFocusResourceId = linkedResourceId
      || (!hasTopologyNavigationContext() ? workspace.initial_focus_resource_id : "");
    if (initialFocusResourceId) {
      selectResource(canonicalResourceId(initialFocusResourceId));
    } else if (incident && !hasTopologyNavigationContext()) {
      selectEvent(String(incident.event_uid || incident.event_id), isScaleMode());
    }
    await Promise.allSettled([requestGraph(), requestResources(), requestDashboards(), requestTopology(), resolveRoute()]);
  } catch (error) {
    document.querySelector("main").innerHTML = `<section class="section-wrap"><div class="panel empty-state"><h1>Workspace could not load</h1><p>${escapeHtml(error.message)}</p></div></section>`;
  }
}

initialize();
