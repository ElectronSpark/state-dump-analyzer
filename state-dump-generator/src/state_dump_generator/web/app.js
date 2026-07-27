"use strict";

const SVG_NS = "http://www.w3.org/2000/svg";
const API = Object.freeze({
  create: "/api/scenario/new",
  validate: "/api/scenario/validate",
  preview: "/api/scenario/preview",
  generate: "/api/scenario/generate",
});

const KIND_NAMES = Object.freeze({
  router: "Router",
  switch: "Switch",
  host: "Host",
  "shared-medium": "Shared medium",
});

const KIND_GLYPHS = Object.freeze({
  router: "↔",
  switch: "⇄",
  host: "▣",
  "shared-medium": "◌",
});

const PATTERNS = Object.freeze({
  "clean-link-flap": {
    title: "Clean link flap",
    description:
      "Changes physical state, schedules delayed observations at both ends, and restores the link.",
    target: "link",
  },
  "one-sided-detection": {
    title: "One-sided detection",
    description:
      "Changes physical state but schedules an observation at only one endpoint.",
    target: "link",
  },
  "delayed-convergence": {
    title: "Delayed convergence",
    description:
      "Schedules staggered local observations so cross-layer state is temporarily inconsistent.",
    target: "link",
  },
  "stale-neighbor": {
    title: "Stale neighbor",
    description:
      "Takes a physical link down while retaining one endpoint's last neighbor state.",
    target: "link",
  },
  "failed-update": {
    title: "Failed update",
    description:
      "Records an attempted resource update with a failed outcome and no final-state change.",
    target: "node",
  },
  "route-change": {
    title: "Next-hop change",
    description:
      "Replaces a route or forwarding dependency at one node, with optional propagation.",
    target: "node",
  },
  "node-restart": {
    title: "Node restart",
    description:
      "Creates a down/up sequence and a burst of local withdraw and restore observations.",
    target: "node",
  },
  "clock-skew": {
    title: "Clock skew",
    description:
      "Adds node-local capture clock metadata without changing physical time.",
    target: "node",
  },
  "log-gap": {
    title: "Log gap",
    description:
      "Marks an interval in which expected node-local source records are unavailable.",
    target: "node",
  },
  "partial-multi-access": {
    title: "Partial multi-access failure",
    description:
      "Schedules different observations for participants on one shared medium.",
    target: "medium",
  },
});

const dom = {};
let scenario = fallbackScenario();
let selection = null;
let selectedEventId = null;
let currentTool = "select";
let linkSourceId = null;
let currentPattern = null;
let dragState = null;
let panZoom = { x: 0, y: 0, scale: 1 };
let history = [];
let future = [];
let dirty = false;
let eventDurationMs = 60_000;
const pointers = new Map();

document.addEventListener("DOMContentLoaded", initialize);

function byId(id) {
  return document.getElementById(id);
}

function initialize() {
  [
    "project-name",
    "new-project",
    "open-project",
    "save-project",
    "project-file",
    "undo",
    "redo",
    "validate-project",
    "generate-dumps",
    "object-count",
    "scenario-canvas",
    "topology-svg",
    "viewport-layer",
    "links-layer",
    "objects-layer",
    "gesture-layer",
    "empty-canvas",
    "link-instruction",
    "zoom-out",
    "zoom-in",
    "zoom-level",
    "fit-canvas",
    "selection-status",
    "validation-summary",
    "object-form",
    "no-object",
    "object-kind-label",
    "object-heading",
    "object-name",
    "object-site",
    "object-profile",
    "object-notes",
    "node-fields",
    "link-fields",
    "link-port-a",
    "link-port-b",
    "link-state",
    "schedule-link-state",
    "delete-object",
    "apply-object",
    "object-tab",
    "event-tab",
    "propagation-tab",
    "object-panel",
    "event-panel",
    "propagation-panel",
    "event-form",
    "event-heading",
    "event-time",
    "event-node",
    "event-kind",
    "event-outcome",
    "event-subject",
    "event-action",
    "event-payload",
    "event-log",
    "event-update-snapshot",
    "event-auto-propagate",
    "payload-error",
    "save-event",
    "delete-event",
    "clear-event-form",
    "propagation-form",
    "propagation-mode",
    "propagation-delay",
    "propagation-jitter",
    "propagation-target-mode",
    "propagation-targets",
    "propagation-target-options",
    "propagation-outcome",
    "propagation-cadence",
    "preview-propagation",
    "apply-propagation",
    "propagation-preview",
    "selected-time",
    "add-event",
    "time-rail",
    "time-labels",
    "event-markers",
    "event-count",
    "event-filter-node",
    "event-filter-physical",
    "event-filter-local",
    "event-list",
    "accessible-object-form",
    "accessible-kind",
    "accessible-name",
    "accessible-link-form",
    "accessible-link-from",
    "accessible-link-to",
    "accessible-select-form",
    "accessible-existing",
    "pattern-dialog",
    "pattern-form",
    "pattern-title",
    "pattern-description",
    "pattern-time",
    "pattern-target",
    "pattern-node",
    "pattern-delay",
    "pattern-duration",
    "apply-pattern",
    "generation-dialog",
    "generation-state",
    "retry-generation",
    "toast-region",
  ].forEach((id) => {
    dom[id] = byId(id);
  });

  bindProjectActions();
  bindPalette();
  bindCanvas();
  bindInspector();
  bindTimeline();
  bindDialogs();
  bindKeyboard();
  void loadBlankProject();
}

function fallbackScenario() {
  const now = new Date().toISOString();
  return {
    schema_version: 1,
    schema_id: "state-dump-generator-scenario/v1",
    id: makeId("scenario"),
    name: "Untitled scenario",
    seed: 1,
    capture_time_ns: 60_000_000_000,
    description: "",
    created_at: now,
    updated_at: now,
    duration_ms: 60_000,
    nodes: [],
    physical_links: [],
    events: [],
    defaults: {
      propagation: {
        mode: "best-effort",
        delay_ms: 250,
        jitter_ms: 50,
        target_mode: "neighbors",
        outcome: "success",
        cadence: "parallel",
      },
    },
  };
}

function normalizeScenario(input) {
  const base = fallbackScenario();
  const source = input && typeof input === "object" ? structuredClone(input) : {};
  const normalized = { ...base, ...source };

  normalized.nodes = Array.isArray(source.nodes) ? source.nodes.map(normalizeNode) : [];
  normalized.physical_links = Array.isArray(source.physical_links)
    ? source.physical_links.map(normalizeLink)
    : Array.isArray(source.links)
      ? source.links.map(normalizeLink)
      : [];
  if (!normalized.physical_links.length && Array.isArray(source.media)) {
    const converted = topologyFromCanonicalMedia(source.media, normalized.nodes);
    normalized.nodes.push(...converted.mediumNodes);
    normalized.physical_links = converted.links;
  }
  normalized.events = Array.isArray(source.events)
    ? source.events.map(normalizeEvent)
    : Array.isArray(source.timeline)
      ? source.timeline.map(normalizeEvent)
      : [];
  normalized.defaults = {
    propagation: {
      ...base.defaults.propagation,
      ...(
        source.defaults?.propagation ||
        source.propagation_defaults ||
        source.metadata?.authoring?.propagation_defaults ||
        {}
      ),
    },
  };
  normalized.duration_ms = Math.max(
    1_000,
    finiteNumber(
      source.duration_ms ??
        (source.capture_time_ns !== undefined
          ? Number(source.capture_time_ns) / 1_000_000
          : undefined),
      maxEventTime(normalized.events) + 10_000,
      60_000,
    ),
  );
  normalized.name = stringValue(source.name || source.metadata?.name, base.name);
  normalized.description = stringValue(
    source.description || source.metadata?.description,
    "",
  );
  normalized.id = stringValue(source.id || source.scenario_id, base.id);
  normalized.seed = Math.max(0, Math.trunc(finiteNumber(source.seed, 1)));
  normalized.capture_time_ns = Math.max(
    0,
    Math.round(finiteNumber(source.capture_time_ns, normalized.duration_ms * 1_000_000)),
  );
  return normalized;
}

function normalizeNode(node, index) {
  const source = node && typeof node === "object" ? node : {};
  const rawKind = stringValue(source.kind || source.device_type || source.role, "router");
  const kind = Object.hasOwn(KIND_NAMES, rawKind) ? rawKind : "router";
  return {
    ...source,
    id: stringValue(source.id || source.node_id, makeId("node")),
    name: stringValue(source.name || source.label, `${KIND_NAMES[kind]} ${index + 1}`),
    kind,
    position: {
      x: finiteNumber(source.position?.x ?? source.x, 120 + (index % 4) * 210),
      y: finiteNumber(source.position?.y ?? source.y, 100 + Math.floor(index / 4) * 150),
    },
    site: stringValue(source.site, ""),
    profile: stringValue(source.profile || source.device_profile, "generic"),
    notes: stringValue(source.notes, ""),
    dump_enabled:
      typeof source.dump_enabled === "boolean" ? source.dump_enabled : kind === "router",
    clock: isPlainObject(source.clock)
      ? structuredClone(source.clock)
      : { offset_ns: 0, uncertainty_ns: 0 },
    initial_resources: Array.isArray(source.initial_resources)
      ? structuredClone(source.initial_resources)
      : [],
  };
}

function normalizeLink(link, index) {
  const source = link && typeof link === "object" ? link : {};
  const endpoints = Array.isArray(source.endpoints) ? source.endpoints : [];
  return {
    ...source,
    id: stringValue(source.id || source.link_id, makeId("link")),
    name: stringValue(source.name || source.label, `Link ${index + 1}`),
    a: normalizeEndpoint(source.a || endpoints[0]),
    b: normalizeEndpoint(source.b || endpoints[1]),
    initial_state: stringValue(source.initial_state || source.state, "up"),
    notes: stringValue(source.notes, ""),
  };
}

function normalizeEndpoint(value) {
  const endpoint = value && typeof value === "object" ? value : {};
  return {
    ...endpoint,
    node_id: stringValue(endpoint.node_id || endpoint.object_id || endpoint.id, ""),
    port: stringValue(endpoint.port || endpoint.port_id || endpoint.interface, "auto"),
    resource_id: stringValue(
      endpoint.resource_id || endpoint.local_resource_id,
      "",
    ),
    properties: isPlainObject(endpoint.properties)
      ? structuredClone(endpoint.properties)
      : {},
  };
}

function normalizeEvent(event) {
  const source = event && typeof event === "object" ? event : {};
  const timeMs =
    source.time_ms ??
    source.timestamp_ms ??
    (source.time_s !== undefined ? Number(source.time_s) * 1000 : undefined) ??
    (source.timestamp_ns !== undefined ? Number(source.timestamp_ns) / 1_000_000 : 0);
  return {
    ...source,
    id: stringValue(source.id || source.event_id, makeId("event")),
    time_ms: Math.max(0, finiteNumber(timeMs, 0)),
    scope:
      source.scope === "physical" ||
      ["medium", "link", "physical-link"].includes(source.target_type) ||
      ["physical-link-state", "link-state", "medium-state", "physical-state"].includes(
        stringValue(source.kind).replaceAll("_", "-"),
      )
        ? "physical"
        : "node",
    node_id: stringValue(source.node_id || source.observer_node_id, ""),
    target_type: stringValue(source.target_type, ""),
    target_id: stringValue(
      source.target_id || source.medium_id || source.link_id,
      "",
    ),
    kind: stringValue(source.kind || source.event_kind, "status"),
    subject: stringValue(source.subject || source.resource_key || source.resource_id, ""),
    action: stringValue(source.action || source.operation, ""),
    outcome: stringValue(source.outcome || source.status, "ok"),
    state_patch: isPlainObject(source.state_patch)
      ? source.state_patch
      : isPlainObject(source.properties)
        ? source.properties
      : isPlainObject(source.payload)
        ? source.payload
        : {},
    log_text: stringValue(source.log_text || source.message, ""),
    update_final_state:
      source.update_final_state !== false && source.update_snapshot !== false,
    propagation: source.propagation && typeof source.propagation === "object"
      ? source.propagation
      : null,
  };
}

function topologyFromCanonicalMedia(media, nodes) {
  const mediumNodes = [];
  const links = [];
  const occupiedIds = new Set(nodes.map((node) => node.id));
  media.forEach((rawMedium, mediumIndex) => {
    const medium = rawMedium && typeof rawMedium === "object" ? rawMedium : {};
    const mediumId = stringValue(
      medium.medium_id || medium.link_id || medium.id,
      `medium-${mediumIndex + 1}`,
    );
    const attachments = Array.isArray(medium.attachments)
      ? medium.attachments.map((attachment) => ({
          ...attachment,
          node_id: stringValue(attachment.node_id || attachment.node, ""),
          port: stringValue(attachment.port_id || attachment.port, "auto"),
          properties: isPlainObject(attachment.properties)
            ? structuredClone(attachment.properties)
            : {},
        }))
      : [];
    const kind = stringValue(medium.kind || medium.media_type, "point-to-point");
    const isPointToPoint =
      attachments.length === 2 &&
      ["point-to-point", "point_to_point", "p2p", "link"].includes(kind.toLowerCase());
    if (isPointToPoint) {
      links.push(
        normalizeLink(
          {
            id: mediumId,
            source_medium_id: mediumId,
            name: medium.name || medium.label || `Link ${mediumIndex + 1}`,
            medium_kind: kind,
            a: attachments[0],
            b: attachments[1],
            initial_state: medium.state || medium.initial_state || "up",
            notes: medium.notes || "",
            medium_properties: isPlainObject(medium.properties)
              ? structuredClone(medium.properties)
              : {},
          },
          links.length,
        ),
      );
      return;
    }
    let uiNodeId = stringValue(medium.ui_node_id, `medium-${mediumId}`);
    while (occupiedIds.has(uiNodeId)) uiNodeId = `${uiNodeId}-media`;
    occupiedIds.add(uiNodeId);
    const centers = attachments
      .map((attachment) => nodes.find((node) => node.id === attachment.node_id))
      .filter(Boolean)
      .map(centerOf);
    const position = isPlainObject(medium.position)
      ? medium.position
      : centers.length
        ? {
            x: centers.reduce((sum, point) => sum + point.x, 0) / centers.length - 75,
            y: centers.reduce((sum, point) => sum + point.y, 0) / centers.length - 100,
          }
        : { x: 340 + mediumIndex * 30, y: 160 + mediumIndex * 30 };
    mediumNodes.push(
      normalizeNode(
        {
          id: uiNodeId,
          medium_id: mediumId,
          name: medium.name || medium.label || mediumId,
          kind: "shared-medium",
          medium_kind: kind,
          initial_state: medium.state || medium.initial_state || "up",
          position,
          notes: medium.notes || "",
          medium_properties: isPlainObject(medium.properties)
            ? structuredClone(medium.properties)
            : {},
          dump_enabled: false,
        },
        nodes.length + mediumNodes.length,
      ),
    );
    attachments.forEach((attachment, attachmentIndex) => {
      links.push(
        normalizeLink(
          {
            id: `${mediumId}-attachment-${attachmentIndex + 1}`,
            source_medium_id: mediumId,
            name: `${medium.name || mediumId} attachment`,
            medium_kind: kind,
            a: attachment,
            b: {
              node_id: uiNodeId,
              port: `attachment-${attachmentIndex + 1}`,
              properties: {},
            },
            initial_state: medium.state || medium.initial_state || "up",
          },
          links.length,
        ),
      );
    });
  });
  return { mediumNodes, links };
}

function finiteNumber(value, fallback, alternateFallback) {
  const number = Number(value);
  if (Number.isFinite(number)) return number;
  const alternate = Number(alternateFallback);
  return Number.isFinite(alternate) ? alternate : fallback;
}

function stringValue(value, fallback = "") {
  return typeof value === "string" ? value : value == null ? fallback : String(value);
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function makeId(prefix) {
  if (globalThis.crypto?.randomUUID) return `${prefix}-${crypto.randomUUID()}`;
  return `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

async function loadBlankProject() {
  try {
    const response = await fetch(API.create, { headers: { Accept: "application/json" } });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const payload = await response.json();
    scenario = normalizeScenario(payload.scenario || payload);
    if (scenario.id === "untitled-scenario") scenario.id = makeId("scenario");
  } catch {
    scenario = fallbackScenario();
  }
  history = [];
  future = [];
  dirty = false;
  selection = null;
  selectedEventId = null;
  panZoom = { x: 0, y: 0, scale: 1 };
  eventDurationMs = scenario.duration_ms;
  loadPropagationControls(scenario.defaults?.propagation || {});
  renderAll();
}

function bindProjectActions() {
  dom["new-project"].addEventListener("click", async () => {
    if (dirty && !globalThis.confirm("Discard the unsaved scenario and start again?")) return;
    await loadBlankProject();
    toast("Started a blank scenario.");
  });
  dom["open-project"].addEventListener("click", () => dom["project-file"].click());
  dom["project-file"].addEventListener("change", handleProjectFile);
  dom["save-project"].addEventListener("click", saveProject);
  dom.undo.addEventListener("click", undo);
  dom.redo.addEventListener("click", redo);
  dom["validate-project"].addEventListener("click", () => void validateProject(true));
  dom["generate-dumps"].addEventListener("click", () => void generateDumps());
  dom["project-name"].addEventListener("change", () => {
    const name = dom["project-name"].value.trim() || "Untitled scenario";
    if (name === scenario.name) return;
    transact(() => {
      scenario.name = name;
    });
  });
  globalThis.addEventListener("beforeunload", (event) => {
    if (!dirty) return;
    event.preventDefault();
    event.returnValue = "";
  });
}

function bindPalette() {
  document.querySelectorAll(".add-object").forEach((button) => {
    button.addEventListener("click", () => addObject(button.dataset.kind));
  });
  document.querySelectorAll(".palette-item").forEach((item) => {
    item.addEventListener("dragstart", (event) => {
      event.dataTransfer.effectAllowed = "copy";
      event.dataTransfer.setData("application/x-scenario-object", item.dataset.kind);
    });
  });
  document.querySelectorAll(".pattern-button").forEach((button) => {
    button.addEventListener("click", () => openPattern(button.dataset.pattern));
  });
  dom["accessible-object-form"].addEventListener("submit", (event) => {
    event.preventDefault();
    const node = addObject(dom["accessible-kind"].value);
    const name = dom["accessible-name"].value.trim();
    if (name) {
      transact(() => {
        node.name = name;
      });
    }
    dom["accessible-name"].value = "";
  });
  dom["accessible-link-form"].addEventListener("submit", (event) => {
    event.preventDefault();
    addLink(dom["accessible-link-from"].value, dom["accessible-link-to"].value);
  });
  dom["accessible-select-form"].addEventListener("submit", (event) => {
    event.preventDefault();
    const separator = dom["accessible-existing"].value.indexOf("|");
    const type = dom["accessible-existing"].value.slice(0, separator);
    const id = dom["accessible-existing"].value.slice(separator + 1);
    if (!id || !["node", "link"].includes(type)) return;
    selection = { type, id };
    renderAll();
    showInspectorPanel("object-tab", "object-panel");
    dom["object-name"].focus();
  });
}

function bindCanvas() {
  document.querySelectorAll(".tool-button[data-tool]").forEach((button) => {
    button.addEventListener("click", () => setTool(button.dataset.tool));
  });
  dom["zoom-out"].addEventListener("click", () => zoomAt(0.82));
  dom["zoom-in"].addEventListener("click", () => zoomAt(1.22));
  dom["fit-canvas"].addEventListener("click", fitCanvas);
  dom["scenario-canvas"].addEventListener("dragover", (event) => {
    if (!event.dataTransfer.types.includes("application/x-scenario-object")) return;
    event.preventDefault();
    event.dataTransfer.dropEffect = "copy";
  });
  dom["scenario-canvas"].addEventListener("drop", (event) => {
    event.preventDefault();
    const kind = event.dataTransfer.getData("application/x-scenario-object");
    if (!Object.hasOwn(KIND_NAMES, kind)) return;
    addObject(kind, clientToWorld(event.clientX, event.clientY));
  });
  dom["topology-svg"].addEventListener("pointerdown", canvasPointerDown);
  dom["topology-svg"].addEventListener("pointermove", canvasPointerMove);
  dom["topology-svg"].addEventListener("pointerup", canvasPointerUp);
  dom["topology-svg"].addEventListener("pointercancel", canvasPointerUp);
  dom["topology-svg"].addEventListener("wheel", canvasWheel, { passive: false });
}

function bindInspector() {
  [
    ["object-tab", "object-panel"],
    ["event-tab", "event-panel"],
    ["propagation-tab", "propagation-panel"],
  ].forEach(([tab, panel]) => {
    dom[tab].addEventListener("click", () => showInspectorPanel(tab, panel));
  });
  dom["object-form"].addEventListener("submit", applyObjectForm);
  dom["delete-object"].addEventListener("click", deleteSelection);
  dom["schedule-link-state"].addEventListener("click", scheduleSelectedLinkState);
  dom["event-form"].addEventListener("submit", saveEventFromForm);
  dom["clear-event-form"].addEventListener("click", clearEventForm);
  dom["delete-event"].addEventListener("click", deleteSelectedEvent);
  dom["event-payload"].addEventListener("input", validatePayloadField);
  dom["event-auto-propagate"].addEventListener("change", () => {
    if (dom["event-auto-propagate"].checked) {
      showInspectorPanel("propagation-tab", "propagation-panel");
    }
  });
  dom["propagation-target-mode"].addEventListener("change", renderPropagationTargets);
  dom["preview-propagation"].addEventListener("click", () => void previewPropagation());
  dom["propagation-form"].addEventListener("submit", applyPropagation);
}

function bindTimeline() {
  dom["selected-time"].addEventListener("input", (event) => setSelectedTime(event.target.value));
  dom["time-rail"].addEventListener("input", (event) => setSelectedTime(event.target.value));
  dom["add-event"].addEventListener("click", () => {
    clearEventForm();
    showInspectorPanel("event-tab", "event-panel");
    dom["event-node"].focus();
  });
  [
    dom["event-filter-node"],
    dom["event-filter-physical"],
    dom["event-filter-local"],
  ].forEach((control) => control.addEventListener("change", renderTimeline));
}

function bindDialogs() {
  document.querySelectorAll(".close-dialog").forEach((button) => {
    button.addEventListener("click", () => button.closest("dialog").close());
  });
  dom["pattern-form"].addEventListener("submit", applyPattern);
  dom["retry-generation"].addEventListener("click", () => void generateDumps());
}

function bindKeyboard() {
  document.addEventListener("keydown", (event) => {
    const editing = /INPUT|TEXTAREA|SELECT/.test(event.target.tagName);
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "z") {
      event.preventDefault();
      event.shiftKey ? redo() : undo();
      return;
    }
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "y") {
      event.preventDefault();
      redo();
      return;
    }
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "s") {
      event.preventDefault();
      saveProject();
      return;
    }
    if (editing) return;
    if (event.key === "Escape") {
      cancelLink();
      selection = null;
      selectedEventId = null;
      renderAll();
      return;
    }
    if (event.key === "Delete" || event.key === "Backspace") {
      if (selection) {
        event.preventDefault();
        deleteSelection();
      }
      return;
    }
    if (event.key.toLowerCase() === "l") setTool("link");
    if (event.key.toLowerCase() === "v") setTool("select");
    if (event.key === "+" || event.key === "=") zoomAt(1.18);
    if (event.key === "-") zoomAt(0.85);
    if (event.key.toLowerCase() === "f") fitCanvas();
    if (
      selection?.type === "node" &&
      ["ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight"].includes(event.key)
    ) {
      event.preventDefault();
      const step = event.shiftKey ? 20 : 4;
      const node = nodeById(selection.id);
      if (!node) return;
      transact(() => {
        if (event.key === "ArrowUp") node.position.y -= step;
        if (event.key === "ArrowDown") node.position.y += step;
        if (event.key === "ArrowLeft") node.position.x -= step;
        if (event.key === "ArrowRight") node.position.x += step;
      });
    }
  });
}

function addObject(kind, point) {
  if (!Object.hasOwn(KIND_NAMES, kind)) return null;
  const count = scenario.nodes.filter((node) => node.kind === kind).length + 1;
  const fallbackPoint = {
    x: 100 + (scenario.nodes.length % 4) * 200,
    y: 100 + Math.floor(scenario.nodes.length / 4) * 140,
  };
  const position = point || fallbackPoint;
  const node = {
    id: makeId("node"),
    name: `${KIND_NAMES[kind]} ${count}`,
    kind,
    position: {
      x: position.x - nodeSize(kind).width / 2,
      y: position.y - nodeSize(kind).height / 2,
    },
    site: "",
    profile: "generic",
    notes: "",
    dump_enabled: kind === "router",
    clock: { offset_ns: 0, uncertainty_ns: 0 },
    initial_resources: [],
  };
  transact(() => {
    scenario.nodes.push(node);
  });
  selection = { type: "node", id: node.id };
  renderAll();
  return node;
}

function addLink(fromId, toId) {
  if (!fromId || !toId || fromId === toId) {
    toast("Choose two different topology objects.", "error");
    return null;
  }
  if (!nodeById(fromId) || !nodeById(toId)) return null;
  if (
    scenario.physical_links.some(
      (link) =>
        (link.a.node_id === fromId && link.b.node_id === toId) ||
        (link.a.node_id === toId && link.b.node_id === fromId),
    )
  ) {
    toast("Those objects already have a physical link.", "error");
    return null;
  }
  const link = {
    id: makeId("link"),
    name: `Link ${scenario.physical_links.length + 1}`,
    a: { node_id: fromId, port: nextPortName(fromId) },
    b: { node_id: toId, port: nextPortName(toId) },
    initial_state: "up",
    notes: "",
  };
  transact(() => scenario.physical_links.push(link));
  selection = { type: "link", id: link.id };
  cancelLink();
  renderAll();
  return link;
}

function nextPortName(nodeId) {
  const node = nodeById(nodeId);
  if (node?.kind === "shared-medium") return `attachment-${linkCount(nodeId) + 1}`;
  return `Ethernet${linkCount(nodeId) + 1}`;
}

function linkCount(nodeId) {
  return scenario.physical_links.filter(
    (link) => link.a.node_id === nodeId || link.b.node_id === nodeId,
  ).length;
}

function transact(mutator, { render = true } = {}) {
  history.push(structuredClone(scenario));
  if (history.length > 80) history.shift();
  future = [];
  mutator();
  scenario.updated_at = new Date().toISOString();
  scenario.duration_ms = Math.max(
    scenario.duration_ms || 60_000,
    maxEventTime(scenario.events) + 10_000,
  );
  eventDurationMs = scenario.duration_ms;
  dirty = true;
  if (render) renderAll();
}

function undo() {
  if (!history.length) return;
  future.push(structuredClone(scenario));
  scenario = history.pop();
  dirty = true;
  repairSelection();
  renderAll();
}

function redo() {
  if (!future.length) return;
  history.push(structuredClone(scenario));
  scenario = future.pop();
  dirty = true;
  repairSelection();
  renderAll();
}

function repairSelection() {
  if (selection?.type === "node" && !nodeById(selection.id)) selection = null;
  if (selection?.type === "link" && !linkById(selection.id)) selection = null;
  if (selectedEventId && !eventById(selectedEventId)) selectedEventId = null;
}

function renderAll() {
  dom["project-name"].value = scenario.name || "Untitled scenario";
  renderCanvas();
  renderInspector();
  renderTimeline();
  renderSelectOptions();
  renderHistoryButtons();
  renderZoom();
}

function renderHistoryButtons() {
  dom.undo.disabled = history.length === 0;
  dom.redo.disabled = future.length === 0;
}

function renderCanvas() {
  dom["objects-layer"].replaceChildren();
  dom["links-layer"].replaceChildren();
  dom["gesture-layer"].replaceChildren();
  dom["viewport-layer"].setAttribute(
    "transform",
    `translate(${panZoom.x} ${panZoom.y}) scale(${panZoom.scale})`,
  );

  const validLinks = scenario.physical_links.filter(
    (link) => nodeById(link.a.node_id) && nodeById(link.b.node_id),
  );
  for (const link of validLinks) renderLink(link);
  for (const node of scenario.nodes) renderNode(node);

  dom["empty-canvas"].hidden = scenario.nodes.length > 0;
  dom["object-count"].textContent = String(scenario.nodes.length);
  dom["scenario-canvas"].classList.toggle("link-mode", currentTool === "link");
  dom["selection-status"].textContent = selectionDescription();
}

function renderNode(node) {
  const size = nodeSize(node.kind);
  const group = svg("g", {
    class: `topology-node kind-${node.kind}${selection?.type === "node" && selection.id === node.id ? " selected" : ""}`,
    transform: `translate(${node.position.x} ${node.position.y})`,
    "data-node-id": node.id,
  });
  const card = svg("rect", {
    class: "node-card",
    width: size.width,
    height: size.height,
    rx: node.kind === "shared-medium" ? size.height / 2 : 11,
  });
  const iconBg = svg("rect", {
    class: "node-icon-bg",
    x: 12,
    y: node.kind === "shared-medium" ? 15 : 13,
    width: 28,
    height: 28,
    rx: node.kind === "shared-medium" ? 14 : 7,
  });
  const glyph = svg("text", {
    class: "node-icon-glyph",
    x: 26,
    y: node.kind === "shared-medium" ? 29 : 27,
  });
  glyph.textContent = KIND_GLYPHS[node.kind] || "?";
  const title = svg("text", {
    class: "node-title",
    x: 49,
    y: node.kind === "shared-medium" ? 24 : 23,
  });
  title.textContent = truncate(node.name, node.kind === "shared-medium" ? 16 : 19);
  const meta = svg("text", {
    class: "node-meta",
    x: 49,
    y: node.kind === "shared-medium" ? 39 : 40,
  });
  meta.textContent =
    node.kind === "shared-medium"
      ? `${linkCount(node.id)} attachments`
      : truncate([node.site, node.profile].filter(Boolean).join(" · ") || node.kind, 25);
  group.append(card, iconBg, glyph, title, meta);
  if (node.kind !== "shared-medium") {
    const state = svg("text", {
      class: "node-state",
      x: 13,
      y: size.height - 12,
    });
    state.textContent = node.kind === "router" ? "DUMP NODE" : "PHYSICAL ONLY";
    group.append(state);
  }
  const ports = [
    [0, size.height / 2, "west"],
    [size.width / 2, 0, "north"],
    [size.width, size.height / 2, "east"],
    [size.width / 2, size.height, "south"],
  ];
  ports.forEach(([x, y, side]) => {
    const port = svg("circle", {
      class: `node-port${linkSourceId === node.id ? " link-source" : ""}`,
      cx: x,
      cy: y,
      r: 3.5,
      "data-side": side,
    });
    group.append(port);
  });
  dom["objects-layer"].append(group);
}

function renderLink(link) {
  const nodeA = nodeById(link.a.node_id);
  const nodeB = nodeById(link.b.node_id);
  const a = attachmentPoint(nodeA, centerOf(nodeB));
  const b = attachmentPoint(nodeB, centerOf(nodeA));
  const curve = curvedPath(a, b, stableCurve(link.id));
  const state = linkStateAt(link.id, selectedTimeMs());
  const group = svg("g", {
    class: `topology-link state-${state}${selection?.type === "link" && selection.id === link.id ? " selected" : ""}`,
    "data-link-id": link.id,
  });
  const hit = svg("path", { class: "link-hit", d: curve.path });
  const visible = svg("path", { class: "link-visible", d: curve.path });
  group.append(hit, visible);

  if (panZoom.scale >= 0.72 || selection?.id === link.id) {
    const label = svg("g", {
      class: "link-label",
      transform: `translate(${curve.mid.x} ${curve.mid.y})`,
    });
    const text = truncate(`${link.a.port} ↔ ${link.b.port}`, 27);
    const width = Math.max(56, text.length * 5.2 + 12);
    label.append(
      svg("rect", { x: -width / 2, y: -8, width, height: 16, rx: 6 }),
    );
    const textNode = svg("text", { x: 0, y: 3 });
    textNode.textContent = text;
    label.append(textNode);
    group.append(label);
  }
  dom["links-layer"].append(group);
}

function nodeSize(kind) {
  if (kind === "shared-medium") return { width: 150, height: 58 };
  if (kind === "host") return { width: 155, height: 78 };
  return { width: 175, height: 84 };
}

function centerOf(node) {
  const size = nodeSize(node.kind);
  return {
    x: node.position.x + size.width / 2,
    y: node.position.y + size.height / 2,
  };
}

function attachmentPoint(node, target) {
  const size = nodeSize(node.kind);
  const center = centerOf(node);
  const dx = target.x - center.x;
  const dy = target.y - center.y;
  if (node.kind === "shared-medium") {
    const rx = size.width / 2;
    const ry = size.height / 2;
    const denominator = Math.sqrt((dx * dx) / (rx * rx) + (dy * dy) / (ry * ry)) || 1;
    return { x: center.x + dx / denominator, y: center.y + dy / denominator };
  }
  const scale = 1 / Math.max(Math.abs(dx) / (size.width / 2), Math.abs(dy) / (size.height / 2), 1);
  return { x: center.x + dx * scale, y: center.y + dy * scale };
}

function curvedPath(a, b, bend) {
  const dx = b.x - a.x;
  const dy = b.y - a.y;
  const distance = Math.max(1, Math.hypot(dx, dy));
  const amount = Math.min(55, distance * 0.13) * bend;
  const control = {
    x: (a.x + b.x) / 2 - (dy / distance) * amount,
    y: (a.y + b.y) / 2 + (dx / distance) * amount,
  };
  const mid = {
    x: 0.25 * a.x + 0.5 * control.x + 0.25 * b.x,
    y: 0.25 * a.y + 0.5 * control.y + 0.25 * b.y,
  };
  return {
    path: `M ${a.x} ${a.y} Q ${control.x} ${control.y} ${b.x} ${b.y}`,
    mid,
  };
}

function stableCurve(id) {
  let hash = 0;
  for (let i = 0; i < id.length; i += 1) hash = (hash * 31 + id.charCodeAt(i)) | 0;
  return hash % 2 === 0 ? 0.42 : -0.42;
}

function svg(tag, attributes = {}) {
  const element = document.createElementNS(SVG_NS, tag);
  Object.entries(attributes).forEach(([name, value]) => element.setAttribute(name, value));
  return element;
}

function truncate(value, max) {
  const text = stringValue(value);
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

function selectionDescription() {
  if (!selection) return "Nothing selected";
  if (selection.type === "node") {
    const node = nodeById(selection.id);
    return node ? `${KIND_NAMES[node.kind]} · ${node.name}` : "Nothing selected";
  }
  const link = linkById(selection.id);
  if (!link) return "Nothing selected";
  return `Physical link · ${nodeById(link.a.node_id)?.name || "?"} ↔ ${nodeById(link.b.node_id)?.name || "?"}`;
}

function canvasPointerDown(event) {
  pointers.set(event.pointerId, { x: event.clientX, y: event.clientY });
  dom["topology-svg"].setPointerCapture(event.pointerId);
  if (pointers.size === 2) {
    dragState = pinchState();
    return;
  }
  const nodeGroup = event.target.closest?.(".topology-node");
  const linkGroup = event.target.closest?.(".topology-link");
  if (nodeGroup) {
    const nodeId = nodeGroup.dataset.nodeId;
    if (currentTool === "link") {
      handleLinkClick(nodeId);
      return;
    }
    selection = { type: "node", id: nodeId };
    selectedEventId = null;
    const node = nodeById(nodeId);
    const world = clientToWorld(event.clientX, event.clientY);
    dragState = {
      kind: "node",
      pointerId: event.pointerId,
      id: nodeId,
      start: world,
      origin: { ...node.position },
      changed: false,
    };
    renderAll();
    return;
  }
  if (linkGroup && currentTool !== "pan") {
    selection = { type: "link", id: linkGroup.dataset.linkId };
    selectedEventId = null;
    renderAll();
    return;
  }
  if (currentTool === "link") {
    cancelLink();
    return;
  }
  selection = null;
  selectedEventId = null;
  dragState = {
    kind: "pan",
    pointerId: event.pointerId,
    client: { x: event.clientX, y: event.clientY },
    origin: { ...panZoom },
  };
  renderAll();
}

function canvasPointerMove(event) {
  if (!pointers.has(event.pointerId)) return;
  pointers.set(event.pointerId, { x: event.clientX, y: event.clientY });
  if (pointers.size === 2 && dragState?.kind === "pinch") {
    const current = pinchMetrics();
    const factor = current.distance / dragState.distance;
    const nextScale = clamp(dragState.scale * factor, 0.12, 8);
    panZoom.scale = nextScale;
    panZoom.x =
      current.center.x -
      dom["scenario-canvas"].getBoundingClientRect().left -
      dragState.world.x * nextScale;
    panZoom.y =
      current.center.y -
      dom["scenario-canvas"].getBoundingClientRect().top -
      dragState.world.y * nextScale;
    renderCanvas();
    renderZoom();
    return;
  }
  if (!dragState || dragState.pointerId !== event.pointerId) return;
  if (dragState.kind === "node") {
    const point = clientToWorld(event.clientX, event.clientY);
    const node = nodeById(dragState.id);
    if (!node) return;
    node.position.x = dragState.origin.x + point.x - dragState.start.x;
    node.position.y = dragState.origin.y + point.y - dragState.start.y;
    dragState.changed = true;
    dirty = true;
    renderCanvas();
  } else if (dragState.kind === "pan") {
    panZoom.x = dragState.origin.x + event.clientX - dragState.client.x;
    panZoom.y = dragState.origin.y + event.clientY - dragState.client.y;
    renderCanvas();
  }
}

function canvasPointerUp(event) {
  pointers.delete(event.pointerId);
  try {
    dom["topology-svg"].releasePointerCapture(event.pointerId);
  } catch {
    // The browser may have released capture after a cancelled gesture.
  }
  if (dragState?.kind === "node" && dragState.changed) {
    const node = nodeById(dragState.id);
    const finalPosition = node ? { ...node.position } : null;
    if (node && finalPosition) {
      node.position = dragState.origin;
      transact(() => {
        node.position = finalPosition;
      });
    }
  }
  if (pointers.size < 2) dragState = null;
}

function pinchMetrics() {
  const [first, second] = [...pointers.values()];
  return {
    center: { x: (first.x + second.x) / 2, y: (first.y + second.y) / 2 },
    distance: Math.max(1, Math.hypot(second.x - first.x, second.y - first.y)),
  };
}

function pinchState() {
  const metrics = pinchMetrics();
  const rect = dom["scenario-canvas"].getBoundingClientRect();
  return {
    kind: "pinch",
    distance: metrics.distance,
    scale: panZoom.scale,
    world: {
      x: (metrics.center.x - rect.left - panZoom.x) / panZoom.scale,
      y: (metrics.center.y - rect.top - panZoom.y) / panZoom.scale,
    },
  };
}

function canvasWheel(event) {
  event.preventDefault();
  // Browsers report touchpad pinch as Ctrl+wheel. Plain two-finger wheel pans.
  if (event.ctrlKey || event.metaKey) {
    const factor = Math.exp(-event.deltaY * 0.002);
    zoomAt(factor, { x: event.clientX, y: event.clientY });
  } else {
    panZoom.x -= event.deltaX;
    panZoom.y -= event.deltaY;
    renderCanvas();
  }
}

function zoomAt(factor, clientPoint) {
  const rect = dom["scenario-canvas"].getBoundingClientRect();
  const point = clientPoint || { x: rect.left + rect.width / 2, y: rect.top + rect.height / 2 };
  const oldScale = panZoom.scale;
  const newScale = clamp(oldScale * factor, 0.12, 8);
  const worldX = (point.x - rect.left - panZoom.x) / oldScale;
  const worldY = (point.y - rect.top - panZoom.y) / oldScale;
  panZoom.x = point.x - rect.left - worldX * newScale;
  panZoom.y = point.y - rect.top - worldY * newScale;
  panZoom.scale = newScale;
  renderCanvas();
  renderZoom();
}

function fitCanvas() {
  if (!scenario.nodes.length) {
    panZoom = { x: 0, y: 0, scale: 1 };
    renderAll();
    return;
  }
  const rect = dom["scenario-canvas"].getBoundingClientRect();
  const boxes = scenario.nodes.map((node) => {
    const size = nodeSize(node.kind);
    return {
      left: node.position.x,
      top: node.position.y,
      right: node.position.x + size.width,
      bottom: node.position.y + size.height,
    };
  });
  const bounds = {
    left: Math.min(...boxes.map((box) => box.left)),
    top: Math.min(...boxes.map((box) => box.top)),
    right: Math.max(...boxes.map((box) => box.right)),
    bottom: Math.max(...boxes.map((box) => box.bottom)),
  };
  const width = Math.max(1, bounds.right - bounds.left);
  const height = Math.max(1, bounds.bottom - bounds.top);
  const scale = clamp(Math.min((rect.width - 90) / width, (rect.height - 90) / height), 0.12, 2);
  panZoom.scale = scale;
  panZoom.x = (rect.width - width * scale) / 2 - bounds.left * scale;
  panZoom.y = (rect.height - height * scale) / 2 - bounds.top * scale;
  renderAll();
}

function renderZoom() {
  dom["zoom-level"].textContent = `${Math.round(panZoom.scale * 100)}%`;
}

function clientToWorld(clientX, clientY) {
  const rect = dom["scenario-canvas"].getBoundingClientRect();
  return {
    x: (clientX - rect.left - panZoom.x) / panZoom.scale,
    y: (clientY - rect.top - panZoom.y) / panZoom.scale,
  };
}

function setTool(tool) {
  currentTool = tool;
  if (tool !== "link") cancelLink(false);
  document.querySelectorAll(".tool-button[data-tool]").forEach((button) => {
    const active = button.dataset.tool === tool;
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", String(active));
  });
  renderCanvas();
}

function handleLinkClick(nodeId) {
  if (!linkSourceId) {
    linkSourceId = nodeId;
    selection = { type: "node", id: nodeId };
    dom["link-instruction"].hidden = false;
    renderCanvas();
    return;
  }
  addLink(linkSourceId, nodeId);
  linkSourceId = null;
}

function cancelLink(render = true) {
  linkSourceId = null;
  dom["link-instruction"].hidden = true;
  if (render) renderCanvas();
}

function renderInspector() {
  if (!selection) {
    dom["object-form"].hidden = true;
    dom["no-object"].hidden = false;
    return;
  }
  const object = selection.type === "node" ? nodeById(selection.id) : linkById(selection.id);
  if (!object) {
    selection = null;
    renderInspector();
    return;
  }
  dom["object-form"].hidden = false;
  dom["no-object"].hidden = true;
  const isLink = selection.type === "link";
  dom["node-fields"].hidden = isLink;
  dom["link-fields"].hidden = !isLink;
  dom["object-kind-label"].textContent = isLink ? "Physical link" : KIND_NAMES[object.kind];
  dom["object-heading"].textContent = object.name;
  dom["object-name"].value = object.name;
  dom["object-site"].value = isLink ? "" : object.site || "";
  dom["object-profile"].value = isLink ? "" : object.profile || "";
  dom["object-notes"].value = object.notes || "";
  if (isLink) {
    dom["link-port-a"].value = object.a.port || "";
    dom["link-port-b"].value = object.b.port || "";
    dom["link-state"].value = linkStateAt(object.id, selectedTimeMs());
  }
}

function applyObjectForm(event) {
  event.preventDefault();
  if (!selection) return;
  const object = selection.type === "node" ? nodeById(selection.id) : linkById(selection.id);
  if (!object) return;
  const next = {
    name: dom["object-name"].value.trim() || object.name,
    notes: dom["object-notes"].value,
    site: dom["object-site"].value.trim(),
    profile: dom["object-profile"].value.trim() || "generic",
    portA: dom["link-port-a"].value.trim() || "auto",
    portB: dom["link-port-b"].value.trim() || "auto",
  };
  transact(() => {
    object.name = next.name;
    object.notes = next.notes;
    if (selection.type === "node") {
      object.site = next.site;
      object.profile = next.profile;
    } else {
      object.a.port = next.portA;
      object.b.port = next.portB;
    }
  });
  toast("Object updated.", "success");
}

function deleteSelection() {
  if (!selection) return;
  const label = selectionDescription();
  if (!globalThis.confirm(`Delete ${label}? Related links and targeted physical events will also be removed.`)) {
    return;
  }
  transact(() => {
    if (selection.type === "node") {
      const nodeId = selection.id;
      const removedLinkIds = new Set(
        scenario.physical_links
          .filter((link) => link.a.node_id === nodeId || link.b.node_id === nodeId)
          .map((link) => link.id),
      );
      scenario.nodes = scenario.nodes.filter((node) => node.id !== nodeId);
      scenario.physical_links = scenario.physical_links.filter((link) => !removedLinkIds.has(link.id));
      scenario.events = scenario.events.filter(
        (event) =>
          event.node_id !== nodeId &&
          event.target_id !== nodeId &&
          !removedLinkIds.has(event.target_id),
      );
    } else {
      scenario.physical_links = scenario.physical_links.filter((link) => link.id !== selection.id);
      scenario.events = scenario.events.filter(
        (event) => !(event.scope === "physical" && event.target_id === selection.id),
      );
    }
  });
  selection = null;
  renderAll();
}

function scheduleSelectedLinkState() {
  if (selection?.type !== "link") return;
  const link = linkById(selection.id);
  if (!link) return;
  const state = dom["link-state"].value;
  const event = makeEvent({
    scope: "physical",
    target_type: "physical-link",
    target_id: link.id,
    subject: link.name,
    kind: "physical-link-state",
    action: "set_state",
    outcome: "ok",
    state_patch: { state },
    log_text: "",
    update_final_state: false,
  });
  transact(() => scenario.events.push(event));
  selectedEventId = event.id;
  loadEventForm(event);
  showInspectorPanel("event-tab", "event-panel");
  toast(`Scheduled physical state “${state}”.`, "success");
}

function renderTimeline() {
  const maxTime = Math.max(1_000, scenario.duration_ms, maxEventTime(scenario.events) + 10_000);
  eventDurationMs = maxTime;
  dom["time-rail"].max = String(maxTime / 1000);
  dom["time-rail"].value = String(Math.min(selectedTimeMs(), maxTime) / 1000);
  dom["selected-time"].value = formatSeconds(selectedTimeMs());
  renderTimeLabels(maxTime);
  renderEventMarkers(maxTime);

  const nodeFilter = dom["event-filter-node"].value;
  const showPhysical = dom["event-filter-physical"].checked;
  const showLocal = dom["event-filter-local"].checked;
  const events = [...scenario.events]
    .filter((event) => (!nodeFilter || event.node_id === nodeFilter))
    .filter((event) => (event.scope === "physical" ? showPhysical : showLocal))
    .sort(eventSort);
  dom["event-count"].textContent = `${events.length} event${events.length === 1 ? "" : "s"}`;
  dom["event-list"].replaceChildren();
  if (!events.length) {
    const row = document.createElement("tr");
    row.className = "empty-row";
    const cell = document.createElement("td");
    cell.colSpan = 7;
    cell.textContent = "No changes match the current filters.";
    row.append(cell);
    dom["event-list"].append(row);
    return;
  }
  events.forEach((event) => dom["event-list"].append(renderEventRow(event)));
}

function renderEventRow(event) {
  const row = document.createElement("tr");
  row.className = `event-row${selectedEventId === event.id ? " selected" : ""}`;
  row.dataset.eventId = event.id;
  row.tabIndex = 0;
  const time = document.createElement("td");
  time.textContent = `+${formatSeconds(event.time_ms)} s`;
  const scope = document.createElement("td");
  const scopePill = document.createElement("span");
  scopePill.className = `scope-pill${event.scope === "physical" ? " physical" : ""}`;
  scopePill.textContent =
    event.scope === "physical"
      ? "physical truth"
      : nodeById(event.node_id)?.name || event.node_id || "unassigned";
  scope.append(scopePill);
  const kind = document.createElement("td");
  kind.textContent = event.kind;
  const subject = document.createElement("td");
  subject.textContent = event.subject || "—";
  const action = document.createElement("td");
  action.textContent = event.action || "—";
  const outcome = document.createElement("td");
  const outcomePill = document.createElement("span");
  outcomePill.className = `outcome-pill ${event.outcome}`;
  outcomePill.textContent = event.outcome;
  outcome.append(outcomePill);
  const actions = document.createElement("td");
  actions.className = "row-actions";
  const edit = document.createElement("button");
  edit.type = "button";
  edit.className = "icon-button";
  edit.title = "Edit event";
  edit.setAttribute("aria-label", "Edit event");
  edit.textContent = "✎";
  edit.addEventListener("click", (clickEvent) => {
    clickEvent.stopPropagation();
    selectEvent(event.id);
  });
  const remove = document.createElement("button");
  remove.type = "button";
  remove.className = "icon-button danger";
  remove.title = "Remove event";
  remove.setAttribute("aria-label", "Remove event");
  remove.textContent = "×";
  remove.addEventListener("click", (clickEvent) => {
    clickEvent.stopPropagation();
    removeEvent(event.id);
  });
  actions.append(edit, remove);
  row.append(time, scope, kind, subject, action, outcome, actions);
  row.addEventListener("click", () => selectEvent(event.id));
  row.addEventListener("keydown", (keyEvent) => {
    if (keyEvent.key === "Enter" || keyEvent.key === " ") {
      keyEvent.preventDefault();
      selectEvent(event.id);
    }
  });
  return row;
}

function renderTimeLabels(maxTime) {
  dom["time-labels"].replaceChildren();
  const count = 5;
  for (let index = 0; index < count; index += 1) {
    const value = (maxTime * index) / (count - 1);
    const label = svg("text", {
      x: `${(index / (count - 1)) * 100}%`,
      y: 11,
      "text-anchor": index === 0 ? "start" : index === count - 1 ? "end" : "middle",
    });
    label.textContent = `+${formatSeconds(value)}s`;
    dom["time-labels"].append(label);
  }
}

function renderEventMarkers(maxTime) {
  dom["event-markers"].replaceChildren();
  scenario.events.forEach((event) => {
    const marker = svg("rect", {
      class: `event-marker${event.scope === "physical" ? " physical" : ""}${event.outcome === "failed" ? " failed" : ""}`,
      x: `${clamp((event.time_ms / maxTime) * 100, 0, 100)}%`,
      y: event.outcome === "failed" ? 0 : 2,
      width: 3,
      height: event.outcome === "failed" ? 14 : 10,
      rx: 1.5,
    });
    dom["event-markers"].append(marker);
  });
}

function renderSelectOptions() {
  const currentEventNode = dom["event-node"].value;
  const currentFilter = dom["event-filter-node"].value;
  setOptions(
    dom["event-node"],
    dumpNodes().map((node) => ({ value: node.id, label: node.name })),
    currentEventNode,
    "Choose a dump-producing node",
  );
  setOptions(
    dom["event-filter-node"],
    dumpNodes().map((node) => ({ value: node.id, label: node.name })),
    currentFilter,
    "All nodes",
    true,
  );
  setOptions(
    dom["accessible-link-from"],
    scenario.nodes.map((node) => ({ value: node.id, label: node.name })),
    dom["accessible-link-from"].value,
    "Choose first object",
  );
  setOptions(
    dom["accessible-link-to"],
    scenario.nodes.map((node) => ({ value: node.id, label: node.name })),
    dom["accessible-link-to"].value,
    "Choose second object",
  );
  setOptions(
    dom["accessible-existing"],
    [
      ...scenario.nodes.map((node) => ({
        value: `node|${node.id}`,
        label: `${KIND_NAMES[node.kind] || node.kind}: ${node.name}`,
      })),
      ...scenario.physical_links.map((link) => ({
        value: `link|${link.id}`,
        label: `Link: ${nodeById(link.a.node_id)?.name || "?"} ↔ ${nodeById(link.b.node_id)?.name || "?"}`,
      })),
    ],
    selection ? `${selection.type}|${selection.id}` : "",
    "Choose an existing item",
  );
  renderPropagationTargets();
}

function setOptions(select, options, current, placeholder, allowEmpty = false) {
  select.replaceChildren();
  const placeholderOption = document.createElement("option");
  placeholderOption.value = "";
  placeholderOption.textContent = placeholder;
  placeholderOption.disabled = !allowEmpty;
  select.append(placeholderOption);
  options.forEach((option) => {
    const element = document.createElement("option");
    element.value = option.value;
    element.textContent = option.label;
    select.append(element);
  });
  if ([...select.options].some((option) => option.value === current)) {
    select.value = current;
  } else if (!allowEmpty && options.length) {
    select.value = options[0].value;
  } else {
    select.value = "";
  }
}

function renderPropagationTargets() {
  const visible = dom["propagation-target-mode"].value === "selected";
  dom["propagation-targets"].hidden = !visible;
  const selectedValues = new Set(
    [...dom["propagation-target-options"].querySelectorAll("input:checked")].map(
      (input) => input.value,
    ),
  );
  dom["propagation-target-options"].replaceChildren();
  dumpNodes().forEach((node) => {
    const label = document.createElement("label");
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.value = node.id;
    checkbox.checked = selectedValues.has(node.id);
    label.append(checkbox, document.createTextNode(node.name));
    dom["propagation-target-options"].append(label);
  });
}

function setSelectedTime(seconds) {
  const value = Math.max(0, finiteNumber(seconds, 0));
  const max = eventDurationMs / 1000;
  const clamped = Math.min(value, max);
  dom["selected-time"].value = String(clamped);
  dom["time-rail"].value = String(clamped);
  renderCanvas();
  renderInspector();
}

function selectedTimeMs() {
  return Math.max(0, finiteNumber(dom["selected-time"]?.value, 0) * 1000);
}

function linkStateAt(linkId, timeMs) {
  const link = linkById(linkId);
  if (!link) return "unknown";
  let state = link.initial_state || "up";
  const targetIds = new Set([
    linkId,
    link.source_medium_id,
    canonicalMediumIdForTarget(linkId),
  ]);
  scenario.events
    .filter(
      (event) =>
        event.scope === "physical" &&
        targetIds.has(event.target_id) &&
        event.time_ms <= timeMs &&
        (event.kind === "physical-link-state" || event.action === "set_state"),
    )
    .sort(eventSort)
    .forEach((event) => {
      state = stringValue(
        event.state_patch?.state ??
          event.state_patch?.oper_status ??
          event.status,
        state,
      );
    });
  return state;
}

function makeEvent(overrides = {}) {
  return normalizeEvent({
    id: makeId("event"),
    time_ms: selectedTimeMs(),
    scope: "node",
    node_id: dumpNodes()[0]?.id || "",
    kind: "status",
    subject: "",
    action: "",
    outcome: "ok",
    state_patch: {},
    log_text: "",
    update_final_state: true,
    propagation: null,
    ...overrides,
  });
}

function saveEventFromForm(event) {
  event.preventDefault();
  const parsed = parsePayload();
  if (!parsed.ok) return;
  const existing = selectedEventId ? eventById(selectedEventId) : null;
  const value = makeEvent({
    id: existing?.id || makeId("event"),
    time_ms: Math.max(0, finiteNumber(dom["event-time"].value, 0) * 1000),
    scope: existing?.scope === "physical" ? "physical" : "node",
    node_id: dom["event-node"].value,
    target_type: existing?.target_type || "",
    target_id: existing?.target_id || "",
    kind: dom["event-kind"].value,
    subject: dom["event-subject"].value.trim(),
    action: dom["event-action"].value.trim(),
    outcome: dom["event-outcome"].value,
    state_patch: parsed.value,
    log_text: dom["event-log"].value,
    update_final_state: dom["event-update-snapshot"].checked,
    propagation: existing?.propagation || null,
  });
  transact(() => {
    if (existing) {
      Object.assign(existing, value);
    } else {
      scenario.events.push(value);
    }
  });
  selectedEventId = value.id;
  dom["save-event"].textContent = "Update event";
  dom["delete-event"].hidden = false;
  if (dom["event-auto-propagate"].checked) {
    showInspectorPanel("propagation-tab", "propagation-panel");
    void previewPropagation();
  }
  toast(existing ? "Event updated." : "Event added.", "success");
}

function loadEventForm(event) {
  selectedEventId = event.id;
  dom["event-heading"].textContent =
    event.scope === "physical" ? "Edit physical change" : "Edit local event";
  dom["event-time"].value = formatSeconds(event.time_ms);
  dom["event-node"].value = event.node_id || dumpNodes()[0]?.id || "";
  dom["event-kind"].value = optionValueOr(dom["event-kind"], event.kind, "status");
  dom["event-outcome"].value = optionValueOr(dom["event-outcome"], event.outcome, "ok");
  dom["event-subject"].value = event.subject || "";
  dom["event-action"].value = event.action || "";
  const displayedPatch = structuredClone(event.state_patch || {});
  if (
    event.scope === "physical" &&
    displayedPatch.state === undefined &&
    event.status !== undefined
  ) {
    displayedPatch.state = event.status;
  }
  dom["event-payload"].value = JSON.stringify(displayedPatch, null, 2);
  dom["event-log"].value = event.log_text || "";
  dom["event-update-snapshot"].checked = event.update_final_state !== false;
  dom["event-auto-propagate"].checked = Boolean(event.propagation);
  dom["save-event"].textContent = "Update event";
  dom["delete-event"].hidden = false;
  dom["event-node"].disabled = event.scope === "physical";
  validatePayloadField();
  if (event.propagation && Object.keys(event.propagation).length) {
    loadPropagationControls(event.propagation);
  }
}

function clearEventForm() {
  selectedEventId = null;
  dom["event-heading"].textContent = "Add event";
  dom["event-time"].value = formatSeconds(selectedTimeMs());
  dom["event-node"].disabled = false;
  dom["event-node"].value = selection?.type === "node" ? selection.id : dumpNodes()[0]?.id || "";
  dom["event-kind"].value = "status";
  dom["event-outcome"].value = "ok";
  dom["event-subject"].value = "";
  dom["event-action"].value = "";
  dom["event-payload"].value = "{}";
  dom["event-log"].value = "";
  dom["event-update-snapshot"].checked = true;
  dom["event-auto-propagate"].checked = false;
  dom["save-event"].textContent = "Add event";
  dom["delete-event"].hidden = true;
  validatePayloadField();
  renderTimeline();
}

function selectEvent(id) {
  const event = eventById(id);
  if (!event) return;
  loadEventForm(event);
  setSelectedTime(event.time_ms / 1000);
  showInspectorPanel("event-tab", "event-panel");
  renderTimeline();
}

function deleteSelectedEvent() {
  if (selectedEventId) removeEvent(selectedEventId);
}

function removeEvent(id) {
  const event = eventById(id);
  if (!event) return;
  if (!globalThis.confirm(`Remove event at +${formatSeconds(event.time_ms)} s?`)) return;
  transact(() => {
    scenario.events = scenario.events.filter((candidate) => candidate.id !== id);
  });
  if (selectedEventId === id) clearEventForm();
}

function parsePayload() {
  try {
    const value = JSON.parse(dom["event-payload"].value || "{}");
    if (!isPlainObject(value)) throw new Error("State patch must be a JSON object.");
    dom["payload-error"].textContent = "";
    return { ok: true, value };
  } catch (error) {
    dom["payload-error"].textContent = error.message;
    return { ok: false, value: null };
  }
}

function validatePayloadField() {
  return parsePayload().ok;
}

function showInspectorPanel(tabId, panelId) {
  ["object-tab", "event-tab", "propagation-tab"].forEach((id) => {
    const active = id === tabId;
    dom[id].classList.toggle("active", active);
    dom[id].setAttribute("aria-selected", String(active));
  });
  ["object-panel", "event-panel", "propagation-panel"].forEach((id) => {
    dom[id].hidden = id !== panelId;
  });
}

function propagationSettings() {
  return {
    mode: dom["propagation-mode"].value,
    delay_ms: Math.max(0, finiteNumber(dom["propagation-delay"].value, 0)),
    jitter_ms: Math.max(0, finiteNumber(dom["propagation-jitter"].value, 0)),
    target_mode: dom["propagation-target-mode"].value,
    target_node_ids: [
      ...dom["propagation-target-options"].querySelectorAll("input:checked"),
    ].map((input) => input.value),
    outcome: dom["propagation-outcome"].value,
    cadence: dom["propagation-cadence"].value,
  };
}

function loadPropagationControls(value) {
  const settings = value && typeof value === "object" ? value : {};
  dom["propagation-mode"].value = optionValueOr(
    dom["propagation-mode"],
    settings.authored_mode || settings.mode || "best-effort",
    "best-effort",
  );
  dom["propagation-delay"].value = String(
    Math.max(0, finiteNumber(settings.delay_ms ?? settings.base_delay_ms, 250)),
  );
  dom["propagation-jitter"].value = String(
    Math.max(0, finiteNumber(settings.jitter_ms, 50)),
  );
  dom["propagation-target-mode"].value = optionValueOr(
    dom["propagation-target-mode"],
    settings.target_mode || settings.targets_mode || "neighbors",
    "neighbors",
  );
  dom["propagation-outcome"].value = optionValueOr(
    dom["propagation-outcome"],
    settings.outcome || settings.intended_outcome || "success",
    "success",
  );
  dom["propagation-cadence"].value = optionValueOr(
    dom["propagation-cadence"],
    settings.cadence || "parallel",
    "parallel",
  );
  renderPropagationTargets();
  const targets = new Set(settings.targets || settings.target_node_ids || []);
  dom["propagation-target-options"].querySelectorAll("input").forEach((input) => {
    input.checked = targets.has(input.value);
  });
}

function propagationSourceEvent() {
  if (selectedEventId) return eventById(selectedEventId);
  return scenario.events
    .filter((event) => event.time_ms <= selectedTimeMs())
    .sort(eventSort)
    .at(-1);
}

function computePropagationPreview(source, settings) {
  if (!source) return { schedule: [], summary: "Select or add an event first." };
  if (settings.mode === "suppressed") {
    return { schedule: [], summary: "Propagation is explicitly suppressed." };
  }
  const sourceNodeId =
    source.node_id ||
    (source.target_type === "physical-link"
      ? linkById(source.target_id)?.a.node_id
      : "");
  let targets = [];
  if (settings.target_mode === "all-nodes") {
    targets = dumpNodes().filter((node) => node.id !== sourceNodeId);
  } else if (settings.target_mode === "selected") {
    const ids = new Set(settings.target_node_ids);
    targets = dumpNodes().filter((node) => ids.has(node.id));
  } else {
    targets = propagationNeighbors(sourceNodeId);
    if (
      source.scope === "physical" &&
      ["physical-link", "link", "medium"].includes(source.target_type)
    ) {
      const link = linkById(source.target_id);
      targets = physicalTargetNodes(link, source.target_id);
    }
  }
  const base = source.time_ms + settings.delay_ms;
  const schedule = targets.map((node, index) => {
    let offset = 0;
    if (settings.cadence === "serial") offset = index * settings.delay_ms;
    if (settings.cadence === "waves") offset = Math.floor(index / 2) * settings.delay_ms;
    const jitter = deterministicJitter(`${source.id}:${node.id}`, settings.jitter_ms);
    const outcome =
      settings.outcome === "partial" && index % 3 === 2
        ? "failed"
        : settings.outcome === "failure"
          ? "failed"
          : settings.outcome === "stale"
            ? "partial"
            : "ok";
    return {
      node,
      time_ms: Math.max(source.time_ms, base + offset + jitter),
      outcome,
    };
  });
  return {
    schedule,
    summary: `${schedule.length} node-local observation${schedule.length === 1 ? "" : "s"} would be scheduled.`,
  };
}

async function previewPropagation() {
  const source = propagationSourceEvent();
  const settings = propagationSettings();
  const preview = computePropagationPreview(source, settings);
  dom["propagation-preview"].replaceChildren();
  const title = document.createElement("strong");
  title.textContent = preview.summary;
  dom["propagation-preview"].append(title);
  if (preview.schedule.length) {
    const list = document.createElement("ul");
    preview.schedule.forEach((item) => {
      const line = document.createElement("li");
      line.textContent = `+${formatSeconds(item.time_ms)} s · ${item.node.name} · ${item.outcome}`;
      list.append(line);
    });
    dom["propagation-preview"].append(list);
  } else {
    const detail = document.createElement("p");
    detail.textContent =
      settings.mode === "manual"
        ? "Manual mode records intent without synthesizing additional observations."
        : "Change the target scope or add connected routers.";
    dom["propagation-preview"].append(detail);
  }

  try {
    const result = await apiJson(API.preview, { scenario: scenarioForApi() });
    const detail = document.createElement("p");
    const totals = result.totals || {};
    detail.textContent = `Current replay: ${result.node_count ?? dumpNodes().length} dump files, ${totals.final_state_records ?? "?"} final records, ${totals.history_records ?? "?"} history records.`;
    dom["propagation-preview"].append(detail);
  } catch {
    // Local scheduling preview remains useful while a partially authored scenario is invalid.
  }
}

function applyPropagation(event) {
  event.preventDefault();
  const source = propagationSourceEvent();
  if (!source) {
    toast("Select or add an event before applying propagation.", "error");
    return;
  }
  const settings = propagationSettings();
  const preview = computePropagationPreview(source, settings);
  transact(() => {
    source.propagation = { ...structuredClone(settings), materialized: true };
    scenario.defaults.propagation = structuredClone(settings);
    if (settings.mode !== "best-effort" && settings.mode !== "failed") return;
    preview.schedule.forEach((item) => {
      const physicalSource = source.scope === "physical";
      const localPhysical = physicalSource
        ? localPhysicalObservation(item.node.id, source.target_id)
        : null;
      const stateChanged =
        settings.outcome !== "stale" && item.outcome !== "failed";
      const requestedState = stringValue(
        source.state_patch?.state ??
          source.state_patch?.oper_status ??
          source.status,
        "unknown",
      );
      scenario.events.push(
        makeEvent({
          time_ms: item.time_ms,
          node_id: item.node.id,
          kind: "propagated-observation",
          subject: localPhysical?.resourceId || source.subject,
          resource_type: localPhysical ? "interface" : source.resource_type,
          action: source.action || "observe_change",
          outcome: item.outcome,
          state_patch: stateChanged
            ? localPhysical
              ? { oper_status: requestedState }
              : structuredClone(source.state_patch)
            : {},
          log_text: localPhysical
            ? stateChanged
              ? `Observed local carrier ${requestedState} on ${localPhysical.port}.`
              : `Local carrier update on ${localPhysical.port} did not change state.`
            : "Best-effort local observation scheduled from the selected event.",
          update_final_state: item.outcome === "ok",
          propagation: {
            parent_event_id: source.id,
            generated: true,
            materialized: true,
            authored_mode: settings.mode,
            ...settings,
            mode: "manual",
          },
        }),
      );
    });
  });
  toast(
    preview.schedule.length
      ? `Scheduled ${preview.schedule.length} propagated observations.`
      : "Saved propagation intent without generated observations.",
    "success",
  );
  void previewPropagation();
}

function deterministicJitter(seed, maximum) {
  if (!maximum) return 0;
  let hash = 2166136261;
  for (let index = 0; index < seed.length; index += 1) {
    hash ^= seed.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return ((Math.abs(hash) % (maximum * 2 + 1)) - maximum);
}

function openPattern(patternId) {
  const pattern = PATTERNS[patternId];
  if (!pattern) return;
  currentPattern = patternId;
  dom["pattern-title"].textContent = pattern.title;
  dom["pattern-description"].textContent = pattern.description;
  dom["pattern-time"].value = formatSeconds(selectedTimeMs());
  const targets =
    pattern.target === "link"
      ? scenario.physical_links.map((link) => ({
          value: link.id,
          label: `${nodeById(link.a.node_id)?.name || "?"} ↔ ${nodeById(link.b.node_id)?.name || "?"}`,
        }))
      : pattern.target === "medium"
        ? scenario.nodes
            .filter((node) => node.kind === "shared-medium")
            .map((node) => ({ value: node.id, label: node.name }))
        : dumpNodes().map((node) => ({ value: node.id, label: node.name }));
  setOptions(dom["pattern-target"], targets, selection?.id, "Choose target");
  setOptions(
    dom["pattern-node"],
    dumpNodes().map((node) => ({ value: node.id, label: node.name })),
    selection?.type === "node" ? selection.id : "",
    "Choose affected node",
  );
  if (!targets.length) {
    toast(
      pattern.target === "link"
        ? "Draw a physical link before using this pattern."
        : pattern.target === "medium"
          ? "Add and connect a shared medium first."
          : "Add a router before using this pattern.",
      "error",
    );
    return;
  }
  dom["pattern-dialog"].showModal();
}

function applyPattern(event) {
  event.preventDefault();
  const pattern = PATTERNS[currentPattern];
  if (!pattern) return;
  const time = Math.max(0, finiteNumber(dom["pattern-time"].value, 0) * 1000);
  const delay = Math.max(0, finiteNumber(dom["pattern-delay"].value, 250));
  const duration = Math.max(0, finiteNumber(dom["pattern-duration"].value, 5) * 1000);
  const targetId = dom["pattern-target"].value;
  const nodeId = dom["pattern-node"].value;
  const generated = buildPatternEvents(currentPattern, { time, delay, duration, targetId, nodeId });
  if (!generated.length) {
    toast("The selected objects cannot support that pattern.", "error");
    return;
  }
  transact(() => scenario.events.push(...generated));
  dom["pattern-dialog"].close();
  setSelectedTime(time / 1000);
  toast(`Scheduled ${generated.length} events for ${pattern.title}.`, "success");
}

function buildPatternEvents(patternId, values) {
  const { time, delay, duration, targetId } = values;
  let { nodeId } = values;
  const link = linkById(targetId);
  if (!nodeId && link) nodeId = link.a.node_id;
  const participants = physicalTargetNodes(link, targetId);
  const participantIds = participants.map((node) => node.id);
  if (!participantIds.includes(nodeId)) nodeId = participantIds[0] || nodeId;
  const peerId = participantIds.find((id) => id !== nodeId) || "";
  const physical = (at, state) =>
    makeEvent({
      time_ms: at,
      scope: "physical",
      node_id: "",
      target_type: "physical-link",
      target_id: targetId,
      kind: "physical-link-state",
      subject: link?.name || targetId,
      action: "set_state",
      outcome: "ok",
      state_patch: { state },
      update_final_state: false,
      propagation: { mode: "manual", materialized: true },
    });
  const observed = (at, observer, action, state, outcome = "ok", update = true) => {
    const localPhysical = localPhysicalObservation(observer, targetId);
    const nodeLocal = localPhysical || {
      port: "local-node",
      resourceId: "system:local-node",
      resourceType: "system",
    };
    return makeEvent({
      time_ms: at,
      node_id: observer,
      kind: "physical-observation",
      subject: nodeLocal.resourceId,
      resource_type: nodeLocal.resourceType,
      action,
      outcome,
      state_patch: state ? { oper_status: state } : {},
      log_text: localPhysical
        ? `${action} on local port ${localPhysical.port}.`
        : `${action} on the local node.`,
      update_final_state: update,
    });
  };

  switch (patternId) {
    case "clean-link-flap":
      return [
        physical(time, "down"),
        ...participantIds.map((id, index) =>
          observed(time + delay + index * 20, id, "link_down_detected", "down"),
        ),
        physical(time + duration, "up"),
        ...participantIds.map((id, index) =>
          observed(time + duration + delay + index * 20, id, "link_up_detected", "up"),
        ),
      ];
    case "one-sided-detection":
      return [physical(time, "down"), observed(time + delay, nodeId, "link_down_detected", "down")];
    case "delayed-convergence":
      return [
        physical(time, "down"),
        observed(time + delay, nodeId, "neighbor_lost", "down"),
        ...(peerId
          ? [observed(time + delay * 4, peerId, "neighbor_lost_late", "down")]
          : []),
        observed(time + delay * 7, nodeId, "route_withdrawn", null),
      ];
    case "stale-neighbor":
      return [
        physical(time, "down"),
        observed(time + delay, nodeId, "link_down_detected", "down"),
        ...(peerId
          ? [
              observed(
                time + delay * 2,
                peerId,
                "neighbor_remains_stale",
                null,
                "partial",
                false,
              ),
            ]
          : []),
      ];
    case "failed-update":
      return [
        makeEvent({
          time_ms: time,
          node_id: targetId || nodeId,
          kind: "resource-upsert",
          subject: "user-specified-resource",
          action: "update_attempt",
          outcome: "failed",
          state_patch: {},
          log_text: "Resource update failed; retained previous state.",
          update_final_state: false,
        }),
      ];
    case "route-change":
      return [
        makeEvent({
          time_ms: time,
          node_id: targetId || nodeId,
          kind: "resource-upsert",
          subject: "route:user-specified-prefix",
          action: "replace_next_hop",
          state_patch: { next_hop: "user-specified", resolution: "manually steered" },
          log_text: "Route dependency changed by scenario author.",
        }),
      ];
    case "node-restart":
      return [
        observed(time, targetId || nodeId, "node_restart_begin", "down"),
        makeEvent({
          time_ms: time + delay,
          node_id: targetId || nodeId,
          kind: "resource-delete",
          subject: "dynamic-resources",
          action: "withdraw_after_restart",
          state_patch: {},
          log_text: "Dynamic resources withdrawn.",
        }),
        observed(time + duration, targetId || nodeId, "node_restart_complete", "up"),
        makeEvent({
          time_ms: time + duration + delay,
          node_id: targetId || nodeId,
          kind: "resource-upsert",
          subject: "dynamic-resources",
          action: "restore_after_restart",
          state_patch: { status: "restored" },
          log_text: "Dynamic resources restored.",
        }),
      ];
    case "clock-skew":
      return [
        makeEvent({
          time_ms: time,
          node_id: targetId || nodeId,
          kind: "clock",
          subject: "capture-clock",
          action: "set_clock_offset",
          state_patch: { offset_ms: Math.round(duration || 5000), uncertainty_ms: delay },
          log_text: "Capture clock offset changed.",
        }),
      ];
    case "log-gap":
      return [
        makeEvent({
          time_ms: time,
          node_id: targetId || nodeId,
          kind: "log",
          subject: "source-log",
          action: "gap_begin",
          outcome: "unknown",
          state_patch: { expected_restore_ms: time + duration },
          log_text: "Source records unavailable.",
          update_final_state: false,
        }),
        makeEvent({
          time_ms: time + duration,
          node_id: targetId || nodeId,
          kind: "log",
          subject: "source-log",
          action: "gap_end",
          state_patch: {},
          log_text: "Source records resumed.",
          update_final_state: false,
        }),
      ];
    case "partial-multi-access": {
      const participants = neighborsOf(targetId).filter(
        (node) => node.kind !== "shared-medium" && node.dump_enabled !== false,
      );
      const output = participants.map((node, index) =>
        makeEvent({
          time_ms: time + delay * index,
          node_id: node.id,
          kind: "physical-observation",
          subject: nodeById(targetId)?.name || targetId,
          action: "multi_access_member_change",
          outcome: index === participants.length - 1 ? "failed" : "ok",
          state_patch: index === participants.length - 1 ? {} : { member_status: "down" },
          log_text:
            index === participants.length - 1
              ? "Member failed to observe the shared-medium change."
              : "Shared-medium member changed state.",
          update_final_state: index !== participants.length - 1,
        }),
      );
      return output;
    }
    default:
      return [];
  }
}

async function handleProjectFile(event) {
  const [file] = event.target.files;
  event.target.value = "";
  if (!file) return;
  try {
    const payload = JSON.parse(await file.text());
    const project = payload.scenario && isPlainObject(payload.scenario) ? payload.scenario : payload;
    scenario = normalizeScenario(project);
    selection = null;
    selectedEventId = null;
    history = [];
    future = [];
    eventDurationMs = scenario.duration_ms;
    loadPropagationControls(scenario.defaults?.propagation || {});
    dirty = false;
    panZoom = { x: 0, y: 0, scale: 1 };
    renderAll();
    requestAnimationFrame(fitCanvas);
    toast(`Loaded ${file.name}.`, "success");
  } catch (error) {
    toast(`Could not open project: ${error.message}`, "error");
  }
}

function saveProject() {
  scenario.name = dom["project-name"].value.trim() || scenario.name;
  scenario.updated_at = new Date().toISOString();
  const blob = new Blob([`${JSON.stringify(toCanonicalProject(), null, 2)}\n`], {
    type: "application/json",
  });
  downloadBlob(blob, `${safeFilename(scenario.name)}.scenario.json`);
  dirty = false;
  toast("Saved the authoring project, including physical ground truth.", "success");
}

async function validateProject(showToast = false) {
  dom["validation-summary"].textContent = "Validating…";
  dom["validation-summary"].className = "muted-status";
  try {
    const result = await apiJson(API.validate, { scenario: scenarioForApi() }, true);
    const errors = Array.isArray(result.errors) ? result.errors : [];
    const warnings = Array.isArray(result.warnings) ? result.warnings : [];
    if (result.ok !== false && errors.length === 0) {
      dom["validation-summary"].textContent = warnings.length
        ? `Valid · ${warnings.length} warning${warnings.length === 1 ? "" : "s"}`
        : "Valid · ready to generate";
      dom["validation-summary"].className = warnings.length ? "status-warning" : "status-ok";
      if (showToast) toast("Scenario validation passed.", "success");
      return { ok: true, result };
    }
    dom["validation-summary"].textContent = `${errors.length || 1} validation error${errors.length === 1 ? "" : "s"}`;
    dom["validation-summary"].className = "status-error";
    if (showToast) toast(issueText(errors[0]) || "Scenario validation failed.", "error");
    return { ok: false, result };
  } catch (error) {
    const detail =
      error instanceof Error && error.message
        ? error.message
        : "The local validation service did not respond.";
    dom["validation-summary"].textContent = `Validation unavailable · ${detail}`;
    dom["validation-summary"].className = "status-error";
    if (showToast) toast(detail, "error");
    return { ok: false, error };
  }
}

async function generateDumps() {
  if (!dom["generation-dialog"].open) dom["generation-dialog"].showModal();
  setGenerationState("working", "Preparing scenario…", "Validating and replaying local history.");
  dom["retry-generation"].hidden = true;
  try {
    const response = await fetch(API.generate, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/gzip, application/json" },
      body: JSON.stringify({
        scenario: scenarioForApi(),
        filename: `${safeFilename(scenario.name)}-state-dumps.tgz`,
      }),
    });
    if (!response.ok) {
      const message = await responseError(response);
      throw new Error(message);
    }
    const blob = await response.blob();
    const disposition = response.headers.get("Content-Disposition") || "";
    const match = disposition.match(/filename="?([^";]+)"?/i);
    const filename = match?.[1] || `${safeFilename(scenario.name)}-state-dumps.tgz`;
    downloadBlob(blob, filename);
    setGenerationState(
      "success",
      "State dump files generated",
      "Downloaded a bundle of node-local final snapshots and past logs. Authoring ground truth was excluded.",
    );
    dirty = false;
  } catch (error) {
    setGenerationState("error", "Generation failed", error.message);
    dom["retry-generation"].hidden = false;
  }
}

function setGenerationState(kind, title, message) {
  dom["generation-state"].className = `generation-state ${kind}`;
  dom["generation-state"].replaceChildren();
  const icon = document.createElement("span");
  if (kind === "working") {
    icon.className = "spinner";
    icon.setAttribute("aria-hidden", "true");
  } else {
    icon.className = `generation-symbol ${kind === "success" ? "status-ok" : "status-error"}`;
    icon.textContent = kind === "success" ? "✓" : "!";
  }
  const text = document.createElement("div");
  const strong = document.createElement("strong");
  strong.textContent = title;
  const paragraph = document.createElement("p");
  paragraph.textContent = message;
  text.append(strong, paragraph);
  dom["generation-state"].append(icon, text);
}

function scenarioForApi() {
  return toCanonicalProject();
}

function toCanonicalProject() {
  const media = canonicalMedia();
  const captureTimeMs = Math.max(
    scenario.duration_ms || 0,
    maxEventTime(scenario.events) + maximumPropagationHorizonMs() + 1,
  );
  scenario.capture_time_ns = Math.max(
    Math.round(captureTimeMs * 1_000_000),
    finiteNumber(scenario.capture_time_ns, 0),
  );
  return {
    schema_version: 1,
    schema_id: "state-dump-generator-scenario/v1",
    scenario_id: safeIdentifier(scenario.id || scenario.scenario_id, "untitled-scenario"),
    name: scenario.name || "Untitled scenario",
    seed: Math.max(0, Math.trunc(finiteNumber(scenario.seed, 1))),
    capture_time_ns: scenario.capture_time_ns,
    nodes: scenario.nodes
      .filter((node) => node.kind !== "shared-medium")
      .map((node) => ({
        node_id: safeIdentifier(node.id, makeId("node")),
        name: node.name,
        kind: node.kind,
        dump_enabled:
          typeof node.dump_enabled === "boolean"
            ? node.dump_enabled
            : node.kind === "router",
        position: {
          x: Math.round(node.position.x * 1000) / 1000,
          y: Math.round(node.position.y * 1000) / 1000,
        },
        site: node.site || "",
        profile: node.profile || "generic",
        clock: {
          offset_ns: Math.trunc(finiteNumber(node.clock?.offset_ns, 0)),
          uncertainty_ns: Math.max(
            0,
            Math.trunc(finiteNumber(node.clock?.uncertainty_ns, 0)),
          ),
        },
        initial_resources: Array.isArray(node.initial_resources)
          ? structuredClone(node.initial_resources)
          : [],
        notes: node.notes || "",
      })),
    media,
    events: [...scenario.events]
      .sort(eventSort)
      .map((event, index) => canonicalEvent(event, index)),
    metadata: {
      ...(isPlainObject(scenario.metadata) ? structuredClone(scenario.metadata) : {}),
      description: scenario.description || "",
      updated_at: scenario.updated_at || new Date().toISOString(),
      authoring: {
        editor: "state-dump-generator-web",
        duration_ms: captureTimeMs,
        propagation_defaults: structuredClone(
          scenario.defaults?.propagation || fallbackScenario().defaults.propagation,
        ),
      },
    },
  };
}

function canonicalMedia() {
  const mediumNodes = new Map(
    scenario.nodes
      .filter((node) => node.kind === "shared-medium")
      .map((node) => [node.id, node]),
  );
  const media = [];
  const usedIds = new Set();

  mediumNodes.forEach((mediumNode) => {
    const incident = scenario.physical_links.filter(
      (link) =>
        link.a.node_id === mediumNode.id || link.b.node_id === mediumNode.id,
    );
    const attachments = incident
      .map((link) => {
        const endpoint =
          link.a.node_id === mediumNode.id ? link.b : link.a;
        if (mediumNodes.has(endpoint.node_id)) return null;
        return canonicalAttachment(endpoint);
      })
      .filter(Boolean);
    const requestedId = mediumNode.medium_id || mediumNode.id;
    const mediumId = uniqueIdentifier(requestedId, usedIds, "medium");
    media.push({
      medium_id: mediumId,
      name: mediumNode.name,
      kind: mediumNode.medium_kind || "broadcast",
      state: mediumNode.initial_state || "up",
      attachments,
      position: {
        x: Math.round(mediumNode.position.x * 1000) / 1000,
        y: Math.round(mediumNode.position.y * 1000) / 1000,
      },
      ui_node_id: mediumNode.id,
      properties: isPlainObject(mediumNode.medium_properties)
        ? structuredClone(mediumNode.medium_properties)
        : {},
      notes: mediumNode.notes || "",
    });
  });

  scenario.physical_links
    .filter(
      (link) =>
        !mediumNodes.has(link.a.node_id) && !mediumNodes.has(link.b.node_id),
    )
    .forEach((link) => {
      const mediumId = uniqueIdentifier(
        link.source_medium_id || link.id,
        usedIds,
        "link",
      );
      media.push({
        medium_id: mediumId,
        name: link.name,
        kind: link.medium_kind || "point-to-point",
        state: link.initial_state || "up",
        attachments: [
          canonicalAttachment(link.a),
          canonicalAttachment(link.b),
        ],
        properties: isPlainObject(link.medium_properties)
          ? structuredClone(link.medium_properties)
          : {},
        notes: link.notes || "",
      });
    });
  return media;
}

function canonicalAttachment(endpoint) {
  const attachment = {
    node_id: safeIdentifier(endpoint.node_id, "unknown-node"),
    port_id: safeIdentifier(endpoint.port || endpoint.port_id, "auto"),
    properties: isPlainObject(endpoint.properties)
      ? structuredClone(endpoint.properties)
      : {},
  };
  if (endpoint.resource_id || endpoint.local_resource_id) {
    attachment.resource_id = safeIdentifier(
      endpoint.resource_id || endpoint.local_resource_id,
      `interface:${attachment.port_id}`,
    );
  }
  if (endpoint.observed_state !== undefined) {
    attachment.observed_state = String(endpoint.observed_state);
  }
  return attachment;
}

function canonicalEvent(event, order) {
  const physical =
    event.scope === "physical" ||
    event.target_type === "physical-link" ||
    ["physical-link-state", "link-state", "medium-state"].includes(event.kind);
  const properties = isPlainObject(event.state_patch)
    ? structuredClone(event.state_patch)
    : {};
  const propagation = canonicalPropagation(event.propagation);
  const base = {
    event_id: safeIdentifier(event.id, `event-${order + 1}`),
    timestamp_ns: Math.max(0, Math.round(event.time_ms * 1_000_000)),
    order,
    kind: event.kind || "status",
    outcome: event.outcome || "ok",
    propagation,
  };
  if (physical) {
    const targetId = canonicalMediumIdForTarget(event.target_id);
    return {
      ...base,
      target_type: "medium",
      target_id: targetId,
      medium_id: targetId,
      status: stringValue(
        event.status ??
          properties.state ??
          properties.oper_status,
        "unknown",
      ),
      properties,
      message: event.log_text || "",
    };
  }
  const value = {
    ...base,
    node_id: safeIdentifier(event.node_id, ""),
    resource_id: event.subject || event.resource_id || event.target_id || `event:${event.id}`,
    resource_type:
      event.resource_type ||
      event.target_type ||
      (event.kind.startsWith("resource-") ? "resource" : event.kind),
    operation: event.action || event.operation || event.kind,
    properties,
    message: event.log_text || event.message || "",
    update_snapshot: event.update_final_state !== false,
  };
  const status =
    event.status ??
    properties.status ??
    properties.oper_status ??
    properties.state ??
    properties.condition;
  if (status !== undefined && !isPlainObject(status) && !Array.isArray(status)) {
    value.status = String(status);
  }
  return value;
}

function canonicalPropagation(value) {
  if (!value || typeof value !== "object") return {};
  const targets = Array.isArray(value.targets)
    ? value.targets
    : Array.isArray(value.target_node_ids)
      ? value.target_node_ids
      : [];
  const result = {
    mode: value.mode || "best-effort",
    delay_ms: Math.max(
      0,
      Math.round(finiteNumber(value.delay_ms ?? value.base_delay_ms, 0)),
    ),
    jitter_ms: Math.max(0, Math.round(finiteNumber(value.jitter_ms, 0))),
    target_mode: value.target_mode || value.targets_mode || "neighbors",
    targets: targets.map((target) => safeIdentifier(target, "")).filter(Boolean),
    outcome: value.outcome || value.intended_outcome || "success",
    cadence: value.cadence || "parallel",
  };
  for (const key of [
    "materialized",
    "generated",
    "parent_event_id",
    "authored_mode",
  ]) {
    if (value[key] !== undefined) result[key] = structuredClone(value[key]);
  }
  return result;
}

function canonicalMediumIdForTarget(targetId) {
  const node = nodeById(targetId);
  if (node?.kind === "shared-medium") return safeIdentifier(node.medium_id || node.id, targetId);
  const link = linkById(targetId);
  if (link) {
    const sharedEndpoint = [link.a.node_id, link.b.node_id]
      .map(nodeById)
      .find((candidate) => candidate?.kind === "shared-medium");
    if (sharedEndpoint) {
      return safeIdentifier(
        sharedEndpoint.medium_id || sharedEndpoint.id,
        targetId,
      );
    }
    return safeIdentifier(link.source_medium_id || link.id, targetId);
  }
  return safeIdentifier(targetId, targetId || "unknown-medium");
}

function maximumPropagationHorizonMs() {
  return scenario.events.reduce((maximum, event) => {
    const propagation = event.propagation;
    if (!propagation || typeof propagation !== "object") return maximum;
    const delay = Math.max(
      0,
      finiteNumber(propagation.delay_ms ?? propagation.base_delay_ms, 0),
    );
    const jitter = Math.max(0, finiteNumber(propagation.jitter_ms, 0));
    return Math.max(maximum, delay + jitter);
  }, 0);
}

function safeIdentifier(value, fallback) {
  const text = stringValue(value, fallback)
    .trim()
    .replace(/[^A-Za-z0-9_.:/-]+/g, "-")
    .slice(0, 256);
  return text || fallback;
}

function uniqueIdentifier(value, used, fallbackPrefix) {
  const base = safeIdentifier(value, makeId(fallbackPrefix));
  let candidate = base;
  let suffix = 2;
  while (used.has(candidate)) {
    candidate = `${base.slice(0, 245)}-${suffix}`;
    suffix += 1;
  }
  used.add(candidate);
  return candidate;
}

async function apiJson(url, payload, allowErrorPayload = false) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(payload),
  });
  let result;
  try {
    result = await response.json();
  } catch {
    throw new Error(`The generator returned HTTP ${response.status}.`);
  }
  if (!response.ok && !allowErrorPayload) {
    throw new Error(result.error || issueText(result.errors?.[0]) || `HTTP ${response.status}`);
  }
  return result;
}

async function responseError(response) {
  try {
    const payload = await response.json();
    return payload.error || issueText(payload.errors?.[0]) || `HTTP ${response.status}`;
  } catch {
    return `The generator returned HTTP ${response.status}.`;
  }
}

function issueText(issue) {
  if (typeof issue === "string") return issue;
  return issue?.message || issue?.detail || "";
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function safeFilename(value) {
  return (
    stringValue(value, "scenario")
      .trim()
      .replace(/[^a-zA-Z0-9._-]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 72) || "scenario"
  );
}

function toast(message, kind = "") {
  const item = document.createElement("div");
  item.className = `toast ${kind}`;
  item.textContent = message;
  dom["toast-region"].append(item);
  setTimeout(() => item.remove(), 4200);
}

function nodeById(id) {
  return scenario.nodes.find((node) => node.id === id);
}

function linkById(id) {
  return scenario.physical_links.find((link) => link.id === id);
}

function eventById(id) {
  return scenario.events.find((event) => event.id === id);
}

function dumpNodes() {
  return scenario.nodes.filter(
    (node) => node.kind !== "shared-medium" && node.dump_enabled !== false,
  );
}

function neighborsOf(nodeId) {
  const ids = new Set();
  scenario.physical_links.forEach((link) => {
    if (link.a.node_id === nodeId) ids.add(link.b.node_id);
    if (link.b.node_id === nodeId) ids.add(link.a.node_id);
  });
  return [...ids].map(nodeById).filter(Boolean);
}

function propagationNeighbors(nodeId) {
  const output = new Map();
  neighborsOf(nodeId).forEach((neighbor) => {
    if (neighbor.kind === "shared-medium") {
      neighborsOf(neighbor.id).forEach((participant) => {
        if (
          participant.id !== nodeId &&
          participant.kind !== "shared-medium" &&
          participant.dump_enabled !== false
        ) {
          output.set(participant.id, participant);
        }
      });
    } else if (neighbor.dump_enabled !== false) {
      output.set(neighbor.id, neighbor);
    }
  });
  return [...output.values()];
}

function physicalTargetNodes(link, targetId) {
  if (link) {
    const endpoints = [nodeById(link.a.node_id), nodeById(link.b.node_id)].filter(Boolean);
    const mediumNode = endpoints.find((node) => node.kind === "shared-medium");
    if (mediumNode) {
      return neighborsOf(mediumNode.id).filter(
        (node) => node.kind !== "shared-medium" && node.dump_enabled !== false,
      );
    }
    return endpoints.filter(
      (node) => node.kind !== "shared-medium" && node.dump_enabled !== false,
    );
  }
  const mediumNode = scenario.nodes.find(
    (node) =>
      node.kind === "shared-medium" &&
      (node.id === targetId || node.medium_id === targetId),
  );
  return mediumNode
    ? neighborsOf(mediumNode.id).filter(
        (node) => node.kind !== "shared-medium" && node.dump_enabled !== false,
      )
    : [];
}

function localPhysicalObservation(nodeId, targetId) {
  const directLink = linkById(targetId);
  let endpoint = null;
  let mediumNode = null;
  if (directLink) {
    endpoint = [directLink.a, directLink.b].find(
      (candidate) => candidate.node_id === nodeId,
    );
    mediumNode = [directLink.a.node_id, directLink.b.node_id]
      .map(nodeById)
      .find((node) => node?.kind === "shared-medium");
  }
  if (!endpoint) {
    mediumNode ||= scenario.nodes.find(
      (node) =>
        node.kind === "shared-medium" &&
        (node.id === targetId || node.medium_id === targetId),
    );
    const incidentLink = scenario.physical_links.find(
      (candidate) =>
        mediumNode &&
        [candidate.a.node_id, candidate.b.node_id].includes(mediumNode.id) &&
        [candidate.a.node_id, candidate.b.node_id].includes(nodeId),
    );
    if (incidentLink) {
      endpoint = [incidentLink.a, incidentLink.b].find(
        (candidate) => candidate.node_id === nodeId,
      );
    }
  }
  if (!endpoint) return null;
  const port = stringValue(endpoint.port || endpoint.port_id, "unknown-port");
  return {
    port,
    resourceId: port.includes(":") ? port : `interface:${port}`,
    resourceType: "interface",
  };
}

function maxEventTime(events) {
  return events.reduce((maximum, event) => Math.max(maximum, finiteNumber(event.time_ms, 0)), 0);
}

function eventSort(left, right) {
  return left.time_ms - right.time_ms || left.id.localeCompare(right.id);
}

function formatSeconds(milliseconds) {
  const seconds = Number(milliseconds) / 1000;
  if (seconds >= 1000) return seconds.toFixed(1);
  if (seconds >= 10) return seconds.toFixed(2).replace(/0+$/, "").replace(/\.$/, "");
  return seconds.toFixed(3).replace(/0+$/, "").replace(/\.$/, "");
}

function optionValueOr(select, value, fallback) {
  return [...select.options].some((option) => option.value === value) ? value : fallback;
}

function clamp(value, minimum, maximum) {
  return Math.min(maximum, Math.max(minimum, value));
}
