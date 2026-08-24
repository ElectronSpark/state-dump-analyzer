// Framework-free helpers shared by both core browser workspaces.
//
// Keep this module limited to generic presentation and transport behavior.
// Node, topology, route, and plug-in semantics belong in their respective
// entry points.

export const byId = (id) => document.getElementById(id);

export function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

export function safeClass(value) {
  return String(value || "unknown").toLowerCase().replace(/[^a-z0-9_-]+/g, "-");
}

export function titleCase(value) {
  return String(value ?? "unknown")
    .replaceAll("_", " ")
    .replaceAll("-", " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

export function toBigInt(value, fallback = 0n) {
  if (typeof value === "bigint") return value;
  if (value === null || value === undefined || value === "") return fallback;
  try {
    return BigInt(String(value).split(".")[0]);
  } catch (_error) {
    return fallback;
  }
}

export async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  if (!response.ok) {
    let message = `${response.status} ${response.statusText}`;
    try {
      const body = await response.json();
      message = body.detail || body.error?.message || message;
    } catch (_error) {
      // Keep the HTTP status when the body is not JSON.
    }
    throw new Error(message);
  }
  return response.json();
}

const ANALYSIS_LOAD_STATES = new Set(["waiting", "running", "ready", "failed"]);
const ANALYSIS_LOAD_STAGE_LABELS = Object.freeze({
  starting: "Starting analysis",
  opening_runtime: "Opening the analysis runtime",
  inventorying: "Reading dump inventory",
  probing: "Selecting compatible plug-ins",
  locating_inputs: "Locating dump records",
  parsing: "Parsing dump files",
  normalizing: "Normalizing router state",
  loading_revision: "Loading node revision",
  indexing: "Building query indexes",
});

function analysisLoadCount(value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : null;
}

export function normalizeAnalysisLoadSnapshot(value) {
  const source = value && typeof value === "object" ? value : {};
  const state = ANALYSIS_LOAD_STATES.has(source.state) ? source.state : "waiting";
  const stage = Object.hasOwn(ANALYSIS_LOAD_STAGE_LABELS, source.stage)
    ? source.stage
    : null;
  const completed = analysisLoadCount(source.completed);
  const total = analysisLoadCount(source.total);
  const determinate = source.determinate === true
    && completed !== null
    && total !== null
    && total > 0
    && completed <= total;
  return Object.freeze({
    state,
    stage,
    completed: determinate ? completed : null,
    total: determinate ? total : null,
    determinate,
    recordsProcessed: analysisLoadCount(source.records_processed)
      ?? analysisLoadCount(source.recordsProcessed)
      ?? 0,
    activeOperations: analysisLoadCount(source.active_operations)
      ?? analysisLoadCount(source.activeOperations)
      ?? 0,
    sequence: analysisLoadCount(source.sequence) ?? 0,
    errorCode: typeof source.error_code === "string"
      ? source.error_code
      : typeof source.errorCode === "string" ? source.errorCode : "",
  });
}

export function analysisLoadProgressPresentation(value) {
  const snapshot = normalizeAnalysisLoadSnapshot(value);
  const visible = snapshot.state === "running" || snapshot.state === "failed";
  const title = snapshot.state === "failed"
    ? "Dump loading failed"
    : ANALYSIS_LOAD_STAGE_LABELS[snapshot.stage] || "Preparing analysis";
  const details = [];
  if (snapshot.state === "failed") {
    details.push("The analyzer could not finish preparing the requested dump data.");
  } else if (snapshot.determinate) {
    details.push(`${snapshot.completed.toLocaleString()} of ${snapshot.total.toLocaleString()}`);
  } else if (snapshot.recordsProcessed > 0) {
    details.push(`${snapshot.recordsProcessed.toLocaleString()} records processed`);
  } else {
    details.push("Waiting for the next bounded progress update");
  }
  if (snapshot.activeOperations > 1) {
    details.push(`${snapshot.activeOperations.toLocaleString()} load operations active`);
  }
  return Object.freeze({
    snapshot,
    visible,
    busy: snapshot.state === "running",
    failed: snapshot.state === "failed",
    title,
    detail: details.join(" · "),
  });
}

function analysisLoadProgressPresentationKey(presentation) {
  const { snapshot } = presentation;
  return JSON.stringify([
    snapshot.state,
    presentation.visible,
    presentation.busy,
    presentation.failed,
    presentation.title,
    presentation.detail,
    snapshot.determinate,
    snapshot.completed,
    snapshot.total,
  ]);
}

export function renderAnalysisLoadProgress(root, value) {
  if (!root) return;
  const presentation = analysisLoadProgressPresentation(value);
  const { snapshot } = presentation;
  const hidden = !presentation.visible;
  if (root.hidden !== hidden) root.hidden = hidden;
  if (root.dataset.state !== snapshot.state) root.dataset.state = snapshot.state;
  const ariaBusy = String(presentation.busy);
  if (root.getAttribute("aria-busy") !== ariaBusy) {
    root.setAttribute("aria-busy", ariaBusy);
  }
  const title = root.querySelector("[data-analysis-load-title]");
  const detail = root.querySelector("[data-analysis-load-detail]");
  const progress = root.querySelector("progress");
  if (title && title.textContent !== presentation.title) {
    title.textContent = presentation.title;
  }
  if (detail && detail.textContent !== presentation.detail) {
    detail.textContent = presentation.detail;
  }
  if (!progress) return;
  if (progress.hidden !== presentation.failed) progress.hidden = presentation.failed;
  if (progress.getAttribute("aria-label") !== presentation.title) {
    progress.setAttribute("aria-label", presentation.title);
  }
  if (snapshot.determinate) {
    if (progress.max !== snapshot.total) progress.max = snapshot.total;
    if (progress.value !== snapshot.completed) progress.value = snapshot.completed;
    const ariaValueText = `${snapshot.completed.toLocaleString()} of ${snapshot.total.toLocaleString()}`;
    if (progress.getAttribute("aria-valuetext") !== ariaValueText) {
      progress.setAttribute("aria-valuetext", ariaValueText);
    }
  } else {
    if (progress.max !== 1) progress.max = 1;
    if (progress.hasAttribute("value")) progress.removeAttribute("value");
    if (progress.hasAttribute("aria-valuetext")) {
      progress.removeAttribute("aria-valuetext");
    }
  }
}

export function createAnalysisLoadProgressController({
  fetchSnapshot,
  render,
  intervalMs = 350,
  setTimer = (callback, delay) => window.setTimeout(callback, delay),
  clearTimer = (timer) => window.clearTimeout(timer),
} = {}) {
  if (typeof fetchSnapshot !== "function") throw new TypeError("fetchSnapshot must be a function");
  if (typeof render !== "function") throw new TypeError("render must be a function");
  if (!Number.isSafeInteger(intervalMs) || intervalMs < 50) {
    throw new TypeError("intervalMs must be an integer of at least 50 milliseconds");
  }
  let generation = 0;
  let timer = null;
  let disposed = false;
  let lastPresentationKey = null;
  const leases = new Set();

  const cancelTimer = () => {
    if (timer === null) return;
    clearTimer(timer);
    timer = null;
  };
  const schedule = (selectedGeneration) => {
    cancelTimer();
    timer = setTimer(() => {
      timer = null;
      void poll(selectedGeneration);
    }, intervalMs);
  };
  const poll = async (selectedGeneration) => {
    let snapshot;
    try {
      snapshot = normalizeAnalysisLoadSnapshot(await fetchSnapshot());
    } catch (_error) {
      snapshot = normalizeAnalysisLoadSnapshot(null);
    }
    if (disposed || selectedGeneration !== generation) return;
    const presentationKey = analysisLoadProgressPresentationKey(
      analysisLoadProgressPresentation(snapshot),
    );
    if (presentationKey !== lastPresentationKey) {
      render(snapshot);
      lastPresentationKey = presentationKey;
    }
    if (leases.size > 0 || snapshot.state === "running") {
      schedule(selectedGeneration);
    }
  };

  return Object.freeze({
    begin() {
      if (disposed) throw new Error("analysis load progress controller is disposed");
      const lease = Symbol("analysis-load-progress");
      leases.add(lease);
      if (leases.size === 1) {
        generation += 1;
        cancelTimer();
        void poll(generation);
      }
      return lease;
    },
    end(lease) {
      if (!leases.delete(lease) || disposed || leases.size > 0) return;
      generation += 1;
      cancelTimer();
      void poll(generation);
    },
    refresh() {
      if (disposed) return;
      generation += 1;
      cancelTimer();
      void poll(generation);
    },
    dispose() {
      disposed = true;
      generation += 1;
      leases.clear();
      cancelTimer();
    },
  });
}
