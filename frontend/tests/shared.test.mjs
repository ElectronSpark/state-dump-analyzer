import assert from "node:assert/strict";
import test from "node:test";

import {
  analysisLoadProgressPresentation,
  createAnalysisLoadProgressController,
  escapeHtml,
  normalizeAnalysisLoadSnapshot,
  renderAnalysisLoadProgress,
  safeClass,
  titleCase,
  toBigInt,
} from "../assets/shared.js";

test("escapeHtml makes plug-in text inert in generated markup", () => {
  assert.equal(
    escapeHtml('<img src=x onerror="alert(1)">'),
    "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;",
  );
});

test("safeClass admits only the class-token subset", () => {
  assert.equal(safeClass('Healthy" onclick="alert(1)'), "healthy-onclick-alert-1-");
});

test("titleCase preserves readable labels without interpreting markup", () => {
  assert.equal(titleCase("best_effort-route"), "Best Effort Route");
});

test("toBigInt preserves nanosecond integers beyond Number precision", () => {
  assert.equal(toBigInt("1759680625001000000"), 1759680625001000000n);
  assert.equal(toBigInt("not-a-number", 9n), 9n);
});

test("analysis load snapshots accept only bounded determinate progress", () => {
  const snapshot = normalizeAnalysisLoadSnapshot({
    state: "running",
    stage: "parsing",
    completed: 25,
    total: 100,
    determinate: true,
    records_processed: 1200,
    active_operations: 2,
    sequence: 7,
  });
  assert.deepEqual(snapshot, {
    state: "running",
    stage: "parsing",
    completed: 25,
    total: 100,
    determinate: true,
    recordsProcessed: 1200,
    activeOperations: 2,
    sequence: 7,
    errorCode: "",
  });

  const invalid = normalizeAnalysisLoadSnapshot({
    state: "running",
    stage: "plugin-private-stage",
    completed: 101,
    total: 100,
    determinate: true,
  });
  assert.equal(invalid.stage, null);
  assert.equal(invalid.determinate, false);
  assert.equal(invalid.completed, null);
  assert.equal(invalid.total, null);
  assert.deepEqual(normalizeAnalysisLoadSnapshot(snapshot), snapshot);
});

test("analysis load presentation is visible only while running or after failure", () => {
  const running = analysisLoadProgressPresentation({
    state: "running",
    stage: "normalizing",
    records_processed: 9000,
    active_operations: 1,
  });
  assert.equal(running.visible, true);
  assert.equal(running.busy, true);
  assert.equal(running.title, "Normalizing router state");
  assert.match(running.detail, /9,000 records processed/);

  assert.equal(analysisLoadProgressPresentation({ state: "waiting" }).visible, false);
  assert.equal(analysisLoadProgressPresentation({ state: "ready" }).visible, false);
  const failed = analysisLoadProgressPresentation({ state: "failed", stage: "parsing" });
  assert.equal(failed.visible, true);
  assert.equal(failed.busy, false);
  assert.equal(failed.title, "Dump loading failed");
});

test("archive, provider and query work has distinct indeterminate progress", () => {
  for (const [stage, title] of Object.entries({
    reading_archive: "Reading archive contents",
    validating_providers: "Validating providers",
    reconstructing_topology: "Reconstructing topology",
    querying_route_tables: "Loading route tables",
    tracing_routes: "Tracing routes",
  })) {
    const presentation = analysisLoadProgressPresentation({ state: "running", stage });
    assert.equal(presentation.title, title);
    assert.equal(presentation.snapshot.stage, stage);
    assert.equal(presentation.snapshot.determinate, false);
    assert.equal(presentation.busy, true);
  }
});

test("analysis load renderer leaves an unchanged live-region presentation untouched", () => {
  const mutations = [];
  const trackProperty = (target, name, initialValue) => {
    let value = initialValue;
    Object.defineProperty(target, name, {
      configurable: true,
      get: () => value,
      set: (nextValue) => {
        mutations.push(`${name}:${nextValue}`);
        value = nextValue;
      },
    });
  };
  const trackAttributes = (target, initialValues = {}) => {
    const attributes = new Map(Object.entries(initialValues));
    target.getAttribute = (name) => attributes.get(name) ?? null;
    target.hasAttribute = (name) => attributes.has(name);
    target.setAttribute = (name, value) => {
      mutations.push(`${name}:${value}`);
      attributes.set(name, String(value));
    };
    target.removeAttribute = (name) => {
      mutations.push(`${name}:removed`);
      attributes.delete(name);
    };
  };

  const title = {};
  const detail = {};
  const progress = {};
  const dataset = {};
  const root = {
    dataset,
    querySelector: (selector) => ({
      "[data-analysis-load-title]": title,
      "[data-analysis-load-detail]": detail,
      progress,
    })[selector] ?? null,
  };
  trackProperty(root, "hidden", true);
  trackProperty(dataset, "state", undefined);
  trackProperty(title, "textContent", "Preparing analysis");
  trackProperty(detail, "textContent", "Waiting for the first progress update");
  trackProperty(progress, "hidden", false);
  trackProperty(progress, "max", 1);
  trackProperty(progress, "value", 0);
  trackAttributes(root, { "aria-busy": "false" });
  trackAttributes(progress, { "aria-label": "Preparing analysis" });

  const snapshot = {
    state: "running",
    stage: "parsing",
    completed: 2,
    total: 10,
    determinate: true,
    sequence: 1,
  };
  renderAnalysisLoadProgress(root, snapshot);
  const initialMutationCount = mutations.length;
  assert.ok(initialMutationCount > 0);

  renderAnalysisLoadProgress(root, { ...snapshot, sequence: 2 });
  assert.equal(mutations.length, initialMutationCount);

  renderAnalysisLoadProgress(root, { ...snapshot, completed: 3, sequence: 3 });
  assert.ok(mutations.length > initialMutationCount);
});

test("analysis load controller discards stale poll generations", async () => {
  const pending = [];
  const rendered = [];
  const fetchSnapshot = () => new Promise((resolve) => pending.push(resolve));
  const controller = createAnalysisLoadProgressController({
    fetchSnapshot,
    render: (snapshot) => rendered.push(snapshot.state),
    setTimer: () => 1,
    clearTimer: () => {},
  });

  const lease = controller.begin();
  controller.end(lease);
  assert.equal(pending.length, 2);
  pending[0]({ state: "running", stage: "parsing" });
  await Promise.resolve();
  assert.deepEqual(rendered, []);
  pending[1]({ state: "ready", stage: "indexing" });
  await Promise.resolve();
  assert.deepEqual(rendered, ["ready"]);
});

test("analysis load controller keeps polling a reported running operation", async () => {
  const timers = [];
  const rendered = [];
  const responses = [
    { state: "running", stage: "parsing" },
    { state: "ready", stage: "indexing" },
  ];
  const controller = createAnalysisLoadProgressController({
    fetchSnapshot: async () => responses.shift() || { state: "ready" },
    render: (snapshot) => rendered.push(snapshot.state),
    setTimer: (callback) => {
      timers.push(callback);
      return timers.length;
    },
    clearTimer: () => {},
  });

  const lease = controller.begin();
  await Promise.resolve();
  assert.deepEqual(rendered, ["running"]);
  controller.end(lease);
  await Promise.resolve();
  assert.deepEqual(rendered, ["running", "ready"]);
});

test("analysis load controller keeps polling without repeating unchanged presentations", async () => {
  const timers = [];
  const rendered = [];
  const responses = [
    { state: "running", stage: "parsing", records_processed: 10, sequence: 1 },
    { state: "running", stage: "parsing", records_processed: 10, sequence: 2 },
    { state: "running", stage: "parsing", records_processed: 11, sequence: 3 },
    { state: "ready", stage: "indexing", records_processed: 11, sequence: 4 },
  ];
  const controller = createAnalysisLoadProgressController({
    fetchSnapshot: async () => responses.shift() || { state: "ready", stage: "indexing" },
    render: (snapshot) => rendered.push(snapshot.sequence),
    setTimer: (callback) => {
      timers.push(callback);
      return timers.length;
    },
    clearTimer: () => {},
  });

  controller.begin();
  await Promise.resolve();
  assert.deepEqual(rendered, [1]);
  assert.equal(timers.length, 1);

  timers.shift()();
  await Promise.resolve();
  assert.deepEqual(rendered, [1]);
  assert.equal(timers.length, 1);

  timers.shift()();
  await Promise.resolve();
  assert.deepEqual(rendered, [1, 3]);
  assert.equal(timers.length, 1);

  timers.shift()();
  await Promise.resolve();
  assert.deepEqual(rendered, [1, 3, 4]);
  controller.dispose();
});
