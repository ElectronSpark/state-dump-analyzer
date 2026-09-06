import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const APP_SOURCE = readFileSync(new URL("../assets/app.js", import.meta.url), "utf8");
const start = APP_SOURCE.indexOf("function bindTimelineStickyHeader(");
const end = APP_SOURCE.indexOf("\nfunction bindControls(", start);
assert.ok(start >= 0 && end > start, "app.js must define the sticky-header binding before bindControls");
const BINDING_SOURCE = APP_SOURCE.slice(start, end);

function stickyHarness({ height = 68, hasObserver = true, hasFrame = true, hasTopbar = true } = {}) {
  const writes = [];
  const listeners = new Map();
  const observers = [];
  let measuredHeight = height;
  let measurements = 0;
  const frame = { style: { setProperty: (name, value) => writes.push({ name, value }) } };
  const topbar = { getBoundingClientRect: () => {
    measurements += 1;
    return { height: measuredHeight };
  } };
  const window = {
    addEventListener(type, callback, options) {
      if (!listeners.has(type)) listeners.set(type, []);
      listeners.get(type).push({ callback, options });
    },
  };
  if (hasObserver) {
    window.ResizeObserver = class {
      constructor(callback) {
        this.callback = callback;
        this.observed = [];
        this.disconnections = 0;
        observers.push(this);
      }

      observe(element) { this.observed.push(element); }
      disconnect() { this.disconnections += 1; }
    };
  }
  const bind = new Function("byId", "document", "window", `${BINDING_SOURCE}\nreturn bindTimelineStickyHeader;`)(
    (id) => id === "timeline-frame" && hasFrame ? frame : null,
    { querySelector: (selector) => selector === ".topbar" && hasTopbar ? topbar : null },
    window,
  );
  return {
    bind, writes, listeners, observers, frame, topbar,
    measurements: () => measurements,
    setHeight: (value) => { measuredHeight = value; },
    emit(type) { for (const listener of listeners.get(type) || []) listener.callback({ type }); },
  };
}

test("sticky header immediately uses the measured topbar border-box height", () => {
  const harness = stickyHarness({ height: 68.5 });
  harness.bind();
  assert.deepEqual(harness.writes, [{ name: "--timeline-sticky-top", value: "68.5px" }]);
  assert.equal(harness.measurements(), 1);
  assert.equal(harness.observers.length, 1);
  assert.deepEqual(harness.observers[0].observed, [harness.topbar]);
});

test("topbar observation updates the offset after wrapping and responsive height changes", () => {
  const harness = stickyHarness();
  harness.bind();
  for (const height of [116, 60, 72.25]) {
    harness.setHeight(height);
    harness.observers[0].callback([]);
    assert.deepEqual(harness.writes.at(-1), { name: "--timeline-sticky-top", value: `${height}px` });
  }
  assert.equal(harness.measurements(), 4);
  assert.equal(harness.observers.length, 1);
});

test("pagehide disconnects observation and pageshow restores it with a fresh measurement", () => {
  const harness = stickyHarness();
  harness.bind();
  const observer = harness.observers[0];
  for (const height of [104, 60]) {
    const previousMeasurements = harness.measurements();
    harness.emit("pagehide");
    assert.equal(harness.measurements(), previousMeasurements);
    harness.setHeight(height);
    harness.emit("pageshow");
    assert.equal(harness.measurements(), previousMeasurements + 1);
    assert.deepEqual(harness.writes.at(-1), { name: "--timeline-sticky-top", value: `${height}px` });
  }
  assert.equal(observer.disconnections, 2);
  assert.deepEqual(observer.observed, [harness.topbar, harness.topbar, harness.topbar]);
  assert.equal(harness.observers.length, 1);
  assert.equal(harness.listeners.get("pagehide").length, 1);
  assert.equal(harness.listeners.get("pageshow").length, 1);
});

test("without ResizeObserver a passive resize listener updates the measured offset", () => {
  const harness = stickyHarness({ hasObserver: false });
  harness.bind();
  assert.deepEqual(harness.writes, [{ name: "--timeline-sticky-top", value: "68px" }]);
  assert.equal(harness.observers.length, 0);
  assert.deepEqual([...harness.listeners.keys()], ["resize"]);
  assert.deepEqual(harness.listeners.get("resize")[0].options, { passive: true });
  harness.setHeight(92);
  harness.emit("resize");
  assert.deepEqual(harness.writes.at(-1), { name: "--timeline-sticky-top", value: "92px" });
});

test("missing timeline or topbar elements make sticky-header binding a no-op", () => {
  for (const options of [{ hasFrame: false }, { hasTopbar: false }, { hasFrame: false, hasTopbar: false }]) {
    const harness = stickyHarness(options);
    assert.doesNotThrow(harness.bind);
    assert.deepEqual(harness.writes, []);
    assert.equal(harness.measurements(), 0);
    assert.equal(harness.observers.length, 0);
    assert.equal(harness.listeners.size, 0);
  }
});

test("CSS owns page scrolling without scroll listeners or timeline-size observation", () => {
  for (const hasObserver of [true, false]) {
    const harness = stickyHarness({ hasObserver });
    harness.bind();
    assert.equal(harness.listeners.has("scroll"), false);
    const before = harness.measurements();
    harness.emit("scroll");
    assert.equal(harness.measurements(), before);
    assert.equal(harness.writes.length, 1);
    if (hasObserver) {
      assert.deepEqual([...harness.listeners.keys()].sort(), ["pagehide", "pageshow"]);
      assert.deepEqual(harness.observers[0].observed, [harness.topbar]);
    }
  }
});
