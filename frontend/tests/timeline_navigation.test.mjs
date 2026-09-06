import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { timelineTimeAtRatio } from "../assets/timeline_viewport.js";

const APP_SOURCE = readFileSync(new URL("../assets/app.js", import.meta.url), "utf8");

function functionSource(name) {
  // Top-level declarations begin in column zero. Use the next declaration as
  // the boundary, not the first opening brace: destructured/default arguments
  // and nested callbacks both contain braces before the function is complete.
  const declaration = new RegExp(`^(?:async )?function ${name}\\(`, "m");
  const match = declaration.exec(APP_SOURCE);
  assert.ok(match, `app.js must define ${name}()`);
  const remainder = APP_SOURCE.slice(match.index + match[0].length);
  const next = /^(?:async )?function [A-Za-z_$][\w$]*\(/m.exec(remainder);
  assert.ok(next, `${name}() must have a following top-level declaration`);
  return APP_SOURCE.slice(match.index, match.index + match[0].length + next.index);
}

function navigationHarness(overrides = {}) {
  const state = {
    viewStartNs: 0n,
    viewEndNs: 10_000n,
    timelineWindowStartNs: 4_000n,
    timelineWindowEndNs: 5_000n,
    zoom: 10,
    cursorSelected: true,
    cursorNs: 4_500n,
    rangeStartNs: 4_200n,
    rangeEndNs: 4_800n,
    selectedResourceId: "resource-1",
    selectedEventUid: "event-1",
    laneMode: "explicit",
    explicitLaneIds: new Set(["resource-1", "resource-3"]),
    hiddenTimelineResourceIds: new Set(["resource-2"]),
    activeLayers: new Set(["network"]),
    ...overrides,
  };
  const calls = [];
  const snapshot = () => ({
    startNs: state.timelineWindowStartNs,
    endNs: state.timelineWindowEndNs,
    zoom: state.zoom,
  });
  const factory = new Function(
    "state", "timelineTimeAtRatio", "timelinePhysicalTrackWidth",
    "cancelScheduledTimelineZoom", "rememberTimelineView",
    "invalidatePendingTimelineWindowRequest", "renderTimeline",
    "scheduleTimelineWindowRefresh",
    `"use strict";
    ${functionSource("timelineWindowBounds")}
    ${functionSource("panTimelineViewport")}
    ${functionSource("panTimelineViewportByPixels")}
    return { panTimelineViewport, panTimelineViewportByPixels };`,
  );
  const api = factory(
    state,
    timelineTimeAtRatio,
    () => 1_000,
    (options) => calls.push({ kind: "cancel", options }),
    () => calls.push({ kind: "history", ...snapshot() }),
    () => calls.push({ kind: "invalidate" }),
    () => calls.push({ kind: "render", ...snapshot() }),
    () => calls.push({ kind: "refresh", ...snapshot() }),
  );
  return { api, state, calls };
}

test("earlier/later commands pan the logical window in opposite directions", () => {
  const harness = navigationHarness();
  const step = timelineTimeAtRatio({ ratio: 0.1, startNs: 0n, endNs: 1_000n });
  assert.ok(step > 0n);

  assert.equal(harness.api.panTimelineViewport(-1), true);
  assert.equal(harness.state.timelineWindowStartNs, 4_000n - step);
  assert.equal(harness.state.timelineWindowEndNs, 5_000n - step);
  assert.equal(harness.api.panTimelineViewport(1), true);
  assert.equal(harness.state.timelineWindowStartNs, 4_000n);
  assert.equal(harness.state.timelineWindowEndNs, 5_000n);
});

test("pan clamps both capture edges without changing the window duration", () => {
  const earlier = navigationHarness({ timelineWindowStartNs: 100n, timelineWindowEndNs: 1_100n });
  assert.equal(earlier.api.panTimelineViewportByPixels(-500), true);
  assert.equal(earlier.state.timelineWindowStartNs, 0n);
  assert.equal(earlier.state.timelineWindowEndNs, 1_000n);

  const later = navigationHarness({ timelineWindowStartNs: 8_900n, timelineWindowEndNs: 9_900n });
  assert.equal(later.api.panTimelineViewportByPixels(500), true);
  assert.equal(later.state.timelineWindowStartNs, 9_000n);
  assert.equal(later.state.timelineWindowEndNs, 10_000n);
});

test("capture-edge and full-fit pan attempts do not render or create history", () => {
  for (const [startNs, endNs, direction] of [
    [0n, 1_000n, -1],
    [9_000n, 10_000n, 1],
    [0n, 10_000n, -1],
    [0n, 10_000n, 1],
  ]) {
    const harness = navigationHarness({ timelineWindowStartNs: startNs, timelineWindowEndNs: endNs });
    assert.equal(harness.api.panTimelineViewport(direction), false);
    assert.equal(harness.state.timelineWindowStartNs, startNs);
    assert.equal(harness.state.timelineWindowEndNs, endNs);
    assert.deepEqual(harness.calls, [{ kind: "cancel", options: { commitHistory: true } }]);
  }
});

test("pan preserves exact absolute BigInt coordinates beyond Number precision", () => {
  const base = 1n << 80n;
  const harness = navigationHarness({
    viewStartNs: base,
    viewEndNs: base + 10_000n,
    timelineWindowStartNs: base + 4_000n,
    timelineWindowEndNs: base + 5_000n,
  });
  assert.equal(harness.api.panTimelineViewportByPixels(250), true);
  assert.equal(harness.state.timelineWindowStartNs, base + 4_250n);
  assert.equal(harness.state.timelineWindowEndNs, base + 5_250n);
  assert.equal(harness.api.panTimelineViewportByPixels(-250), true);
  assert.equal(harness.state.timelineWindowStartNs, base + 4_000n);
});

test("one-nanosecond windows still move by one exact nanosecond", () => {
  const base = 1n << 80n;
  const harness = navigationHarness({
    viewStartNs: base,
    viewEndNs: base + 10n,
    timelineWindowStartNs: base + 4n,
    timelineWindowEndNs: base + 5n,
    zoom: Number.MAX_VALUE / 2,
  });
  assert.equal(harness.api.panTimelineViewport(1), true);
  assert.equal(harness.state.timelineWindowStartNs, base + 5n);
  assert.equal(harness.state.timelineWindowEndNs, base + 6n);
  assert.equal(harness.api.panTimelineViewport(-1), true);
  assert.equal(harness.state.timelineWindowStartNs, base + 4n);
  assert.equal(harness.state.timelineWindowEndNs, base + 5n);
});

test("panning preserves selections, lanes, zoom, and the full capture domain", () => {
  const harness = navigationHarness();
  const references = { ...harness.state };
  const before = structuredClone(harness.state);
  assert.equal(harness.api.panTimelineViewport(1), true);
  const { timelineWindowStartNs, timelineWindowEndNs, ...preserved } = harness.state;
  const { timelineWindowStartNs: oldStart, timelineWindowEndNs: oldEnd, ...expected } = before;
  assert.deepEqual(preserved, expected);
  assert.equal(preserved.explicitLaneIds, references.explicitLaneIds);
  assert.equal(preserved.hiddenTimelineResourceIds, references.hiddenTimelineResourceIds);
  assert.equal(preserved.activeLayers, references.activeLayers);
  assert.equal(timelineWindowEndNs - timelineWindowStartNs, oldEnd - oldStart);
});

test("direct pan records before/after views and invalidates before rendering and refreshing", () => {
  const harness = navigationHarness();
  assert.equal(harness.api.panTimelineViewportByPixels(500), true);
  assert.deepEqual(harness.calls, [
    { kind: "cancel", options: { commitHistory: true } },
    { kind: "history", startNs: 4_000n, endNs: 5_000n, zoom: 10 },
    { kind: "invalidate" },
    { kind: "render", startNs: 4_500n, endNs: 5_500n, zoom: 10 },
    { kind: "history", startNs: 4_500n, endNs: 5_500n, zoom: 10 },
    { kind: "refresh", startNs: 4_500n, endNs: 5_500n, zoom: 10 },
  ]);
});

test("wheel pan defers history and refresh to burst completion", () => {
  const harness = navigationHarness();
  assert.equal(harness.api.panTimelineViewportByPixels(500, { recordHistory: false, fromWheel: true }), true);
  assert.deepEqual(harness.calls, [
    { kind: "invalidate" },
    { kind: "render", startNs: 4_500n, endNs: 5_500n, zoom: 10 },
  ]);
});

test("invalid and zero pan deltas have no side effects", () => {
  for (const delta of [0, Number.NaN, Infinity, -Infinity]) {
    const harness = navigationHarness();
    const before = { ...harness.state };
    assert.equal(harness.api.panTimelineViewportByPixels(delta), false);
    assert.deepEqual(harness.state, before);
    assert.deepEqual(harness.calls, []);
  }
});

function availabilityHarness(overrides = {}) {
  const state = {
    ...navigationHarness().state,
    timelineViewHistoryIndex: 1,
    timelineViewHistory: [{}, {}],
    ...overrides,
  };
  const document = { activeElement: null };
  const focusCalls = [];
  const formatted = [];
  class Button {
    constructor(id) {
      this.id = id;
      this.disabled = false;
      this.textContent = "";
    }

    closest(selector) {
      return selector === "#timeline-viewport-controls" && !this.id.startsWith("timeline-pan-")
        ? this
        : null;
    }

    focus(options) {
      focusCalls.push({ id: this.id, options });
      document.activeElement = this;
    }
  }
  const elements = new Map([
    "timeline-pan-earlier", "timeline-pan-later", "timeline-window-readout",
    "timeline-view-back", "timeline-view-forward", "timeline-zoom-out",
    "timeline-zoom-selection", "timeline-center", "timeline-scroll",
  ].map((id) => [id, new Button(id)]));
  const factory = new Function(
    "state", "document", "HTMLButtonElement", "byId", "rangeBounds",
    "formatOffset", "visibleTimelineOffsetPrecision", "syncTimelineToolbarTabStop",
    "timelineToolbarItems",
    `"use strict";
    ${functionSource("timelineWindowBounds")}
    ${functionSource("updateTimelineCommandAvailability")}
    return updateTimelineCommandAvailability;`,
  );
  const update = factory(
    state,
    document,
    Button,
    (id) => elements.get(id),
    () => state.rangeStartNs === null ? null : [state.rangeStartNs, state.rangeEndNs],
    (timeNs, precision) => {
      formatted.push({ timeNs, precision });
      return `${timeNs}ns`;
    },
    () => 9,
    () => {},
    () => [],
  );
  return { state, document, elements, focusCalls, formatted, update };
}

test("middle-window navigation is enabled and the readout describes the viewport, not the selection", () => {
  const harness = availabilityHarness();
  harness.update();
  assert.equal(harness.elements.get("timeline-pan-earlier").disabled, false);
  assert.equal(harness.elements.get("timeline-pan-later").disabled, false);
  assert.equal(harness.elements.get("timeline-window-readout").textContent, "4000ns – 5000ns");
  assert.deepEqual(harness.formatted, [
    { timeNs: 4_000n, precision: 9 },
    { timeNs: 5_000n, precision: 9 },
  ]);
  assert.deepEqual(harness.focusCalls, []);
});

test("deep-zoom readouts format both exact BigInt endpoints with visible-window precision", () => {
  const base = 1n << 80n;
  const harness = availabilityHarness({
    viewStartNs: base,
    viewEndNs: base + 10n,
    timelineWindowStartNs: base + 4n,
    timelineWindowEndNs: base + 5n,
  });
  harness.update();
  assert.deepEqual(harness.formatted, [
    { timeNs: base + 4n, precision: 9 },
    { timeNs: base + 5n, precision: 9 },
  ]);
  assert.equal(harness.elements.get("timeline-window-readout").textContent, `${base + 4n}ns – ${base + 5n}ns`);
});

test("navigation availability follows both capture boundaries and full fit", () => {
  for (const [startNs, endNs, earlierDisabled, laterDisabled] of [
    [0n, 1_000n, true, false],
    [9_000n, 10_000n, false, true],
    [0n, 10_000n, true, true],
  ]) {
    const harness = availabilityHarness({ timelineWindowStartNs: startNs, timelineWindowEndNs: endNs });
    harness.update();
    assert.equal(harness.elements.get("timeline-pan-earlier").disabled, earlierDisabled);
    assert.equal(harness.elements.get("timeline-pan-later").disabled, laterDisabled);
    assert.equal(harness.elements.get("timeline-window-readout").textContent, `${startNs}ns – ${endNs}ns`);
  }
});

test("moving away from a capture boundary re-enables the pan control", () => {
  const navigation = navigationHarness({ timelineWindowStartNs: 0n, timelineWindowEndNs: 1_000n });
  const harness = availabilityHarness(navigation.state);
  harness.update();
  assert.equal(harness.elements.get("timeline-pan-earlier").disabled, true);
  assert.equal(navigation.api.panTimelineViewport(1), true);
  Object.assign(harness.state, navigation.state);
  harness.update();
  assert.equal(harness.elements.get("timeline-pan-earlier").disabled, false);
  assert.equal(harness.elements.get("timeline-pan-later").disabled, false);
});

test("focus moves to the opposite pan control when the focused direction reaches its boundary", () => {
  for (const [startNs, endNs, focused, destination] of [
    [0n, 1_000n, "timeline-pan-earlier", "timeline-pan-later"],
    [9_000n, 10_000n, "timeline-pan-later", "timeline-pan-earlier"],
  ]) {
    const harness = availabilityHarness({ timelineWindowStartNs: startNs, timelineWindowEndNs: endNs });
    harness.document.activeElement = harness.elements.get(focused);
    harness.update();
    assert.deepEqual(harness.focusCalls, [{ id: destination, options: { preventScroll: true } }]);
    assert.equal(harness.document.activeElement, harness.elements.get(destination));
  }
});

test("full fit returns focus from either disabled pan control to the timeline", () => {
  for (const focused of ["timeline-pan-earlier", "timeline-pan-later"]) {
    const harness = availabilityHarness({ timelineWindowStartNs: 0n, timelineWindowEndNs: 10_000n });
    harness.document.activeElement = harness.elements.get(focused);
    harness.update();
    assert.deepEqual(harness.focusCalls, [{ id: "timeline-scroll", options: { preventScroll: true } }]);
  }
});

test("enabled pan controls keep keyboard focus when availability refreshes", () => {
  for (const focused of ["timeline-pan-earlier", "timeline-pan-later"]) {
    const harness = availabilityHarness();
    const button = harness.elements.get(focused);
    harness.document.activeElement = button;
    harness.update();
    assert.equal(harness.document.activeElement, button);
    assert.deepEqual(harness.focusCalls, []);
  }
});

test("visible navigation buttons execute the earlier/later pan commands", () => {
  const source = functionSource("bindControls");
  const callbacks = new Map();
  const navigation = navigationHarness();
  for (const id of ["timeline-pan-earlier", "timeline-pan-later"]) {
    const binding = new RegExp(`byId\\("${id}"\\)\\.addEventListener\\("click",[^;]+;`).exec(source);
    assert.ok(binding, `${id} must bind a click command`);
    new Function("byId", "panTimelineViewport", binding[0])(
      (elementId) => ({ addEventListener: (type, callback) => callbacks.set(`${elementId}:${type}`, callback) }),
      navigation.api.panTimelineViewport,
    );
  }
  callbacks.get("timeline-pan-earlier:click")();
  assert.ok(navigation.state.timelineWindowStartNs < 4_000n);
  callbacks.get("timeline-pan-later:click")();
  assert.equal(navigation.state.timelineWindowStartNs, 4_000n);
});

function keyboardHarness({ height = 600 } = {}) {
  const state = {
    ...navigationHarness().state,
    brush: null,
    timelineViewHistoryIndex: 2,
    timelinePanDeltaPx: 0,
    timelinePanFrameId: null,
  };
  const calls = [];
  const frames = new Map();
  const document = { activeElement: null };
  let nextFrameId = 1;
  function node(id, { parent = null, tag = "div", attributes = {} } = {}) {
    return {
      id,
      parent,
      attributes,
      matches(selector) {
        return selector.split(",").some((raw) => {
          const item = raw.trim();
          if (item.startsWith("#")) return item.slice(1) === id;
          if (item.startsWith("[")) {
            const attribute = /^\[([^=\]]+)(?:=['"]?([^'"\]]+)['"]?)?\]/.exec(item);
            if (!attribute || !(attribute[1] in attributes)) return false;
            if (attribute[2] !== undefined && attributes[attribute[1]] !== attribute[2]) return false;
            if (item.includes(":not(") && attributes.contenteditable === "false") return false;
            return true;
          }
          return tag === item;
        });
      },
      closest(selector) {
        for (let candidate = this; candidate; candidate = candidate.parent) {
          if (candidate.matches(selector)) return candidate;
        }
        return null;
      },
      contains(target) {
        for (let candidate = target; candidate; candidate = candidate.parent) {
          if (candidate === this) return true;
        }
        return false;
      },
      focus(options) {
        calls.push({ kind: "focus", id, options });
        document.activeElement = this;
      },
    };
  }
  const scroll = node("timeline-scroll");
  const content = node("timeline-content", { parent: scroll });
  const panControls = node("timeline-pan-controls");
  const glyph = node("event-mark", { parent: content, tag: "button" });
  const lane = node("lane-label", { parent: content, tag: "button" });
  const panButton = node("timeline-pan-earlier", { parent: panControls, tag: "button" });
  const outside = node("outside-button", { tag: "button" });
  scroll.clientHeight = height;
  scroll.scrollHeight = 2_000;
  let scrollTop = 400;
  Object.defineProperty(scroll, "scrollTop", {
    get: () => scrollTop,
    set: (value) => { scrollTop = Math.max(0, Math.min(scroll.scrollHeight - scroll.clientHeight, value)); },
  });
  scroll.scrollBy = (options) => { scroll.scrollTop += options.top; };
  content.querySelector = () => glyph;
  const elements = new Map([scroll, content, panControls, glyph, lane, panButton].map((element) => [element.id, element]));
  const factory = new Function(
    "state", "document", "window", "byId", "timelinePhysicalTrackWidth",
    "panTimelineViewport", "panTimelineViewportByPixels", "closeTimelineContextMenu",
    "beginTimelineWheelBurst", "scheduleTimelineWheelBurstFinish", "restoreTimelineView",
    "rangeBounds", "zoomTimelineBy", "fitTimelineCapture", "zoomToSelectedRange",
    "centerTimelineAt", "openTimelineContextMenu",
    `"use strict";
    ${functionSource("scheduleTimelinePan")}
    ${functionSource("timelineViewportKeyDown")}
    return timelineViewportKeyDown;`,
  );
  const handle = factory(
    state,
    document,
    { requestAnimationFrame: (callback) => {
      const id = nextFrameId++;
      frames.set(id, callback);
      return id;
    } },
    (id) => elements.get(id),
    () => 1_000,
    (direction) => calls.push({ kind: "pan", direction }),
    (deltaPx, options) => calls.push({ kind: "panPixels", deltaPx, options }),
    () => calls.push({ kind: "closeMenu" }),
    (mode) => calls.push({ kind: "beginBurst", mode }),
    () => calls.push({ kind: "finishBurstLater" }),
    (index) => calls.push({ kind: "history", index }),
    () => [state.rangeStartNs, state.rangeEndNs],
    (direction) => calls.push({ kind: "zoom", direction }),
    () => calls.push({ kind: "fit" }),
    () => calls.push({ kind: "zoomRange" }),
    () => calls.push({ kind: "center" }),
    () => calls.push({ kind: "contextMenu" }),
  );
  function event(key, target = scroll, overrides = {}) {
    return {
      key,
      target,
      repeat: false,
      defaultPrevented: false,
      isComposing: false,
      ctrlKey: false,
      metaKey: false,
      altKey: false,
      shiftKey: false,
      preventions: 0,
      preventDefault() {
        this.defaultPrevented = true;
        this.preventions += 1;
      },
      stopPropagation() {},
      ...overrides,
    };
  }
  return {
    state, calls, frames, document, scroll, content, panControls, glyph, lane,
    panButton, outside, node, event, handle,
    flushFrames() {
      const pending = [...frames.values()];
      frames.clear();
      pending.forEach((callback) => callback());
    },
  };
}

test("left/right keys pan from the timeline, resource lanes, events, and dedicated navigation controls", () => {
  for (const targetName of ["scroll", "lane", "glyph", "panControls", "panButton"]) {
    for (const [key, direction] of [["ArrowLeft", -1], ["ArrowRight", 1]]) {
      const harness = keyboardHarness();
      const event = harness.event(key, harness[targetName]);
      harness.document.activeElement = event.target;
      harness.handle(event);
      assert.equal(event.defaultPrevented, true, `${targetName} ${key}`);
      const focus = ["lane", "glyph"].includes(targetName)
        ? [{ kind: "focus", id: "timeline-scroll", options: { preventScroll: true } }]
        : [];
      assert.deepEqual(harness.calls, [...focus, { kind: "pan", direction }]);
    }
  }
});

test("held horizontal arrows coalesce repeated key events into one pending frame", () => {
  for (const [key, direction] of [["ArrowLeft", -1], ["ArrowRight", 1]]) {
    const harness = keyboardHarness();
    harness.handle(harness.event(key));
    for (let index = 0; index < 3; index += 1) {
      const event = harness.event(key, harness.scroll, { repeat: true });
      harness.handle(event);
      assert.equal(event.defaultPrevented, true);
    }
    assert.deepEqual(harness.calls.filter(({ kind }) => kind === "pan"), [{ kind: "pan", direction }]);
    assert.equal(harness.frames.size, 1);
    assert.equal(harness.state.timelinePanDeltaPx, direction * 300);
    assert.equal(harness.calls.some(({ kind }) => kind === "panPixels"), false);
    harness.flushFrames();
    assert.deepEqual(harness.calls.filter(({ kind }) => kind === "panPixels"), [{
      kind: "panPixels", deltaPx: direction * 300, options: { recordHistory: false, fromWheel: true },
    }]);
    assert.equal(harness.state.timelinePanDeltaPx, 0);
    assert.equal(harness.state.timelinePanFrameId, null);
  }
});

test("up/down scroll lanes by a viewport-relative step without changing time selections", () => {
  for (const targetName of ["scroll", "lane", "glyph", "panButton"]) {
    for (const [key, direction] of [["ArrowUp", -1], ["ArrowDown", 1]]) {
      const harness = keyboardHarness();
      const original = structuredClone(harness.state);
      const event = harness.event(key, harness[targetName]);
      harness.handle(event);
      assert.equal(event.defaultPrevented, true);
      assert.equal(harness.scroll.scrollTop, 400 + direction * 60);
      assert.deepEqual(harness.state, original);
      assert.deepEqual(harness.calls, ["lane", "glyph"].includes(targetName)
        ? [{ kind: "focus", id: "timeline-scroll", options: { preventScroll: true } }]
        : []);
    }
  }
});

test("vertical keyboard scroll has a usable minimum step and clamps at lane bounds", () => {
  const harness = keyboardHarness({ height: 200 });
  harness.handle(harness.event("ArrowDown"));
  assert.equal(harness.scroll.scrollTop, 440);
  harness.scroll.scrollTop = 10;
  harness.handle(harness.event("ArrowUp", harness.scroll, { repeat: true }));
  assert.equal(harness.scroll.scrollTop, 0);
  harness.scroll.scrollTop = 1_790;
  harness.handle(harness.event("ArrowDown", harness.scroll, { repeat: true }));
  assert.equal(harness.scroll.scrollTop, 1_800);
  assert.deepEqual(harness.calls, []);
});

test("already-handled and composing keyboard events remain untouched", () => {
  for (const flags of [{ defaultPrevented: true }, { isComposing: true }]) {
    for (const key of ["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown", "+"]) {
      const harness = keyboardHarness();
      const event = harness.event(key, harness.glyph, flags);
      harness.handle(event);
      assert.equal(event.preventions, 0);
      assert.deepEqual(harness.calls, []);
      assert.equal(harness.scroll.scrollTop, 400);
    }
  }
});

test("non-arrow repeat events do not repeatedly execute viewport commands", () => {
  for (const key of ["+", "-", "0", "z", "c", "Enter", "ContextMenu"]) {
    const harness = keyboardHarness();
    const event = harness.event(key, harness.scroll, { repeat: true });
    harness.handle(event);
    assert.equal(event.defaultPrevented, false);
    assert.deepEqual(harness.calls, []);
  }
});

test("text controls, editable descendants, sliders, and range handles retain their arrow keys", () => {
  for (const options of [
    { tag: "input" }, { tag: "textarea" }, { tag: "select" },
    { attributes: { contenteditable: "" } },
    { attributes: { contenteditable: "true" } },
    { attributes: { contenteditable: "plaintext-only" } },
    { attributes: { role: "slider" } },
    { attributes: { "data-range-handle": "start" } },
  ]) {
    for (const key of ["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown"]) {
      const harness = keyboardHarness();
      const control = harness.node("control", { parent: harness.content, ...options });
      const descendant = harness.node("control-child", { parent: control });
      const event = harness.event(key, descendant);
      harness.handle(event);
      assert.equal(event.defaultPrevented, false, `${JSON.stringify(options)} ${key}`);
      assert.deepEqual(harness.calls, []);
      assert.equal(harness.scroll.scrollTop, 400);
    }
  }
});

test("Ctrl/Meta/Shift arrow combinations are not consumed as viewport navigation", () => {
  for (const modifier of ["ctrlKey", "metaKey", "shiftKey"]) {
    for (const key of ["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown"]) {
      const harness = keyboardHarness();
      const event = harness.event(key, harness.glyph, { [modifier]: true });
      harness.handle(event);
      assert.equal(event.defaultPrevented, false);
      assert.deepEqual(harness.calls, []);
      assert.equal(harness.scroll.scrollTop, 400);
    }
  }
});

test("Alt vertical arrows and mixed-modifier horizontal arrows retain native behavior", () => {
  for (const [key, flags] of [
    ["ArrowUp", { altKey: true }],
    ["ArrowDown", { altKey: true }],
    ["ArrowLeft", { altKey: true, ctrlKey: true }],
    ["ArrowRight", { altKey: true, metaKey: true }],
    ["ArrowRight", { altKey: true, shiftKey: true }],
  ]) {
    const harness = keyboardHarness();
    const event = harness.event(key, harness.glyph, flags);
    harness.handle(event);
    assert.equal(event.defaultPrevented, false);
    assert.deepEqual(harness.calls, []);
    assert.equal(harness.scroll.scrollTop, 400);
  }
});

test("explicitly non-editable timeline descendants still support directional navigation", () => {
  const harness = keyboardHarness();
  const target = harness.node("non-editable", { parent: harness.content, attributes: { contenteditable: "false" } });
  const event = harness.event("ArrowRight", target);
  harness.handle(event);
  assert.equal(event.defaultPrevented, true);
  assert.deepEqual(harness.calls, [
    { kind: "focus", id: "timeline-scroll", options: { preventScroll: true } },
    { kind: "pan", direction: 1 },
  ]);
});

test("Alt+Left/Right retains history navigation rather than ordinary pan", () => {
  for (const [key, index] of [["ArrowLeft", 1], ["ArrowRight", 3]]) {
    const harness = keyboardHarness();
    const event = harness.event(key, harness.glyph, { altKey: true });
    harness.handle(event);
    assert.equal(event.defaultPrevented, true);
    assert.deepEqual(harness.calls, [
      { kind: "focus", id: "timeline-scroll", options: { preventScroll: true } },
      { kind: "history", index },
    ]);
    assert.equal(harness.frames.size, 0);
  }
});

test("an active range brush owns arrow input without changing viewport or selection", () => {
  for (const key of ["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown"]) {
    for (const repeat of [false, true]) {
      const harness = keyboardHarness();
      harness.state.brush = { pointerId: 1, mode: "range" };
      const original = structuredClone(harness.state);
      const event = harness.event(key, harness.glyph, { repeat });
      harness.handle(event);
      assert.equal(event.defaultPrevented, true);
      assert.deepEqual(harness.calls, []);
      assert.equal(harness.frames.size, 0);
      assert.equal(harness.scroll.scrollTop, 400);
      assert.deepEqual(harness.state, original);
    }
  }
});

test("one bubbling directional key event is handled only once", () => {
  for (const key of ["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown"]) {
    const harness = keyboardHarness();
    const event = harness.event(key, harness.glyph);
    harness.handle(event);
    const firstCalls = structuredClone(harness.calls);
    const firstScroll = harness.scroll.scrollTop;
    harness.handle(event);
    assert.equal(event.preventions, 1);
    assert.deepEqual(harness.calls, firstCalls);
    assert.equal(harness.scroll.scrollTop, firstScroll);
  }
});

test("directional navigation listeners are attached only to the timeline and its dedicated pan controls", () => {
  const bindings = [...functionSource("bindControls").matchAll(
    /(?:[A-Za-z_$][\w$]*|byId\("[^"\n]+"\))\.addEventListener\("keydown", timelineViewportKeyDown\);/g,
  )].map(([binding]) => binding);
  assert.equal(bindings.length, 3);
  const registrations = [];
  const target = (id) => ({ addEventListener: (type, callback) => registrations.push({ id, type, callback }) });
  const harness = keyboardHarness();
  new Function("timelineContent", "timelineScroll", "byId", "timelineViewportKeyDown", bindings.join("\n"))(
    target("timeline-content"), target("timeline-scroll"), target, harness.handle,
  );
  assert.deepEqual(registrations.map(({ id }) => id).sort(), [
    "timeline-content", "timeline-pan-controls", "timeline-scroll",
  ]);
  const event = harness.event("ArrowRight", harness.glyph);
  registrations.find(({ id }) => id === "timeline-content").callback(event);
  registrations.find(({ id }) => id === "timeline-scroll").callback(event);
  assert.deepEqual(harness.calls.filter(({ kind }) => kind === "pan"), [{ kind: "pan", direction: 1 }]);
  assert.equal(event.preventions, 1);
});
