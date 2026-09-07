import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(new URL("../assets/app.js", import.meta.url), "utf8");
function functionSource(name) {
  const start = source.indexOf(`function ${name}(`);
  assert.notEqual(start, -1);
  const end = /\r?\n\}/.exec(source.slice(start));
  return source.slice(start, start + end.index + end[0].length);
}

function harness() {
  const state = {
    eventLogSelectionAnchor: null, eventLogSelectionFocus: null,
    eventLogSelectionRanges: [], eventLogSuppressClickUntil: 0,
  };
  const handlers = new Map();
  const selections = [];
  const row = {
    dataset: { selectionIndex: "1" },
    closest: (selector) => selector.startsWith("tr[") ? row : null,
    addEventListener: (name, handler) => handlers.set(name, handler),
  };
  const host = {
    captured: null,
    setPointerCapture(id) { this.captured = id; },
    hasPointerCapture(id) { return this.captured === id; },
    releasePointerCapture() { this.captured = null; },
    classList: { add() {}, remove() {} },
    querySelectorAll: () => [row],
  };
  const factory = new Function("state", "host", "row", "selections", `
    const byId = () => host;
    const window = { requestAnimationFrame: () => 1, cancelAnimationFrame() {} };
    const performance = { now: () => 1000 };
    const setEventLogSelectionRanges = (ranges) => { state.eventLogSelectionRanges = ranges; };
    const eventLogDragRanges = (_, index) => [[1, index]];
    const visibleEventLogRowAtPoint = () => row;
    const runEventLogDragAutoScroll = () => {};
    const renderEventLogSelectionToolbar = () => {};
    const renderEventTableWindow = () => {};
    const registerVisibleEventLogHoverModels = () => {};
    const focusEventLogEntry = () => {};
    const applyEventLogSelectionGesture = (index) => selections.push(index);
    ${["eventLogPointerDown", "eventLogPointerMove", "finishEventLogDrag", "bindVisibleEventLogRows"].map(functionSource).join("\n")}
    return { eventLogPointerDown, eventLogPointerMove, finishEventLogDrag, bindVisibleEventLogRows };
  `);
  const actions = factory(state, host, row, selections);
  actions.bindVisibleEventLogRows();
  const event = (overrides = {}) => ({
    target: row, pointerType: "mouse", pointerId: 1, isPrimary: true,
    button: 0, clientX: 10, clientY: 10, preventDefault() {}, ...overrides,
  });
  return { state, host, row, selections, handlers, event, ...actions };
}

test("a source-row click keeps its row target and invokes selection", () => {
  const h = harness();
  h.eventLogPointerDown(h.event());
  h.eventLogPointerMove(h.event({ clientX: 12 }));
  // Browsers target click at the capturing element when pointerup was captured.
  const clickTarget = h.host.captured === null ? h.row : h.host;
  h.finishEventLogDrag(h.event());
  if (clickTarget === h.row) h.handlers.get("click")(h.event());
  assert.deepEqual(h.selections, [1]);
  assert.equal(h.host.captured, null);
});

test("an actual drag captures the pointer and cancellation restores selection", () => {
  const h = harness();
  h.state.eventLogSelectionRanges = [[3, 3]];
  h.eventLogPointerDown(h.event());
  assert.equal(h.host.captured, null);
  h.eventLogPointerMove(h.event({ clientY: 20 }));
  assert.equal(h.host.captured, 1);
  assert.equal(h.state.eventLogDrag.active, true);
  h.finishEventLogDrag(h.event(), true);
  assert.deepEqual(h.state.eventLogSelectionRanges, [[3, 3]]);
  assert.equal(h.host.captured, null);
  assert.equal(h.state.eventLogDrag, null);
  assert.ok(h.state.eventLogSuppressClickUntil > 1000);
});
