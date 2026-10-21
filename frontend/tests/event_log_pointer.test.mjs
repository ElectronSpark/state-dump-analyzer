import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(new URL("../assets/app.js", import.meta.url), "utf8");
function functionSource(name) {
  const start = source.indexOf(`function ${name}(`);
  assert.notEqual(start, -1);
  const end = /\r?\n\}(?=\r?\n)/.exec(source.slice(start));
  return source.slice(start, start + end.index + end[0].length);
}

function harness({ actualSelection = false } = {}) {
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
    ${actualSelection ? ["normalizeEventLogSelectionRanges", "eventLogSelectionIncludes", "addEventLogSelectionRange", "removeEventLogSelectionRange", "setEventLogSelectionRanges", "applyEventLogSelectionGesture"].map(functionSource).join("\n") : `
    const setEventLogSelectionRanges = (ranges) => { state.eventLogSelectionRanges = ranges; };
    const applyEventLogSelectionGesture = (index) => selections.push(index);
    `}
    const eventLogDragRanges = (_, index) => [[1, index]];
    const visibleEventLogRowAtPoint = () => row;
    const runEventLogDragAutoScroll = () => {};
    const renderEventLogSelectionToolbar = () => {};
    const renderEventTableWindow = () => {};
    const registerVisibleEventLogHoverModels = () => {};
    const focusEventLogEntry = () => {};
    const focusEventLogSelectionIndex = (index) => { state.keyboardTarget = index; };
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

for (const modifier of ["ctrlKey", "metaKey"]) {
  test(`${modifier} click adds and toggles one row without pointer capture`, () => {
    const h = harness({ actualSelection: true });
    h.state.eventLogSelectionRanges = [[0, 0]];
    h.state.eventLogSelectionAnchor = 0;
    for (const expected of [[[0, 1]], [[0, 0]]]) {
      const event = h.event({ [modifier]: true });
      h.eventLogPointerDown(event);
      h.eventLogPointerMove(h.event({ [modifier]: true, clientX: 12 }));
      assert.equal(h.host.captured, null);
      h.finishEventLogDrag(event);
      h.handlers.get("click")(event);
      assert.deepEqual(h.state.eventLogSelectionRanges, expected);
    }
  });
}

test("single, Ctrl and Shift row clicks preserve the expected multi-selection", () => {
  const h = harness({ actualSelection: true });
  const click = (index, modifiers = {}) => {
    h.row.dataset.selectionIndex = String(index);
    h.bindVisibleEventLogRows();
    const event = h.event(modifiers);
    h.eventLogPointerDown(event);
    h.finishEventLogDrag(event);
    h.handlers.get("click")(event);
  };
  click(0);
  assert.deepEqual(h.state.eventLogSelectionRanges, [[0, 0]]);
  click(1, { ctrlKey: true });
  assert.deepEqual(h.state.eventLogSelectionRanges, [[0, 1]]);
  click(2, { ctrlKey: true, shiftKey: true });
  assert.deepEqual(h.state.eventLogSelectionRanges, [[0, 2]]);
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


test("Home and End navigate the entire log and preserve Shift range intent", () => {
  const h = harness({ actualSelection: true });
  h.state.eventLogSelectableCount = 5000;
  h.state.eventLogSelectionAnchor = 1;
  h.handlers.get("keydown")(h.event({key: "End", shiftKey: true}));
  assert.equal(h.state.keyboardTarget, 4999);
  assert.deepEqual(h.state.eventLogSelectionRanges, [[1, 4999]]);
  h.handlers.get("keydown")(h.event({key: "Home"}));
  assert.equal(h.state.keyboardTarget, 0);
  assert.deepEqual(h.state.eventLogSelectionRanges, [[0, 0]]);
});
