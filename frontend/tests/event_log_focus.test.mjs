import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { virtualScrollWindow } from "../assets/view_models.js";

const source = readFileSync(new URL("../assets/app.js", import.meta.url), "utf8");
const start = source.indexOf("function renderEventTableWindow(");
const end = /\r?\n\}/.exec(source.slice(start));
const renderSource = source.slice(start, start + end.index + end[0].length);

function harness() {
  const document = { body: {}, activeElement: null };
  document.activeElement = document.body;
  let rows = new Map();
  const externalInput = {};
  const body = {
    contains: (row) => [...rows.values()].includes(row),
    closest: () => ({ setAttribute() {} }),
    querySelector(selector) {
      const index = /data-selection-index="(\d+)"/.exec(selector)?.[1];
      return index === undefined ? rows.values().next().value : rows.get(index);
    },
    set innerHTML(html) {
      if (this.contains(document.activeElement)) document.activeElement = document.body;
      rows = new Map([...html.matchAll(/row:(\d+);/g)].map((match) => {
        const row = { dataset: { selectionIndex: match[1] },
          matches: () => true, setAttribute() {},
          focus(options) { assert.deepEqual(options, { preventScroll: true }); document.activeElement = row; },
        };
        return [match[1], row];
      }));
    },
  };
  const scroll = { clientHeight: 384, scrollTop: 0 };
  const state = { eventLogHoverModels: new Map(), eventLogSelectionFocus: 8,
    eventLogRows: Array.from({ length: 20 }, (_, index) => index),
  };
  const render = new Function("document", "state", "body", "scroll", "virtualScrollWindow", `
    const byId = (id) => id === "event-log-scroll" ? scroll : body;
    const EVENT_LOG_ROW_HEIGHT = 44, EVENT_LOG_MAX_SCROLL_HEIGHT = 8000000, EVENT_LOG_OVERSCAN = 10;
    const eventLogBodyViewportHeight = () => 352;
    const usesServerWindowedHistory = () => false;
    const renderEventLogRow = (index) => "row:" + index + ";";
    const bindVisibleEventLogRows = () => {};
    ${renderSource}
    return renderEventTableWindow;
  `)(document, state, body, scroll, virtualScrollWindow);
  return { render, document, body, scroll, state, externalInput };
}

test("delayed scroll and page rerenders retain the keyboard row focus", () => {
  const h = harness();
  h.render();
  for (const index of [8, 7, 6, 5]) {
    h.state.eventLogSelectionFocus = index;
    h.body.querySelector(`tr[data-selection-index="${index}"]`).focus({ preventScroll: true });
    // Reproduce queued scroll/page work after the navigation focus callback.
    h.scroll.scrollTop += 5;
    h.render();
    h.render();
    assert.equal(h.document.activeElement.dataset.selectionIndex, String(index));
    assert.equal(h.document.activeElement, h.body.querySelector(`tr[data-selection-index="${index}"]`));
  }
});

test("background event-log rerenders leave external control focus intact", () => {
  const h = harness();
  h.render();
  h.document.activeElement = h.externalInput;
  h.render();
  assert.equal(h.document.activeElement, h.externalInput);
});
