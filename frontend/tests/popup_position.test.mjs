import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const source = readFileSync(new URL('../assets/app.js', import.meta.url), 'utf8');
function harness() {
  const key = 'source-record:preset-b:source-1';
  let top = 380, renders = 0, bindings = 0, queries = 0;
  const control = {}, detail = { scrollTop: 87 };
  const card = { hidden: true, style: {}, classList: { toggle() {}, remove() {} },
    scrollHeight: 230, contains: target => target === control || target === detail,
    set innerHTML(value) { renders++; this.content = value; } };
  const marker = { isConnected: true, getBoundingClientRect: () => ({ left: 380, width: 14, top, bottom: top + 14 }) };
  let current = marker;
  const document = { activeElement: control, addEventListener(type, handler, options) {
    assert.equal(type, 'scroll'); this.scroll = handler; this.options = options;
  }, querySelector(selector) {
    queries++; assert.equal(selector, `[data-hover-key="${key}"]`); return current;
  } };
  const state = { hoverModels: new Map([[key, { type: 'source-record', mark: {} }]]),
    eventLogHoverModels: new Map(), hoverPinned: false, hoverKey: null };
  const window = { innerWidth: 608, innerHeight: 668, clearTimeout() {} };
  const byId = id => { assert.equal(id, 'timeline-hover'); return card; };
  const bodies = ['showHover', 'positionHover', 'closeHover'].map(name => {
    const match = new RegExp(`^function ${name}\\(`, 'm').exec(source);
    assert.ok(match, name);
    const tail = source.slice(match.index);
    return tail.slice(0, /\n(?:async )?function \w+\(/.exec(tail)?.index);
  });
  const api = new Function('state', 'window', 'document', 'byId', 'CSS', 'sourceRecordHoverHtml', 'bindHoverCardActions',
    `${bodies.join('\n')}\nreturn {showHover, positionHover, closeHover};`)(state, window, document, byId,
    { escape: String }, () => 'source details', () => { bindings++; });
  // Install the production capture listener, without unrelated page controls.
  const start = source.indexOf('  document.addEventListener("scroll",');
  const end = source.indexOf('\n  window.addEventListener("resize",', start);
  assert.ok(start >= 0 && end > start);
  new Function('document', 'byId', 'positionHover', source.slice(start, end))(document, byId, api.positionHover);
  return { api, state, window, document, card, control, detail, marker, key,
    move: value => { top = value; }, replace: value => { current = value; },
    counts: () => ({ renders, bindings, queries }) };
}

for (const target of ['document', 'nested timeline']) test(`open popup follows ${target} scrolling without rebuilding details`, () => {
  const h = harness();
  h.api.showHover(h.key, h.marker, true);
  assert.equal(h.card.style.top, '404px');
  assert.deepEqual(h.document.options, { capture: true, passive: true });
  for (const top of [350, 320, 327]) {
    h.move(top);
    h.document.scroll({ target: target === 'document' ? h.document : {} });
    assert.equal(h.card.style.top, `${top + 24}px`);
  }
  assert.equal(h.counts().renders, 1);
  assert.equal(h.counts().bindings, 1);
  assert.equal(h.document.activeElement, h.control);
  assert.equal(h.detail.scrollTop, 87);
  assert.equal(h.state.hoverPinned, true);
});

test('scroll resolves the live instance after replacement and closes when it disappears', () => {
  const h = harness();
  h.api.showHover(h.key, h.marker, false);
  h.marker.isConnected = false;
  h.replace({ isConnected: true, getBoundingClientRect: () => ({ left: 100, width: 20, top: 200, bottom: 220 }) });
  h.document.scroll({ target: h.document });
  assert.equal(h.card.style.top, '230px');
  assert.equal(h.card.style.left, '12px');
  h.replace(null);
  h.document.scroll({ target: h.document });
  assert.equal(h.card.hidden, true);
  assert.equal(h.state.hoverKey, null);
});

test('scrolling inside the popup or after closing does no anchor lookup or content work', () => {
  const h = harness();
  h.api.showHover(h.key, h.marker, true);
  const opened = h.counts();
  h.document.scroll({ target: h.detail });
  assert.deepEqual(h.counts(), opened);
  h.api.closeHover();
  h.document.scroll({ target: h.document });
  assert.deepEqual(h.counts(), opened);
});
