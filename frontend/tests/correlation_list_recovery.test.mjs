import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const source = readFileSync(new URL('../assets/app.js', import.meta.url), 'utf8');
const start = source.indexOf('function renderCorrelationList(');
const end = source.indexOf('\nfunction ', start + 1);
const renderer = source.slice(start, end);

function hoverHarness() {
  const functions = ['showCorrelationHover', 'positionCorrelationHover', 'closeCorrelationHover'].map(name => {
    const from = source.indexOf(`function ${name}(`);
    return source.slice(from, source.indexOf('\nfunction ', from + 1));
  }).join('\n');
  const card = { style: {}, dataset: {}, scrollHeight: 430,
    getBoundingClientRect: () => ({ width: 440 }), contains: target => target === card };
  const viewport = { innerWidth: 592, innerHeight: 668, clearTimeout() {} };
  const header = { bottom: 0 };
  const document = { querySelector: () => ({ getBoundingClientRect: () => header }) };
  const api = new Function('window', 'document', 'byId', 'correlationHoverCard',
    `${functions}; return {show: showCorrelationHover, position: positionCorrelationHover, close: closeCorrelationHover};`
  )(viewport, document, () => card, () => card);
  const anchor = rect => ({ isConnected: true, closest: () => null, getBoundingClientRect: () => rect });
  return { ...api, card, viewport, header, document, anchor };
}

test('correlation hover stays outside its trigger in a narrow viewport and restores height on reopen', () => {
  const { show, card, viewport, anchor } = hoverHarness();
  for (const top of [250, 323, 390]) {
    const rect = { left: 80, right: 175, width: 95, top, bottom: top + 23, height: 23 };
    show(anchor(rect), 'facts', { pinned: true });
    const cardTop = Number.parseFloat(card.style.top);
    const cardHeight = Math.min(430, Number.parseFloat(card.style.maxHeight) || 430);
    assert.ok(cardTop >= 12 && cardTop + cardHeight <= viewport.innerHeight - 12);
    assert.ok(cardTop + cardHeight <= rect.top - 8 || cardTop >= rect.bottom + 8,
      `hover must not intercept the control at ${top}`);
    assert.equal(card.dataset.pinned, 'true');
  }
  viewport.innerHeight = 1000;
  show(anchor({ left: 80, right: 175, width: 95, top: 50, bottom: 73, height: 23 }), 'facts');
  assert.equal(card.style.maxHeight, '');
  assert.equal(card.style.top, '81px');
  assert.equal(card.dataset.pinned, 'false');
});

test('pinned correlation card tracks a partly visible anchor then retires behind the sticky header', () => {
  const h = hoverHarness();
  h.header.bottom = 84;
  const rect = { left: 80, right: 175, top: 90, bottom: 113 };
  const trigger = h.anchor(rect);
  h.show(trigger, 'facts', { pinned: true });
  const originalTop = h.card.style.top;
  rect.top = 70; rect.bottom = 93;
  h.position();
  assert.equal(h.card.hidden, false);
  assert.notEqual(h.card.style.top, originalTop);
  assert.ok(Number.parseFloat(h.card.style.top) >= rect.bottom + 8);
  h.card.scrollTop = 90;
  h.show(trigger, 'replacement facts from passive re-entry');
  assert.equal(h.card.innerHTML, 'facts');
  assert.equal(h.card.scrollTop, 90);
  assert.equal(h.card.dataset.pinned, 'true');
  rect.bottom = 84;
  h.position();
  assert.equal(h.card.hidden, true);
  rect.top = 90; rect.bottom = 113;
  h.position();
  assert.equal(h.card.hidden, true, 'scrolling back must not revive a dismissed card');
});

for (const boundary of ['left', 'right', 'top', 'bottom', 'detached']) {
  test(`correlation card dismisses when its anchor leaves the ${boundary} boundary`, () => {
    const h = hoverHarness();
    const rect = { left: 100, right: 200, top: 200, bottom: 230 };
    const trigger = h.anchor(rect);
    const clip = { clientLeft: 2, clientTop: 2, clientWidth: 400, clientHeight: 300,
      getBoundingClientRect: () => ({ left: 20, top: 100 }) };
    trigger.closest = () => clip;
    h.show(trigger, 'facts', { pinned: true });
    if (boundary === 'left') { rect.left = 0; rect.right = 22; }
    if (boundary === 'right') { rect.left = 422; rect.right = 480; }
    if (boundary === 'top') { rect.top = 50; rect.bottom = 102; }
    if (boundary === 'bottom') { rect.top = 402; rect.bottom = 430; }
    if (boundary === 'detached') trigger.isConnected = false;
    h.position();
    assert.equal(h.card.hidden, true);
    assert.equal(h.card.dataset.pinned, 'false');
  });
}

test('captured page scroll reconciles correlation anchors without disturbing internal card scrolling', () => {
  const h = hoverHarness();
  let handler;
  const begin = source.indexOf('  document.addEventListener("scroll", (event) => {');
  const end = source.indexOf('\n  window.addEventListener("resize"', begin);
  const document = { addEventListener: (_name, fn) => { handler = fn; } };
  new Function('document', 'byId', 'positionHover', 'positionCorrelationHover', source.slice(begin, end))(
    document, id => id === 'correlation-hover' ? h.card : { contains: () => false }, () => {}, h.position);
  const rect = { left: 80, right: 175, top: 200, bottom: 230 };
  h.show(h.anchor(rect), 'facts', { pinned: true });
  rect.top = -100; rect.bottom = -70;
  handler({ target: h.card });
  assert.equal(h.card.hidden, false, 'internal detail scrolling does not reposition the card');
  handler({ target: document });
  assert.equal(h.card.hidden, true, 'page scroll dismisses the clipped card before surrounding controls are clicked');
});

test('visible horizontal and vertical graph strokes remain valid popup anchors', () => {
  for (const rect of [
    { left: 100, right: 200, top: 200, bottom: 200 },
    { left: 100, right: 100, top: 200, bottom: 230 },
  ]) {
    const h = hoverHarness();
    h.show(h.anchor(rect), 'edge facts', { pinned: true });
    assert.equal(h.card.hidden, false);
    rect.top = -30; rect.bottom = -20;
    h.position();
    assert.equal(h.card.hidden, true);
  }
});

test('relationship index scrollport clips focused correlation anchors', () => {
  const h = hoverHarness();
  const rect = { left: 100, right: 200, top: 200, bottom: 230 };
  const trigger = h.anchor(rect);
  trigger.closest = selector => selector.split(', ').includes('.correlation-rows') ? {
    clientLeft: 0, clientTop: 0, clientWidth: 400, clientHeight: 190,
    getBoundingClientRect: () => ({ left: 20, top: 100 }),
  } : null;
  h.show(trigger, 'facts', { pinned: true });
  assert.equal(h.card.hidden, false);
  rect.top = 290; rect.bottom = 320;
  h.position();
  assert.equal(h.card.hidden, true);
});

test('side-positioned correlation facts fit below the header in a short viewport', () => {
  const h = hoverHarness();
  h.viewport.innerWidth = 1200;
  h.viewport.innerHeight = 260;
  h.header.bottom = 84;
  h.show(h.anchor({ left: 100, right: 200, top: 110, bottom: 140 }), 'tall facts', { pinned: true });
  const top = Number.parseFloat(h.card.style.top);
  assert.ok(top >= 84);
  assert.ok(top + Number.parseFloat(h.card.style.maxHeight) <= 248);
});

// The harness replaces elements on innerHTML assignment, as the browser does.
// It retains only the DOM operations used by the production renderer.
function harness() {
  const state = { selectedResourceId: 'root', resourceById: new Map(), correlationListLimit: 2, graphShowFull: false };
  let focused = null;
  const scrolls = [];
  const element = (className, parent = null) => ({
    className, parent, open: true, dataset: {}, handlers: {}, children: [],
    classList: { contains: name => className.split(' ').includes(name) },
    matches(selector) { return selector === '.correlation-group' && this.classList.contains('correlation-group'); },
    closest(selector) { return this.matches(selector) ? this : this.parent?.closest(selector) || null; },
    querySelector(selector) {
      if (selector === '[data-correlation-edge-id]') return this.tag || null;
      if (selector === '[data-correlation-show-more]') return this.more || null;
      if (selector === 'summary, button') return this.summary || null;
      return null;
    },
    addEventListener(name, callback) { this.handlers[name] = callback; },
    focus() { focused = this; },
    scrollIntoView(options) { scrolls.push({ element: this, options }); },
  });
  const container = {
    dataset: {}, scrollTop: 123, groups: [], details: [], buttons: [], tags: [],
    set innerHTML(html) {
      focused = null;
      this.groups = []; this.details = []; this.buttons = []; this.tags = [];
      const chunks = [...html.matchAll(/<details class="correlation-group (incoming|outgoing)" open>([\s\S]*?)(?=<details class="correlation-group |$)/g)];
      for (const [, direction, body] of chunks) {
        const group = element(`correlation-group ${direction}`);
        group.summary = element('summary', group);
        this.groups.push(group); this.details.push(group);
        for (const [, itemClass, id] of body.matchAll(/<details class="(correlation-item [^"]+)">[\s\S]*?data-correlation-edge-id="([^"]+)"/g)) {
          const item = element(itemClass, group);
          item.open = false;
          item.tag = element('correlation-relation', item);
          item.tag.dataset.correlationEdgeId = id;
          this.details.push(item); this.tags.push(item.tag);
        }
        if (body.includes('data-correlation-show-more')) {
          group.more = element('button', group);
          this.buttons.push(group.more);
        }
      }
    },
    querySelectorAll(selector) {
      return selector === 'details' ? this.details
        : selector === '[data-correlation-show-more]' ? this.buttons
        : selector === '[data-correlation-edge-id]' ? this.tags : [];
    },
    querySelector(selector) {
      if (selector.startsWith('.correlation-group.')) return this.groups.find(group => group.classList.contains(selector.split('.').at(-1)));
      return selector === '[data-correlation-show-more]' ? this.buttons[0] : null;
    },
  };
  const deps = {
    state, byId: () => container, graphDisplayTimeNs: graph => graph.at,
    resourceLabel: (_, id) => id, humanResourceType: String, resourceKind: () => 'type',
    humanLayer: String, resourceLayer: () => 'layer', relationshipPresentation: () => ({ directed: true, displayLabel: 'Owns' }),
    escapeHtml: String, formatOffset: String, CORRELATION_LIST_PAGE_SIZE: 2,
    bindCorrelationHover() {}, graphEdgeHoverHtml() {}, closeCorrelationHover() {},
  };
  const render = new Function(...Object.keys(deps), `${renderer}; return renderCorrelationList;`)(...Object.values(deps));
  const graph = { at: 1, nodes: [], edges: Array.from({ length: 5 }, (_, i) => ({ id: `e${i}`, source: `r${i}`, target: 'root', type: 'owns' })) };
  return { state, container, render, graph, scrolls, focused: () => focused };
}

test('same-query redraw retains both closed groups and open edge details', () => {
  const h = harness();
  h.render(h.graph);
  h.container.groups[0].open = false;
  h.container.details.find(item => item.tag?.dataset.correlationEdgeId === 'e0').open = true;
  h.render({ ...h.graph, nodes: [] });
  assert.equal(h.container.groups[0].open, false);
  assert.equal(h.container.details.find(item => item.tag?.dataset.correlationEdgeId === 'e0').open, true);
});

for (const change of ['resource', 'time', 'scope']) test(`correlation disclosures reset for changed ${change}`, () => {
  const h = harness();
  h.render(h.graph);
  h.container.groups[0].open = false;
  if (change === 'resource') h.state.selectedResourceId = 'r0';
  if (change === 'time') h.graph.at = 2;
  if (change === 'scope') h.state.graphShowFull = true;
  h.render(h.graph);
  assert.equal(h.container.groups[0].open, true);
});

test('repeated pagination focuses and reveals the next control, then the final group summary', () => {
  const h = harness();
  h.render(h.graph);
  h.container.groups[0].open = false;
  h.container.details.find(item => item.tag?.dataset.correlationEdgeId === 'e0').open = true;
  h.container.buttons[0].handlers.click();
  assert.equal(h.state.correlationListLimit, 4);
  assert.equal(h.focused(), h.container.buttons[0]);
  assert.equal(h.scrolls.at(-1).element, h.focused());
  assert.equal(h.container.groups[0].open, false);
  assert.equal(h.container.details.find(item => item.tag?.dataset.correlationEdgeId === 'e0').open, true);
  h.container.buttons[0].handlers.click();
  assert.equal(h.state.correlationListLimit, 6);
  assert.equal(h.container.buttons.length, 0);
  assert.equal(h.focused(), h.container.groups[1].summary);
  assert.equal(h.scrolls.at(-1).element, h.focused());
  assert.equal(h.scrolls.length, 2);
});
