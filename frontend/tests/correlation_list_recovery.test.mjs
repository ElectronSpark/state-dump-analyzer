import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const source = readFileSync(new URL('../assets/app.js', import.meta.url), 'utf8');
const start = source.indexOf('function renderCorrelationList(');
const end = source.indexOf('\nfunction ', start + 1);
const renderer = source.slice(start, end);

test('correlation hover stays outside its trigger in a narrow viewport and restores height on reopen', () => {
  const hoverStart = source.indexOf('function showCorrelationHover(');
  const hoverBody = source.slice(hoverStart, source.indexOf('\nfunction ', hoverStart + 1));
  const card = { style: {}, dataset: {}, scrollHeight: 430,
    getBoundingClientRect: () => ({ width: 440 }) };
  const viewport = { innerWidth: 592, innerHeight: 668, clearTimeout() {} };
  const show = new Function('window', 'correlationHoverCard', `${hoverBody}; return showCorrelationHover;`)(viewport, () => card);
  for (const top of [250, 323, 390]) {
    const rect = { left: 80, right: 175, width: 95, top, bottom: top + 23, height: 23 };
    show({ getBoundingClientRect: () => rect }, 'facts', { pinned: true });
    const cardTop = Number.parseFloat(card.style.top);
    const cardHeight = Math.min(430, Number.parseFloat(card.style.maxHeight) || 430);
    assert.ok(cardTop >= 12 && cardTop + cardHeight <= viewport.innerHeight - 12);
    assert.ok(cardTop + cardHeight <= rect.top - 8 || cardTop >= rect.bottom + 8,
      `hover must not intercept the control at ${top}`);
    assert.equal(card.dataset.pinned, 'true');
  }
  viewport.innerHeight = 1000;
  show({ getBoundingClientRect: () => ({ left: 80, right: 175, width: 95, top: 50, bottom: 73, height: 23 }) }, 'facts');
  assert.equal(card.style.maxHeight, '');
  assert.equal(card.style.top, '81px');
  assert.equal(card.dataset.pinned, 'false');
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
