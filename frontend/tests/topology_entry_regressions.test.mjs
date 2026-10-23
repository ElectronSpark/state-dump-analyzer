import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { escapeHtml } from '../assets/shared.js';

const source = readFileSync(new URL('../assets/topology.js', import.meta.url), 'utf8');
function extract(name) {
  const start = source.indexOf(`function ${name}(`);
  const tail = source.slice(start);
  const end = /\r?\n\}/.exec(tail);
  return tail.slice(0, end.index + end[0].length);
}

test('device checkbox change preserves focus by device identity through replacement and filtering', () => {
  const doc = { activeElement: null };
  let toggles = [];
  const container = {
    contains: (element) => toggles.includes(element),
    set innerHTML(html) {
      toggles = [...html.matchAll(/<input id="([^"]+)"[^>]*data-node-toggle="([^"]+)"[^>]*>/g)].map((match) => ({
        id: match[1], dataset: { nodeToggle: match[2] }, disabled: match[0].includes('disabled'),
        checked: match[0].includes('checked'),
        addEventListener(name, handler) { this[name] = handler; },
        focus(options) { doc.activeElement = this; this.focusOptions = options; },
      }));
    },
    querySelectorAll: (selector) => selector === '[data-node-toggle]' ? toggles : [],
  };
  const state = { nodeFilter: '', capabilities: { nodes: [
    { key: 'site/a', label: 'First', site: 'x', device_type: 'router' },
    { key: 'site/b', label: 'Second', site: 'x', device_type: 'router' },
  ] }, selectedNodeKeys: new Set(), pending: false };
  const deps = { state, document: doc, byId: (id) => id === 'mn-node-index' ? container : null,
    escapeHtml, selectedResultNodes: () => [], nodePlan: () => ({}), nodeHealth: () => 'good',
    navigationHref: () => '/', markTopologyQueryDirty() {}, renderMetrics() {}, renderMap() {}, syncUrl() {}, focusNode() {} };
  const render = new Function(...Object.keys(deps), `${extract('renderCapabilityNodeIndex')} return renderCapabilityNodeIndex;`)(...Object.values(deps));
  render();
  const old = toggles[1];
  old.focus();
  old.checked = true;
  old.change({ currentTarget: old });
  assert.notEqual(doc.activeElement, old);
  assert.equal(doc.activeElement.dataset.nodeToggle, 'site/b');
  assert.equal(doc.activeElement.checked, true);
  assert.deepEqual(doc.activeElement.focusOptions, { preventScroll: true });
  const stableId = doc.activeElement.id;
  state.nodeFilter = 'second';
  render();
  assert.equal(doc.activeElement.id, stableId);
  const external = {};
  doc.activeElement = external;
  render();
  assert.equal(doc.activeElement, external);
});

test('Use in trace refreshes scenario guidance after applying the row scenario', () => {
  const elements = new Map();
  const byId = (id) => {
    if (!elements.has(id)) elements.set(id, { value: '', textContent: '', scrollIntoView() {} });
    return elements.get(id);
  };
  const scenarios = [{ scenario_id: 'old', description: 'Old guidance' }, { scenario_id: 'new', description: 'New guidance' }];
  const state = { routeCapabilities: { scenarios }, routeTableSnapshot: { items: [{
    route_entry_id: 'row', traceable: true, trace_query: { scenario_id: 'new' }, prefix: '10.0.0.0/24',
  }] } };
  byId('mn-route-scenario').value = 'old';
  byId('mn-route-scenario-description').textContent = 'Old guidance';
  const deps = { state, byId, selectedRouteScenario: () => scenarios.find((s) => s.scenario_id === byId('mn-route-scenario').value),
    routeEndpointSeedValue: () => '', routeStartSeedValue: () => '', renderRouteSteeringProfiles() {},
    setRouteEndpointInput() {}, setRouteStartInput() {}, syncRouteStartControlState() {}, ensureRouteSelectValue() {}, invalidateRouteTraceResult() {}, syncUrl() {},
    matchMedia: () => ({ matches: true }), showToast() {} };
  const use = new Function(...Object.keys(deps), `${extract('renderRouteScenarioGuide')} ${extract('useRouteTableEntry')} return useRouteTableEntry;`)(...Object.values(deps));
  use('row');
  assert.equal(byId('mn-route-scenario').value, 'new');
  assert.equal(byId('mn-route-scenario-description').textContent, 'New guidance');
  state.routeTableSnapshot.items[0].trace_query.scenario_id = 'unknown';
  use('row');
  assert.equal(byId('mn-route-scenario-description').textContent, 'New guidance');
});

function inspectorHarness() {
  const rect = (left, top, width, height) => ({ left, top, width, height, right: left + width, bottom: top + height });
  const document = { activeElement: null, body: {}, querySelector: () => ({ getBoundingClientRect: () => rect(0, 0, 1265, 76) }) };
  const classes = new Set();
  let close, rectangle = rect(300, 240, 100, 60);
  const card = { hidden: true, style: {}, scrollTop: 0, scrollHeight: 700, parentElement: document.body,
    classList: { add: (name) => classes.add(name), remove: (name) => classes.delete(name),
      contains: (name) => classes.has(name), toggle(name, enabled) { enabled ? classes.add(name) : classes.delete(name); } },
    setAttribute() {}, contains: (target) => target === close,
    set innerHTML(value) { close = value ? { addEventListener() {}, focus() { document.activeElement = this; } } : null; },
    querySelector: () => close };
  const stage = { clientLeft: 1, clientTop: 1, clientWidth: 898, clientHeight: 498,
    getBoundingClientRect: () => rect(100, 100, 900, 500),
    querySelectorAll: () => [anchor], dataset: {}, style: { setProperty() {} } };
  const anchor = { isConnected: true, dataset: { topologyInspectKey: 'subnet' },
    getBoundingClientRect: () => rectangle, closest: () => stage };
  const view = { scale: 1, panX: 0, panY: 0 };
  const state = { topologyInspectorItems: new Map([['subnet', { title: 'Subnet' }]]),
    topologyInspectorPositionFrame: null, graphViews: { topology: view } };
  const byId = (id) => id === 'mn-topology-hover-card' ? card : stage;
  const frames = [];
  const deps = { state, document, byId, window: { innerWidth: 1265, innerHeight: 720 },
    requestAnimationFrame: (fn) => { frames.push(fn); return frames.length; }, cancelAnimationFrame() {},
    clearTimeout() {}, topologyInspectorMarkup: () => 'Inspector', clearTopologyRelationshipContext() {},
    applyTopologyRelationshipContext() {}, graphViewportElements: () => ({ layers: [], readout: null }) };
  const names = ['positionTopologyInspector', 'scheduleTopologyInspectorPosition', 'cancelTopologyInspectorPosition',
    'clearTopologyInspector', 'showTopologyInspector', 'capturePinnedTopologyInspector', 'restorePinnedTopologyInspector', 'applyGraphTransform'];
  const api = new Function(...Object.keys(deps), `${names.map(extract).join('\n')} return {${names.join(',')}};`)(...Object.values(deps));
  return { api, state, document, card, anchor, view, frames, byId, rect, move: (value) => { rectangle = value; } };
}

test('pinned inspector redraw preserves external filter focus and restores only its own focus', () => {
  const h = inspectorHarness();
  h.api.showTopologyInspector('subnet', h.anchor, true);
  assert.equal(h.card.contains(h.document.activeElement), true, 'explicit activation enters the inspector');
  const filter = { value: 'p' };
  h.document.activeElement = filter;
  h.card.scrollTop = 87;
  let snapshot = h.api.capturePinnedTopologyInspector();
  h.api.clearTopologyInspector();
  h.api.restorePinnedTopologyInspector(snapshot);
  h.document.activeElement.value += '1';
  assert.equal(filter.value, 'p1');
  assert.equal(h.card.scrollTop, 87);
  assert.equal(h.card.hidden, false);
  h.card.querySelector().focus();
  snapshot = h.api.capturePinnedTopologyInspector();
  const oldClose = h.document.activeElement;
  h.api.clearTopologyInspector();
  h.api.restorePinnedTopologyInspector(snapshot);
  assert.notEqual(h.document.activeElement, oldClose);
  assert.equal(h.card.contains(h.document.activeElement), true);
  const pinnedClose = h.document.activeElement;
  h.card.scrollTop = 121;
  h.api.showTopologyInspector('subnet', h.anchor, false, { clientX: 350, clientY: 250 });
  assert.notEqual(h.document.activeElement, pinnedClose);
  assert.equal(h.card.contains(h.document.activeElement), true, 'passive reentry preserves the pin\'s existing keyboard ownership');
  assert.equal(h.card.scrollTop, 121);
  h.document.activeElement = filter;
  h.api.showTopologyInspector('subnet', h.anchor);
  assert.equal(h.document.activeElement, filter, 'hover/focus preview of an existing pin is passive');
});

test('graph transforms dismiss fully clipped pins on every boundary without reviving them on return', () => {
  for (const [left, top] of [[-100, 240], [1100, 240], [300, -100], [300, 610]]) {
    const h = inspectorHarness();
    h.api.showTopologyInspector('subnet', h.anchor, true);
    h.move(h.rect(left, top, 100, 60));
    h.api.applyGraphTransform('mn-map-stage', 'topology');
    assert.equal(h.card.hidden, true);
    assert.equal(h.state.topologyInspectorPinned, false);
    h.move(h.rect(300, 240, 100, 60));
    h.api.applyGraphTransform('mn-map-stage', 'topology');
    assert.equal(h.card.hidden, true);
  }
});

test('partial anchors and zero-height SVG strokes remain inspectable without covering the sticky header', () => {
  const h = inspectorHarness();
  h.move(h.rect(90, 110, 20, 0));
  h.api.showTopologyInspector('subnet', h.anchor, true);
  assert.equal(h.card.hidden, false);
  assert.ok(parseFloat(h.card.style.top) >= 88);
  assert.ok(parseFloat(h.card.style.top) + parseFloat(h.card.style.maxHeight) <= 708);
  h.anchor.isConnected = false;
  h.api.positionTopologyInspector(h.anchor);
  assert.equal(h.card.hidden, true);
});

test('document scroll repositions the existing pin but inspector detail scroll preserves it', () => {
  const h = inspectorHarness();
  const start = source.indexOf('  document.addEventListener("scroll",');
  const end = source.indexOf('\n}', start);
  h.document.addEventListener = (type, handler, options) => {
    assert.equal(type, 'scroll');
    assert.deepEqual(options, { capture: true, passive: true });
    h.document.scroll = handler;
  };
  new Function('document', 'state', 'byId', 'scheduleTopologyInspectorPosition', source.slice(start, end))(
    h.document, h.state, h.byId, h.api.scheduleTopologyInspectorPosition);
  h.api.showTopologyInspector('subnet', h.anchor, true);
  h.card.scrollTop = 120;
  h.document.scroll({ target: h.document.activeElement });
  assert.equal(h.frames.length, 0);
  h.move(h.rect(300, 0, 100, 60));
  h.document.scroll({ target: h.document });
  h.frames.shift()();
  assert.equal(h.card.hidden, true, 'the header occludes the anchor after page scrolling');
});
