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
    setRouteEndpointInput() {}, setRouteStartInput() {}, ensureRouteSelectValue() {}, invalidateRouteTraceResult() {}, syncUrl() {},
    matchMedia: () => ({ matches: true }), showToast() {} };
  const use = new Function(...Object.keys(deps), `${extract('renderRouteScenarioGuide')} ${extract('useRouteTableEntry')} return useRouteTableEntry;`)(...Object.values(deps));
  use('row');
  assert.equal(byId('mn-route-scenario').value, 'new');
  assert.equal(byId('mn-route-scenario-description').textContent, 'New guidance');
  state.routeTableSnapshot.items[0].trace_query.scenario_id = 'unknown';
  use('row');
  assert.equal(byId('mn-route-scenario-description').textContent, 'New guidance');
});
