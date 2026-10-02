import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { escapeHtml } from '../assets/shared.js';
const source = readFileSync(new URL('../assets/topology.js', import.meta.url), 'utf8');
function extract(name) {
  const start = source.indexOf(`function ${name}(`);
  const tail = source.slice(source.slice(Math.max(0, start - 6), start) === "async " ? start - 6 : start);
  const ending = /\r?\n\}/.exec(tail);
  return tail.slice(0, ending.index + ending[0].length);
}
function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}
function harness({ fail = false } = {}) {
  const caps = deferred();
  const tables = deferred();
  const requests = [];
  const state = {
    topologyRequestGeneration: 0, routeRequestGeneration: 0,
    reconstructionTimelineCommitTimer: null, routeTableOpenNodes: new Set(),
    routeCapabilitiesPromise: caps.promise,
  };
  const effects = { renders: [], tableQueries: [], traces: 0 };
  const elements = new Map();
  const byId = (id) => {
    if (!elements.has(id)) elements.set(id, { textContent: '', disabled: false });
    return elements.get(id);
  };
  let context = 0;
  const dependencies = {
    state, byId, clearTimeout, immutableSnapshot: structuredClone,
    buildQueryRequest: () => ({ basis: { kind: 'capture' }, node_queries: [{ node_id: 'a' }] }),
    analysisLoadProgress: { begin() {}, end() {} },
    replaceAbortController: (previous) => { previous?.abort(); return new AbortController(); },
    reconstruct: async (request) => { if (fail) throw new Error('reconstruction failed'); return ({ context_id: `ctx-${++context}`, request, nodes: [{ key: 'a' }], source_mode: 'api' }); },
    queryRouteTables: async (query, signal) => {
      effects.tableQueries.push({ query, signal });
      const response = deferred();
      requests.push(response);
      return response.promise;
    },
    isAbortError: (error) => error.name === 'AbortError',
    renderAll: () => effects.renders.push(state.query.context_id),
    runRouteTrace: () => { effects.traces++; },
  };
  for (const name of ['renderReconstructionTimeline', 'clearRoutePacketSelection', 'clearRoutePathPreview', 'clearRouteHover', 'setFormBusy', 'renderSourceBanner', 'renderCapabilityNodeIndex', 'renderRouteTables', 'syncUrl']) dependencies[name] = () => {};
  const methods = new Function(...Object.keys(dependencies), `${extract('loadRouteTables')}\n${extract('runQuery')}\nreturn { runQuery };`)(...Object.values(dependencies));
  return { ...methods, state, effects, caps, tables, requests };
}
const settle = async () => { await new Promise((resolve) => setImmediate(resolve)); };
test('committed topology renders while route capabilities and tables remain pending; tracing is explicit', async () => {
  const h = harness();
  await h.runQuery();
  assert.deepEqual(h.effects.renders, ['ctx-1']);
  assert.equal(h.state.pending, false);
  assert.equal(h.state.routeTablePending, true);
  assert.equal(h.effects.tableQueries.length, 0);
  h.caps.resolve();
  await settle();
  assert.equal(h.effects.tableQueries[0].query.context_id, 'ctx-1');
  assert.equal(h.state.routeTablePending, true);
  h.requests[0].resolve({ items: ['ready'] });
  await settle();
  assert.deepEqual(h.state.routeTableSnapshot, { items: ['ready'] });
  assert.equal(h.effects.traces, 0);
});
test('superseded reconstruction cancels route loading before capabilities resolve', async () => {
  const h = harness();
  await h.runQuery();
  const obsolete = h.state.routeTableAbortController;
  await h.runQuery();
  assert.equal(obsolete.signal.aborted, true);
  h.caps.resolve();
  await settle();
  assert.deepEqual(h.effects.tableQueries.map(({ query }) => query.context_id), ['ctx-2']);
  h.requests[0].resolve({ context_id: 'ctx-2' });
  await settle();
  assert.equal(h.state.routeTableSnapshot.context_id, 'ctx-2');
});

test('a late response from the previous topology cannot publish route tables', async () => {
  const h = harness();
  h.caps.resolve();
  await h.runQuery();
  await settle();
  await h.runQuery();
  await settle();
  h.requests[1].resolve({ context_id: 'ctx-2' });
  await settle();
  h.requests[0].resolve({ context_id: 'ctx-1' });
  await settle();
  assert.equal(h.state.routeTableSnapshot.context_id, 'ctx-2');
});
test('reconstruction failure releases the table controller', async () => {
  const h = harness({ fail: true });
  await h.runQuery();
  assert.equal(h.state.routeTableAbortController, null);
  assert.equal(h.state.routeTablePending, false);
  assert.equal(h.effects.tableQueries.length, 0);
});
test('initialization reconstructs topology before slow route capability discovery completes', async () => {
  const caps = deferred();
  const state = {};
  const effects = { reconstructed: false, routeControls: 0 };
  const byId = () => ({ textContent: '' });
  const deps = {
    state, byId, analysisLoadProgress: { begin() {}, end() {} },
    discoverCapabilities: async () => ({ source_mode: 'api' }),
    bootstrapFromCapabilities: () => ({ workspace: {} }),
    discoverRouteCapabilities: () => caps.promise,
    renderControls() {}, initializeNodeSelection() {}, bindControls() {},
    renderSourceBanner() {}, renderCapabilityNodeIndex() {}, setFormBusy() {},
    renderRouteControls() { effects.routeControls++; },
    runQuery: async () => { effects.reconstructed = true; },
  };
  const initialize = new Function(...Object.keys(deps), `${extract('initialize')}\nreturn initialize;`)(...Object.values(deps));
  await initialize();
  assert.equal(effects.reconstructed, true);
  assert.equal(state.routeCapabilitiesPending, true);
  assert.equal(state.routeCapabilities, undefined);
  caps.resolve({ scenarios: [] });
  await state.routeCapabilitiesPromise;
  assert.equal(state.routeCapabilitiesPending, false);
  assert.equal(effects.routeControls, 2);
});
test('route controls restore advertised availability when capabilities arrive during reconstruction', async () => {
  const caps = deferred();
  const query = deferred();
  const state = {};
  const control = { disabled: true, dataset: {} };
  const byId = () => ({ textContent: '', querySelectorAll: () => [control] });
  const busyStart = source.indexOf('function setFormBusy(');
  const tail = source.slice(busyStart);
  const ending = /\r?\n\}/.exec(tail);
  const setFormBusy = new Function('byId', `${tail.slice(0, ending.index + ending[0].length)}\nreturn setFormBusy;`)(byId);
  const deps = {
    state, byId, setFormBusy, analysisLoadProgress: { begin() {}, end() {} },
    discoverCapabilities: async () => ({ source_mode: 'api' }),
    bootstrapFromCapabilities: () => ({ workspace: {} }), discoverRouteCapabilities: () => caps.promise,
    renderControls() {}, initializeNodeSelection() {}, bindControls() {}, renderSourceBanner() {}, renderCapabilityNodeIndex() {},
    renderRouteControls() { control.disabled = !state.routeCapabilities; },
    runQuery: async () => {
      state.pending = true;
      setFormBusy('mn-route-form', true);
      await query.promise;
      state.pending = false;
      setFormBusy('mn-route-form', false);
    },
  };
  const initialize = new Function(...Object.keys(deps), `${extract('initialize')}\nreturn initialize;`)(...Object.values(deps));
  const initialization = initialize();
  await settle();
  assert.equal(control.disabled, true);
  caps.resolve({ scenarios: [] });
  await state.routeCapabilitiesPromise;
  assert.equal(control.disabled, true);
  assert.equal(control.dataset.disabledBeforeBusy, 'false');
  query.resolve();
  await initialization;
  assert.equal(control.disabled, false);
});
test('trace rendering preserves pending and unavailable resolver messages', () => {
  const state = { routeTrace: null, routePending: false, routeCapabilities: null, routeCapabilitiesPending: true };
  const elements = new Map();
  const byId = (id) => {
    if (!elements.has(id)) elements.set(id, { innerHTML: '', hidden: false });
    return elements.get(id);
  };
  const deps = { state, byId, document: { querySelector: () => ({ hidden: false }) }, escapeHtml: (value) => String(value).replaceAll('<', '&lt;'),
    renderDirectionTabs() {}, renderRouteSeed() {}, updateRouteViewChrome() {}, renderRouteOutcome() {}, renderRoutePacketEvolution() {},
  };
  const render = new Function(...Object.keys(deps), `${extract('routeCapabilityEmptyMarkup')}\n${extract('renderRouteTrace')}\nreturn renderRouteTrace;`)(...Object.values(deps));
  render();
  assert.match(byId('mn-route-empty').innerHTML, /Loading route capabilities/);
  assert.doesNotMatch(byId('mn-route-empty').innerHTML, /Choose a trace start/);
  state.routeCapabilitiesPending = false;
  state.routeCapabilityError = '<resolver unavailable>';
  render();
  assert.match(byId('mn-route-empty').innerHTML, /not advertised/);
  assert.match(byId('mn-route-empty').innerHTML, /&lt;resolver unavailable>/);
  state.routeCapabilities = {};
  render();
  assert.match(byId('mn-route-empty').innerHTML, /Choose a trace start/);
});

test('failed discovery clears loading placeholders and offers explicit retry and node navigation', async () => {
  const state = {};
  const elements = new Map();
  const effects = { ended: false, reloads: 0, busy: [] };
  const byId = (id) => {
    if (!elements.has(id)) elements.set(id, {
      textContent: '', innerHTML: '', classList: { add() {} },
      addEventListener(type, listener) { this[type] = listener; },
    });
    return elements.get(id);
  };
  const deps = {
    state, byId, escapeHtml,
    discoverCapabilities: async () => { throw new Error('<provider unavailable>'); },
    analysisLoadProgress: { begin() { return 3; }, end(lease) { assert.equal(lease, 3); effects.ended = true; } },
    setFormBusy: (id, value) => effects.busy.push([id, value]),
    location: { reload() { effects.reloads++; } },
  };
  const initialize = new Function(...Object.keys(deps), `${extract('initialize')}\nreturn initialize;`)(...Object.values(deps));
  await initialize();
  assert.equal(state.apiMode, 'error');
  assert.equal(state.pending, false);
  assert.equal(byId('mn-revision').textContent, 'Unavailable');
  assert.equal(byId('mn-node-selection-summary').textContent, 'Devices unavailable');
  assert.equal(byId('mn-route-api-status').textContent, 'unavailable');
  assert.match(byId('mn-route-empty').textContent, /unavailable/);
  const banner = byId('mn-source-banner').innerHTML;
  assert.match(banner, /&lt;provider unavailable&gt;/);
  assert.match(banner, /href="\/node"/);
  assert.doesNotMatch(banner, /mn-spinner/);
  assert.equal(effects.ended, true);
  assert.equal(effects.reloads, 0);
  byId('mn-startup-retry').click();
  assert.equal(effects.reloads, 1);
});

test('timeouts never replay discovery, reconstruction or route tables through endpoint aliases', async () => {
  for (const name of ['discoverCapabilities', 'reconstruct', 'queryRouteTables']) {
    const timeout = Object.assign(new Error('deadline'), { name: 'TimeoutError' });
    const calls = [];
    const request = { basis: {}, node_queries: [{ node_id: 'a', revision_id: 'r1' }] };
    const deps = {
      state: { bootstrap: { workspace: { revision_id: 'r1' } }, capabilities: { source_mode: 'global-api' }, routeCapabilities: { route_table_query_href: '/advertised' } },
      location: { search: '?revision_id=r1' }, URLSearchParams,
      api: async (path) => { calls.push(path); throw timeout; },
      fetchRouteTablePages: async (path) => { calls.push(path); throw timeout; },
      normalizeCapabilities: (value) => value,
      topologyAssemblyId: () => 'assembly', firstArray: (items) => items,
      ROUTE_TABLE_QUERY_LIMIT: 500, isAbortError: (error) => error.name === 'AbortError',
    };
    const invoke = new Function(...Object.keys(deps), `${extract(name)}\nreturn ${name};`)(...Object.values(deps));
    await assert.rejects(invoke(name === 'queryRouteTables' ? { request } : request), (error) => error === timeout);
    assert.equal(calls.length, 1, name);
  }
});
