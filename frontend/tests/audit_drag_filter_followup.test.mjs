import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

// Controlled handler tests complement native-browser audit evidence. The DOM
// facade delivers HTML drag events; it cannot establish native event delivery.
const source = readFileSync(new URL('../assets/app.js', import.meta.url), 'utf8');
const noop = () => {};
const settle = () => new Promise(resolve => setImmediate(resolve));
function production(name) {
  const match = new RegExp(`^(?:async )?function ${name}\\(`, 'm').exec(source);
  assert.ok(match, name);
  const tail = source.slice(match.index);
  return tail.slice(0, /\n(?:async )?function \w+\(/.exec(tail)?.index);
}
function load(names, deps, registration = '') {
  return new Function(...Object.keys(deps), `${names.map(production).join('\n')}\n${registration}\nreturn {${names.join(',')}};`)(...Object.values(deps));
}
function element(dataset = {}) {
  const classes = new Set();
  const listeners = new Map();
  return {
    dataset, value: '', tagName: 'BUTTON', attrs: {}, children: [], html: '',
    classList: { add: (...values) => values.forEach(v => classes.add(v)), remove: (...values) => values.forEach(v => classes.delete(v)),
      contains: value => classes.has(value), toggle(value, on) { if (on) classes.add(value); else classes.delete(value); } },
    addEventListener(type, listener) { listeners.set(type, listener); },
    emit(type, event = {}) { return listeners.get(type)?.({ preventDefault: noop, ...event }); },
    setAttribute(name, value) { this.attrs[name] = value; },
    getAttribute(name) { return this.attrs[name]; },
    contains(item) { return this.children.includes(item); },
    closest() { return this.parent || null; },
    querySelectorAll(selector) {
      if (selector === '.plugin-dashboard-module') return this.children.filter(item => item.module);
      const attribute = /^\[data-([a-z-]+)\]$/.exec(selector)?.[1];
      const key = attribute?.replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
      return key ? this.children.filter(item => item.dataset[key] !== undefined) : [];
    },
    querySelector() { return null; },
    set innerHTML(value) { this.html = value; this.parse?.(value); },
    get innerHTML() { return this.html; },
  };
}
function attributes(markup) {
  return Object.fromEntries([...markup.matchAll(/data-([a-z-]+)="([^"]*)"/g)].map(([, key, value]) => [key.replace(/-([a-z])/g, (_, c) => c.toUpperCase()), value]));
}
const ids = ['scale-overview', 'forwarding-population', 'event-phases'];
function harness(initialKind = 'NEIGHBOR') {
  const elements = Object.fromEntries(['resource-table-wrap', 'resource-type-tabs', 'resource-search', 'resource-table-summary',
    'dashboard-index', 'dashboard-modules', 'dashboard-time-status', 'reset-dashboard-layout'].map(id => [id, element()]));
  elements['resource-type-tabs'].parse = function (html) {
    this.children = [...html.matchAll(/<button[^>]*data-kind="([^"]+)"[^>]*aria-selected="([^"]+)"/g)]
      .map(([, kind, selected]) => Object.assign(element({ kind }), { selected }));
  };
  elements['dashboard-index'].parse = function (html) {
    this.children = [...html.matchAll(/<button[^>]*data-dashboard-open="[^"]+"[^>]*>/g)].map(([tag]) => element(attributes(tag)));
  };
  elements['dashboard-modules'].parse = function (html) {
    this.children = [];
    for (const [index, part] of html.split('<article class="plugin-dashboard-module ').slice(1).entries()) {
      const id = /data-dashboard-id="([^"]+)"/.exec(part)[1];
      const module = Object.assign(element({ dashboardId: id }), { module: true, getBoundingClientRect: () => ({ top: index * 200, height: 180 }) });
      this.children.push(module);
      for (const [tag] of part.matchAll(/<(?:button|span)[^>]*data-dashboard-(?:drag|move|close|expand|resource-id)="[^"]+"[^>]*>/g)) {
        const control = element(attributes(tag)); control.parent = module;
        control.disabled = /\sdisabled(?:\s|>)/.test(tag);
        this.children.push(control); module.children.push(control);
      }
    }
  };
  const payload = {
    time_ns: '720', population_count: 7510,
    dashboards: ids.map((id, index) => ({ dashboard_id: id,
      statistics: [{ statistic_id: 'population', value: 100 + index, matching_count: 100 + index, sample_count: 100 + index }],
      tables: [{ table_id: 'rows', items: [{ resource_id: `${id}/item`, label: `${id} row` }], total_count: 100 + index, truncated: true }],
    })),
  };
  const state = {
    cursorNs: 720n, selectedResourceKind: initialKind, selectedResourceViewId: null,
    resourceTableSelectionReady: true, resourceRequestId: 0, resourceOffset: 500, resourcePending: false,
    resourceReturnedTimeNs: 720n, resourceQuery: { time_ns: '720', items: [], counts_by_kind: { NEIGHBOR: 4000, IP_ROUTING: 3, DTE: 400, VIRTUAL_INTERFACE: 6, MPLS_BINDING: 8 } },
    dashboardLayoutReady: true, dashboardOrder: [...ids], openDashboardIds: new Set(ids), expandedDashboardIds: new Set(ids),
    dashboardPending: false, dashboardRequestId: 0, dashboardReturnedTimeNs: 720n, dashboardQuery: payload,
    dataset: { scale: { metrics: { archive: 1250005 } }, schema: { dashboards: ids.map(id => ({ dashboard_id: id, title: id,
      statistics: [{ statistic_id: 'archive', scale_metric: 'archive' }, { statistic_id: 'population', aggregation: 'count' }],
      tables: [{ table_id: 'rows', columns: [{ field: 'label' }] }],
    })) } },
  };
  const calls = [], timers = new Map(); let timerId = 0, saves = 0;
  const deps = {
    state, document: { activeElement: null, body: {} }, byId: id => elements[id],
    isScaleMode: () => true, isTopologyNodeSnapshot: () => false,
    abortLatestRequests: key => state[key]?.abort(), beginLatestRequest: key => state[key] = new AbortController(),
    finishLatestRequest: (key, controller) => { if (state[key] === controller) state[key] = null; },
    requestWasAborted: (_error, controller) => controller.signal.aborted,
    analysisRuntimeApi: (path, options) => {
      const call = { path, body: JSON.parse(options.body), signal: options.signal }; calls.push(call);
      if (path === 'dashboards/query') return Promise.resolve({ ...payload, dashboards: payload.dashboards.filter(d => call.body.dashboard_ids.includes(d.dashboard_id)) });
      return new Promise(resolve => { call.resolve = resolve; });
    },
    revisionPath: x => x, clampNs: x => x, toNs: (x, fallback) => x == null ? fallback : BigInt(x), formatOffset: String,
    window: { clearTimeout: id => timers.delete(id), setTimeout: callback => { timers.set(++timerId, callback); return timerId; } },
    initializeResourceTableView: noop, resourceTableViewDescriptors: () => [], canonicalResourceId: x => x,
    registerResource: noop, resourceLabel: (_item, id) => id, escapeHtml: String, humanResourceType: String, humanLayer: String, titleCase: String,
    presentationColumns: kind => [{ label: `${kind} field`, field: 'kind' }], presentationTags: () => new Set(),
    resourcePageDetails: query => ({ returned: query.items.length, first: query.items.length ? 1 : 0, last: query.items.length }),
    resourcePaginationMarkup: () => '', bindResourcePagination: noop, bindLaneVisibilityCheckboxes: noop,
    laneVisibilityCheckbox: () => '', resourceExistenceLabel: () => 'yes', stateChipClassName: () => '',
    formatResourceTableCell: item => item.kind, MAX_RESOURCE_ROWS: 500,
    initializeDashboardLayout: noop, saveDashboardLayout: () => { saves++; }, dashboardDescriptorErrorMessage: () => null,
    dashboardFieldValue: (item, field) => item[field], formatValue: String, selectResource: noop,
  };
  const inputStart = source.indexOf('  byId("resource-search").addEventListener("input",');
  const inputEnd = source.indexOf('\n  byId("reset-dashboard-layout")', inputStart);
  assert.ok(inputStart > 0 && inputEnd > inputStart);
  const api = load(['requestResources', 'markResourcesPending', 'settleResourceRequest', 'refreshResourceTimePresentation',
    'resourceDisplayTimeNs', 'resourceTimeSummary', 'renderResourceTables', 'dashboardDescriptors', 'dashboardResultFor',
    'dashboardStatisticResult', 'formatDashboardStatistic', 'renderDashboardStatistic', 'renderDashboardTable', 'formatDashboardCell',
    'dashboardDisplayTimeNs', 'dashboardTimeSummary', 'refreshDashboardTimePresentation', 'renderPluginDashboards',
    'placeDashboard', 'moveDashboard', 'toggleDashboardOpen', 'toggleDashboardExpanded', 'requestDashboards',
    'dashboardNeedsPointInTimeQuery', 'dashboardQueryIds', 'markDashboardsPending', 'settleDashboardRequest'], deps, source.slice(inputStart, inputEnd));
  api.renderResourceTables(); api.renderPluginDashboards();
  return { api, state, elements, calls, saves: () => saves,
    search(value) { elements['resource-search'].value = value; elements['resource-search'].emit('input'); },
    flushSearch() { const callbacks = [...timers.values()]; timers.clear(); return callbacks.map(callback => callback()); },
    kind(kind) { const button = elements['resource-type-tabs'].children.find(b => b.dataset.kind === kind); assert.ok(button, `available kind ${kind}`); button.emit('click'); },
    control(key, value, id) { return elements['dashboard-modules'].children.find(c => c.dataset[key] === value && (!id || c.dataset.dashboardId === id)); },
    module(id) { return elements['dashboard-modules'].children.find(c => c.module && c.dataset.dashboardId === id); },
    moduleOrder() { return elements['dashboard-modules'].children.filter(c => c.module).map(c => c.dataset.dashboardId); },
  };
}

for (const [original, search, next] of [['NEIGHBOR', 'peer-00000', 'VIRTUAL_INTERFACE'], ['IP_ROUTING', 'blue', 'MPLS_BINDING']]) {
  for (const staleLast of [true, false]) test(`${original}: pending search input followed by actual kind click rejects stale ${staleLast ? 'late' : 'early'} response`, async () => {
    const h = harness(original);
    h.search(search); const [oldRequest] = h.flushSearch();
    assert.equal(h.state.resourcePending, true);
    assert.deepEqual(h.calls[0].body, { time_ns: '720', kinds: [original], search, limit: 500, offset: 0 });
    h.kind(next);
    assert.equal(h.calls.length, 2); assert.equal(h.calls[0].signal.aborted, true);
    const stale = { time_ns: '111', items: [{ resource_id: 'stale', kind: original, label: search }], counts_by_kind: { [original]: 9 } };
    const fresh = { time_ns: '720', items: [{ resource_id: 'fresh', kind: next, label: search }], counts_by_kind: { [next]: 1, [original]: 9 } };
    if (!staleLast) { h.calls[0].resolve(stale); await oldRequest; assert.equal(h.state.resourcePending, true); }
    h.calls[1].resolve(fresh); await settle();
    if (staleLast) { h.calls[0].resolve(stale); await oldRequest; }
    assert.equal(h.state.resourceQuery, fresh); assert.equal(h.state.resourceReturnedTimeNs, 720n);
    assert.equal(h.state.selectedResourceKind, next); assert.equal(h.state.resourcePending, false);
    assert.match(h.elements['resource-table-wrap'].innerHTML, new RegExp(`${next} field`));
    assert.match(h.elements['resource-table-wrap'].innerHTML, /data-resource-id="fresh"/);
    assert.doesNotMatch(h.elements['resource-table-wrap'].innerHTML, /stale/);
    h.search(''); const [clearRequest] = h.flushSearch();
    h.calls[2].resolve({ ...fresh, counts_by_kind: { [next]: 1, [original]: 9 } }); await clearRequest;
    h.kind(original);
    const restored = { time_ns: '720', items: [{ resource_id: 'restored', kind: original }], counts_by_kind: { [original]: 9, [next]: 1 } };
    h.calls[3].resolve(restored); await settle();
    assert.equal(h.state.resourceQuery, restored);
    assert.match(h.elements['resource-table-wrap'].innerHTML, new RegExp(`${original} field`));
    assert.equal(h.elements['resource-type-tabs'].children.find(b => b.dataset.kind === original).selected, 'true');
  });
}

for (const id of ids) test(`${id}: HTML drag handlers reorder once, clear styles, and retain keyboard recovery`, () => {
  const h = harness();
  for (const before of [false, true]) {
    const original = [...h.state.dashboardOrder];
    const targetId = original.find(candidate => candidate !== id && (before || original.indexOf(candidate) > original.indexOf(id))) || original[0];
    const handle = h.control('dashboardDrag', id), target = h.module(targetId);
    const data = new Map(), transfer = { setData: (key, value) => data.set(key, value) };
    let prevented = 0;
    handle.emit('dragstart', { dataTransfer: transfer });
    assert.equal(h.state.draggedDashboardId, id); assert.equal(data.get('text/plain'), id); assert.equal(transfer.effectAllowed, 'move');
    assert.equal(h.module(id).classList.contains('is-dragging'), true);
    const rect = target.getBoundingClientRect();
    target.emit('dragover', { clientY: rect.top + rect.height * (before ? 0.25 : 0.75), dataTransfer: transfer, preventDefault: () => { prevented++; } });
    assert.equal(target.classList.contains(before ? 'drop-before' : 'drop-after'), true);
    const saves = h.saves();
    target.emit('drop', { preventDefault: () => { prevented++; } });
    handle.emit('dragend');
    const expected = original.filter(candidate => candidate !== id);
    expected.splice(expected.indexOf(targetId) + (before ? 0 : 1), 0, id);
    assert.deepEqual(h.state.dashboardOrder, expected); assert.deepEqual(h.moduleOrder(), expected);
    assert.equal(h.saves(), saves + 1); assert.equal(prevented, 2); assert.equal(h.state.draggedDashboardId, null);
    for (const moduleId of ids) for (const name of ['is-dragging', 'drop-before', 'drop-after']) assert.equal(h.module(moduleId).classList.contains(name), false);
    const direction = expected.indexOf(id) > 0 ? '-1' : '1';
    h.control('dashboardMove', direction, id).emit('click');
    assert.equal(h.state.dashboardOrder.indexOf(id), expected.indexOf(id) + Number(direction));
    h.control('dashboardMove', String(-Number(direction)), id).emit('click');
    assert.deepEqual(h.moduleOrder(), expected);
    assert.deepEqual(h.elements['dashboard-index'].children.map(c => c.dataset.dashboardOpen), expected);
  }
});

for (const id of ids) test(`${id}: no-match resource filtering and close/reopen preserve nonempty authoritative population`, async () => {
  const h = harness();
  const descriptor = h.state.dataset.schema.dashboards.find(item => item.dashboard_id === id);
  const body = () => descriptor.statistics.map(stat => h.api.renderDashboardStatistic(stat, id)).join('') + h.api.renderDashboardTable(descriptor.tables[0], id);
  const baseline = body();
  assert.match(baseline, /1,250,005/); assert.match(baseline, /Showing 1 of 10[012]/);
  assert.match(baseline, /authoritative population at 720/);
  h.search('AUDIT600_NO_SUCH_RESOURCE_9c74'); const [request] = h.flushSearch();
  h.calls[0].resolve({ time_ns: '720', items: [], counts_by_kind: {} }); await request;
  assert.deepEqual(h.elements['resource-type-tabs'].children.map(b => b.dataset.kind), ['NEIGHBOR']);
  assert.match(h.elements['resource-table-wrap'].innerHTML, /No resources match/);
  h.api.renderPluginDashboards(); assert.equal(body(), baseline);
  h.control('dashboardClose', id).emit('click'); await settle();
  assert.equal(h.module(id), undefined);
  h.elements['dashboard-index'].children.find(c => c.dataset.dashboardOpen === id).emit('click'); await settle();
  assert.ok(h.module(id)); assert.equal(body(), baseline);
  const dashboardCalls = h.calls.filter(call => call.path === 'dashboards/query');
  assert.equal(dashboardCalls.length, 2);
  for (const call of dashboardCalls) assert.deepEqual(Object.keys(call.body).sort(), ['dashboard_ids', 'time_ns']);
  h.search(''); const [clearRequest] = h.flushSearch();
  h.calls.at(-1).resolve({ time_ns: '720', items: [], counts_by_kind: { NEIGHBOR: 4000, DTE: 400 } }); await clearRequest;
  h.kind('DTE'); h.calls.at(-1).resolve({ time_ns: '720', items: [], counts_by_kind: { NEIGHBOR: 4000, DTE: 400 } }); await settle();
  assert.equal(h.state.selectedResourceKind, 'DTE'); assert.equal(body(), baseline);
});
