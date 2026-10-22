import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { replaceAbortController } from '../assets/browser_transport.js';
import { escapeHtml, titleCase, toBigInt as toNs } from '../assets/shared.js';
import { dashboardFieldValue, routePayloadForwardingPresentation } from '../assets/view_models.js';
import { timelineWindowForZoom } from '../assets/timeline_viewport.js';

// Controlled request completion supplements the natural-timing browser audit.
// Production originating handlers and request ownership stay intact. Transport,
// DOM geometry and unrelated paint work are harness boundaries, not browser proof.
const source = readFileSync(new URL('../assets/app.js', import.meta.url), 'utf8');
const noop = () => {};
function declaration(name) {
  const match = new RegExp(`^(?:async )?function ${name}\\(`, 'm').exec(source);
  assert.ok(match, name);
  const tail = source.slice(match.index);
  return tail.slice(0, /\n(?:async )?function \w+\(/.exec(tail)?.index);
}
function load(names, deps) {
  return new Function(...Object.keys(deps), `${names.map(declaration).join('\n')}\nreturn {${names.join(',')}};`)(...Object.values(deps));
}
function install(startMarker, endMarker, deps) {
  const start = source.indexOf(startMarker), end = source.indexOf(endMarker, start + startMarker.length);
  assert.ok(start >= 0 && end > start, startMarker);
  new Function(...Object.keys(deps), source.slice(start, end))(...Object.values(deps));
}
function element(extra = {}) {
  const handlers = new Map();
  return { value: '', innerHTML: '', dataset: {}, style: {}, scrollLeft: 0, scrollWidth: 800, clientWidth: 800,
    contains: () => false, querySelectorAll: () => [], getBoundingClientRect: () => ({left: 0}),
    setAttribute(key, value) { this[key] = value; },
    addEventListener(type, handler) { handlers.set(type, [...handlers.get(type) || [], handler]); },
    fire(type, event = {}) { return Promise.all((handlers.get(type) || []).map(fn => fn({preventDefault: noop, target: this, ...event}))); },
    ...extra };
}
function transport(state) {
  const requests = [];
  const names = ['beginLatestRequest', 'finishLatestRequest', 'abortLatestRequests', 'requestWasAborted'];
  return { requests, ...load(names, {state, replaceAbortController}),
    analysisRuntimeApi(path, options) {
      let resolve, reject;
      const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
      // Deliberately ignore abort at this boundary: stale successful responses
      // can finish after cancellation, so token checks must protect the result.
      requests.push({path, body: JSON.parse(options.body), signal: options.signal, resolve, reject});
      return promise;
    } };
}
const flush = async () => { for (let index = 0; index < 8; index++) await Promise.resolve(); };

const routeCases = [
  ['S273', 'all-active-ecmp', 'All-active ECMP'],
  ['S279', 'recursive-resolution-cycle', 'Recursive next-hop cycle'],
  ['S285', 'cross-layer-inconsistent', 'Cross-layer forwarding inconsistency'],
  ['S291', 'single-active-primary', 'Single-active primary with eligible standby'],
  ['S297', 'cross-node-mpls-label-mismatch', 'Cross-node MPLS label handoff mismatch'],
];
for (const [id, routeId, label] of routeCases) for (const staleOutcome of ['success', 'failure']) {
  test(`${id}: route change and submit retain latest attribution after stale ${staleOutcome}`, async () => {
    const state = {routeRequestId: 0, cursorNs: 30n};
    const controls = new Map(['route-form', 'route-choice', 'route-basis', 'route-result'].map(id => [id, element()]));
    const byId = id => controls.get(id), requests = transport(state);
    byId('route-basis').value = 'observed_capture_vector';
    byId('route-form').querySelectorAll = () => [byId('route-choice'), byId('route-basis')];
    const routes = routeCases.map(([, route_id, label]) => ({route_id, label}));
    const api = load(['selectedRouteDescriptor', 'renderRoutePayload', 'resolveRoute'], {
      state, byId, ...requests, escapeHtml, titleCase, toNs, routePayloadForwardingPresentation,
      FormData: class { get(key) { return byId(key === 'route_id' ? 'route-choice' : 'route-basis').value; } },
      routeResolutionCapability: () => ({routes}), isTopologyNodeSnapshot: () => false,
      explanationSteps: () => [], formatOffset: String, revisionPath: x => x,
    });
    install('byId("route-form").addEventListener("submit", resolveRoute);', '  byId("event-layer-filter").addEventListener', {byId, ...api});
    byId('route-choice').value = routeId === 'all-active-ecmp' ? 'recursive-resolution-cycle' : 'all-active-ecmp';
    const older = byId('route-choice').fire('change');
    byId('route-choice').value = routeId;
    state.cursorNs = 120n;
    const changed = byId('route-choice').fire('change');
    const submitted = byId('route-form').fire('submit');
    assert.equal(requests.requests.length, 3);
    assert.ok(requests.requests[0].signal.aborted && requests.requests[1].signal.aborted);
    assert.equal(byId('route-result')['aria-busy'], 'true');
    assert.deepEqual(requests.requests[2].body, {route_id: routeId, basis_kind: 'observed_capture_vector', time_ns: '120'});
    const payload = tag => ({matched_prefix: `${tag}-prefix`, result: 'resolved', basis_kind: 'observed_capture_vector', time_ns: '120',
      branches: [{next_hop: `${tag}-next-hop`, egress_interface_resource_id: `${tag}-egress`, active: true}]});
    requests.requests[2].resolve(payload('latest'));
    await submitted;
    const rendered = byId('route-result').innerHTML;
    assert.ok(rendered.includes(label));
    for (const field of ['latest-prefix', 'latest-next-hop', 'latest-egress', 'returned for 120']) assert.ok(rendered.includes(field), field);
    if (staleOutcome === 'success') requests.requests[0].resolve(payload('obsolete'));
    else requests.requests[0].reject(new Error('obsolete request error'));
    requests.requests[1].resolve(payload('superseded-same-route'));
    await Promise.all([older, changed]);
    assert.equal(byId('route-result').innerHTML, rendered);
    assert.equal(byId('route-result')['aria-busy'], 'false');
    assert.equal(state.routeAbortController, null);
    const repeated = byId('route-form').fire('submit');
    requests.requests[3].resolve(payload('repeat'));
    await repeated;
    assert.ok(byId('route-result').innerHTML.includes('repeat-prefix'));
    assert.ok(byId('route-result').innerHTML.includes(label));
    assert.equal(byId('route-result')['aria-busy'], 'false');
  });
}

function timelineHarness() {
  const state = {timelineNavigationIntent: 0, timelineRequestId: 0, cursorNs: 50n,
    viewStartNs: 0n, viewEndNs: 1000n, timelineWindowStartNs: 400n, timelineWindowEndNs: 500n, zoom: 10,
    timelineViewHistoryIndex: 1, timelineViewHistory: [{startNs: 200n, endNs: 300n, zoom: 10}, {startNs: 400n, endNs: 500n, zoom: 10}],
    laneMode: 'custom', explicitLaneIds: new Set(), hiddenTimelineResourceIds: new Set(),
    activeLayers: new Set(), layerMeta: new Map(), laneByResource: new Map(), lanes: [],
    recordLaneRules: [], selectedResourceId: null, hoverModels: new Map(), correlatedResourceIds: new Set()};
  const controls = new Map(), byId = id => { if (!controls.has(id)) controls.set(id, element()); return controls.get(id); };
  const requests = transport(state), frames = [], selections = [], focused = [], scrolled = [], normalized = [];
  const events = {A: {uid: 'A', resource: 'resource-A', time: 30n}, B: {uid: 'B', resource: 'resource-B', time: 700n}};
  const marks = Object.values(events).map(event => ({dataset: {eventUid: event.uid},
    closest: () => ({dataset: {resourceId: event.resource}}), focus: () => focused.push(event.uid)}));
  const deps = {state, byId, ...requests, timelineWindowForZoom, MAX_SCALE_TIMELINE_LANES: 32,
    canonicalResourceId: x => x, eventOrMark: uid => events[uid], eventTime: event => event.time,
    eventResourceRefs: event => [event.resource], isScaleMode: () => true, isTopologyNodeSnapshot: () => false,
    clampNs: x => x, rangeBounds: () => null, timelinePhysicalTrackWidth: () => 800, timelineLaneWidth: () => 200,
    cancelScheduledTimelineZoom: noop, rememberTimelineView: noop, scheduleTimelineWindowRefresh: noop,
    updateTimelineCommandAvailability: noop, renderTimeline: noop, renderResourceTables: noop,
    renderLayerToggles: noop, layerConfig: noop, showToast: noop, revisionPath: x => x,
    scaleTimelineResourceIds: () => [...state.explicitLaneIds].filter(id => !state.hiddenTimelineResourceIds.has(id)),
    resourceHiddenFromTimeline: id => state.hiddenTimelineResourceIds.has(id),
    laneSelectedByMode: id => state.explicitLaneIds.has(id) && !state.hiddenTimelineResourceIds.has(id),
    window: {clearTimeout: noop, requestAnimationFrame: fn => frames.push(fn)},
    document: {querySelectorAll: selector => selector.includes('[data-event-uid]') ? marks.filter(mark => state.laneByResource.has(mark.closest().dataset.resourceId)) : []},
    scrollTimelineTargetIntoView: mark => scrolled.push(mark.dataset.eventUid), navigationPulse: noop,
    normalizeTimeline(payload) { normalized.push(payload.tag); state.lanes = payload.lanes; state.laneByResource = new Map(payload.lanes.map(lane => [lane.resourceId, lane])); },
    selectEvent(uid, _move, resource) { selections.push(uid); state.selectedEventUid = uid; state.selectedEventResourceId = resource; state.cursorNs = events[uid].time; },
  };
  const api = load(['timelineWindowBounds', 'timelineZoomControlValue', 'visibleTimelineCenterNs', 'applyTimelineZoom',
    'fitTimelineCapture', 'restoreTimelineView', 'invalidatePendingTimelineWindowRequest', 'moveTimelineWindowToReveal',
    'eventLaneFor', 'jumpToTimelineEvent', 'refreshTimelineForNavigation', 'requestTimeline', 'refreshScaleTimeline',
    'setExplicitLaneVisibility', 'bindLaneVisibilityCheckboxes'], deps);
  install('byId("timeline-view-back").addEventListener', '  byId("timeline-view-forward").addEventListener', {state, byId, ...api});
  install('byId("timeline-fit").addEventListener', '  byId("range-mode").addEventListener', {byId, ...api});
  const response = (request, tag) => ({tag, lanes: request.body.resource_ids.map(resourceId => ({resourceId, layer: 'control-plane', clusters: [],
    marks: Object.values(events).filter(event => event.resource === resourceId).map(event => ({eventUid: event.uid}))}))});
  return {state, byId, api, requests: requests.requests, response, frames, selections, focused, scrolled, normalized};
}

test('C010: Back wins over an outstanding timeline reveal and the next explicit reveal succeeds', async () => {
  const h = timelineHarness(), pending = h.api.jumpToTimelineEvent('A');
  assert.equal(h.requests.length, 1);
  assert.equal(h.requests[0].body.selected_event_uid, 'A');
  await h.byId('timeline-view-back').fire('click');
  assert.ok(h.requests[0].signal.aborted);
  h.requests[0].resolve(h.response(h.requests[0], 'obsolete'));
  await pending;
  assert.deepEqual(h.normalized, []);
  assert.deepEqual(h.selections, []);
  assert.deepEqual([h.state.timelineWindowStartNs, h.state.timelineWindowEndNs], [200n, 300n]);
  const recovery = h.api.jumpToTimelineEvent('A');
  h.requests[1].resolve(h.response(h.requests[1], 'recovery'));
  await recovery;
  h.frames.forEach(fn => fn());
  assert.deepEqual(h.normalized, ['recovery']);
  assert.deepEqual(h.selections, ['A']);
  assert.deepEqual(h.focused, ['A']);
  assert.deepEqual(h.scrolled, ['A']);
  assert.equal(h.state.cursorNs, 30n);
});

test('C011: Fit and B supersede outstanding A payload and target focus', async () => {
  const h = timelineHarness(), older = h.api.jumpToTimelineEvent('A');
  await h.byId('timeline-fit').fire('click');
  assert.deepEqual([h.state.timelineWindowStartNs, h.state.timelineWindowEndNs], [0n, 1000n]);
  const latest = h.api.jumpToTimelineEvent('B');
  assert.equal(h.requests.length, 2);
  h.requests[1].resolve(h.response(h.requests[1], 'B'));
  await latest;
  h.requests[0].resolve(h.response(h.requests[0], 'A'));
  await older;
  h.frames.forEach(fn => fn());
  assert.deepEqual(h.normalized, ['B']);
  assert.deepEqual(h.selections, ['B']);
  assert.deepEqual(h.focused, ['B']);
  assert.deepEqual(h.scrolled, ['B']);
  assert.equal(h.state.selectedEventUid, 'B');
  assert.equal(h.state.selectedEventResourceId, 'resource-B');
  assert.equal(h.state.cursorNs, 700n);
});

test('C012: hide during absent-lane allocation wins, then explicit reveal restores exactly one lane', async () => {
  const h = timelineHarness(), older = h.api.jumpToTimelineEvent('A');
  assert.deepEqual(h.requests[0].body.resource_ids, ['resource-A']);
  assert.equal(h.state.lanes.length, 0, 'allocation is genuinely outstanding');
  const checkbox = element({dataset: {laneToggle: 'resource-A'}, checked: false});
  h.api.bindLaneVisibilityCheckboxes({querySelectorAll: () => [checkbox]});
  await checkbox.fire('click', {stopPropagation: noop});
  assert.deepEqual(h.requests[1].body.resource_ids, []);
  h.requests[1].resolve(h.response(h.requests[1], 'hide'));
  await flush();
  h.requests[0].resolve(h.response(h.requests[0], 'obsolete-add'));
  await older;
  assert.deepEqual(h.normalized, ['hide']);
  assert.equal(h.state.lanes.length, 0);
  assert.equal(h.state.explicitLaneIds.size, 0);
  assert.equal(h.state.hiddenTimelineResourceIds.has('resource-A'), true);
  assert.deepEqual(h.selections, []);
  const recovery = h.api.jumpToTimelineEvent('A');
  h.requests[2].resolve(h.response(h.requests[2], 'recovery'));
  await recovery;
  h.frames.forEach(fn => fn());
  assert.deepEqual(h.state.lanes.map(lane => lane.resourceId), ['resource-A']);
  assert.equal(h.state.explicitLaneIds.size, 1);
  assert.equal(h.state.hiddenTimelineResourceIds.has('resource-A'), false);
  assert.deepEqual(h.focused, ['A']);
});

for (const [original, alternate] of [['ETG', 'NEIGHBOR'], ['NEIGHBOR', 'ETG']]) {
  test(`C030: search, ${alternate} kind click and ${original} dashboard selection retain current rows and schema`, async () => {
    const resource = kind => ({resource_id: `${kind}-resource`, kind, label: `matching ${kind}`, layer: 'link', exists: true, status: 'up'});
    const items = [resource('ETG'), resource('NEIGHBOR')];
    const state = {resourceRequestId: 0, timelineNavigationIntent: 0, selectedResourceKind: original, selectedResourceViewId: null,
      selectedResourceId: null, resourceOffset: 0, resourceTableSelectionReady: true, cursorNs: 120n,
      resourceQuery: {items, counts_by_kind: {ETG: 1, NEIGHBOR: 1}}, resourceById: new Map(items.map(item => [item.resource_id, item])),
      laneByResource: new Map(items.map(item => [item.resource_id, {resourceId: item.resource_id}])), correlatedResourceIds: new Set()};
    const controls = new Map(['resource-search', 'resource-table-wrap', 'resource-table-summary', 'resource-type-tabs', 'dashboard-modules']
      .map(id => [id, element()])), byId = id => controls.get(id);
    let kindButtons = [], searchTimer;
    Object.defineProperty(byId('resource-type-tabs'), 'innerHTML', {set(html) {
      kindButtons = [...html.matchAll(/data-kind="([^"]+)"/g)].map(match => element({dataset: {kind: match[1]}}));
    }});
    byId('resource-type-tabs').querySelectorAll = selector => selector === '[data-kind]' ? kindButtons : [];
    const dashboardButtons = items.map(item => element({dataset: {dashboardResourceId: item.resource_id}}));
    const dashboardRows = items.map(item => ({dataset: {dashboardResourceRow: item.resource_id}, selected: false,
      classList: {toggle(_name, value) { dashboardRows.find(row => row.dataset.dashboardResourceRow === item.resource_id).selected = value; }}}));
    byId('dashboard-modules').querySelectorAll = selector => selector === '[data-dashboard-resource-row]' ? dashboardRows : dashboardButtons;
    const requests = transport(state);
    const api = load(['requestResources', 'renderResourceTables', 'selectResource', 'refreshDashboardSelectionPresentation',
      'presentationColumns', 'normalizeResourceTableColumn', 'resourceTableFieldLabel', 'formatResourceTableCell', 'resourceTableFieldValue'], {
      state, byId, ...requests, escapeHtml, titleCase, dashboardFieldValue, MAX_RESOURCE_ROWS: 500,
      document: {activeElement: null}, window: {clearTimeout: () => { searchTimer = null; }, setTimeout: fn => { searchTimer = fn; return 1; }},
      isTopologyNodeSnapshot: () => false, isScaleMode: () => true, canonicalResourceId: x => x, revisionPath: x => x,
      initializeResourceTableView: noop, resourceTableViewDescriptors: () => [], fallbackResourceItems: () => [],
      markResourcesPending: () => {state.resourcePending = true;}, settleResourceRequest: () => {state.resourcePending = false;},
      registerResource: (item, id) => state.resourceById.set(id, item),
      resourcePageDetails: () => ({returned: state.resourceQuery.items.length, first: 1, last: state.resourceQuery.items.length}),
      humanResourceType: String, humanLayer: String, resourceTimeSummary: () => 'at 120', resourcePaginationMarkup: () => '',
      resourceExistenceLabel: String, stateChipClassName: () => 'up', presentationTags: () => new Set(),
      laneVisibilityCheckbox: () => '', bindLaneVisibilityCheckboxes: noop, bindResourcePagination: noop, formatValue: String,
      markCorrelationPending: noop, rerenderTimelinePreservingScroll: noop, requestGraph: noop, updateFabricNavigationLink: noop,
    });
    install('byId("resource-search").addEventListener', '  byId("reset-dashboard-layout").addEventListener', {
      state, byId, ...api, isScaleMode: () => true,
      window: {clearTimeout: () => {searchTimer = null;}, setTimeout: fn => {searchTimer = fn; return 1;}},
    });
    install('modules.querySelectorAll("[data-dashboard-resource-id]").forEach', '  modules.querySelectorAll("[data-dashboard-drag]").forEach', {
      modules: byId('dashboard-modules'), ...api,
    });
    api.renderResourceTables();
    byId('resource-search').value = 'matching';
    await byId('resource-search').fire('input');
    assert.equal(typeof searchTimer, 'function');
    const first = searchTimer();
    assert.equal(state.resourcePending, true);
    assert.equal(requests.requests.length, 1);
    await kindButtons.find(button => button.dataset.kind === alternate).fire('click');
    await dashboardButtons.find(button => button.dataset.dashboardResourceId === `${original}-resource`).fire('click');
    assert.equal(requests.requests.length, 3);
    assert.deepEqual(requests.requests.map(request => request.body.kinds), [[original], [alternate], [original]]);
    assert.ok(requests.requests.every(request => request.body.search === 'matching'));
    assert.ok(requests.requests[0].signal.aborted && requests.requests[1].signal.aborted);
    const payload = (kind, tag) => ({time_ns: '120', items: [{...resource(kind), label: `matching ${tag}`, state: {value: `${tag}-value`}}],
      counts_by_kind: {[kind]: 1}, tables: [{kind, columns: [{field: 'value', label: `${tag}-column`}]}]});
    requests.requests[2].resolve(payload(original, 'latest'));
    await flush();
    const expectedMarkup = byId('resource-table-wrap').innerHTML;
    assert.ok(expectedMarkup.includes(`data-resource-id="${original}-resource" class="selected`));
    assert.ok(expectedMarkup.includes('latest-column'));
    assert.ok(expectedMarkup.includes('latest-value'));
    requests.requests[1].resolve(payload(alternate, 'obsolete-kind'));
    requests.requests[0].resolve(payload(original, 'obsolete-search'));
    await first;
    await flush();
    assert.equal(byId('resource-table-wrap').innerHTML, expectedMarkup);
    assert.equal(state.selectedResourceId, `${original}-resource`);
    assert.equal(state.selectedResourceKind, original);
    assert.equal(state.resourcePending, false);
    assert.deepEqual(dashboardRows.filter(row => row.selected).map(row => row.dataset.dashboardResourceRow), [`${original}-resource`]);
    assert.equal(state.resourceAbortController, null);
  });
}
