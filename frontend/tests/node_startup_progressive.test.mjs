import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { escapeHtml } from '../assets/shared.js';
const source = readFileSync(new URL('../assets/app.js', import.meta.url), 'utf8');
function extract(name) {
  const match = new RegExp(`(?:async )?function ${name}\\(`).exec(source);
  assert.ok(match);
  const tail = source.slice(match.index);
  const ending = /\r?\n\}/.exec(tail);
  return tail.slice(0, ending.index + ending[0].length);
}
function deferred() { let resolve; let reject; const promise = new Promise((done, fail) => { resolve = done; reject = fail; }); return { promise, resolve, reject }; }
const settle = () => new Promise((resolve) => setImmediate(resolve));
function harness({ resource = false, scale = false, incident = false, navigation = false } = {}) {
  const timeline = deferred(); const preview = deferred(); const topology = deferred();
  const dataset = { resources: resource ? [{ resource_id: 'r1', kind: 'port' }] : [], events: incident ? [{ event_uid: 'e1', resource_id: 'r1' }] : [] };
  const state = { resourceById: new Map(), eventByUid: new Map(), layerMeta: new Map(), lanes: [], durableReview: {}, failureIncidentPreview: [], selectedResourceKind: 'old', correlatedResourceIds: new Set(), laneByResource: new Map(), explicitLaneIds: new Set() };
  const effects = { calls: [], renders: 0, selections: [] };
  const deps = {
    state, navigationContext: navigation ? { timeNs: '5' } : {},
    analysisRuntimeApi: async () => dataset, bootstrapDatasetPath: () => '/v1/revisions/rev1/analysis',
    workspaceMetadata: () => ({ timeline_start_ns: '0', timeline_end_ns: '10', capture_ns: '10', initial_focus_resource_id: resource ? 'r1' : '' }),
    registerResource: (item) => state.resourceById.set(item.resource_id, item),
    compareLogEntries: () => 0, sourceRecordUid: (item) => item.uid,
    isScaleMode: () => scale, eventTime: () => 3n, toNs: (value, fallback = 0n) => value == null ? fallback : BigInt(value), clampNs: (value) => value,
    initialScaleLaneIds: () => [], MAX_RECORD_LANES: 10,
    requestTimeline: () => { effects.calls.push('timeline'); return timeline.promise; },
    requestFailureIncidentPreview: () => { effects.calls.push('preview'); return preview.promise; },
    requestTopologyCapabilities: () => { effects.calls.push('capabilities'); return topology.promise; },
    fillSummary: () => { effects.renders++; },
    eventFailed: () => true, navigationTargetsLoadedMember: () => true, hasTopologyNavigationContext: () => navigation,
    canonicalResourceId: (id) => id,
    selectResource: (id, options) => { effects.selections.push({ id, options }); state.selectedResourceId = id; },
    selectEvent: (id, move, resourceId, options) => { effects.selections.push({ id, move, options }); state.selectedEventUid = id; },
    document: { querySelector: () => ({ innerHTML: '' }) }, escapeHtml: String,
  };
  for (const name of ['initializeDurableReviewSetup', 'initializeResourceTableView', 'initializeSourceRecordGroups', 'discoverPresentation', 'renderTopologyNavigationBanner', 'initializeDashboardLayout', 'markDashboardsPending', 'renderIncidentSummary', 'renderLayerToggles', 'renderTimeline', 'renderRangeSummary', 'renderFindings', 'renderTopologyResults', 'renderInventory', 'configureRouteControls', 'renderReview', 'renderEventLayerFilter', 'syncEventLogIncludeControls', 'renderEventTable', 'renderPluginDashboards', 'bindControls']) deps[name] = () => {};
  for (const name of ['requestGraph', 'requestResources', 'requestDashboards', 'requestTopology', 'resolveRoute']) deps[name] = async () => { effects.calls.push(name); };
  const initialize = new Function(...Object.keys(deps), `${extract('initialize')}\nreturn initialize;`)(...Object.values(deps));
  return { initialize, state, effects, timeline, preview, topology };
}
test('timeline starts alongside optional discovery and first render does not wait for either optional response', async () => {
  const h = harness({ resource: true });
  const pending = h.initialize(); await settle();
  assert.deepEqual(h.effects.calls, ['preview', 'capabilities', 'timeline']);
  h.timeline.resolve(); await pending;
  assert.equal(h.effects.renders, 1);
  assert.deepEqual(h.effects.selections, [{ id: 'r1', options: { deferRequests: true } }]);
  assert.deepEqual(h.effects.calls.slice(3), ['requestGraph', 'requestResources', 'requestDashboards', 'resolveRoute']);
  h.topology.resolve(); h.preview.resolve(); await settle();
  assert.equal(h.effects.calls.filter((call) => call === 'requestTopology').length, 1);
});
test('initial scale incident uses deferred requests and retains cursor-moving selection', async () => {
  const h = harness({ incident: true, scale: true });
  const pending = h.initialize(); await settle(); h.timeline.resolve(); await pending;
  assert.deepEqual(h.effects.selections, [{ id: 'e1', move: true, options: { deferRequests: true } }]);
});
test('late incident preview may focus an empty startup but cannot override user selection or navigation', async () => {
  for (const protectedSelection of [false, true, 'navigation']) {
    const h = harness({ scale: true, navigation: protectedSelection === 'navigation' });
    const pending = h.initialize(); await settle(); h.timeline.resolve(); await pending;
    if (protectedSelection === true) h.state.selectedResourceId = 'user-resource';
    h.state.failureIncidentPreview = [{ event_uid: 'late' }]; h.preview.resolve(); await settle();
    assert.equal(h.effects.selections.length, protectedSelection ? 0 : 1);
  }
});
test('deferred initial event selection refreshes scale timeline once using final cursor and focus', async () => {
  for (const loaded of [false, true]) {
    const event = { event_uid: 'e1' };
    const state = { cursorNs: 10n, resourceById: new Map([['r1', { kind: 'port' }]]), correlatedResourceIds: new Set(), laneByResource: new Map(loaded ? [['r1', {}]] : []), explicitLaneIds: new Set(), selectedResourceId: null };
    const effects = { graph: 0, resource: 0, temporal: 0, topology: 0, timelines: [] };
    const deps = {
      state, eventOrMark: () => event, eventResourceRefs: () => ['r1'], resourceKind: () => 'port', isScaleMode: () => true, MAX_SCALE_TIMELINE_LANES: 10,
      pruneServerEventLogOwnedCaches() {}, renderEventInspector() {}, renderTimeline() {}, renderEventTable() {}, rerenderTimelinePreservingScroll() {},
      eventTime: () => 3n, requestEventDetail: async () => null,
      refreshScaleTimeline: async () => { effects.timelines.push({ cursor: state.cursorNs, resource: state.selectedResourceId }); },
      requestGraph: () => { effects.graph++; }, requestResources: () => { effects.resource++; },
      clampNs: (value) => value, updateCursorVisual() {}, updateFabricNavigationLink() {}, markResourcesPending() {}, markDashboardsPending() {}, updateTimelineCommandAvailability() {},
      scheduleTemporalRefresh: () => { effects.temporal++; }, scheduleTopologyRefreshFromCursor: (schedule = true) => { if (schedule) effects.topology++; },
    };
    const select = new Function(...Object.keys(deps), `${extract('setCursor')}\n${extract('selectEvent')}\nreturn selectEvent;`)(...Object.values(deps));
    select('e1', true, null, { deferRequests: true });
    assert.equal(state.selectedEventUid, 'e1');
    assert.equal(state.cursorSelected, true);
    assert.deepEqual(effects.timelines, [{ cursor: 3n, resource: 'r1' }]);
    assert.equal(effects.graph + effects.resource + effects.temporal + effects.topology, 0);
  }
});
test('deferred resource selection establishes kind and lane without duplicate graph or resource queries', () => {
  const state = { selectedResourceKind: 'old', selectedResourceViewId: null, resourceById: new Map([['r1', { kind: 'port' }]]), correlatedResourceIds: new Set(), laneByResource: new Map(), explicitLaneIds: new Set(), cursorNs: 3n };
  const effects = { graph: 0, resources: 0, timeline: 0 };
  const deps = { state, canonicalResourceId: (value) => value, resourceKind: () => 'port', isScaleMode: () => true, MAX_SCALE_TIMELINE_LANES: 10,
    requestResources: () => { effects.resources++; }, requestGraph: () => { effects.graph++; }, refreshScaleTimeline: () => { effects.timeline++; },
    markCorrelationPending() {}, rerenderTimelinePreservingScroll() {}, renderResourceTables() {}, refreshDashboardSelectionPresentation() {}, renderGraph() {}, updateFabricNavigationLink() {},
  };
  const select = new Function(...Object.keys(deps), `${extract('selectResource')}\nreturn selectResource;`)(...Object.values(deps));
  select('r1', { deferRequests: true });
  assert.equal(state.selectedResourceId, 'r1');
  assert.equal(state.selectedResourceKind, 'port');
  assert.equal(state.resourceOffset, 0);
  assert.equal(effects.resources + effects.graph, 0);
  assert.equal(effects.timeline, 1);
});
test('optional discovery failures are handled immediately while timeline remains pending', async () => {
  const h = harness();
  const pending = h.initialize(); await settle();
  h.preview.reject(new Error('optional preview unavailable'));
  h.topology.reject(new Error('optional topology unavailable'));
  await settle();
  assert.equal(h.effects.renders, 0);
  h.timeline.resolve(); await pending;
  assert.equal(h.effects.renders, 1);
  assert.equal(h.effects.calls.filter((call) => call === 'requestGraph').length, 1);
});
test('deferred cursor selection synchronizes follow-cursor topology input without a duplicate timer', () => {
  const state = { cursorNs: 10n, topologyCapabilities: {} };
  const inputs = new Map([
    ['topology-absolute-time', { value: '10' }],
    ['topology-basis-kind', { value: 'absolute_time' }],
    ['topology-follow-cursor', { checked: true }],
  ]);
  const effects = { timers: 0, temporal: 0 };
  const deps = { state, byId: (id) => inputs.get(id), clampNs: (value) => value,
    window: { clearTimeout() {}, setTimeout() { effects.timers++; } }, requestTopology() {},
    updateCursorVisual() {}, updateFabricNavigationLink() {}, markResourcesPending() {}, markDashboardsPending() {}, updateTimelineCommandAvailability() {},
    scheduleTemporalRefresh: () => { effects.temporal++; },
  };
  const setCursor = new Function(...Object.keys(deps), `${extract('scheduleTopologyRefreshFromCursor')}\n${extract('setCursor')}\nreturn setCursor;`)(...Object.values(deps));
  setCursor(3n, false, true, false);
  assert.equal(state.cursorNs, 3n);
  assert.equal(inputs.get('topology-absolute-time').value, '3');
  assert.equal(effects.timers + effects.temporal, 0);
  inputs.get('topology-follow-cursor').checked = false;
  setCursor(4n, false, true, false);
  assert.equal(inputs.get('topology-absolute-time').value, '3');
  inputs.get('topology-follow-cursor').checked = true;
  setCursor(5n);
  assert.equal(inputs.get('topology-absolute-time').value, '5');
  assert.equal(effects.timers, 1);
  assert.equal(effects.temporal, 1);
});

test('failed node startup offers manual retry with escaped error text', async () => {
  const main = { innerHTML: '' };
  let retry;
  let reloads = 0;
  const deps = {
    state: {},
    analysisRuntimeApi: async () => { throw new Error('<load failed>'); },
    bootstrapDatasetPath: () => '/workspace', escapeHtml,
    document: { querySelector: () => main },
    byId: () => ({ addEventListener(_type, listener) { retry = listener; } }),
    location: { reload() { reloads++; } },
  };
  const initialize = new Function(...Object.keys(deps), `${extract('initialize')}\nreturn initialize;`)(...Object.values(deps));
  await initialize();
  assert.match(main.innerHTML, /&lt;load failed&gt;/);
  assert.match(main.innerHTML, /Retry loading/);
  assert.equal(reloads, 0);
  retry();
  assert.equal(reloads, 1);
});
