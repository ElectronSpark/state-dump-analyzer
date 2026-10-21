import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
const source = readFileSync(new URL('../assets/app.js', import.meta.url), 'utf8');
function body(name) {
  const start = new RegExp(`^(?:async )?function ${name}\\(`, 'm').exec(source).index;
  const rest = source.slice(start);
  const next = /\n(?:async )?function \w+\(/.exec(rest);
  return rest.slice(0, next.index);
}
function load(name, bindings) {
  return new Function(...Object.keys(bindings), `${body(name)}; return ${name};`)(...Object.values(bindings));
}
const noop = () => {};

test('source lookup crosses normalized lanes without stored clusters and absent sources have log hover', () => {
  const state = { recordLanes: [{ laneId: 'first', marks: [] }, { laneId: 'second', marks: [{ sourceRecordUid: 'later' }] }] };
  const lookup = load('sourceRecordLaneFor', { state });
  assert.equal(lookup('later').laneId, 'second');
  assert.equal(lookup('absent'), null);
  const hover = load('eventLogHoverModel', { state, isSourceLogEntry: () => true, sourceRecordUid: r => r.uid,
    sourceRecordLaneFor: lookup, sourceTypeDescriptor: () => ({ label: 'Records' }), normalizeSourceMark: (r, lane) => ({ record: r, lane }) });
  assert.equal(hover({ uid: 'later' }).lane.laneId, 'second');
  assert.equal(hover({ uid: 'absent' }).lane.laneId, 'log-source:absent');
});

test('Selected preset survives choosing an unloaded scale resource through the selection handler', () => {
  const state = { laneMode: 'selected', laneByResource: new Map(), explicitLaneIds: new Set(['old']),
    resourceById: new Map(), correlatedResourceIds: new Set(), cursorNs: 0n };
  let refreshes = 0;
  const select = load('selectResource', { state, canonicalResourceId: x => x, isScaleMode: () => true,
    MAX_SCALE_TIMELINE_LANES: 32, refreshScaleTimeline: () => refreshes++, requestResources: noop,
    markCorrelationPending: noop, rerenderTimelinePreservingScroll: noop, renderResourceTables: noop,
    refreshDashboardSelectionPresentation: noop, requestGraph: noop, updateFabricNavigationLink: noop });
  select('new');
  assert.equal(state.laneMode, 'selected');
  assert.equal(state.selectedResourceId, 'new');
  assert.equal(refreshes, 1);
});

test('a superseded event jump cannot select or focus after its delayed refresh', async () => {
  const state = { hiddenTimelineResourceIds: new Set(), activeLayers: new Set(), laneByResource: new Map() };
  let release;
  const pending = new Promise(resolve => release = resolve);
  const selections = [], frames = [];
  const jump = load('jumpToTimelineEvent', { state, eventOrMark: uid => ({ uid }), eventTime: () => 1n,
    eventLaneFor: () => null, eventResourceRefs: () => ['resource'], isScaleMode: () => false,
    moveTimelineWindowToReveal: () => true, refreshTimelineForNavigation: () => pending,
    renderLayerToggles: noop, selectEvent: uid => selections.push(uid), window: { requestAnimationFrame: f => frames.push(f) } });
  const task = jump('old');
  state.timelineNavigationIntent++;
  state.selectedEventUid = 'new';
  release(true);
  await task;
  assert.deepEqual(selections, []);
  assert.deepEqual(frames, []);
  assert.equal(state.selectedEventUid, 'new');
});

test('a loaded jump deferred focus is superseded by a newer selection', async () => {
  const lane = { resourceId: 'r', layer: 'l' };
  const state = { hiddenTimelineResourceIds: new Set(), activeLayers: new Set(), laneByResource: new Map([['r', lane]]) };
  const frames = [];
  const jump = load('jumpToTimelineEvent', { state, eventOrMark: () => ({}), eventTime: () => 1n,
    eventLaneFor: () => lane, eventResourceRefs: () => ['r'], isScaleMode: () => false,
    moveTimelineWindowToReveal: () => false, laneSelectedByMode: () => true,
    renderLayerToggles: noop, selectEvent: () => state.timelineNavigationIntent++, window: { requestAnimationFrame: f => frames.push(f) },
    document: { querySelectorAll: () => { throw new Error('stale focus callback queried DOM'); } } });
  await jump('old');
  state.timelineNavigationIntent++;
  frames[0]();
});

test('duplicate tree occurrences preserve their own focus descriptor', () => {
  class Element { constructor(treeKey) { this.dataset = { eventUid: 'event' }; this.treeKey = treeKey; } closest() { return { dataset: { resourceId: 'r', treeKey: this.treeKey } }; } }
  const first = new Element('first'), second = new Element('second');
  const content = { contains: () => true, querySelectorAll: () => [first, second] };
  const bindings = { byId: () => content, HTMLElement: Element, document: { activeElement: second } };
  const descriptor = load('timelineFocusDescriptor', bindings)();
  assert.equal(descriptor.treeKey, 'second');
  assert.equal(load('timelineElementForFocusDescriptor', bindings)(descriptor), second);
});

test('Combined associations are absent when the focused resource layer is hidden', () => {
  const state = { correlationTimelineView: 'combined', selectedResourceId: 'r', correlationTimelineExpanded: true,
    activeLayers: new Set(['other']), laneByResource: new Map([['r', { layer: 'hidden' }]]) };
  const render = load('combinedAssociationLane', { state, resourceHiddenFromTimeline: () => false,
    temporalRelationshipSpans: () => { throw new Error('hidden layer queried relationships'); } });
  assert.equal(render(500), '');
});

test('lane picker change handler retains checkbox focus after rebuilding controls', () => {
  const state = { correlationTimelineView: 'separate', selectedResourceId: null, recordLaneRules: [],
    correlatedResourceIds: new Set(), lanes: [{ resourceId: 'r', kind: 'port', label: 'Port', layer: 'link' }], laneFilterText: '' };
  const document = { body: {}, activeElement: null, querySelectorAll: () => [] };
  let current;
  function input() { return { dataset: { laneResourceId: 'r' }, checked: true,
    addEventListener: (_event, handler) => current.handler = handler,
    focus: () => { document.activeElement = current; } }; }
  current = input(); document.activeElement = current;
  const list = { contains: element => element === current, querySelectorAll: () => [current],
    set innerHTML(value) { current = input(); document.activeElement = document.body; } };
  const render = load('renderLanePicker', { state, document, byId: id => id === 'lane-picker-list' ? list : {},
    visibleTimelineLanes: () => [], isScaleMode: () => false, laneSelectedByMode: () => true,
    escapeHtml: x => x, titleCase: x => x, humanLayer: x => x, renderRecordLaneManager: noop,
    setExplicitLaneVisibility: () => render() });
  render();
  assert.equal(document.activeElement, current);
  const old = current;
  old.handler();
  assert.notEqual(current, old);
  assert.equal(document.activeElement, current);
});

for (const kind of ['event', 'resource']) test(`Selected preset queries the new unloaded ${kind} reveal target`, async () => {
  const state = { laneMode: 'selected', selectedResourceId: 'old', laneByResource: new Map(),
    hiddenTimelineResourceIds: new Set(), explicitLaneIds: new Set(['unrelated']), activeLayers: new Set(),
    correlatedResourceIds: new Set(['old-related']), correlationTimelineView: 'separate' };
  const lane = { resourceId: 'new', layer: 'link' };
  let queries = 0;
  const refresh = async () => {
    queries++;
    assert.equal(state.laneMode, 'selected');
    assert.equal(state.selectedResourceId, 'new');
    assert.equal(state.correlatedResourceIds.size, 0);
    state.laneByResource.set('new', lane);
  };
  const bindings = { state, canonicalResourceId: x => x, eventOrMark: () => ({}), eventTime: () => 1n,
    eventLaneFor: () => state.laneByResource.get('new'), eventResourceRefs: () => ['new'], isScaleMode: () => true,
    moveTimelineWindowToReveal: () => false, refreshTimelineForNavigation: refresh, refreshScaleTimeline: refresh,
    MAX_SCALE_TIMELINE_LANES: 32, renderLayerToggles: noop, selectEvent: noop, selectResource: noop,
    window: { requestAnimationFrame: noop } };
  await load(kind === 'event' ? 'jumpToTimelineEvent' : 'jumpToTimelineResource', bindings)('new');
  assert.equal(queries, 1);
  assert.equal(state.laneMode, 'selected');
  assert.equal(state.laneByResource.get('new'), lane);
});

test('explicit timeline clear invalidates pending navigation authority', () => {
  const state = { timelineNavigationIntent: 7, selectedEventUid: 'old', cursorSelected: true, viewEndNs: 20n };
  const clear = load('clearTimelineSelection', { state, byId: () => null, rangeBounds: () => null,
    closeHover: noop, hideTimelineHoverLine: noop, clearRangeSelection: noop, setCursor: noop,
    rerenderTimelinePreservingScroll: noop, renderEmptyEventInspector: noop, renderEventTable: noop,
    requestGraph: noop, requestResources: noop, requestDashboards: noop, showToast: noop, window: { clearTimeout: noop } });
  assert.equal(clear(), true);
  assert.equal(state.timelineNavigationIntent, 8);
  assert.equal(state.selectedEventUid, null);
});

test('source reveal creates and finds a lane when normalized lanes lack the target', async () => {
  const state = { recordLanes: [{ laneId: 'first', marks: [] }], recordLaneRules: [], customRecordLaneSequence: 0 };
  const lookup = load('sourceRecordLaneFor', { state });
  const ensure = load('ensureSourceRecordLane', { state, sourceRecordUid: record => record.uid,
    sourceRecordLaneFor: lookup, MAX_RECORD_LANES: 8, showToast: noop, regexEscape: x => x,
    requestTimeline: async () => state.recordLanes.push({ laneId: 'jump-record-1', marks: [{ sourceRecordUid: 'target' }] }),
    renderTimeline: noop, renderLanePicker: noop });
  assert.equal((await ensure({ uid: 'target' })).laneId, 'jump-record-1');
  assert.equal(state.recordLaneRules[0].pattern, 'target');
});

for (const supersede of ['loaded selection', 'clear', 'normal window loaded selection', 'normal window other loaded selection']) test(`timeline query preserves current context after ${supersede}`, async () => {
  let release;
  const response = new Promise(resolve => release = resolve);
  const b = { resourceId: 'B', layer: 'link' };
  const state = { timelineRequestId: 0, timelineNavigationIntent: 0, laneMode: 'selected', selectedResourceId: 'B',
    selectedResourceKind: 'port', lanes: [b], laneByResource: new Map([['B', b]]),
    explicitLaneIds: new Set(), hiddenTimelineResourceIds: new Set(), correlatedResourceIds: new Set(),
    activeLayers: new Set(['link']), layerMeta: new Map([['link', {}]]), recordLaneRules: [], cursorNs: 0n,
    resourceById: new Map([['B', { kind: 'port' }]]), viewEndNs: 100n, cursorSelected: true };
  const c = { resourceId: 'C', layer: 'link' };
  if (supersede.includes('other')) { state.lanes.push(c); state.laneByResource.set('C', c); }
  const refreshedC = { ...c, refreshed: true };
  let requests = 0, normalizations = 0;
  const deps = { state, MAX_SCALE_TIMELINE_LANES: 32, isScaleMode: () => true, isTopologyNodeSnapshot: () => false,
    canonicalResourceId: x => x, abortLatestRequests: noop, beginLatestRequest: () => ({ signal: {} }),
    finishLatestRequest: noop, timelineWindowBounds: () => [0n, 100n], rangeBounds: () => null,
    timelinePhysicalTrackWidth: () => 500, revisionPath: x => x,
    analysisRuntimeApi: async (_path, request) => {
      requests++;
      assert.deepEqual(JSON.parse(request.body).resource_ids, [requests > 1 ? 'C' : supersede.startsWith('normal') ? 'B' : 'A']);
      return requests > 1 ? { lanes: [refreshedC] } : response;
    },
    requestWasAborted: () => false, normalizeTimeline: payload => { normalizations++; state.lanes = payload.lanes; state.laneByResource = new Map(payload.lanes.map(lane => [lane.resourceId, lane])); },
    renderLayerToggles: noop, renderTimeline: noop, renderResourceTables: noop, layerConfig: noop,
    markCorrelationPending: noop, rerenderTimelinePreservingScroll: noop, refreshDashboardSelectionPresentation: noop,
    requestResources: noop, requestGraph: noop, updateFabricNavigationLink: noop, showToast: noop,
    byId: () => null, closeHover: noop, hideTimelineHoverLine: noop, clearRangeSelection: noop, setCursor: noop,
    renderEmptyEventInspector: noop, renderEventTable: noop, requestDashboards: noop,
    window: { requestAnimationFrame: noop, clearTimeout: noop } };
  const names = ['resourceHiddenFromTimeline', 'laneSelectedByMode', 'currentModeLaneIds', 'scaleTimelineResourceIds',
    'requestTimeline', 'refreshScaleTimeline', 'selectResource', 'clearTimelineSelection', 'jumpToTimelineResource'];
  const api = new Function(...Object.keys(deps), `${names.map(body).join('\n')}\nreturn { requestTimeline, jumpToTimelineResource, selectResource, clearTimelineSelection };`)(...Object.values(deps));
  const pending = supersede.startsWith('normal') ? api.requestTimeline() : api.jumpToTimelineResource('A');
  assert.equal(requests, 1);
  if (supersede.includes('loaded selection')) api.selectResource(supersede.includes('other') ? 'C' : 'B');
  else api.clearTimelineSelection();
  const refreshedB = { resourceId: 'B', layer: 'link', refreshed: true };
  release({ lanes: [supersede.startsWith('normal') ? refreshedB : { resourceId: 'A', layer: 'link' }] });
  await pending;
  assert.equal(requests, supersede.includes('other') ? 2 : 1, 'ordinary changed-context windows are refreshed; stale jumps are discarded');
  assert.equal(normalizations, supersede.startsWith('normal') ? 1 : 0, 'only ordinary current-context refreshes reach normalization');
  const expected = supersede.includes('other') ? refreshedC : supersede.startsWith('normal') ? refreshedB : b;
  assert.equal(state.lanes[0], expected);
  assert.equal(state.laneByResource.get(expected.resourceId), expected);
  if (supersede.includes('loaded selection')) assert.equal(state.selectedResourceId, expected.resourceId);
  else assert.equal(state.selectedEventUid, null);
});

test('timeline reset invalidates navigation continuations as well as query authority', () => {
  const state = { timelineNavigationIntent: 4, timelineRequestId: 3, lanes: [], expandedTimelineTreeKeys: new Set(),
    hiddenTimelineResourceIds: new Set(), layerMeta: new Map(), viewStartNs: 0n, viewEndNs: 100n };
  const deps = { state,
    cancelScheduledTimelineZoom: noop, rememberTimelineView: noop, closeTimelineContextMenu: noop, abortLatestRequests: noop,
    clearRangeSelection: noop, isScaleMode: () => false, byId: () => ({}), renderLayerToggles: noop,
    renderRangeSummary: noop, renderEventTable: noop, renderTimeline: noop, scheduleTimelineWindowRefresh: noop, setCursor: noop };
  const reset = new Function(...Object.keys(deps), `${body('invalidatePendingTimelineWindowRequest')}\n${body('resetTimelineView')}\nreturn resetTimelineView;`)(...Object.values(deps));
  reset();
  assert.equal(state.timelineNavigationIntent, 5);
  assert.equal(state.timelineRequestId, 4);
});
