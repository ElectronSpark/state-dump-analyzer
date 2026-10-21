import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { durableReviewTokenMatches } from '../assets/durable_review_controller.js';

const source = readFileSync(new URL('../assets/app.js', import.meta.url), 'utf8');
function load(names, deps) {
  const functions = names.map(name => {
    const match = new RegExp(`^(?:async )?function ${name}\\(`, 'm').exec(source);
    assert.ok(match, name);
    const tail = source.slice(match.index);
    const end = /\r?\n(?:async )?function \w+\(/.exec(tail);
    return tail.slice(0, end.index);
  });
  return new Function(...Object.keys(deps), `${functions.join('\n')}\nreturn {${names.join(',')}};`)(...Object.values(deps));
}
const noop = () => {};
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
function cursorDeps(state) {
  return { state, clampNs: value => value, updateCursorVisual: noop, updateFabricNavigationLink: noop,
    markResourcesPending: noop, markDashboardsPending: noop, scheduleTopologyRefreshFromCursor: noop,
    updateTimelineCommandAvailability: noop, scheduleTemporalRefresh: noop };
}

for (const newer of ['cursor', 'resource', 'none']) test(`toolbar selection resolution yields to ${newer}`, async () => {
  const response = deferred();
  const state = { eventLogSelectionRanges: [[0, 0]], eventLogSelectionQueryKey: 'q', eventLogSelectionRequestId: 0,
    eventLogSelectionFocus: 0, timelineNavigationIntent: 0, laneByResource: new Map(),
    explicitLaneIds: new Set(), hiddenTimelineResourceIds: new Set(), correlatedResourceIds: new Set(),
    resourceById: new Map(), laneMode: 'all' };
  const jumps = [];
  const api = load(['eventLogSelectionCount', 'eventLogSelectionSignature', 'eventLogSelectionRequestBody',
    'resolveEventLogSelection', 'revealFocusedEventLogSelection', 'setCursor', 'selectResource'], {
    ...cursorDeps(state), MAX_EVENT_LOG_SELECTION_ITEMS: 10000, MAX_EVENT_LOG_SELECTION_RANGES: 128,
    serverEventLogRequestBody: () => ({}), revisionPath: x => x, analysisRuntimeApi: () => response.promise,
    rememberTimelineEntryProjection: item => ({ uid: item.uid }), jumpToTimelineEvent: uid => jumps.push(uid),
    forgetTimelineEntryProjection: noop, pruneServerEventLogOwnedCaches: noop, showToast: assert.fail,
    canonicalResourceId: x => x, isScaleMode: () => false, markCorrelationPending: noop,
    rerenderTimelinePreservingScroll: noop, renderResourceTables: noop, refreshDashboardSelectionPresentation: noop,
    requestGraph: noop,
  });
  const pending = api.revealFocusedEventLogSelection();
  if (newer === 'cursor') api.setCursor(90n);
  if (newer === 'resource') api.selectResource('new');
  response.resolve({ items: [{ uid: 'old', display_index: 0 }] });
  await pending;
  assert.deepEqual(jumps, newer === 'none' ? ['old'] : []);
});

for (const interaction of ['input', 'keydown', 'pointerdown']) test(`direct event jump yields to cursor ${interaction} even at the same boundary`, async () => {
  const response = deferred();
  const state = { hiddenTimelineResourceIds: new Set(), activeLayers: new Set(), laneByResource: new Map(),
    laneMode: 'all', timelineNavigationIntent: 0, cursorNs: 720n };
  const selected = [];
  const api = load(['jumpToTimelineEvent', 'setCursor', 'timelineCursorInteraction'], {
    ...cursorDeps(state), eventOrMark: () => ({}), eventTime: () => 30n,
    eventLaneFor: () => null, eventResourceRefs: () => ['old'], isScaleMode: () => false,
    moveTimelineWindowToReveal: () => true, refreshTimelineForNavigation: () => response.promise,
    renderLayerToggles: noop, selectEvent: uid => selected.push(uid), window: { requestAnimationFrame: assert.fail },
    nsAtRatio: () => 720n,
  });
  const pending = api.jumpToTimelineEvent('old');
  api.timelineCursorInteraction({type: interaction, key: 'End', target: {value: '1000000'}});
  response.resolve(true);
  await pending;
  assert.equal(state.cursorNs, 720n);
  assert.deepEqual(selected, []);
});

for (const timing of ['pending response', 'clear', 'queued focus', 'unchanged']) test(`log locate respects ${timing}`, async () => {
  const response = deferred();
  const frames = [], focused = [], scrolled = [];
  const state = { eventLogInclude: {}, eventLogServerQueryId: 1, eventLogLocateRequestId: 0,
    eventLogServerItems: new Map([[20, {}]]), eventLogRows: Array(30), eventLogSelectionRequestId: 0 };
  const scroll = { set scrollTop(value) { scrolled.push(value); } };
  const api = load(['locateServerEventLogEntry', 'focusServerEventLogTarget', 'setEventLogSelectionRanges', 'clearEventLogSelection'], {
    state, syncEventLogIncludeControls: noop, prepareServerEventLogQuery: noop, revisionPath: x => x,
    serverEventLogRequestBody: () => ({}), analysisRuntimeApi: () => response.promise,
    applyServerEventLogPayload: noop, EVENT_LOG_PAGE_SIZE: 80, EVENT_LOG_OVERSCAN: 10,
    EVENT_LOG_ROW_HEIGHT: 44, EVENT_LOG_MAX_SCROLL_HEIGHT: 8000000,
    serverEventLogVirtualRowForDataIndex: x => x, virtualScrollTopForIndex: ({index}) => index,
    eventLogBodyViewportHeight: () => 400, renderEventTableWindow: noop, navigationPulse: noop,
    showToast: assert.fail, normalizeEventLogSelectionRanges: x => x,
    eventLogSelectionCount: () => 1, finishEventLogDrag: noop,
    byId: id => id === 'event-log-scroll' ? scroll : { scrollIntoView: noop,
      querySelectorAll: () => [{ dataset: { logEntryId: 'event:old' }, focus: () => focused.push('old') }] },
    window: { requestAnimationFrame: fn => frames.push(fn) },
  });
  const pending = api.locateServerEventLogEntry('event:old');
  if (timing === 'pending response') api.setEventLogSelectionRanges([[0, 0]], {focus: 0, render: false});
  if (timing === 'clear') api.clearEventLogSelection({render: false});
  response.resolve({ located_display_index: 20 });
  await pending;
  if (timing === 'queued focus') api.setEventLogSelectionRanges([[0, 0]], {focus: 0, render: false});
  while (frames.length) frames.shift()();
  assert.deepEqual(focused, timing === 'unchanged' ? ['old'] : []);
  assert.deepEqual(scrolled, ['pending response', 'clear'].includes(timing) ? [] : [20]);
});

for (const outcome of ['accepted', 'rejected', 'superseded']) test(`candidate timeline stays uncommitted when ${outcome}`, async () => {
  const response = deferred();
  const previous = {lanes: ['previous']};
  const state = {timelineRequestId: 0, timelineNavigationIntent: 0, recordLaneRules: [], cursorNs: 0n, timelinePayload: previous};
  const candidate = [{lane_id: 'candidate', label: 'Warnings', pattern: 'warning|error'}];
  const api = load(['requestTimeline', 'setCursor'], {
    ...cursorDeps(state), isTopologyNodeSnapshot: () => false, isScaleMode: () => false,
    abortLatestRequests: noop, beginLatestRequest: () => new AbortController(), finishLatestRequest: noop,
    timelineWindowBounds: () => [0n, 100n], rangeBounds: () => null, scaleTimelineResourceIds: () => [],
    canonicalResourceId: x => x, timelinePhysicalTrackWidth: () => 900, revisionPath: x => x,
    analysisRuntimeApi: (_path, opts) => {assert.equal(JSON.parse(opts.body).record_lane_rules[0].lane_id, 'candidate'); return response.promise;},
    requestWasAborted: () => false, normalizeTimeline: assert.fail, showToast: assert.fail,
  });
  const pending = api.requestTimeline({navigationIntent: 0, recordLaneRules: candidate});
  if (outcome === 'rejected') {
    response.reject(new Error('invalid pattern'));
    await assert.rejects(pending, /invalid pattern/);
  } else {
    if (outcome === 'superseded') api.setCursor(90n);
    const payload = {record_lanes: ['candidate']};
    response.resolve(payload);
    assert.equal(await pending, outcome === 'accepted' ? payload : false);
  }
  assert.equal(state.timelinePayload, previous);
  assert.deepEqual(state.recordLaneRules, []);
});

for (const outcome of ['rejected', 'edited', 'accepted', 'newer query']) test(`staged lane ${outcome} preserves the pending viewport refresh`, async () => {
  const controls = new Map(['label', 'pattern', 'source', 'unmatched', 'error'].map(key => [`record-lane-${key}`, {value: '', checked: false}]));
  controls.get('record-lane-label').value = 'Warnings';
  controls.get('record-lane-pattern').value = 'warning|error';
  const button = {disabled: false};
  controls.set('record-lane-form', {querySelector: () => button,
    querySelectorAll: () => ['label', 'pattern', 'source', 'unmatched'].map(key => controls.get(`record-lane-${key}`)), reset: noop});
  const state = {timelineRequestId: 0, timelineNavigationIntent: 0, recordLaneRules: [], customRecordLaneSequence: 0,
    cursorNs: 0n, timelinePayload: {window: 'old'}};
  const requests = [];
  let rendered = 0;
  const api = load(['requestTimeline', 'refreshRecordLanes', 'validateRecordLanePattern', 'addRecordLane'], {
    state, byId: id => controls.get(id), document: {activeElement: null},
    MAX_RECORD_PATTERN_LENGTH: 256, MAX_RECORD_LANES: 8,
    isTopologyNodeSnapshot: () => false, isScaleMode: () => false,
    abortLatestRequests: key => state[key]?.abort(), beginLatestRequest: key => state[key] = new AbortController(),
    finishLatestRequest: (key, controller) => {if (state[key] === controller) state[key] = null;},
    requestWasAborted: (_error, controller) => controller.signal.aborted,
    timelineWindowBounds: () => [50n, 60n], rangeBounds: () => null, scaleTimelineResourceIds: () => [],
    canonicalResourceId: x => x, timelinePhysicalTrackWidth: () => 900, revisionPath: x => x,
    analysisRuntimeApi: (_path, opts) => {
      const response = deferred();
      requests.push({...response, signal: opts.signal, body: JSON.parse(opts.body)});
      opts.signal.addEventListener('abort', () => response.reject(new DOMException('aborted', 'AbortError')));
      return response.promise;
    },
    normalizeTimeline: noop, renderTimeline: () => rendered++, showToast: assert.fail,
  });
  const old = api.requestTimeline();
  const staged = api.addRecordLane({preventDefault: noop});
  assert.equal(requests[0].signal.aborted, true);
  let newer;
  if (outcome === 'rejected') requests[1].reject(new Error('core rejected pattern'));
  else if (outcome === 'newer query') newer = api.refreshRecordLanes();
  else {
    if (outcome === 'edited') controls.get('record-lane-label').value = 'Newer input';
    requests[1].resolve({window: 'current'});
  }
  await Promise.all([old, staged]);
  assert.equal(requests.length, outcome === 'accepted' ? 2 : 3);
  if (outcome !== 'accepted') {
    assert.deepEqual(requests[2].body.record_lane_rules, []);
    requests[2].resolve({window: 'current'});
    if (newer) await newer;
    else {await Promise.resolve(); await Promise.resolve();}
  }
  assert.equal(state.timelinePayload.window, 'current');
  assert.equal(rendered, 1);
  assert.equal(state.recordLaneRules.length, outcome === 'accepted' ? 1 : 0);
});

test('repeated overlapping source reveals reuse one allocation and complete the newest request', async () => {
  const state = { sourceRecordByUid: new Map([['source-1', {source_record_uid: 'source-1', source_type: 'trace', timestamp_ns: '30'}]]),
    recordLanes: [], recordLaneRules: [], customRecordLaneSequence: 0, timelineNavigationIntent: 0,
    timelineRequestId: 0, timelinePayload: null, cursorNs: 0n, selectedResourceId: null, lanes: [] };
  const requests = [], selections = [];
  const api = load(['sourceRecordUid', 'sourceRecordLaneFor', 'regexEscape', 'ensureSourceRecordLane',
    'requestTimeline', 'jumpSourceRecordToTimeline'], {
    state, MAX_RECORD_LANES: 8, showToast: assert.fail, eventOrMark: () => null,
    sourceRecordTime: () => 30n, moveTimelineWindowToReveal: () => false,
    selectSourceRecord: uid => selections.push(uid), renderTimeline: noop, renderLanePicker: noop,
    isTopologyNodeSnapshot: () => false, isScaleMode: () => false,
    timelineWindowBounds: () => [0n, 100n], rangeBounds: () => null,
    scaleTimelineResourceIds: () => [], canonicalResourceId: x => x, timelinePhysicalTrackWidth: () => 900, revisionPath: x => x,
    abortLatestRequests: key => state[key]?.abort(), beginLatestRequest: key => state[key] = new AbortController(),
    finishLatestRequest: (key, controller) => { if (state[key] === controller) state[key] = null; },
    requestWasAborted: (_error, controller) => controller.signal.aborted,
    analysisRuntimeApi: (_path, opts) => new Promise((resolve, reject) => {
      requests.push({body: JSON.parse(opts.body), resolve});
      opts.signal.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
    }),
    normalizeTimeline: payload => { state.recordLanes = payload.record_lanes; },
    window: {requestAnimationFrame: noop},
  });
  const pending = Array.from({length: 9}, () => api.jumpSourceRecordToTimeline('source-1'));
  assert.equal(state.recordLaneRules.length, 1);
  const last = requests.at(-1);
  last.resolve({record_lanes: last.body.record_lane_rules.map(rule => ({laneId: rule.lane_id, marks: [{sourceRecordUid: 'source-1'}]}))});
  await Promise.all(pending);
  assert.equal(state.recordLanes.length, 1);
  assert.deepEqual(selections, ['source-1']);
  await api.jumpSourceRecordToTimeline('source-1');
  assert.equal(requests.length, 9, 'loaded repeat needs no query or allocation');
});

test('custom lane validation rejects without retention, permits correction, and preserves newer form input', async () => {
  const controls = new Map(['label', 'pattern', 'source', 'unmatched', 'error'].map(key => [`record-lane-${key}`, {value: '', checked: false}]));
  const button = { disabled: false };
  let resetCount = 0, refreshCount = 0, response;
  const form = { querySelector: () => button, querySelectorAll: () => ['label', 'pattern', 'source', 'unmatched'].map(key => controls.get(`record-lane-${key}`)), reset: () => resetCount++ };
  controls.set('record-lane-form', form);
  const state = {recordLaneRules: [], customRecordLaneSequence: 0};
  const api = load(['validateRecordLanePattern', 'addRecordLane'], {state, byId: id => controls.get(id),
    document: {activeElement: null},
    MAX_RECORD_PATTERN_LENGTH: 256, MAX_RECORD_LANES: 8, isTopologyNodeSnapshot: () => false,
    requestTimeline: () => response.promise, normalizeTimeline: noop, renderTimeline: () => refreshCount++});
  controls.get('record-lane-label').value = 'Warnings';
  for (const pattern of ['(warning|error)', 'warning{2}', 'warning.*error.*timeout']) {
    controls.get('record-lane-pattern').value = pattern;
    response = deferred();
    const pending = api.addRecordLane({preventDefault: noop});
    response.reject(new Error('core rejected pattern'));
    await pending;
    assert.equal(state.recordLaneRules.length, 0);
    assert.equal(controls.get('record-lane-pattern').value, pattern);
    assert.equal(button.disabled, false);
  }
  controls.get('record-lane-pattern').value = 'warning|error';
  response = deferred();
  const stale = api.addRecordLane({preventDefault: noop});
  controls.get('record-lane-label').value = 'Newer name';
  response.resolve({});
  await stale;
  assert.equal(state.recordLaneRules.length, 0);
  response = deferred();
  const current = api.addRecordLane({preventDefault: noop});
  response.resolve({});
  await current;
  assert.equal(state.recordLaneRules.length, 1);
  assert.equal(state.recordLaneRules[0].label, 'Newer name');
  assert.equal(resetCount, 1);
  assert.equal(refreshCount, 1);
});

test('typed subpixel ranges remain bounded and never move opposite the keyboard direction', () => {
  const origin = 1700000000000000000n;
  const state = {viewStartNs: origin, viewEndNs: origin + 720000000000n, trackWidth: 1176};
  const controls = new Map([['range-start-input', {value: '0'}], ['range-end-input', {value: '0.01'}]]);
  const byId = id => { if (!controls.has(id)) controls.set(id, {}); return controls.get(id); };
  const api = load(['clampNs', 'rangeBounds', 'rangeMinimumNs', 'formatRangeInput', 'parseRangeInput',
    'syncRangeInputs', 'applyRangeEditor', 'timelineHandleKeyDown', 'applyHandlePosition'], {
    state, byId, toNs: BigInt, timelineWindowBounds: () => [state.viewStartNs, state.viewEndNs],
    updateRangeBands: noop, requestRangeSummary: () => {
      assert.ok(state.rangeStartNs >= state.viewStartNs && state.rangeEndNs <= state.viewEndNs);
    },
  });
  const key = (boundary, key) => api.timelineHandleKeyDown({target: {closest: () => ({dataset: {rangeHandle: boundary}})}, key, preventDefault: noop});
  api.applyRangeEditor();
  key('start', 'ArrowRight');
  assert.equal(state.rangeStartNs, origin);
  key('end', 'ArrowRight');
  assert.ok(state.rangeEndNs > origin + 10000000n);
  byId('range-start-input').value = '719.986';
  byId('range-end-input').value = '719.996';
  api.applyRangeEditor();
  key('end', 'ArrowLeft');
  assert.equal(state.rangeEndNs, origin + 719996000000n);
  key('start', 'Home');
  assert.equal(state.rangeStartNs, origin);
  key('end', 'End');
  assert.equal(state.rangeEndNs, state.viewEndNs);
});

for (const change of ['disconnect', 'reconnect', 'none']) test(`pending correlation preparation handles ${change}`, async () => {
  const response = deferred();
  const state = {eventLogSelectionRanges: [[0, 1]], eventLogSelectionQueryKey: 'q', eventLogSelectionRequestId: 0,
    durableReview: {status: 'ready', config: {tenantId: 't', projectId: 'p', workspaceId: 'w', principalId: 'u'},
      catalogRevisionId: 'rev-A', canWrite: true, connectionSequence: 1, pendingCorrelationSubjects: []}};
  const controls = new Map();
  const byId = id => { if (!controls.has(id)) controls.set(id, {open: false, focus: noop,
    showModal() {this.open = true;}, close() {this.open = false;}}); return controls.get(id); };
  const api = load(['eventLogSelectionCount', 'eventLogSelectionSignature', 'eventLogSelectionRequestBody',
    'resolveEventLogSelection', 'exactReviewSubject', 'reviewSubjectKey', 'uniqueReviewSubjects',
    'isDurableReviewReady', 'isDurableReviewWritable', 'durableReviewConnectionToken', 'durableReviewTokenIsCurrent',
    'openManualCorrelationDialog', 'closeManualCorrelationDialog', 'connectDurableReview'], {
    state, byId, durableReviewTokenMatches, MAX_EVENT_LOG_SELECTION_ITEMS: 10000, MAX_EVENT_LOG_SELECTION_RANGES: 128,
    serverEventLogRequestBody: () => ({}), revisionPath: x => x, analysisRuntimeApi: () => response.promise,
    showToast: assert.fail, durableReviewConfigFromInputs: () => null, clearDurableReviewMarkers: noop,
    renderDurableReportScopes: noop, setDurableReviewStatus: status => {state.durableReview.status = status;},
  });
  const pending = api.openManualCorrelationDialog();
  if (change !== 'none') await api.connectDurableReview();
  if (change === 'reconnect') Object.assign(state.durableReview, {status: 'ready', canWrite: true,
    config: {tenantId: 't', projectId: 'p', workspaceId: 'other', principalId: 'u'}, catalogRevisionId: 'rev-B'});
  response.resolve({items: [{stream_kind: 'event', uid: 'A'}, {stream_kind: 'event', uid: 'B'}]});
  await pending;
  assert.equal(byId('correlation-dialog').open, change === 'none');
  assert.equal(state.durableReview.pendingCorrelationSubjects.length, change === 'none' ? 2 : 0);
  if (change === 'none') assert.equal(state.durableReview.pendingCorrelationSubjects[0].revision_id, 'rev-A');
});
