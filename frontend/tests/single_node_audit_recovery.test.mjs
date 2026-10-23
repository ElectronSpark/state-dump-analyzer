import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const source = readFileSync(new URL('../assets/app.js', import.meta.url), 'utf8');
function load(names, deps) {
  const bodies = names.map(name => {
    const match = new RegExp(`^(?:async )?function ${name}\\(`, 'm').exec(source);
    assert.ok(match, name);
    const tail = source.slice(match.index);
    const end = /\n(?:async )?function \w+\(/.exec(tail);
    return tail.slice(0, end?.index);
  });
  return new Function(...Object.keys(deps), `${bodies.join('\n')}\nreturn {${names.join(',')}};`)(...Object.values(deps));
}
const noop = () => {};
const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; };

for (const [kind, identity, key] of [
  ['event', { eventUid: 'e', resourceId: 'r', treeKey: 'branch-b' }, 'event:branch-b:e'],
  ['event review', { eventUid: 'e', resourceId: null }, 'review-marker:event:e'],
  ['source', { sourceRecordUid: 's', sourceLaneId: 'preset-b' }, 'source-record:preset-b:s'],
  ['source review', { sourceRecordUid: 's', sourceLaneId: null }, 'review-marker:source:s'],
  ['event cluster', { clusterId: 'c' }, 'cluster:branch-b:c'],
  ['source cluster', { sourceClusterId: 'c' }, 'source-cluster:preset-b:c'],
  ['review cluster', {}, 'annotation-cluster:0:10'],
]) test(`${kind} pointer activation anchors to its live instance through repeated timeline replacement`, () => {
  const original = { dataset: { hoverKey: key }, isConnected: true };
  const other = { dataset: { hoverKey: `other-instance:${key}` }, isConnected: true };
  let replacement = original;
  let current = [other, original];
  const selections = [];
  const shown = [];
  const select = (...args) => {
    selections.push(args);
    replacement.isConnected = false;
    replacement = { dataset: { hoverKey: key }, isConnected: true };
    current = [other, replacement];
  };
  const timeline = { querySelector: selector => current.find(item => selector === `[data-hover-key="${item.dataset.hoverKey}"]`) || null };
  const api = load(['activateShortGestureTarget'], {
    state: {}, performance: { now: () => 1000 }, CSS: { escape: String }, byId: () => timeline,
    selectEvent: select, selectSourceRecord: select,
    showHover: (hoverKey, anchor, pin) => shown.push({ hoverKey, anchor, pin }),
  });
  for (let repeat = 0; repeat < 2; repeat++) {
    assert.equal(api.activateShortGestureTarget({ ...identity, hoverKey: key, element: original }), true);
    assert.deepEqual(shown.at(-1), { hoverKey: key, anchor: replacement, pin: true });
    assert.equal(shown.at(-1).anchor.isConnected, true);
    assert.notEqual(shown.at(-1).anchor, other);
  }
  const selectedArgs = identity.eventUid ? ['e', true, identity.resourceId] : ['s', true];
  assert.deepEqual(selections, identity.eventUid || identity.sourceRecordUid ? [selectedArgs, selectedArgs] : []);
  current = [];
  const count = shown.length;
  assert.equal(api.activateShortGestureTarget({ hoverKey: key, element: original }), true);
  assert.equal(shown.length, count, 'a removed target must not anchor to detached DOM');
});

test('source keyboard click handler reacquires its instance after selection and keeps Ctrl-click navigation', () => {
  const listeners = new Map();
  const key = 'source-record:preset-b:source-1';
  const original = { dataset: { sourceRecordUid: 'source-1', hoverKey: key },
    addEventListener: (type, listener) => listeners.set(type, listener) };
  const replacement = { dataset: { ...original.dataset }, isConnected: true };
  const timeline = {
    querySelectorAll: selector => selector === '.source-record-mark[data-source-record-uid]' ? [original] : [],
    querySelector: selector => selector === `[data-hover-key="${key}"]` ? replacement : null,
  };
  const shown = [], selected = [], jumped = [];
  const api = load(['bindTimelineInteractions'], {
    byId: () => timeline, state: { suppressTimelineClickUntil: 0 },
    performance: { now: () => 1000 }, CSS: { escape: String },
    selectSourceRecord: (...args) => { original.isConnected = false; selected.push(args); },
    showHover: (...args) => shown.push(args), jumpToSourceLog: uid => jumped.push(uid),
  });
  api.bindTimelineInteractions();
  const click = listeners.get('click');
  for (let repeat = 0; repeat < 2; repeat++) click({ stopPropagation: noop });
  assert.deepEqual(selected, [['source-1', true], ['source-1', true]]);
  assert.deepEqual(shown, [[key, replacement, true], [key, replacement, true]]);
  click({ ctrlKey: true, stopPropagation: noop, preventDefault: noop });
  assert.deepEqual(jumped, ['source-1']);
  assert.equal(selected.length, 2);
  assert.equal(shown.length, 2);
  timeline.querySelector = () => null;
  click({ stopPropagation: noop });
  assert.equal(shown.length, 2, 'a removed source instance must not reopen a stale popup');
});

for (const kind of ['event', 'event review', 'source review']) test(`${kind} click skips a popup when selection removes its instance`, () => {
  const listeners = new Map();
  const entryId = kind === 'source review' ? 'source:s' : 'event:e';
  const original = { isConnected: true, dataset: { eventUid: 'e', hoverKey: kind, logEntryId: entryId },
    addEventListener: (type, listener) => listeners.set(type, listener), closest: () => ({ dataset: { resourceId: 'r' } }) };
  const selector = kind === 'event' ? '.event-mark[data-event-uid]' : '.review-marker[data-hover-key]';
  const timeline = { querySelectorAll: value => value === selector && original.isConnected ? [original] : [], querySelector: () => null };
  const api = load(['bindTimelineInteractions'], {
    byId: () => timeline, state: { suppressTimelineClickUntil: 0,
      timelineEntryProjections: new Map([[entryId, { streamKind: kind === 'source review' ? 'source' : 'event', uid: 'id' }]]) },
    performance: { now: () => 1000 }, CSS: { escape: String },
    selectEvent: () => { original.isConnected = false; }, selectSourceRecord: () => { original.isConnected = false; },
    showHover: () => assert.fail('detached marker used as a popup anchor'),
  });
  api.bindTimelineInteractions();
  listeners.get('click')({ stopPropagation: noop });
  assert.equal(original.isConnected, false);
});

for (const kind of ['cluster', 'source-cluster', 'annotation-cluster']) test(`dense ${kind} layout bounds neighboring footprints without changing exact identity`, () => {
  let zoom = 1;
  const api = load(['timelineGlyphLayout'], { timelinePercent: time => Number(time) * zoom / 10 });
  const cluster = { kind, clusterId: '132-events', startNs: 124n, endNs: 149n, count: 132 };
  const next = { kind, clusterId: '12-events', startNs: 149n, endNs: 151n, count: 12 };
  const event = { kind: 'event', eventUid: 'exact', timeNs: 130n, failure: true };
  const layout = api.timelineGlyphLayout([cluster, next, event], 1000);
  assert.deepEqual(layout.map(item => item.glyph), [event, cluster, next]);
  assert.deepEqual(layout.map(item => item.space), [6, 6, 14]);
  assert.equal(cluster.clusterId, '132-events');
  assert.equal(cluster.count, 132);
  assert.deepEqual([cluster.startNs, cluster.endNs], [124n, 149n]);
  zoom = 10;
  assert.deepEqual(api.timelineGlyphLayout([cluster, next, event], 1000).map(item => item.space), [27, 27, 27]);
  const css = readFileSync(new URL('../assets/styles.css', import.meta.url), 'utf8');
  assert.match(css, /max-width: var\(--glyph-space, 27px\)/);
  assert.match(css, /\.event-mark\.cluster span\s*\{\s*pointer-events: none/);
});

for (const kind of ['cluster', 'source-cluster', 'annotation-cluster']) test(`equal-time events and a ${kind} midpoint retain visible footprints`, () => {
  const api = load(['timelineGlyphLayout'], { timelinePercent: Number });
  const glyphs = [
    { eventUid: 'a', timeNs: 50n }, { eventUid: 'b', timeNs: 50n, failure: true },
    { kind, startNs: 40n, endNs: 60n, staleWindow: true },
  ];
  assert.deepEqual(api.timelineGlyphLayout(glyphs, 100).map(item => item.space), [27, 27, 27]);
  assert.deepEqual(api.timelineGlyphLayout([...glyphs, {timeNs: 60n}], 100).map(item => item.space), [10, 10, 10, 10]);
});

test('review markers keep both nearby identities reachable and bound adjacent cluster footprints through zoom changes', () => {
  let zoom = 1;
  const projections = Array.from({ length: 130 }, (_, index) => ({
    entryId: `event:${index}`, uid: String(index), streamKind: 'event', timeNs: BigInt(index),
    entry: { event_type: `event-${index}` },
  }));
  const state = { trackWidth: 1000, hoverModels: new Map(), hiddenTimelineEntryIds: new Set(['event:0']),
    markedTimelineEntryIds: new Set(), timelineEntryProjections: new Map(projections.map(item => [item.entryId, item])) };
  const api = load(['buildAnnotationGlyphs', 'timelineGlyphLayout', 'reviewMarkerLaneHtml',
    'annotationClusterHoverHtml', 'annotationProjectionLabel'], {
    state, timelinePercent: ns => Number(ns) * zoom / 100, timelinePointVisible: () => true,
    escapeHtml: String, formatOffset: String, visibleTimelineOffsetPrecision: () => 3,
    timelineLaneWidth: () => 210, eventLogHoverModel: entry => ({ entry }),
  });
  state.markedTimelineEntryIds = new Set(['event:0', 'event:1']);
  let html = api.reviewMarkerLaneHtml();
  assert.equal((html.match(/class="review-marker cluster/g) || []).length, 1);
  assert.match(html, /2 review markers; 1 underlying marks hidden/);
  const cluster = [...state.hoverModels.values()][0];
  assert.deepEqual(cluster.items.map(item => item.entryId), ['event:0', 'event:1']);
  const drilldown = api.annotationClusterHoverHtml(cluster.items);
  for (const id of ['event:0', 'event:1']) assert.ok(drilldown.includes(`data-annotation-entry-id="${id}"`));
  zoom = 200;
  html = api.reviewMarkerLaneHtml();
  assert.equal((html.match(/class="review-marker event/g) || []).length, 2);
  for (const id of ['event:0', 'event:1']) assert.ok(html.includes(`data-log-entry-id="${id}"`));
  zoom = 1;
  state.markedTimelineEntryIds = new Set(projections.map(item => item.entryId));
  state.hoverModels.clear();
  html = api.reviewMarkerLaneHtml();
  assert.equal((html.match(/class="review-marker cluster/g) || []).length, 3);
  const layout = api.timelineGlyphLayout(api.buildAnnotationGlyphs(projections), state.trackWidth);
  assert.deepEqual(layout.map(item => item.glyph.items.length), [64, 64, 2]);
  assert.deepEqual([...state.hoverModels.values()].flatMap(model => model.items.map(item => item.entryId)),
    projections.map(item => item.entryId));
  layout.forEach(({ space }) => assert.ok(html.includes(`--glyph-space:${space}px`)));
  for (let index = 1; index < layout.length; index++) {
    const gap = Number(layout[index].time - layout[index - 1].time) / 10;
    assert.ok((layout[index].space + layout[index - 1].space) / 2 <= gap + 1e-10);
  }
});

test('log and review hover reuse the matching resource mark including finite or open duration and effect operation', () => {
  const unrelated = { eventUid: 'other', durationToNextChangeNs: 900n };
  const mark = { eventUid: 'event', action: 'modify', durationToNextChangeNs: 120_000_000_000n };
  const lane = { resourceId: 'backup', marks: [unrelated, mark] };
  const state = { lanes: [lane], resourceById: new Map() };
  const api = load(['eventLogHoverModel', 'formatDuration'], {
    state, isSourceLogEntry: () => false, eventResourceRefs: () => ['primary'],
    normalizeMark: () => assert.fail('rebuilding the raw entry loses per-resource history'), toNs: BigInt,
  });
  const model = api.eventLogHoverModel({ event_uid: 'event', action: 'state-change' });
  assert.equal(model.lane, lane);
  assert.equal(model.mark, mark);
  assert.equal(model.mark.action, 'modify');
  assert.equal(api.formatDuration(model.mark.durationToNextChangeNs), '2m 0s');
  mark.durationToNextChangeNs = null;
  assert.equal(api.formatDuration(api.eventLogHoverModel({ event_uid: 'event' }).mark.durationToNextChangeNs), 'until capture end');
});

test('unloaded log events distinguish unknown duration from explicit open-ended evidence without inventing history', () => {
  const state = { lanes: [], resourceById: new Map(), eventByUid: new Map() };
  const api = load(['eventLogHoverModel', 'normalizeMark', 'formatDuration'], {
    state, isSourceLogEntry: () => false, eventResourceRefs: () => ['resource'],
    eventSubject: () => ({}), resourceLayer: () => 'layer', resourceKind: () => 'kind',
    resourceEffectFor: () => null, normalizedEventOutcome: () => 'success', titleCase: String,
    eventFailed: () => false, eventChangesState: () => true,
    toNs: (value, fallback) => value == null ? fallback : BigInt(value),
  });
  for (const [raw, expected] of [
    [{}, 'unknown'], [{ duration_to_next_change_ns: null }, 'until capture end'],
    [{ duration_to_next_change_ns: '0' }, '0 ns'], [{ duration_to_next_change_ns: '120000000000' }, '2m 0s'],
  ]) {
    const model = api.eventLogHoverModel({ event_uid: 'unloaded', timestamp_ns: '10', ...raw });
    assert.equal(api.formatDuration(model.mark.durationToNextChangeNs), expected);
    assert.equal(model.lane.resourceId, 'resource');
    assert.deepEqual(model.occurrenceLanes, []);
  }
});

test('server duration evidence survives normalization, bounded lane derivation and shared log/review hover', () => {
  const state = { viewEndNs: 100n, eventByUid: new Map(), resourceById: new Map(), lanes: [] };
  const api = load(['normalizeMark', 'deriveLaneIntervals', 'eventLogHoverModel'], {
    state, toNs: (value, fallback) => value == null ? fallback : BigInt(value),
    resourceEffectFor: () => ({ effect_type: 'modify', state_changed: true }),
    normalizedEventOutcome: () => 'success', titleCase: String, eventFailed: () => false,
    eventChangesState: () => true, isSourceLogEntry: () => false, eventResourceRefs: () => ['resource'],
  });
  for (const duration of ['0', '90', null, undefined]) {
    const lane = { laneId: 'resource', resourceId: 'resource', authoritativeHistory: true };
    const raw = { event_uid: 'event', time_ns: '10', duration_to_next_change_ns: duration,
      event: { event_uid: 'event', timestamp_ns: '10' } };
    lane.marks = [api.normalizeMark(raw, lane)];
    state.lanes = [lane];
    api.deriveLaneIntervals(lane);
    assert.equal(api.eventLogHoverModel(raw.event).mark.durationToNextChangeNs,
      duration == null ? duration : BigInt(duration));
  }
});

test('inspector duration belongs to the selected resource even when only another effect is loaded', () => {
  const elements = new Map();
  const byId = id => { if (!elements.has(id)) elements.set(id, {}); return elements.get(id); };
  const lane = { resourceId: 'loaded', label: 'Loaded resource' };
  lane.marks = [{ eventUid: 'event', lane, durationToNextChangeNs: 90n }];
  const state = { selectedEventResourceId: 'loaded', lanes: [lane], resourceById: new Map() };
  const api = load(['formatDuration', 'renderEventInspector'], {
    state, byId, toNs: BigInt, eventSubject: () => ({ resource_id: 'other' }),
    resourceEffectFor: () => ({ effect_type: 'modify' }), resourceEffectCondition: () => null,
    titleCase: String, humanLayer: String, eventOutcomeText: () => 'success', eventTime: () => 10n,
    formatOffset: String, formatValue: String, eventStatus: () => 'unknown', escapeHtml: String,
    eventEffectMarkup: () => '',
  });
  for (const [selected, duration] of [['loaded', '90 ns'], ['other', 'unknown']]) {
    state.selectedEventResourceId = selected;
    api.renderEventInspector({ event_uid: 'event', event_type: 'changed' });
    assert.ok(byId('selected-event-fields').innerHTML.includes(`<dt>Status duration</dt><dd>${duration}</dd>`));
  }
});
function bindControlGroup(selector, nextSelector, deps) {
  const start=source.indexOf(`document.querySelectorAll("${selector}").forEach((button) => button.addEventListener`);
  const end=source.indexOf(`document.querySelectorAll("${nextSelector}")`,start+1);
  assert.ok(start>=0&&end>start);
  new Function(...Object.keys(deps),source.slice(start,end))(...Object.values(deps));
}
function viewportDeps(state) {
  const element={value:'',style:{},scrollLeft:0,scrollWidth:800,clientWidth:800,
    getBoundingClientRect:()=>({left:0}),setAttribute:noop};
  return {byId:()=>element,cancelScheduledTimelineZoom:noop,timelinePhysicalTrackWidth:()=>800,timelineLaneWidth:()=>200,
    timelineZoomControlValue:String,clampNs:x=>x,visibleTimelineCenterNs:()=>50n,
    timelineWindowBounds:()=>[state.timelineWindowStartNs,state.timelineWindowEndNs],
    timelineWindowForZoom:({zoom,anchorNs})=>({zoom,startNs:anchorNs-20n,endNs:anchorNs+20n}),
    rememberTimelineView:noop,scheduleTimelineWindowRefresh:noop,invalidatePendingTimelineWindowRequest:noop,
    renderTimeline:noop,updateTimelineCommandAvailability:noop};
}

for (const newer of ['back', 'pan', 'hide', 'none']) test(`pending toolbar Reveal yields to originating ${newer} handler`, async () => {
  const response = deferred();
  const state = { timelineNavigationIntent: 0, eventLogSelectionFocus: 0, cursorNs: 90n,
    timelineViewHistoryIndex: 1, timelineViewHistory: [{ zoom: 2, startNs: 50n, endNs: 100n }, { zoom: 2, startNs: 0n, endNs: 50n }],
    viewStartNs: 0n, viewEndNs: 100n, timelineWindowStartNs: 10n, timelineWindowEndNs: 30n,
    laneMode: 'custom', explicitLaneIds: new Set(['r']), hiddenTimelineResourceIds: new Set() };
  const jumps = [];
  const api = load(['revealFocusedEventLogSelection', 'restoreTimelineView', 'panTimelineViewportByPixels', 'setExplicitLaneVisibility'], {
    state, resolveEventLogSelection: () => response.promise, rememberTimelineEntryProjection: item => item,
    jumpToTimelineEvent: uid => jumps.push(uid), forgetTimelineEntryProjection: noop, pruneServerEventLogOwnedCaches: noop,
    showToast: assert.fail, canonicalResourceId: x => x, isScaleMode: () => false,
    renderTimeline: noop, renderResourceTables: noop, cancelScheduledTimelineZoom: noop,
    invalidatePendingTimelineWindowRequest: noop, byId: () => ({style:{}}), timelineZoomControlValue: String,
    scheduleTimelineWindowRefresh: noop, updateTimelineCommandAvailability: noop,
    timelineWindowBounds: () => [state.timelineWindowStartNs,state.timelineWindowEndNs], timelinePhysicalTrackWidth: () => 100,
    timelineTimeAtRatio: ({ratio,endNs}) => BigInt(Math.round(ratio * Number(endNs))), rememberTimelineView: noop,
  });
  const pending = api.revealFocusedEventLogSelection();
  if (newer === 'back') api.restoreTimelineView(0);
  if (newer === 'pan') api.panTimelineViewportByPixels(20);
  if (newer === 'hide') api.setExplicitLaneVisibility('r', false);
  if (newer === 'none') {
    const button={dataset:{laneAction:'none'},addEventListener(_type,fn){this.click=fn;}};
    bindControlGroup('[data-lane-action]','[data-correlation-view]',{state,document:{querySelectorAll:()=>[button]},
      isScaleMode:()=>false,renderTimeline:noop,renderResourceTables:noop});
    button.click();
  }
  const finalView = [state.timelineWindowStartNs,state.timelineWindowEndNs];
  response.resolve({ items: [{uid:'old',display_index:0}] });
  await pending;
  assert.deepEqual(jumps, []);
  assert.deepEqual([state.timelineWindowStartNs,state.timelineWindowEndNs],finalView);
  if (newer === 'hide') assert.equal(state.explicitLaneIds.has('r'),false);
  if (newer === 'none') assert.equal(state.explicitLaneIds.size,0);
});

for (const changed of [false,true]) test(`independent log actions share unchanged selection resolution; changed=${changed}`, async () => {
  const response = deferred(); let requests = 0;
  const state = { eventLogSelectionRequestId: 0, eventLogSelectionRanges:[[0,1]], eventLogSelectionQueryKey:'q',
    hiddenTimelineEntryIds:new Set(['event:a','event:b']), markedTimelineEntryIds:new Set(['event:a','event:b']),
    localMarkedTimelineEntryIds:new Set(['event:a','event:b']), durableReview:{markedEntryIds:new Set()} };
  const messages=[];
  const api = load(['resolveEventLogSelection','applyEventLogTimelineAction'], {
    state, eventLogSelectionCount:()=>2, eventLogSelectionSignature:()=>`${state.eventLogSelectionRequestId}`,
    MAX_EVENT_LOG_SELECTION_ITEMS:5000,MAX_EVENT_LOG_SELECTION_RANGES:128,eventLogSelectionRequestBody:()=>({}),
    analysisRuntimeApi:()=>{requests++;return response.promise;},revisionPath:x=>x,
    beginDurableReviewOperation:()=>({}),isDurableReviewReady:()=>false,isDurableReviewWritable:()=>false,
    applyLocalMarkerSelection:items=>items.forEach(item=>state.localMarkedTimelineEntryIds.delete(item.entry_id)),
    forgetTimelineEntryProjection:noop,pruneServerEventLogOwnedCaches:noop,rerenderTimelinePreservingScroll:noop,
    renderEventTableWindow:noop,showToast:m=>messages.push(m),finishDurableReviewOperation:noop,
  });
  const show=api.applyEventLogTimelineAction('show');
  const remove=api.applyEventLogTimelineAction('unmark');
  assert.equal(requests,1);
  if(changed) state.eventLogSelectionRequestId++;
  response.resolve({items:[{entry_id:'event:a'},{entry_id:'event:b'}]});
  await Promise.all([show,remove]);
  assert.equal(state.hiddenTimelineEntryIds.size,changed?2:0);
  assert.equal(state.markedTimelineEntryIds.size,changed?2:0);
  assert.equal(messages.filter(m=>m.startsWith('Could not')).length,changed?2:0);
});

test('multi-effect event reveal enables and focuses the originally chosen resource after refinement', async () => {
  const frames=[];const target={focus:()=>{target.focused=true;},dataset:{eventUid:'e'},closest:()=>({dataset:{resourceId:'etg'}})};
  const row={dataset:{resourceId:'etg'}};
  const state={timelineNavigationIntent:0,zoom:2,viewStartNs:0n,viewEndNs:1000n,timelineWindowStartNs:0n,timelineWindowEndNs:100n,
    hiddenTimelineResourceIds:new Set(),activeLayers:new Set(['control']),
    laneMode:'custom',explicitLaneIds:new Set(['etg']),laneByResource:new Map([['etg',{resourceId:'etg',layer:'bridge'}]])};
  let first=true;let selected;
  const api=load(['jumpToTimelineEvent','moveTimelineWindowToReveal','applyTimelineZoom'],{state,...viewportDeps(state),eventOrMark:()=>({}),eventTime:()=>120n,eventResourceRefs:()=>['etg'],
    eventLaneFor:()=>first?(first=false,{resourceId:'etg',layer:'bridge'}):{resourceId:'peer',layer:'control'},
    isScaleMode:()=>false,refreshTimelineForNavigation:async()=>true,
    laneSelectedByMode:id=>state.explicitLaneIds.has(id),renderLayerToggles:noop,
    selectEvent:(_uid,_move,id)=>{selected=id;},window:{requestAnimationFrame:f=>frames.push(f)},
    document:{querySelectorAll:selector=>selector.includes('data-event-uid')?[target]:[row]},
    scrollTimelineTargetIntoView:noop,navigationPulse:noop});
  state.hoverModels=new Map();
  await api.jumpToTimelineEvent('e');frames.forEach(f=>f());
  assert.equal(selected,'etg');assert.ok(state.activeLayers.has('bridge'));assert.equal(state.activeLayers.has('hardware'),false);
  assert.equal(target.focused,true);
});

test('combined association rendering honors counterpart layers and samples the full wide window',()=>{
  const state={correlationTimelineView:'combined',selectedResourceId:'root',correlationTimelineExpanded:true,
    activeLayers:new Set(['control','bridge']),laneByResource:new Map([['root',{layer:'control'}],['child',{layer:'bridge'}]]),
    resourceById:new Map(),hoverModels:new Map(),viewStartNs:0n,viewEndNs:10000n};
  let spans=Array.from({length:8000},(_,i)=>({id:String(i),source:'root',target:'child',startNs:BigInt(i),endNs:BigInt(i+1)}));
  const api=load(['combinedAssociationLane'],{state,resourceHiddenFromTimeline:()=>false,temporalRelationshipSpans:()=>spans,
    resourceLayer:()=> 'bridge',timelineIntervalVisible:()=>true,rangeBounds:()=>null,timelineRangeBandHtml:()=>'',
    timelinePointVisible:()=>true,timelinePercent:x=>Number(x)/100,barStyle:()=>'',safeClass:String,escapeHtml:String,
    intersectsRange:()=>false,layerColor:()=>'',resourceLabel:(_,id)=>id,relationshipDisplayLabel:String,timelineLaneWidth:()=>200});
  const wide=api.combinedAssociationLane(800);
  assert.match(wide,/Sampled 300 of 8000/);
  assert.equal((wide.match(/class="association-segment /g)||[]).length,300);
  assert.ok(state.hoverModels.has('relationship:0:combined'));assert.ok(state.hoverModels.has('relationship:7999:combined'));
  state.activeLayers.delete('bridge');assert.doesNotMatch(api.combinedAssociationLane(800),/class="association-segment /);
  state.activeLayers.add('bridge');spans=spans.slice(4000,4050);
  const narrow=api.combinedAssociationLane(800);assert.doesNotMatch(narrow,/Sampled/);
  assert.equal((narrow.match(/class="association-segment /g)||[]).length,50);
});

test('cluster accessibility retains authoritative totals and qualifies preview range counts',()=>{
  const attrs={};const classes=new Set();
  const element={dataset:{hoverKey:'cluster'},classList:{contains:()=>false,toggle:(key,on)=>on?classes.add(key):classes.delete(key)},setAttribute:(k,v)=>attrs[k]=v};
  const cluster={count:249,items:Array.from({length:50},(_,i)=>({timeNs:BigInt(i)})),staleWindow:true};
  const api=load(['pointClusterRangeState','applyRangeHighlight'],{state:{hoverModels:new Map([['cluster',{cluster}]])},
    byId:()=>({classList:{toggle:noop}}),document:{querySelectorAll:s=>s.includes('[data-hover-key]')?[element]:[]}});
  api.applyRangeHighlight(null);assert.match(attrs['aria-label'],/^249 collapsed events;/);
  api.applyRangeHighlight([0n,48n]);assert.match(attrs['aria-label'],/49 of 50 loaded preview events/);
  assert.match(attrs['aria-label'],/previous viewport/);assert.equal(classes.has('in-range'),false);
  cluster.detailHydrated=true;cluster.detailItems=Array.from({length:200},(_,i)=>({timeNs:BigInt(i)}));
  api.applyRangeHighlight([0n,65n]);assert.match(attrs['aria-label'],/66 of 200 loaded preview events/);
});

test('cache pruning bounds history while preserving visible, selected, projected, open and pending evidence',()=>{
  const entries=prefix=>new Map(Array.from({length:2000},(_,i)=>[`${prefix}${i}`,{i}]));
  const state={eventByUid:entries('e'),eventDetailByUid:entries('e'),sourceRecordByUid:entries('s'),
    selectedEventUid:'e0',selectedSourceRecordUid:'s0',eventDetailRequests:new Map([['e1',{}]]),
    lanes:[{marks:[{eventUid:'e2'}],clusters:[{items:[{eventUid:'e3'}],detailItems:[{eventUid:'e4'}]}]}],
    recordLanes:[{marks:[{sourceRecordUid:'s1'}]}],hoverKey:'open',hoverModels:new Map([['open',{mark:{eventUid:'e5'}}]]),
    eventLogServerItems:new Map([[0,{kind:'entry',entry:{event_uid:'e6'}}]]),
    timelineEntryProjections:new Map([['source:s2',{streamKind:'source',uid:'s2'}]])};
  const api=load(['pruneTimelineCaches'],{state,isScaleMode:()=>true,isSourceLogEntry:()=>false});
  api.pruneTimelineCaches();
  for(let i=0;i<7;i++) assert.ok(state.eventByUid.has(`e${i}`));
  assert.equal(state.eventByUid.size,519);assert.equal(state.eventDetailByUid.size,519);assert.equal(state.sourceRecordByUid.size,515);
  state.lanes=[];state.recordLanes=[];state.hoverModels.clear();state.eventDetailRequests.clear();state.eventLogServerItems.clear();state.timelineEntryProjections.clear();
  api.pruneTimelineCaches();assert.equal(state.eventByUid.size,513);assert.equal(state.sourceRecordByUid.size,513);
});

test('a boundary range key preserves completed facts and does not repeat the summary request',()=>{
  const summary={event_count:100};const state={rangeStartNs:0n,rangeEndNs:720n,viewStartNs:0n,viewEndNs:720n,rangeSummary:summary};
  const api=load(['timelineHandleKeyDown','applyHandlePosition'],{state,rangeBounds:()=>[state.rangeStartNs,state.rangeEndNs],
    rangeMinimumNs:()=>1n,clampNs:x=>x<0n?0n:x>720n?720n:x,requestRangeSummary:assert.fail,updateRangeBands:assert.fail,syncRangeInputs:assert.fail});
  api.timelineHandleKeyDown({key:'End',target:{closest:()=>({dataset:{rangeHandle:'end'}})},preventDefault:noop});
  assert.equal(state.rangeSummary,summary);
});

test('cancelling a brush replaces an interrupted summary instead of restoring an orphan loading state',async()=>{
  const responses=[];const renders=[];
  const state={rangeStartNs:600n,rangeEndNs:610n,rangeRequestId:0,rangeSummary:null,brush:null,rangeMode:false};
  const elements=new Map();const byId=id=>{
    if(!elements.has(id)) elements.set(id,{classList:{add:noop,remove:noop},contains:()=>true,setPointerCapture:noop,hasPointerCapture:()=>true,releasePointerCapture:noop});
    return elements.get(id);
  };
  const api=load(['rangeBounds','requestRangeSummary','timelinePointerDown','finishTimelinePointer'],{
    state,byId,abortLatestRequests:key=>state[key]?.abort(),isTopologyNodeSnapshot:()=>false,
    beginLatestRequest:key=>state[key]=new AbortController(),finishLatestRequest:(key,c)=>{if(state[key]===c)state[key]=null;},
    analysisRuntimeApi:(_path,options)=>{const response=deferred();responses.push({...response,body:JSON.parse(options.body)});return response.promise;},
    revisionPath:x=>x,requestWasAborted:(_error,c)=>c.signal.aborted,
    renderRangeSummary:()=>renders.push({start:state.rangeStartNs,summary:state.rangeSummary}),
    hideTimelineHoverLine:noop,pointNsFromClientX:()=>50n,timelineViewportSnapshot:()=>({}),updateRangePreview:noop,
    window:{cancelAnimationFrame:noop},stopBrushAutoScroll:noop,finishBrushViewportNavigation:noop,
    updateRangeBands:noop,syncRangeInputs:noop,performance:{now:()=>0},
  });
  const old=api.requestRangeSummary();
  const track={dataset:{resourceId:'r'}};
  api.timelinePointerDown({button:0,pointerId:1,clientX:100,shiftKey:true,target:{closest:s=>s==='.lane-track'?track:null},preventDefault:noop});
  responses[0].resolve({event_count:100,source:'server'});await old;
  assert.equal(renders.some(r=>r.start===50n&&r.summary?.event_count===100),false);
  api.finishTimelinePointer(null,true);
  assert.equal(responses.length,2);assert.deepEqual(responses[1].body,{start_ns:'600',end_ns:'610'});
  assert.ok(state.rangeAbortController);responses[1].resolve({event_count:100,source:'server'});
  await Promise.resolve();await Promise.resolve();
  assert.equal(state.rangeSummary.event_count,100);assert.equal(state.rangeAbortController,null);
});

test('cluster paging retains keyboard control while loading, then a reachable final destination',()=>{
  const document={body:{},activeElement:null};let controls=[];
  const control=kind=>({kind,hasAttribute:name=>name==='data-cluster-detail-offset'&&kind==='more',
    focus(){document.activeElement=this;},scrollIntoView(){this.scrolled=true;}});
  const cluster={detailLoading:false,hasMore:true};const model={type:'cluster',cluster};
  const windowElement={scrollTop:120};
  const card={hidden:false,contains:x=>controls.includes(x),set innerHTML(_value){
    if(this.contains(document.activeElement))document.activeElement=document.body;
    controls=[control('close'),...(cluster.hasMore||cluster.detailLoading?[control('more')]:[])];
  },querySelector:s=>s==='.cluster-window'?windowElement:controls.find(c=>c.kind===(s==='.hover-close'?'close':'more'))};
  const api=load(['refreshOpenClusterHover'],{state:{hoverKey:'key',hoverModels:new Map([['key',model]])},document,
    byId:()=>card,clusterHoverHtml:()=>'',bindHoverCardActions:noop});
  card.innerHTML='';controls[1].focus();cluster.detailLoading=true;api.refreshOpenClusterHover('key',cluster,{});
  assert.equal(document.activeElement.kind,'more');assert.equal(windowElement.scrollTop,120);
  cluster.detailLoading=false;cluster.hasMore=false;api.refreshOpenClusterHover('key',cluster,{});
  assert.equal(document.activeElement.kind,'close');assert.equal(document.activeElement.scrolled,true);
  const external={};document.activeElement=external;api.refreshOpenClusterHover('key',cluster,{});assert.equal(document.activeElement,external);
});

function resourceHarness() {
  const document={body:{},activeElement:null};let rows=[];let buttons=[];let html='';
  const makeRow=(id,path)=>{
    const row={tagName:'TR',dataset:{resourceId:id,...(path?{bundlePath:path}:{})},handlers:{},
      closest:()=>row,addEventListener(type,fn){this.handlers[type]=fn;},focus(){document.activeElement=this;}};
    row.input={tagName:'INPUT',dataset:{laneToggle:id},checked:true,closest:()=>row,handlers:{},
      addEventListener(type,fn){this.handlers[type]=fn;},focus(){document.activeElement=this;}};
    return row;
  };
  const wrap={contains:x=>rows.some(r=>r===x||r.input===x),set innerHTML(value){
    if(this.contains(document.activeElement))document.activeElement=document.body;
    html=value;rows=[...value.matchAll(/<tr data-resource-id="([^"]+)"/g)].map(m=>makeRow(m[1]));
  },get innerHTML(){return html;},querySelectorAll(selector){
    if(selector==='tr[data-resource-id]')return rows;
    if(selector.startsWith('input'))return rows.map(r=>r.input);
    return rows.flatMap(r=>[r,r.input]);
  }};
  const tabs={contains:x=>buttons.includes(x),set innerHTML(value){
    if(this.contains(document.activeElement))document.activeElement=document.body;
    buttons=[...value.matchAll(/data-kind="([^"]+)" aria-selected="([^"]+)"/g)].map(m=>({tagName:'BUTTON',dataset:{kind:m[1]},selected:m[2],
      closest:()=>null,addEventListener:noop,focus(){document.activeElement=this;}}));
  },querySelectorAll:selector=>selector.includes('data-resource-view')?[]:buttons};
  const state={selectedResourceKind:'ETG',selectedResourceViewId:null,selectedResourceId:'r',resourceQuery:{items:[{resource_id:'r',kind:'ETG'}],counts_by_kind:{ETG:1}}};
  const search={value:''};const elements={'resource-table-wrap':wrap,'resource-type-tabs':tabs,'resource-search':search,'resource-table-summary':{}};
  let api;let selected=0;
  api=load(['renderResourceTables','bindLaneVisibilityCheckboxes'],{state,document,byId:id=>elements[id],
    initializeResourceTableView:noop,resourceTableViewDescriptors:()=>[],canonicalResourceId:x=>x,escapeHtml:String,humanResourceType:String,
    presentationColumns:()=>[],resourcePageDetails:()=>({returned:state.resourceQuery.items.length,first:1,last:state.resourceQuery.items.length}),
    resourceTimeSummary:()=>'',resourcePaginationMarkup:()=>'',resourceLayer:()=>'',resourceLabel:(_,id)=>id,
    humanLayer:String,presentationTags:()=>new Set(),resourceExistenceLabel:()=>'',stateChipClassName:()=>'',
    laneVisibilityCheckbox:()=>'',MAX_RESOURCE_ROWS:500,bindResourcePagination:noop,
    selectResource:()=>{selected++;api.renderResourceTables();},setExplicitLaneVisibility:(_id,visible)=>{api.renderResourceTables();rows[0].input.checked=visible;return true;},
    laneSelectedByMode:()=>true});
  return {api,state,search,document,rows:()=>rows,buttons:()=>buttons,selected:()=>selected};
}

test('flat row activation retains identity, while nested Space reaches the native checkbox',()=>{
  const h=resourceHarness();h.api.renderResourceTables();h.rows()[0].focus();
  h.rows()[0].handlers.keydown({target:h.rows()[0],key:'Enter',preventDefault:noop});
  assert.equal(h.document.activeElement,h.rows()[0]);assert.equal(h.selected(),1);
  const row=h.rows()[0];row.input.focus();let prevented=false;
  row.handlers.keydown({target:row.input,key:' ',preventDefault:()=>{prevented=true;}});
  assert.equal(prevented,false);assert.equal(h.selected(),1);
  row.input.checked=false;row.input.handlers.click({stopPropagation:noop});
  assert.equal(h.document.activeElement,h.rows()[0].input);assert.equal(h.rows()[0].input.checked,false);
});

test('a filtered empty flat table retains its selected kind tab alongside matching other kinds',()=>{
  const h=resourceHarness();h.api.renderResourceTables();h.search.value='peer';
  h.state.resourceQuery={items:[],counts_by_kind:{NEIGHBOR:1}};h.api.renderResourceTables();
  assert.deepEqual(h.buttons().map(b=>[b.dataset.kind,b.selected]),[['ETG','true'],['NEIGHBOR','false']]);
  h.state.resourceQuery.counts_by_kind={};h.api.renderResourceTables();
  assert.deepEqual(h.buttons().map(b=>[b.dataset.kind,b.selected]),[['ETG','true']]);
});

test('successive real timeline normalization and detail requests retain only the current evidence plus bounded caches',async()=>{
  const state={dataset:{},viewStartNs:0n,viewEndNs:10000n,resourceById:new Map(),eventByUid:new Map(),eventDetailByUid:new Map(),
    eventDetailRequests:new Map(),sourceRecordByUid:new Map(),eventLogOwnedEvents:new Map(),eventLogOwnedSources:new Map(),
    eventLogServerItems:new Map(),timelineEntryProjections:new Map(),hoverModels:new Map(),lanes:[],recordLanes:[]};
  const api=load(['ensureLane','normalizeTimeline','normalizeMark','normalizeRecordLane','normalizeSourceMark',
    'hydrateEventDetail','requestEventDetail','pruneTimelineCaches','pruneServerEventLogOwnedCaches'],{
    state,isScaleMode:()=>true,isTopologyNodeSnapshot:()=>false,canonicalResourceId:x=>x,resourceIdOf:r=>r?.resource_id,
    registerResource:r=>{state.resourceById.set(r.resource_id,r);return r.resource_id;},
    resourceLayer:()=> 'link',resourceKind:()=> 'port',resourceLabel:(_r,id)=>id,presentationTags:()=>[],
    toNs:(v,fallback)=>v==null?fallback:BigInt(v),resourceEffectFor:()=>null,normalizedEventOutcome:()=> 'success',titleCase:String,
    eventFailed:()=>false,eventChangesState:()=>false,deriveLaneIntervals:noop,
    eventTime:e=>e.timestamp_ns==null?null:BigInt(e.timestamp_ns),sourceRecordTime:r=>r.timestamp_ns==null?null:BigInt(r.timestamp_ns),
    sourceRecordMatchedEventUids:()=>[],isSourceLogEntry:r=>'source_record_uid' in r,sourceRecordUid:r=>r.source_record_uid,
    normalizedLogEntryId:uid=>`event:${uid}`,sourceLogEntryId:uid=>`source:${uid}`,revisionPath:x=>x,
    api:async()=>({timestamp_ns:'1',message:'exact detail'}),eventOrMark:()=>null,
  });
  for(let page=0;page<100;page++){
    const events=Array.from({length:20},(_,i)=>({event_uid:`e-${page}-${i}`,timestamp_ns:String(page*20+i)}));
    const sources=Array.from({length:20},(_,i)=>({source_record_uid:`s-${page}-${i}`,timestamp_ns:String(page*20+i),source_type:'trace'}));
    api.normalizeTimeline({lanes:[{resource_id:'r',event_marks:events}],record_lanes:[{lane_id:'source',marks:sources}]});
    api.pruneServerEventLogOwnedCaches();
    assert.ok(state.eventByUid.size<=532);assert.ok(state.sourceRecordByUid.size<=532);
    assert.ok(events.every(e=>state.eventByUid.has(e.event_uid)));assert.ok(sources.every(r=>state.sourceRecordByUid.has(r.source_record_uid)));
  }
  for(let i=0;i<700;i++)await api.requestEventDetail(`detail-${i}`);
  assert.equal(state.eventDetailByUid.size,512);assert.equal(state.eventDetailRequests.size,0);
  api.normalizeTimeline({lanes:[],record_lanes:[]});
  assert.equal(state.eventByUid.size,512);assert.equal(state.sourceRecordByUid.size,512);
});

test('range reuse is owned by the same loaded revision and bounds',async()=>{
  const requests=[];const state={dataset:{revision:'a'},rangeStartNs:0n,rangeEndNs:10n,rangeRequestId:0};
  const api=load(['requestRangeSummary'],{state,rangeBounds:()=>[state.rangeStartNs,state.rangeEndNs],isTopologyNodeSnapshot:()=>false,
    abortLatestRequests:key=>state[key]?.abort(),beginLatestRequest:key=>state[key]=new AbortController(),
    finishLatestRequest:(key,c)=>{if(state[key]===c)state[key]=null;},revisionPath:x=>x,
    analysisRuntimeApi:()=>{const r=deferred();requests.push(r);return r.promise;},renderRangeSummary:noop,requestWasAborted:()=>false});
  const first=api.requestRangeSummary();requests[0].resolve({event_count:1});await first;
  await api.requestRangeSummary();assert.equal(requests.length,1);
  state.dataset={revision:'b'};const second=api.requestRangeSummary();assert.equal(requests.length,2);
  requests[1].resolve({event_count:2});await second;assert.equal(state.rangeSummary.event_count,2);
});

test('applied topology policy comes from retained result basis, never an invalid newer draft',()=>{
  const target={};const button={};let clock='strict';
  const state={topologyCapabilities:{projections:[{id:'p'}],status_perspectives:[{id:'s'}]},
    topologyQuery:{projection_id:'p',status_perspective_id:'s',resolved_basis:{clock_policy:'strict'}}};
  const api=load(['renderTopologyQueryState'],{state,byId:id=>id==='topology-query-state'?target:{value:clock},
    document:{querySelector:()=>button},topologyProjectionId:x=>x.id,topologyPerspectiveId:x=>x.id,
    firstArray:(...xs)=>xs.find(Array.isArray)||[],escapeHtml:String});
  api.renderTopologyQueryState();clock='best_effort';api.renderTopologyQueryState();
  assert.match(target.innerHTML,/Clock <strong>strict<\/strong>/);assert.doesNotMatch(target.innerHTML,/best_effort/);
});

test('timeline reveal corrects page-header occlusion and inner-scroller clipping before focus',()=>{
  let pageShift=0,inner=89;const topbar={getBoundingClientRect:()=>({bottom:84})};
  const header={getBoundingClientRect:()=>({bottom:164})};
  const scroll={scrollIntoView:noop,getBoundingClientRect:()=>({top:100+pageShift,bottom:400+pageShift}),clientTop:0,clientHeight:285,
    get scrollTop(){return inner;},set scrollTop(v){inner=Math.max(0,v);}};
  const row={getBoundingClientRect:()=>({top:100+pageShift-inner,bottom:160+pageShift-inner})};
  const api=load(['scrollTimelineTargetIntoView'],{byId:()=>scroll,
    document:{querySelector:s=>s==='.topbar'?topbar:header},window:{innerHeight:700,scrollBy:({top})=>{pageShift-=top;}}});
  api.scrollTimelineTargetIntoView(row);const rect=row.getBoundingClientRect();
  assert.ok(rect.top>=164);assert.ok(rect.bottom<=scroll.getBoundingClientRect().top+scroll.clientHeight);
});

for (const initialLeft of [638, 180]) test(`timeline reveal brings a marker at x=${initialLeft} inside the scrollport and past its sticky label`,()=>{
  const initialScroll=initialLeft>580?8:300;
  let horizontal=initialScroll;
  const viewport={left:13,right:580,top:180,bottom:500};
  const label={getBoundingClientRect:()=>({right:223})};
  const scroll={scrollIntoView:noop,getBoundingClientRect:()=>viewport,scrollTop:0,
    clientTop:0,clientHeight:305,clientLeft:0,clientWidth:552,
    get scrollLeft(){return horizontal;},set scrollLeft(value){horizontal=Math.max(0,value);}};
  const marker={closest:()=>({parentElement:{querySelector:()=>label}}),
    getBoundingClientRect:()=>({left:initialLeft+initialScroll-horizontal,right:initialLeft+initialScroll+23-horizontal,top:220,bottom:240})};
  const api=load(['scrollTimelineTargetIntoView'],{byId:()=>scroll,
    document:{querySelector:()=>null},window:{innerWidth:608,innerHeight:668,scrollBy:assert.fail}});
  api.scrollTimelineTargetIntoView(marker);
  assert.ok(marker.getBoundingClientRect().left>=231);
  assert.ok(marker.getBoundingClientRect().right<=557);
  assert.equal(scroll.scrollTop,0);
});

test('source lanes apply shared footprint bounds while retaining cluster and singleton identities',()=>{
  const cluster={kind:'source-cluster',clusterId:'s1',startNs:120n,endNs:124n,
    recordUids:['s1','s2'],count:2,items:[{timeNs:120n},{timeNs:124n}]};
  const mark={kind:'source-record',sourceRecordUid:'s3',timeNs:125n,recordName:'record'};
  const state={recordLanes:[{laneId:'lane',sourceTypes:['ctf'],marks:[cluster,mark],recordCount:3}],
    selectedSourceRecordUid:'s1',hoverModels:new Map()};
  const api=load(['timelineGlyphLayout','sourceRecordLanesHtml','pointClusterRangeState'],{
    state,rangeBounds:()=>null,timelineRangeBandHtml:()=>'',sourceTypeDescriptor:()=>({label:'CTF',color:'#fff'}),
    buildSourceGlyphs:lane=>lane.marks,timelinePercent:ns=>Number(ns)/10,escapeHtml:String,inSelectedRange:()=>false,
    formatOffset:String,visibleTimelineOffsetPrecision:()=>1,timelineLaneWidth:()=>210});
  const html=api.sourceRecordLanesHtml(1000);
  assert.equal((html.match(/--glyph-space:3px/g)||[]).length,2);
  assert.match(html,/source-record-mark cluster selected/);
  assert.match(html,/data-last-source-record-uid="s2"/);
  assert.match(html,/data-source-record-uid="s3"/);
  assert.equal(state.hoverModels.get('source-cluster:lane:s1').cluster,cluster);
});

for(const initialTop of [1108,40]) test(`log locate reveals the actual row at y=${initialTop} before focus, after tall controls and sticky headers`,()=>{
  let top=initialTop,focused=false;
  const frames=[];
  const scroll={scrollTop:0};
  const row={dataset:{logEntryId:'source:s1'},getBoundingClientRect:()=>({top,bottom:top+44}),
    scrollIntoView:()=>assert.fail('native scrolling disturbs compressed virtual positioning'),
    focus:()=>{assert.ok(top>=92&&top+44<=668);focused=true;}};
  const state={eventLogServerQueryId:1,eventLogLocateRequestId:1,eventLogRows:Array(30)};
  const api=load(['focusEventLogTarget'],{state,byId:id=>id==='event-table-body'?{querySelectorAll:()=>[row]}:scroll,
    virtualScrollTopForIndex:()=>20,eventLogBodyViewportHeight:()=>400,renderEventTableWindow:noop,navigationPulse:noop,
    EVENT_LOG_OVERSCAN:10,EVENT_LOG_ROW_HEIGHT:44,EVENT_LOG_MAX_SCROLL_HEIGHT:8000000,
    document:{querySelector:()=>({getBoundingClientRect:()=>({bottom:84})})},
    window:{innerHeight:668,requestAnimationFrame:fn=>frames.push(fn),scrollBy:opts=>{assert.equal(opts.behavior,'instant');top-=opts.top;}}});
  api.focusEventLogTarget('source:s1',20);
  while(frames.length)frames.shift()();
  assert.equal(focused,true);
  assert.equal(scroll.scrollTop,20);
});

test('small capture jumps reuse the same row focus routine and retire the previous popup and queued locate',()=>{
  const state={eventLogInclude:{},eventLogIndexById:new Map([['event:e1',12]]),eventLogLocateRequestId:7};
  const focus=[];let closed=0;
  const api=load(['jumpToLogEntry'],{state,closeHover:()=>closed++,usesServerWindowedHistory:()=>false,
    syncEventLogIncludeControls:noop,byId:()=>({value:''}),renderEventTable:noop,
    focusEventLogTarget:(...args)=>focus.push(args),showToast:assert.fail});
  api.jumpToLogEntry('event:e1');
  assert.deepEqual(focus,[['event:e1',12]]);assert.equal(closed,1);assert.equal(state.eventLogLocateRequestId,8);
});

test('bundle repaint restores the same duplicate-resource instance control',()=>{
  const document={body:{},activeElement:null};let controls=[];
  const build=()=>['root/primary/shared','root/backup/shared'].map(path=>{
    const row={dataset:{resourceId:'shared',bundlePath:path}};
    return {tagName:'BUTTON',dataset:{bundleDetails:'shared'},closest:()=>row,focus(){document.activeElement=this;}};
  });
  controls=build();document.activeElement=controls[1];
  const container={contains:node=>controls.includes(node),querySelectorAll:()=>controls};
  const tabs={contains:()=>false,querySelectorAll:()=>[]};
  const state={selectedResourceViewId:'bundle',resourceQuery:{items:[],counts_by_kind:{}}};
  const api=load(['renderResourceTables'],{state,document,byId:id=>id==='resource-table-wrap'?container:id==='resource-type-tabs'?tabs:{value:''},
    initializeResourceTableView:noop,resourceTableViewDescriptors:()=>[{view_id:'bundle',label:'Bundle'}],escapeHtml:String,
    renderResourceBundleTable:()=>{document.activeElement=document.body;controls=build();}});
  api.renderResourceTables();
  assert.equal(document.activeElement,controls[1]);assert.equal(document.activeElement.closest().dataset.bundlePath,'root/backup/shared');
});

for(const declared of [false,true]) test(`visible incident buttons retain selectable evidence across cache turnover; causal=${declared}`,()=>{
  const oldEvents=Array.from({length:8},(_,i)=>({event_uid:`old-${i}`,timestamp_ns:String(i),event_type:'failure'}));
  const state={dataset:{causal_links:declared?Array.from({length:7},(_,i)=>({source_event_uid:`old-${i}`,target_event_uid:`old-${i+1}`})):[]},
    failureIncidentPreview:declared?[]:oldEvents.slice(0,3),eventByUid:new Map(oldEvents.map(e=>[e.event_uid,e])),
    eventDetailByUid:new Map(),sourceRecordByUid:new Map(),eventDetailRequests:new Map(),lanes:[],recordLanes:[],
    hoverModels:new Map(),eventLogServerItems:new Map(),timelineEntryProjections:new Map()};
  let buttons=[];const inspected=[];
  const container={set innerHTML(value){buttons=[...value.matchAll(/data-event-uid="([^"]+)"/g)].map(m=>({dataset:{eventUid:m[1]},
    addEventListener(_type,handler){this.click=handler;}}));},querySelectorAll:()=>buttons};
  const api=load(['pruneTimelineCaches','incidentCausalPath','renderIncidentSummary','eventOrMark','selectEvent'],{
    state,isScaleMode:()=>true,isTopologyNodeSnapshot:()=>false,byId:id=>id==='incident-chain'?container:{scrollIntoView:noop},
    compareLogEntries:(a,b)=>Number(a.timestamp_ns)-Number(b.timestamp_ns),compareLogEntryIds:(a,b)=>a.localeCompare(b),
    eventSubject:()=>({layer:'control'}),causalLinkDisplayLabel:()=> 'causes',escapeHtml:String,layerColor:()=>'',humanLayer:String,
    formatValue:String,eventOutcomeText:()=> 'failure',formatOffset:String,eventTime:e=>BigInt(e.timestamp_ns),
    eventResourceRefs:()=>[],pruneServerEventLogOwnedCaches:noop,renderEventInspector:e=>inspected.push(e.event_uid),
    setCursor:time=>state.cursorNs=time,renderTimeline:noop,renderEventTable:noop,requestEventDetail:()=>Promise.resolve(null),
  });
  api.renderIncidentSummary();const visible=buttons.slice();
  assert.equal(visible.length,declared?4:3);
  for(let batch=0;batch<5;batch++){
    for(let i=0;i<300;i++){const uid=`new-${batch}-${i}`;state.eventByUid.set(uid,{event_uid:uid,timestamp_ns:String(100+i)});}
    api.pruneTimelineCaches();
  }
  for(const button of visible){
    button.click();assert.equal(state.selectedEventUid,button.dataset.eventUid);
    assert.equal(inspected.at(-1),button.dataset.eventUid);
  }
  assert.ok(state.eventByUid.size<=512+visible.length);
  assert.equal(state.eventByUid.has('old-7'),false);
  assert.equal(state.eventByUid.has('new-0-0'),false);
  api.renderIncidentSummary();assert.deepEqual(buttons.map(b=>b.dataset.eventUid),visible.map(b=>b.dataset.eventUid));
});

for(const mode of ['ctrl','alt','pan']) for(const continued of [false,true]) {
  test(`pending Reveal yields before a queued ${mode} wheel frame; continued burst=${continued}`,async()=>{
    const response=deferred();const frames=new Map();const timers=new Map();const history=[];const applied=[];const jumps=[];
    let nextId=0,refreshes=0;
    const state={timelineNavigationIntent:0,eventLogSelectionFocus:0,zoom:2,
      timelineWheelBurstActive:false,timelineWheelMode:null,timelineWheelHistoryTimer:null,
      timelineWheelFrameId:null,timelinePanFrameId:null,timelineWheelTargetZoom:null,timelinePanDeltaPx:0};
    const api=load(['revealFocusedEventLogSelection','timelineWheel','scheduleTimelineZoom','scheduleTimelinePan',
      'beginTimelineWheelBurst','scheduleTimelineWheelBurstFinish','settlePendingTimelineWheelFrames','finishTimelineWheelBurst'],{
      state,resolveEventLogSelection:()=>response.promise,rememberTimelineEntryProjection:item=>item,
      jumpToTimelineEvent:uid=>jumps.push(uid),forgetTimelineEntryProjection:noop,pruneServerEventLogOwnedCaches:noop,showToast:assert.fail,
      pointNsFromClientX:()=>50n,visibleTimelineCenterNs:()=>50n,closeTimelineContextMenu:noop,
      WheelEvent:{DOM_DELTA_LINE:1,DOM_DELTA_PAGE:2},TIMELINE_WHEEL_HISTORY_DELAY_MS:180,
      timelineZoomStep:(zoom,direction,factor)=>direction==='in'?zoom*factor:zoom/factor,
      window:{requestAnimationFrame:fn=>{frames.set(++nextId,fn);return nextId;},cancelAnimationFrame:id=>frames.delete(id),
        setTimeout:fn=>{timers.set(++nextId,fn);return nextId;},clearTimeout:id=>timers.delete(id)},
      rememberTimelineView:()=>history.push(state.zoom),scheduleTimelineWindowRefresh:()=>refreshes++,
      applyTimelineZoom:(zoom,options)=>{applied.push({zoom,options});state.zoom=zoom;},
      panTimelineViewportByPixels:(delta,options)=>applied.push({delta,options}),
    });
    const wheel=()=>api.timelineWheel({ctrlKey:mode==='ctrl',altKey:mode==='alt',metaKey:false,shiftKey:false,
      deltaMode:0,deltaX:mode==='pan'?10:0,deltaY:mode==='pan'?0:-10,clientX:100,
      target:{closest:()=>({})},preventDefault:noop});
    if(continued)wheel();
    const pending=api.revealFocusedEventLogSelection();wheel();
    assert.equal(frames.size,1);assert.equal(applied.length,0);assert.equal(history.length,1);assert.equal(timers.size,1);
    response.resolve({items:[{uid:'older',display_index:0}]});await pending;
    assert.deepEqual(jumps,[]);
    api.finishTimelineWheelBurst();
    assert.equal(applied.length,1);assert.equal(applied[0].options.recordHistory,false);assert.equal(applied[0].options.fromWheel,true);
    assert.equal('zoom' in applied[0],mode==='alt');assert.equal('delta' in applied[0],mode!=='alt');
    assert.equal(history.length,2);assert.equal(refreshes,1);assert.equal(frames.size,0);assert.equal(timers.size,0);
    assert.equal(state.timelineWheelBurstActive,false);
  });
}

for(const retainCurrent of [false,true]) test(`late cluster pages stay bounded after navigation; current evidence=${retainCurrent}`,async()=>{
  const responses=[];
  const lanes=Array.from({length:20},(_,i)=>({resourceId:`r${i}`,marks:[],clusters:[{serverBacked:true,
    startNs:0n,endNs:99n,detailRequestId:0,detailTruncated:true,detailNextOffset:null,items:[],eventUids:[],detailItems:[]}]}));
  const state={lanes,recordLanes:[],eventByUid:new Map(),eventDetailByUid:new Map(),sourceRecordByUid:new Map(),
    eventDetailRequests:new Map(),hoverModels:new Map(),eventLogServerItems:new Map(),timelineEntryProjections:new Map(),hiddenTimelineEntryIds:new Set()};
  const api=load(['requestClusterDetail','clusterDetailRequestAvailable','normalizeMark','pruneTimelineCaches'],{
    state,isScaleMode:()=>true,isTopologyNodeSnapshot:()=>false,refreshOpenClusterHover:noop,revisionPath:x=>x,
    CLUSTER_DETAIL_PAGE_SIZE:100,api:()=>{const response=deferred();responses.push(response);return response.promise;},
    normalizedLogEntryId:uid=>`event:${uid}`,resourceEffectFor:()=>null,toNs:x=>BigInt(x),normalizedEventOutcome:()=> 'success',
    titleCase:String,eventFailed:()=>false,eventChangesState:()=>false,
  });
  const requests=lanes.map((lane,i)=>api.requestClusterDetail(`c${i}`,lane.clusters[0],lane));
  assert.equal(responses.length,20);
  state.lanes=retainCurrent?[lanes[1]]:[];
  if(retainCurrent){state.hoverKey='open';state.hoverModels.set('open',{cluster:lanes[0].clusters[0]});}
  api.pruneTimelineCaches();assert.equal(state.eventByUid.size,0);
  for(let i=0;i<20;i++){
    responses[i].resolve({items:Array.from({length:100},(_,j)=>({event_uid:`e${i}-${j}`,timestamp_ns:String(j)})),total_count:100,next_offset:null});
    assert.equal(await requests[i],true);
    assert.ok(state.eventByUid.size<=512+(retainCurrent?200:0));
  }
  assert.equal(state.eventByUid.size,512+(retainCurrent?200:0));
  if(retainCurrent) for(let i=0;i<2;i++) for(let j=0;j<100;j++) assert.ok(state.eventByUid.has(`e${i}-${j}`));
});

for(const newer of ['preset','remove','add','layer','fit']) test(`pending Reveal yields to accepted ${newer} controls`,async()=>{
  const response=deferred(),staged=deferred();const jumps=[];let layerButtons=[];
  const state={timelineNavigationIntent:0,eventLogSelectionFocus:0,recordLaneRules:[{lane_id:'custom'}],
    recordLanePresets:[{lane_id:'preset',pattern:'.'}],customRecordLaneSequence:0,
    activeLayers:new Set(['control','bridge']),layerMeta:new Map([['control',{}],['bridge',{}]]),
    zoom:1,viewStartNs:20n,viewEndNs:60n,timelineWindowStartNs:0n,timelineWindowEndNs:40n};
  const button={disabled:false};const controls=new Map(['label','pattern','source','unmatched','error'].map(k=>[`record-lane-${k}`,{value:'',checked:false}]));
  controls.get('record-lane-label').value='New';controls.get('record-lane-pattern').value='warning';
  controls.set('record-lane-form',{querySelector:()=>button,querySelectorAll:()=>[controls.get('record-lane-label')],reset:noop});
  const layers={contains:()=>false,set innerHTML(value){layerButtons=[...value.matchAll(/data-layer="([^"]+)"/g)].map(m=>({dataset:{layer:m[1]},addEventListener(_t,f){this.click=f;}}));},querySelectorAll:()=>layerButtons};
  const viewport=viewportDeps(state);
  const api=load(['revealFocusedEventLogSelection','setRecordLanePreset','removeRecordLane','addRecordLane',
    'renderLayerToggles','fitTimelineCapture','applyTimelineZoom'],{
    state,...viewport,byId:id=>id==='layer-toggles'?layers:controls.get(id)||viewport.byId(id),document:{activeElement:null},
    resolveEventLogSelection:()=>response.promise,rememberTimelineEntryProjection:item=>item,jumpToTimelineEvent:uid=>jumps.push(uid),
    forgetTimelineEntryProjection:noop,pruneServerEventLogOwnedCaches:noop,showToast:noop,
    MAX_RECORD_LANES:8,refreshRecordLanes:noop,validateRecordLanePattern:()=>'',isTopologyNodeSnapshot:()=>false,
    requestTimeline:()=>staged.promise,normalizeTimeline:noop,escapeHtml:String,layerColor:()=>'',humanLayer:String,
  });
  const pending=api.revealFocusedEventLogSelection();let add;
  if(newer==='preset')api.setRecordLanePreset('preset',true);
  if(newer==='remove')api.removeRecordLane('custom');
  if(newer==='add')add=api.addRecordLane({preventDefault:noop});
  if(newer==='layer'){api.renderLayerToggles();layerButtons[1].click();}
  if(newer==='fit')api.fitTimelineCapture({announce:false});
  response.resolve({items:[{uid:'old',display_index:0}]});await pending;
  assert.deepEqual(jumps,[]);
  if(add){staged.resolve({});await add;assert.equal(state.recordLaneRules.length,2);}
});

test('source reveal keeps ownership through its own viewport move',async()=>{
  const state={timelineNavigationIntent:0,zoom:2,viewStartNs:0n,viewEndNs:1000n,timelineWindowStartNs:0n,timelineWindowEndNs:100n,
    sourceRecordByUid:new Map([['s',{source_record_uid:'s'}]])};
  const selected=[];
  const api=load(['jumpSourceRecordToTimeline','moveTimelineWindowToReveal','applyTimelineZoom'],{
    state,...viewportDeps(state),sourceRecordTime:()=>120n,refreshTimelineForNavigation:async()=>true,
    ensureSourceRecordLane:async()=>({laneId:'source'}),selectSourceRecord:uid=>selected.push(uid),window:{requestAnimationFrame:noop},
  });
  await api.jumpSourceRecordToTimeline('s');
  assert.deepEqual(selected,['s']);assert.equal(state.timelineWindowStartNs,100n);
});
