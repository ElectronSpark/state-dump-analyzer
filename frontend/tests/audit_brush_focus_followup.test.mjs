import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { replaceAbortController } from '../assets/browser_transport.js';
import { escapeHtml, titleCase } from '../assets/shared.js';
import { rangeSummaryFacts } from '../assets/view_models.js';

// Controlled handler tests complement the native-browser audit. Synthetic DOM
// capture/scroll here does not establish native pointer or layout delivery.
const source = readFileSync(new URL('../assets/app.js', import.meta.url), 'utf8');
const noop = () => {};
const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; };
const settle = async () => { for (let i = 0; i < 12; i++) await Promise.resolve(); };
function load(names, deps) {
  const bodies = names.map(name => {
    const match = new RegExp(`^(?:async )?function ${name}\\(`, 'm').exec(source);
    assert.ok(match, name);
    const tail = source.slice(match.index);
    return tail.slice(0, /\n(?:async )?function \w+\(/.exec(tail)?.index);
  });
  return new Function(...Object.keys(deps), `${bodies.join('\n')}\nreturn {${names.join(',')}};`)(...Object.values(deps));
}
function install(startText, endText, deps) {
  const start = source.indexOf(startText), end = source.indexOf(endText, start);
  assert.ok(start >= 0 && end > start, startText);
  new Function(...Object.keys(deps), source.slice(start, end))(...Object.values(deps));
}

function brushHarness() {
  const base = 1_759_680_000_000_000_000n;
  const state = { dataset: {}, viewStartNs: base, viewEndNs: base + 719_996_000_000n,
    rangeStartNs: null, rangeEndNs: null, rangeSummary: null, rangeRequestId: 0,
    brush: null, rangeMode: false, trackWidth: 1000 };
  const frames = new Map(), elements = new Map(), replies = [], captures = new Set();
  let nextFrame = 1, releases = 0;
  const byId = id => {
    if (!elements.has(id)) {
      const classes = new Set();
      elements.set(id, { value: '', hidden: id === 'lane-picker', textContent: '', innerHTML: '',
        listeners: new Map(), addEventListener(type, fn) { this.listeners.set(type, fn); },
        classList: { add: x => classes.add(x), remove: x => classes.delete(x), contains: x => classes.has(x) },
        querySelectorAll: () => [], contains: () => true,
        setPointerCapture: id => captures.add(id), hasPointerCapture: id => captures.has(id),
        releasePointerCapture(id) { captures.delete(id); releases++; this.listeners.get('lostpointercapture')?.({ pointerId: id }); },
        getBoundingClientRect: () => ({ left: 0, right: 1200 }), scrollLeft: 0 });
    }
    return elements.get(id);
  };
  const window = { requestAnimationFrame(fn) { const id = nextFrame++; frames.set(id, fn); return id; },
    cancelAnimationFrame: id => frames.delete(id) };
  const names = ['beginLatestRequest', 'finishLatestRequest', 'requestWasAborted', 'abortLatestRequests',
    'rangeBounds', 'formatRangeInput', 'parseRangeInput', 'syncRangeInputs', 'applyRangeEditor',
    'conciseEndpointState', 'endpointDiffItems', 'renderRangeSummary', 'requestRangeSummary',
    'timelinePointerDown', 'timelinePointerMove', 'scheduleBrushFrame', 'brushNsFromClientX', 'updateRangePreview',
    'stopBrushAutoScroll', 'updateBrushAutoScroll', 'finishBrushViewportNavigation', 'finishTimelinePointer', 'handleEscapeKey'];
  const api = load(names, { state, byId, window, replaceAbortController, escapeHtml, titleCase, rangeSummaryFacts,
    clampNs: value => value < state.viewStartNs ? state.viewStartNs : value > state.viewEndNs ? state.viewEndNs : value,
    isTopologyNodeSnapshot: () => false, revisionPath: path => path,
    analysisRuntimeApi(path, options) { const reply = deferred(); replies.push({ ...reply, path, body: JSON.parse(options.body), signal: options.signal }); return reply.promise; },
    formatOffset: value => `${value - base} ns`, formatDuration: String, formatValue: String,
    eventFailed: () => false, canonicalResourceId: value => value, relationshipDisplayLabel: String,
    selectResource: noop, updateRangeBands: noop,
    hideTimelineHoverLine: noop, pointNsFromClientX: x => base + BigInt(x - 200) * 1_000_000_000n,
    timelineLaneWidth: () => 200, timelineNsAtLocalRatio: ratio => base + BigInt(Math.round(ratio * 1000)) * 1_000_000_000n,
    timelineViewportSnapshot: () => ({ zoom: 1, startNs: state.viewStartNs, endNs: state.viewEndNs }),
    closeCorrelationHover: noop, closeTimelineContextMenu: () => false, closeHover: noop,
    performance: { now: () => 1000 },
  });
  const timelineContent = byId('timeline-content');
  install('  timelineContent.addEventListener("pointerdown",', '  timelineContent.addEventListener("keydown",', {
    timelineContent, ...api, hideTimelineHoverLine: noop,
  });
  const document = { addEventListener(type, fn) { assert.equal(type, 'keydown'); this.keydown = fn; } };
  const escapeBinding = 'document.addEventListener("keydown", handleEscapeKey);';
  assert.ok(source.includes(escapeBinding));
  new Function('document', 'handleEscapeKey', escapeBinding)(document, api.handleEscapeKey);
  const target = { closest: selector => selector === '.lane-track' ? { dataset: { resourceId: 'r' } } : null };
  const dispatch = (type, extra = {}) => {
    const event = { button: 0, pointerId: 7, clientX: 250, shiftKey: true, target, cancelable: true,
      preventDefault() { this.defaultPrevented = true; }, ...extra };
    timelineContent.listeners.get(type)(event);
    return event;
  };
  return { state, byId, api, document, frames, replies, captures, dispatch, base, releases: () => releases,
    apply(start, end) { byId('range-start-input').value = start; byId('range-end-input').value = end; return api.applyRangeEditor({ preventDefault: noop }); },
    flushFrames() { const pending = [...frames.values()]; frames.clear(); pending.forEach(fn => fn()); } };
}

const periods = [
  ['S094', 'S095', '0', '0.01'], ['S099', 'S100', '719.986', '719.996'],
  ['S104', 'S105', '50', '60'], ['S109', 'S110', '120', '121'],
  ['S114', 'S115', '240', '245'], ['S119', 'S120', '600', '610'],
];
for (const [settledId, pendingId, start, end] of periods) {
  for (const completion of ['settled', 'during brush', 'after cancellation']) {
    test(`${completion === 'settled' ? settledId : pendingId}: Escape restores ${start}–${end}s (${completion})`, async () => {
      const h = brushHarness();
      assert.equal(h.apply(start, end), true);
      assert.equal(h.replies.length, 1);
      const original = h.api.rangeBounds(), body = { ...h.replies[0].body };
      const absoluteNs = value => {
        const [whole, fraction = ''] = value.split('.');
        return String(h.base + BigInt(whole) * 1_000_000_000n + BigInt(fraction.padEnd(9, '0')));
      };
      assert.deepEqual(body, { start_ns: absoluteNs(start), end_ns: absoluteNs(end) });
      const facts = { event_count: 123, failure_count: 2, affected_resource_count: 3, endpoint_diff: [] };
      assert.match(h.byId('range-facts').innerHTML, /Loading range summary/);
      if (completion === 'settled') { h.replies[0].resolve(facts); await settle(); }
      const savedFacts = h.byId('range-facts').innerHTML;
      h.dispatch('pointerdown');
      assert.equal(h.state.brush.mode, 'range');
      assert.ok(h.captures.has(7));
      h.dispatch('pointermove', { clientX: 255 });
      h.flushFrames();
      assert.deepEqual(h.api.rangeBounds(), [h.base + 50_000_000_000n, h.base + 55_000_000_000n]);
      assert.match(h.byId('range-facts').innerHTML, /Release to summarize/);
      if (completion !== 'settled') assert.equal(h.replies[0].signal.aborted, true);
      if (completion === 'during brush') {
        h.replies[0].resolve(facts); await settle();
        assert.equal(h.state.rangeSummary, null, 'old reply cannot become the temporary brush summary');
        assert.match(h.byId('range-facts').innerHTML, /Release to summarize/);
      }
      const escape = { key: 'Escape', preventDefault() { this.defaultPrevented = true; } };
      h.document.keydown(escape);
      assert.equal(escape.defaultPrevented, true);
      assert.equal(h.state.brush, null);
      assert.deepEqual(h.api.rangeBounds(), original);
      assert.equal(h.captures.size, 0);
      assert.equal(h.releases(), 1);
      assert.equal(h.frames.size, 0);
      assert.equal(h.byId('timeline-frame').classList.contains('is-brushing'), false);
      h.dispatch('pointerup', { clientX: 260 });
      assert.deepEqual(h.api.rangeBounds(), original, 'release after Escape must not commit the cancelled drag');
      if (completion === 'settled') {
        assert.equal(h.replies.length, 1);
        assert.equal(h.state.rangeSummary, facts);
        assert.equal(h.byId('range-facts').innerHTML, savedFacts);
      } else {
        assert.equal(h.replies.length, 2, 'cancelled loading summary gets a replacement read');
        assert.deepEqual(h.replies[1].body, body);
        assert.equal(h.replies[1].signal.aborted, false);
        assert.ok(h.state.rangeAbortController);
        if (completion === 'after cancellation') {
          h.replies[0].resolve({ event_count: 999 }); await settle();
          assert.equal(h.state.rangeSummary.source, 'loading');
          assert.ok(h.state.rangeAbortController, 'late old finally must not clear the new request');
        }
        h.replies[1].resolve(facts); await settle();
        assert.equal(h.state.rangeSummary, facts);
      }
      assert.equal(h.state.rangeAbortController, null);
      assert.match(h.byId('range-facts').innerHTML, /123 events/);
      assert.equal(h.apply(start, end), true);
      await settle();
      assert.deepEqual(h.api.rangeBounds(), original);
      assert.equal(h.state.rangeSummary, facts);
      assert.doesNotMatch(h.byId('range-facts').innerHTML, /Loading|unavailable/);
      assert.equal(h.byId('range-start-input').value, start);
      assert.equal(h.byId('range-end-input').value, end);
    });
  }
}

const rect = (left, top, width = 14, height = 14) => ({ left, top, right: left + width, bottom: top + height, width, height });
function focusHarness(kind) {
  const key = kind === 'density' ? 'density:20:720' : 'event:root:r:e';
  const event = { event_uid: 'e', resource_ids: ['r'], timestamp_ns: '50' };
  const mark = { eventUid: 'e', event }, lane = { resourceId: 'r', marks: [mark] };
  const state = { hoverModels: new Map([[key, kind === 'density' ? { type: 'density', bin: {} } : { type: 'event', mark, lane }]]),
    eventLogHoverModels: new Map(), hoverPinned: false, hoverKey: null, timelineFocusRestoring: false,
    eventByUid: new Map([['e', event]]), eventDetailByUid: new Map(), eventDetailRequests: new Map(), lanes: [lane],
    laneByResource: new Map([['r', lane]]), resourceById: new Map([['r', { kind: 'TEST' }]]),
    selectedResourceId: 'r', correlatedResourceIds: new Set(), cursorNs: 50n, graphRequestId: 0, laneMode: 'custom' };
  const frames = [], timers = new Map(), replies = [], inspected = [];
  let current, top = 300, replacements = 0, reveals = 0, api;
  const document = { body: {}, documentElement: {}, activeElement: null,
    addEventListener(type, fn) { assert.equal(type, 'scroll'); this.scroll = fn; },
    querySelector: selector => selector.startsWith('[data-hover-key') ? current : null };
  const scroll = { id: 'timeline-scroll', scrollTop: 20, scrollLeft: 28,
    clientLeft: 2, clientTop: 2, clientWidth: 500, clientHeight: 300,
    getBoundingClientRect: () => rect(40, 180, 520, 320), addEventListener(type, fn) { this[type] = fn; } };
  const window = { innerWidth: 608, innerHeight: 668, scrollY: 300,
    clearTimeout: id => timers.delete(id), setTimeout(fn) { const id = Symbol(); timers.set(id, fn); return id; },
    requestAnimationFrame: fn => frames.push(fn) };
  const card = { hidden: true, style: {}, classList: { toggle: noop, remove: noop }, scrollHeight: 230, contains: () => false };
  const header = { getBoundingClientRect: () => rect(40, 150, 520, 60) };
  class Marker {
    constructor() { this.dataset = { hoverKey: key, ...(kind === 'event' ? { eventUid: 'e' } : {}) }; this.isConnected = true; this.listeners = new Map(); }
    addEventListener(type, fn) { this.listeners.set(type, fn); }
    getBoundingClientRect() { return rect(380, top); }
    closest(selector) {
      if (selector === '.timeline-row') return { dataset: kind === 'density' ? {} : { resourceId: 'r', treeKey: 'root:r' } };
      if (selector === '#timeline-content') return content;
      if (selector.startsWith('#timeline-scroll')) return scroll;
      return null;
    }
    focus(options) {
      if (options) assert.deepEqual(options, { preventScroll: true });
      document.activeElement = this; this.listeners.get('focus')();
    }
    scrollIntoView() { reveals++; top = 300; scroll.scrollTop = 20; window.scrollY = 0; }
  }
  const replace = (bind = true) => {
    const old = current; old.isConnected = false;
    if (document.activeElement === old) document.activeElement = document.body;
    current = new Marker(); replacements++; if (bind) api.bindHoverTarget(current);
  };
  const row = { replaceWith(replacement) { assert.equal(replacement, replacementRow); replace(false); } };
  const replacementRow = { querySelectorAll: () => [current] };
  const content = { contains: value => value === current, querySelectorAll: () => [current], querySelector: () => row };
  document.createElement = () => ({ content: { firstElementChild: replacementRow } });
  const ruler = { style: {} };
  const byId = id => ({ 'timeline-content': content, 'timeline-scroll': scroll, 'timeline-hover': card,
    'timeline-floating-header': header, 'timeline-ruler': ruler })[id];
  const read = path => { const response = deferred(); replies.push({ ...response, path }); return response.promise; };
  const names = ['beginLatestRequest', 'finishLatestRequest', 'requestWasAborted', 'abortLatestRequests',
    'bindHoverTarget', 'showHover', 'positionHover', 'closeHover', 'timelineFocusDescriptor',
    'timelineElementForFocusDescriptor', 'restoreTimelineFocusDescriptor', 'refreshDensityLaneForScroll',
    'rerenderTimelinePreservingScroll', 'selectEvent', 'requestEventDetail', 'hydrateEventDetail', 'requestGraph'];
  api = load(names, { state, document, window, byId, HTMLElement: Marker, CSS: { escape: String }, replaceAbortController,
    eventHoverHtml: () => 'event', densityHoverHtml: () => 'density', bindHoverCardActions: noop,
    scheduleHoverClose: noop, eventDensityLane: () => '<div></div>',
    scrollTimelineTargetIntoView: () => assert.fail('intentional focus should already place the marker'),
    renderTimeline() {
      const descriptor = api.timelineFocusDescriptor(); replace();
      scroll.scrollTop = 0; scroll.scrollLeft = 0;
      api.positionHover(); api.restoreTimelineFocusDescriptor(descriptor);
    },
    eventOrMark: uid => state.eventByUid.get(uid), eventResourceRefs: value => value.resource_ids,
    pruneServerEventLogOwnedCaches: noop, pruneTimelineCaches: noop,
    renderEventInspector: value => inspected.push(value), renderEventTable: noop,
    isScaleMode: () => false, isTopologyNodeSnapshot: () => false, api: read, analysisRuntimeApi: read,
    revisionPath: value => value, resourceEffectFor: () => null, normalizedEventOutcome: () => 'accepted',
    eventFailed: () => false, titleCase, resourceKind: () => 'TEST', toNs: value => BigInt(value),
    CORRELATION_LIST_PAGE_SIZE: 100, markCorrelationPending() { state.graphPending = true; },
    updateCorrelationState: noop, renderCorrelationTimeState: noop, renderGraph: noop,
  });
  current = new Marker(); api.bindHoverTarget(current);
  install('  document.addEventListener("scroll",', '\n  window.addEventListener("resize",', { document, byId, positionHover: api.positionHover });
  install('  timelineScroll.addEventListener("scroll",', '\n  byId("resource-search")', {
    state, window, byId, timelineScroll: scroll, hideTimelineHoverLine: noop, closeTimelineContextMenu: noop,
    refreshDensityLaneForScroll: api.refreshDensityLaneForScroll, scheduleTimelineViewHistory: noop,
  });
  return { api, state, document, window, scroll, card, frames, timers, replies, inspected,
    current: () => current, replacements: () => replacements, reveals: () => reveals,
    pin() { document.activeElement = current; api.showHover(key, current, true); assert.equal(card.hidden, false); },
    clip() { top = 90; scroll.scrollTop = 185; scroll.scrollLeft = 28; window.scrollY = 300; document.scroll({ target: scroll }); assert.equal(card.hidden, true); },
    flushFrames() { while (frames.length) frames.shift()(); },
    offsets: () => [scroll.scrollTop, scroll.scrollLeft, window.scrollY] };
}

test('C015: the production scroll timer replaces a clipped focused density bin without revealing it', () => {
  const h = focusHarness('density');
  h.pin(); h.clip(); const old = h.current(), saved = h.offsets();
  h.scroll.scroll();
  assert.equal(h.timers.size, 1);
  [...h.timers.values()][0]();
  assert.equal(h.replacements(), 1);
  assert.notEqual(h.current(), old);
  assert.equal(old.isConnected, false);
  assert.equal(h.document.activeElement, h.document.body);
  h.flushFrames();
  assert.equal(h.document.activeElement, h.current());
  assert.deepEqual(h.offsets(), saved);
  assert.equal(h.reveals(), 0);
  assert.equal(h.card.hidden, true);
  assert.equal(h.state.hoverKey, null);
  h.document.activeElement = h.document.body; h.current().focus();
  assert.equal(h.reveals(), 1);
  assert.equal(h.card.hidden, false);
});

for (const order of [['detail', 'graph'], ['graph', 'detail']]) {
  test(`C016: actual event selection completes delayed ${order.join(' then ')} work without reviving clipped focus`, async () => {
    const h = focusHarness('event');
    h.api.selectEvent('e', false, 'r');
    assert.equal(h.replies.length, 2);
    assert.equal(h.state.eventDetailRequests.size, 1);
    assert.equal(h.state.graphPending, true);
    h.pin(); h.clip(); const saved = h.offsets();
    for (const kind of order) {
      const old = h.current(), previousCount = h.replacements();
      const reply = h.replies.find(r => r.path === (kind === 'graph' ? 'graph/query' : 'events/e'));
      reply.resolve(kind === 'graph' ? { time_ns: '50', nodes: [], edges: [] } : { event_uid: 'e', display_name: 'Hydrated event' });
      await settle();
      assert.equal(h.replacements(), previousCount + 1);
      assert.equal(old.isConnected, false);
      h.flushFrames();
      assert.equal(h.document.activeElement, h.current());
      assert.deepEqual(h.offsets(), saved);
      assert.equal(h.reveals(), 0);
      assert.equal(h.card.hidden, true);
      assert.equal(h.state.hoverKey, null);
    }
    assert.equal(h.state.eventDetailRequests.size, 0);
    assert.equal(h.state.eventDetailByUid.get('e').display_name, 'Hydrated event');
    assert.equal(h.inspected.at(-1).display_name, 'Hydrated event');
    assert.equal(h.state.graphPending, false);
    assert.equal(h.state.graphAbortController, null);
    h.document.activeElement = h.document.body; h.current().focus();
    assert.equal(h.reveals(), 1);
    assert.equal(h.card.hidden, false);
  });
}
