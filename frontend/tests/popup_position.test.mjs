import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const source = readFileSync(new URL('../assets/app.js', import.meta.url), 'utf8');
const rect = (left = 380, top = 380, width = 14, height = 14) => ({ left, top, width, height, right: left + width, bottom: top + height });
function load(names, dependencies) {
  const bodies = names.map(name => {
    const match = new RegExp(`^function ${name}\\(`, 'm').exec(source);
    assert.ok(match, name);
    const tail = source.slice(match.index);
    return tail.slice(0, /\n(?:async )?function \w+\(/.exec(tail)?.index);
  });
  return new Function(...Object.keys(dependencies), `${bodies.join('\n')}\nreturn {${names.join(',')}};`)(...Object.values(dependencies));
}

function harness() {
  const key = 'source-record:preset-b:source-1';
  let rectangle = rect(), renders = 0, bindings = 0, queries = 0;
  let scroll = null, header = null, label = null, topbar = null;
  const control = {}, detail = { scrollTop: 87 };
  const card = { hidden: true, style: {}, classList: { toggle() {}, remove() {} },
    scrollHeight: 230, contains: target => target === control || target === detail,
    set innerHTML(value) { renders++; this.content = value; } };
  const marker = { isConnected: true, getBoundingClientRect: () => rectangle,
    closest: selector => selector.startsWith('#') ? scroll : label ? { parentElement: { querySelector: () => label } } : null };
  let current = marker;
  const document = { activeElement: control, addEventListener(type, handler, options) {
    assert.equal(type, 'scroll'); this.scroll = handler; this.options = options;
  }, querySelector(selector) {
    if (selector === '.topbar') return topbar;
    if (selector === '.timeline-floating-header') return header;
    queries++; assert.equal(selector, `[data-hover-key="${key}"]`); return current;
  } };
  const state = { hoverModels: new Map([[key, { type: 'source-record', mark: {} }]]),
    eventLogHoverModels: new Map(), hoverPinned: false, hoverKey: null };
  const window = { innerWidth: 608, innerHeight: 668, clearTimeout() {} };
  const byId = id => {
    if (id === 'timeline-floating-header') return header;
    if (id === 'timeline-scroll') return scroll;
    assert.equal(id, 'timeline-hover'); return card;
  };
  const api = load(['showHover', 'positionHover', 'closeHover'], {
    state, window, document, byId, CSS: { escape: String },
    sourceRecordHoverHtml: () => 'source details', bindHoverCardActions: () => { bindings++; },
  });
  // Install the production capture listener, without unrelated page controls.
  const start = source.indexOf('  document.addEventListener("scroll",');
  const end = source.indexOf('\n  window.addEventListener("resize",', start);
  assert.ok(start >= 0 && end > start);
  new Function('document', 'byId', 'positionHover', source.slice(start, end))(document, byId, api.positionHover);
  return { api, state, window, document, byId, card, control, detail, marker, key,
    move: value => { rectangle = rect(rectangle.left, value, rectangle.width, rectangle.height); },
    setRect: value => { rectangle = value; }, replace: value => { current = value; },
    clip: value => { ({ scroll = null, header = null, label = null, topbar = null } = value); },
    counts: () => ({ renders, bindings, queries }) };
}

for (const target of ['document', 'nested timeline']) test(`open popup follows ${target} scrolling without rebuilding details`, () => {
  const h = harness();
  h.api.showHover(h.key, h.marker, true);
  assert.equal(h.card.style.top, '404px');
  assert.deepEqual(h.document.options, { capture: true, passive: true });
  for (const top of [350, 320, 327]) {
    h.move(top);
    h.document.scroll({ target: target === 'document' ? h.document : {} });
    assert.equal(h.card.style.top, `${top + 24}px`);
  }
  assert.equal(h.counts().renders, 1);
  assert.equal(h.counts().bindings, 1);
  assert.equal(h.document.activeElement, h.control);
  assert.equal(h.detail.scrollTop, 87);
  assert.equal(h.state.hoverPinned, true);
});

test('scroll resolves the live instance after replacement and closes when it disappears', () => {
  const h = harness();
  h.api.showHover(h.key, h.marker, false);
  h.marker.isConnected = false;
  h.replace({ isConnected: true, closest: () => null, getBoundingClientRect: () => rect(100, 200, 20, 20) });
  h.document.scroll({ target: h.document });
  assert.equal(h.card.style.top, '230px');
  assert.equal(h.card.style.left, '12px');
  h.replace(null);
  h.document.scroll({ target: h.document });
  assert.equal(h.card.hidden, true);
  assert.equal(h.state.hoverKey, null);
});

test('scrolling inside the popup or after closing does no anchor lookup or content work', () => {
  const h = harness();
  h.api.showHover(h.key, h.marker, true);
  const opened = h.counts();
  h.document.scroll({ target: h.detail });
  assert.deepEqual(h.counts(), opened);
  h.api.closeHover();
  h.document.scroll({ target: h.document });
  assert.deepEqual(h.counts(), opened);
});

test('opening the lane picker dismisses pinned and pending hover before moving focus', () => {
  const h = harness();
  h.api.showHover(h.key, h.marker, true);
  h.state.hoverOpenTimer = 10;
  h.state.hoverCloseTimer = 11;
  const cancelled = [];
  h.window.clearTimeout = timer => cancelled.push(timer);
  let click, focused = 0;
  const picker = { hidden: true };
  const toggle = { addEventListener: (type, callback) => { assert.equal(type, 'click'); click = callback; }, setAttribute() {} };
  const filter = { focus() {
    assert.equal(h.card.hidden, true);
    assert.equal(h.state.hoverPinned, false);
    assert.equal(h.state.hoverKey, null);
    assert.deepEqual(cancelled.slice(-2), [10, 11]);
    focused++;
  } };
  const controls = { 'lane-picker': picker, 'lane-picker-toggle': toggle, 'lane-filter': filter };
  const start = source.indexOf('  byId("lane-picker-toggle").addEventListener("click",');
  const end = source.indexOf('\n  byId("close-lane-picker")', start);
  assert.ok(start >= 0 && end > start);
  new Function('byId', 'closeHover', source.slice(start, end))(id => controls[id], h.api.closeHover);
  click();
  assert.equal(picker.hidden, false);
  click();
  assert.equal(picker.hidden, true);
  assert.equal(focused, 1);
  assert.deepEqual(cancelled, [10, 11], 'closing the picker does not run opening side effects');
});

test('timeline rerender follows a moved live anchor and dismisses a removed one without a scroll event', () => {
  const h = harness();
  h.api.showHover(h.key, h.marker, true);
  const noop = () => {};
  let nextAnchor = h.marker;
  const content = { style: {}, appendChild: noop,
    set innerHTML(_value) { h.replace(nextAnchor); } };
  const frame = { querySelector: () => ({ style: {} }) };
  Object.assign(h.state, { laneByResource: new Map(), activeLayers: new Set(), cursorNs: 0n });
  h.document.createElement = () => ({ style: {}, setAttribute: noop });
  h.window.requestAnimationFrame = noop;
  const api = load(['renderTimeline'], {
    state: h.state, window: h.window, document: h.document,
    byId: id => ({ 'timeline-content': content, 'timeline-frame': frame })[id],
    timelineFocusDescriptor: () => null, visibleTimelineLanes: () => [],
    resourceHiddenFromTimeline: () => false, timelineTreeInstances: () => [],
    timelinePhysicalTrackWidth: () => 500, timelineLaneWidth: () => 250,
    eventDensityLane: () => '', timelineExpansionNoticeHtml: () => '', sourceRecordLanesHtml: () => '', reviewMarkerLaneHtml: () => '',
    combinedAssociationLane: () => '', timelinePercent: () => 0, rangeBounds: () => null,
    renderRuler: noop, rebuildHiddenEventProjectionIndex: noop, bindTimelineInteractions: noop,
    updateCursorVisual: noop, updateRangeBands: noop, renderLanePicker: noop,
    updateTimelineCommandAvailability: noop, restoreTimelineFocusDescriptor: noop,
    drawTimelineCorrelationOverlay: noop, positionHover: h.api.positionHover,
  });
  for (const top of [329.2, 380, 329.2]) {
    nextAnchor = { isConnected: true, closest: () => null, getBoundingClientRect: () => rect(380, top) };
    api.renderTimeline();
    assert.equal(h.card.style.top, `${top + 24}px`);
    assert.equal(h.card.hidden, false);
    assert.equal(h.document.activeElement, h.control);
    assert.equal(h.detail.scrollTop, 87);
    assert.equal(h.counts().renders, 1);
    assert.equal(h.counts().bindings, 1);
  }
  nextAnchor = null;
  api.renderTimeline();
  assert.equal(h.card.hidden, true);
  assert.equal(h.state.hoverPinned, false);
});

test('scroll dismisses fully clipped document anchors and does not revive them on return', () => {
  for (const hidden of [rect(-14, 380), rect(608, 380), rect(380, -14), rect(380, 668), rect(380, 54)]) {
    const h = harness();
    h.clip({ topbar: { getBoundingClientRect: () => rect(0, 0, 608, 68) } });
    h.api.showHover(h.key, h.marker, true);
    h.setRect(hidden);
    h.document.scroll({ target: h.document });
    assert.equal(h.card.hidden, true);
    assert.equal(h.state.hoverKey, null);
    assert.equal(h.state.hoverPinned, false);
    h.move(380);
    h.document.scroll({ target: h.document });
    assert.equal(h.card.hidden, true, 'scrolling back does not reopen an old pinned card');
  }
});

test('timeline clipping includes client bounds, sticky header and lane label', () => {
  for (const hidden of [rect(236, 300), rect(542, 300), rect(380, 196), rect(380, 482)]) {
    const h = harness();
    const scroll = { id: 'timeline-scroll', clientLeft: 2, clientTop: 2, clientWidth: 500, clientHeight: 300,
      getBoundingClientRect: () => rect(40, 180, 520, 320) };
    h.clip({ scroll, header: { getBoundingClientRect: () => rect(40, 150, 520, 60) },
      label: { getBoundingClientRect: () => rect(42, 210, 208, 272) } });
    h.api.showHover(h.key, h.marker, true);
    h.setRect(hidden);
    h.document.scroll({ target: scroll });
    assert.equal(h.card.hidden, true, JSON.stringify(hidden));
  }
});

test('positive visible slivers keep the card and clamp it within the viewport', () => {
  const h = harness();
  h.api.showHover(h.key, h.marker, true);
  for (const partial of [rect(-13.5, 380), rect(607.5, 380), rect(380, -13.5), rect(380, 667.5)]) {
    h.setRect(partial);
    h.document.scroll({ target: h.document });
    assert.equal(h.card.hidden, false);
    assert.ok(Number.parseFloat(h.card.style.left) >= 12);
    assert.ok(Number.parseFloat(h.card.style.left) + 390 <= h.window.innerWidth - 12);
    assert.ok(Number.parseFloat(h.card.style.top) >= 12);
    assert.ok(Number.parseFloat(h.card.style.top) + 230 <= h.window.innerHeight - 12);
    assert.equal(h.document.activeElement, h.control);
    assert.equal(h.detail.scrollTop, 87);
  }
  h.window.innerHeight = 220;
  h.setRect(rect(380, 219.5));
  h.api.positionHover();
  assert.equal(h.card.hidden, false);
  assert.equal(h.card.style.top, '12px', 'placement uses the CSS viewport height cap');
  assert.equal(h.counts().renders, 1);
  assert.equal(h.counts().bindings, 1);
});

test('log anchors use their own scrollport and thead rather than timeline occlusion', () => {
  const h = harness();
  const scroll = { id: 'event-log-scroll', clientLeft: 2, clientTop: 2, clientWidth: 500, clientHeight: 300,
    getBoundingClientRect: () => rect(40, 180, 520, 320),
    querySelector: selector => { assert.equal(selector, 'thead'); return { getBoundingClientRect: () => rect(42, 182, 1050, 30) }; } };
  h.clip({ scroll, header: { getBoundingClientRect: () => rect(0, 0, 608, 400) } });
  h.setRect(rect(42, 215, 1050, 44));
  h.api.showHover(h.key, h.marker, true);
  assert.equal(h.card.hidden, false);
  assert.equal(h.card.style.left, '97px', 'center over the visible part of a wide log row');
  h.setRect(rect(42, 198, 1050, 14));
  h.document.scroll({ target: scroll });
  assert.equal(h.card.hidden, true);
});

test('opening on a fully clipped target does not bind hidden card actions', () => {
  const h = harness();
  h.setRect(rect(608, 380));
  h.api.showHover(h.key, h.marker, true);
  assert.equal(h.card.hidden, true);
  assert.equal(h.state.hoverKey, null);
  assert.equal(h.counts().bindings, 0);
  h.setRect(rect());
  h.api.showHover(h.key, h.marker, true);
  assert.equal(h.card.hidden, false);
  assert.equal(h.card.style.top, '404px');
  assert.equal(h.counts().bindings, 1);
});

test('timeline focus settles native reveal before opening and preserves nearest alignment', () => {
  const h = harness(), listeners = new Map(), calls = [];
  h.marker.dataset = { hoverKey: h.key };
  h.marker.addEventListener = (type, listener) => listeners.set(type, listener);
  h.marker.closest = selector => selector === '#timeline-content' ? {} : null;
  h.marker.scrollIntoView = options => {
    calls.push(options);
    assert.deepEqual(options, { behavior: 'instant', block: 'nearest', inline: 'nearest' });
    const before = h.marker.getBoundingClientRect();
    if (before.top >= h.window.innerHeight) h.move(333);
  };
  const api = load(['bindHoverTarget'], { state: h.state, window: h.window, document: h.document, byId: h.byId,
    scrollTimelineTargetIntoView: () => assert.fail('visible targets must not be centered'),
    showHover: h.api.showHover, scheduleHoverClose() {} });
  api.bindHoverTarget(h.marker);
  h.document.activeElement = h.marker;
  for (let repeat = 0; repeat < 2; repeat++) {
    h.setRect(rect(380, 710));
    listeners.get('focus')();
    assert.equal(h.card.hidden, false, 'visibility is tested after the focus reveal');
    assert.equal(h.card.style.top, '357px');
    assert.equal(h.document.activeElement, h.marker);
    h.api.closeHover();
  }
  const visible = h.marker.getBoundingClientRect();
  listeners.get('focus')();
  assert.deepEqual(h.marker.getBoundingClientRect(), visible, 'nearest alignment leaves an already visible target in place');
  assert.equal(calls.length, 3);
});

for (const refresh of ['full timeline', 'density lane']) test(`${refresh} passive focus repair preserves scroll after the animation frame`, () => {
  const h = harness(), listeners = new Map(), frames = [];
  const descriptor = { property: 'hoverKey', value: h.key };
  const scroll = { id: 'timeline-scroll', scrollTop: 185, scrollLeft: 28,
    clientLeft: 2, clientTop: 2, clientWidth: 500, clientHeight: 300,
    getBoundingClientRect: () => rect(40, 180, 520, 320) };
  h.clip({ scroll, header: { getBoundingClientRect: () => rect(40, 150, 520, 60) } });
  h.state.timelineFocusRestoring = false;
  h.document.body = {};
  h.window.scrollY = 300;
  h.window.requestAnimationFrame = callback => frames.push(callback);
  h.marker.dataset = { hoverKey: h.key };
  h.marker.addEventListener = (type, listener) => listeners.set(type, listener);
  h.marker.closest = selector => selector === '#timeline-content' ? {} : selector.startsWith('#') ? scroll : null;
  let reveals = 0, replacements = 0;
  h.marker.scrollIntoView = () => {
    reveals++;
    scroll.scrollTop = 0;
    h.window.scrollY = 0;
    h.move(300);
  };
  h.marker.focus = options => {
    if (options) assert.deepEqual(options, { preventScroll: true });
    h.document.activeElement = h.marker;
    listeners.get('focus')();
  };
  const replacement = { querySelectorAll: () => [h.marker] };
  const row = { replaceWith(next) {
    assert.equal(next, replacement);
    replacements++;
    h.document.activeElement = h.document.body;
  } };
  const content = { querySelector: selector => { assert.equal(selector, '.density-row'); return row; } };
  h.document.createElement = tag => {
    assert.equal(tag, 'template');
    return { content: { firstElementChild: replacement } };
  };
  const api = load(['bindHoverTarget', 'restoreTimelineFocusDescriptor', 'rerenderTimelinePreservingScroll', 'refreshDensityLaneForScroll'], {
    state: h.state, window: h.window, document: h.document,
    byId: id => id === 'timeline-content' ? content : h.byId(id),
    timelineElementForFocusDescriptor: value => { assert.equal(value, descriptor); return h.marker; },
    timelineFocusDescriptor: () => h.document.activeElement === h.marker ? descriptor : null,
    eventDensityLane: () => '<div></div>',
    renderTimeline() {
      h.document.activeElement = h.document.body;
      scroll.scrollTop = 1;
      scroll.scrollLeft = 2;
      api.restoreTimelineFocusDescriptor(descriptor);
    },
    scrollTimelineTargetIntoView: () => assert.fail('passive repair must not center the timeline'),
    showHover: h.api.showHover, scheduleHoverClose() {},
  });
  api.bindHoverTarget(h.marker);
  h.document.activeElement = h.marker;
  h.api.showHover(h.key, h.marker, true);
  h.setRect(rect(380, 90));
  h.document.scroll({ target: scroll });
  assert.equal(h.card.hidden, true);
  if (refresh === 'full timeline') api.rerenderTimelinePreservingScroll();
  else api.refreshDensityLaneForScroll();
  const saved = [scroll.scrollTop, scroll.scrollLeft, h.window.scrollY];
  assert.deepEqual(saved, [185, 28, 300]);
  assert.equal(frames.length, 1);
  frames.shift()();
  assert.deepEqual([scroll.scrollTop, scroll.scrollLeft, h.window.scrollY], saved);
  assert.equal(reveals, 0);
  assert.equal(h.card.hidden, true, 'restoring clipped focus does not revive a dismissed card');
  assert.equal(h.state.hoverKey, null);
  assert.equal(h.document.activeElement, h.marker);
  assert.equal(h.state.timelineFocusRestoring, false);
  assert.equal(replacements, refresh === 'density lane' ? 1 : 0);
  h.document.activeElement = h.document.body;
  h.marker.focus();
  assert.equal(reveals, 1, 'a later explicit focus still reveals the target');
  assert.equal(h.card.hidden, false);
  api.restoreTimelineFocusDescriptor(descriptor);
  h.document.activeElement = h.control;
  frames.shift()();
  assert.equal(h.document.activeElement, h.control, 'a newer user focus move still wins');
  assert.equal(reveals, 1);
});

for (const occlusion of ['header', 'label']) test(`timeline focus corrects native alignment behind its sticky ${occlusion}`, () => {
  const h = harness(), listeners = new Map();
  let pageShift = 0, vertical = 89, horizontal = 300, reveals = 0;
  const initial = occlusion === 'header' ? rect(380, 0.041, 14.143, 14.143) : rect(200, 300);
  const initialTop = occlusion === 'header' ? -100 : 180;
  const header = { getBoundingClientRect: () => rect(40, 60, 520, 134.2) };
  const label = { getBoundingClientRect: () => rect(42, h.marker.getBoundingClientRect().top - 5, 208, 24) };
  const scroll = { id: 'timeline-scroll', clientLeft: 2, clientTop: 2, clientWidth: 500, clientHeight: 580,
    getBoundingClientRect: () => rect(40, initialTop + pageShift, 520, 600),
    scrollIntoView(options) {
      assert.deepEqual(options, { behavior: 'instant', block: 'center', inline: 'nearest' });
      reveals++;
      pageShift += 180 - scroll.getBoundingClientRect().top;
    },
    get scrollTop() { return vertical; }, set scrollTop(value) { vertical = Math.max(0, value); },
    get scrollLeft() { return horizontal; }, set scrollLeft(value) { horizontal = Math.max(0, value); },
  };
  h.clip({ scroll, header, label, topbar: { getBoundingClientRect: () => rect(0, 0, 608, 60) } });
  h.window.scrollBy = ({ top, behavior }) => { assert.equal(behavior, 'instant'); pageShift -= top; };
  h.marker.getBoundingClientRect = () => rect(initial.left + 300 - horizontal, initial.top + pageShift + 89 - vertical,
    initial.width, initial.height);
  h.marker.dataset = { hoverKey: h.key };
  h.marker.addEventListener = (type, listener) => listeners.set(type, listener);
  h.marker.closest = selector => selector === '#timeline-content' ? {}
    : selector.startsWith('#') ? scroll : { parentElement: { querySelector: () => label } };
  h.marker.scrollIntoView = options => assert.deepEqual(options, { behavior: 'instant', block: 'nearest', inline: 'nearest' });
  const api = load(['bindHoverTarget', 'scrollTimelineTargetIntoView'], {
    state: h.state, window: h.window, document: h.document, byId: h.byId,
    showHover: h.api.showHover, scheduleHoverClose() {},
  });
  api.bindHoverTarget(h.marker);
  h.document.activeElement = h.marker;
  for (let repeat = 0; repeat < 2; repeat++) {
    pageShift = 0; vertical = 89; horizontal = 300;
    listeners.get('focus')();
    const target = h.marker.getBoundingClientRect();
    assert.ok(target.top >= header.getBoundingClientRect().bottom, 'marker clears the sticky header');
    assert.ok(target.left >= label.getBoundingClientRect().right, 'marker clears the sticky lane label');
    assert.ok(target.bottom <= h.window.innerHeight);
    assert.ok(target.right <= scroll.getBoundingClientRect().left + scroll.clientLeft + scroll.clientWidth);
    assert.equal(h.card.hidden, false, 'corrected reveal opens the card');
    assert.equal(h.document.activeElement, h.marker);
    h.api.closeHover();
  }
  assert.equal(reveals, 2);
});

test('timeline focus leaves a positive visible sliver beside sticky controls stationary', () => {
  const h = harness(), listeners = new Map();
  const scroll = { id: 'timeline-scroll', clientLeft: 2, clientTop: 2, clientWidth: 500, clientHeight: 580,
    getBoundingClientRect: () => rect(40, 0, 520, 600) };
  const header = { getBoundingClientRect: () => rect(40, 60, 520, 134.2) };
  const label = { getBoundingClientRect: () => rect(42, 180, 208, 200) };
  h.clip({ scroll, header, label, topbar: { getBoundingClientRect: () => rect(0, 0, 608, 60) } });
  h.marker.dataset = { hoverKey: h.key };
  h.marker.addEventListener = (type, listener) => listeners.set(type, listener);
  h.marker.closest = selector => selector === '#timeline-content' ? {}
    : selector.startsWith('#') ? scroll : { parentElement: { querySelector: () => label } };
  h.marker.scrollIntoView = options => assert.deepEqual(options, { behavior: 'instant', block: 'nearest', inline: 'nearest' });
  const api = load(['bindHoverTarget'], { state: h.state, window: h.window, document: h.document, byId: h.byId,
    scrollTimelineTargetIntoView: () => assert.fail('partially visible targets must not be centered'),
    showHover: h.api.showHover, scheduleHoverClose() {},
  });
  api.bindHoverTarget(h.marker);
  for (const target of [rect(380, 180.7), rect(236.5, 300)]) {
    h.setRect(target);
    listeners.get('focus')();
    assert.deepEqual(h.marker.getBoundingClientRect(), target);
    assert.equal(h.card.hidden, false);
    h.api.closeHover();
  }
});

test('log focus does not replace virtual row positioning with native scrolling', () => {
  const h = harness(), listeners = new Map();
  h.marker.dataset = { hoverKey: h.key };
  h.marker.addEventListener = (type, listener) => listeners.set(type, listener);
  h.marker.closest = () => null;
  h.marker.scrollIntoView = () => assert.fail('native scrolling would disturb the virtual row position');
  const api = load(['bindHoverTarget'], { state: h.state, window: h.window,
    showHover: h.api.showHover, scheduleHoverClose() {} });
  api.bindHoverTarget(h.marker);
  listeners.get('focus')();
  assert.equal(h.card.hidden, false);
  assert.equal(h.card.style.top, '404px');
});

for (const kind of ['source', 'normalized']) test(`${kind} open cluster tracks Apply/Clear repeatedly without replacing loaded details`, () => {
  const state = { rangeStartNs: 360n, rangeEndNs: 361n, rangeRequestId: 0,
    // The card is a retained snapshot; current lane models need not contain its entries.
    hoverModels: new Map(), viewStartNs: 0n, viewEndNs: 1000n };
  const controls = { 'range-start-input': { value: '120' }, 'range-end-input': { value: '129' },
    'range-error': {}, 'clear-range': {}, 'timeline-frame': { classList: { toggle() {} } } };
  let rows = [], placements = 0;
  const document = { activeElement: null, querySelectorAll: selector => selector.includes('.cluster-event[data-time-ns]') ? rows : [] };
  const noop = () => {};
  const api = load(['rangeBounds', 'inSelectedRange', 'sourceClusterHoverHtml', 'clusterHoverHtml',
    'applyRangeHighlight', 'updateRangeBands', 'applyRangeEditor', 'clearRangeSelection'], {
    state, document, byId: id => controls[id], toNs: BigInt, parseRangeInput: BigInt,
    formatOffset: String, escapeHtml: String, rangeMinimumNs: () => 1n,
    updateRangeHandles: noop, updateTimelineCommandAvailability: noop, syncRangeInputs: noop,
    requestRangeSummary: noop, abortLatestRequests: noop, renderRangeSummary: noop,
    positionHover: () => { placements++; },
  });
  const items = [119n, 120n, 129n].map((timeNs, i) => ({ timeNs,
    eventUid: `e${i}`, sourceRecordUid: `s${i}`, label: `Event ${i}`, recordName: `Source ${i}`,
    action: 'modify', outcome: 'success', sourceType: 'ctf', matchedEventUid: i ? null : 'match' }));
  const cluster = { items: items.slice(0, 1), detailItems: items, detailHydrated: true,
    detailTotal: 5, count: 5, detailNextOffset: 3, eventUids: items.map(item => item.eventUid) };
  const html = kind === 'source' ? api.sourceClusterHoverHtml({ items, count: 3 }) : api.clusterHoverHtml(cluster, {});
  // Parse production markup into bounded DOM doubles, so absent/wrong metadata fails too.
  rows = [...html.matchAll(/<button type="button" class="(cluster-event[^"]*)"([^>]*)>(.*?)<\/button>/gs)].map(match => {
    const attributes = Object.fromEntries([...match[2].matchAll(/([\w-]+)="([^"]*)"/g)].map(item => [item[1], item[2]]));
    const suffix = /<span class="cluster-range-label">([^<]*)<\/span>/.exec(match[3]);
    assert.ok(suffix, 'each rendered entry owns a range suffix');
    const classes = new Set(match[1].split(' '));
    const rangeLabel = { textContent: suffix[1] };
    return { dataset: { timeNs: attributes['data-time-ns'] }, attributes, rangeLabel,
      baseText: /<small>(.*?)<span class="cluster-range-label">/s.exec(match[3])[1],
      classList: { toggle: (name, value) => value ? classes.add(name) : classes.delete(name), contains: name => classes.has(name) },
      querySelector: selector => selector === '.cluster-range-label' ? rangeLabel : null,
      hasAttribute: name => Object.hasOwn(attributes, name),
      set innerHTML(_value) { assert.fail('range update replaced a detail row'); } };
  });
  assert.equal(rows.length, 3);
  assert.deepEqual(rows.map(row => row.dataset.timeNs), ['119', '120', '129']);
  const originalRows = [...rows], baseText = rows.map(row => row.baseText);
  const detail = { scrollTop: 137, children: rows };
  const paging = kind === 'normalized' ? /<button class="cluster-load-more"[^>]*data-cluster-detail-offset="3"[^>]*>/.exec(html)?.[0] : null;
  if (kind === 'normalized') assert.ok(paging, 'hydrated pages retain their existing next-page control');
  document.activeElement = rows[1];
  for (let repeat = 0; repeat < 2; repeat++) {
    assert.equal(api.applyRangeEditor({ preventDefault: noop }), true);
    assert.deepEqual(rows.map(row => row.classList.contains('in-range')), [false, true, true]);
    assert.deepEqual(rows.map(row => row.rangeLabel.textContent), [kind === 'source' ? '' : ' / outside selected range', ' / in selected range', ' / in selected range']);
    api.clearRangeSelection();
    assert.deepEqual(rows.map(row => row.classList.contains('in-range')), [false, false, false]);
    assert.deepEqual(rows.map(row => row.rangeLabel.textContent), ['', '', '']);
    assert.deepEqual(rows.map(row => row.baseText), baseText);
    rows.forEach((row, index) => assert.equal(row, originalRows[index]));
    assert.equal(document.activeElement, rows[1]);
    assert.equal(detail.scrollTop, 137);
    assert.equal(detail.children, rows);
    assert.equal(cluster.detailItems, items);
    assert.equal(cluster.detailNextOffset, 3);
  }
  assert.equal(placements, 4, 'range updates reconcile height without reopening the card');
});
