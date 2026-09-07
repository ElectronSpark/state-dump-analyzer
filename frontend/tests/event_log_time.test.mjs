import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { escapeHtml, titleCase, toBigInt } from "../assets/shared.js";

const source = readFileSync(new URL("../assets/app.js", import.meta.url), "utf8");
function functionSource(name) {
  const signature = new RegExp(`(?:async )?function ${name}\\(`).exec(source);
  assert.ok(signature, `missing production function ${name}`);
  const tail = source.slice(signature.index);
  const ending = /\r?\n\}/.exec(tail);
  assert.ok(ending);
  return tail.slice(0, ending.index + ending[0].length);
}

function harness(events = [], sources = []) {
  const state = {
    dataset: { events }, sourceRecords: sources,
    eventLogInclude: { normalized: true },
    viewStartNs: -100n, viewEndNs: 100n, rangeStartNs: null, rangeEndNs: null,
    sourceRecordByUid: new Map(sources.map((entry) => [entry.source_record_uid, entry])),
    eventByUid: new Map(events.map((entry) => [entry.event_uid, entry])),
    eventLogOwnedSources: new Map(), eventLogOwnedEvents: new Map(),
    timelineEntryProjections: new Map(), hiddenTimelineEntryIds: new Set(),
    markedTimelineEntryIds: new Set(), eventLogSelectionRanges: [],
    durableReview: { markedEntryIds: new Set() }, trackWidth: 800,
  };
  const elements = new Map();
  const byId = (id) => {
    if (!elements.has(id)) elements.set(id, { textContent: "", innerHTML: "", scrollTop: 0 });
    return elements.get(id);
  };
  const effects = { cursor: [], toasts: [], viewport: [] };
  const dependencies = {
    state, byId, escapeHtml, titleCase, toNs: toBigInt,
    usesServerWindowedHistory: () => false,
    bindEventLogSelectionToQuery() {}, serverEventLogQueryKey: () => "query",
    filteredEvents: () => events, filteredSourceRecords: () => sources,
    isTopologyNodeSnapshot: () => false,
    timelineWindowBounds: () => [-100n, 100n],
    timelinePercent: (time) => { assert.equal(typeof time, "bigint"); return Number(time); },
    eventLogSelectionIncludes: (index) => state.eventLogSelectionRanges.some(([a, b]) => a <= index && index <= b),
    sourceTypeDescriptor: () => ({ label: "Status JSON", color: "#abcdef" }),
    humanLayer: String, formatValue: String,
    pruneServerEventLogOwnedCaches() {}, renderTimeline() {}, renderEventTable() {},
    setCursor: (time) => effects.cursor.push(time),
    showToast: (message) => effects.toasts.push(message),
    eventOrMark: (uid) => state.eventByUid.get(uid),
    moveTimelineWindowToReveal: (time) => effects.viewport.push(time),
    selectEvent() {}, eventResourceRefs: () => [], durableReviewTokenIsCurrent: () => true,
  };
  const names = [
    "eventTime", "sourceRecordTime", "sourceRecordUid", "sourceRecordMatchedEventUids",
    "normalizedLogEntryId", "sourceLogEntryId", "isSourceLogEntry", "logEntryId", "logEntryTime",
    "compareLogEntryIds", "compareLogEntries", "mergeLogEntries", "formatOffset",
    "rangeBounds", "inSelectedRange", "timelinePointVisible", "virtualEventLogRows",
    "rebuildEventLogRows", "renderSourceRecordRow", "renderSourceRecordInspector",
    "sourceRecordHoverHtml", "normalizeSourceMark", "buildSourceGlyphs",
    "rememberTimelineEntryProjection", "hydrateDurableReviewProjections",
    "selectSourceRecord", "jumpSourceRecordToTimeline", "jumpToTimelineEvent",
  ];
  const actions = new Function(...Object.keys(dependencies),
    `${names.map(functionSource).join("\n")}\nreturn {${names.join(",")}};`)(...Object.values(dependencies));
  const rows = () => {
    actions.rebuildEventLogRows();
    return state.eventLogRows.slice(0, state.eventLogRows.length).filter((row) => row.kind === "entry");
  };
  return { state, effects, byId, rows, ...actions };
}

test("embedded log orders known times, then untimed, with sequence and code-point ID ties", () => {
  const events = [
    { event_uid: "unknown", timestamp_ns: null, source_sequence: 1 },
    { event_uid: "positive", timestamp_ns: "7" },
    { event_uid: "zero", timestamp_ns: "0", source_sequence: 3 },
    { event_uid: "negative", timestamp_ns: "-2" },
  ];
  const sources = [
    { source_record_uid: "\u{10000}", timestamp_ns: "0", source_sequence: 2 },
    { source_record_uid: "unknown", timestamp_ns: null, source_sequence: 0 },
    { source_record_uid: "\uE000", timestamp_ns: "0", source_sequence: 2 },
    { source_record_uid: "a", timestamp_ns: "0", source_sequence: 2 },
    { source_record_uid: "Z", timestamp_ns: "0", source_sequence: 2 },
  ];
  const h = harness(events, sources);
  assert.deepEqual(h.rows().map((row) => h.logEntryId(row.entry)), [
    "event:negative", "source:Z", "source:a", "source:\uE000", "source:\u{10000}",
    "event:zero", "event:positive", "source:unknown", "event:unknown",
  ]);
  h.state.viewStartNs = 5000n;
  assert.equal(h.sourceRecordTime(sources[1]), null);
  assert.equal(h.rows()[7].selectionIndex, 7);
  assert.equal(h.logEntryId(h.rows()[7].entry), "source:unknown");
});

test("range partition keeps untimed rows selectable as Other records without temporal membership", () => {
  const sources = [
    { source_record_uid: "unknown", timestamp_ns: null },
    { source_record_uid: "negative", timestamp_ns: "-2" },
    { source_record_uid: "zero", timestamp_ns: "0" },
    { source_record_uid: "positive", timestamp_ns: "2" },
  ];
  const h = harness([], sources);
  h.state.rangeStartNs = -1n;
  h.state.rangeEndNs = 1n;
  assert.deepEqual(h.rows().map(({ entry, membership, selectionIndex }) => [entry.source_record_uid, membership, selectionIndex]), [
    ["zero", "inside", 0], ["negative", "outside", 1],
    ["positive", "outside", 2], ["unknown", "outside", 3],
  ]);
  assert.equal(h.inSelectedRange(null), false);
  assert.equal(h.state.eventLogSelectableCount, 4);
});

test("embedded index selections match the Python combined-log conformance fixture", () => {
  const fixture = JSON.parse(readFileSync(
    new URL("../../tests/fixtures/event-log-time-parity.json", import.meta.url), "utf8",
  ));
  for (const { selected_range: selectedRange, response } of fixture.cases) {
    const h = harness(fixture.dataset.events, fixture.dataset.source_records);
    if (selectedRange) [h.state.rangeStartNs, h.state.rangeEndNs] = selectedRange.map(BigInt);
    const local = h.rows().map((row) => ({
      display_index: row.selectionIndex,
      entry_id: h.logEntryId(row.entry),
      timestamp_ns: h.logEntryTime(row.entry)?.toString() ?? null,
      membership: row.membership ?? "all",
    }));
    const expected = response.items.map((item) => ({
      display_index: item.display_index,
      entry_id: `${item.stream_kind}:${item.uid}`,
      timestamp_ns: item.timestamp_ns,
      membership: item.membership,
    }));
    assert.deepEqual(local, expected, JSON.stringify(selectedRange));
    assert.equal(local[1].entry_id, expected[1].entry_id);
    assert.equal(local.filter((item) => item.membership === "inside").length, response.inside_count);
  }
});

test("unknown source time is displayed without fabricated offsets or null-nanosecond text", () => {
  const record = { source_record_uid: "unknown", timestamp_ns: null, source_type: "status-json" };
  const h = harness([], [record]);
  assert.match(h.renderSourceRecordRow(record, null, 0), /<td>Unknown<\/td>/);
  h.renderSourceRecordInspector(record);
  assert.match(h.byId("selected-event-fields").innerHTML, /<dt>Time<\/dt><dd>Unknown<\/dd>/);
  const mark = h.normalizeSourceMark(record, { laneId: "source" });
  const hover = h.sourceRecordHoverHtml(mark);
  assert.match(hover, /<dt>When<\/dt><dd>Unknown<\/dd>/);
  assert.doesNotMatch(hover, /null ns|undefined ns/);
});

test("untimed selections and durable projections remain unpositioned and do not move the cursor", async () => {
  const source = { source_record_uid: "unknown", timestamp_ns: null, source_type: "status-json" };
  const event = { event_uid: "unknown", timestamp_ns: null };
  const h = harness([event], [source]);
  const projection = h.rememberTimelineEntryProjection({
    stream_kind: "source", uid: "unknown", timestamp_ns: null, entry: source,
  });
  assert.equal(projection.timeNs, null);
  assert.equal(h.timelinePointVisible(projection.timeNs), false);
  const lane = { laneId: "source", marks: [h.normalizeSourceMark(source, { laneId: "source" })] };
  assert.deepEqual(h.buildSourceGlyphs(lane), []);
  h.state.durableReview.markedEntryIds = new Set(["event:unknown", "source:unknown"]);
  h.hydrateDurableReviewProjections({ observations: { events: [event], source_records: [source] } }, {});
  assert.equal(h.state.timelineEntryProjections.get("event:unknown").timeNs, null);
  assert.equal(h.state.timelineEntryProjections.get("source:unknown").timeNs, null);
  h.selectSourceRecord("unknown", true);
  await h.jumpSourceRecordToTimeline("unknown");
  await h.jumpToTimelineEvent("unknown");
  assert.deepEqual(h.effects.cursor, []);
  assert.deepEqual(h.effects.viewport, []);
  assert.equal(h.effects.toasts.length, 2);
});
