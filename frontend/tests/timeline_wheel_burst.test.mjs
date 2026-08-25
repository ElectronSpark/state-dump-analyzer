import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const APP_SOURCE = readFileSync(
  new URL("../assets/app.js", import.meta.url),
  "utf8",
);

function functionSource(name) {
  const marker = `function ${name}(`;
  const start = APP_SOURCE.indexOf(marker);
  assert.notEqual(start, -1, `app.js must define ${name}()`);
  const openingBrace = APP_SOURCE.indexOf("{", start + marker.length);
  assert.notEqual(openingBrace, -1, `${name}() must have a body`);
  let depth = 0;
  for (let index = openingBrace; index < APP_SOURCE.length; index += 1) {
    if (APP_SOURCE[index] === "{") depth += 1;
    else if (APP_SOURCE[index] === "}") {
      depth -= 1;
      if (depth === 0) return APP_SOURCE.slice(start, index + 1);
    }
  }
  throw new Error(`${name}() has an unterminated body`);
}

function wheelBurstHarness() {
  let nextTimerId = 1;
  const timers = new Map();
  const cleared = [];
  const history = [];
  let settled = 0;
  let refreshes = 0;
  const fakeWindow = {
    setTimeout(callback) {
      const identifier = nextTimerId;
      nextTimerId += 1;
      timers.set(identifier, callback);
      return identifier;
    },
    clearTimeout(identifier) {
      cleared.push(identifier);
      timers.delete(identifier);
    },
  };
  const state = {
    timelineWheelBurstActive: false,
    timelineWheelMode: null,
    timelineWheelHistoryTimer: null,
    timelineWheelAnchorNs: null,
    timelineWheelAnchorClientX: null,
  };
  const factory = new Function(
    "state",
    "window",
    "rememberTimelineView",
    "settlePendingTimelineWheelFrames",
    "scheduleTimelineWindowRefresh",
    "TIMELINE_WHEEL_HISTORY_DELAY_MS",
    `"use strict";
    ${functionSource("beginTimelineWheelBurst")}
    ${functionSource("scheduleTimelineWheelBurstFinish")}
    ${functionSource("finishTimelineWheelBurst")}
    return { beginTimelineWheelBurst, scheduleTimelineWheelBurstFinish, finishTimelineWheelBurst };`,
  );
  const api = factory(
    state,
    fakeWindow,
    () => history.push(state.timelineWheelMode),
    () => { settled += 1; },
    () => { refreshes += 1; },
    180,
  );
  return {
    api,
    state,
    timers,
    cleared,
    history,
    runTimer(identifier) {
      const callback = timers.get(identifier);
      if (!callback) return false;
      timers.delete(identifier);
      callback();
      return true;
    },
    settled: () => settled,
    refreshes: () => refreshes,
  };
}

for (const [firstMode, secondMode] of [["pan", "zoom"], ["zoom", "pan"]]) {
  test(`${firstMode} to ${secondMode} handoff retires the old finish timer`, () => {
    const harness = wheelBurstHarness();
    harness.api.beginTimelineWheelBurst(firstMode);
    harness.api.scheduleTimelineWheelBurstFinish();
    const staleTimer = harness.state.timelineWheelHistoryTimer;
    assert.equal(harness.timers.has(staleTimer), true);

    harness.api.beginTimelineWheelBurst(secondMode);
    assert.equal(harness.cleared.includes(staleTimer), true);
    assert.equal(harness.timers.has(staleTimer), false);
    assert.equal(harness.state.timelineWheelBurstActive, true);
    assert.equal(harness.state.timelineWheelMode, secondMode);

    harness.api.scheduleTimelineWheelBurstFinish();
    const currentTimer = harness.state.timelineWheelHistoryTimer;
    assert.notEqual(currentTimer, staleTimer);
    assert.deepEqual([...harness.timers.keys()], [currentTimer]);

    assert.equal(harness.runTimer(staleTimer), false);
    assert.equal(harness.state.timelineWheelBurstActive, true);
    assert.equal(harness.state.timelineWheelMode, secondMode);

    assert.equal(harness.runTimer(currentTimer), true);
    assert.equal(harness.state.timelineWheelBurstActive, false);
    assert.equal(harness.state.timelineWheelMode, null);
    assert.equal(harness.state.timelineWheelHistoryTimer, null);
    assert.equal(harness.settled(), 2);
    assert.equal(harness.refreshes(), 2);
  });
}
