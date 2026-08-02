import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  eventChangesState,
  eventEffects,
  eventFailed,
  eventMarkClass,
  normalizedEventOutcome,
  resourceEffectStatusClass,
} from "../assets/timeline_models.js";

const appSource = readFileSync(
  new URL("../assets/app.js", import.meta.url),
  "utf8",
);

test("the node entry point consumes the shared timeline model", () => {
  assert.match(appSource, /from "\.\/timeline_models\.js"/);
  for (const name of [
    "eventChangesState",
    "eventEffects",
    "eventFailed",
    "eventMarkClass",
    "normalizedEventOutcome",
    "resourceEffectStatusClass",
  ]) {
    const references = appSource.match(new RegExp(`\\b${name}\\b`, "g"));
    assert.ok(
      references && references.length >= 2,
      `app.js must import and call ${name}`,
    );
    assert.doesNotMatch(
      appSource,
      new RegExp(`function\\s+${name}\\s*\\(`),
      `${name} must not be reimplemented in app.js`,
    );
  }
});

test("normalized event outcomes are closed and explicit failure wins", () => {
  for (const [event, expected] of [
    [{ outcome: "SUCCESS" }, "success"],
    [{ outcome: "failure" }, "failure"],
    [{ outcome: "unknown" }, "unknown"],
    [{ outcome: "degraded" }, "unknown"],
    [{ outcome: 1 }, "unknown"],
    [{ outcome: "success", failure: true }, "failure"],
    [{ outcome: "success", failed: true }, "failure"],
  ]) {
    assert.equal(normalizedEventOutcome(event), expected);
  }
  assert.equal(eventFailed({ outcome: "success" }), false);
  assert.equal(eventFailed({ outcome: "failure" }), true);
});

test("event effects discard non-record values without inventing mutations", () => {
  const first = { state_changed: false };
  const second = { state_changed: true };
  assert.deepEqual(eventEffects({ effects: [null, "bad", first, 0, second] }), [
    first,
    second,
  ]);
  assert.deepEqual(eventEffects({ effects: "not-an-array" }), []);
});

test("event state-change precedence preserves explicit false and tri-state absence", () => {
  assert.equal(
    eventChangesState({ state_changed: false, effects: [{ state_changed: true }] }),
    false,
  );
  assert.equal(eventChangesState({ state_changed: 1 }), true);
  assert.equal(
    eventChangesState({ effects: [{ state_changed: false }, { state_changed: true }] }),
    true,
  );
  assert.equal(eventChangesState({ effects: [{ state_changed: false }] }), false);
  assert.equal(
    eventChangesState({ effects: [{ state_changed: null }, { other: true }] }),
    null,
  );
  assert.equal(eventChangesState({}), null);
});

test("resource status class uses declared transport precedence and fails closed", () => {
  assert.equal(
    resourceEffectStatusClass(
      { status_class: "effect-status", condition_class: "effect-condition" },
      { status_class: "event-status" },
    ),
    "effect-status",
  );
  assert.equal(
    resourceEffectStatusClass(
      { condition_class: "effect-condition" },
      { status_class: "event-status" },
    ),
    "effect-condition",
  );
  assert.equal(
    resourceEffectStatusClass({}, { status_class: "event-status" }),
    "event-status",
  );
  assert.equal(
    resourceEffectStatusClass({}, { condition_class: "event-condition" }),
    "event-condition",
  );
  for (const value of [null, "", 0, false]) {
    assert.equal(resourceEffectStatusClass({ status_class: value }), "unknown");
  }
  assert.equal(resourceEffectStatusClass(null, null), "unknown");
});

test("timeline mark classes cover every normalized effect family", () => {
  for (const [mark, expected] of [
    [{ failure: true, effectType: "create" }, "failure"],
    [{ effectType: "created" }, "create"],
    [{ effectType: "CREATE" }, "create"],
    [{ effectType: "deleted" }, "delete"],
    [{ effectType: "DELETE" }, "delete"],
    [{ effectType: "modified" }, "modify"],
    [{ effectType: "MODIFY" }, "modify"],
    [{ effectType: "unchanged" }, "modify"],
    [{ effectType: "failed" }, "unknown"],
    [{ effectType: "" }, "unknown"],
    [null, "unknown"],
  ]) {
    assert.equal(eventMarkClass(mark), expected);
  }
});
