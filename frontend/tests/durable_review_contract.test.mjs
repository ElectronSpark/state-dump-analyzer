import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(
  new URL("../assets/app.js", import.meta.url),
  "utf8",
);
const nodePage = readFileSync(
  new URL("../pages/node.html", import.meta.url),
  "utf8",
);

test("the node entry point wires the executable durable-review module", () => {
  assert.match(source, /from "\.\/durable_review_controller\.js"/);
  for (const importedBehavior of [
    "awaitCurrentDurableReview",
    "buildDurableAnnotationMarkerIndex",
    "completePendingReviewMutation",
    "durableCreationRequestOptions",
    "durableConditionalRequestOptions",
    "durableMutationPayloadIdentity",
    "durableMutationScopeKey",
    "listAllDurableAnnotations",
    "reconcilePendingReviewMutations",
    "reservePendingReviewMutation",
    "requestDurableReview",
    "savePendingReviewMutations",
  ]) {
    const references = source.match(
      new RegExp(`\\b${importedBehavior}\\b`, "g"),
    );
    assert.ok(
      references && references.length >= 2,
      `app.js must import and call ${importedBehavior}`,
    );
  }
});

test("durable review HTML exposes every bound control and snapshot copy", () => {
  for (const id of [
    "durable-review-setup",
    "durable-review-form",
    "durable-review-tenant",
    "durable-review-project",
    "durable-review-workspace",
    "durable-review-principal",
    "durable-review-connect",
    "durable-review-local",
    "durable-review-discard-pending",
    "durable-review-reset-pending",
    "durable-review-report-scope",
    "durable-review-copy-report",
    "durable-review-download-report",
    "event-selection-mark",
    "event-selection-unmark",
    "event-selection-correlate",
    "correlation-dialog",
    "correlation-form",
    "correlation-link-type",
    "correlation-rationale",
    "correlation-submit",
  ]) {
    assert.match(nodePage, new RegExp(`\\bid="${id}"`), `missing #${id}`);
  }
  assert.match(nodePage, /snapshots freeze a reproducible revision vector/);
});

test("a reconnect cannot carry correlation subjects into another scope", () => {
  const match = source.match(
    /async function connectDurableReview\([^)]*\) \{([\s\S]*?)const config = durableReviewConfigFromInputs\(\);/,
  );
  assert.ok(match, "connectDurableReview must keep an inspectable reconnect preamble");
  assert.match(match[1], /closeManualCorrelationDialog\(\)/);
});
