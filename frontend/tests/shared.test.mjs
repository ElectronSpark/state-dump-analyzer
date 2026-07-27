import assert from "node:assert/strict";
import test from "node:test";

import {
  escapeHtml,
  safeClass,
  titleCase,
  toBigInt,
} from "../assets/shared.js";

test("escapeHtml makes plug-in text inert in generated markup", () => {
  assert.equal(
    escapeHtml('<img src=x onerror="alert(1)">'),
    "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;",
  );
});

test("safeClass admits only the class-token subset", () => {
  assert.equal(safeClass('Healthy" onclick="alert(1)'), "healthy-onclick-alert-1-");
});

test("titleCase preserves readable labels without interpreting markup", () => {
  assert.equal(titleCase("best_effort-route"), "Best Effort Route");
});

test("toBigInt preserves nanosecond integers beyond Number precision", () => {
  assert.equal(toBigInt("1759680625001000000"), 1759680625001000000n);
  assert.equal(toBigInt("not-a-number", 9n), 9n);
});
