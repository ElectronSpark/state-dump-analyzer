import test from "node:test";
import assert from "node:assert/strict";
import { analysisTimeAt, analysisQuery, analysisNanoseconds } from "../assets/management_analysis.js";

test("timeline slider preserves nanoseconds beyond Number precision", () => {
  assert.equal(analysisTimeAt("1788624096356087000", "1788624096356089000", 500), "1788624096356088000");
  assert.equal(analysisTimeAt("-1000", "1000", 250), "-500");
  assert.throws(() => analysisTimeAt("1", "0", 0)); assert.throws(() => analysisTimeAt("0", "1", 1001));
});
test("queries preserve session digest and explicit member; no event range leaks to resource reads", () => {
  const state = { analysisSelector: { session_id: "s" }, analysisDigest: "digest", analysisMember: "m", analysisTime: "9007199254740999", analysisSection: "resources", analysisRange: { start_ns: "1", end_ns: "2" } };
  assert.deepEqual(analysisQuery(state), { selector: { session_id: "s" }, section: "resources", offset: 0, limit: 50, expected_revision_vector_digest: "digest", selected_member_id: "m", time_ns: "9007199254740999" });
  assert.equal(analysisQuery({ ...state, analysisSection: "events" }).end_ns, "2");
  assert.throws(() => analysisQuery({}));
});

test("analysis coordinates reject noncanonical and out-of-range values before changing query state", () => {
  for (const value of ["-9223372036854775808", "0", "9223372036854775807"]) assert.equal(analysisNanoseconds(value), value);
  for (const value of [0, "-0", "01", "+1", " 1", "1e9", "9223372036854775808", "-9223372036854775809", "1".repeat(100)]) assert.throws(() => analysisNanoseconds(value));
  assert.throws(() => analysisQuery({ analysisSelector: { session_id: "s" }, analysisTime: "-0" }));
  assert.throws(() => analysisQuery({ analysisSelector: { session_id: "s" }, analysisSection: "events", analysisRange: { start_ns: "2", end_ns: "1" } }));
});
