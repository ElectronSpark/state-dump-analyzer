import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  api,
  ControlPlaneRequestError,
  listControlPlaneCollection,
  replaceAbortController,
  requestControlPlane,
} from "../assets/browser_transport.js";
import { controlPlaneCollectionPageDecision } from "../assets/view_models.js";
import * as legacyReview from "../assets/durable_review_controller.js";
import { api as legacyApi } from "../assets/shared.js";
import { replaceAbortController as legacyReplace } from "../assets/view_models.js";

test("compatibility imports preserve function and error class identity", () => {
  assert.equal(legacyApi, api);
  assert.equal(legacyReplace, replaceAbortController);
  assert.equal(legacyReview.ControlPlaneRequestError, ControlPlaneRequestError);
  assert.equal(legacyReview.requestControlPlane, requestControlPlane);
  assert.equal(legacyReview.listControlPlaneCollection, listControlPlaneCollection);
  assert.ok(new ControlPlaneRequestError("failed") instanceof legacyReview.ControlPlaneRequestError);
});

test("generic transport has no dependency on feature controllers", () => {
  const source = readFileSync(new URL("../assets/browser_transport.js", import.meta.url), "utf8");
  assert.doesNotMatch(source, /(?:^|\n)\s*(?:import|export)\s+[^;]*\bfrom\s+["']/);
  for (const name of ["management_controller", "private_analysis_controller"]) {
    const consumer = readFileSync(new URL(`../assets/${name}.js`, import.meta.url), "utf8");
    assert.match(consumer, /from "\.\/browser_transport\.js"/);
    assert.doesNotMatch(consumer, /from "\.\/durable_review_controller\.js"/);
  }
});

function response(payload, { status = 200, contentType = "application/json" } = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 200 ? "OK" : "Failure",
    headers: { get: () => contentType },
    async json() { return payload; },
    async text() { return typeof payload === "string" ? payload : JSON.stringify(payload); },
  };
}

test("JSON api preserves fetch options and caller-owned cancellation", async (context) => {
  const controller = new AbortController();
  const calls = [];
  context.mock.method(globalThis, "fetch", async (path, options) => {
    calls.push({ path, options });
    return response({ ready: true });
  });
  assert.deepEqual(await api("/ready"), { ready: true });
  assert.deepEqual(calls[0], {
    path: "/ready", options: { headers: { "Content-Type": "application/json" } },
  });
  const headers = { Accept: "application/json" };
  const body = '{"query":"test"}';
  await api("/query", { method: "POST", body, headers, signal: controller.signal, cache: "no-store" });
  assert.deepEqual(calls[1].options, {
    headers, method: "POST", body, signal: controller.signal, cache: "no-store",
  });
  const abort = Object.assign(new Error("caller cancelled"), { name: "AbortError" });
  context.mock.method(globalThis, "fetch", async () => { throw abort; });
  await assert.rejects(api("/query", { signal: controller.signal }), (error) => error === abort);
});

test("JSON api retains detail, nested error, status fallback and JSON decoding errors", async (context) => {
  for (const [payload, message] of [
    [{ detail: "bad query" }, "bad query"],
    [{ error: { message: "nested detail" } }, "nested detail"],
    [{}, "422 Failure"],
  ]) {
    context.mock.method(globalThis, "fetch", async () => response(payload, { status: 422 }));
    await assert.rejects(api("/query"), (error) => error.constructor === Error && error.message === message);
  }
  const decodeError = new SyntaxError("invalid JSON");
  for (const status of [200, 503]) {
    context.mock.method(globalThis, "fetch", async () => ({
      ...response(null, { status }), json: async () => { throw decodeError; },
    }));
    await assert.rejects(api("/query"), (error) => status === 200
      ? error === decodeError : error.constructor === Error && error.message === "503 Failure");
  }
});

test("bounded transport retains JSON, text, raw response and no-content results", async () => {
  for (const responseType of ["json", "text", "response", "empty"]) {
    const result = response({ ready: true }, { status: responseType === "empty" ? 204 : 200 });
    const decoded = [];
    result.json = async () => { decoded.push("json"); return { ready: true }; };
    result.text = async () => { decoded.push("text"); return "ready"; };
    const cleared = [];
    const value = await requestControlPlane("/result", {
      responseType, fetchImpl: async (_path, options) => {
        assert.equal(Object.hasOwn(options, "body"), false);
        return result;
      },
      setTimer: () => 23, clearTimer: (timer) => cleared.push(timer),
    });
    assert.deepEqual(cleared, [23]);
    if (responseType === "response") assert.equal(value, result);
    else if (responseType === "empty") assert.equal(value, null);
    else assert.deepEqual(value, responseType === "json" ? { ready: true } : "ready");
    assert.deepEqual(decoded, ["json", "text"].includes(responseType) ? [responseType] : []);
  }
});

test("bounded transport preserves retryable status classification and bounded error text", async () => {
  for (const mutate of [false, true]) {
    for (const status of [400, 408, 409, 425, 429, 500, 502, 503, 504]) {
      await assert.rejects(requestControlPlane("/request", {
        mutate, fetchImpl: async () => response("bad\n\u0000" + "x".repeat(3000), { status, contentType: "text/plain" }),
        setTimer: () => 1, clearTimer: () => {},
      }), (error) => {
        assert.equal(error.status, status);
        assert.equal(error.ambiguous, mutate && ![400, 409].includes(status));
        assert.equal(error.message.length, 2048);
        assert.equal(error.message.startsWith("bad x"), true);
        return error instanceof ControlPlaneRequestError;
      });
    }
  }
});

test("bounded transport preserves status on malformed bodies and custom ambiguity policy", async () => {
  await assert.rejects(requestControlPlane("/request", {
    mutate: true, ambiguousStatuses: new Set([409]),
    fetchImpl: async () => ({
      ...response(null, { status: 409 }), json: async () => { throw new SyntaxError("bad JSON"); },
    }),
    setTimer: () => 1, clearTimer: () => {},
  }), (error) => error.status === 409 && error.ambiguous && error.message === "409 Failure");
});

test("bounded transport wraps caller aborts and decode failures while clearing its timer", async () => {
  for (const mutate of [false, true]) {
    for (const decodeFailure of [false, true]) {
      const controller = new AbortController();
      let rejectFetch;
      let cleared = false;
      const failure = decodeFailure ? new SyntaxError("bad JSON") : Object.assign(new Error("caller cancelled"), { name: "AbortError" });
      const pending = requestControlPlane("/request", {
        mutate, createAbortController: () => controller,
        fetchImpl: (_path, { signal }) => decodeFailure
          ? Promise.resolve({ ...response(null), json: async () => { throw failure; } })
          : new Promise((_resolve, reject) => {
            rejectFetch = reject;
            signal.addEventListener("abort", () => rejectFetch(failure), { once: true });
          }),
        setTimer: () => 1, clearTimer: () => { cleared = true; },
      });
      if (!decodeFailure) controller.abort();
      await assert.rejects(pending, (error) => error instanceof ControlPlaneRequestError
        && error.status === 0 && error.ambiguous === mutate
        && error.message === `Control-plane request failed: ${failure.message}`);
      assert.equal(cleared, true);
    }
  }
});

test("bounded transport rejects invalid dependencies before dispatch", async () => {
  for (const options of [
    { fetchImpl: null }, { timeoutMs: 0 }, { timeoutMs: 300_001 },
    { timeoutMs: 1.5 }, { createAbortController: () => ({}) },
  ]) {
    await assert.rejects(requestControlPlane("/request", {
      fetchImpl: async () => assert.fail("invalid request was dispatched"), ...options,
    }), (error) => error instanceof TypeError || error instanceof RangeError);
  }
});

test("request timeout aborts and classifies a mutation as ambiguous", async () => {
  let timeoutCallback;
  let cleared = false;
  let aborted = false;
  const controller = {
    signal: { aborted: false },
    abort() {
      aborted = true;
      this.signal.aborted = true;
      rejectFetch(Object.assign(new Error("aborted"), { name: "AbortError" }));
    },
  };
  let rejectFetch;
  const pending = requestControlPlane("/write", {
    method: "POST",
    mutate: true,
    timeoutMs: 25,
    fetchImpl: () => new Promise((_resolve, reject) => { rejectFetch = reject; }),
    createAbortController: () => controller,
    setTimer: (callback) => { timeoutCallback = callback; return 7; },
    clearTimer: (value) => { assert.equal(value, 7); cleared = true; },
  });
  timeoutCallback();
  await assert.rejects(pending, (error) => {
    assert.ok(error instanceof ControlPlaneRequestError);
    assert.equal(error.status, 0);
    assert.equal(error.ambiguous, true);
    assert.match(error.message, /timed out/);
    return true;
  });
  assert.equal(aborted, true);
  assert.equal(cleared, true);
});

test("known validation responses are not ambiguous and keep the public detail", async () => {
  await assert.rejects(
    requestControlPlane("/write", {
      method: "POST",
      mutate: true,
      fetchImpl: async () => response({ detail: "invalid subject" }, { status: 422 }),
      setTimer: () => 1,
      clearTimer: () => {},
    }),
    (error) => {
      assert.equal(error.status, 422);
      assert.equal(error.ambiguous, false);
      assert.equal(error.message, "invalid subject");
      return true;
    },
  );
});

test("request forwards idempotency and strong version headers to fetch", async () => {
  let captured;
  const payload = await requestControlPlane("/write", {
    method: "PATCH",
    body: { title: "confirmed" },
    mutate: true,
    headers: {
      "Idempotency-Key": "marker-operation-1",
      "If-Match": '"7"',
    },
    fetchImpl: async (path, init) => {
      captured = { path, init };
      return response({ version: 8 });
    },
    setTimer: () => 11,
    clearTimer: (timer) => assert.equal(timer, 11),
  });
  assert.deepEqual(payload, { version: 8 });
  assert.equal(captured.path, "/write");
  assert.equal(captured.init.method, "PATCH");
  assert.deepEqual(captured.init.headers, {
    "Idempotency-Key": "marker-operation-1",
    "If-Match": '"7"',
  });
  assert.equal(captured.init.body, JSON.stringify({ title: "confirmed" }));
  assert.ok(captured.init.signal);
});

test("bounded pagination hydrates every page and rechecks connection freshness", async () => {
  const calls = [];
  let freshnessChecks = 0;
  const pages = new Map([
    [0, { items: [{ id: 1 }, { id: 2 }], next_offset: 2 }],
    [2, { items: [{ id: 3 }], next_offset: null }],
  ]);
  const items = await listControlPlaneCollection("/records", {
    origin: "http://127.0.0.1:8765",
    request: async (path) => {
      const offset = Number(new URL(path, "http://127.0.0.1:8765").searchParams.get("offset"));
      calls.push(offset);
      return pages.get(offset);
    },
    pageDecision: controlPlaneCollectionPageDecision,
    pageSize: 2,
    maximumRecords: 4,
    assertCurrent: () => { freshnessChecks += 1; },
  });
  assert.deepEqual(items.map((item) => item.id), [1, 2, 3]);
  assert.deepEqual(calls, [0, 2]);
  assert.ok(freshnessChecks >= 4);
});

test("bounded pagination owns limit and offset and validates caller parameters", async () => {
  const base = {
    origin: "http://127.0.0.1:8765",
    request: async () => ({ items: [], next_offset: null }),
    pageDecision: controlPlaneCollectionPageDecision,
  };
  await assert.rejects(
    listControlPlaneCollection("/records", {
      ...base,
      requestParameters: null,
    }),
    /request, pageDecision, requestParameters, and pageValidator must be callable/,
  );
  await assert.rejects(
    listControlPlaneCollection("/records", {
      ...base,
      requestParameters: () => null,
    }),
    /requestParameters must return an object/,
  );
  for (const reserved of [{ limit: "1" }, { offset: "0" }]) {
    await assert.rejects(
      listControlPlaneCollection("/records", {
        ...base,
        requestParameters: () => reserved,
      }),
      /cannot replace limit or offset/,
    );
  }
  await assert.rejects(
    listControlPlaneCollection("/records", {
      ...base,
      requestParameters: () => ({ filter: 1 }),
    }),
    /collection request parameters must be strings/,
  );
});

test("bounded pagination validates limits, offset progress, and the remaining page size", async () => {
  const base = {
    origin: "http://127.0.0.1:8765",
    request: async () => ({ items: [], next_offset: null }),
    pageDecision: controlPlaneCollectionPageDecision,
  };
  for (const invalidPageSize of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    await assert.rejects(
      listControlPlaneCollection("/records", {
        ...base,
        pageSize: invalidPageSize,
      }),
      /pageSize must be a positive safe integer/,
    );
  }
  await assert.rejects(
    listControlPlaneCollection("/records", {
      ...base,
      maximumRecords: 0,
    }),
    /maximumRecords must be a positive safe integer/,
  );
  await assert.rejects(
    listControlPlaneCollection("/records", {
      ...base,
      request: async () => ({ items: [{ id: 1 }], next_offset: 0 }),
    }),
    /next_offset does not advance/,
  );

  const calls = [];
  const items = await listControlPlaneCollection("/records", {
    origin: base.origin,
    pageSize: 2,
    maximumRecords: 3,
    request: async (path) => {
      const target = new URL(path, base.origin);
      const offset = Number(target.searchParams.get("offset"));
      const limit = Number(target.searchParams.get("limit"));
      calls.push({ offset, limit });
      if (offset === 0) return { items: [{ id: 1 }, { id: 2 }], next_offset: 2 };
      if (offset === 2) return { items: [{ id: 3 }], next_offset: 3 };
      return { items: [], next_offset: null };
    },
    pageDecision: controlPlaneCollectionPageDecision,
  });
  assert.deepEqual(items.map((item) => item.id), [1, 2, 3]);
  assert.deepEqual(calls, [
    { offset: 0, limit: 2 },
    { offset: 2, limit: 1 },
    { offset: 3, limit: 1 },
  ]);

  let safetyCapRequests = 0;
  await assert.rejects(
    listControlPlaneCollection("/records", {
      origin: base.origin,
      pageSize: 1,
      maximumRecords: 1,
      request: async () => {
        safetyCapRequests += 1;
        return safetyCapRequests === 1
          ? { items: [{ id: 1 }] }
          : { items: [] };
      },
      pageDecision: ({ payload }) => ({
        complete: payload.items.length === 0,
        capExceeded: false,
        nextOffset: 1,
      }),
    }),
    /exceeds the 1-record UI safety cap/,
  );
  assert.equal(
    safetyCapRequests,
    1,
    "a page policy cannot bypass the controller-owned safety cap",
  );
});

test("request replacement aborts the prior signal and preserves explicit cancellation", () => {
  const previous = new AbortController();
  const next = replaceAbortController(previous);
  assert.equal(previous.signal.aborted, true);
  assert.equal(next.signal.aborted, false);
  next.abort();
  assert.equal(next.signal.aborted, true);
});
