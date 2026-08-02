import assert from "node:assert/strict";
import test from "node:test";

import {
  ControlPlaneRequestError,
  DurableReviewJournalCapacityError,
  DurableReviewJournalError,
  StaleDurableReviewConnectionError,
  awaitCurrentDurableReview,
  beginReviewOperation,
  buildDurableAnnotationMarkerIndex,
  completePendingReviewMutation,
  decodePendingReviewMutations,
  discardPendingReviewMutationsForScope,
  durableConditionalRequestOptions,
  durableCreationRequestOptions,
  durableMutationPayloadIdentity,
  durableReadPostRequestOptions,
  durableReviewScopesEqual,
  durableReviewTokenMatches,
  encodePendingReviewMutations,
  finishReviewOperation,
  listAllDurableAnnotations,
  listControlPlaneCollection,
  loadThenCommitConfirmedState,
  loadDurableReviewConfig,
  loadPendingReviewMutations,
  reconcileControlPlaneVersionConflict,
  reconcilePendingReviewMutations,
  replaceConfirmedSet,
  reservePendingReviewMutation,
  requestControlPlane,
  requestDurableReview,
  resetPendingReviewMutationStorage,
  resetPendingReviewMutations,
  savePendingReviewMutations,
  saveDurableReviewConfig,
} from "../assets/durable_review_controller.js";
import { controlPlaneCollectionPageDecision } from "../assets/view_models.js";

const payloadIdentity = (digit) => `sha256:${String(digit).repeat(64)}`;

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

test("durable request builders enforce write identity and classification", () => {
  assert.deepEqual(
    durableCreationRequestOptions({
      idempotencyKey: "marker-operation-1",
      body: { annotation_id: "annotation-a" },
      reviewConfig: { tenantId: "tenant-a" },
    }),
    {
      method: "POST",
      mutate: true,
      headers: { "Idempotency-Key": "marker-operation-1" },
      body: { annotation_id: "annotation-a" },
      reviewConfig: { tenantId: "tenant-a" },
    },
  );
  assert.throws(
    () => durableCreationRequestOptions({ idempotencyKey: "", body: {} }),
    /idempotencyKey/,
  );
  assert.throws(
    () => durableCreationRequestOptions({ idempotencyKey: "bad\nkey", body: {} }),
    /idempotencyKey/,
  );

  assert.deepEqual(
    durableConditionalRequestOptions({ method: "patch", version: 7, body: {} }),
    {
      method: "PATCH",
      mutate: true,
      headers: { "If-Match": '"7"' },
      body: {},
    },
  );
  assert.deepEqual(
    durableConditionalRequestOptions({ method: "DELETE", version: "8" }),
    {
      method: "DELETE",
      mutate: true,
      headers: { "If-Match": '"8"' },
    },
  );
  assert.throws(
    () => durableConditionalRequestOptions({ method: "POST", version: 1 }),
    /PATCH or DELETE/,
  );

  assert.deepEqual(
    durableReadPostRequestOptions({ body: { scope: "revision" } }),
    {
      method: "POST",
      mutate: false,
      body: { scope: "revision" },
    },
  );
});

test("scoped durable adapter preserves write identity through retryable failure", async () => {
  let captured;
  const options = durableCreationRequestOptions({
    idempotencyKey: "marker-operation-7",
    body: { annotation_id: "annotation-7" },
  });
  await assert.rejects(
    requestDurableReview("/annotations", {
      ...options,
      config: {
        tenantId: "tenant-a",
        projectId: "project-a",
        workspaceId: "workspace-a",
        principalId: "reviewer-a",
      },
      fetchImpl: async (path, init) => {
        captured = { path, init };
        return response({ detail: "temporarily unavailable" }, { status: 503 });
      },
      setTimer: () => 17,
      clearTimer: (value) => assert.equal(value, 17),
    }),
    (error) => {
      assert.ok(error instanceof ControlPlaneRequestError);
      assert.equal(error.status, 503);
      assert.equal(error.ambiguous, true);
      return true;
    },
  );
  assert.equal(captured.path, "/annotations");
  assert.equal(captured.init.method, "POST");
  assert.equal(captured.init.headers["Idempotency-Key"], "marker-operation-7");
  assert.equal(captured.init.headers["X-Tenant-ID"], "tenant-a");
  assert.equal(captured.init.headers["X-Principal-ID"], "reviewer-a");
  assert.equal(captured.init.headers["Content-Type"], "application/json");
});

test("scoped durable adapter executes both conditional mutation forms", async () => {
  const calls = [];
  const config = {
    tenantId: "tenant-a",
    projectId: "project-a",
    workspaceId: "workspace-a",
    principalId: "reviewer-a",
  };
  const fetchImpl = async (path, init) => {
    calls.push({ path, init });
    return response(null, { status: 204 });
  };
  await requestDurableReview("/annotations/a", {
    ...durableConditionalRequestOptions({
      method: "PATCH",
      version: "9",
      body: { subjects: [] },
    }),
    config,
    fetchImpl,
    setTimer: () => 1,
    clearTimer: () => {},
  });
  await requestDurableReview("/annotations/a", {
    ...durableConditionalRequestOptions({ method: "DELETE", version: "10" }),
    config,
    fetchImpl,
    setTimer: () => 2,
    clearTimer: () => {},
  });
  assert.deepEqual(
    calls.map(({ init }) => [init.method, init.headers["If-Match"], init.body]),
    [
      ["PATCH", '"9"', JSON.stringify({ subjects: [] })],
      ["DELETE", '"10"', undefined],
    ],
  );
  await assert.rejects(
    requestDurableReview("/annotations", {
      config,
      method: "POST",
      body: {},
      fetchImpl,
    }),
    /declare mutate/,
  );
  await assert.rejects(
    requestDurableReview("/annotations", {
      config,
      method: "POST",
      mutate: true,
      body: {},
      fetchImpl,
    }),
    /Idempotency-Key/,
  );
});

test("409 reconciliation refreshes only a current durable scope", async () => {
  const conflict = new ControlPlaneRequestError("stale version", 409);
  let reloads = 0;
  assert.equal(
    await reconcileControlPlaneVersionConflict(conflict, {
      isCurrent: () => true,
      reload: async () => { reloads += 1; },
    }),
    true,
  );
  assert.equal(reloads, 1);

  assert.equal(
    await reconcileControlPlaneVersionConflict(conflict, {
      isCurrent: () => false,
      reload: async () => { reloads += 1; },
    }),
    false,
  );
  assert.equal(
    await reconcileControlPlaneVersionConflict(
      new ControlPlaneRequestError("invalid", 422),
      {
        isCurrent: () => true,
        reload: async () => { reloads += 1; },
      },
    ),
    false,
  );
  assert.equal(reloads, 1);
});

test("failed 409 reconciliation cannot replace the original conflict", async () => {
  const conflict = new ControlPlaneRequestError("stale version", 409);
  const mutate = async () => {
    try {
      throw conflict;
    } catch (error) {
      await reconcileControlPlaneVersionConflict(error, {
        isCurrent: () => true,
        reload: async () => { throw new Error("refresh failed"); },
      });
      throw error;
    }
  };
  await assert.rejects(mutate(), (error) => error === conflict);
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

test("annotation hydration consumes every page and refuses silent cap truncation", async () => {
  const calls = [];
  const pages = new Map([
    [0, [{ annotation_id: "annotation-1" }, { annotation_id: "annotation-2" }]],
    [2, [{ annotation_id: "annotation-3" }]],
  ]);
  const result = await listAllDurableAnnotations("/annotations", {
    origin: "http://127.0.0.1:8765",
    request: async (path) => {
      const offset = Number(
        new URL(path, "http://127.0.0.1:8765").searchParams.get("offset"),
      );
      calls.push(offset);
      return { items: pages.get(offset) || [], audit_watermark: "7" };
    },
    isCurrent: () => true,
    pageSize: 2,
    maximumRecords: 4,
  });
  assert.deepEqual(
    result.items.map((item) => item.annotation_id),
    ["annotation-1", "annotation-2", "annotation-3"],
  );
  assert.deepEqual(calls, [0, 2]);
  assert.equal(result.truncated, false);

  const overflowCalls = [];
  await assert.rejects(
    listAllDurableAnnotations("/annotations", {
      origin: "http://127.0.0.1:8765",
      request: async (path) => {
        const offset = Number(
          new URL(path, "http://127.0.0.1:8765").searchParams.get("offset"),
        );
        overflowCalls.push(offset);
        return {
          items: offset === 0 ? [{ id: 1 }, { id: 2 }] : [{ id: 3 }],
          audit_watermark: "8",
        };
      },
      isCurrent: () => true,
      pageSize: 2,
      maximumRecords: 2,
    }),
    /exceeds the 2-record UI safety cap/,
  );
  assert.deepEqual(overflowCalls, [0, 2], "the cap must be probed before failing");

  await assert.rejects(
    listAllDurableAnnotations("/annotations", {
      origin: "http://127.0.0.1:8765",
      request: async (path) => {
        const offset = Number(
          new URL(path, "http://127.0.0.1:8765").searchParams.get("offset"),
        );
        return {
          items: offset === 0 ? [{ id: 1 }, { id: 2 }] : [],
          audit_watermark: "9",
        };
      },
      isCurrent: () => true,
      pageSize: 1,
      maximumRecords: 4,
    }),
    (error) => (
      error instanceof ControlPlaneRequestError
      && error.status === 502
      && /page exceeds the requested limit/.test(error.message)
    ),
  );
});

test("annotation hydration binds every page to one watermark and restarts once", async () => {
  const calls = [];
  let attempt = 0;
  const result = await listAllDurableAnnotations("/annotations", {
    origin: "http://127.0.0.1:8765",
    request: async (path) => {
      const target = new URL(path, "http://127.0.0.1:8765");
      const offset = Number(target.searchParams.get("offset"));
      const expected = target.searchParams.get("expected_audit_watermark");
      if (offset === 0) attempt += 1;
      calls.push({ attempt, offset, expected });
      if (attempt === 1 && offset === 2) {
        throw new ControlPlaneRequestError("watermark changed", 409);
      }
      return {
        items: offset === 0
          ? [{ annotation_id: `annotation-${attempt}-a` }, { annotation_id: `annotation-${attempt}-b` }]
          : [{ annotation_id: `annotation-${attempt}-c` }],
        audit_watermark: attempt === 1 ? "10" : "11",
      };
    },
    isCurrent: () => true,
    pageSize: 2,
    maximumRecords: 8,
  });
  assert.deepEqual(
    result.items.map((item) => item.annotation_id),
    ["annotation-2-a", "annotation-2-b", "annotation-2-c"],
  );
  assert.equal(result.auditWatermark, "11");
  assert.deepEqual(calls, [
    { attempt: 1, offset: 0, expected: null },
    { attempt: 1, offset: 2, expected: "10" },
    { attempt: 2, offset: 0, expected: null },
    { attempt: 2, offset: 2, expected: "11" },
  ]);
});

test("annotation hydration rejects noncanonical audit watermarks", async () => {
  for (const auditWatermark of (
    [1, "", "01", "+1", "-1", "1.0", "9223372036854775808"]
  )) {
    await assert.rejects(
      listAllDurableAnnotations("/annotations", {
        origin: "http://127.0.0.1:8765",
        request: async () => ({ items: [], audit_watermark: auditWatermark }),
        isCurrent: () => true,
      }),
      (error) => (
        error instanceof ControlPlaneRequestError
        && error.status === 502
        && /canonical audit_watermark string/.test(error.message)
      ),
      `watermark ${JSON.stringify(auditWatermark)} must fail closed`,
    );
  }
});

test("annotation hydration detects client-side watermark drift and retries only once", async () => {
  let firstPageCount = 0;
  const calls = [];
  await assert.rejects(
    listAllDurableAnnotations("/annotations", {
      origin: "http://127.0.0.1:8765",
      pageSize: 1,
      maximumRecords: 4,
      request: async (path) => {
        const target = new URL(path, "http://127.0.0.1:8765");
        const offset = Number(target.searchParams.get("offset"));
        const expected = target.searchParams.get("expected_audit_watermark");
        if (offset === 0) firstPageCount += 1;
        calls.push({ attempt: firstPageCount, offset, expected });
        return {
          items: offset === 0 ? [{ id: `attempt-${firstPageCount}` }] : [],
          audit_watermark: offset === 0 ? String(firstPageCount) : "99",
        };
      },
      isCurrent: () => true,
    }),
    (error) => error instanceof ControlPlaneRequestError && error.status === 409,
  );
  assert.equal(firstPageCount, 2);
  assert.deepEqual(calls, [
    { attempt: 1, offset: 0, expected: null },
    { attempt: 1, offset: 1, expected: "1" },
    { attempt: 2, offset: 0, expected: null },
    { attempt: 2, offset: 1, expected: "2" },
  ]);
});

test("repeated annotation watermark drift fails without replacing confirmed state", async () => {
  const confirmed = new Set(["annotation-old"]);
  let attempt = 0;
  await assert.rejects(
    listAllDurableAnnotations("/annotations", {
      origin: "http://127.0.0.1:8765",
      request: async (path) => {
        const target = new URL(path, "http://127.0.0.1:8765");
        const offset = Number(target.searchParams.get("offset"));
        if (offset === 0) {
          attempt += 1;
          return { items: [{ id: 1 }, { id: 2 }], audit_watermark: String(attempt) };
        }
        throw new ControlPlaneRequestError("watermark changed", 409);
      },
      isCurrent: () => true,
      pageSize: 2,
      maximumRecords: 8,
    }),
    (error) => error instanceof ControlPlaneRequestError && error.status === 409,
  );
  assert.deepEqual([...confirmed], ["annotation-old"]);
  assert.equal(attempt, 2);
});

test("annotation marker index validates the complete replacement before commit", async () => {
  const confirmed = new Set(["event:old"]);
  const valid = {
    annotation_id: "annotation-a",
    kind: "marker",
    version: 1,
    subjects: [
      { revision_id: "revision-a", kind: "event", subject_id: "event-a" },
    ],
  };
  const projection = buildDurableAnnotationMarkerIndex(
    [valid],
    "revision-a",
    (subject) => `${subject.kind}:${subject.subject_id}`,
  );
  assert.deepEqual([...projection.annotations.keys()], ["annotation-a"]);
  assert.deepEqual([...projection.markedEntryIds], ["event:event-a"]);

  await assert.rejects(
    loadThenCommitConfirmedState(
      async () => [
        valid,
        {
          annotation_id: "annotation-b",
          kind: "marker",
          version: 1,
          subjects: { revision_id: "revision-a" },
        },
      ],
      (annotations) => {
        const replacement = buildDurableAnnotationMarkerIndex(
          annotations,
          "revision-a",
          (subject) => `${subject.kind}:${subject.subject_id}`,
        );
        replaceConfirmedSet(confirmed, replacement.markedEntryIds);
      },
    ),
    /bounded subjects array/,
  );
  assert.deepEqual([...confirmed], ["event:old"]);
  assert.throws(
    () => buildDurableAnnotationMarkerIndex(
      [
        { ...valid, kind: "note" },
        valid,
      ],
      "revision-a",
      () => "event:event-a",
    ),
    /duplicate annotation_id/,
  );
});

test("awaited durable work rechecks the immutable connection token afterwards", async () => {
  let current = true;
  let resolveOperation;
  const pending = awaitCurrentDurableReview(
    () => new Promise((resolve) => { resolveOperation = resolve; }),
    () => current,
  );
  current = false;
  resolveOperation({ annotation_id: "stale-result" });
  await assert.rejects(
    pending,
    (error) => error instanceof StaleDurableReviewConnectionError,
  );

  let invoked = false;
  await assert.rejects(
    awaitCurrentDurableReview(
      async () => { invoked = true; },
      () => false,
    ),
    (error) => error instanceof StaleDurableReviewConnectionError,
  );
  assert.equal(invoked, false);
});

test("stale connection tokens fail closed", () => {
  const token = {
    sequence: 4,
    tenantId: "tenant-a",
    projectId: "project-a",
    workspaceId: "workspace-a",
    principalId: "reviewer-a",
    catalogRevisionId: "revision-a",
  };
  const current = {
    sequence: 4,
    config: {
      tenantId: "tenant-a",
      projectId: "project-a",
      workspaceId: "workspace-a",
      principalId: "reviewer-a",
    },
    catalogRevisionId: "revision-a",
    status: "ready",
  };
  assert.equal(durableReviewTokenMatches(token, current), true);
  assert.equal(durableReviewTokenMatches(token, { ...current, sequence: 5 }), false);
  assert.equal(durableReviewTokenMatches(token, { ...current, status: "error" }), false);
  assert.equal(
    durableReviewTokenMatches(token, { ...current, status: "error" }, { requireReady: false }),
    true,
  );
});

test("same-scope refresh comparison ignores generation but not durable identity", () => {
  const confirmedScope = {
    sequence: 4,
    tenantId: "tenant-a",
    projectId: "project-a",
    workspaceId: "workspace-a",
    principalId: "reviewer-a",
    catalogRevisionId: "revision-a",
  };
  assert.equal(
    durableReviewScopesEqual(confirmedScope, { ...confirmedScope, sequence: 99 }),
    true,
  );
  for (const [field, value] of [
    ["tenantId", "tenant-b"],
    ["projectId", "project-b"],
    ["workspaceId", "workspace-b"],
    ["principalId", "reviewer-b"],
    ["catalogRevisionId", "revision-b"],
  ]) {
    assert.equal(
      durableReviewScopesEqual(confirmedScope, { ...confirmedScope, [field]: value }),
      false,
      `${field} must define a different durable scope`,
    );
  }
  assert.equal(durableReviewScopesEqual(confirmedScope, null), false);
});

test("operation locks release only for their owner and exclude conflicts", () => {
  const operations = new Map();
  const owner = beginReviewOperation(operations, "report", ["report", "marker"], () => "owner-a");
  assert.equal(owner, "owner-a");
  assert.equal(beginReviewOperation(operations, "marker", ["report", "marker"]), null);
  assert.equal(finishReviewOperation(operations, "report", "owner-b"), false);
  assert.equal(operations.get("report"), "owner-a");
  assert.equal(finishReviewOperation(operations, "report", "owner-a"), true);
  assert.equal(operations.size, 0);
});

test("ambiguous pending writes reconcile by durable object identity", () => {
  const scope = "tenant\u001fproject\u001fworkspace\u001fprincipal\u001frevision";
  const pending = new Map([
    [`${scope}\u001etimeline-marker\u001epayload`, {
      kind: "timeline-marker",
      recordId: "annotation-a",
    }],
    [`${scope}\u001emanual-correlation\u001epayload`, {
      kind: "manual-correlation",
      recordId: "correlation-a",
    }],
    ["other\u001etimeline-marker\u001epayload", {
      kind: "timeline-marker",
      recordId: "annotation-a",
    }],
  ]);
  const count = reconcilePendingReviewMutations(pending, scope, {
    annotationIds: new Set(["annotation-a"]),
    correlationIds: new Set(["correlation-a"]),
  });
  assert.equal(count, 2);
  assert.deepEqual([...pending.keys()], ["other\u001etimeline-marker\u001epayload"]);
});

test("durable mutation journal distinguishes writes and reuses unresolved identity", () => {
  const token = {
    tenantId: "tenant-a",
    projectId: "project-a",
    workspaceId: "workspace-a",
    principalId: "reviewer-a",
    catalogRevisionId: "revision-a",
  };
  const pending = new Map();
  let sequence = 0;
  const createId = (prefix) => `${prefix}-${++sequence}`;
  const first = reservePendingReviewMutation(
    pending,
    token,
    "timeline-marker",
    payloadIdentity("a"),
    "annotation",
    { createId },
  );
  const retry = reservePendingReviewMutation(
    pending,
    token,
    "timeline-marker",
    payloadIdentity("a"),
    "annotation",
    { createId },
  );
  const distinct = reservePendingReviewMutation(
    pending,
    token,
    "timeline-marker",
    payloadIdentity("b"),
    "annotation",
    { createId },
  );

  assert.equal(retry, first, "an unresolved retry must reuse operation identity");
  assert.notEqual(distinct.key, first.key, "distinct writes must not share a key");
  assert.notEqual(distinct.idempotencyKey, first.idempotencyKey);
  assert.notEqual(distinct.recordId, first.recordId);
  assert.equal(sequence, 4, "ids are allocated only for new journal entries");
  assert.equal(pending.size, 2);

  assert.equal(completePendingReviewMutation(pending, { ...first }), false);
  assert.equal(completePendingReviewMutation(pending, first), true);
  assert.equal(completePendingReviewMutation(pending, first), false);
  assert.deepEqual([...pending.values()], [distinct]);

  const reconciled = reconcilePendingReviewMutations(
    pending,
    distinct.scopeKey,
    { annotationIds: new Set([distinct.recordId]) },
  );
  assert.equal(reconciled, 1);
  assert.equal(pending.size, 0);
});

test("durable mutation journal rejects a duplicate-producing identity source", () => {
  const token = {
    tenantId: "tenant-a",
    projectId: "project-a",
    workspaceId: "workspace-a",
    principalId: "reviewer-a",
    catalogRevisionId: "revision-a",
  };
  const constantJournal = new Map();
  assert.throws(
    () => reservePendingReviewMutation(
      constantJournal,
      token,
      "timeline-marker",
      payloadIdentity("a"),
      "annotation",
      { createId: () => "constant-identity" },
    ),
    /must produce unique values/,
  );
  assert.equal(constantJournal.size, 0);

  const existingJournal = new Map();
  const identities = [
    "idempotency-a",
    "annotation-a",
    "idempotency-a",
    "annotation-b",
  ];
  const createId = () => identities.shift();
  reservePendingReviewMutation(
    existingJournal,
    token,
    "timeline-marker",
    payloadIdentity("a"),
    "annotation",
    { createId },
  );
  assert.throws(
    () => reservePendingReviewMutation(
      existingJournal,
      token,
      "timeline-marker",
      payloadIdentity("b"),
      "annotation",
      { createId },
    ),
    /must produce unique values/,
  );
  assert.equal(existingJournal.size, 1);
});

test("journal identities are unique across UI scopes sharing one server ReviewScope", () => {
  const base = {
    tenantId: "tenant-a",
    projectId: "project-a",
    workspaceId: "workspace-a",
    catalogRevisionId: "revision-a",
  };
  const pending = new Map();
  let firstIds = ["shared-idempotency", "shared-record"];
  reservePendingReviewMutation(
    pending,
    { ...base, principalId: "reviewer-a" },
    "timeline-marker",
    payloadIdentity("a"),
    "annotation",
    { createId: () => firstIds.shift() },
  );
  let secondIds = ["shared-idempotency", "other-record"];
  assert.throws(
    () => reservePendingReviewMutation(
      pending,
      {
        ...base,
        principalId: "reviewer-b",
        catalogRevisionId: "revision-b",
      },
      "timeline-marker",
      payloadIdentity("b"),
      "annotation",
      { createId: () => secondIds.shift() },
    ),
    /must produce unique values/,
  );
  assert.equal(pending.size, 1);

  const firstDocument = JSON.parse(encodePendingReviewMutations(pending));
  const duplicate = structuredClone(firstDocument.entries[0]);
  duplicate.scope.principalId = "reviewer-b";
  duplicate.scope.catalogRevisionId = "revision-b";
  duplicate.payload_identity = payloadIdentity("b");
  const tampered = JSON.stringify({
    schema_version: 1,
    entries: [firstDocument.entries[0], duplicate],
  });
  assert.throws(
    () => decodePendingReviewMutations(tampered),
    /server-scoped operation identity/,
  );
});

test("durable payload identity is bounded and hashes the exact JSON document", async () => {
  let captured;
  const identity = await durableMutationPayloadIdentity(
    { event: "event-a", ordinal: 7 },
    {
      digestImpl: async (bytes) => {
        captured = new TextDecoder().decode(bytes);
        return new Uint8Array(32).fill(0xab);
      },
    },
  );
  assert.equal(captured, JSON.stringify({ event: "event-a", ordinal: 7 }));
  assert.equal(identity, `sha256:${"ab".repeat(32)}`);
  await assert.rejects(
    durableMutationPayloadIdentity({ body: "oversized" }, { maximumBytes: 2 }),
    /identity limit/,
  );
});

test("unresolved mutation identity survives storage reload and exact retry", () => {
  const token = {
    tenantId: "tenant-a",
    projectId: "project-a",
    workspaceId: "workspace-a",
    principalId: "reviewer-a",
    catalogRevisionId: "revision-a",
  };
  const values = new Map();
  const storage = {
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value),
    removeItem: (key) => values.delete(key),
  };
  let sequence = 0;
  const original = new Map();
  const first = reservePendingReviewMutation(
    original,
    token,
    "timeline-marker",
    payloadIdentity("a"),
    "annotation",
    { createId: (prefix) => `${prefix}-${++sequence}` },
  );
  savePendingReviewMutations(storage, "journal", original);

  const reloaded = loadPendingReviewMutations(storage, "journal");
  const retry = reservePendingReviewMutation(
    reloaded,
    token,
    "timeline-marker",
    payloadIdentity("a"),
    "annotation",
    { createId: () => { throw new Error("retry allocated a new identity"); } },
  );
  assert.equal(retry.idempotencyKey, first.idempotencyKey);
  assert.equal(retry.recordId, first.recordId);
  assert.equal(retry.payloadIdentity, first.payloadIdentity);
});

test("persisted mutation journal rejects tampering instead of partially loading", () => {
  const token = {
    tenantId: "tenant-a",
    projectId: "project-a",
    workspaceId: "workspace-a",
    principalId: "reviewer-a",
    catalogRevisionId: "revision-a",
  };
  const pending = new Map();
  let sequence = 0;
  reservePendingReviewMutation(
    pending,
    token,
    "timeline-marker",
    payloadIdentity("a"),
    "annotation",
    { createId: (prefix) => `${prefix}-${++sequence}` },
  );
  const encoded = JSON.parse(
    (() => {
      const values = new Map();
      savePendingReviewMutations({ setItem: (key, value) => values.set(key, value) }, "j", pending);
      return values.get("j");
    })(),
  );
  encoded.entries[0].record_id = encoded.entries[0].idempotency_key;
  assert.throws(
    () => decodePendingReviewMutations(JSON.stringify(encoded)),
    (error) => error instanceof DurableReviewJournalError,
  );
  encoded.entries[0].record_id = "annotation-restored";
  encoded.entries[0].unexpected = true;
  assert.throws(
    () => decodePendingReviewMutations(JSON.stringify(encoded)),
    (error) => error instanceof DurableReviewJournalError,
  );
});

test("mutation journal capacity is per scope and current scope can be discarded", () => {
  const tokenA = {
    tenantId: "tenant-a",
    projectId: "project-a",
    workspaceId: "workspace-a",
    principalId: "reviewer-a",
    catalogRevisionId: "revision-a",
  };
  const tokenB = { ...tokenA, workspaceId: "workspace-b" };
  const pending = new Map();
  let sequence = 0;
  const options = {
    maximumEntries: 1,
    maximumTotalEntries: 4,
    createId: (prefix) => `${prefix}-${++sequence}`,
  };
  reservePendingReviewMutation(
    pending,
    tokenA,
    "timeline-marker",
    payloadIdentity("a"),
    "annotation",
    options,
  );
  assert.throws(
    () => reservePendingReviewMutation(
      pending,
      tokenA,
      "timeline-marker",
      payloadIdentity("b"),
      "annotation",
      options,
    ),
    /in this scope/,
  );
  reservePendingReviewMutation(
    pending,
    tokenB,
    "timeline-marker",
    payloadIdentity("b"),
    "annotation",
    options,
  );
  assert.equal(pending.size, 2);
  assert.equal(discardPendingReviewMutationsForScope(pending, tokenA), 1);
  assert.equal(pending.size, 1);
  assert.equal([...pending.values()][0].scope.workspaceId, "workspace-b");
});

test("global journal capacity exposes all-scope recovery and reset permits new writes", () => {
  const tokenA = {
    tenantId: "tenant-a",
    projectId: "project-a",
    workspaceId: "workspace-a",
    principalId: "reviewer-a",
    catalogRevisionId: "revision-a",
  };
  const tokenB = { ...tokenA, workspaceId: "workspace-b" };
  const tokenC = { ...tokenA, workspaceId: "workspace-c" };
  const pending = new Map();
  let sequence = 0;
  const options = {
    maximumEntries: 2,
    maximumTotalEntries: 2,
    createId: (prefix) => `${prefix}-${++sequence}`,
  };
  reservePendingReviewMutation(
    pending,
    tokenA,
    "timeline-marker",
    payloadIdentity("a"),
    "annotation",
    options,
  );
  reservePendingReviewMutation(
    pending,
    tokenB,
    "timeline-marker",
    payloadIdentity("b"),
    "annotation",
    options,
  );
  assert.throws(
    () => reservePendingReviewMutation(
      pending,
      tokenC,
      "timeline-marker",
      payloadIdentity("c"),
      "annotation",
      options,
    ),
    (error) => error instanceof DurableReviewJournalCapacityError
      && error.capacity === "global",
  );
  const values = new Map([["journal", "persisted"]]);
  const storage = { removeItem: (key) => values.delete(key) };
  assert.equal(resetPendingReviewMutations(storage, "journal", pending), 2);
  assert.equal(values.has("journal"), false);
  assert.equal(pending.size, 0);
  reservePendingReviewMutation(
    pending,
    tokenC,
    "timeline-marker",
    payloadIdentity("c"),
    "annotation",
    options,
  );
  assert.equal(pending.size, 1);
});

test("explicit journal reset removes persisted unresolved identities", () => {
  const values = new Map([["journal", "opaque"]]);
  const storage = {
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value),
    removeItem: (key) => values.delete(key),
  };
  assert.equal(resetPendingReviewMutationStorage(storage, "journal"), true);
  assert.equal(values.has("journal"), false);
  assert.throws(
    () => loadPendingReviewMutations({}, "journal"),
    (error) => error instanceof DurableReviewJournalError,
  );
});

test("confirmed marker orchestration preserves old state when bounded hydration fails", async () => {
  const confirmed = new Set(["event:a", "event:b"]);
  let committed = false;
  await assert.rejects(
    loadThenCommitConfirmedState(
      async () => {
        throw new ControlPlaneRequestError("watermark changed twice", 409);
      },
      (values) => {
        committed = true;
        replaceConfirmedSet(confirmed, values);
      },
    ),
    (error) => error instanceof ControlPlaneRequestError && error.status === 409,
  );
  assert.equal(committed, false);
  assert.deepEqual([...confirmed], ["event:a", "event:b"]);

  await loadThenCommitConfirmedState(
    async () => ["event:b", "event:c"],
    (values) => replaceConfirmedSet(confirmed, values),
  );
  assert.deepEqual([...confirmed], ["event:b", "event:c"]);
});

test("blocked storage does not disable the in-memory review scope", () => {
  const blocked = {
    getItem() { throw new Error("blocked"); },
    setItem() { throw new Error("blocked"); },
  };
  assert.equal(loadDurableReviewConfig(blocked, "scope"), null);
  assert.equal(saveDurableReviewConfig(blocked, "scope", { tenantId: "t" }), false);

  const values = new Map();
  const storage = {
    getItem(key) { return values.get(key) ?? null; },
    setItem(key, value) { values.set(key, value); },
  };
  const config = {
    tenantId: "tenant",
    projectId: "project",
    workspaceId: "workspace",
    principalId: "reviewer",
  };
  assert.equal(saveDurableReviewConfig(storage, "scope", config), true);
  assert.deepEqual(loadDurableReviewConfig(storage, "scope"), config);
});
