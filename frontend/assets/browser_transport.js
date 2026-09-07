// Core browser transport. Callers own scope, mutation policy, and stale-result checks.
// The small JSON API and bounded control-plane API retain their distinct error contracts.

const DEFAULT_AMBIGUOUS_STATUSES = Object.freeze(
  new Set([408, 425, 429, 500, 502, 503, 504]),
);

export async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  if (!response.ok) {
    let message = `${response.status} ${response.statusText}`;
    try {
      const body = await response.json();
      message = body.detail || body.error?.message || message;
    } catch (_error) {
      // Keep the HTTP status when the body is not JSON.
    }
    throw new Error(message);
  }
  return response.json();
}

export function replaceAbortController(previous, createController = () => new AbortController()) {
  previous?.abort();
  return createController();
}

export class ControlPlaneRequestError extends Error {
  constructor(message, status = 0, { ambiguous = false } = {}) {
    super(message);
    this.name = "ControlPlaneRequestError";
    this.status = status;
    this.ambiguous = ambiguous;
  }
}

function boundedErrorMessage(error, fallback) {
  const value = String(error?.message || fallback)
    .replace(/[\u0000-\u001f\u007f]+/g, " ")
    .trim();
  return (value || fallback).slice(0, 2048);
}

export async function requestControlPlane(path, {
  method = "GET",
  body = null,
  mutate = false,
  responseType = "json",
  headers = {},
  timeoutMs = 30_000,
  fetchImpl = globalThis.fetch,
  createAbortController = () => new AbortController(),
  setTimer = globalThis.setTimeout,
  clearTimer = globalThis.clearTimeout,
  ambiguousStatuses = DEFAULT_AMBIGUOUS_STATUSES,
} = {}) {
  if (typeof fetchImpl !== "function") {
    throw new TypeError("fetchImpl must be callable");
  }
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 300_000) {
    throw new RangeError("timeoutMs must be between 1 and 300000");
  }
  const controller = createAbortController();
  if (!controller?.signal || typeof controller.abort !== "function") {
    throw new TypeError("createAbortController must return an AbortController-like value");
  }
  let timedOut = false;
  const timeout = setTimer(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);
  try {
    const response = await fetchImpl(path, {
      method,
      headers,
      signal: controller.signal,
      ...(body === null ? {} : { body: JSON.stringify(body) }),
    });
    if (!response?.ok) {
      const status = Number(response?.status || 0);
      let message = `${status || "Request"} ${response?.statusText || "failed"}`.trim();
      try {
        const contentType = response?.headers?.get?.("content-type") || "";
        if (contentType.includes("json")) {
          const payload = await response.json();
          message = String(payload?.detail || payload?.error?.message || message);
        } else if (typeof response?.text === "function") {
          message = String(await response.text() || message);
        }
      } catch (_error) {
        // Keep the bounded status line when the response body is malformed.
      }
      throw new ControlPlaneRequestError(
        boundedErrorMessage({ message }, "Control-plane request failed."),
        status,
        { ambiguous: mutate && ambiguousStatuses.has(status) },
      );
    }
    if (responseType === "text") return await response.text();
    if (responseType === "response") return response;
    if (response.status === 204) return null;
    return await response.json();
  } catch (error) {
    if (error instanceof ControlPlaneRequestError) throw error;
    throw new ControlPlaneRequestError(
      timedOut
        ? `Control-plane request timed out after ${Math.round(timeoutMs / 1000)} seconds.`
        : `Control-plane request failed: ${boundedErrorMessage(error, "unknown transport error")}`,
      0,
      { ambiguous: mutate },
    );
  } finally {
    clearTimer(timeout);
  }
}

export async function listControlPlaneCollection(path, {
  request,
  origin,
  pageDecision,
  requestParameters = () => ({}),
  pageValidator = () => {},
  pageSize = 5_000,
  maximumRecords = 20_000,
  assertCurrent = () => {},
  label = "control-plane collection",
} = {}) {
  if (
    typeof request !== "function"
    || typeof pageDecision !== "function"
    || typeof requestParameters !== "function"
    || typeof pageValidator !== "function"
  ) {
    throw new TypeError(
      "request, pageDecision, requestParameters, and pageValidator must be callable",
    );
  }
  if (!Number.isSafeInteger(pageSize) || pageSize < 1) {
    throw new RangeError("pageSize must be a positive safe integer");
  }
  if (!Number.isSafeInteger(maximumRecords) || maximumRecords < 1) {
    throw new RangeError("maximumRecords must be a positive safe integer");
  }
  const items = [];
  let offset = 0;
  const requestPage = async (pageOffset, limit, { probe = false } = {}) => {
    const target = new URL(path, origin);
    const parameters = requestParameters({
      offset: pageOffset,
      requestedLimit: limit,
      probe,
    });
    if (!parameters || typeof parameters !== "object" || Array.isArray(parameters)) {
      throw new TypeError("requestParameters must return an object");
    }
    for (const [name, value] of Object.entries(parameters)) {
      if (name === "limit" || name === "offset") {
        throw new TypeError("requestParameters cannot replace limit or offset");
      }
      if (typeof value !== "string") {
        throw new TypeError("collection request parameters must be strings");
      }
      target.searchParams.set(name, value);
    }
    target.searchParams.set("limit", String(limit));
    target.searchParams.set("offset", String(pageOffset));
    const payload = await request(`${target.pathname}${target.search}`);
    assertCurrent();
    try {
      pageValidator(payload, {
        offset: pageOffset,
        requestedLimit: limit,
        probe,
      });
    } catch (error) {
      if (error instanceof ControlPlaneRequestError) throw error;
      throw new ControlPlaneRequestError(
        `${label} returned an invalid paginated response: ${boundedErrorMessage(error, "invalid page")}`,
        502,
      );
    }
    return payload;
  };
  while (true) {
    assertCurrent();
    const requestedLimit = Math.min(pageSize, maximumRecords - items.length);
    if (requestedLimit <= 0) {
      throw new ControlPlaneRequestError(
        `${label} exceeds the ${maximumRecords.toLocaleString()}-record UI safety cap.`,
        422,
      );
    }
    const payload = await requestPage(offset, requestedLimit);
    let decision;
    try {
      decision = pageDecision({
        payload,
        offset,
        requestedLimit,
        accumulatedCount: items.length,
        maximumCount: maximumRecords,
      });
    } catch (error) {
      if (error instanceof ControlPlaneRequestError) throw error;
      throw new ControlPlaneRequestError(
        `${label} returned an invalid paginated response: ${boundedErrorMessage(error, "invalid page")}`,
        502,
      );
    }
    items.push(...payload.items);
    if (decision.complete) return items;
    if (decision.capExceeded) {
      const probe = await requestPage(decision.nextOffset, 1, { probe: true });
      if (!probe || typeof probe !== "object" || !Array.isArray(probe.items)) {
        throw new ControlPlaneRequestError(
          `${label} returned an invalid pagination probe.`,
          502,
        );
      }
      if (probe.items.length === 0) return items;
      throw new ControlPlaneRequestError(
        `${label} exceeds the ${maximumRecords.toLocaleString()}-record UI safety cap.`,
        422,
      );
    }
    offset = decision.nextOffset;
  }
}
