import { timelineDensityBinBounds } from "./timeline_viewport.js";

// Stable levels let nearby zoom gestures share an exact immutable partition.
export function densityResolution(zoom, startNs, endNs) {
  const slots = endNs - startNs + 1n;
  const useful = Number(slots > BigInt(Number.MAX_SAFE_INTEGER) ? BigInt(Number.MAX_SAFE_INTEGER) : slots);
  const level = Math.max(0, Math.round(Math.log2(Math.max(1, zoom))));
  return Math.max(1, Math.min(useful, 180 * 2 ** level));
}

export function densityPageQuery({ context, url, startNs, endNs, binCount, windowStartNs, windowEndNs, globalStart, globalEnd }) {
  // Align pages so small pans reuse the same response. Keep pages within the
  // core's 4096-bin limit even if a caller supplies a wider render window.
  const start = Math.floor(globalStart / 256) * 256;
  const end = Math.min(binCount, Math.ceil(globalEnd / 256) * 256, start + 4096);
  const identity = JSON.stringify([context, url, String(startNs), String(endNs)]);
  return { context, url, identity, startNs, endNs, binCount, windowStartNs, windowEndNs,
    globalStart: start, globalEnd: end,
    key: JSON.stringify([identity, binCount, start, end]) };
}

export function normalizeDensityPage(payload, query) {
  const bins = (payload?.bins || []).map((raw) => {
    const index = Number(raw.index);
    if (!Number.isSafeInteger(index) || index < query.globalStart || index >= query.globalEnd) return null;
    const bounds = timelineDensityBinBounds({ index, startNs: query.startNs, endNs: query.endNs, binCount: query.binCount });
    return { index, ...bounds, count: Number(raw.count || 0), failures: Number(raw.failure_count ?? raw.failures ?? 0),
      topTypes: new Map((raw.top_types || []).map((item) => [String(item.event_type || item.type || "event"), Number(item.count || 0)])) };
  }).filter((bin) => bin && bin.count > 0);
  const first = timelineDensityBinBounds({ index: query.globalStart, startNs: query.startNs, endNs: query.endNs, binCount: query.binCount });
  const last = timelineDensityBinBounds({ index: query.globalEnd - 1, startNs: query.startNs, endNs: query.endNs, binCount: query.binCount });
  return { ...query, coverageStartNs: first.startNs, coverageEndNs: last.endNs, bins, totalCount: Number(payload?.total_count || 0) };
}

export function createDensityViewportController({ fetchPage, onChange = () => {}, schedule = setTimeout, cancel = clearTimeout, createAbortController = () => new AbortController(), delayMs = 40, cacheLimit = 12 }) {
  const pages = new Map();
  let identity = null;
  let desired = null;
  let generation = 0;
  let timer = null;
  let controller = null;
  let pendingKey = null;
  let errorKey = null;
  let gesture = false;

  function cancelPending() {
    generation += 1;
    if (timer !== null) cancel(timer);
    timer = null;
    controller?.abort();
    controller = null;
    pendingKey = null;
  }
  function reset() {
    cancelPending();
    pages.clear();
    identity = null;
    desired = null;
    errorKey = null;
    gesture = false;
  }
  function select(query) {
    if (identity !== query.identity) {
      const activeGesture = gesture;
      reset();
      gesture = activeGesture;
      identity = query.identity;
    }
    if (desired?.key !== query.key) {
      cancelPending();
      desired = query;
      errorKey = null;
    } else {
      // The aligned page stays the same while its visible time window moves.
      desired = query;
    }
  }
  function exactPage(query) {
    for (const [key, page] of pages) {
      if (page.identity !== query.identity || page.binCount !== query.binCount || page.globalStart > query.globalStart || page.globalEnd < query.globalEnd) continue;
      pages.delete(key);
      pages.set(key, page);
      return page;
    }
    return null;
  }
  function previewPage(query) {
    let best = null;
    let distance = Infinity;
    for (const page of pages.values()) {
      if (page.identity !== query.identity || page.coverageEndNs < query.windowStartNs || page.coverageStartNs > query.windowEndNs) continue;
      const difference = Math.abs(Math.log2(page.binCount / query.binCount));
      if (difference <= distance) { best = page; distance = difference; }
    }
    return best;
  }
  function request(query) {
    if (gesture || exactPage(query) || pendingKey === query.key || errorKey === query.key) return;
    pendingKey = query.key;
    const ticket = generation;
    timer = schedule(async () => {
      timer = null;
      const active = createAbortController();
      controller = active;
      try {
        const payload = await fetchPage(query, active.signal);
        if (active.signal.aborted || ticket !== generation || desired?.key !== query.key || identity !== query.identity) return;
        const page = normalizeDensityPage(payload, query);
        pages.delete(page.key);
        pages.set(page.key, page);
        while (pages.size > cacheLimit) pages.delete(pages.keys().next().value);
        pendingKey = null;
        errorKey = null;
        onChange();
      } catch (error) {
        if (active.signal.aborted || ticket !== generation || desired?.key !== query.key) return;
        pendingKey = null;
        errorKey = query.key;
        onChange();
      } finally {
        if (controller === active) controller = null;
      }
    }, delayMs);
  }
  function view(query) {
    select(query);
    const exact = exactPage(query);
    const page = exact || previewPage(query);
    request(query);
    return { page, exact: Boolean(exact), pending: pendingKey === query.key,
      failed: errorKey === query.key, gesture,
      coverageComplete: Boolean(page && page.coverageStartNs <= query.windowStartNs && page.coverageEndNs >= query.windowEndNs) };
  }
  function setGesture(active) {
    gesture = Boolean(active);
    if (gesture) cancelPending();
    else if (desired) request(desired);
  }
  return { view, setGesture, reset };
}
