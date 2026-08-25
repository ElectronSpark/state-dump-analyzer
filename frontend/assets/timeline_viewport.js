// Pure timeline viewport geometry.
//
// These helpers calculate exact virtual time windows without reading or
// mutating DOM state, so browser wiring and node:test share one definition of
// pointer anchoring, fitting, and range zoom without a huge physical surface.

const MINIMUM_ZOOM = 1;
const DEFAULT_ZOOM_FACTOR = 1.5;
const DEFAULT_RANGE_PADDING_RATIO = 0.08;
const TIME_RATIO_SCALE = 1n << 53n;

function finiteNumber(value, name, { minimum = -Infinity } = {}) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < minimum) {
    throw new RangeError(`${name} must be a finite number${Number.isFinite(minimum) ? ` greater than or equal to ${minimum}` : ""}`);
  }
  return value;
}

function unitRatio(value, name) {
  finiteNumber(value, name);
  if (value < 0 || value > 1) {
    throw new RangeError(`${name} must be between 0 and 1`);
  }
  return value;
}

function bigintTime(value, name) {
  if (typeof value !== "bigint") {
    throw new TypeError(`${name} must be a bigint`);
  }
  return value;
}

function orderedTimeBounds(startNs, endNs) {
  const start = bigintTime(startNs, "startNs");
  const end = bigintTime(endNs, "endNs");
  if (end <= start) throw new RangeError("endNs must be greater than startNs");
  return { start, end, span: end - start };
}

function densityPartition(startNs, endNs, binCount) {
  const start = bigintTime(startNs, "startNs");
  const end = bigintTime(endNs, "endNs");
  if (end < start) throw new RangeError("endNs must be greater than or equal to startNs");
  if (!Number.isSafeInteger(binCount) || binCount < 1) {
    throw new RangeError("binCount must be a positive safe integer");
  }
  const span = end - start + 1n;
  const count = BigInt(binCount);
  if (count > span) throw new RangeError("binCount must not exceed the inclusive time span");
  return { start, end, span, count };
}

function scaledUnitRatio(ratio) {
  return BigInt(Math.round(unitRatio(ratio, "ratio") * Number(TIME_RATIO_SCALE)));
}

/**
 * Project an exact integer timestamp onto a Number ratio without first
 * converting the absolute timestamp to Number. The 53-bit rational scale
 * retains browser-useful precision while timestamps remain exact BigInts.
 */
export function timelineRatioForTime({ timeNs, startNs, endNs, clamp = true }) {
  const { start, end, span } = orderedTimeBounds(startNs, endNs);
  const time = bigintTime(timeNs, "timeNs");
  if (clamp && time <= start) return 0;
  if (clamp && time >= end) return 1;
  if (!clamp && time < start) {
    const magnitude = ((start - time) * TIME_RATIO_SCALE + span - 1n) / span;
    return -Number(magnitude) / Number(TIME_RATIO_SCALE);
  }
  if (!clamp && time > end) {
    const magnitude = ((time - end) * TIME_RATIO_SCALE + span - 1n) / span;
    return 1 + Math.max(
      Number.EPSILON,
      Number(magnitude) / Number(TIME_RATIO_SCALE),
    );
  }
  const scaled = ((time - start) * TIME_RATIO_SCALE) / span;
  return Number(scaled) / Number(TIME_RATIO_SCALE);
}

/** Invert timelineRatioForTime while keeping the absolute coordinate exact. */
export function timelineTimeAtRatio({ ratio, startNs, endNs }) {
  const { start, span } = orderedTimeBounds(startNs, endNs);
  const scaled = scaledUnitRatio(ratio);
  return start + (span * scaled) / TIME_RATIO_SCALE;
}

/** Test a state/relationship interval against a half-open viewport. */
export function timelineHalfOpenIntervalVisible({
  intervalStartNs,
  intervalEndNs,
  startNs,
  endNs,
}) {
  const bounds = orderedTimeBounds(startNs, endNs);
  const intervalStart = bigintTime(intervalStartNs, "intervalStartNs");
  const intervalEnd = bigintTime(intervalEndNs, "intervalEndNs");
  return intervalEnd > intervalStart
    && intervalEnd > bounds.start
    && intervalStart < bounds.end;
}

/** Test an inclusive point envelope (clusters/density) against the viewport. */
export function timelineInclusiveIntervalVisible({
  intervalStartNs,
  intervalEndNs,
  startNs,
  endNs,
}) {
  const bounds = orderedTimeBounds(startNs, endNs);
  const rawStart = bigintTime(intervalStartNs, "intervalStartNs");
  const rawEnd = bigintTime(intervalEndNs, "intervalEndNs");
  const intervalStart = rawStart <= rawEnd ? rawStart : rawEnd;
  const intervalEnd = rawStart <= rawEnd ? rawEnd : rawStart;
  return intervalEnd >= bounds.start && intervalStart <= bounds.end;
}

/** Resolve one timestamp to the bin that contains it in an inclusive partition. */
export function timelineDensityBinIndex({ timeNs, startNs, endNs, binCount }) {
  const partition = densityPartition(startNs, endNs, binCount);
  const rawTime = bigintTime(timeNs, "timeNs");
  const time = rawTime < partition.start
    ? partition.start
    : rawTime > partition.end ? partition.end : rawTime;
  const offset = time - partition.start;
  // Bin i is [floor(span*i/k), floor(span*(i+1)/k)). This is the
  // exact integer inverse of those boundaries, including non-divisible spans.
  return Number(
    (((offset + 1n) * partition.count) - 1n) / partition.span,
  );
}

/** Return the inclusive nanosecond bounds for one exact density bin. */
export function timelineDensityBinBounds({ index, startNs, endNs, binCount }) {
  const partition = densityPartition(startNs, endNs, binCount);
  if (!Number.isSafeInteger(index) || index < 0 || index >= binCount) {
    throw new RangeError("index must identify a density bin");
  }
  const binIndex = BigInt(index);
  const binStartNs = partition.start
    + (partition.span * binIndex) / partition.count;
  const binEndNs = partition.start
    + (partition.span * (binIndex + 1n)) / partition.count
    - 1n;
  return { startNs: binStartNs, endNs: binEndNs };
}

function finiteNumberRatio(value) {
  const [coefficient, exponentText = "0"] = String(value).toLowerCase().split("e");
  const exponent = Number(exponentText);
  const [whole, fraction = ""] = coefficient.split(".");
  let numerator = BigInt(`${whole}${fraction}`);
  let denominator = 1n;
  const decimalPlaces = fraction.length - exponent;
  if (decimalPlaces > 0) denominator = 10n ** BigInt(decimalPlaces);
  else if (decimalPlaces < 0) numerator *= 10n ** BigInt(-decimalPlaces);
  return { numerator, denominator };
}

function durationForZoom(span, zoom) {
  if (zoom <= MINIMUM_ZOOM) return span;
  // Converting span to Number rounds once it exceeds 2^53 and can make the
  // virtual window one nanosecond too short. Treat the finite Number zoom as
  // its exact decimal ratio and perform the ceiling entirely with BigInt.
  const { numerator, denominator } = finiteNumberRatio(zoom);
  const scaledSpan = span * denominator;
  const requested = (scaledSpan + numerator - 1n) / numerator;
  if (requested >= span) return span;
  return requested < 1n ? 1n : requested;
}

/**
 * Resolve an unbounded logical zoom into an exact visible time window.
 * Rendering can therefore stay bounded to the viewport instead of relying on
 * a browser-clamped, multi-billion-pixel CSS surface.
 */
export function timelineWindowForZoom({
  zoom,
  anchorNs,
  anchorOffsetRatio = 0.5,
  startNs,
  endNs,
}) {
  const normalizedZoom = finiteNumber(zoom, "zoom", { minimum: MINIMUM_ZOOM });
  const offset = scaledUnitRatio(anchorOffsetRatio);
  const { start, end, span } = orderedTimeBounds(startNs, endNs);
  const anchor = bigintTime(anchorNs, "anchorNs") < start
    ? start
    : anchorNs > end ? end : anchorNs;
  const duration = durationForZoom(span, normalizedZoom);
  const maximumStart = end - duration;
  let windowStart = anchor - (duration * offset) / TIME_RATIO_SCALE;
  if (windowStart < start) windowStart = start;
  if (windowStart > maximumStart) windowStart = maximumStart;
  return {
    zoom: normalizedZoom,
    startNs: windowStart,
    endNs: windowStart + duration,
    durationNs: duration,
  };
}

/** Fit a selected exact time range into the logical viewport with padding. */
export function timelineWindowForRange({
  rangeStartNs,
  rangeEndNs,
  startNs,
  endNs,
  paddingRatio = DEFAULT_RANGE_PADDING_RATIO,
}) {
  const padding = finiteNumber(paddingRatio, "paddingRatio", { minimum: 0 });
  if (!(padding < 0.5)) throw new RangeError("paddingRatio must be less than 0.5");
  const bounds = orderedTimeBounds(startNs, endNs);
  let selectionStart = bigintTime(rangeStartNs, "rangeStartNs");
  let selectionEnd = bigintTime(rangeEndNs, "rangeEndNs");
  if (selectionEnd < selectionStart) [selectionStart, selectionEnd] = [selectionEnd, selectionStart];
  selectionStart = selectionStart < bounds.start ? bounds.start : selectionStart > bounds.end ? bounds.end : selectionStart;
  selectionEnd = selectionEnd < bounds.start ? bounds.start : selectionEnd > bounds.end ? bounds.end : selectionEnd;
  const selectedDuration = selectionEnd > selectionStart ? selectionEnd - selectionStart : 1n;
  const usableScale = BigInt(Math.max(1, Math.round((1 - 2 * padding) * Number(TIME_RATIO_SCALE))));
  let duration = (selectedDuration * TIME_RATIO_SCALE + usableScale - 1n) / usableScale;
  if (duration < 1n) duration = 1n;
  if (duration > bounds.span) duration = bounds.span;
  const center = selectionStart + (selectionEnd - selectionStart) / 2n;
  const maximumStart = bounds.end - duration;
  let windowStart = center - duration / 2n;
  if (windowStart < bounds.start) windowStart = bounds.start;
  if (windowStart > maximumStart) windowStart = maximumStart;
  const zoom = Math.max(MINIMUM_ZOOM, Number(bounds.span) / Number(duration));
  if (!Number.isFinite(zoom)) throw new RangeError("selected range zoom must remain finite");
  return {
    zoom,
    startNs: windowStart,
    endNs: windowStart + duration,
    durationNs: duration,
  };
}

/**
 * Return one multiplicative zoom step.
 *
 * `direction` accepts "in"/1 and "out"/-1. Zoom never drops below one and
 * has no artificial upper limit; only values that Number cannot represent
 * are rejected.
 */
export function timelineZoomStep(currentZoom, direction, factor = DEFAULT_ZOOM_FACTOR) {
  const current = finiteNumber(currentZoom, "currentZoom", { minimum: MINIMUM_ZOOM });
  const step = finiteNumber(factor, "factor", { minimum: Number.EPSILON });
  if (!(step > 1)) throw new RangeError("factor must be greater than 1");

  let requested;
  if (direction === "in" || direction === 1) requested = current * step;
  else if (direction === "out" || direction === -1) requested = current / step;
  else throw new TypeError('direction must be "in", "out", 1, or -1');

  if (!Number.isFinite(requested)) {
    throw new RangeError("zoom step must remain finite");
  }
  return Math.max(MINIMUM_ZOOM, requested);
}
