import assert from "node:assert/strict";
import test from "node:test";

import {
  timelineDensityBinBounds,
  timelineDensityBinIndex,
  timelineHalfOpenIntervalVisible,
  timelineInclusiveIntervalVisible,
  timelineRatioForTime,
  timelineTimeAtRatio,
  timelineWindowForRange,
  timelineWindowForZoom,
  timelineZoomStep,
} from "../assets/timeline_viewport.js";

function closeTo(actual, expected, tolerance = 1e-9) {
  assert.ok(
    Math.abs(actual - expected) <= tolerance,
    `expected ${actual} to be within ${tolerance} of ${expected}`,
  );
}

test("zoom steps enforce the minimum without imposing an upper cap", () => {
  assert.equal(timelineZoomStep(2, "in"), 3);
  closeTo(timelineZoomStep(2, "out"), 4 / 3);
  assert.equal(timelineZoomStep(1, "out"), 1);
  assert.equal(timelineZoomStep(3, 1, 2), 6);
  assert.equal(timelineZoomStep(3, -1, 2), 1.5);

  const veryLarge = Number.MAX_VALUE / 4;
  assert.equal(timelineZoomStep(veryLarge, "out"), veryLarge / 1.5);
  assert.throws(() => timelineZoomStep(Number.MAX_VALUE, "in", 2), /finite/);
});

test("logical zoom preserves an exact BigInt anchor at the requested viewport offset", () => {
  const startNs = 9_007_199_254_740_993n;
  const endNs = startNs + 1_000n;
  const anchorNs = startNs + 420n;
  const before = timelineWindowForZoom({
    zoom: 2,
    anchorNs,
    anchorOffsetRatio: 0.25,
    startNs,
    endNs,
  });
  const after = timelineWindowForZoom({
    zoom: 5,
    anchorNs,
    anchorOffsetRatio: 0.25,
    startNs,
    endNs,
  });

  assert.deepEqual(before, {
    zoom: 2,
    startNs: startNs + 295n,
    endNs: startNs + 795n,
    durationNs: 500n,
  });
  assert.deepEqual(after, {
    zoom: 5,
    startNs: startNs + 370n,
    endNs: startNs + 570n,
    durationNs: 200n,
  });
});

test("logical zoom rounds exact BigInt durations upward without Number precision loss", () => {
  const span = 9_007_199_254_740_993n;
  const half = timelineWindowForZoom({
    zoom: 2,
    anchorNs: 0n,
    anchorOffsetRatio: 0,
    startNs: 0n,
    endNs: span,
  });
  assert.equal(half.durationNs, 4_503_599_627_370_497n);

  const twoThirds = timelineWindowForZoom({
    zoom: 1.5,
    anchorNs: 0n,
    anchorOffsetRatio: 0,
    startNs: 0n,
    endNs: span,
  });
  assert.equal(twoThirds.durationNs, (span * 2n + 2n) / 3n);

  const decimal = timelineWindowForZoom({
    zoom: 1.1,
    anchorNs: span,
    anchorOffsetRatio: 1,
    startNs: 0n,
    endNs: span,
  });
  assert.equal(decimal.durationNs, (span * 10n + 10n) / 11n);
  assert.equal(decimal.endNs, span);

  const enormous = timelineWindowForZoom({
    zoom: 1e300,
    anchorNs: span / 2n,
    anchorOffsetRatio: 0.5,
    startNs: 0n,
    endNs: span,
  });
  assert.equal(enormous.durationNs, 1n);
});

test("exact BigInt time projection preserves 100 microsecond distinctions above Number.MAX_SAFE_INTEGER", () => {
  const startNs = 9_007_199_254_740_993n;
  const endNs = startNs + 1_000_000_000_000n;
  const firstNs = startNs + 400_000_000_000n;
  const secondNs = firstNs + 100_000n;

  const firstRatio = timelineRatioForTime({ timeNs: firstNs, startNs, endNs });
  const secondRatio = timelineRatioForTime({ timeNs: secondNs, startNs, endNs });
  assert.ok(secondRatio > firstRatio, "100 microseconds must not collapse to one timeline coordinate");

  for (const [timeNs, ratio] of [[firstNs, firstRatio], [secondNs, secondRatio]]) {
    const restoredNs = timelineTimeAtRatio({ ratio, startNs, endNs });
    const errorNs = restoredNs >= timeNs ? restoredNs - timeNs : timeNs - restoredNs;
    assert.ok(errorNs <= 1n, `round trip drifted by ${errorNs} ns`);
  }
});

test("unclamped exact projection identifies artifacts outside the virtual render window", () => {
  const startNs = 9_007_199_254_740_993n;
  const endNs = startNs + 4_000_000n;
  const beforeNs = startNs - 1_000_000n;
  const afterNs = endNs + 1_000_000n;

  assert.equal(timelineRatioForTime({ timeNs: beforeNs, startNs, endNs }), 0);
  assert.equal(timelineRatioForTime({ timeNs: afterNs, startNs, endNs }), 1);
  assert.equal(timelineRatioForTime({ timeNs: beforeNs, startNs, endNs, clamp: false }), -0.25);
  assert.equal(timelineRatioForTime({ timeNs: afterNs, startNs, endNs, clamp: false }), 1.25);

  const wideEndNs = startNs + 9_007_199_254_740_993n;
  assert.ok(timelineRatioForTime({
    timeNs: startNs - 1n,
    startNs,
    endNs: wideEndNs,
    clamp: false,
  }) < 0);
  assert.ok(timelineRatioForTime({
    timeNs: wideEndNs + 1n,
    startNs,
    endNs: wideEndNs,
    clamp: false,
  }) > 1);
});

test("half-open timeline intervals do not leave endpoint slivers", () => {
  const visible = (intervalStartNs, intervalEndNs) => timelineHalfOpenIntervalVisible({
    intervalStartNs,
    intervalEndNs,
    startNs: 100n,
    endNs: 200n,
  });
  assert.equal(visible(50n, 100n), false, "an interval ending at the window start is outside");
  assert.equal(visible(100n, 150n), true, "an interval beginning at the window start is inside");
  assert.equal(visible(150n, 200n), true, "an interval ending at the window end overlaps");
  assert.equal(visible(200n, 250n), false, "an interval beginning at the window end is outside");
  assert.equal(visible(120n, 120n), false, "an empty interval is not rendered");
});

test("inclusive point envelopes retain exact endpoint and zero-width clusters", () => {
  const visible = (intervalStartNs, intervalEndNs) => timelineInclusiveIntervalVisible({
    intervalStartNs,
    intervalEndNs,
    startNs: 100n,
    endNs: 200n,
  });
  assert.equal(visible(99n, 99n), false);
  assert.equal(visible(100n, 100n), true);
  assert.equal(visible(200n, 200n), true);
  assert.equal(visible(201n, 201n), false);
  assert.equal(visible(250n, 150n), true, "reversed envelopes are normalized");
});

test("density assignment exactly inverts non-divisible inclusive bin bounds", () => {
  const expected = [
    { startNs: 0n, endNs: 0n },
    { startNs: 1n, endNs: 2n },
    { startNs: 3n, endNs: 4n },
    { startNs: 5n, endNs: 5n },
    { startNs: 6n, endNs: 7n },
    { startNs: 8n, endNs: 9n },
  ];
  assert.deepEqual(
    expected.map((_, index) => timelineDensityBinBounds({
      index,
      startNs: 0n,
      endNs: 9n,
      binCount: 6,
    })),
    expected,
  );
  assert.equal(timelineDensityBinIndex({
    timeNs: 3n,
    startNs: 0n,
    endNs: 9n,
    binCount: 6,
  }), 2);
  expected.forEach((bounds, index) => {
    for (let timeNs = bounds.startNs; timeNs <= bounds.endNs; timeNs += 1n) {
      assert.equal(timelineDensityBinIndex({
        timeNs,
        startNs: 0n,
        endNs: 9n,
        binCount: 6,
      }), index);
    }
  });
});

test("logical fit spans the complete capture even when the rendered temporal area is narrower than the base track", () => {
  const startNs = 12_345_678_901_234_567n;
  const endNs = startNs + 900_000_000_000n;
  const fitted = timelineWindowForZoom({
    zoom: 1,
    anchorNs: startNs + 600_000_000_000n,
    anchorOffsetRatio: 0.9,
    startNs,
    endNs,
  });

  assert.deepEqual(fitted, {
    zoom: 1,
    startNs,
    endNs,
    durationNs: endNs - startNs,
  });

  const selected = timelineWindowForRange({
    rangeStartNs: startNs + 100_000n,
    rangeEndNs: startNs + 200_000n,
    startNs,
    endNs,
    paddingRatio: 0.1,
  });
  assert.ok(selected.startNs <= startNs + 100_000n);
  assert.ok(selected.endNs >= startNs + 200_000n);
  assert.ok(selected.durationNs < fitted.durationNs);
});

test("logical zoom clamps exact windows cleanly at both capture edges", () => {
  const left = timelineWindowForZoom({
    zoom: 4,
    anchorNs: 0n,
    anchorOffsetRatio: 0.5,
    startNs: 0n,
    endNs: 1_000n,
  });
  const right = timelineWindowForZoom({
    zoom: 4,
    anchorNs: 1_000n,
    anchorOffsetRatio: 0.5,
    startNs: 0n,
    endNs: 1_000n,
  });

  assert.deepEqual(left, { zoom: 4, startNs: 0n, endNs: 250n, durationNs: 250n });
  assert.deepEqual(right, { zoom: 4, startNs: 750n, endNs: 1_000n, durationNs: 250n });
});

test("range windows normalize reversed bounds and preserve exact padding", () => {
  const window = timelineWindowForRange({
    rangeStartNs: 600n,
    rangeEndNs: 400n,
    startNs: 0n,
    endNs: 1_000n,
    paddingRatio: 0.1,
  });

  assert.deepEqual(window, {
    zoom: 4,
    startNs: 375n,
    endNs: 625n,
    durationNs: 250n,
  });
});

test("a point range and arbitrarily large finite zoom remain exact without a pixel surface", () => {
  const point = timelineWindowForRange({
    rangeStartNs: 500n,
    rangeEndNs: 500n,
    startNs: 0n,
    endNs: 1_000n,
    paddingRatio: 0.1,
  });
  assert.equal(point.startNs, 499n);
  assert.equal(point.endNs, 501n);
  assert.equal(point.durationNs, 2n);
  assert.equal(point.zoom, 500);

  const zoom = Number.MAX_VALUE / 2;
  const deep = timelineWindowForZoom({
    zoom,
    anchorNs: 500n,
    anchorOffsetRatio: 0.5,
    startNs: 0n,
    endNs: 1_000n,
  });
  assert.equal(deep.zoom, zoom);
  assert.equal(deep.durationNs, 1n);
  assert.equal(deep.endNs - deep.startNs, 1n);
});

test("invalid exact-window and zoom inputs fail closed", () => {
  assert.throws(() => timelineZoomStep(0.5, "in"), /currentZoom/);
  assert.throws(() => timelineZoomStep(2, "sideways"), /direction/);
  assert.throws(() => timelineZoomStep(2, "in", 1), /factor/);
  assert.throws(() => timelineWindowForZoom({
    zoom: Number.NaN,
    anchorNs: 500n,
    startNs: 0n,
    endNs: 1_000n,
  }), /zoom/);
  assert.throws(() => timelineWindowForZoom({
    zoom: 2,
    anchorNs: 500n,
    anchorOffsetRatio: 1.1,
    startNs: 0n,
    endNs: 1_000n,
  }), /ratio/);
  assert.throws(() => timelineWindowForRange({
    rangeStartNs: 200n,
    rangeEndNs: 400n,
    startNs: 0n,
    endNs: 1_000n,
    paddingRatio: 0.5,
  }), /paddingRatio/);
  assert.throws(() => timelineWindowForRange({
    rangeStartNs: 200n,
    rangeEndNs: 400n,
    startNs: 1_000n,
    endNs: 0n,
  }), /endNs/);
  assert.throws(() => timelineRatioForTime({
    timeNs: 1,
    startNs: 0n,
    endNs: 1_000n,
  }), /bigint/);
});
