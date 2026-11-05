import assert from "node:assert/strict";
import test from "node:test";

import {
  formatQualityCounts,
  qualityStatusMeta,
  splitQualityItems,
} from "../lib/quality-report.mjs";

function item(itemId, overrides = {}) {
  return {
    item_id: itemId,
    fixability: "auto_fix",
    manual_decision_required: false,
    ...overrides,
  };
}

test("report_only item is not placed in the fixable group", () => {
  const block = {
    items: [
      item("fix-1"),
      item("report-1", { fixability: "report_only" }),
      item("manual-1", {
        fixability: "report_only",
        manual_decision_required: true,
      }),
    ],
    fixable_item_ids: ["fix-1"],
    manual_confirm_item_ids: ["manual-1"],
  };

  const groups = splitQualityItems(block);

  assert.deepEqual(
    groups.fixable.map((entry) => entry.item_id),
    ["fix-1"],
  );
  assert.deepEqual(
    groups.manual.map((entry) => entry.item_id),
    ["manual-1"],
  );
  assert.deepEqual(
    groups.other.map((entry) => entry.item_id),
    ["report-1"],
  );
});

test("item groups follow backend id order and ignore unknown ids", () => {
  const block = {
    items: [item("a"), item("b"), item("c")],
    fixable_item_ids: ["c", "missing", "a"],
    manual_confirm_item_ids: ["b", "b"],
  };

  const groups = splitQualityItems(block);
  assert.deepEqual(
    groups.fixable.map((entry) => entry.item_id),
    ["c", "a"],
  );
  assert.deepEqual(
    groups.manual.map((entry) => entry.item_id),
    ["b"],
  );
  assert.deepEqual(groups.other, []);
});

test("missing id lists keep every item visible instead of hiding findings", () => {
  const groups = splitQualityItems({ items: [item("a"), item("b")] });
  assert.deepEqual(groups.fixable, []);
  assert.deepEqual(groups.manual, []);
  assert.deepEqual(
    groups.other.map((entry) => entry.item_id),
    ["a", "b"],
  );
});

test("nested counts never render as [object Object]", () => {
  const view = formatQualityCounts({
    total_items: 3,
    by_rule: { "font/missing-asset": 2, "comment/missing": 1 },
  });

  assert.deepEqual(view.scalars, [["total_items", "3"]]);
  assert.deepEqual(view.nested, [
    [
      "by_rule",
      [
        ["font/missing-asset", "2"],
        ["comment/missing", "1"],
      ],
    ],
  ]);
  assert.ok(!JSON.stringify(view).includes("[object Object]"));
});

test("deeper nested count values are JSON-encoded", () => {
  const view = formatQualityCounts({
    groups: { a: { nested: 1 } },
  });
  assert.deepEqual(view.nested, [["groups", [["a", '{"nested":1}']]]]);
});

test("unknown block status gets a fallback label and style", () => {
  assert.deepEqual(qualityStatusMeta("completed"), {
    label: "已完成",
    className: "severity-info",
  });
  assert.deepEqual(qualityStatusMeta("future_status"), {
    label: "未知状态",
    className: "severity-low",
  });
});
