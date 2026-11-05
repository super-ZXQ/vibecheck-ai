/**
 * Pure view-model helpers for the quality report tab.
 *
 * Kept in a .mjs module so the same logic can be unit-tested with node:test
 * without a React/component testing setup.
 */

const STATUS_PRESENTATION = {
  completed: { label: "已完成", className: "severity-info" },
  partial: { label: "部分完成", className: "severity-medium" },
  not_completed: { label: "未完成", className: "severity-high" },
  not_applicable: { label: "不适用", className: "severity-low" },
};

const UNKNOWN_STATUS = { label: "未知状态", className: "severity-low" };

/**
 * Split a block's items using the backend's authoritative id lists.
 *
 * `report_only` items that are neither fixable nor manual are returned in
 * `other`, so they stay visible without being mislabelled as fixable.
 */
export function splitQualityItems(block) {
  const items = Array.isArray(block?.items) ? block.items : [];
  const byId = new Map(items.map((item) => [item.item_id, item]));

  const pick = (ids) => {
    if (!Array.isArray(ids)) return [];
    const seen = new Set();
    const picked = [];
    for (const id of ids) {
      if (seen.has(id)) continue;
      seen.add(id);
      const item = byId.get(id);
      if (item) picked.push(item);
    }
    return picked;
  };

  const fixable = pick(block?.fixable_item_ids);
  const manual = pick(block?.manual_confirm_item_ids);
  const grouped = new Set([...fixable, ...manual].map((item) => item.item_id));
  const other = items.filter((item) => !grouped.has(item.item_id));

  return { fixable, manual, other };
}

function stringifyCount(value) {
  if (value === null || value === undefined) return "";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

/**
 * Normalise conclusion counts for rendering.
 *
 * Scalars stay inline; nested maps (e.g. `by_rule`) are returned separately
 * so the UI can render them as a collapsible detail instead of
 * `[object Object]`.
 */
export function formatQualityCounts(counts) {
  const scalars = [];
  const nested = [];
  if (!counts || typeof counts !== "object") return { scalars, nested };

  for (const [key, value] of Object.entries(counts)) {
    if (value && typeof value === "object") {
      nested.push([
        key,
        Object.entries(value).map(([childKey, childValue]) => [
          childKey,
          stringifyCount(childValue),
        ]),
      ]);
    } else {
      scalars.push([key, stringifyCount(value)]);
    }
  }
  return { scalars, nested };
}

export function qualityStatusMeta(status) {
  return STATUS_PRESENTATION[status] ?? UNKNOWN_STATUS;
}
