/**
 * E2E tests: Quality report tab.
 *
 * Covers:
 * - available report with all four block statuses and nested counts
 * - backend-authoritative item grouping (fixable / manual / report-only)
 * - 409 (unavailable) and 500 (error) endpoint states
 * - empty report across all four dimensions
 * - WAI-ARIA tabs pattern (roles, aria-selected, arrow/Home/End keys)
 * - keep-alive panels preserve per-tab UI state across tab switches
 */

import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";

import {
  TEST_TASK_ID,
  mockAllResults,
  mockCompletedStatus,
  mockEmptyQualityReport,
  mockQualityReport,
  mockTaskStatusSequence,
} from "./fixtures";

const QUALITY_TAB = "质量检查";
const QUALITY_PANEL = "#result-panel-quality";

async function openQualityTab(page: Page) {
  await mockTaskStatusSequence(page, [mockCompletedStatus]);
  await page.goto(`/check/${TEST_TASK_ID}`);
  await expect(page.locator(".page-title")).toContainText("检测结果", {
    timeout: 15_000,
  });
  await page.locator(".tab", { hasText: QUALITY_TAB }).click();
  const panel = page.locator(QUALITY_PANEL);
  await expect(panel).toBeVisible();
  return panel;
}

function blockCard(page: Page, label: string) {
  return page.locator(`${QUALITY_PANEL} .card`, { hasText: label });
}

test.describe("Quality report available", () => {
  test("renders four statuses, nested counts, and backend grouping", async ({
    page,
  }) => {
    await mockAllResults(page, { qualityReportBody: mockQualityReport });
    const panel = await openQualityTab(page);

    // Four block statuses (one badge per block card).
    await expect(
      blockCard(page, "前端死代码").locator(".severity-badge").first(),
    ).toHaveText("已完成");
    await expect(
      blockCard(page, "字体许可与冗余").locator(".severity-badge").first(),
    ).toHaveText("部分完成");
    await expect(
      blockCard(page, "后端路由审计").locator(".severity-badge").first(),
    ).toHaveText("未完成");
    await expect(
      blockCard(page, "中文注释规范").locator(".severity-badge").first(),
    ).toHaveText("不适用");

    // Nested counts expand instead of rendering [object Object].
    const deadCode = blockCard(page, "前端死代码");
    const nested = deadCode.locator("details", { hasText: "by_severity" });
    await expect(nested.locator("summary")).toContainText("by_severity 明细（2）");
    await nested.locator("summary").click();
    await expect(nested.locator("li", { hasText: "P2: 1" })).toBeVisible();
    await expect(nested.locator("li", { hasText: "P3: 1" })).toBeVisible();
    await expect(panel).not.toContainText("[object Object]");

    // Grouping follows the backend id lists: report_only items stay in
    // "其他发现（仅报告）" and are never counted as fixable.
    const fixable = deadCode.locator('[data-quality-group="fixable"]');
    const other = deadCode.locator('[data-quality-group="other"]');
    await expect(fixable).toContainText("可修复项（1）");
    await expect(fixable).toContainText("未引用的导出 helper");
    await expect(fixable).not.toContainText("CSS 类可能未使用");
    await expect(other).toContainText("其他发现（仅报告）（1）");
    await expect(other).toContainText("CSS 类可能未使用");

    const fontBlock = blockCard(page, "字体许可与冗余");
    await expect(
      fontBlock.locator('[data-quality-group="manual"]'),
    ).toContainText("需人工确认项（1）");
    await expect(
      fontBlock.locator('[data-quality-group="manual"]'),
    ).toContainText("Inter 字体许可需人工确认");
    await expect(fontBlock.locator('[data-quality-group="fixable"]')).toHaveCount(
      0,
    );

    // Top summary numbers match the rendered group sizes.
    const fixableCard = page.locator(".dimension-card", { hasText: "可修复" });
    await expect(fixableCard.locator("strong")).toHaveText("1");
    await expect(
      page.locator(`${QUALITY_PANEL} [data-quality-group="fixable"] > ul > li`),
    ).toHaveCount(1);
    await expect(
      page.locator(`${QUALITY_PANEL} [data-quality-group="manual"] > ul > li`),
    ).toHaveCount(1);
    await expect(
      page.locator(`${QUALITY_PANEL} [data-quality-group="other"] > ul > li`),
    ).toHaveCount(2);

    // Duplicate limitation strings are both rendered (index keys).
    await expect(panel.locator("li", { hasText: "仅覆盖已成功解析的文件。" })).toHaveCount(2);
  });

  test("keeps panel state when switching tabs", async ({ page }) => {
    await mockAllResults(page, { qualityReportBody: mockQualityReport });
    const panel = await openQualityTab(page);

    const evidence = panel.locator("details", { hasText: "证据" }).first();
    await evidence.locator("summary").click();
    await expect(evidence).toHaveAttribute("open", "");

    await page.locator(".tab", { hasText: "扫描结果" }).click();
    await expect(page.locator(QUALITY_PANEL)).toBeHidden();

    await page.locator(".tab", { hasText: QUALITY_TAB }).click();
    await expect(page.locator(QUALITY_PANEL)).toBeVisible();
    await expect(evidence).toHaveAttribute("open", "");
  });
});

test.describe("Quality report unavailable (409)", () => {
  test("marks the tab unavailable and shows an empty state", async ({ page }) => {
    await mockAllResults(page, { qualityReportStatus: 409 });
    const panel = await openQualityTab(page);

    await expect(page.locator(".tab", { hasText: QUALITY_TAB })).toContainText("−");
    await expect(panel.locator(".empty-state")).toContainText("不可用");
    await expect(panel.locator(".error-box")).toHaveCount(0);
  });
});

test.describe("Quality report failure (500)", () => {
  test("marks the tab as error and shows the safe error box", async ({ page }) => {
    await mockAllResults(page, { qualityReportStatus: 500 });
    const panel = await openQualityTab(page);

    await expect(page.locator(".tab", { hasText: QUALITY_TAB })).toContainText("!");
    await expect(panel.locator(".error-box")).toContainText("加载失败");
    await expect(panel.locator(".empty-state")).toHaveCount(0);
  });
});

test.describe("Quality report empty", () => {
  test("shows the no-findings empty state for all four dimensions", async ({
    page,
  }) => {
    await mockAllResults(page, { qualityReportBody: mockEmptyQualityReport });
    const panel = await openQualityTab(page);

    await expect(panel.locator(".empty-state")).toHaveCount(4);
    await expect(panel.locator(".empty-state").first()).toContainText(
      "未发现问题",
    );
    for (let index = 0; index < 4; index += 1) {
      await expect(panel.locator(".empty-state").nth(index)).toContainText(
        "未发现问题",
      );
    }
    await expect(panel).not.toContainText("可修复项（1）");
  });
});

test.describe("Quality tab accessibility", () => {
  test("exposes tablist semantics and supports arrow/Home/End navigation", async ({
    page,
  }) => {
    await mockAllResults(page, { qualityReportBody: mockQualityReport });
    await mockTaskStatusSequence(page, [mockCompletedStatus]);
    await page.goto(`/check/${TEST_TASK_ID}`);
    await expect(page.locator(".page-title")).toContainText("检测结果", {
      timeout: 15_000,
    });

    const tablist = page.locator('[role="tablist"]');
    await expect(tablist).toHaveAttribute("aria-label", "检测结果");

    const tabs = page.locator('[role="tab"]');
    await expect(tabs).toHaveCount(5);

    const scanTab = page.locator('[role="tab"]', { hasText: "扫描结果" });
    await expect(scanTab).toHaveAttribute("aria-selected", "true");
    await expect(scanTab).toHaveAttribute("aria-controls", "result-panel-scan");
    await expect(page.locator("#result-panel-scan")).toHaveAttribute(
      "aria-labelledby",
      "result-tab-scan",
    );

    await scanTab.focus();
    await page.keyboard.press("ArrowRight");
    const assessmentTab = page.locator('[role="tab"]', { hasText: "安全评估" });
    await expect(assessmentTab).toBeFocused();
    await expect(assessmentTab).toHaveAttribute("aria-selected", "true");

    await page.keyboard.press("ArrowLeft");
    await expect(scanTab).toBeFocused();
    await expect(scanTab).toHaveAttribute("aria-selected", "true");

    await page.keyboard.press("End");
    const qualityTab = page.locator('[role="tab"]', { hasText: QUALITY_TAB });
    await expect(qualityTab).toBeFocused();
    await expect(qualityTab).toHaveAttribute("aria-selected", "true");
    await expect(page.locator(QUALITY_PANEL)).toBeVisible();

    await page.keyboard.press("Home");
    await expect(scanTab).toBeFocused();
    await expect(scanTab).toHaveAttribute("aria-selected", "true");
    await expect(page.locator("#result-panel-scan")).toBeVisible();
  });
});
