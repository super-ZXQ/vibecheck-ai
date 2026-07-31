/**
 * E2E tests: Result display.
 *
 * Covers:
 * 5. All three result endpoints success after completed
 * 6. Assessment legacy 409
 * 7. Repair plan legacy 409
 * 13. Findings pagination 25/50
 */

import { expect, test } from "@playwright/test";

import {
  TEST_TASK_ID,
  mockAllResults,
  mockCompletedStatus,
  mockScanResult,
  mockTaskStatusSequence,
} from "./fixtures";

// ---------------------------------------------------------------------------
// Test 5: All three result endpoints success
// ---------------------------------------------------------------------------

test.describe("All results success", () => {
  test("displays all three tabs with content after completed", async ({ page }) => {
    await mockTaskStatusSequence(page, [mockCompletedStatus]);
    await mockAllResults(page);

    await page.goto(`/check/${TEST_TASK_ID}`);

    // Wait for completed state
    await expect(page.locator(".page-title")).toContainText("检测结果", { timeout: 15_000 });

    // Verify score summary is shown
    await expect(page.locator(".score-number")).toContainText("45");
    await expect(page.locator(".score-verdict")).toContainText("不推荐上线");

    // Verify scan results tab is active and has content
    await expect(page.locator(".tab-active")).toContainText("扫描结果");
    await expect(page.locator(".findings-table")).toBeVisible();

    // Switch to assessment tab
    await page.locator(".tab", { hasText: "安全评估" }).click();
    await expect(page.locator(".tab-active")).toContainText("安全评估");
    // Use .first() because both ScoreSummary and AssessmentDetails have .score-number
    await expect(page.locator(".score-number").first()).toContainText("45");

    // Switch to repair plan tab
    await page.locator(".tab", { hasText: "修复计划" }).click();
    await expect(page.locator(".tab-active")).toContainText("修复计划");
    await expect(page.locator("h3", { hasText: "修复组" })).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// Test 6: Assessment legacy 409
// ---------------------------------------------------------------------------

test.describe("Assessment legacy 409", () => {
  test("marks assessment tab as unavailable, other tabs normal", async ({ page }) => {
    await mockTaskStatusSequence(page, [mockCompletedStatus]);
    // Scan result → 200, Assessment → 409, Repair → 200
    await mockAllResults(page, {
      assessmentStatus: 409,
    });

    await page.goto(`/check/${TEST_TASK_ID}`);

    // Wait for completed state
    await expect(page.locator(".page-title")).toContainText("检测结果", { timeout: 15_000 });

    // Scan tab should be available (✓)
    const scanTab = page.locator(".tab", { hasText: "扫描结果" });
    await expect(scanTab).toContainText("✓");

    // Assessment tab should be unavailable (−)
    const assessmentTab = page.locator(".tab", { hasText: "安全评估" });
    await expect(assessmentTab).toContainText("−");

    // Repair tab should be available (✓)
    const repairTab = page.locator(".tab", { hasText: "修复计划" });
    await expect(repairTab).toContainText("✓");

    // Click assessment tab → should show unavailable message
    await assessmentTab.click();
    await expect(page.locator(".empty-state")).toContainText("不可用");

    // Scan tab should still work
    await page.locator(".tab", { hasText: "扫描结果" }).click();
    await expect(page.locator(".findings-table")).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// Test 7: Repair plan legacy 409
// ---------------------------------------------------------------------------

test.describe("Repair plan legacy 409", () => {
  test("marks repair tab as unavailable, other tabs normal", async ({ page }) => {
    await mockTaskStatusSequence(page, [mockCompletedStatus]);
    // Scan result → 200, Assessment → 200, Repair → 409
    await mockAllResults(page, {
      repairPlanStatus: 409,
    });

    await page.goto(`/check/${TEST_TASK_ID}`);

    // Wait for completed state
    await expect(page.locator(".page-title")).toContainText("检测结果", { timeout: 15_000 });

    // Scan tab should be available (✓)
    const scanTab = page.locator(".tab", { hasText: "扫描结果" });
    await expect(scanTab).toContainText("✓");

    // Assessment tab should be available (✓)
    const assessmentTab = page.locator(".tab", { hasText: "安全评估" });
    await expect(assessmentTab).toContainText("✓");

    // Repair tab should be unavailable (−)
    const repairTab = page.locator(".tab", { hasText: "修复计划" });
    await expect(repairTab).toContainText("−");

    // Click repair tab → should show unavailable message
    await repairTab.click();
    await expect(page.locator(".empty-state")).toContainText("不可用");

    // Assessment tab should still work
    await page.locator(".tab", { hasText: "安全评估" }).click();
    await expect(page.locator(".score-number").first()).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// Test 13: Findings pagination 25/50
// ---------------------------------------------------------------------------

test.describe("Findings pagination", () => {
  test("paginates findings with 25 per page by default", async ({ page }) => {
    await mockTaskStatusSequence(page, [mockCompletedStatus]);
    // mockScanResult has 30 findings
    await mockAllResults(page, {
      scanResultBody: mockScanResult,
    });

    await page.goto(`/check/${TEST_TASK_ID}`);

    // Wait for completed state
    await expect(page.locator(".page-title")).toContainText("检测结果", { timeout: 15_000 });

    // Verify default 25 per page
    const rows = page.locator(".findings-table tbody tr");
    await expect(rows).toHaveCount(25);

    // Verify pagination info
    await expect(page.locator(".pagination")).toContainText("1-25");
    await expect(page.locator(".pagination")).toContainText("共 30 条");

    // Verify page selector shows 25
    const select = page.locator(".page-size-select");
    await expect(select).toHaveValue("25");

    // Navigate to next page
    await page.locator("button", { hasText: "下一页" }).click();
    await expect(rows).toHaveCount(5); // 30 - 25 = 5 on second page
    await expect(page.locator(".pagination")).toContainText("26-30");
  });

  test("switches to 50 per page", async ({ page }) => {
    await mockTaskStatusSequence(page, [mockCompletedStatus]);
    await mockAllResults(page, {
      scanResultBody: mockScanResult,
    });

    await page.goto(`/check/${TEST_TASK_ID}`);

    await expect(page.locator(".page-title")).toContainText("检测结果", { timeout: 15_000 });

    // Switch to 50 per page
    await page.selectOption(".page-size-select", "50");

    // All 30 findings should be on one page
    const rows = page.locator(".findings-table tbody tr");
    await expect(rows).toHaveCount(30);

    // Verify pagination shows 1-30
    await expect(page.locator(".pagination")).toContainText("1-30");
    await expect(page.locator(".pagination")).toContainText("共 30 条");

    // Verify total pages is 1
    await expect(page.locator(".pagination")).toContainText("1 / 1");
  });
});
