/**
 * E2E tests: Repair plan and page refresh.
 *
 * Covers:
 * 10. Agent prompt copy
 * 11. Page refresh recovery by task_id
 */

import { expect, test } from "@playwright/test";

import {
  API_BASE,
  TEST_TASK_ID,
  mockAllResults,
  mockAssessment,
  mockCompletedStatus,
  mockPendingStatus,
  mockRepairPlan,
  mockRunningStatus,
  mockScanResult,
  mockTaskStatusSequence,
} from "./fixtures";

// ---------------------------------------------------------------------------
// Test 10: Agent prompt copy
// ---------------------------------------------------------------------------

test.describe("Agent prompt copy", () => {
  test("copies agent prompt only on user click", async ({ page, context }) => {
    // Grant clipboard permissions
    await context.grantPermissions(["clipboard-read", "clipboard-write"]);

    await mockTaskStatusSequence(page, [mockCompletedStatus]);
    await mockAllResults(page);

    await page.goto(`/check/${TEST_TASK_ID}`);

    // Wait for completed state
    await expect(page.locator(".page-title")).toContainText("检测结果", { timeout: 15_000 });

    // Switch to repair plan tab
    await page.locator(".tab", { hasText: "修复计划" }).click();

    // Verify agent prompt section is visible
    await expect(page.locator("h3", { hasText: "Agent 指令" })).toBeVisible();
    await expect(page.locator(".agent-prompt-text")).toBeVisible();

    // Verify the copy button exists
    const copyButton = page.locator("button", { hasText: "复制指令" });
    await expect(copyButton).toBeVisible();

    // Click copy button
    await copyButton.click();

    // Verify success feedback
    await expect(page.locator(".copy-success")).toBeVisible({ timeout: 5_000 });
    await expect(page.locator(".copy-success")).toContainText("已复制到剪贴板");

    // Verify clipboard content matches the agent prompt
    const clipboardText = await page.evaluate(() => navigator.clipboard.readText());
    expect(clipboardText).toContain("Replace hardcoded passwords");
    expect(clipboardText).toContain("Remove private key files");

    // Verify the safety note is displayed
    await expect(page.locator("body")).toContainText("不会自动执行或发送到任何外部服务");
  });

  test("does not auto-copy agent prompt on page load", async ({ page, context }) => {
    await context.grantPermissions(["clipboard-read", "clipboard-write"]);

    // Set initial clipboard content to verify it's not overwritten
    await page.goto("/");
    await page.evaluate(() => navigator.clipboard.writeText("INITIAL_VALUE"));

    await mockTaskStatusSequence(page, [mockCompletedStatus]);
    await mockAllResults(page);

    await page.goto(`/check/${TEST_TASK_ID}`);

    await expect(page.locator(".page-title")).toContainText("检测结果", { timeout: 15_000 });

    // Switch to repair tab
    await page.locator(".tab", { hasText: "修复计划" }).click();

    // Wait a moment to ensure no auto-copy happens
    await page.waitForTimeout(2000);

    // Verify clipboard was NOT changed (no auto-copy)
    const clipboardText = await page.evaluate(() => navigator.clipboard.readText());
    expect(clipboardText).toBe("INITIAL_VALUE");
  });
});

// ---------------------------------------------------------------------------
// Test 11: Page refresh recovery by task_id
// ---------------------------------------------------------------------------

test.describe("Page refresh recovery", () => {
  test("recovers polling state when navigating directly to check page", async ({ page }) => {
    // Simulate page refresh: navigate directly to /check/{task_id}
    // The page should start polling automatically.
    await mockTaskStatusSequence(page, [
      mockPendingStatus,
      mockRunningStatus,
      mockCompletedStatus,
    ]);
    await mockAllResults(page);

    // Navigate directly (simulates refresh or shared link)
    await page.goto(`/check/${TEST_TASK_ID}`);

    // Verify polling starts — should show progress
    await expect(page.locator(".card")).toContainText("排队中", { timeout: 10_000 });

    // Wait for running stage
    await expect(page.locator(".card")).toContainText("扫描敏感信息", { timeout: 10_000 });

    // Wait for completed results
    await expect(page.locator(".page-title")).toContainText("检测结果", { timeout: 15_000 });

    // Verify results are displayed
    await expect(page.locator(".findings-table")).toBeVisible();
  });

  test("rejects invalid task_id format", async ({ page }) => {
    // Navigate with an invalid (non-UUID) task_id
    await page.goto(`/check/not-a-valid-uuid`);

    // Should show invalid task ID error
    await expect(page.locator(".error-box")).toContainText("任务ID格式无效");
  });

  test("accepts valid UUID format task_id", async ({ page }) => {
    // Use a valid UUID format
    const validUuid = "12345678-1234-1234-1234-123456789abc";

    await page.route(`${API_BASE}/api/check/${validUuid}`, (route) => {
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          ...mockCompletedStatus,
          task_id: validUuid,
        }),
      });
    });

    await page.route(`${API_BASE}/api/check/${validUuid}/result`, (route) => {
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(mockScanResult),
      });
    });

    await page.route(`${API_BASE}/api/check/${validUuid}/assessment`, (route) => {
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(mockAssessment),
      });
    });

    await page.route(`${API_BASE}/api/check/${validUuid}/repair-plan`, (route) => {
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(mockRepairPlan),
      });
    });

    await page.goto(`/check/${validUuid}`);

    // Should NOT show invalid task ID error
    await expect(page.locator(".error-box")).not.toBeVisible({ timeout: 5_000 });

    // Should proceed to results
    await expect(page.locator(".page-title")).toContainText("检测结果", { timeout: 15_000 });
  });
});
