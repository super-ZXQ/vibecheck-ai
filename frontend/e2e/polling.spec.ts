/**
 * E2E tests: Polling lifecycle.
 *
 * Covers:
 * 2. queued → completed progress change
 * 3. failed with fixed safe error
 * 8. Network error and retry
 * 9. Poll timeout without waiting 5 minutes
 * 14. Page unload stops polling
 * 15. No overlapping poll requests
 */

import { expect, test } from "@playwright/test";

import {
  API_BASE,
  TEST_TASK_ID,
  mockAllResults,
  mockCompletedStatus,
  mockFailedStatus,
  mockPendingStatus,
  mockRunningStatus,
  mockTaskStatusSequence,
} from "./fixtures";

// ---------------------------------------------------------------------------
// Test 2: queued → completed progress change
// ---------------------------------------------------------------------------

test.describe("Progress change", () => {
  test("shows progress from queued to completed", async ({ page }) => {
    // Sequence: pending → running → completed
    await mockTaskStatusSequence(page, [
      mockPendingStatus,
      mockRunningStatus,
      mockCompletedStatus,
    ]);
    await mockAllResults(page);

    await page.goto(`/check/${TEST_TASK_ID}`);

    // Verify pending stage is shown
    await expect(page.locator(".stage-label")).toContainText("当前阶段", { timeout: 10_000 });
    await expect(page.locator(".card")).toContainText("排队中");

    // Wait for running stage (progress 50%)
    await expect(page.locator(".card")).toContainText("扫描敏感信息", { timeout: 10_000 });
    await expect(page.locator(".progress-bar-fill")).toBeVisible();

    // Wait for completed → results page
    await expect(page.locator(".page-title")).toContainText("检测结果", { timeout: 15_000 });
  });
});

// ---------------------------------------------------------------------------
// Test 3: failed with fixed safe error
// ---------------------------------------------------------------------------

test.describe("Failed state", () => {
  test("displays fixed safe error message for failed task", async ({ page }) => {
    let submissions = 0;
    await page.route(`${API_BASE}/api/check`, (route) => {
      submissions++;
      route.abort("failed");
    });
    await mockTaskStatusSequence(page, [mockFailedStatus]);

    await page.goto(`/check/${TEST_TASK_ID}`);

    // Verify failed state
    await expect(page.locator(".page-title")).toContainText("检测失败", { timeout: 10_000 });

    // Verify the backend's desensitized error_message is displayed
    await expect(page.locator(".error-box")).toContainText("仓库不存在或无法访问");

    await page.getByRole("link", { name: "重新检测" }).click();
    await expect(page).toHaveURL("/");
    await expect(page.getByLabel("GitHub 仓库地址")).toHaveValue("");
    expect(submissions).toBe(0);
  });

  test("falls back to error_code mapping when error_message is null", async ({ page }) => {
    const failedWithoutMessage = {
      ...mockFailedStatus,
      error_message: null,
      error_code: "DOWNLOAD_FAILED",
    };
    await mockTaskStatusSequence(page, [failedWithoutMessage]);

    await page.goto(`/check/${TEST_TASK_ID}`);

    await expect(page.locator(".page-title")).toContainText("检测失败", { timeout: 10_000 });
    // DOWNLOAD_FAILED → "下载失败，请稍后重试。"
    await expect(page.locator(".error-box")).toContainText("下载失败");
  });
});

// ---------------------------------------------------------------------------
// HTTP polling failures
// ---------------------------------------------------------------------------

test.describe("HTTP polling failures", () => {
  const scenarios = [
    { status: 404, errorCode: "TASK_NOT_FOUND", expected: "任务不存在" },
    { status: 422, errorCode: "INVALID_TASK_ID", expected: "任务ID格式无效" },
    { status: 500, errorCode: "INTERNAL_ERROR", expected: "内部错误" },
  ];

  for (const scenario of scenarios) {
    test(`${scenario.status} stops immediately with a fixed mapping`, async ({
      page,
    }) => {
      let statusRequests = 0;
      const untrustedMessage = ["server detail ", "must not ", "be rendered"].join("");
      await page.route(`${API_BASE}/api/check/${TEST_TASK_ID}`, (route) => {
        statusRequests++;
        route.fulfill({
          status: scenario.status,
          contentType: "application/json",
          body: JSON.stringify({
            detail: {
              error_code: scenario.errorCode,
              error_message: untrustedMessage,
            },
          }),
        });
      });

      await page.goto(`/check/${TEST_TASK_ID}`);

      await expect(page.locator(".page-title")).toContainText("检测失败");
      await expect(page.locator(".error-box")).toContainText(scenario.expected);
      await expect(page.locator("body")).not.toContainText(untrustedMessage);
      await page.waitForTimeout(2500);
      expect(statusRequests).toBe(1);
    });
  }
});

// ---------------------------------------------------------------------------
// Network error and retry
// ---------------------------------------------------------------------------

test.describe("Network error retry", () => {
  test("retries polling after network error and eventually succeeds", async ({ page }) => {
    let callCount = 0;

    await page.route(`${API_BASE}/api/check/${TEST_TASK_ID}`, (route) => {
      callCount++;
      if (callCount === 1) {
        // First poll → network error
        route.abort("failed");
      } else {
        // Second poll → completed
        route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(mockCompletedStatus),
        });
      }
    });
    await mockAllResults(page);

    await page.goto(`/check/${TEST_TASK_ID}`);

    // Should eventually reach completed state despite first network error
    await expect(page.locator(".page-title")).toContainText("检测结果", { timeout: 15_000 });

    // Verify at least 2 polls occurred (first failed, second succeeded)
    expect(callCount).toBeGreaterThanOrEqual(2);
  });

  test("persistent network errors end in timeout", async ({ page }) => {
    await page.clock.install();
    let callCount = 0;
    await page.route(`${API_BASE}/api/check/${TEST_TASK_ID}`, (route) => {
      callCount++;
      route.abort("failed");
    });

    await page.goto(`/check/${TEST_TASK_ID}`);
    await expect.poll(() => callCount).toBeGreaterThanOrEqual(1);

    await page.clock.fastForward(300_001);
    await expect(page.locator(".page-title")).toContainText("检测超时");
    expect(callCount).toBeGreaterThanOrEqual(2);
  });
});

// ---------------------------------------------------------------------------
// Test 9: Poll timeout without waiting 5 minutes
// ---------------------------------------------------------------------------

test.describe("Poll timeout", () => {
  test("enters timeout state without waiting five minutes", async ({ page }) => {
    await page.clock.install();

    // Mock status to always return pending (never completes)
    await page.route(`${API_BASE}/api/check/${TEST_TASK_ID}`, (route) => {
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(mockPendingStatus),
      });
    });

    await page.goto(`/check/${TEST_TASK_ID}`);

    // Verify polling starts
    await expect(page.locator(".card")).toContainText("排队中", { timeout: 10_000 });

    // Jump past the production timeout. Only the due recursive timer fires.
    await page.clock.fastForward(300_001);
    await expect(page.locator(".page-title")).toContainText("检测超时");
    await expect(page.locator(".error-box")).toContainText("检测超时");
    await page.getByRole("link", { name: "重新检测" }).click();
    await expect(page).toHaveURL("/");
    await expect(page.getByLabel("GitHub 仓库地址")).toHaveValue("");
  });
});

// ---------------------------------------------------------------------------
// Task ID changes
// ---------------------------------------------------------------------------

test.describe("Task ID changes", () => {
  test("stops the old task and polls only the new task", async ({ page }) => {
    const nextTaskId = "12345678-1234-1234-1234-123456789abc";
    let oldTaskRequests = 0;
    let newTaskRequests = 0;

    await page.route(`${API_BASE}/api/check/${TEST_TASK_ID}`, (route) => {
      oldTaskRequests++;
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(mockPendingStatus),
      });
    });
    await page.route(`${API_BASE}/api/check/${nextTaskId}`, (route) => {
      newTaskRequests++;
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          ...mockFailedStatus,
          task_id: nextTaskId,
        }),
      });
    });

    await page.goto(`/check/${TEST_TASK_ID}`);
    await expect(page.locator(".card")).toContainText("排队中");
    const oldCountAtNavigation = oldTaskRequests;

    await page.goto(`/check/${nextTaskId}`);
    await expect(page.locator(".page-title")).toContainText("检测失败");
    await page.waitForTimeout(2500);

    expect(oldTaskRequests).toBe(oldCountAtNavigation);
    expect(newTaskRequests).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// Test 14: Page unload stops polling
// ---------------------------------------------------------------------------

test.describe("Page unload stops polling", () => {
  test("stops polling when navigating away from check page", async ({ page }) => {
    let pollCount = 0;

    await page.route(`${API_BASE}/api/check/${TEST_TASK_ID}`, (route) => {
      pollCount++;
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(mockPendingStatus),
      });
    });

    await page.goto(`/check/${TEST_TASK_ID}`);

    // Wait for at least one poll
    await expect(page.locator(".card")).toContainText("排队中", { timeout: 10_000 });
    await page.waitForTimeout(1000);

    const countBeforeNavigation = pollCount;

    // Navigate away (simulates page unload)
    await page.goto("/");

    // Wait enough time for at least one more poll cycle (2s interval)
    await page.waitForTimeout(5000);

    // Verify no more polls occurred after navigation
    expect(pollCount).toBe(countBeforeNavigation);
  });
});

// ---------------------------------------------------------------------------
// Test 15: No overlapping poll requests
// ---------------------------------------------------------------------------

test.describe("No overlapping requests", () => {
  test("does not send overlapping poll requests", async ({ page }) => {
    let inFlight = false;
    let overlapDetected = false;
    let totalRequests = 0;

    await page.route(`${API_BASE}/api/check/${TEST_TASK_ID}`, async (route) => {
      totalRequests++;

      // Check for overlap
      if (inFlight) {
        overlapDetected = true;
      }
      inFlight = true;

      // Delay response to ensure the next poll would be scheduled
      // only after this one completes
      await new Promise((resolve) => setTimeout(resolve, 1500));

      inFlight = false;

      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(mockPendingStatus),
      });
    });

    await page.goto(`/check/${TEST_TASK_ID}`);

    // Wait for multiple poll cycles
    await page.waitForTimeout(8000);

    // Verify at least 2 requests were made
    expect(totalRequests).toBeGreaterThanOrEqual(2);

    // Verify no overlapping requests
    expect(overlapDetected).toBe(false);
  });
});
