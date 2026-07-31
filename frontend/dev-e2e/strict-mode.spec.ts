import { expect, test } from "@playwright/test";

import {
  API_BASE,
  TEST_TASK_ID,
  mockAllResults,
  mockCompletedStatus,
  mockPendingStatus,
  mockRunningStatus,
} from "../e2e/fixtures";

test("direct result URL keeps one polling session after Strict Mode replay", async ({
  page,
}) => {
  let firstRequestAt = 0;
  let inFlight = 0;
  let overlapAfterReplay = false;
  let statusRequests = 0;

  await page.route(`${API_BASE}/api/check/${TEST_TASK_ID}`, async (route) => {
    const now = Date.now();
    if (!firstRequestAt) firstRequestAt = now;
    if (now - firstRequestAt > 500 && inFlight > 0) {
      overlapAfterReplay = true;
    }

    inFlight++;
    statusRequests++;
    await new Promise((resolve) => setTimeout(resolve, 200));

    const elapsed = Date.now() - firstRequestAt;
    const response =
      elapsed < 500
        ? mockPendingStatus
        : elapsed < 2500
          ? mockRunningStatus
          : mockCompletedStatus;
    try {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(response),
      });
    } finally {
      inFlight--;
    }
  });
  await mockAllResults(page);

  await page.goto(`/check/${TEST_TASK_ID}`);

  await expect(page.locator(".card")).toContainText("排队中");
  await expect(page.locator(".page-title")).toContainText("检测结果", {
    timeout: 15_000,
  });
  await expect(page.locator("body")).not.toContainText("正在获取任务状态");

  expect(statusRequests).toBeGreaterThanOrEqual(3);
  expect(statusRequests).toBeLessThanOrEqual(5);
  expect(overlapAfterReplay).toBe(false);
});

test("task ID change stops the old Strict Mode polling session", async ({
  page,
}) => {
  const nextTaskId = "12345678-1234-1234-1234-123456789abc";
  let oldTaskRequests = 0;
  let newTaskRequests = 0;

  await page.route(`${API_BASE}/api/check/${TEST_TASK_ID}`, (route) => {
    oldTaskRequests++;
    return route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(mockPendingStatus),
    });
  });
  await page.route(`${API_BASE}/api/check/${nextTaskId}`, (route) => {
    newTaskRequests++;
    return route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        ...mockPendingStatus,
        task_id: nextTaskId,
      }),
    });
  });
  await mockAllResults(page);

  await page.goto(`/check/${TEST_TASK_ID}`);
  await expect(page.locator(".card")).toContainText("排队中");

  await page.goto(`/check/${nextTaskId}`);
  await expect.poll(() => newTaskRequests).toBeGreaterThanOrEqual(1);
  const oldCountAfterNavigation = oldTaskRequests;

  await page.waitForTimeout(2_500);

  expect(oldTaskRequests).toBe(oldCountAfterNavigation);
  expect(newTaskRequests).toBeGreaterThanOrEqual(1);
});

test("page unload aborts the Strict Mode session without a later poll", async ({
  page,
}) => {
  let statusRequests = 0;

  await page.route(`${API_BASE}/api/check/${TEST_TASK_ID}`, (route) => {
    statusRequests++;
    return route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(mockPendingStatus),
    });
  });

  await page.goto(`/check/${TEST_TASK_ID}`);
  await expect(page.locator(".card")).toContainText("排队中");

  await page.goto("/");
  const countAfterNavigation = statusRequests;
  await page.waitForTimeout(2_500);

  await expect(page.locator(".error-box")).toHaveCount(0);
  expect(statusRequests).toBe(countAfterNavigation);
});
