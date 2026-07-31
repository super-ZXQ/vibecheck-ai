import { expect, test } from "@playwright/test";
import type { Page, Route } from "@playwright/test";

import { NETWORK_ERROR_MESSAGE } from "../lib/error-messages";
import {
  API_BASE,
  TEST_TASK_ID,
  mockAssessment,
  mockCompletedStatus,
  mockFailedStatus,
  mockPendingStatus,
  mockRepairPlan,
  mockScanResult,
} from "./fixtures";

const RESULT_ENDPOINTS = {
  scan: {
    path: "result",
    body: mockScanResult,
    tabIndex: 0,
  },
  assessment: {
    path: "assessment",
    body: mockAssessment,
    tabIndex: 1,
  },
  repair: {
    path: "repair-plan",
    body: mockRepairPlan,
    tabIndex: 2,
  },
} as const;

function fulfillJson(route: Route, body: unknown, status = 200) {
  return route.fulfill({
    status,
    contentType: "application/json",
    body: JSON.stringify(body),
  });
}

async function mockCompletedTaskWithHungResult(
  page: Page,
  hungResult: keyof typeof RESULT_ENDPOINTS,
) {
  await page.route(`${API_BASE}/api/check/${TEST_TASK_ID}`, (route) =>
    fulfillJson(route, mockCompletedStatus),
  );

  let hungRequests = 0;
  for (const [key, endpoint] of Object.entries(RESULT_ENDPOINTS)) {
    await page.route(
      `${API_BASE}/api/check/${TEST_TASK_ID}/${endpoint.path}`,
      (route) => {
        if (key === hungResult) {
          hungRequests++;
          return;
        }
        return fulfillJson(route, endpoint.body);
      },
    );
  }

  return () => hungRequests;
}

test("submit request timeout leaves submitting and shows the fixed network error", async ({
  page,
}) => {
  await page.clock.install();
  let submitRequests = 0;
  await page.route(`${API_BASE}/api/check`, () => {
    submitRequests++;
  });

  await page.goto("/");
  await page.getByLabel("GitHub 仓库地址").fill("https://github.com/owner/repo");
  await page.getByRole("button", { name: "开始检测" }).click();
  await expect.poll(() => submitRequests).toBe(1);

  await page.clock.fastForward(10_001);

  await expect(page.locator(".error-box")).toHaveText(NETWORK_ERROR_MESSAGE);
  await expect(page.getByRole("button", { name: "开始检测" })).toBeEnabled();
});

test("one status request timeout schedules another poll and can recover", async ({
  page,
}) => {
  await page.clock.install();
  let statusRequests = 0;
  await page.route(`${API_BASE}/api/check/${TEST_TASK_ID}`, (route) => {
    statusRequests++;
    if (statusRequests === 1) {
      return;
    }
    return fulfillJson(route, mockCompletedStatus);
  });

  for (const endpoint of Object.values(RESULT_ENDPOINTS)) {
    await page.route(
      `${API_BASE}/api/check/${TEST_TASK_ID}/${endpoint.path}`,
      (route) => fulfillJson(route, endpoint.body),
    );
  }

  await page.goto(`/check/${TEST_TASK_ID}`);
  await expect.poll(() => statusRequests).toBe(1);

  await page.clock.fastForward(10_001);
  await page.clock.fastForward(2_001);

  await expect(page.locator(".tabs")).toBeVisible();
  expect(statusRequests).toBeGreaterThanOrEqual(2);
});

test("the hard deadline aborts the active status request and stops later polls", async ({
  page,
}) => {
  await page.clock.install();
  let statusRequests = 0;
  let failedStatusRequests = 0;
  let firstStatusRoute: Route | null = null;

  page.on("requestfailed", (request) => {
    if (request.url() === `${API_BASE}/api/check/${TEST_TASK_ID}`) {
      failedStatusRequests++;
    }
  });
  await page.route(`${API_BASE}/api/check/${TEST_TASK_ID}`, (route) => {
    statusRequests++;
    if (statusRequests === 1) {
      firstStatusRoute = route;
    }
  });

  await page.goto(`/check/${TEST_TASK_ID}`);
  await expect.poll(() => statusRequests).toBe(1);

  await page.clock.fastForward(1);
  if (!firstStatusRoute) throw new Error("Expected the initial status request");
  await fulfillJson(firstStatusRoute, mockPendingStatus);

  await page.clock.fastForward(298_999);
  await expect(page.locator(".page-title")).toHaveText("检测进行中");
  const failuresBeforeDeadline = failedStatusRequests;

  await page.clock.fastForward(1_000);

  await expect(page.locator(".page-title")).toHaveText("检测超时");
  await expect
    .poll(() => failedStatusRequests)
    .toBeGreaterThan(failuresBeforeDeadline);

  const requestsAtDeadline = statusRequests;
  await page.clock.fastForward(30_000);
  expect(statusRequests).toBe(requestsAtDeadline);
});

test("completion before the hard deadline keeps result loading alive", async ({
  page,
}) => {
  await page.clock.install();
  let statusRequests = 0;
  let firstStatusRoute: Route | null = null;
  let activeStatusRoute: Route | null = null;
  const resultRoutes = new Map<string, Route>();

  await page.route(`${API_BASE}/api/check/${TEST_TASK_ID}`, (route) => {
    statusRequests++;
    if (statusRequests === 1) {
      firstStatusRoute = route;
    } else {
      activeStatusRoute = route;
    }
  });
  for (const endpoint of Object.values(RESULT_ENDPOINTS)) {
    await page.route(
      `${API_BASE}/api/check/${TEST_TASK_ID}/${endpoint.path}`,
      (route) => {
        resultRoutes.set(endpoint.path, route);
      },
    );
  }

  await page.goto(`/check/${TEST_TASK_ID}`);
  await expect.poll(() => statusRequests).toBe(1);

  await page.clock.fastForward(1);
  if (!firstStatusRoute) throw new Error("Expected the initial status request");
  await fulfillJson(firstStatusRoute, mockPendingStatus);

  await page.clock.fastForward(290_000);
  await expect.poll(() => activeStatusRoute).not.toBeNull();
  await page.clock.fastForward(8_999);

  if (!activeStatusRoute) throw new Error("Expected an active status request");
  await fulfillJson(activeStatusRoute, mockCompletedStatus);
  await expect.poll(() => resultRoutes.size).toBe(3);

  await page.clock.fastForward(2_000);
  await Promise.all(
    Object.values(RESULT_ENDPOINTS).map((endpoint) => {
      const route = resultRoutes.get(endpoint.path);
      if (!route) throw new Error(`Missing ${endpoint.path} request`);
      return fulfillJson(route, endpoint.body);
    }),
  );

  await expect(page.locator(".tabs")).toBeVisible();
  await expect(page.locator(".page-title")).toHaveText("检测结果");
});

test("failed status clears the hard deadline", async ({ page }) => {
  await page.clock.install();
  let statusRequests = 0;
  await page.route(`${API_BASE}/api/check/${TEST_TASK_ID}`, (route) => {
    statusRequests++;
    return fulfillJson(route, mockFailedStatus);
  });

  await page.goto(`/check/${TEST_TASK_ID}`);
  await expect(page.locator(".page-title")).toHaveText("检测失败");
  const requestsAfterFailure = statusRequests;

  await page.clock.fastForward(300_001);

  await expect(page.locator(".page-title")).toHaveText("检测失败");
  expect(statusRequests).toBe(requestsAfterFailure);
});

test("an old task deadline cannot stop the replacement task session", async ({
  page,
}) => {
  await page.clock.install();
  const nextTaskId = "12345678-1234-1234-1234-123456789abc";
  let oldTaskRequests = 0;
  let newTaskRequests = 0;

  await page.route(`${API_BASE}/api/check/${TEST_TASK_ID}`, () => {
    oldTaskRequests++;
  });
  await page.route(`${API_BASE}/api/check/${nextTaskId}`, () => {
    newTaskRequests++;
  });

  await page.goto(`/check/${TEST_TASK_ID}`);
  await expect.poll(() => oldTaskRequests).toBe(1);
  await page.clock.fastForward(1_000);

  await page.goto(`/check/${nextTaskId}`);
  await expect.poll(() => newTaskRequests).toBe(1);
  const oldRequestsAfterReplacement = oldTaskRequests;

  await page.clock.fastForward(299_000);

  await expect(page.locator(".page-title")).toHaveText("检测进行中");
  expect(oldTaskRequests).toBe(oldRequestsAfterReplacement);
});

for (const [hungResult, endpoint] of Object.entries(RESULT_ENDPOINTS)) {
  test(`${hungResult} request timeout marks only its tab as error`, async ({
    page,
  }) => {
    await page.clock.install();
    const getHungRequests = await mockCompletedTaskWithHungResult(
      page,
      hungResult as keyof typeof RESULT_ENDPOINTS,
    );

    await page.goto(`/check/${TEST_TASK_ID}`);
    await expect.poll(getHungRequests).toBe(1);
    await page.clock.fastForward(10_001);

    const tabs = page.locator(".tab");
    await expect(tabs).toHaveCount(3);
    await expect(tabs.nth(endpoint.tabIndex)).toContainText("!");

    for (const availableEndpoint of Object.values(RESULT_ENDPOINTS)) {
      if (availableEndpoint.tabIndex !== endpoint.tabIndex) {
        await expect(tabs.nth(availableEndpoint.tabIndex)).not.toContainText("!");
      }
    }

    await tabs.nth(endpoint.tabIndex).click();
    await expect(page.locator(".error-box")).toBeVisible();

    if (hungResult !== "scan") {
      await tabs.nth(0).click();
      await expect(page.locator(".findings-table")).toBeVisible();
    }
    if (hungResult !== "assessment") {
      await tabs.nth(1).click();
      await expect(page.locator(".score-number").first()).toHaveText("45");
    }
    if (hungResult !== "repair") {
      await tabs.nth(2).click();
      await expect(page.locator(".repair-group")).toBeVisible();
    }
  });
}

test("caller abort on page unload stays silent and sends no later request", async ({
  page,
}) => {
  await page.clock.install();
  let statusRequests = 0;
  await page.route(`${API_BASE}/api/check/${TEST_TASK_ID}`, () => {
    statusRequests++;
  });

  await page.goto(`/check/${TEST_TASK_ID}`);
  await expect.poll(() => statusRequests).toBe(1);

  await page.goto("/");
  await page.clock.fastForward(300_001);

  await expect(page.locator(".error-box")).toHaveCount(0);
  expect(statusRequests).toBe(1);
});
