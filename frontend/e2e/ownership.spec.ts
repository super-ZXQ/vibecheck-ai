/**
 * E2E tests: anonymous task ownership key.
 *
 * Covers:
 * 1. Submission sends X-Submitter-Key and the same browser keeps using it
 *    when it polls the task it created.
 * 2. The key survives a reload (it is the only thing that lets this browser
 *    read its own tasks later).
 * 3. The key stays in the request header — never in the URL or the page.
 */

import { expect, test } from "@playwright/test";

import { SUBMITTER_KEY_STORAGE } from "../lib/submitter-key.mjs";
import { API_BASE, TEST_TASK_ID, mockPendingStatus } from "./fixtures";

test.describe("task ownership key", () => {
  test("submit and poll carry the same anonymous key", async ({ page }) => {
    const keys: { submit?: string; poll?: string } = {};

    await page.route(`${API_BASE}/api/check`, (route) => {
      keys.submit = route.request().headers()["x-submitter-key"];
      route.fulfill({
        status: 202,
        contentType: "application/json",
        body: JSON.stringify({
          task_id: TEST_TASK_ID,
          status: "pending",
          check_url: `/api/check/${TEST_TASK_ID}`,
        }),
      });
    });
    await page.route(`${API_BASE}/api/check/${TEST_TASK_ID}`, (route) => {
      keys.poll = route.request().headers()["x-submitter-key"];
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(mockPendingStatus),
      });
    });

    await page.goto("/");
    await page
      .getByLabel("GitHub 仓库地址")
      .fill("https://github.com/owner/repo");
    await page.getByRole("button", { name: "开始检测" }).click();
    await page.waitForURL(`/check/${TEST_TASK_ID}`);
    await expect(page.getByText("正在获取任务状态")).toBeVisible({ timeout: 10_000 });

    // Well-formed for the backend pattern (16-64 URL-safe characters).
    expect(keys.submit).toMatch(/^[a-z0-9]{16,64}$/);
    expect(keys.poll).toBe(keys.submit);
  });

  test("the key is stored locally and survives a reload", async ({ page }) => {
    let submittedKey: string | undefined;
    await page.route(`${API_BASE}/api/check`, (route) => {
      submittedKey = route.request().headers()["x-submitter-key"];
      route.fulfill({
        status: 202,
        contentType: "application/json",
        body: JSON.stringify({
          task_id: TEST_TASK_ID,
          status: "pending",
          check_url: `/api/check/${TEST_TASK_ID}`,
        }),
      });
    });
    await page.route(`${API_BASE}/api/check/${TEST_TASK_ID}`, (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(mockPendingStatus),
      }),
    );

    await page.goto("/");
    await page
      .getByLabel("GitHub 仓库地址")
      .fill("https://github.com/owner/repo");
    await page.getByRole("button", { name: "开始检测" }).click();
    await page.waitForURL(`/check/${TEST_TASK_ID}`);

    await page.reload({ waitUntil: "domcontentloaded" });
    const stored = await page.evaluate(
      (key) => window.localStorage.getItem(key),
      SUBMITTER_KEY_STORAGE,
    );
    expect(stored).toBe(submittedKey);
  });

  test("the key never reaches the URL or the page content", async ({ page }) => {
    let submittedKey = "";
    await page.route(`${API_BASE}/api/check`, (route) => {
      submittedKey = route.request().headers()["x-submitter-key"] ?? "";
      route.fulfill({
        status: 202,
        contentType: "application/json",
        body: JSON.stringify({
          task_id: TEST_TASK_ID,
          status: "pending",
          check_url: `/api/check/${TEST_TASK_ID}`,
        }),
      });
    });
    await page.route(`${API_BASE}/api/check/${TEST_TASK_ID}`, (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(mockPendingStatus),
      }),
    );

    await page.goto("/");
    await page
      .getByLabel("GitHub 仓库地址")
      .fill("https://github.com/owner/repo");
    await page.getByRole("button", { name: "开始检测" }).click();
    await page.waitForURL(`/check/${TEST_TASK_ID}`);
    await expect(page.getByText("正在获取任务状态")).toBeVisible({ timeout: 10_000 });

    expect(submittedKey.length).toBeGreaterThan(0);
    expect(page.url()).not.toContain(submittedKey);
    expect(await page.content()).not.toContain(submittedKey);
  });
});
