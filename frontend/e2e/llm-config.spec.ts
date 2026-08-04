/**
 * E2E tests: per-user LLM settings.
 *
 * All API calls are mocked via page.route — no real backend involved.
 *
 * Covers:
 * 1. Saving LLM config persists to localStorage and marks the button
 * 2. A detection submission carries the X-LLM-* headers
 * 3. Clearing the config drops the headers again
 */

import { expect, test } from "@playwright/test";

import {
  API_BASE,
  TEST_TASK_ID,
} from "./fixtures";

const LLM_CONFIG_KEY = "vibecheck.llm-config";

async function openSettings(page: import("@playwright/test").Page) {
  await page.getByRole("button", { name: "LLM 设置" }).click();
  await expect(page.getByRole("dialog", { name: "LLM 设置" })).toBeVisible();
}

async function fillConfig(page: import("@playwright/test").Page) {
  await page.getByLabel("API Key").fill("sk-user-test-key");
  await page.getByLabel("Base URL").fill("https://api.user.example.com/v1");
  await page.getByLabel("模型").fill("user-model");
  await page.getByRole("button", { name: "保存" }).click();
}

test.describe("LLM settings", () => {
  test("saves the config to localStorage and marks the button", async ({
    page,
  }) => {
    await page.goto("/");

    await openSettings(page);
    await fillConfig(page);

    const stored = await page.evaluate((key) => {
      return window.localStorage.getItem(key);
    }, LLM_CONFIG_KEY);
    expect(stored).not.toBeNull();
    const parsed = JSON.parse(stored ?? "{}");
    expect(parsed.apiKey).toBe("sk-user-test-key");
    expect(parsed.baseUrl).toBe("https://api.user.example.com/v1");
    expect(parsed.model).toBe("user-model");

    // Reload: the button keeps its configured state.
    await page.reload();
    const cls = await page
      .getByRole("button", { name: "LLM 设置" })
      .getAttribute("class");
    expect(cls).toContain("llm-settings-button-configured");
  });

  test("submission carries X-LLM-* headers when configured", async ({
    page,
  }) => {
    let capturedHeaders: Record<string, string> | null = null;
    await page.route(`${API_BASE}/api/check`, (route) => {
      capturedHeaders = route.request().headers();
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

    await page.goto("/");
    await openSettings(page);
    await fillConfig(page);

    await page.getByLabel("GitHub 仓库地址").fill("super-ZXQ/vibecheck-ai");
    await page.getByRole("button", { name: "开始检测" }).click();
    await page.waitForURL(`/check/${TEST_TASK_ID}`);

    expect(capturedHeaders).not.toBeNull();
    expect(capturedHeaders?.["x-llm-api-key"]).toBe("sk-user-test-key");
    expect(capturedHeaders?.["x-llm-base-url"]).toBe(
      "https://api.user.example.com/v1",
    );
    expect(capturedHeaders?.["x-llm-model"]).toBe("user-model");
  });

  test("clearing the config drops the headers", async ({ page }) => {
    let capturedHeaders: Record<string, string> | null = null;
    await page.route(`${API_BASE}/api/check`, (route) => {
      capturedHeaders = route.request().headers();
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

    // Seed a stored config first, then clear it in the UI.
    await page.goto("/");
    await openSettings(page);
    await fillConfig(page);

    await openSettings(page);
    await page.getByRole("button", { name: "清除" }).click();

    await page.getByLabel("GitHub 仓库地址").fill("super-ZXQ/vibecheck-ai");
    await page.getByRole("button", { name: "开始检测" }).click();
    await page.waitForURL(`/check/${TEST_TASK_ID}`);

    expect(capturedHeaders).not.toBeNull();
    expect(capturedHeaders?.["x-llm-api-key"]).toBeUndefined();
    expect(capturedHeaders?.["x-llm-base-url"]).toBeUndefined();
    expect(capturedHeaders?.["x-llm-model"]).toBeUndefined();
  });
});
