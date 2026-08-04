/**
 * E2E tests: oversized-repository upload guidance.
 *
 * All API calls are mocked via page.route — no real backend involved.
 *
 * Covers:
 * 1. DOWNLOAD_TOO_LARGE failure shows the upload guidance card
 * 2. EXTRACTION_LIMIT_EXCEEDED failure shows the upload guidance card
 * 3. Other failure codes do NOT show the guidance card
 * 4. "改用本地上传" navigates to /?upload=1, which highlights the upload card
 */

import { expect, test } from "@playwright/test";

import {
  API_BASE,
  TEST_TASK_ID,
  mockFailedStatus,
  mockTaskStatus,
} from "./fixtures";

async function mockFailedWithCode(page: import("@playwright/test").Page, errorCode: string) {
  await mockTaskStatus(page, {
    ...mockFailedStatus,
    error_code: errorCode,
  });
}

test.describe("Upload guidance", () => {
  test("shows guidance for DOWNLOAD_TOO_LARGE", async ({ page }) => {
    await mockFailedWithCode(page, "DOWNLOAD_TOO_LARGE");
    await page.goto(`/check/${TEST_TASK_ID}`);

    await expect(
      page.getByText("该仓库超出下载大小限制"),
    ).toBeVisible();
    await expect(page.getByRole("link", { name: "改用本地上传" })).toBeVisible();
  });

  test("shows guidance for EXTRACTION_LIMIT_EXCEEDED", async ({ page }) => {
    await mockFailedWithCode(page, "EXTRACTION_LIMIT_EXCEEDED");
    await page.goto(`/check/${TEST_TASK_ID}`);

    await expect(
      page.getByText("该仓库超出下载大小限制"),
    ).toBeVisible();
  });

  test("does not show guidance for other failures", async ({ page }) => {
    await mockFailedWithCode(page, "REPOSITORY_NOT_FOUND");
    await page.goto(`/check/${TEST_TASK_ID}`);

    await expect(page.getByText("检测失败")).toBeVisible();
    await expect(page.getByText("该仓库超出下载大小限制")).toHaveCount(0);
    await expect(
      page.getByRole("link", { name: "改用本地上传" }),
    ).toHaveCount(0);
  });

  test("guidance link lands on homepage and highlights the upload card", async ({
    page,
  }) => {
    await mockFailedWithCode(page, "DOWNLOAD_TOO_LARGE");
    await page.goto(`/check/${TEST_TASK_ID}`);

    await page.getByRole("link", { name: "改用本地上传" }).click();
    await page.waitForURL("**/?upload=1");

    const card = page.locator(".upload-card");
    await expect(card).toHaveClass(/upload-card-highlight/);
    await expect(page.getByText("或上传本地文件检测")).toBeVisible();
  });
});
