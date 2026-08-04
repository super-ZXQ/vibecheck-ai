/**
 * E2E tests: local archive / folder upload submission.
 *
 * All API calls are mocked via page.route — no real backend involved.
 *
 * Covers:
 * 1. ZIP archive upload submits multipart (mode=archive) and redirects
 * 2. Folder upload submits each file with its relative path
 * 3. Rejected upload shows a fixed safe message
 */

import { expect, test } from "@playwright/test";

import {
  API_BASE,
  TEST_TASK_ID,
  mockUploadError,
  mockUploadSuccess,
} from "./fixtures";

const ZIP_MAGIC = Buffer.from([0x50, 0x4b, 0x03, 0x04]);

test.describe("Local upload submission", () => {
  test("submits a ZIP archive and redirects to the check page", async ({
    page,
  }) => {
    let captured: string | null = null;
    await page.route(`${API_BASE}/api/check/upload`, async (route) => {
      const buf = route.request().postDataBuffer();
      captured = buf ? buf.toString("utf8") : null;
      await route.fulfill({
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
    await page.setInputFiles('input[aria-label="上传压缩包"]', {
      name: "demo.zip",
      mimeType: "application/zip",
      buffer: ZIP_MAGIC,
    });

    // Selection summary appears before submitting.
    await expect(page.getByText(/已选择压缩包：demo\.zip/)).toBeVisible();

    await page.getByRole("button", { name: "上传检测" }).click();
    await page.waitForURL(`/check/${TEST_TASK_ID}`, {
      timeout: 10_000,
      waitUntil: "domcontentloaded",
    });

    expect(captured).not.toBeNull();
    expect(captured).toContain('name="mode"');
    expect(captured).toContain("demo.zip");
    expect(captured).toContain('name="file"');
  });

  test("submits a folder with relative paths", async ({ page }) => {
    let captured: string | null = null;
    await page.route(`${API_BASE}/api/check/upload`, async (route) => {
      const buf = route.request().postDataBuffer();
      captured = buf ? buf.toString("utf8") : null;
      await route.fulfill({
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
    await page.evaluate(() => {
      const input = document.querySelector(
        'input[aria-label="上传文件夹"]',
      ) as HTMLInputElement;
      const dt = new DataTransfer();
      const files: Array<{ name: string; content: string }> = [
        { name: "proj/README.md", content: "# Local Project\n" },
        { name: "proj/src/util.py", content: "def helper():\n    return 1\n" },
      ];
      for (const f of files) {
        const file = new File([f.content], f.name, { type: "text/plain" });
        Object.defineProperty(file, "webkitRelativePath", {
          value: f.name,
          configurable: true,
        });
        dt.items.add(file);
      }
      input.files = dt.files;
      input.dispatchEvent(new Event("change", { bubbles: true }));
    });

    await expect(page.getByText(/已选择文件夹：2 个文件/)).toBeVisible();

    await page.getByRole("button", { name: "上传检测" }).click();
    await page.waitForURL(`/check/${TEST_TASK_ID}`, {
      timeout: 10_000,
      waitUntil: "domcontentloaded",
    });

    expect(captured).not.toBeNull();
    expect(captured).toContain('name="mode"');
    expect(captured).toContain("proj/README.md");
    expect(captured).toContain("proj/src/util.py");
  });

  test("shows a fixed safe message when the upload is rejected", async ({
    page,
  }) => {
    await mockUploadError(page, 413, "UPLOAD_TOO_LARGE");

    await page.goto("/");
    await page.setInputFiles('input[aria-label="上传压缩包"]', {
      name: "big.zip",
      mimeType: "application/zip",
      buffer: ZIP_MAGIC,
    });
    await page.getByRole("button", { name: "上传检测" }).click();

    await expect(page.locator(".error-box")).toContainText(
      "上传内容超过大小限制",
    );
    // No raw error body is rendered.
    await expect(page.getByText("UPLOAD_TOO_LARGE")).toHaveCount(0);
  });
});
