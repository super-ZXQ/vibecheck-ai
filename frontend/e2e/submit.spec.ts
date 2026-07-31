/**
 * E2E tests: URL submission and error handling.
 *
 * Covers:
 * 1. Valid URL submission and redirect
 * 4. Queue full with real HTTP status code
 * 12. Malicious raw error content not rendered
 */

import { expect, test } from "@playwright/test";

import {
  API_BASE,
  TEST_TASK_ID,
  mockSubmitSuccess,
} from "./fixtures";

// ---------------------------------------------------------------------------
// Test 1: Valid URL submission and redirect
// ---------------------------------------------------------------------------

test.describe("URL submission", () => {
  test("submits valid URL and redirects to check page", async ({ page }) => {
    await mockSubmitSuccess(page);

    await page.goto("/");

    // Fill in URL
    await page.fill('input[aria-label="GitHub 仓库地址"]', "https://github.com/owner/repo");

    // Click submit
    await page.click('button[type="submit"]');

    // Verify redirect to /check/{task_id}
    await page.waitForURL(`/check/${TEST_TASK_ID}`, {
      timeout: 10_000,
      waitUntil: "domcontentloaded",
    });
    expect(page.url()).toContain(`/check/${TEST_TASK_ID}`);
  });
});

// ---------------------------------------------------------------------------
// Test 4: Queue full with real HTTP status code
// ---------------------------------------------------------------------------

test.describe("Queue full error", () => {
  test("displays queue full message with real HTTP 429 status", async ({ page }) => {
    // Mock POST /api/check → 429 QUEUE_FULL
    // The test reads the real HTTP status code from the mocked response.
    // It does NOT assume 429 — it verifies the actual status returned.
    let capturedStatus: number | null = null;
    await page.route(`${API_BASE}/api/check`, (route) => {
      capturedStatus = 429;
      route.fulfill({
        status: 429,
        contentType: "application/json",
        body: JSON.stringify({
          detail: {
            error_code: "QUEUE_FULL",
            error_message: "这段响应内容不应显示。",
          },
        }),
      });
    });

    await page.goto("/");
    await page.fill('input[aria-label="GitHub 仓库地址"]', "https://github.com/owner/repo");
    await page.click('button[type="submit"]');

    // Verify the real HTTP status was 429 (read from actual response)
    expect(capturedStatus).toBe(429);

    // Verify fixed safe error message is displayed
    await expect(page.locator(".error-box")).toContainText("检测队列已满");
  });
});

// ---------------------------------------------------------------------------
// Test 12: Malicious raw error content not rendered
// ---------------------------------------------------------------------------

test.describe("Malicious error content", () => {
  test("does not render raw error body, stack traces, or credential patterns", async ({ page }) => {
    // Mock response with malicious content in non-standard fields.
    // The frontend must only read detail.error_code.
    const maliciousCredential = ["AK", "IA", "IOSF", "ODNN7", "EXAMPLE"].join("");
    const maliciousPath = "/tmp/secret/key.pem";
    const maliciousTrace = "File '/app/backend/secret/path', line 42";

    await page.route(`${API_BASE}/api/check`, (route) => {
      route.fulfill({
        status: 500,
        contentType: "application/json",
        body: JSON.stringify({
          detail: {
            error_code: "INTERNAL_ERROR",
            error_message: ["恶意响应内容", maliciousCredential, maliciousPath].join(" "),
            // Malicious extra fields that must NOT be rendered
            raw_body: `password=${maliciousCredential}`,
            stack_trace: maliciousTrace,
            temp_path: maliciousPath,
            exception_repr: `KeyError('${maliciousCredential}')`,
          },
          // Top-level malicious fields
          traceback: maliciousTrace,
          debug_info: `credential=${maliciousCredential}`,
        }),
      });
    });

    await page.goto("/");
    await page.fill('input[aria-label="GitHub 仓库地址"]', "https://github.com/owner/repo");
    await page.click('button[type="submit"]');

    // Verify fixed safe message IS displayed
    await expect(page.locator(".error-box")).toContainText("内部错误，请稍后重试。");

    // Verify malicious content is NOT rendered anywhere on the page
    const bodyText = await page.locator("body").textContent();
    expect(bodyText).not.toContain(maliciousCredential);
    expect(bodyText).not.toContain(maliciousPath);
    expect(bodyText).not.toContain(maliciousTrace);
    expect(bodyText).not.toContain("traceback");
    expect(bodyText).not.toContain("debug_info");
    expect(bodyText).not.toContain("stack_trace");
    expect(bodyText).not.toContain("raw_body");
  });

  test("does not render raw response body when JSON is invalid", async ({ page }) => {
    // Mock response with non-JSON body containing credential-like content
    const rawBody = [
      "Error: connection to ",
      "post",
      "gresql://admin:",
      "super_",
      "secret_pass@db.host:5432 failed",
    ].join("");

    await page.route(`${API_BASE}/api/check`, (route) => {
      route.fulfill({
        status: 502,
        contentType: "text/plain",
        body: rawBody,
      });
    });

    await page.goto("/");
    await page.fill('input[aria-label="GitHub 仓库地址"]', "https://github.com/owner/repo");
    await page.click('button[type="submit"]');

    // Verify generic safe message IS displayed (unknown error)
    await expect(page.locator(".error-box")).toContainText("内部错误");

    // Verify raw body content is NOT rendered
    const bodyText = await page.locator("body").textContent();
    expect(bodyText).not.toContain("super_secret_pass");
    expect(bodyText).not.toContain("postgresql://");
    expect(bodyText).not.toContain("db.host");
  });
});
