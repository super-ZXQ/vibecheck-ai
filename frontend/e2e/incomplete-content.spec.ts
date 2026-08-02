import { expect, test } from "@playwright/test";

import {
  TEST_TASK_ID,
  mockAllResults,
  mockCompletedStatus,
  mockMultidimensionalScanResult,
  mockScanResult,
  mockTaskStatusSequence,
} from "./fixtures";


test("shows dimension counts, filters with fresh pagination, and expands advice", async ({ page }) => {
  await mockTaskStatusSequence(page, [mockCompletedStatus]);
  await mockAllResults(page, { scanResultBody: mockMultidimensionalScanResult });
  await page.goto(`/check/${TEST_TASK_ID}`);

  await expect(page.locator(".page-title")).toContainText("检测结果", { timeout: 15_000 });
  await expect(page.getByTestId("sensitive-dimension-count")).toContainText("26");
  await expect(page.getByTestId("incomplete-dimension-count")).toContainText("6");
  await expect(page.getByText("未完成内容暂不计入安全评分。")).toBeVisible();

  await page.getByRole("button", { name: "敏感信息", exact: true }).click();
  await expect(page.locator(".findings-table tbody tr")).toHaveCount(25);
  await expect(page.locator(".pagination")).toContainText("共 26 条");

  await page.getByRole("button", { name: "未完成内容", exact: true }).click();
  await expect(page.locator(".findings-table tbody tr")).toHaveCount(6);
  await expect(page.locator(".pagination")).toContainText("1 / 1");
  await expect(page.locator(".dimension-incomplete_content")).toHaveCount(6);

  await page.getByRole("button", { name: "查看建议" }).first().click();
  await expect(page.getByText("An unfinished construct remains in production source code.")).toBeVisible();
  await expect(page.getByText("Complete the implementation before shipping.")).toBeVisible();
});


test("treats a legacy result without dimensions as sensitive data", async ({ page }) => {
  const legacyResult = {
    ...mockScanResult,
    schema_version: 1,
    findings: mockScanResult.findings.map(({ dimension: _dimension, ...finding }) => finding),
    summary: Object.fromEntries(
      Object.entries(mockScanResult.summary).filter(([key]) => key !== "dimension_counts"),
    ),
  };
  await mockTaskStatusSequence(page, [mockCompletedStatus]);
  await mockAllResults(page, { scanResultBody: legacyResult });
  await page.goto(`/check/${TEST_TASK_ID}`);

  await expect(page.locator(".page-title")).toContainText("检测结果", { timeout: 15_000 });
  await expect(page.getByTestId("sensitive-dimension-count")).toContainText("30");
  await expect(page.getByTestId("incomplete-dimension-count")).toContainText("0");
  await page.getByRole("button", { name: "未完成内容", exact: true }).click();
  await expect(page.getByText("当前维度没有发现问题。")).toBeVisible();
  await page.getByRole("button", { name: "敏感信息", exact: true }).click();
  await expect(page.locator(".findings-table tbody tr")).toHaveCount(25);
});
