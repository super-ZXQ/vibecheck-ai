import { expect, test } from "@playwright/test";

import {
  TEST_TASK_ID,
  mockAllResults,
  mockCompletedStatus,
  mockMultidimensionalScanResult,
  mockTaskStatusSequence,
  mockThreeDimensionalScanResult,
} from "./fixtures";


test("shows and filters deployability findings with fixed advice", async ({ page }) => {
  await mockTaskStatusSequence(page, [mockCompletedStatus]);
  await mockAllResults(page, { scanResultBody: mockThreeDimensionalScanResult });
  await page.goto(`/check/${TEST_TASK_ID}`);

  await expect(page.locator(".page-title")).toContainText("检测结果", { timeout: 15_000 });
  await expect(page.getByTestId("deployability-dimension-count")).toContainText("27");
  await expect(page.getByText("未完成内容和可部署性暂不计入安全评分。")).toBeVisible();

  await page.getByRole("button", { name: "可部署性", exact: true }).click();
  await expect(page.locator(".findings-table tbody tr")).toHaveCount(25);
  await expect(page.locator(".dimension-deployability_production")).toHaveCount(25);
  await expect(page.locator(".pagination")).toContainText("共 27 条");

  await page.locator(".pagination button").last().click();
  await expect(page.locator(".findings-table tbody tr")).toHaveCount(2);

  await page.getByRole("button", { name: "敏感信息", exact: true }).click();
  await expect(page.locator(".findings-table tbody tr")).toHaveCount(25);
  await expect(page.locator(".pagination")).toContainText("共 26 条");

  await page.getByRole("button", { name: "可部署性", exact: true }).click();

  await page.getByRole("button", { name: "查看建议" }).first().click();
  await expect(page.getByText("A production deployment prerequisite is missing.")).toBeVisible();
  await expect(page.getByText("Add the missing production configuration before deployment.")).toBeVisible();
});


test("treats a P0-10 v2 result without deployability count as zero", async ({ page }) => {
  const oldV2 = {
    ...mockMultidimensionalScanResult,
    summary: {
      ...mockMultidimensionalScanResult.summary,
      dimension_counts: {
        sensitive_data_security: 26,
        incomplete_content: 6,
      },
    },
  };
  await mockTaskStatusSequence(page, [mockCompletedStatus]);
  await mockAllResults(page, { scanResultBody: oldV2 });
  await page.goto(`/check/${TEST_TASK_ID}`);

  await expect(page.locator(".page-title")).toContainText("检测结果", { timeout: 15_000 });
  await expect(page.getByTestId("deployability-dimension-count")).toContainText("0");
  await page.getByRole("button", { name: "可部署性", exact: true }).click();
  await expect(page.getByText("当前维度没有发现问题。")).toBeVisible();
});
