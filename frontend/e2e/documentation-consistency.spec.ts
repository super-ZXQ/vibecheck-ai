import { expect, test } from "@playwright/test";

import {
  TEST_TASK_ID,
  mockAllResults,
  mockCompletedStatus,
  mockFiveDimensionalScanResult,
  mockFourDimensionalScanResult,
  mockTaskStatusSequence,
} from "./fixtures";


test("shows and filters documentation findings with fixed advice", async ({ page }) => {
  await mockTaskStatusSequence(page, [mockCompletedStatus]);
  await mockAllResults(page, { scanResultBody: mockFiveDimensionalScanResult });
  await page.goto(`/check/${TEST_TASK_ID}`);

  await expect(page.locator(".page-title")).toContainText("检测结果", { timeout: 15_000 });
  await expect(page.getByTestId("documentation-dimension-count")).toContainText("27");
  await expect(page.getByText(
    "未完成内容、可部署性、基础安全和文档一致性暂不计入安全评分。",
  )).toBeVisible();

  await page.getByRole("button", { name: "文档一致性", exact: true }).click();
  await expect(page.locator(".findings-table tbody tr")).toHaveCount(25);
  await expect(page.locator(".dimension-documentation_consistency")).toHaveCount(25);
  await expect(page.locator(".pagination")).toContainText("共 27 条");

  await page.locator(".pagination button").last().click();
  await expect(page.locator(".findings-table tbody tr")).toHaveCount(2);

  await page.getByRole("button", { name: "文档一致性", exact: true }).click();
  await page.getByRole("button", { name: "查看建议" }).first().click();
  await expect(page.getByText(
    "A documented repository fact does not match the project.",
  )).toBeVisible();
  await expect(page.getByText(
    "Update the documentation or restore the referenced project element.",
  )).toBeVisible();
});


test("treats a P0-12 v2 result without documentation count as zero", async ({ page }) => {
  const oldV2 = {
    ...mockFourDimensionalScanResult,
    summary: {
      ...mockFourDimensionalScanResult.summary,
      dimension_counts: {
        sensitive_data_security: 26,
        incomplete_content: 6,
        deployability_production: 27,
        basic_security: 27,
      },
    },
  };
  await mockTaskStatusSequence(page, [mockCompletedStatus]);
  await mockAllResults(page, { scanResultBody: oldV2 });
  await page.goto(`/check/${TEST_TASK_ID}`);

  await expect(page.locator(".page-title")).toContainText("检测结果", { timeout: 15_000 });
  await expect(page.getByTestId("documentation-dimension-count")).toContainText("0");
  await page.getByRole("button", { name: "文档一致性", exact: true }).click();
  await expect(page.getByText("当前维度没有发现问题。")).toBeVisible();
});
