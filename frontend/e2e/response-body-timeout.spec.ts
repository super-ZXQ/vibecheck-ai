import { createServer } from "node:http";
import type { IncomingMessage, Server, ServerResponse } from "node:http";

import { expect, test } from "@playwright/test";

import {
  getErrorMessage,
  NETWORK_ERROR_MESSAGE,
} from "../lib/error-messages";
import {
  TEST_TASK_ID,
  mockAssessment,
  mockCompletedStatus,
  mockRepairPlan,
  mockScanResult,
} from "./fixtures";

type ResponseHandler = (
  request: IncomingMessage,
  response: ServerResponse,
) => void;

const FRONTEND_ORIGIN = "http://localhost:3000";
const RAW_RESPONSE_MARKER = "RAW_RESPONSE_MARKER";

let server: Server;
let responseHandler: ResponseHandler;
let closedStreamingResponses = 0;
const openStreamingResponses = new Set<ServerResponse>();

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": FRONTEND_ORIGIN,
    "Access-Control-Allow-Headers": "Content-Type, Accept",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Content-Type": "application/json",
  };
}

function sendJson(
  response: ServerResponse,
  status: number,
  body: unknown,
) {
  response.writeHead(status, corsHeaders());
  response.end(JSON.stringify(body));
}

function sendInvalidJson(response: ServerResponse, status: number) {
  response.writeHead(status, corsHeaders());
  response.end(RAW_RESPONSE_MARKER);
}

function sendHangingJson(response: ServerResponse, status: number) {
  openStreamingResponses.add(response);
  response.on("close", () => {
    openStreamingResponses.delete(response);
    closedStreamingResponses++;
  });
  response.writeHead(status, corsHeaders());
  response.flushHeaders();
  response.write('{"partial":');
}

function handleCompletedTask(
  request: IncomingMessage,
  response: ServerResponse,
  options?: { hangingResult?: "result" | "assessment" | "repair-plan" },
) {
  const path = request.url;
  if (path === `/api/check/${TEST_TASK_ID}`) {
    sendJson(response, 200, mockCompletedStatus);
  } else if (path === `/api/check/${TEST_TASK_ID}/result`) {
    if (options?.hangingResult === "result") {
      sendHangingJson(response, 200);
    } else {
      sendJson(response, 200, mockScanResult);
    }
  } else if (path === `/api/check/${TEST_TASK_ID}/assessment`) {
    if (options?.hangingResult === "assessment") {
      sendHangingJson(response, 200);
    } else {
      sendJson(response, 200, mockAssessment);
    }
  } else if (path === `/api/check/${TEST_TASK_ID}/repair-plan`) {
    if (options?.hangingResult === "repair-plan") {
      sendHangingJson(response, 200);
    } else {
      sendJson(response, 200, mockRepairPlan);
    }
  } else {
    sendJson(response, 404, { detail: { error_code: "NOT_FOUND" } });
  }
}

test.beforeAll(async () => {
  responseHandler = (_request, response) => {
    sendJson(response, 500, { detail: { error_code: "INTERNAL_ERROR" } });
  };
  server = createServer((request, response) => {
    if (request.method === "OPTIONS") {
      response.writeHead(204, corsHeaders());
      response.end();
      return;
    }
    responseHandler(request, response);
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(8000, resolve);
  });
});

test.afterEach(() => {
  for (const response of openStreamingResponses) {
    response.destroy();
  }
  openStreamingResponses.clear();
  closedStreamingResponses = 0;
});

test.afterAll(async () => {
  server.closeAllConnections();
  await new Promise<void>((resolve, reject) => {
    server.close((error) => {
      if (error) reject(error);
      else resolve();
    });
  });
});

for (const status of [200, 500]) {
  test(`${status} response headers followed by a hanging body become a request timeout`, async ({
    page,
  }) => {
    await page.clock.install();
    let submitRequests = 0;
    responseHandler = (request, response) => {
      if (request.method === "POST" && request.url === "/api/check") {
        submitRequests++;
        sendHangingJson(response, status);
        return;
      }
      sendJson(response, 404, { detail: { error_code: "NOT_FOUND" } });
    };

    await page.goto("/");
    await page
      .getByLabel("GitHub 仓库地址")
      .fill("https://github.com/owner/repo");
    await page.getByRole("button", { name: "开始检测" }).click();
    await expect.poll(() => submitRequests).toBe(1);

    await page.clock.fastForward(10_001);

    await expect(page.locator(".error-box")).toHaveText(
      NETWORK_ERROR_MESSAGE,
    );
    await expect(page.getByRole("button", { name: "开始检测" })).toBeEnabled();
    await expect.poll(() => closedStreamingResponses).toBe(1);
  });
}

test("caller abort while reading a response body stays silent", async ({
  page,
}) => {
  let submitRequests = 0;
  responseHandler = (request, response) => {
    if (request.method === "POST" && request.url === "/api/check") {
      submitRequests++;
      sendHangingJson(response, 200);
      return;
    }
    sendJson(response, 404, { detail: { error_code: "NOT_FOUND" } });
  };

  await page.goto("/");
  await page
    .getByLabel("GitHub 仓库地址")
    .fill("https://github.com/owner/repo");
  await page.getByRole("button", { name: "开始检测" }).click();
  await expect.poll(() => submitRequests).toBe(1);

  await page.goto("/check/not-a-uuid");

  await expect(page.locator(".error-box")).toHaveText("任务ID格式无效。");
  await expect.poll(() => closedStreamingResponses).toBe(1);
  expect(submitRequests).toBe(1);
});

for (const status of [200, 500]) {
  test(`${status} invalid JSON produces only a fixed HTTP error`, async ({
    page,
  }) => {
    const consoleMessages: string[] = [];
    page.on("console", (message) => {
      consoleMessages.push(message.text());
    });
    responseHandler = (request, response) => {
      if (request.method === "POST" && request.url === "/api/check") {
        sendInvalidJson(response, status);
        return;
      }
      sendJson(response, 404, { detail: { error_code: "NOT_FOUND" } });
    };

    await page.goto("/");
    await page
      .getByLabel("GitHub 仓库地址")
      .fill("https://github.com/owner/repo");
    await page.getByRole("button", { name: "开始检测" }).click();

    await expect(page.locator(".error-box")).toHaveText(
      getErrorMessage(status === 200 ? "INTERNAL_ERROR" : null),
    );
    await expect(page.locator("body")).not.toContainText(RAW_RESPONSE_MARKER);
    expect(consoleMessages.join("\n")).not.toContain(RAW_RESPONSE_MARKER);
  });
}

test("a status body timeout retries and can recover", async ({ page }) => {
  await page.clock.install();
  let statusRequests = 0;
  responseHandler = (request, response) => {
    if (request.url === `/api/check/${TEST_TASK_ID}`) {
      statusRequests++;
      if (statusRequests === 1) {
        sendHangingJson(response, 200);
      } else {
        sendJson(response, 200, mockCompletedStatus);
      }
      return;
    }
    handleCompletedTask(request, response);
  };

  await page.goto(`/check/${TEST_TASK_ID}`);
  await expect.poll(() => statusRequests).toBe(1);

  await page.clock.fastForward(10_001);
  await page.clock.fastForward(2_001);

  await expect(page.locator(".tabs")).toBeVisible();
  expect(statusRequests).toBeGreaterThanOrEqual(2);
});

test("a result body timeout marks only its tab as error", async ({ page }) => {
  await page.clock.install();
  let scanResultRequests = 0;
  responseHandler = (request, response) => {
    if (request.url === `/api/check/${TEST_TASK_ID}/result`) {
      scanResultRequests++;
    }
    handleCompletedTask(request, response, { hangingResult: "result" });
  };

  await page.goto(`/check/${TEST_TASK_ID}`);
  await expect.poll(() => scanResultRequests).toBe(1);

  await page.clock.fastForward(10_001);

  const tabs = page.locator(".tab");
  await expect(tabs).toHaveCount(3);
  await expect(tabs.nth(0)).toContainText("!");
  await expect(tabs.nth(1)).not.toContainText("!");
  await expect(tabs.nth(2)).not.toContainText("!");
  await expect(page.locator(".page-title")).toHaveText("检测结果");
});
