import fs from "node:fs";
import { defineConfig, devices } from "@playwright/test";

const SYSTEM_CHROME_PATHS = [
  "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
  "/usr/bin/google-chrome",
  "/usr/bin/chromium-browser",
  "/usr/bin/chromium",
];

const systemChromePath = SYSTEM_CHROME_PATHS.find((candidate) =>
  fs.existsSync(candidate),
);

export default defineConfig({
  testDir: "./dev-e2e",
  fullyParallel: false,
  workers: 1,
  reporter: process.env.CI ? "github" : "list",
  timeout: 60_000,
  expect: {
    timeout: 15_000,
  },
  use: {
    baseURL: "http://127.0.0.1:3001",
    trace: "on-first-retry",
  },
  projects: [
    {
      name: "chromium",
      use: {
        ...devices["Desktop Chrome"],
        ...(systemChromePath
          ? {
              launchOptions: {
                executablePath: systemChromePath,
              },
            }
          : {}),
      },
    },
  ],
});
