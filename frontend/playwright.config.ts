import fs from "node:fs";
import { defineConfig, devices } from "@playwright/test";

/**
 * Playwright configuration for VibeCheck frontend E2E tests.
 *
 * All API calls are mocked via page.route — no real backend required.
 * Requires a production build: run `npm run build` before `npx playwright test`.
 * CI runs: npm ci → npm run build → npx playwright install → npx playwright test
 *
 * Uses npm start (production server) for reliable test execution. The Next.js
 * dev server compiles pages on-demand which can cause test timeouts.
 *
 * Local development: uses the system-installed Google Chrome when available
 * to avoid downloading the 190MB Playwright-bundled Chromium. CI (where
 * system Chrome is not installed) uses the Playwright-downloaded Chromium.
 */
const SYSTEM_CHROME_PATHS = [
  "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
  "/usr/bin/google-chrome",
  "/usr/bin/chromium-browser",
  "/usr/bin/chromium",
];

const systemChromePath = SYSTEM_CHROME_PATHS.find((p) => {
  try {
    return fs.existsSync(p);
  } catch {
    return false;
  }
});

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: process.env.CI ? "github" : "list",
  timeout: 60_000,
  expect: {
    timeout: 10_000,
  },
  use: {
    baseURL: "http://localhost:3000",
    trace: "on-first-retry",
    actionTimeout: 10_000,
  },
  webServer: {
    // Always use the production server (npm start) for reliable test execution.
    // The Next.js dev server compiles pages on-demand, causing test timeouts.
    // Requires a prior `npm run build` — CI runs build before tests.
    command: "npm start",
    url: "http://localhost:3000",
    // Always start fresh to ensure env vars are properly set.
    // Reusing an existing server may miss NEXT_PUBLIC_API_BASE_URL.
    reuseExistingServer: false,
    timeout: 120_000,
    env: {
      NEXT_PUBLIC_API_BASE_URL: "http://localhost:8000",
    },
  },
  projects: [
    {
      name: "chromium",
      use: {
        ...devices["Desktop Chrome"],
        // Use system Chrome when available (local dev).
        // Fall back to Playwright-downloaded Chromium in CI.
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
