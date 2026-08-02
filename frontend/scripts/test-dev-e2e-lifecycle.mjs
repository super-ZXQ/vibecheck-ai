#!/usr/bin/env node
/**
 * Dev E2E lifecycle verification script.
 *
 * Exercises the critical paths of run-dev-e2e.mjs:
 *   1. Port already occupied — script must refuse to start.
 *   2. Playwright failure — non-matching grep, must exit non-zero.
 *   3. SIGINT during startup — must exit 130, port released.
 *   4. SIGTERM during Playwright — must exit 143, port released.
 *
 * POSIX process group cleanup is verified in CI (frontend-tests.yml)
 * because it requires a Linux environment.
 *
 * Usage:  node scripts/test-dev-e2e-lifecycle.mjs
 */

import { spawn, spawnSync } from "node:child_process";
import { createServer } from "node:net";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";

const HOST = "127.0.0.1";
const PORT = 3001;
const SCRIPT = fileURLToPath(new URL("./run-dev-e2e.mjs", import.meta.url));
const CWD = dirname(dirname(SCRIPT));

const results = [];

function log(msg) {
  console.error(`[lifecycle-test] ${msg}`);
}

function record(name, passed, detail = "") {
  results.push({ name, passed, detail });
  const status = passed ? "PASS" : "FAIL";
  log(`${status}: ${name}${detail ? " — " + detail : ""}`);
}

/**
 * Check if a TCP port is free by attempting to listen on it.
 */
function isPortFree() {
  return new Promise((resolve) => {
    const server = createServer();
    server.unref();
    server.once("error", (err) => resolve(err.code !== "EADDRINUSE"));
    server.once("listening", () => server.close(() => resolve(true)));
    server.listen(PORT, HOST);
  });
}

/**
 * Wait for port to be free, polling every 500ms up to 30s.
 */
async function waitForPortFree() {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    if (await isPortFree()) return true;
    await sleep(500);
  }
  return false;
}

/**
 * Run a child process and optionally send a signal after a delay.
 * Returns { code, signal, stdout, stderr }.
 */
function runChild({ args = [], signalAfter = null, signalType = null, cwd = CWD }) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [SCRIPT, ...args], {
      cwd,
      stdio: ["ignore", "pipe", "pipe"],
      env: process.env,
    });

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (d) => { stdout += d.toString(); });
    child.stderr.on("data", (d) => { stderr += d.toString(); });

    let signalSent = false;

    if (signalAfter !== null && signalType !== null) {
      setTimeout(() => {
        if (!signalSent && child.exitCode === null) {
          signalSent = true;
          try {
            child.kill(signalType);
            log(`sent ${signalType} after ${signalAfter}ms`);
          } catch {
            log(`could not send ${signalType}`);
          }
        }
      }, signalAfter);
    }

    child.on("exit", (code, signal) => {
      resolve({ code, signal, stdout, stderr });
    });
  });
}

// ---------------------------------------------------------------------------
// Test 1: Port already occupied
// ---------------------------------------------------------------------------

async function testPortOccupied() {
  log("Test 1: port already occupied");

  // Occupy port 3001 with a dummy server.
  const dummy = createServer();
  await new Promise((resolve, reject) => {
    dummy.once("error", reject);
    dummy.once("listening", resolve);
    dummy.listen(PORT, HOST);
  });

  try {
    const { code, stderr } = await runChild({});
    const detected = code === 1 && stderr.includes("already in use");

    // Close the dummy server, then verify port is free.
    await new Promise((resolve) => dummy.close(resolve));
    const portFree = await waitForPortFree();

    const passed = detected && portFree;
    record(
      "port-already-occupied",
      passed,
      `exit=${code}, detected=${detected}, portFree=${portFree}`,
    );
  } catch (err) {
    dummy.close();
    throw err;
  }
}

// ---------------------------------------------------------------------------
// Test 2: Playwright failure (non-matching grep)
// ---------------------------------------------------------------------------

async function testPlaywrightFailure() {
  log("Test 2: Playwright failure (non-matching grep)");

  const { code } = await runChild({
    args: ["--grep", "__NO_MATCHING_TEST__", "--reporter=line"],
  });
  const portFree = await waitForPortFree();

  const passed = code !== 0 && code !== null && portFree;
  record(
    "playwright-failure",
    passed,
    `exit=${code}, portFree=${portFree}`,
  );
}

// ---------------------------------------------------------------------------
// Test 3: SIGINT during startup
// ---------------------------------------------------------------------------

async function testStartupInterruption() {
  log("Test 3: SIGINT during startup");

  // Send SIGINT after 3 seconds — should be during waitForServer or warmup.
  const { code, signal } = await runChild({
    signalAfter: 3_000,
    signalType: "SIGINT",
  });
  const portFree = await waitForPortFree();

  // On POSIX, SIGINT triggers the handler which exits with code 130.
  // On Windows, child.kill('SIGINT') uses TerminateProcess — the child
  // is killed immediately without running its signal handler, so exit
  // code is null.  We accept both: explicit exit code OR signal-killed
  // with port released (OS reclaims the socket).
  const passed = process.platform === "win32"
    ? portFree  // Windows: TerminateProcess kills child, port freed by OS
    : (code === 130) && portFree;
  record(
    "startup-sigint",
    passed,
    `exit=${code}, signal=${signal}, portFree=${portFree}`,
  );
}

// ---------------------------------------------------------------------------
// Test 4: SIGTERM during Playwright phase
// ---------------------------------------------------------------------------

async function testPlaywrightInterruption() {
  log("Test 4: SIGTERM during Playwright phase");

  // Wait 30 seconds for the server to start and Playwright to begin.
  // The script clears .next, starts the dev server, warms up the route,
  // then spawns Playwright.  30s should be enough to reach Playwright.
  const { code, signal } = await runChild({
    signalAfter: 30_000,
    signalType: "SIGTERM",
  });
  const portFree = await waitForPortFree();

  // On POSIX, SIGTERM triggers the handler which exits with code 143.
  // On Windows, child.kill('SIGTERM') uses TerminateProcess — the child
  // is killed immediately, exit code is null.  Port release is the
  // reliable indicator that cleanup succeeded.
  const passed = process.platform === "win32"
    ? portFree  // Windows: TerminateProcess kills child, port freed by OS
    : (code === 143) && portFree;
  record(
    "playwright-sigterm",
    passed,
    `exit=${code}, signal=${signal}, portFree=${portFree}`,
  );
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  log(`Platform: ${process.platform}`);
  log(`Script: ${SCRIPT}`);
  log(`CWD: ${CWD}`);

  // Ensure port is free before starting.
  if (!(await isPortFree())) {
    log(`ERROR: port ${PORT} is already in use — aborting tests`);
    process.exit(1);
  }

  await testPortOccupied();
  await testPlaywrightFailure();
  await testStartupInterruption();
  await testPlaywrightInterruption();

  // Summary
  log("\n--- Summary ---");
  const passed = results.filter((r) => r.passed).length;
  const failed = results.length - passed;
  for (const r of results) {
    log(`${r.passed ? "PASS" : "FAIL"}: ${r.name} — ${r.detail}`);
  }
  log(`\nTotal: ${results.length}, Passed: ${passed}, Failed: ${failed}`);

  process.exit(failed > 0 ? 1 : 0);
}

main().catch((err) => {
  log(`fatal: ${err?.stack ?? err}`);
  process.exit(1);
});
