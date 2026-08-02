/**
 * Dev E2E lifecycle manager.
 *
 * Playwright's built-in webServer cannot reliably tear down a Next.js dev
 * server process tree on Windows.  This script owns the full lifecycle:
 *
 *   1. Verify port 3001 is free.
 *   2. Clear stale .next cache to prevent intermittent route 404s.
 *   3. Spawn the local Next CLI directly (no shell, no "npm run dev").
 *   4. Poll http://127.0.0.1:3001 until it responds.
 *   5. Warm up the /check/[taskId] route so it is compiled before tests.
 *   6. Spawn the local Playwright CLI, forwarding extra argv.
 *   7. Always clean up the Next process tree (taskkill /T on Windows,
 *      SIGTERM -> SIGKILL on a dedicated process group elsewhere).
 *   8. Verify port 3001 is released.
 *   9. Exit with the correct code.
 */

import { createRequire } from "node:module";
import { spawn, spawnSync } from "node:child_process";
import { createServer } from "node:net";
import { request } from "node:http";
import { rmSync } from "node:fs";

const require = createRequire(import.meta.url);

const HOST = "127.0.0.1";
const PORT = 3001;
const BASE_URL = `http://${HOST}:${PORT}`;
const STARTUP_TIMEOUT_MS = 120_000;
const CLEANUP_POLL_MS = 500;
const CLEANUP_TIMEOUT_MS = 30_000;
const SIGTERM_GRACE_MS = 5_000;
const POST_KILL_DELAY_MS = 2_000;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Return true when nothing is listening on the target port.
 *
 * Windows:  uses netstat -ano to check for LISTENING sockets.
 * POSIX:    uses a transient listen probe (bind, close immediately).
 */
function isPortFree(host, port) {
  if (process.platform === "win32") {
    const result = spawnSync("netstat", ["-ano"], {
      stdio: "pipe",
      windowsHide: true,
      maxBuffer: 1024 * 1024,
    });
    const output = result.stdout ? result.stdout.toString() : "";
    const lines = output.split("\n");
    for (const line of lines) {
      if (line.includes(`:${port} `) && line.includes("LISTENING")) {
        return Promise.resolve(false);
      }
    }
    return Promise.resolve(true);
  }
  // POSIX: transient listen probe
  return new Promise((resolve) => {
    const server = createServer();
    server.unref();
    server.once("error", (err) => {
      resolve(err.code !== "EADDRINUSE");
    });
    server.once("listening", () => {
      server.close(() => resolve(true));
    });
    server.listen(port, host);
  });
}

function resolveNextCli() {
  try {
    return require.resolve("next/dist/bin/next");
  } catch {
    throw new Error(
      "next/dist/bin/next not found - run 'npm ci' before executing dev E2E tests",
    );
  }
}

function resolvePlaywrightCli() {
  try {
    return require.resolve("playwright/cli");
  } catch {
    try {
      return require.resolve("@playwright/test/cli");
    } catch {
      throw new Error(
        "playwright CLI not found - run 'npm ci' before executing dev E2E tests",
      );
    }
  }
}

function waitForServer() {
  const deadline = Date.now() + STARTUP_TIMEOUT_MS;
  return new Promise((resolve, reject) => {
    function attempt() {
      if (Date.now() > deadline) {
        reject(new Error(`dev server did not become ready within ${STARTUP_TIMEOUT_MS}ms`));
        return;
      }
      const req = request(BASE_URL, (res) => {
        const code = res.statusCode ?? 0;
        res.resume();
        if (
          (code >= 200 && code < 400) ||
          [400, 401, 402, 403].includes(code)
        ) {
          resolve();
        } else {
          setTimeout(attempt, 500);
        }
      });
      req.once("error", () => setTimeout(attempt, 500));
      req.setTimeout(3_000, () => {
        req.destroy();
        setTimeout(attempt, 500);
      });
      req.end();
    }
    attempt();
  });
}

/**
 * Warm up the /check/[taskId] route so that Turbopack has compiled it
 * before Playwright tries to navigate there.  Without this, the first
 * test request can race with on-demand compilation and intermittently
 * receive a 404.
 */
function warmupCheckRoute() {
  const warmupUrl = `${BASE_URL}/check/550e8400-e29b-41d4-a716-446655440000`;
  const deadline = Date.now() + 30_000;
  return new Promise((resolve) => {
    function attempt() {
      if (Date.now() > deadline) {
        console.error("[run-dev-e2e] warmup: check route not ready after 30s, continuing");
        resolve();
        return;
      }
      const req = request(warmupUrl, (res) => {
        const code = res.statusCode ?? 0;
        res.resume();
        if (code >= 200 && code < 400) {
          resolve();
          return;
        }
        setTimeout(attempt, 1_000);
      });
      req.once("error", () => setTimeout(attempt, 1_000));
      req.setTimeout(5_000, () => {
        req.destroy();
        setTimeout(attempt, 1_000);
      });
      req.end();
    }
    attempt();
  });
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

/**
 * Kill the recorded server PID and its entire process tree.
 *
 * ALWAYS attempts the kill, even if the main process appears to have exited,
 * because Next.js / Turbopack may leave orphaned worker children that still
 * hold the listening socket.
 *
 * Windows:  taskkill /PID <pid> /T /F  (tree kill, also kills descendants)
 * Other:    SIGTERM the process group, escalate to SIGKILL after grace.
 */
async function killProcessTree(serverProc) {
  if (!serverProc) {
    await sleep(POST_KILL_DELAY_MS);
    return;
  }
  const pid = serverProc.pid;
  if (!pid) {
    await sleep(POST_KILL_DELAY_MS);
    return;
  }

  if (process.platform === "win32") {
    // Always call taskkill /T /F - it cleans up the entire process tree
    // even if the main process has already exited (orphaned children).
    const result = spawnSync(
      "taskkill",
      ["/PID", String(pid), "/T", "/F"],
      { stdio: "pipe", windowsHide: true },
    );
    const stderr = result.stderr ? result.stderr.toString().trim() : "";
    // 0 = success, 128 = process not found (already exited), null = signal
    if (result.status !== 0 && result.status !== 128 && result.status !== null) {
      console.error(
        `[run-dev-e2e] taskkill exit ${result.status} for PID ${pid}: ${stderr}`,
      );
    }
    // Give the OS time to release the socket.
    await sleep(POST_KILL_DELAY_MS);
    return;
  }

  // POSIX: signal the process group (negative PID).
  const exited = serverProc.exitCode !== null;
  if (!exited) {
    try {
      process.kill(-pid, "SIGTERM");
    } catch {
      try { process.kill(pid, "SIGTERM"); } catch { /* gone */ }
    }
    await new Promise((resolve) => {
      const timer = setTimeout(resolve, SIGTERM_GRACE_MS);
      serverProc.once("exit", () => { clearTimeout(timer); resolve(); });
    });
    try {
      process.kill(-pid, "SIGKILL");
    } catch {
      try { process.kill(pid, "SIGKILL"); } catch { /* gone */ }
    }
  }
  await sleep(POST_KILL_DELAY_MS);
}

async function waitForPortFree() {
  const deadline = Date.now() + CLEANUP_TIMEOUT_MS;
  let attempt = 0;
  while (Date.now() < deadline) {
    attempt++;
    const free = await isPortFree(HOST, PORT);
    if (free) {
      console.error(`[run-dev-e2e] port ${PORT} is free after ${attempt} attempt(s)`);
      return true;
    }
    await sleep(CLEANUP_POLL_MS);
  }
  console.error(`[run-dev-e2e] port ${PORT} still in use after ${attempt} attempts`);
  return false;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  // 1. Port pre-check
  if (!(await isPortFree(HOST, PORT))) {
    console.error(
      `[run-dev-e2e] port ${PORT} is already in use - refusing to start`,
    );
    process.exit(1);
  }

  // 2. Clear stale .next cache to prevent intermittent 404s on restart
  try {
    rmSync(".next", { recursive: true, force: true });
    console.error("[run-dev-e2e] cleared .next cache");
  } catch (err) {
    console.error(`[run-dev-e2e] could not clear .next: ${err.message}`);
  }

  // 3. Spawn Next dev server directly
  const nextCli = resolveNextCli();
  const serverProc = spawn(
    process.execPath,
    [nextCli, "dev", "--hostname", HOST, "--port", String(PORT)],
    {
      cwd: process.cwd(),
      stdio: ["ignore", "inherit", "inherit"],
      env: {
        ...process.env,
        NEXT_PUBLIC_API_BASE_URL: "http://localhost:8000",
      },
      detached: process.platform !== "win32",
    },
  );

  let serverReady = false;
  let playwrightExitCode = 1;

  try {
    // 4. Wait for readiness
    try {
      await waitForServer();
      serverReady = true;
    } catch (error) {
      console.error(`[run-dev-e2e] ${error.message}`);
      process.exitCode = 1;
      return;
    }

    // 5. Warm up the /check/[taskId] route
    await warmupCheckRoute();

    // 6. Run Playwright
    const pwCli = resolvePlaywrightCli();
    const pwArgs = [pwCli, "test", "--config=playwright.dev.config.ts", ...process.argv.slice(2)];

    playwrightExitCode = await new Promise((resolve) => {
      const pw = spawn(process.execPath, pwArgs, {
        cwd: process.cwd(),
        stdio: "inherit",
        env: process.env,
      });
      pw.on("error", (err) => {
        console.error(`[run-dev-e2e] failed to launch playwright: ${err.message}`);
        resolve(1);
      });
      pw.on("exit", (code) => resolve(code ?? 1));
    });
  } finally {
    // 7. Always clean up the Next process tree
    await killProcessTree(serverProc);

    // 8. Verify port released
    const portFree = await waitForPortFree();
    if (!portFree) {
      console.error(
        `[run-dev-e2e] port ${PORT} is still in use after cleanup - reporting failure`,
      );
      process.exitCode = 1;
      return;
    }
  }

  // 9. Propagate Playwright exit code
  process.exitCode = playwrightExitCode;
}

let interrupted = false;
process.on("SIGINT", () => {
  if (interrupted) process.exit(130);
  interrupted = true;
  console.error("\n[run-dev-e2e] interrupted - cleaning up dev server...");
});
process.on("SIGTERM", () => {
  if (interrupted) process.exit(143);
  interrupted = true;
  console.error("\n[run-dev-e2e] terminated - cleaning up dev server...");
});

main()
  .catch((error) => {
    console.error(`[run-dev-e2e] fatal: ${error?.stack ?? error}`);
    process.exitCode = 1;
  })
  .finally(() => {
    process.exit(process.exitCode ?? 0);
  });