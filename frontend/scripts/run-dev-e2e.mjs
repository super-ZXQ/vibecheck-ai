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
 *
 * Shutdown is unified through a single AbortController.  The first SIGINT
 * or SIGTERM triggers cleanup via the normal finally block; no
 * process.exit() is called from signal handlers.
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
// Unified shutdown controller
// ---------------------------------------------------------------------------

/** Single source of truth for shutdown requests. */
const shutdown = {
  controller: new AbortController(),
  exitCode: null, // 130 for SIGINT, 143 for SIGTERM
  forceCount: 0,
};

/**
 * Request a graceful shutdown with the given exit code.
 * Idempotent — subsequent calls increment forceCount but do not bypass
 * the ongoing cleanup.  Never calls process.exit() directly.
 */
function requestShutdown(code) {
  if (!shutdown.controller.signal.aborted) {
    shutdown.exitCode = code;
    shutdown.controller.abort();
  } else {
    shutdown.forceCount++;
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Return true when nothing is listening on the target port.
 *
 * Windows:  uses netstat -ano to check for LISTENING sockets.
 * POSIX:    uses a transient listen probe (bind, close immediately).
 *
 * Fail-closed: if netstat exits non-zero or output is empty on Windows,
 * the port is assumed IN USE (returns false) to prevent starting a
 * second server on a port we cannot verify is free.
 */
function isPortFree(host, port) {
  if (process.platform === "win32") {
    const result = spawnSync("netstat", ["-ano"], {
      stdio: "pipe",
      windowsHide: true,
      maxBuffer: 1024 * 1024,
    });
    if (result.status !== 0 || result.error) {
      // netstat failed — fail closed (assume port is in use).
      return Promise.resolve(false);
    }
    const output = result.stdout ? result.stdout.toString() : "";
    if (!output) {
      // No output — fail closed.
      return Promise.resolve(false);
    }
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

/**
 * Poll BASE_URL until the dev server responds.
 *
 * Accepts an AbortSignal — when aborted, the current in-flight request
 * is destroyed, pending timers are cleared, and the promise rejects.
 */
function waitForServer(signal) {
  const deadline = Date.now() + STARTUP_TIMEOUT_MS;
  return new Promise((resolve, reject) => {
    let timer = null;
    let currentReq = null;

    function onAbort() {
      if (timer) clearTimeout(timer);
      if (currentReq) currentReq.destroy();
      reject(new Error("dev server startup aborted"));
    }

    if (signal.aborted) {
      onAbort();
      return;
    }
    signal.addEventListener("abort", onAbort, { once: true });

    function attempt() {
      if (signal.aborted) return;
      if (Date.now() > deadline) {
        signal.removeEventListener("abort", onAbort);
        reject(new Error(`dev server did not become ready within ${STARTUP_TIMEOUT_MS}ms`));
        return;
      }
      currentReq = request(BASE_URL, (res) => {
        const code = res.statusCode ?? 0;
        res.resume();
        if (
          (code >= 200 && code < 400) ||
          [400, 401, 402, 403].includes(code)
        ) {
          signal.removeEventListener("abort", onAbort);
          resolve();
        } else {
          timer = setTimeout(attempt, 500);
        }
      });
      currentReq.once("error", () => {
        if (!signal.aborted) timer = setTimeout(attempt, 500);
      });
      currentReq.setTimeout(3_000, () => {
        currentReq.destroy();
        if (!signal.aborted) timer = setTimeout(attempt, 500);
      });
      currentReq.end();
    }
    attempt();
  });
}

/**
 * Warm up the /check/[taskId] route so that Turbopack has compiled it
 * before Playwright tries to navigate there.
 *
 * Accepts an AbortSignal — when aborted, the current request is destroyed
 * and the promise rejects.  Failure after 30 seconds also rejects.
 */
function warmupCheckRoute(signal) {
  const warmupUrl = `${BASE_URL}/check/550e8400-e29b-41d4-a716-446655440000`;
  const deadline = Date.now() + 30_000;
  return new Promise((resolve, reject) => {
    let timer = null;
    let currentReq = null;

    function onAbort() {
      if (timer) clearTimeout(timer);
      if (currentReq) currentReq.destroy();
      reject(new Error("route warmup aborted"));
    }

    if (signal.aborted) {
      onAbort();
      return;
    }
    signal.addEventListener("abort", onAbort, { once: true });

    function attempt() {
      if (signal.aborted) return;
      if (Date.now() > deadline) {
        signal.removeEventListener("abort", onAbort);
        reject(new Error("route warmup failed: check route not ready after 30s"));
        return;
      }
      currentReq = request(warmupUrl, (res) => {
        const code = res.statusCode ?? 0;
        res.resume();
        if (code >= 200 && code < 400) {
          signal.removeEventListener("abort", onAbort);
          resolve();
          return;
        }
        timer = setTimeout(attempt, 1_000);
      });
      currentReq.once("error", () => {
        if (!signal.aborted) timer = setTimeout(attempt, 1_000);
      });
      currentReq.setTimeout(5_000, () => {
        currentReq.destroy();
        if (!signal.aborted) timer = setTimeout(attempt, 1_000);
      });
      currentReq.end();
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
 *           Always attempts to signal the process group (negative PID),
 *           even when the main process has already exited, to clean up
 *           any orphaned children.  ESRCH (process/group does not exist)
 *           is treated as successful cleanup.
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

  // POSIX: always signal the process group (negative PID), even if the
  // main process has exited, to catch orphaned children.
  try {
    process.kill(-pid, "SIGTERM");
  } catch (err) {
    // ESRCH means the process group doesn't exist — acceptable.
    if (err.code !== "ESRCH") {
      try { process.kill(pid, "SIGTERM"); } catch { /* gone */ }
    }
  }

  // Wait for graceful exit (only meaningful if process hasn't exited yet).
  if (serverProc.exitCode === null) {
    await new Promise((resolve) => {
      const timer = setTimeout(resolve, SIGTERM_GRACE_MS);
      serverProc.once("exit", () => { clearTimeout(timer); resolve(); });
    });
  }

  // Always escalate to SIGKILL on the process group.
  try {
    process.kill(-pid, "SIGKILL");
  } catch (err) {
    if (err.code !== "ESRCH") {
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
  const signal = shutdown.controller.signal;

  // 1. Port pre-check
  if (!(await isPortFree(HOST, PORT))) {
    console.error(
      `[run-dev-e2e] port ${PORT} is already in use - refusing to start`,
    );
    return 1;
  }

  // 2. Clear stale .next cache — failure is fatal because stale cache
  //    causes intermittent 404s that the warmup step is designed to prevent.
  try {
    rmSync(".next", { recursive: true, force: true });
    console.error("[run-dev-e2e] cleared .next cache");
  } catch (err) {
    console.error(`[run-dev-e2e] fatal: could not clear .next cache: ${err.message}`);
    return 1;
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

  let playwrightExitCode = 1;
  let playwrightProc = null;

  try {
    // 4. Wait for readiness (abortable)
    try {
      await waitForServer(signal);
    } catch (error) {
      if (signal.aborted) {
        console.error(`[run-dev-e2e] ${error.message}`);
        return shutdown.exitCode ?? 1;
      }
      console.error(`[run-dev-e2e] ${error.message}`);
      return 1;
    }

    // 5. Warm up the /check/[taskId] route (abortable, must succeed)
    try {
      await warmupCheckRoute(signal);
    } catch (error) {
      if (signal.aborted) {
        console.error(`[run-dev-e2e] ${error.message}`);
        return shutdown.exitCode ?? 1;
      }
      console.error(`[run-dev-e2e] fatal: ${error.message}`);
      return 1;
    }

    // 6. Run Playwright
    const pwCli = resolvePlaywrightCli();
    const pwArgs = [pwCli, "test", "--config=playwright.dev.config.ts", ...process.argv.slice(2)];

    playwrightExitCode = await new Promise((resolve) => {
      playwrightProc = spawn(process.execPath, pwArgs, {
        cwd: process.cwd(),
        stdio: "inherit",
        env: process.env,
      });
      playwrightProc.on("error", (err) => {
        console.error(`[run-dev-e2e] failed to launch playwright: ${err.message}`);
        playwrightProc = null;
        resolve(1);
      });
      playwrightProc.on("exit", (code) => {
        playwrightProc = null;
        resolve(code ?? 1);
      });

      // If already interrupted before Playwright spawned, resolve now.
      if (signal.aborted) {
        if (playwrightProc) {
          try { playwrightProc.kill("SIGTERM"); } catch { /* gone */ }
        }
        resolve(shutdown.exitCode ?? 1);
      }

      // Abort Playwright if shutdown is requested while it's running.
      signal.addEventListener("abort", () => {
        if (playwrightProc) {
          try { playwrightProc.kill("SIGTERM"); } catch { /* gone */ }
        }
      }, { once: true });
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
      return 1;
    }
  }

  // 9. Propagate exit code: signal interruption takes priority
  if (signal.aborted && shutdown.exitCode !== null) {
    return shutdown.exitCode;
  }
  return playwrightExitCode;
}

// Signal handlers — never call process.exit(); just request shutdown.
process.on("SIGINT", () => {
  console.error("\n[run-dev-e2e] interrupted (SIGINT) - cleaning up...");
  requestShutdown(130);
});
process.on("SIGTERM", () => {
  console.error("\n[run-dev-e2e] terminated (SIGTERM) - cleaning up...");
  requestShutdown(143);
});

main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((error) => {
    console.error(`[run-dev-e2e] fatal: ${error?.stack ?? error}`);
    process.exitCode = 1;
  })
  .finally(() => {
    process.exit(process.exitCode ?? 0);
  });
