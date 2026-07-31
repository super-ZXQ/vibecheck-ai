import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

const frontendRoot = fileURLToPath(new URL("..", import.meta.url));

function loadProductionConfig(apiBaseUrl) {
  const env = {
    ...process.env,
    NODE_ENV: "production",
  };
  if (apiBaseUrl === undefined) {
    delete env.NEXT_PUBLIC_API_BASE_URL;
  } else {
    env.NEXT_PUBLIC_API_BASE_URL = apiBaseUrl;
  }

  return spawnSync(
    process.execPath,
    [
      "-e",
      "const config=require('./next.config.js');" +
        "process.stdout.write(JSON.stringify({" +
        "output:config.output," +
        "poweredByHeader:config.poweredByHeader," +
        "reactStrictMode:config.reactStrictMode" +
        "}));",
    ],
    {
      cwd: frontendRoot,
      env,
      encoding: "utf8",
    },
  );
}

test("production Next config rejects a missing API origin", () => {
  const result = loadProductionConfig(undefined);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /NEXT_PUBLIC_API_BASE_URL is required/);
});

test("production Next config rejects an API URL with a path", () => {
  const result = loadProductionConfig("https://api.example.com/v1");
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /must be a pure HTTP\(S\) origin/);
});

test("production Next config enables standalone and removes X-Powered-By", () => {
  const result = loadProductionConfig("https://api.example.com");
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), {
    output: "standalone",
    poweredByHeader: false,
    reactStrictMode: true,
  });
});
