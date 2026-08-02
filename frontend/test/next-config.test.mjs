import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import test from "node:test";
import { fileURLToPath } from "node:url";

const frontendRoot = fileURLToPath(new URL("..", import.meta.url));
const require = createRequire(import.meta.url);
const {
  getProductionApiOrigin,
} = require("../lib/production-api-origin.cjs");

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

for (const apiOrigin of [
  "https://api.example.com",
  "http://localhost:8000",
  "http://127.0.0.1:8000",
  "http://[::1]:8000",
]) {
  test(`production API origin accepts ${apiOrigin}`, () => {
    assert.equal(getProductionApiOrigin(apiOrigin), apiOrigin);
  });
}

for (const apiOrigin of [
  "http://api.example.com",
  "https://user:pass@example.com",
  "https://example.com/api",
  "https://example.com?x=1",
  "https://example.com#fragment",
  "javascript:alert(1)",
]) {
  test(`production API origin rejects ${apiOrigin}`, () => {
    assert.throws(
      () => getProductionApiOrigin(apiOrigin),
      /NEXT_PUBLIC_API_BASE_URL/,
    );
  });
}
