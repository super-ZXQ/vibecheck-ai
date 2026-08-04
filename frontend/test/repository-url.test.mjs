import assert from "node:assert/strict";
import test from "node:test";

import { normalizeGitHubRepoUrl } from "../lib/repository-url.mjs";

test("adds HTTPS to a github.com repository URL without a scheme", () => {
  assert.equal(
    normalizeGitHubRepoUrl("github.com/powercy/BossHunter"),
    "https://github.com/powercy/BossHunter",
  );
});

test("normalizes github.com host casing and surrounding whitespace", () => {
  assert.equal(
    normalizeGitHubRepoUrl("  GitHub.com/owner/repo  "),
    "https://github.com/owner/repo",
  );
});

test("keeps an existing HTTPS repository URL unchanged", () => {
  assert.equal(
    normalizeGitHubRepoUrl("https://github.com/owner/repo"),
    "https://github.com/owner/repo",
  );
});

test("does not upgrade HTTP or lookalike hosts", () => {
  assert.equal(
    normalizeGitHubRepoUrl("http://github.com/owner/repo"),
    "http://github.com/owner/repo",
  );
  assert.equal(
    normalizeGitHubRepoUrl("github.com.evil.example/owner/repo"),
    "github.com.evil.example/owner/repo",
  );
});
