/**
 * The ownership key only protects a request if every request carries it.
 *
 * lib/api.ts is not importable from node (its extension-less TS imports
 * resolve only under the bundler), so the wiring is checked at source level:
 * every request header object must attach buildSubmitterHeaders(), and no new
 * fetch() site may appear without being reviewed here.
 */

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const API_SOURCE = await readFile(
  new URL("../lib/api.ts", import.meta.url),
  "utf8",
);

function balancedObject(source, openIndex) {
  let depth = 0;
  for (let index = openIndex; index < source.length; index += 1) {
    if (source[index] === "{") depth += 1;
    else if (source[index] === "}") {
      depth -= 1;
      if (depth === 0) return source.slice(openIndex, index + 1);
    }
  }
  return null;
}

/** Object literals a `headers:` property resolves to, ternary branches included. */
function headerObjects(source) {
  const found = [];
  for (const match of source.matchAll(/headers:/g)) {
    let cursor = match.index + "headers:".length;
    let isTernaryElse = false;
    for (;;) {
      const window = source.slice(cursor, cursor + 400);
      const braceAt = window.indexOf("{");
      if (braceAt === -1) break;
      const between = window.slice(0, braceAt);
      const reachable = isTernaryElse
        ? /^[\s:]*$/.test(between)
        : !/[{};,]/.test(between);
      if (!reachable) break;
      const object = balancedObject(source, cursor + braceAt);
      if (!object) break;
      found.push(object);
      cursor += braceAt + object.length;
      isTernaryElse = true;
    }
  }
  return found;
}

test("the API client has only the two audited fetch call sites", () => {
  const sites = API_SOURCE.match(/await fetch\(/g) ?? [];
  assert.equal(
    sites.length,
    2,
    "a new fetch() site must be checked for the ownership header",
  );
});

test("every request header object attaches the ownership key", () => {
  const headers = headerObjects(API_SOURCE);
  // apiFetch POST branch, apiFetch GET branch, submitUpload multipart POST.
  assert.equal(
    headers.length,
    3,
    `expected 3 request header objects, found ${headers.length}`,
  );
  for (const literal of headers) {
    assert.ok(
      literal.includes("buildSubmitterHeaders()"),
      `request header object is missing the ownership key: ${literal
        .replace(/\s+/g, " ")
        .slice(0, 120)}`,
    );
  }
});

test("reads carry the ownership key without leaking LLM config", () => {
  const getBranch = headerObjects(API_SOURCE).find(
    (literal) =>
      literal.includes("Accept:") && !literal.includes('"Content-Type"'),
  );
  assert.ok(getBranch, "no GET header object found");
  assert.ok(getBranch.includes("buildSubmitterHeaders()"));
  assert.ok(
    !getBranch.includes("buildLLMHeaders()"),
    "reads must not send per-user LLM configuration",
  );
});
