import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const here = path.dirname(fileURLToPath(import.meta.url));
const analyzer = path.resolve(here, "..", "analyzer.mjs");
const repoRoot = path.resolve(here, "..", "..", "..", "..", "..", "..");

function makeRepo(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "frontend-analyzer-test-"));
  for (const [rel, content] of Object.entries(files)) {
    const target = path.join(root, rel);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, content);
  }
  return root;
}

function run(root) {
  const stdout = execFileSync(process.execPath, [analyzer, root], {
    encoding: "utf8",
    timeout: 60_000,
  });
  return JSON.parse(stdout);
}

function itemNames(payload) {
  return payload.items.map((item) => item.name ?? item.class_name);
}

test("golden repository reports exactly two helpers and four CSS classes", () => {
  const payload = run(repoRoot);
  assert.equal(payload.status, "completed");
  assert.equal(payload.counts.zero_call_functions, 2);
  assert.equal(payload.counts.css_classes, 4);
  const functionNames = payload.items
    .filter((item) => item.category === "frontend_zero_call_export")
    .map((item) => item.name);
  assert.deepEqual(functionNames.sort(), ["mockSubmitError", "mockTaskStatusNetworkError"]);
  const cssNames = payload.items
    .filter((item) => item.category === "frontend_unused_css_class")
    .map((item) => item.class_name)
    .sort();
  assert.deepEqual(cssNames, [
    "card-hover",
    "focus-visible",
    "history-status-completed",
    "visually-hidden",
  ]);
});

test("Next entry exports, barrels, side-effect imports and used imports are not dead", () => {
  const root = makeRepo({
    "app/page.tsx": `
      import { viaBarrel } from "../lib";
      import "../lib/side";
      import { importedButNeverCalled } from "../lib/helpers";
      import { Badge } from "../components/Badge";
      export function pageLocalHelper() { return 1; }
      export default function Page() { viaBarrel(); return <Badge dimension="a" />; }
    `,
    "lib/index.ts": `export { viaBarrel } from "./barrel";`,
    "lib/barrel.ts": `export function viaBarrel() { return 1; }`,
    "lib/side.ts": `export function sideEffectExport() { return 1; }`,
    "lib/helpers.ts": `export function importedButNeverCalled() { return 1; }`,
    "app/globals.css": `
      .used-in-tsx { color: red; }
      .dimension-a { color: blue; }
      .dimension-b { color: green; }
    `,
    "components/Badge.tsx": `
      export function Badge({ dimension }: { dimension: string }) {
        return <span className={\`dimension-\${dimension}\`} />;
      }
      export const used = "used-in-tsx";
    `,
  });
  const payload = run(root);
  const names = itemNames(payload);
  assert.deepEqual(names, []);
});

test("template class families are matched by prefix, not literal", () => {
  const root = makeRepo({
    "app/page.tsx": `
      export default function Page({ value }: { value: string }) {
        return <div className={\`dimension-\${value}\`} />;
      }
    `,
    "app/globals.css": `
      .dimension-basic { color: red; }
      .dimension-deployable { color: blue; }
    `,
  });
  const payload = run(root);
  assert.equal(payload.counts.css_classes, 0);
});

test("missing build output degrades candidates to medium confidence", () => {
  const root = makeRepo({
    "app/page.tsx": `export default function Page() { return null; }`,
    "app/globals.css": `.orphan-class { color: red; }`,
  });
  const payload = run(root);
  assert.equal(payload.status, "partial");
  assert.equal(payload.items.length, 1);
  assert.equal(payload.items[0].confidence, "medium");
  assert.ok(payload.limitations.some((row) => row.includes("构建产物缺失")));
});

test("plain unreferenced CSS is reported", () => {
  const root = makeRepo({
    "app/page.tsx": `export default function Page() { return null; }`,
    "app/globals.css": `.orphan-class { color: red; }`,
  });
  const payload = run(root);
  assert.deepEqual(itemNames(payload), ["orphan-class"]);
});

test("reflection string reference is reported as low confidence", () => {
  const root = makeRepo({
    "app/page.tsx": `export default function Page() { return null; }`,
    "lib/registry.ts": `
      export function reflectMe() { return 1; }
      export const registryName = "reflectMe";
    `,
  });
  const payload = run(root);
  const item = payload.items.find((row) => row.name === "reflectMe");
  assert.ok(item);
  assert.equal(item.confidence, "low");
  assert.equal(item.category, "frontend_reflection_reference");
});

test("dynamic import in the same directory degrades a candidate to medium", () => {
  const root = makeRepo({
    "app/page.tsx": `export default function Page() { return null; }`,
    "lib/plugin.ts": `export function maybeLoaded() { return 1; }`,
    "lib/loader.ts": `export async function load(name: string) { return import(\`./\${name}\`); }`,
  });
  const payload = run(root);
  const item = payload.items.find((row) => row.name === "maybeLoaded");
  assert.ok(item);
  assert.equal(item.confidence, "medium");
});
