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
  const withManifest = {
    "package.json": JSON.stringify({
      dependencies: { next: "14.0.0", react: "18.0.0" },
    }),
    ...files,
  };
  for (const [rel, content] of Object.entries(withManifest)) {
    const target = path.join(root, rel);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, content);
  }
  return root;
}

function run(root, env = {}) {
  const stdout = execFileSync(process.execPath, [analyzer, root], {
    encoding: "utf8",
    timeout: 60_000,
    env: { ...process.env, ...env },
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

test("CSS Modules resolve local classes through import bindings", () => {
  const root = makeRepo({
    "app/page.tsx": `
      import { Card } from "../components/Card";
      export default function Page() { return <Card />; }
    `,
    "components/Card.tsx": `
      import styles from "./card.module.css";
      const label = "orphan";
      export function Card() {
        return <div className={styles.card}><span className={styles["title"]} /></div>;
      }
    `,
    "components/card.module.css": `
      .card { color: red; }
      .title { color: blue; }
      .orphan { color: green; }
    `,
  });
  const payload = run(root);
  const cssNames = payload.items
    .filter((item) => item.category === "frontend_unused_css_class")
    .map((item) => item.class_name)
    .sort();
  assert.deepEqual(cssNames, ["orphan"]);
});

test("Pages Router files are treated as entries and not reported dead", () => {
  const root = makeRepo({
    "pages/about.tsx": `
      export function aboutHelper() { return 1; }
      export default function About() { return <div>{aboutHelper()}</div>; }
    `,
  });
  const payload = run(root);
  assert.deepEqual(itemNames(payload), []);
});

test("arrow functions, exported objects and class methods are candidates", () => {
  const root = makeRepo({
    "app/page.tsx": `
      import { Widget } from "../components/Widget";
      import { handlers } from "../components/handlers";
      export default function Page() { return <div><Widget /><span>{handlers.idle()}</span></div>; }
    `,
    "components/symbols.ts": `
      export const deadArrow = () => 1;
    `,
    "components/handlers.ts": `
      export const handlers = {
        idle: () => 0,
        deadAction: () => 1,
      };
    `,
    "components/Widget.tsx": `
      export class Widget {
        render() { return null; }
        deadMethod() { return 1; }
      }
    `,
  });
  const payload = run(root);
  const names = itemNames(payload).sort();
  assert.ok(names.includes("deadArrow"));
  assert.ok(names.includes("handlers.deadAction"));
  assert.ok(names.includes("Widget.deadMethod"));
  assert.ok(!names.includes("handlers.idle"));
});

test("build output matching uses identifier boundaries", () => {
  const root = makeRepo({
    ".next/chunk.js": `const foobar = 1;`,
    "components/symbols.ts": `export function foo() { return 1; }`,
  });
  const payload = run(root);
  assert.ok(itemNames(payload).includes("foo"));
});

test("pure backend repository is not mistaken for a frontend project", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "frontend-analyzer-backend-"));
  fs.mkdirSync(path.join(root, "app"), { recursive: true });
  fs.writeFileSync(path.join(root, "app", "main.py"), "def main():\n    return 1\n");
  fs.writeFileSync(path.join(root, "requirements.txt"), "django\n");
  const payload = run(root);
  assert.equal(payload.status, "not_applicable");
});

test("output truncation degrades to partial with omitted count", () => {
  const exports = Array.from(
    { length: 205 },
    (_, index) => `export const unused${index} = () => ${index};`,
  ).join("\n");
  const root = makeRepo({ "components/many.ts": exports });
  const payload = run(root);
  assert.equal(payload.status, "partial");
  assert.equal(payload.reason_code, "RESULT_TRUNCATED");
  assert.equal(payload.items.length, 200);
  assert.equal(payload.counts.omitted_items, 5);
});

test("source enumeration truncation degrades to partial and never claims completion", () => {
  const files = {};
  for (let index = 0; index < 6; index += 1) {
    files[`components/c${index}.ts`] = `export const unused${index} = () => ${index};`;
  }
  const root = makeRepo(files);
  const payload = run(root, { VIBECHECK_ANALYZER_MAX_FILES: "3" });
  assert.equal(payload.status, "partial");
  assert.equal(payload.reason_code, "RESULT_TRUNCATED");
  assert.equal(payload.counts.omitted_source_files, null);
  assert.ok(
    payload.limitations.some((line) => line.includes("源文件枚举")),
  );
});
