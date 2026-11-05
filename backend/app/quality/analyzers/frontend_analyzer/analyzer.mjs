// Offline frontend dead-code analyzer.
//
// Input: repository root (argv[2]).
// Output: one JSON object on stdout. The Python caller owns timeout, memory and
// output caps; this script never imports or executes files from the scanned
// repository and never runs its package scripts.

import fs from "node:fs";
import path from "node:path";
import { Project, SyntaxKind } from "ts-morph";
import postcss from "postcss";
import postcssScss from "postcss-scss";

const MAX_FILES = 4000;
const MAX_FINDINGS = 200;
const MAX_BUILD_BYTES = 16 * 1024 * 1024;
const SCAN_SKIP_DIRS = new Set([
  "node_modules",
  ".next",
  ".git",
  ".turbo",
  "coverage",
  "dist",
  "build",
  "out",
]);

const NEXT_ENTRY_RE =
  /\/app\/(?:.*\/)?(?:page|layout|route|template|default|loading|error|global-error|not-found|forbidden|unauthorized|instrumentation)\.(?:tsx?|jsx?)$/;
const TEST_FILE_RE = /(?:\.spec|\.test)\.(?:tsx?|jsx?)$/;

function jsonOut(payload) {
  process.stdout.write(JSON.stringify(payload));
}

function readText(file, limit = 2 * 1024 * 1024) {
  try {
    const stat = fs.statSync(file);
    if (!stat.isFile() || stat.size > limit) return null;
    return fs.readFileSync(file, "utf8");
  } catch {
    return null;
  }
}

function listFiles(root, extensions, maxFiles = MAX_FILES) {
  const result = [];
  const stack = [root];
  while (stack.length && result.length < maxFiles) {
    const dir = stack.pop();
    let entries = [];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!SCAN_SKIP_DIRS.has(entry.name)) stack.push(full);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (extensions.includes(ext)) result.push(full);
      }
    }
  }
  return result;
}

function findFrontendRoot(repoRoot) {
    const marker = (dir) =>
    fs.existsSync(path.join(dir, "next.config.js")) ||
    fs.existsSync(path.join(dir, "next.config.mjs")) ||
    fs.existsSync(path.join(dir, "next.config.ts")) ||
    fs.existsSync(path.join(dir, "app")) ||
    fs.existsSync(path.join(dir, "src", "app"));
  if (marker(repoRoot)) return repoRoot;
  const candidates = ["frontend", "web", "apps/web", "client", "ui"];
  for (const candidate of candidates) {
    const dir = path.join(repoRoot, candidate);
    if (fs.existsSync(dir) && marker(dir)) return dir;
  }
  try {
    for (const entry of fs.readdirSync(repoRoot, { withFileTypes: true })) {
      if (!entry.isDirectory() || SCAN_SKIP_DIRS.has(entry.name)) continue;
      const dir = path.join(repoRoot, entry.name);
      if (marker(dir)) return dir;
    }
  } catch {
    // ignore
  }
  return null;
}

function relative(repoRoot, file) {
  return path.relative(repoRoot, file).split(path.sep).join("/");
}

function lineOf(sourceFile, start) {
  return sourceFile.getLineAndColumnAtPos(start).line;
}

function collectNextEntries(frontendRoot) {
  const entries = [];
  const candidates = listFiles(frontendRoot, [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]);
  for (const file of candidates) {
    const rel = relative(frontendRoot, file);
    if (
      NEXT_ENTRY_RE.test(`/${rel}`) ||
      /^(?:\/)?(?:middleware|instrumentation)\.(?:tsx?|jsx?)$/.test(`/${rel}`) ||
      /^\/next\.config\.(?:js|mjs|ts)$/.test(`/${rel}`)
    ) {
      entries.push(file);
    }
  }
  return entries;
}

function buildOutputState(frontendRoot) {
  const dirs = [".next", "dist", "build", "out"]
    .map((name) => path.join(frontendRoot, name))
    .filter((dir) => {
      try {
        return fs.statSync(dir).isDirectory();
      } catch {
        return false;
      }
    });
  const minifiedCss = [];
  for (const dir of dirs) {
    const cssFiles = listFiles(dir, [".css"], 400);
    for (const file of cssFiles.slice(0, 10)) minifiedCss.push(file);
  }
  return {
    available: dirs.length > 0,
    directories: dirs.map((dir) => path.basename(dir)),
    minified_css_files: minifiedCss.length,
  };
}

function buildSearchText(frontendRoot) {
  const dirs = [".next", "dist", "build", "out"]
    .map((name) => path.join(frontendRoot, name))
    .filter((dir) => {
      try {
        return fs.statSync(dir).isDirectory();
      } catch {
        return false;
      }
    });
  let total = 0;
  const chunks = [];
  for (const dir of dirs) {
    const files = listFiles(dir, [".js", ".mjs", ".css"], 2000);
    for (const file of files) {
      const text = readText(file, 1024 * 1024);
      if (!text) continue;
      total += Buffer.byteLength(text);
      if (total > MAX_BUILD_BYTES) return chunks.join("\n");
      chunks.push(text);
    }
  }
  return chunks.join("\n");
}

function createProject(frontendRoot) {
  const tsconfig = ["tsconfig.json", "jsconfig.json"]
    .map((name) => path.join(frontendRoot, name))
    .find((file) => fs.existsSync(file));
  let project;
  if (tsconfig) {
    project = new Project({
      tsConfigFilePath: tsconfig,
      skipAddingFilesFromTsConfig: false,
      skipFileDependencyResolution: true,
    });
  } else {
    project = new Project({
      compilerOptions: {
        allowJs: true,
        jsx: 4,
        target: 7,
        module: 1,
        moduleResolution: 2,
        baseUrl: frontendRoot,
      },
    });
    const files = listFiles(frontendRoot, [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]);
    project.addSourceFilesAtPaths(files);
  }
  // e2e helpers are often excluded by the app tsconfig; include them explicitly.
  for (const dirName of ["e2e", "dev-e2e", "playwright", "tests"]) {
    const dir = path.join(frontendRoot, dirName);
    if (!fs.existsSync(dir)) continue;
    const files = listFiles(dir, [".ts", ".tsx", ".js", ".jsx"], 800);
    project.addSourceFilesAtPaths(files);
  }
  return project;
}

function importTarget(importDeclaration) {
  try {
    return importDeclaration.getModuleSpecifierSourceFile();
  } catch {
    return null;
  }
}

function exportNameOf(namedExport) {
  return namedExport.getAliasNode()?.getText() ?? namedExport.getName();
}

function localNameOf(namedExport) {
  return namedExport.getName();
}

function collectUsage(project) {
  const files = project
    .getSourceFiles()
    .filter((file) => {
      const rel = file.getFilePath().split(path.sep).join("/");
      return !rel.includes("/node_modules/") && !rel.includes("/.next/");
    });
  const usedExports = new Map(); // "absPath#exportName" -> true
  const sideEffectModules = new Set();
  const barrelLinks = []; // {fromFile, targetFile, exportName}
  const importedNames = new Map(); // absPath -> Set(export names)
  const dynamicImportDirs = new Set();
  const functionCalls = new Map(); // "absPath#localName" -> count
  const stringReferences = new Set(); // symbol names seen in string literals

  const markUsed = (file, name) => {
    usedExports.set(`${file.getFilePath()}#${name}`, true);
  };
  const markAllUsed = (file) => {
    for (const declaration of file.getFunctions()) {
      if (declaration.isExported()) markUsed(file, declaration.getName() ?? "default");
    }
    for (const declaration of file.getClasses()) {
      if (declaration.isExported()) markUsed(file, declaration.getName() ?? "default");
    }
    for (const declaration of file.getVariableDeclarations()) {
      if (declaration.isExported()) markUsed(file, declaration.getName());
    }
  };

  for (const file of files) {
    const abs = file.getFilePath();
    const names = new Set();
    for (const imp of file.getImportDeclarations()) {
      const target = importTarget(imp);
      const defaultImport = imp.getDefaultImport();
      const namespaceImport = imp.getNamespaceImport();
      const namedImports = imp.getNamedImports();
      if (!target) continue;
      if (defaultImport) names.add("default");
      if (namespaceImport) {
        markAllUsed(target);
        names.add("*");
      }
      for (const named of namedImports) {
        const exported = named.getName();
        const local = named.getAliasNode()?.getText() ?? exported;
        names.add(exported);
        markUsed(target, exported);
        const key = `${target.getFilePath()}#${local}`;
        functionCalls.set(key, (functionCalls.get(key) ?? 0) + 1);
      }
      if (!defaultImport && !namespaceImport && namedImports.length === 0) {
        sideEffectModules.add(target.getFilePath());
      }
    }
    for (const exp of file.getExportDeclarations()) {
      const target = importTarget(exp);
      const named = exp.getNamedExports();
      for (const item of named) {
        if (!target) continue;
        barrelLinks.push({
          fromFile: file,
          targetFile: target,
          exportName: item.getName(),
        });
      }
    }
    const fileDir = path.dirname(abs);
    for (const call of file.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      const expression = call.getExpression();
      if (expression.getKind() === SyntaxKind.ImportKeyword) {
        dynamicImportDirs.add(fileDir);
      }
      const callee = expression.getText();
      if (/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(callee)) {
        const key = `${abs}#${callee}`;
        functionCalls.set(key, (functionCalls.get(key) ?? 0) + 1);
      }
    }
    for (const text of file.getDescendantsOfKind(SyntaxKind.StringLiteral)) {
      stringReferences.add(text.getLiteralText());
    }
    for (const text of file.getDescendantsOfKind(SyntaxKind.NoSubstitutionTemplateLiteral)) {
      stringReferences.add(text.getLiteralText());
    }
  }

  // Propagate barrel re-exports: importing a barrel name marks the upstream
  // declaration used. Iterate to support nested barrels.
  let changed = true;
  while (changed) {
    changed = false;
    for (const link of barrelLinks) {
      const barrelKey = `${link.fromFile.getFilePath()}#${link.exportName}`;
      if (!usedExports.has(barrelKey)) continue;
      const targetKey = `${link.targetFile.getFilePath()}#${link.exportName}`;
      if (!usedExports.has(targetKey)) {
        usedExports.set(targetKey, true);
        changed = true;
      }
    }
  }

  return {
    files,
    usedExports,
    sideEffectModules,
    dynamicImportDirs,
    functionCalls,
    stringReferences,
    importedNames,
  };
}

function collectFunctions(project, repoRoot, frontendRoot, usage, entries, buildAvailable) {
  const findings = [];
  const entryPaths = new Set(entries.map((file) => file.getFilePath?.() ?? file));
  const buildText = buildAvailable ? buildSearchText(frontendRoot) : "";
  for (const file of usage.files) {
    const rel = relative(frontendRoot, file.getFilePath());
    if (TEST_FILE_RE.test(rel)) continue;
    if (entryPaths.has(file.getFilePath())) continue;
    const functions = file.getFunctions();
    for (const fn of functions) {
      if (!fn.isExported()) continue;
      const name = fn.getName();
      if (!name) continue;
      const key = `${file.getFilePath()}#${name}`;
      if (usage.usedExports.has(key)) continue;
      if (usage.sideEffectModules.has(file.getFilePath())) continue;
      if ((usage.functionCalls.get(key) ?? 0) > 0) continue;
      if (buildText && buildText.includes(name)) continue;
      if (usage.stringReferences.has(name)) {
        findings.push({
          category: "frontend_reflection_reference",
          name,
          file: relative(repoRoot, file.getFilePath()),
          line: lineOf(file, fn.getStart()),
          confidence: "low",
          reason: "symbol name appears as a string literal; runtime/reflection registration cannot be excluded",
        });
        continue;
      }
      const dir = path.dirname(file.getFilePath());
      const dynamicNearby = usage.dynamicImportDirs.has(dir);
      const confidence = dynamicNearby || !buildAvailable ? "medium" : "high";
      findings.push({
        category: "frontend_zero_call_export",
        name,
        file: relative(repoRoot, file.getFilePath()),
        line: lineOf(file, fn.getStart()),
        confidence,
        reason: dynamicNearby
          ? "zero references; directory contains dynamic import/template resolution"
          : buildAvailable
            ? "zero references and absent from build output"
            : "zero references but build output is unavailable",
      });
    }
  }
  return findings;
}

function classTokensFromText(text) {
  const tokens = new Set();
  for (const raw of text.split(/[\s"'`{}()[\],;:]+/)) {
    const token = raw.replace(/^[.#]+/, "").replace(/[+~>]+$/, "");
    if (/^[A-Za-z_][A-Za-z0-9_-]*$/.test(token) && token.length >= 2) {
      tokens.add(token);
    }
  }
  return tokens;
}

function collectClassUsage(project) {
  const used = new Set();
  const familyPrefixes = new Set();
  for (const file of project.getSourceFiles()) {
    const filePath = file.getFilePath().split(path.sep).join("/");
    if (filePath.includes("/node_modules/") || filePath.includes("/.next/")) continue;
    if (!/\.(?:tsx?|jsx?|mjs|cjs)$/.test(filePath)) continue;
    for (const text of file.getDescendantsOfKind(SyntaxKind.StringLiteral)) {
      for (const token of classTokensFromText(text.getLiteralText())) used.add(token);
    }
    for (const text of file.getDescendantsOfKind(SyntaxKind.NoSubstitutionTemplateLiteral)) {
      for (const token of classTokensFromText(text.getLiteralText())) used.add(token);
    }
    for (const template of file.getDescendantsOfKind(SyntaxKind.TemplateExpression)) {
      const text = template.getText();
      const chunks = text.split(/\$\{[^}]*\}/);
      for (const chunk of chunks) {
        for (const token of classTokensFromText(chunk)) used.add(token);
      }
      for (let index = 0; index < chunks.length - 1; index += 1) {
        const trailing = chunks[index].trimEnd().split(/\s+/).pop();
        if (!trailing) continue;
        const prefix = trailing.replace(/^[`"'.#]+/, "").replace(/[`"']+$/, "");
        if (/^[A-Za-z_][A-Za-z0-9_-]*$/.test(prefix) && prefix.length >= 2) {
          familyPrefixes.add(prefix);
        }
      }
    }
  }
  return { used, familyPrefixes };
}

function matchesFamily(className, prefixes) {
  for (const prefix of prefixes) {
    if (className === prefix) return true;
    if (prefix.endsWith("-") && className.startsWith(prefix)) return true;
    if (className.startsWith(`${prefix}-`)) return true;
  }
  return false;
}

function collectMinifiedClasses(frontendRoot) {
  const classes = new Set();
  const dirs = [".next", "dist", "build", "out"]
    .map((name) => path.join(frontendRoot, name))
    .filter((dir) => {
      try {
        return fs.statSync(dir).isDirectory();
      } catch {
        return false;
      }
    });
  if (!dirs.length) return classes;
  let total = 0;
  for (const dir of dirs) {
    const files = listFiles(dir, [".css"], 400).slice(0, 10);
    for (const file of files) {
      const text = readText(file, 1024 * 1024);
      if (!text) continue;
      total += Buffer.byteLength(text);
      if (total > 4 * 1024 * 1024) return classes;
      for (const match of text.matchAll(/\.(-?[A-Za-z_][A-Za-z0-9_-]*)/g)) {
        classes.add(match[1]);
      }
    }
  }
  return classes;
}

function collectCssFindings(
  repoRoot,
  frontendRoot,
  usedClasses,
  buildAvailable,
  minifiedClasses,
) {
  const cssFiles = listFiles(frontendRoot, [".css", ".scss", ".sass"]);
  const findings = [];
  const seen = new Set();
  for (const file of cssFiles) {
    const text = readText(file);
    if (!text) continue;
    let root;
    try {
      root = postcssScss.parse(text, { from: file });
    } catch {
      try {
        root = postcss.parse(text, { from: file });
      } catch {
        continue;
      }
    }
    const rel = relative(repoRoot, file);
    root.walkRules((rule) => {
      if (rule.parent && rule.parent.type === "atrule" && /keyframes/i.test(rule.parent.name)) {
        return;
      }
      for (const selector of rule.selectors ?? []) {
        for (const match of selector.matchAll(/\.(-?[A-Za-z_][A-Za-z0-9_-]*)/g)) {
          const className = match[1];
          if (seen.has(`${rel}#${className}`)) continue;
          seen.add(`${rel}#${className}`);
          if (usedClasses.used.has(className)) continue;
          if (matchesFamily(className, usedClasses.familyPrefixes)) continue;
          findings.push({
            category: "frontend_unused_css_class",
            class_name: className,
            selector,
            file: rel,
            line: rule.source?.start?.line ?? 1,
            confidence: buildAvailable ? "high" : "medium",
            minified_css_checked: minifiedClasses.size > 0,
            present_in_minified_css: minifiedClasses.has(className),
            reason: buildAvailable
              ? "zero references and build output is available"
              : "zero references but build output is unavailable",
          });
        }
      }
    });
  }
  return findings;
}

function collectPublicAssets(frontendRoot, project) {
  const publicDir = path.join(frontendRoot, "public");
  if (!fs.existsSync(publicDir)) return { count: 0, referenced: 0 };
  const assets = listFiles(publicDir, [
    ".svg",
    ".png",
    ".jpg",
    ".jpeg",
    ".webp",
    ".gif",
    ".ico",
    ".avif",
  ]);
  let sourceText = "";
  for (const file of project.getSourceFiles()) {
    if (sourceText.length > 4 * 1024 * 1024) break;
    sourceText += `${file.getFullText()}\n`;
  }
  const referenced = assets.filter((asset) => {
    const rel = `/` + path.relative(frontendRoot, asset).split(path.sep).join("/");
    const base = path.basename(asset);
    return sourceText.includes(rel) || sourceText.includes(base);
  }).length;
  return { count: assets.length, referenced };
}

function main() {
  const repoRoot = path.resolve(process.argv[2] ?? ".");
  const frontendRoot = findFrontendRoot(repoRoot);
  if (!frontendRoot) {
    jsonOut({
      status: "not_applicable",
      reason_code: "NO_FRONTEND",
      message: "未发现 Next.js 前端工程。",
      items: [],
    });
    return;
  }
  const entries = collectNextEntries(frontendRoot);
  const build = buildOutputState(frontendRoot);
  let project;
  try {
    project = createProject(frontendRoot);
  } catch (error) {
    jsonOut({
      status: "not_completed",
      reason_code: "ANALYZER_ERROR",
      message: `ts-morph project creation failed: ${error.message}`,
      items: [],
    });
    return;
  }
  const usage = collectUsage(project);
  const functions = collectFunctions(
    project,
    repoRoot,
    frontendRoot,
    usage,
    entries,
    build.available,
  );
  const usedClasses = collectClassUsage(project);
  const minifiedClasses = collectMinifiedClasses(frontendRoot);
  const css = collectCssFindings(
    repoRoot,
    frontendRoot,
    usedClasses,
    build.available,
    minifiedClasses,
  );
  const items = [...functions, ...css]
    .sort((a, b) => (a.file === b.file ? a.line - b.line : a.file.localeCompare(b.file)))
    .slice(0, MAX_FINDINGS);
  const limitations = [];
  if (!build.available) {
    limitations.push("构建产物缺失，前端死代码最高只能给出中等置信度。");
  }
  if (items.length >= MAX_FINDINGS) {
    limitations.push("分析结果达到输出条数上限，已截断。");
  }
  jsonOut({
    status: build.available ? "completed" : "partial",
    reason_code: build.available ? null : "PARTIAL_ENUMERATION",
    message: build.available
      ? "前端死代码静态分析完成。"
      : "构建产物缺失，置信度已降级。",
    frontend_root: path.relative(repoRoot, frontendRoot).split(path.sep).join("/") || ".",
    build_output: build,
    next_entries: entries.map((file) => relative(repoRoot, file)),
    public_assets: collectPublicAssets(frontendRoot, project),
    counts: {
      source_files: usage.files.length,
      next_entries: entries.length,
      zero_call_functions: functions.length,
      css_classes: css.length,
      used_class_tokens: usedClasses.used.size,
      family_prefixes: usedClasses.familyPrefixes.size,
      minified_css_classes: minifiedClasses.size,
    },
    limitations,
    items,
  });
}

main();
