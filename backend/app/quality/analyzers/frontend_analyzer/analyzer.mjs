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

// Env override exists so regression tests (and operators) can exercise the
// large-repository truncation path without creating thousands of files.
const MAX_FILES = (() => {
  const raw = Number.parseInt(process.env.VIBECHECK_ANALYZER_MAX_FILES ?? "", 10);
  return Number.isFinite(raw) && raw > 0 ? raw : 4000;
})();
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
const PAGES_ENTRY_RE = /^\/src\/pages\/.+\.(?:tsx?|jsx?)$|^\/pages\/.+\.(?:tsx?|jsx?)$/;
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

function listFiles(root, extensions, maxFiles = MAX_FILES, stats = null) {
  const result = [];
  const stack = [root];
  scan: while (stack.length && result.length < maxFiles) {
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
        if (!extensions.includes(ext)) continue;
        if (result.length >= maxFiles) {
          // 同一目录里仍有未枚举的源文件：必须显式标记截断，
          // 不能因为本次 readdir 返回超过上限就静默多收或漏报。
          if (stats) stats.truncated = true;
          break scan;
        }
        result.push(full);
      }
    }
  }
  if (stats && result.length >= maxFiles && stack.length) stats.truncated = true;
  return result;
}

function readPackageJson(dir) {
  const file = path.join(dir, "package.json");
  const text = readText(file, 512 * 1024);
  if (!text) return null;
  try {
    const parsed = JSON.parse(text);
    return parsed && typeof parsed === "object" ? parsed : null;
  } catch {
    return null;
  }
}

function packageHasDependency(manifest, names) {
  if (!manifest) return false;
  for (const section of ["dependencies", "devDependencies", "peerDependencies"]) {
    const deps = manifest[section];
    if (!deps || typeof deps !== "object") continue;
    for (const name of names) {
      if (Object.prototype.hasOwnProperty.call(deps, name)) return true;
    }
  }
  return false;
}

function hasNextConfig(dir) {
  return ["next.config.js", "next.config.mjs", "next.config.ts", "next.config.cjs"]
    .map((name) => path.join(dir, name))
    .some((file) => fs.existsSync(file));
}

function hasRouterDirectory(dir) {
  return ["app", "src/app", "pages", "src/pages"]
    .map((name) => path.join(dir, name))
    .some((candidate) => {
      try {
        return fs.statSync(candidate).isDirectory();
      } catch {
        return false;
      }
    });
}

function findFrontendRoot(repoRoot) {
  // 纯后端仓库（例如 Django 的 app/ 目录）不能被误判为前端工程：
  // 目录存在只是必要条件，React/Next 依赖才是充分条件。
  const marker = (dir) => {
    if (hasNextConfig(dir)) return true;
    const manifest = readPackageJson(dir);
    if (!manifest) return false;
    if (packageHasDependency(manifest, ["next"])) return true;
    return (
      packageHasDependency(manifest, ["react", "react-dom"]) &&
      hasRouterDirectory(dir)
    );
  };
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

function collectNextEntries(frontendRoot, stats = null) {
  const entries = [];
  const candidates = listFiles(
    frontendRoot,
    [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"],
    MAX_FILES,
    stats,
  );
  for (const file of candidates) {
    const rel = relative(frontendRoot, file);
    const normalized = `/${rel}`;
    if (
      NEXT_ENTRY_RE.test(normalized) ||
      PAGES_ENTRY_RE.test(normalized) ||
      /^(?:\/)?(?:middleware|instrumentation)\.(?:tsx?|jsx?)$/.test(normalized) ||
      /^\/next\.config\.(?:js|mjs|ts)$/.test(normalized)
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
      if (total > MAX_BUILD_BYTES) return { text: chunks.join("\n"), truncated: true };
      chunks.push(text);
    }
  }
  return { text: chunks.join("\n"), truncated: false };
}

function createProject(frontendRoot, stats = null) {
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
    const files = listFiles(
      frontendRoot,
      [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"],
      MAX_FILES,
      stats,
    );
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
  const propertyReferences = new Set(); // member names seen in obj.member / obj["member"]

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
    for (const access of file.getDescendantsOfKind(SyntaxKind.PropertyAccessExpression)) {
      propertyReferences.add(access.getName());
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
    propertyReferences,
    importedNames,
  };
}

function containsIdentifier(text, name) {
  // 边界匹配，避免 "foo" 命中 "foobar"/"myFoo" 之类的子串。
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`(^|[^A-Za-z0-9_$])${escaped}([^A-Za-z0-9_$]|$)`).test(text);
}

function collectFunctions(project, repoRoot, frontendRoot, usage, entries, buildAvailable) {
  const findings = [];
  const entryPaths = new Set(entries.map((file) => file.getFilePath?.() ?? file));
  const buildScan = buildAvailable
    ? buildSearchText(frontendRoot)
    : { text: "", truncated: false };
  const buildText = buildScan.text;
  for (const file of usage.files) {
    const rel = relative(frontendRoot, file.getFilePath());
    if (TEST_FILE_RE.test(rel)) continue;
    if (entryPaths.has(file.getFilePath())) continue;
    const filePath = file.getFilePath();
    const dir = path.dirname(filePath);
    const dynamicNearby = usage.dynamicImportDirs.has(dir);
    const confidence = dynamicNearby || !buildAvailable ? "medium" : "high";

    const emit = (displayName, lookupName, start, isMember = false) => {
      if (!lookupName) return;
      const key = `${filePath}#${lookupName}`;
      if (usage.usedExports.has(key)) return;
      if (usage.sideEffectModules.has(filePath)) return;
      if (!isMember && (usage.functionCalls.get(key) ?? 0) > 0) return;
      if (isMember && usage.propertyReferences.has(lookupName)) return;
      if (buildText && containsIdentifier(buildText, lookupName)) return;
      if (usage.stringReferences.has(lookupName)) {
        findings.push({
          category: "frontend_reflection_reference",
          name: displayName,
          file: relative(repoRoot, filePath),
          line: lineOf(file, start),
          confidence: "low",
          reason: "symbol name appears as a string literal; runtime/reflection registration cannot be excluded",
        });
        return;
      }
      findings.push({
        category: "frontend_zero_call_export",
        name: displayName,
        file: relative(repoRoot, filePath),
        line: lineOf(file, start),
        confidence,
        reason: dynamicNearby
          ? "zero references; directory contains dynamic import/template resolution"
          : buildAvailable
            ? "zero references and absent from build output"
            : "zero references but build output is unavailable",
      });
    };

    for (const fn of file.getFunctions()) {
      if (!fn.isExported()) continue;
      const name = fn.getName();
      if (name) emit(name, name, fn.getStart());
    }

    for (const declaration of file.getVariableDeclarations()) {
      if (!declaration.isExported()) continue;
      const name = declaration.getName();
      if (!name) continue;
      const initializer = declaration.getInitializer();
      const kind = initializer?.getKind();
      // 标量常量可能是对外公开的配置项，噪声大；只纳入函数/对象常量。
      if (
        kind !== SyntaxKind.ObjectLiteralExpression &&
        kind !== SyntaxKind.ArrowFunction &&
        kind !== SyntaxKind.FunctionExpression
      ) {
        continue;
      }
      emit(name, name, declaration.getStart());
      // 对象成员只在对象本身被使用时检查，避免未使用对象的重复报告。
      if (
        kind === SyntaxKind.ObjectLiteralExpression &&
        usage.usedExports.has(`${filePath}#${name}`)
      ) {
        for (const property of initializer.getProperties()) {
          if (property.getKind() !== SyntaxKind.PropertyAssignment) continue;
          // 只把可执行对象成员视为候选；数据字段不是"死代码"。
          const propertyValue = property.getInitializer();
          const valueKind = propertyValue?.getKind();
          if (
            valueKind !== SyntaxKind.ArrowFunction &&
            valueKind !== SyntaxKind.FunctionExpression
          ) {
            continue;
          }
          const member = property.getName();
          if (!member) continue;
          emit(`${name}.${member}`, member, property.getStart(), true);
        }
      }
    }

    for (const declaration of file.getClasses()) {
      if (!declaration.isExported()) continue;
      const className = declaration.getName();
      if (!className) continue;
      const classKey = `${filePath}#${className}`;
      const classUsed =
        usage.usedExports.has(classKey) ||
        (usage.functionCalls.get(classKey) ?? 0) > 0;
      if (!classUsed) {
        emit(className, className, declaration.getStart());
        continue;
      }
      for (const method of declaration.getMethods()) {
        const methodName = method.getName();
        if (!methodName || methodName === "constructor" || methodName.startsWith("#")) {
          continue;
        }
        emit(`${className}.${methodName}`, methodName, method.getStart(), true);
      }
    }
  }
  return { findings, build_truncated: buildScan.truncated };
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

const CSS_MODULE_RE = /\.module\.(?:css|scss|sass|less)$/i;
const CLASS_HELPER_RE = /^(?:clsx|classnames|cn|cx|twmerge|twjoin|cva)$/i;
const CLASS_LIST_METHODS = new Set(["add", "remove", "toggle", "contains", "replace"]);

function collectClassUsage(project) {
  const used = new Set();
  const familyPrefixes = new Set();
  const moduleUsage = new Map(); // normalized css module path -> Set(local class)
  const bindings = new Map(); // local import/namespace name -> css module path

  const normalize = (value) => value.split(path.sep).join("/");
  const addTokens = (text) => {
    for (const token of classTokensFromText(text)) used.add(token);
  };
  const addModuleClass = (modulePath, className) => {
    if (!className) return;
    let set = moduleUsage.get(modulePath);
    if (!set) {
      set = new Set();
      moduleUsage.set(modulePath, set);
    }
    set.add(className);
  };
  const addTemplateTokens = (template) => {
    addTokens(template.getHead().getLiteralText());
    for (const span of template.getTemplateSpans()) {
      addTokens(span.getLiteral().getLiteralText());
    }
  };
  const addPrefixFromChunk = (chunk) => {
    const trailing = chunk.trimEnd().split(/\s+/).pop();
    if (!trailing) return;
    const prefix = trailing.replace(/^[`"'.#]+/, "").replace(/[`"']+$/, "");
    if (/^[A-Za-z_][A-Za-z0-9_-]*$/.test(prefix) && prefix.length >= 2) {
      familyPrefixes.add(prefix);
    }
  };
  const addStringsInNode = (node) => {
    if (!node) return;
    const kind = node.getKind();
    if (kind === SyntaxKind.StringLiteral) {
      addTokens(node.getLiteralText());
      return;
    }
    if (kind === SyntaxKind.NoSubstitutionTemplateLiteral) {
      addTokens(node.getLiteralText());
      return;
    }
    if (kind === SyntaxKind.TemplateExpression) {
      addTemplateTokens(node);
      // 只有插值之前的前缀片段才算 family prefix，末尾片段不是前缀。
      addPrefixFromChunk(node.getHead().getLiteralText());
      const spans = node.getTemplateSpans();
      for (let index = 0; index < spans.length - 1; index += 1) {
        addPrefixFromChunk(spans[index].getLiteral().getLiteralText());
      }
      return;
    }
    for (const text of node.getDescendantsOfKind(SyntaxKind.StringLiteral)) {
      addTokens(text.getLiteralText());
    }
    for (const text of node.getDescendantsOfKind(SyntaxKind.NoSubstitutionTemplateLiteral)) {
      addTokens(text.getLiteralText());
    }
    for (const template of node.getDescendantsOfKind(SyntaxKind.TemplateExpression)) {
      addTemplateTokens(template);
      addPrefixFromChunk(template.getHead().getLiteralText());
      const spans = template.getTemplateSpans();
      for (let index = 0; index < spans.length - 1; index += 1) {
        addPrefixFromChunk(spans[index].getLiteral().getLiteralText());
      }
    }
  };
  const addTemplatePrefixes = (node) => {
    for (const template of node.getDescendantsOfKind(SyntaxKind.TemplateExpression)) {
      const text = template.getText();
      const chunks = text.split(/\$\{[^}]*\}/);
      for (let index = 0; index < chunks.length - 1; index += 1) {
        const trailing = chunks[index].trimEnd().split(/\s+/).pop();
        if (!trailing) continue;
        const prefix = trailing.replace(/^[`"'.#]+/, "").replace(/[`"']+$/, "");
        if (/^[A-Za-z_][A-Za-z0-9_-]*$/.test(prefix) && prefix.length >= 2) {
          familyPrefixes.add(prefix);
        }
      }
    }
  };

  for (const file of project.getSourceFiles()) {
    const filePath = normalize(file.getFilePath());
    if (filePath.includes("/node_modules/") || filePath.includes("/.next/")) continue;
    if (!/\.(?:tsx?|jsx?|mjs|cjs)$/.test(filePath)) continue;

    // 1) 解析 CSS Modules：只认 import 绑定后的局部类名。
    for (const declaration of file.getImportDeclarations()) {
      const specifier = declaration.getModuleSpecifierValue();
      if (!CSS_MODULE_RE.test(specifier)) continue;
      const modulePath = normalize(path.resolve(path.dirname(filePath), specifier));
      if (!fs.existsSync(modulePath)) continue;
      const defaultImport = declaration.getDefaultImport();
      if (defaultImport) bindings.set(defaultImport.getText(), modulePath);
      const namespaceImport = declaration.getNamespaceImport();
      if (namespaceImport) bindings.set(namespaceImport.getText(), modulePath);
      for (const named of declaration.getNamedImports()) {
        const local = named.getAliasNode()?.getText() ?? named.getName();
        bindings.set(local, modulePath);
        addModuleClass(modulePath, named.getName());
      }
    }
    for (const access of file.getDescendantsOfKind(SyntaxKind.PropertyAccessExpression)) {
      const owner = access.getExpression().getText();
      const modulePath = bindings.get(owner);
      if (modulePath) addModuleClass(modulePath, access.getName());
    }
    for (const access of file.getDescendantsOfKind(SyntaxKind.ElementAccessExpression)) {
      const modulePath = bindings.get(access.getExpression().getText());
      if (!modulePath) continue;
      const argument = access.getArgumentExpression();
      if (!argument) continue;
      if (
        argument.getKind() === SyntaxKind.StringLiteral ||
        argument.getKind() === SyntaxKind.NoSubstitutionTemplateLiteral
      ) {
        addModuleClass(modulePath, argument.getLiteralText());
      }
    }
    for (const declaration of file.getVariableDeclarations()) {
      const nameNode = declaration.getNameNode();
      if (nameNode.getKind() !== SyntaxKind.ObjectBindingPattern) continue;
      const modulePath = bindings.get(declaration.getInitializer()?.getText() ?? "");
      if (!modulePath) continue;
      for (const element of nameNode.getElements()) {
        addModuleClass(modulePath, element.getName());
      }
    }

    // 2) 全局 CSS 的来源：className/class、class helper、classList，
    // 以及变量常量/映射与 return 值中的类名字符串（常见间接用法）。
    for (const attribute of file.getDescendantsOfKind(SyntaxKind.JsxAttribute)) {
      const attributeName = attribute.getNameNode().getText();
      if (attributeName !== "className" && attributeName !== "class") continue;
      addStringsInNode(attribute.getInitializer());
    }
    for (const declaration of file.getVariableDeclarations()) {
      addStringsInNode(declaration.getInitializer());
    }
    for (const statement of file.getDescendantsOfKind(SyntaxKind.ReturnStatement)) {
      addStringsInNode(statement.getExpression());
    }
    for (const call of file.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      const callee = call.getExpression().getText().split(".").pop() ?? "";
      if (CLASS_HELPER_RE.test(callee)) {
        for (const argument of call.getArguments()) addStringsInNode(argument);
        addTemplatePrefixes(call);
        continue;
      }
      if (call.getExpression().getKind() !== SyntaxKind.PropertyAccessExpression) {
        continue;
      }
      const property = call.getExpression().getName?.() ?? "";
      if (!CLASS_LIST_METHODS.has(property)) continue;
      const argument = call.getArguments()[0];
      if (argument) addStringsInNode(argument);
    }
  }
  return { used, familyPrefixes, moduleUsage };
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
    const moduleUsed = CSS_MODULE_RE.test(file)
      ? usedClasses.moduleUsage.get(file.split(path.sep).join("/")) ?? new Set()
      : null;
    root.walkRules((rule) => {
      if (rule.parent && rule.parent.type === "atrule" && /keyframes/i.test(rule.parent.name)) {
        return;
      }
      for (const selector of rule.selectors ?? []) {
        for (const match of selector.matchAll(/\.(-?[A-Za-z_][A-Za-z0-9_-]*)/g)) {
          const className = match[1];
          if (seen.has(`${rel}#${className}`)) continue;
          seen.add(`${rel}#${className}`);
          if (moduleUsed) {
            // CSS Modules 只认同一模块 import 绑定后的局部类名。
            if (moduleUsed.has(className)) continue;
            if (/:global\(/.test(selector) && usedClasses.used.has(className)) continue;
          } else {
            if (usedClasses.used.has(className)) continue;
            if (matchesFamily(className, usedClasses.familyPrefixes)) continue;
          }
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
  const scanStats = { truncated: false };
  const entries = collectNextEntries(frontendRoot, scanStats);
  const build = buildOutputState(frontendRoot);
  let project;
  try {
    project = createProject(frontendRoot, scanStats);
  } catch (error) {
    // 原始异常只写服务端 stderr，对外只给稳定错误码与简短描述。
    console.error(`ts-morph project creation failed: ${error?.stack ?? error}`);
    jsonOut({
      status: "not_completed",
      reason_code: "ANALYZER_ERROR",
      message: "前端分析器项目初始化失败，未完成。",
      items: [],
    });
    return;
  }
  const usage = collectUsage(project);
  const functionScan = collectFunctions(
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
  const allItems = [...functionScan.findings, ...css].sort((a, b) =>
    a.file === b.file ? a.line - b.line : a.file.localeCompare(b.file),
  );
  const items = allItems.slice(0, MAX_FINDINGS);
  const omittedItems = Math.max(0, allItems.length - items.length);
  const outputTruncated = omittedItems > 0;
  const enumerationTruncated = scanStats.truncated;
  const degraded = !build.available || enumerationTruncated || functionScan.build_truncated;
  const limitations = [];
  if (!build.available) {
    limitations.push("构建产物缺失，前端死代码最高只能给出中等置信度。");
  }
  if (outputTruncated) {
    limitations.push(`分析结果超过输出上限，已省略 ${omittedItems} 条。`);
  }
  if (enumerationTruncated) {
    limitations.push("源文件枚举达到上限，部分文件未分析（省略数量未知）。");
  }
  if (functionScan.build_truncated) {
    limitations.push("构建产物扫描达到字节上限，部分产物未参与比对。");
  }
  const truncated = outputTruncated || enumerationTruncated;
  let status = truncated || degraded ? "partial" : "completed";
  let reasonCode = truncated
    ? "RESULT_TRUNCATED"
    : degraded
      ? "PARTIAL_ENUMERATION"
      : null;
  let message = "前端死代码静态分析完成。";
  if (outputTruncated) {
    message = `分析结果超出容量上限，已省略 ${omittedItems} 条。`;
  } else if (enumerationTruncated) {
    message = "源文件数量超过枚举上限，部分文件未分析（省略数量未知）。";
  } else if (degraded) {
    message = "部分输入缺失或达到上限，结果可能不完整。";
  }
  jsonOut({
    status,
    reason_code: reasonCode,
    message,
    frontend_root: path.relative(repoRoot, frontendRoot).split(path.sep).join("/") || ".",
    build_output: build,
    next_entries: entries.map((file) => relative(repoRoot, file)),
    public_assets: collectPublicAssets(frontendRoot, project),
    counts: {
      source_files: usage.files.length,
      next_entries: entries.length,
      zero_call_functions: functionScan.findings.length,
      css_classes: css.length,
      used_class_tokens: usedClasses.used.size,
      family_prefixes: usedClasses.familyPrefixes.size,
      minified_css_classes: minifiedClasses.size,
      omitted_items: omittedItems,
      omitted_source_files: scanStats.truncated ? null : 0,
    },
    limitations,
    items,
  });
}

main();
