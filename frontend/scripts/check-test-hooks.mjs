import { readdir, readFile } from "node:fs/promises";
import path from "node:path";

const sourceDirectories = ["app", "lib", "hooks", "components"];
const forbiddenMarker = "__TEST_";

async function listFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const entryPath = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await listFiles(entryPath)));
    } else {
      files.push(entryPath);
    }
  }
  return files;
}

for (const directory of sourceDirectories) {
  for (const file of await listFiles(directory)) {
    const content = await readFile(file, "utf8");
    if (content.includes(forbiddenMarker)) {
      throw new Error(`Forbidden test hook marker found in ${file}`);
    }
  }
}
