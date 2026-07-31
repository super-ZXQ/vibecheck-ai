import { cp, mkdir, stat } from "node:fs/promises";

async function copyIfPresent(source, destination) {
  try {
    await stat(source);
  } catch (error) {
    if (error?.code === "ENOENT") return;
    throw error;
  }
  await cp(source, destination, { recursive: true });
}

await mkdir(".next/standalone/.next", { recursive: true });
await copyIfPresent(".next/static", ".next/standalone/.next/static");
await copyIfPresent("public", ".next/standalone/public");
