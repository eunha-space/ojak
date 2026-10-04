import { cpSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const docs = fileURLToPath(new URL(".", import.meta.url));
const target = fileURLToPath(new URL("../target/api-docs/", import.meta.url));

function run(command, args) {
  const result = spawnSync(command, args, { cwd: docs, stdio: "inherit" });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}

run("cargo", [
  "doc", "--locked", "--no-deps", "--lib",
  "--manifest-path", "../Cargo.toml", "--target-dir", target,
  "-p", "ojak", "-p", "ojak-axum", "-p", "ojak-postgres",
  "-p", "ojak-redis", "-p", "ojak-sig", "-p", "ojak-jsonld", "-p", "ojak-vocab",
]);
run(process.execPath, ["node_modules/vitepress/bin/vitepress.js", "build"]);

const api = new URL(".vitepress/dist/api/", import.meta.url);
mkdirSync(api, { recursive: true });
cpSync(join(target, "doc"), api, { recursive: true });
