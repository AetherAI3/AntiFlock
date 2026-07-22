#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const commands = [
  ["Tests", "node", ["scripts/test-all.mjs"]],
  ["Acceptance", "node", ["scripts/acceptance.mjs", "--strict"]],
];

for (const [label, command, args] of commands) {
  process.stdout.write(`\n==> ${label}\n`);
  const result = spawnSync(command, args, { cwd: root, stdio: "inherit", timeout: 900_000, env: { ...process.env, CI: "1" } });
  if (result.status !== 0) process.exit(result.status ?? 1);
}

