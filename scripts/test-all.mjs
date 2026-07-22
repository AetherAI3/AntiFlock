#!/usr/bin/env node

import { existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const failures = [];

function run(label, command, args, cwd = root, timeout = 600_000) {
  process.stdout.write(`\n==> ${label}\n`);
  const result = spawnSync(command, args, { cwd, stdio: "inherit", timeout, env: { ...process.env, CI: "1" } });
  if (result.status !== 0) failures.push(label);
}

function hasCommand(command) {
  return spawnSync(process.platform === "win32" ? "where.exe" : "sh", process.platform === "win32" ? [command] : ["-c", `command -v ${command}`], { stdio: "ignore" }).status === 0;
}

if (existsSync(join(root, "go.mod"))) {
  if (hasCommand("go")) {
    run("Go tests", "go", ["test", "-race", "./..."]);
  } else {
    run("Go tests (container)", "docker", ["run", "--rm", "-v", `${root}:/workspace`, "-w", "/workspace", "golang:1.26.5-bookworm", "go", "test", "./..."]);
  }
}

for (const workspace of ["apps/web", "sdk/typescript", "apps/aether-demo"]) {
  if (existsSync(join(root, workspace, "package.json"))) {
    run(`${workspace} tests`, "npm.cmd", ["test", "--prefix", workspace]);
  }
}

if (failures.length > 0) {
  process.stderr.write(`\nFailed suites: ${failures.join(", ")}\n`);
  process.exitCode = 1;
}

