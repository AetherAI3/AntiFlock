#!/usr/bin/env node
// Bootstraps a local AntiFl0ck checkout and drives its Docker Compose stack.
// Zero runtime dependencies by design — this package only shells out to git,
// node, and docker, all of which the underlying stack already requires.

import { existsSync, mkdirSync, readdirSync, readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const selfDir = dirname(fileURLToPath(import.meta.url));
const ownPackage = JSON.parse(readFileSync(join(selfDir, "..", "package.json"), "utf8"));

const REPO_URL = "https://github.com/AetherAI3/AntiFlock.git";
const DEFAULT_REF = "main";
const DEFAULT_DIR = "antiflock";
const REF_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$/;

const composeActions = new Set(["dev", "down", "lab", "build", "clean"]);

function printHelp() {
  process.stdout.write(`antiflock ${ownPackage.version} — bootstrap and run AntiFl0ck locally

Usage:
  antiflock init [--dir <path>] [--ref <git-ref>]     Clone (if needed) and generate local config
  antiflock dev  [--dir <path>] [--ref <git-ref>]      Build and start the full local stack
  antiflock lab  [--dir <path>] [--ref <git-ref>]      Run the one-shot coffee-shop simulation
  antiflock build [--dir <path>] [--ref <git-ref>]     Build images without starting them
  antiflock down [--dir <path>]                        Stop the local stack
  antiflock clean [--dir <path>]                        Stop and remove local stack volumes
  antiflock --version                                   Print the CLI version
  antiflock --help                                      Show this help

Requires Docker and Node 20+. Defaults to a fresh checkout in ./antiflock unless
run from inside an existing AntiFlock checkout, or --dir points at one.

Docs: https://github.com/AetherAI3/AntiFlock#readme
`);
}

function isCheckout(dir) {
  return existsSync(join(dir, "docker-compose.yml")) && existsSync(join(dir, "scripts", "compose.mjs"));
}

function parseArguments(argv) {
  const options = { dir: undefined, ref: DEFAULT_REF };
  const positionals = [];
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--dir") {
      options.dir = argv[index + 1];
      index += 1;
    } else if (argument === "--ref") {
      options.ref = argv[index + 1];
      index += 1;
    } else if (argument === "--help" || argument === "-h") {
      options.help = true;
    } else if (argument === "--version" || argument === "-v") {
      options.version = true;
    } else {
      positionals.push(argument);
    }
  }
  return { command: positionals[0], options };
}

function resolveTargetDirectory(options) {
  if (options.dir) return resolve(options.dir);
  if (isCheckout(process.cwd())) return process.cwd();
  return resolve(DEFAULT_DIR);
}

function ensureGitAvailable() {
  const result = spawnSync("git", ["--version"], { stdio: "ignore" });
  if (result.error || result.status !== 0) {
    process.stderr.write("git is required to fetch AntiFlock. Install it, then re-run.\n");
    process.exit(1);
  }
}

function ensureCheckout(targetDir, ref) {
  if (isCheckout(targetDir)) return { cloned: false };

  if (existsSync(targetDir) && readdirSync(targetDir).length > 0) {
    process.stderr.write(
      `${targetDir} already exists and is not an AntiFlock checkout. ` +
        `Pick an empty directory with --dir, or remove it first.\n`,
    );
    process.exit(1);
  }
  if (!REF_PATTERN.test(ref)) {
    process.stderr.write(`Invalid --ref value: ${ref}\n`);
    process.exit(1);
  }

  ensureGitAvailable();
  mkdirSync(targetDir, { recursive: true });
  process.stdout.write(`Cloning AntiFlock (${ref}) into ${targetDir} ...\n`);
  const clone = spawnSync("git", ["clone", "--depth", "1", "--branch", ref, REPO_URL, targetDir], {
    stdio: "inherit",
  });
  if (clone.status !== 0) {
    process.stderr.write("git clone failed. See output above.\n");
    process.exit(clone.status ?? 1);
  }
  return { cloned: true };
}

async function runInit(targetDir) {
  const moduleURL = pathToFileURL(join(targetDir, "scripts", "dev-environment.mjs")).href;
  const { ensureDevelopmentEnvironment } = await import(moduleURL);
  const environment = ensureDevelopmentEnvironment(targetDir);
  const status = environment.created ? "Generated" : environment.updated ? "Updated" : "Reusing";
  process.stdout.write(`${status} local config at ${environment.environmentPath}\n\n`);
  process.stdout.write(
    [
      "Next steps:",
      "  antiflock dev   Build and start Core, the simulator, and the dashboard",
      "  antiflock lab   Run the one-shot coffee-shop simulation against a running stack",
      "",
      "Once running, open http://127.0.0.1:4173 — username `operator`, token is",
      "ANTIFLOCK_OPERATOR_TOKEN in the config file above. Never commit that file.",
      "",
      "Feature/config knobs live in configs/demo.yaml and docker-compose.yml",
      "(profiles, ports, demo-mode flags); full guide: docs/operator-runbook.md",
      "in the checkout.",
      "",
    ].join("\n"),
  );
}

function runCompose(targetDir, action) {
  const result = spawnSync(process.execPath, [join(targetDir, "scripts", "compose.mjs"), action], {
    cwd: targetDir,
    stdio: "inherit",
  });
  process.exit(result.status ?? 1);
}

async function main() {
  const { command, options } = parseArguments(process.argv.slice(2));

  if (options.version) {
    process.stdout.write(`${ownPackage.version}\n`);
    return;
  }
  if (options.help) {
    printHelp();
    return;
  }
  if (!command) {
    printHelp();
    process.exit(2);
  }

  if (command !== "init" && !composeActions.has(command)) {
    process.stderr.write(`Unknown command: ${command}\n\n`);
    printHelp();
    process.exit(2);
  }

  const targetDir = resolveTargetDirectory(options);
  ensureCheckout(targetDir, options.ref ?? DEFAULT_REF);

  if (command === "init") {
    await runInit(targetDir);
    return;
  }
  runCompose(targetDir, command);
}

main().catch((error) => {
  process.stderr.write(`${error?.message ?? error}\n`);
  process.exit(1);
});
