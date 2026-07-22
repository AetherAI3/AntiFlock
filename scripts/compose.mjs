#!/usr/bin/env node

import { relative, sep } from "node:path";
import { ensureDevelopmentEnvironment } from "./dev-environment.mjs";
import { commandExists, root, runStep } from "./tooling.mjs";

const commands = Object.freeze({
  dev: ["up", "--build"],
  down: ["down", "--remove-orphans"],
  lab: ["--profile", "lab", "up", "--build", "--abort-on-container-exit", "lab"],
  build: ["build"],
  clean: ["down", "--remove-orphans", "--volumes"],
});

const action = process.argv[2];
if (!commands[action] || process.argv.length !== 3) {
  process.stderr.write("Usage: node scripts/compose.mjs <dev|down|lab|build|clean>\n");
  process.exit(2);
}

try {
  const environment = ensureDevelopmentEnvironment(root);
  const status = environment.created ? "Created" : environment.updated ? "Updated" : "Reusing";
  process.stdout.write(`${status} private development environment at .antiflock/dev.env.\n`);

  if (!commandExists("docker")) throw new Error("Docker is required to run the local AntiFlock stack.");
  const environmentArgument = relative(root, environment.environmentPath).split(sep).join("/");
  const passed = runStep(
    `Docker Compose ${action}`,
    "docker",
    ["compose", "--env-file", environmentArgument, ...commands[action]],
    { timeout: 1_800_000 },
  );
  if (!passed) process.exitCode = 1;
} catch (error) {
  process.stderr.write(`Local stack command failed: ${error.message}\n`);
  process.exitCode = 1;
}
