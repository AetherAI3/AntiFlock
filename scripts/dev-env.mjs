#!/usr/bin/env node

import { ensureDevelopmentEnvironment } from "./dev-environment.mjs";
import { root } from "./tooling.mjs";

try {
  const result = ensureDevelopmentEnvironment(root);
  const action = result.created ? "Created" : result.updated ? "Updated" : "Reusing";
  process.stdout.write(`${action} private development environment at .antiflock/dev.env.\n`);
} catch (error) {
  process.stderr.write(`Development environment setup failed: ${error.message}\n`);
  process.exitCode = 1;
}
