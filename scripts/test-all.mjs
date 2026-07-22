#!/usr/bin/env node

import {
  goPackagePatterns,
  javascriptWorkspaces,
  requireFile,
  runAndroidTests,
  runGoStep,
  runStep,
  runWorkspaceScript,
} from "./tooling.mjs";

const failures = [];

function check(label, passed) {
  if (!passed) failures.push(label);
}

check(
  "Tooling tests",
  runStep("Tooling tests", process.execPath, ["--test", "scripts/dev-environment.test.mjs"], {
    timeout: 300_000,
  }),
);

if (requireFile("go.mod", "Go module")) {
  check("Go race tests", runGoStep("Go race tests", ["test", "-race", ...goPackagePatterns], { timeout: 900_000 }));
} else {
  failures.push("Go race tests");
}

for (const workspace of javascriptWorkspaces) {
  check(`${workspace} tests`, runWorkspaceScript(workspace, "test", { timeout: 900_000 }));
}

check("Android JVM tests", runAndroidTests());

if (failures.length > 0) {
  process.stderr.write(`\nFailed suites: ${failures.join(", ")}\n`);
  process.exitCode = 1;
}
