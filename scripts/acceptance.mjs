#!/usr/bin/env node

import { existsSync, readFileSync, readdirSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { versions } from "./tooling.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const strict = process.argv.includes("--strict");

function pathExists(path) {
  return existsSync(join(root, path));
}

function pathsGate(id, title, paths) {
  const missing = paths.filter((path) => !pathExists(path));
  return {
    id,
    title,
    passed: missing.length === 0,
    evidence: missing.length === 0 ? paths : [],
    missing,
  };
}

function workingNameContractsGate(paths, packagePaths) {
  const gate = pathsGate("contracts", "Locked security, privacy, and working-name contracts", paths);
  const publishable = [];
  for (const packagePath of packagePaths) {
    const absolute = join(root, packagePath);
    if (!existsSync(absolute)) {
      publishable.push(packagePath);
      continue;
    }
    try {
      if (JSON.parse(readFileSync(absolute, "utf8")).private !== true) {
        publishable.push(`${packagePath}#private=true`);
      }
    } catch {
      publishable.push(`${packagePath}#valid-json`);
    }
  }
  return {
    ...gate,
    passed: gate.passed && publishable.length === 0,
    evidence: gate.passed && publishable.length === 0 ? [...gate.evidence, ...packagePaths] : [],
    missing: [...gate.missing, ...publishable],
  };
}

function commandExists(command) {
  const probe = process.platform === "win32" ? "where.exe" : "sh";
  const args = process.platform === "win32" ? [command] : ["-c", `command -v ${command}`];
  return spawnSync(probe, args, { encoding: "utf8", stdio: "ignore" }).status === 0;
}

function run(command, args, cwd = root, timeout = 180_000) {
  const isWindowsBatch = process.platform === "win32" && /\.(?:bat|cmd)$/i.test(command);
  const executable = isWindowsBatch ? (process.env.ComSpec ?? "cmd.exe") : command;
  const executableArgs = isWindowsBatch ? ["/d", "/s", "/c", command, ...args] : args;
  const result = spawnSync(executable, executableArgs, {
    cwd,
    encoding: "utf8",
    timeout,
    env: { ...process.env, CI: "1" },
    shell: false,
  });

  return {
    command: [command, ...args].join(" "),
    passed: result.status === 0,
    status: result.status,
    stdout: (result.stdout ?? "").trim().slice(-4000),
    stderr: (result.stderr ?? "").trim().slice(-4000),
    error: result.error?.message,
  };
}

function combine(results) {
  const failed = results.find((result) => !result.passed);
  return {
    command: results.map((result) => result.command).join(" && "),
    passed: failed === undefined,
    status: failed?.status ?? 0,
    stdout: results
      .map((result) => result.stdout)
      .filter(Boolean)
      .join("\n"),
    stderr: results
      .map((result) => result.stderr)
      .filter(Boolean)
      .join("\n"),
    error: failed?.error,
    steps: results,
  };
}

function runnableGate(id, title, prerequisites, runner) {
  const missing = prerequisites.filter((path) => !pathExists(path));
  if (missing.length > 0) {
    return { id, title, passed: false, evidence: [], missing, command: null };
  }

  const result = runner();
  return {
    id,
    title,
    passed: result.passed,
    evidence: result.passed ? [result.command] : [],
    missing: [],
    command: result,
  };
}

const goScopes = Object.freeze({
  core: Object.freeze([
    "./api/gen/go/...",
    "./internal/...",
    "./cmd/antiflock-core",
    "./cmd/antiflockctl",
    "./core/config",
    "./core/retention",
    "./core/server",
  ]),
  eventSpine: Object.freeze([
    "./core/audit",
    "./core/enrollment",
    "./core/events",
    "./core/identity",
    "./core/storage",
  ]),
  decisionPlane: Object.freeze([
    "./core/actions",
    "./core/findings",
    "./core/footprint",
    "./core/nano",
    "./core/policy",
    "./core/posture",
    "./core/scrambler",
  ]),
  agent: Object.freeze([
    "./adapters/...",
    "./agent/...",
    "./cmd/antiflock-agent",
    "./cmd/antiflock-sim",
  ]),
  coffeeShop: Object.freeze(["./tests/end-to-end"]),
});

function goTest(packagePatterns, extraArgs = []) {
  const args = ["test", "-count=1", ...extraArgs, ...packagePatterns];
  if (commandExists("go")) {
    return run("go", args, root, 300_000);
  }

  if (!commandExists("docker")) {
    return {
      command: `go ${args.join(" ")}`,
      passed: false,
      status: null,
      stderr: "Neither Go nor Docker is available.",
    };
  }

  const dockerInfo = run("docker", ["info", "--format", "{{.ServerVersion}}"], root, 30_000);
  if (!dockerInfo.passed) {
    return {
      command: "docker info",
      passed: false,
      status: dockerInfo.status,
      stderr: "Docker is installed but its engine is unavailable.",
    };
  }

  return run(
    "docker",
    [
      "run",
      "--rm",
      "-e",
      "CGO_ENABLED=0",
      "-v",
      `${root}:/workspace`,
      "-v",
      "antiflock-go-mod:/go/pkg/mod",
      "-v",
      "antiflock-go-build:/root/.cache/go-build",
      "-w",
      "/workspace",
      versions.goImage,
      "go",
      ...args,
    ],
    root,
    600_000,
  );
}

function androidTest() {
  const directory = join(root, "apps", "android");
  const wrapper = process.platform === "win32" ? "gradlew.bat" : "gradlew";
  const wrapperPath = join(directory, wrapper);
  if (!existsSync(wrapperPath)) {
    return {
      command: `${wrapper} --no-daemon test`,
      passed: false,
      status: null,
      stderr: "The checked-in Android Gradle wrapper is missing.",
    };
  }

  if (commandExists("java")) {
    const command = process.platform === "win32" ? wrapperPath : `./${wrapper}`;
    return run(command, ["--no-daemon", "test"], directory, 900_000);
  }

  if (!commandExists("docker")) {
    return {
      command: `${wrapper} --no-daemon test`,
      passed: false,
      status: null,
      stderr: "Neither Java nor Docker is available.",
    };
  }

  const dockerInfo = run("docker", ["info", "--format", "{{.ServerVersion}}"], root, 30_000);
  if (!dockerInfo.passed) {
    return {
      command: "docker info",
      passed: false,
      status: dockerInfo.status,
      stderr: "Docker is installed but its engine is unavailable.",
    };
  }

  return run(
    "docker",
    [
      "run",
      "--rm",
      "-e",
      "GRADLE_USER_HOME=/home/gradle/.gradle",
      "-v",
      `${root}:/workspace`,
      "-v",
      "antiflock-gradle-cache:/home/gradle/.gradle",
      "-w",
      "/workspace/apps/android",
      versions.gradleImage,
      "bash",
      "./gradlew",
      "--no-daemon",
      "test",
    ],
    root,
    900_000,
  );
}

function npmTest(directory) {
  const packagePath = join(root, directory, "package.json");
  if (!existsSync(packagePath)) {
    return { command: `npm test --prefix ${directory}`, passed: false, status: null };
  }
  const pkg = JSON.parse(readFileSync(packagePath, "utf8"));
  const script = pkg.scripts?.verify ? "verify" : "test";
  const npm = process.platform === "win32" ? "npm.cmd" : "npm";
  return run(npm, ["run", script, "--prefix", directory], root, 300_000);
}

function npmRootScript(script, timeout = 300_000) {
  const npm = process.platform === "win32" ? "npm.cmd" : "npm";
  return run(npm, ["run", script], root, timeout);
}

// Gate 11: adversarial fixtures are present, statically sound, and pass.
// A hostile test file must contain at least one test that is not skipped
// unconditionally, every skip must carry a KNOWN-GAP id (or an
// ENV-UNAVAILABLE reason), and every gap id must be documented in
// docs/adversarial-qualification.md. The suites are then executed.
const adversarialSuiteDirectories = Object.freeze(["tests/hostile", "tests/replay", "tests/fuzz", "tests/netns"]);
const adversarialStaticDirectories = Object.freeze(["tests/hostile", "tests/replay"]);
const gapIdPattern = /KNOWN-GAP (AF-GAP-\d{3}):/;
const environmentSkipPattern = /^ENV-UNAVAILABLE:/;

function listGoTestFiles(directory) {
  const absolute = join(root, directory);
  if (!existsSync(absolute)) return [];
  return readdirSync(absolute, { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith("_test.go"))
    .map((entry) => `${directory}/${entry.name}`)
    .sort();
}

function skipLiteral(source, index) {
  // Returns the first string literal argument of the t.Skip/t.Skipf call
  // starting at index, or null when the argument is not a literal.
  const rest = source.slice(index);
  const match = rest.match(/^t\.Skipf?\(\s*("((?:[^"\\]|\\.)*)"|`([^`]*)`)/);
  if (!match) return null;
  return match[2] ?? match[3] ?? "";
}

function inspectHostileFile(path) {
  const source = readFileSync(join(root, path), "utf8");
  const problems = [];
  const gapIds = new Set();
  let tests = 0;
  let liveTests = 0;
  for (const match of source.matchAll(/^func (Test[A-Za-z0-9_]+)\(t \*testing\.T\) \{\n([\s\S]*?)\n\}\n/gm)) {
    tests += 1;
    // A skip indented by exactly one tab is a top-level statement of the test
    // body: the whole test is skipped unconditionally.
    if (!/^\tt\.Skipf?\(/m.test(match[2])) liveTests += 1;
  }
  for (const match of source.matchAll(/t\.Skipf?\(/g)) {
    const literal = skipLiteral(source, match.index);
    const line = source.slice(0, match.index).split("\n").length;
    if (literal === null) {
      problems.push(`${path}:${line} skip reason must be a string literal`);
      continue;
    }
    const gap = literal.match(gapIdPattern);
    if (gap) {
      gapIds.add(gap[1]);
    } else if (!environmentSkipPattern.test(literal)) {
      problems.push(`${path}:${line} skip lacks a KNOWN-GAP AF-GAP-nnn id: ${JSON.stringify(literal)}`);
    }
  }
  if (tests === 0) problems.push(`${path} declares no tests`);
  else if (liveTests === 0) problems.push(`${path} has no test that is not skipped unconditionally`);
  return { problems, gapIds, tests, liveTests };
}

function adversarialFixturesGate() {
  const id = "adversarial-fixtures";
  const title = "Adversarial fixtures present, every skip names a documented gap, and the suites pass";
  const documentation = "docs/adversarial-qualification.md";
  const missing = [];
  const evidence = [];
  const documented = existsSync(join(root, documentation))
    ? new Set([...readFileSync(join(root, documentation), "utf8").matchAll(/AF-GAP-\d{3}/g)].map((match) => match[0]))
    : null;
  if (documented === null) missing.push(`${documentation} is missing`);
  const files = adversarialStaticDirectories.flatMap(listGoTestFiles);
  if (files.length === 0) missing.push("no adversarial test files under tests/hostile or tests/replay");
  let tests = 0;
  let liveTests = 0;
  for (const file of files) {
    const inspection = inspectHostileFile(file);
    tests += inspection.tests;
    liveTests += inspection.liveTests;
    missing.push(...inspection.problems);
    for (const gapId of inspection.gapIds) {
      if (documented && !documented.has(gapId)) missing.push(`${file} references ${gapId}, which ${documentation} does not document`);
    }
    if (inspection.problems.length === 0) evidence.push(`${file}: ${inspection.liveTests}/${inspection.tests} tests live`);
  }
  for (const directory of adversarialSuiteDirectories) {
    if (!existsSync(join(root, directory))) missing.push(`${directory} is missing`);
  }
  if (missing.length > 0) {
    return { id, title, passed: false, evidence: [], missing, command: null, tests, liveTests };
  }
  const result = goTest(adversarialSuiteDirectories.map((directory) => `./${directory}/`), ["-race"]);
  return {
    id,
    title,
    passed: result.passed,
    evidence: result.passed ? [...evidence, result.command] : [],
    missing: result.passed ? [] : ["adversarial suites failed"],
    command: result,
    tests,
    liveTests,
  };
}

// Gate 12: the external adversarial CI (rootless netns smoke, disposable VM,
// partition and upgrade drills) must report "pass" through the
// ADVERSARIAL_CI_RESULT environment variable or the file named by
// ADVERSARIAL_CI_RESULT_FILE. Absence is a failure: an unavailable external
// gate is never a pass. The gate is required-once-configured: --strict
// treats it as required as soon as either input is present.
function externalAdversarialGate() {
  const id = "external-adversarial-ci";
  const title = "External adversarial CI reports pass";
  const unavailable = "external adversarial CI unavailable is not a pass";
  let source = null;
  let value = null;
  if (process.env.ADVERSARIAL_CI_RESULT !== undefined) {
    source = "env:ADVERSARIAL_CI_RESULT";
    value = process.env.ADVERSARIAL_CI_RESULT;
  } else if (process.env.ADVERSARIAL_CI_RESULT_FILE) {
    source = `file:${process.env.ADVERSARIAL_CI_RESULT_FILE}`;
    try {
      value = readFileSync(process.env.ADVERSARIAL_CI_RESULT_FILE, "utf8");
    } catch {
      value = null;
    }
  }
  const configured = source !== null;
  const passed = configured && value !== null && value.trim() === "pass";
  return {
    id,
    title,
    passed,
    required: configured,
    requiredOnceConfigured: true,
    evidence: passed ? [source] : [],
    missing: passed ? [] : [configured ? `${source} reported ${JSON.stringify(value === null ? null : value.trim())}; ${unavailable}` : unavailable],
    command: null,
  };
}

const gates = [
  workingNameContractsGate([
    "LICENSE",
    "SECURITY.md",
    "GOVERNANCE.md",
    "docs/vision.md",
    "docs/threat-model.md",
    "docs/evidence-model.md",
    "docs/privacy-invariants.md",
    "docs/protection-states.md",
    "docs/community-intelligence-policy.md",
    "docs/scrambler-safety-model.md",
  ], [
    "package.json",
    "apps/web/package.json",
    "apps/aether-demo/package.json",
    "sdk/typescript/package.json",
  ]),
  runnableGate("schemas", "Canonical protocol schemas format, lint, build, and generated-code parity", [
    "buf.yaml",
    "buf.gen.yaml",
    "api/proto/antiflock/v1/common.proto",
    "api/proto/antiflock/v1/event.proto",
    "api/proto/antiflock/v1/finding.proto",
    "api/proto/antiflock/v1/posture.proto",
    "api/proto/antiflock/v1/policy.proto",
    "api/proto/antiflock/v1/plan.proto",
    "api/proto/antiflock/v1/action.proto",
  ], () => run(process.execPath, ["scripts/verify.mjs", "--section", "proto"], root, 600_000)),
  runnableGate("core", "Core API, configuration, retention, and CLI behavior", [
    "go.mod",
    "cmd/antiflock-core/main.go",
  ], () => goTest(goScopes.core)),
  runnableGate("event-spine", "Durable identity, enrollment, event, projection, and audit behavior", [
    "go.mod",
    "core/storage/migrations/001_initial.sql",
  ], () => goTest(goScopes.eventSpine)),
  runnableGate("decision-plane", "Fail-closed posture, policy, finding, action, and Scrambler behavior", [
    "go.mod",
    "core/posture/engine.go",
  ], () => goTest(goScopes.decisionPlane)),
  runnableGate("agent", "Agent observation, mesh probing, enforcement, verification, and rollback behavior", [
    "go.mod",
    "cmd/antiflock-agent/main.go",
  ], () => goTest(goScopes.agent)),
  runnableGate("web", "Third-Eye dashboard rendering, live-data, and proxy behavior", [
    "apps/web/package.json",
  ], () => npmTest("apps/web")),
  runnableGate("secure-action-sdk", "Secure Action SDK and Aether fail-closed lifecycle behavior", [
    "sdk/typescript/package.json",
    "apps/aether-demo/package.json",
    "scripts/sdk-live-e2e.mjs",
    "deploy/compose/sdk-live.override.yml",
  ], () => combine([
    npmTest("sdk/typescript"),
    npmTest("apps/aether-demo"),
    npmRootScript("test:sdk:live", 600_000),
  ])),
  runnableGate("android", "Android Guard reference state-machine and fail-closed adapter behavior", [
    "apps/android/settings.gradle.kts",
    "apps/android/gradle/wrapper/gradle-wrapper.jar",
    "apps/android/gradle/wrapper/gradle-wrapper.properties",
  ], androidTest),
  runnableGate("coffee-shop", "Auditable coffee-shop failure and recovery acceptance scenario", [
    "tests/end-to-end/coffee_shop_test.go",
    "go.mod",
  ], () => goTest(
    goScopes.coffeeShop,
    ["-run", "^TestCoffeeShopFailureHoldRecoveryAndRelease$"],
  )),
  adversarialFixturesGate(),
  externalAdversarialGate(),
];

for (const gate of gates) {
  if (gate.required === undefined) gate.required = true;
}
const passed = gates.filter((gate) => gate.passed).length;
const requiredGates = gates.filter((gate) => gate.required);
const requiredPassed = requiredGates.filter((gate) => gate.passed).length;
const report = {
  schemaVersion: "antiflock.reference-vertical-slice-acceptance/v1",
  title: "AntiFlock reference vertical slice acceptance",
  measuredAt: new Date().toISOString(),
  harness: "node scripts/acceptance.mjs",
  metric: "reference_vertical_slice_gates_passed",
  direction: "higher-is-better",
  value: passed,
  total: gates.length,
  ratio: passed / gates.length,
  required: requiredGates.length,
  requiredPassed,
  strict,
  strictPassed: requiredPassed === requiredGates.length,
  environment: {
    platform: process.platform,
    architecture: process.arch,
    node: process.version,
    goAvailable: commandExists("go"),
    dockerAvailable: commandExists("docker"),
  },
  gates,
};

process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
if (strict && requiredPassed !== requiredGates.length) {
  process.exitCode = 1;
}
