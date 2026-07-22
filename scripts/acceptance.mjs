#!/usr/bin/env node

import { existsSync, readFileSync } from "node:fs";
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
  ], () => combine([
    npmTest("sdk/typescript"),
    npmTest("apps/aether-demo"),
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
];

const passed = gates.filter((gate) => gate.passed).length;
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
if (strict && passed !== gates.length) {
  process.exitCode = 1;
}
