#!/usr/bin/env node

import { existsSync, readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

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

function goTest() {
  if (commandExists("go")) {
    return run("go", ["test", "./..."], root, 300_000);
  }

  if (!commandExists("docker")) {
    return {
      command: "go test ./...",
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
      "-w",
      "/workspace",
      "golang:1.26.5-bookworm",
      "go",
      "test",
      "./...",
    ],
    root,
    600_000,
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
  pathsGate("contracts", "Locked security and privacy contracts", [
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
  ]),
  pathsGate("schemas", "Canonical versioned protocol schemas", [
    "api/proto/antiflock/v1/common.proto",
    "api/proto/antiflock/v1/event.proto",
    "api/proto/antiflock/v1/finding.proto",
    "api/proto/antiflock/v1/posture.proto",
    "api/proto/antiflock/v1/policy.proto",
    "api/proto/antiflock/v1/plan.proto",
    "api/proto/antiflock/v1/action.proto",
  ]),
  runnableGate("core", "Core modules and tests", ["go.mod", "cmd/antiflock-core/main.go"], goTest),
  pathsGate("event-spine", "Identity, enrollment, SQLite event spine, projections, and audit", [
    "core/storage/migrations/001_initial.sql",
    "core/identity/identity.go",
    "core/enrollment/service.go",
    "core/events/store.go",
    "core/audit/service.go",
  ]),
  pathsGate("decision-plane", "Deterministic posture, policy, findings, action gate, and Scrambler planner", [
    "core/posture/engine.go",
    "core/policy/compiler.go",
    "core/findings/service.go",
    "core/actions/gate.go",
    "core/scrambler/planner.go",
  ]),
  pathsGate("agent", "Simulator, Linux observation, mesh probes, enforcement, verification, and rollback", [
    "cmd/antiflock-agent/main.go",
    "cmd/antiflock-sim/main.go",
    "agent/collectors/collectors.go",
    "agent/enforcement/enforcer.go",
    "adapters/mesh/tailscale/probe.go",
    "adapters/mesh/headscale/client.go",
  ]),
  runnableGate("web", "Third-Eye dashboard build and tests", ["apps/web/package.json"], () => npmTest("apps/web")),
  runnableGate("secure-action-sdk", "Secure Action SDK and Aether demonstration", ["sdk/typescript/package.json"], () => npmTest("sdk/typescript")),
  pathsGate("android", "Android Guard reference JVM state machine and fail-closed policy", [
    "apps/android/settings.gradle.kts",
    "apps/android/guard-domain/src/main/kotlin/ai/aether/antiflock/guard/domain/GuardEvaluator.kt",
    "apps/android/guard-domain/src/test/kotlin/ai/aether/antiflock/guard/domain/GuardDomainTest.kt",
    "apps/android/platform-adapters/src/test/kotlin/ai/aether/antiflock/guard/platform/AndroidGuardCoordinatorTest.kt",
    "apps/android/reference-app/src/main/kotlin/ai/aether/antiflock/guard/reference/Main.kt",
  ]),
  runnableGate("coffee-shop", "Auditable coffee-shop failure and recovery acceptance scenario", [
    "tests/end-to-end/coffee_shop_test.go",
    "go.mod",
  ], goTest),
];

const passed = gates.filter((gate) => gate.passed).length;
const report = {
  schemaVersion: "antiflock.acceptance/v1",
  measuredAt: new Date().toISOString(),
  harness: "node scripts/acceptance.mjs",
  metric: "locked_vertical_slice_gates_passed",
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
