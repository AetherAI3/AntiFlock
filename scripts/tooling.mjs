#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import {
  existsSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
} from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

export const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export const versions = Object.freeze({
  go: "1.26.5",
  goImage: "golang:1.26.5-bookworm@sha256:1ecb7edf62a0408027bd5729dfd6b1b8766e578e8df93995b225dfd0944eb651",
  node: "24.18.0",
  buf: "1.72.0",
  bufImage: "bufbuild/buf:1.72.0@sha256:65bd496a89c762ad7151ca9e7d885a45dacb3671a8e8ec39738b9f844d3405ea",
  gradle: "9.6.1",
  gradleImage: "gradle:9.6.1-jdk17@sha256:7364ce528f33bb6038672bcef990d524f1ad8fbc292935819c235db886d0fae7",
  staticcheck: "2026.1",
  govulncheck: "v1.1.4",
});

export const javascriptWorkspaces = Object.freeze([
  "sdk/typescript",
  "apps/aether-demo",
  "apps/web",
]);

export const goPackagePatterns = Object.freeze([
  "./adapters/...",
  "./agent/...",
  "./api/gen/go/...",
  "./cmd/...",
  "./core/...",
  "./internal/...",
  "./tests/...",
]);

const ignoredDirectoryNames = new Set([
  ".git",
  ".cache",
  ".gradle",
  ".next",
  ".tools",
  "build",
  "coverage",
  "dist",
  "node_modules",
]);

let dockerUsable;

export function commandExists(command) {
  const probe = process.platform === "win32" ? "where.exe" : "sh";
  const args =
    process.platform === "win32"
      ? [command]
      : ["-c", `command -v -- \"$1\" >/dev/null 2>&1`, "sh", command];
  return spawnSync(probe, args, { stdio: "ignore", shell: false }).status === 0;
}

export function run(command, args, options = {}) {
  const isWindowsBatch = process.platform === "win32" && /\.(?:bat|cmd)$/i.test(command);
  const executable = isWindowsBatch ? (process.env.ComSpec ?? "cmd.exe") : command;
  const executableArgs = isWindowsBatch ? ["/d", "/s", "/c", command, ...args] : args;
  return spawnSync(executable, executableArgs, {
    cwd: options.cwd ?? root,
    stdio: options.capture ? "pipe" : "inherit",
    encoding: options.capture ? "utf8" : undefined,
    timeout: options.timeout ?? 900_000,
    shell: false,
    env: {
      ...process.env,
      CI: "1",
      ...options.env,
    },
  });
}

function printFailure(result) {
  if (result.error) {
    process.stderr.write(`${result.error.message}\n`);
  }
  if (result.stdout) {
    process.stderr.write(`${result.stdout.trimEnd()}\n`);
  }
  if (result.stderr) {
    process.stderr.write(`${result.stderr.trimEnd()}\n`);
  }
}

export function runStep(label, command, args, options = {}) {
  process.stdout.write(`\n==> ${label}\n`);
  const result = run(command, args, options);
  if (result.status !== 0) {
    if (options.capture) printFailure(result);
    process.stderr.write(
      `${label} failed${result.status === null ? " before starting" : ` with exit code ${result.status}`}.\n`,
    );
    return false;
  }
  return true;
}

export function dockerAvailable() {
  if (dockerUsable !== undefined) return dockerUsable;
  if (!commandExists("docker")) {
    dockerUsable = false;
    return dockerUsable;
  }
  dockerUsable =
    run("docker", ["info", "--format", "{{.ServerVersion}}"], {
      capture: true,
      timeout: 30_000,
    }).status === 0;
  return dockerUsable;
}

function containerArgs(image, args, options = {}) {
  const environment = Object.entries(options.containerEnv ?? {}).flatMap(([key, value]) => [
    "-e",
    `${key}=${value}`,
  ]);
  const volumes = (options.volumes ?? []).flatMap((volume) => ["-v", volume]);
  return [
    "run",
    "--rm",
    ...environment,
    ...volumes,
    "-v",
    `${root}:/workspace`,
    "-w",
    options.containerWorkdir ?? "/workspace",
    image,
    ...args,
  ];
}

function missingTool(label, localTool, image) {
  process.stdout.write(`\n==> ${label}\n`);
  process.stderr.write(
    `Cannot run ${label}: ${localTool} is unavailable and Docker cannot run the pinned fallback ${image}.\n`,
  );
  return false;
}

export function runGoStep(label, args, options = {}) {
  if (commandExists("go")) {
    return runStep(label, "go", args, options);
  }
  if (!dockerAvailable()) return missingTool(label, "Go", versions.goImage);
  return runStep(
    `${label} (Go ${versions.go} container)`,
    "docker",
    containerArgs(versions.goImage, ["go", ...args], {
      containerEnv: { CGO_ENABLED: options.cgo === false ? "0" : "1" },
      volumes: [
        "antiflock-go-mod:/go/pkg/mod",
        "antiflock-go-build:/root/.cache/go-build",
      ],
    }),
    options,
  );
}

export function runGoToolStep(label, binary, module, version, args, options = {}) {
  if (commandExists(binary)) {
    return runStep(label, binary, args, options);
  }
  return runGoStep(
    `${label} (bootstrap ${version})`,
    ["run", `${module}@${version}`, ...args],
    options,
  );
}

export function runBufStep(label, args, options = {}) {
  if (commandExists("buf")) {
    return runStep(label, "buf", args, options);
  }
  if (!dockerAvailable()) return missingTool(label, "Buf", versions.bufImage);
  return runStep(
    `${label} (Buf ${versions.buf} container)`,
    "docker",
    containerArgs(versions.bufImage, args),
    options,
  );
}

export function npmCommand() {
  return process.platform === "win32" ? "npm.cmd" : "npm";
}

export function requireFile(path, description = path) {
  const absolute = join(root, path);
  if (!existsSync(absolute) || !statSync(absolute).isFile()) {
    process.stderr.write(`Required ${description} is missing: ${path}\n`);
    return false;
  }
  return true;
}

export function readPackage(workspace) {
  const packagePath = join(root, workspace, "package.json");
  if (!requireFile(join(workspace, "package.json"), `${workspace} package manifest`)) {
    return null;
  }
  try {
    return JSON.parse(readFileSync(packagePath, "utf8"));
  } catch (error) {
    process.stderr.write(`Cannot parse ${workspace}/package.json: ${error.message}\n`);
    return null;
  }
}

export function runWorkspaceScript(workspace, script, options = {}) {
  const pkg = readPackage(workspace);
  if (!pkg) return false;
  if (!pkg.scripts?.[script]) {
    process.stderr.write(`Required npm script ${workspace}:${script} is not defined.\n`);
    return false;
  }
  return runStep(
    `${workspace} npm run ${script}`,
    npmCommand(),
    ["run", script, "--prefix", workspace],
    options,
  );
}

export function installJavascriptWorkspaces() {
  let passed = true;
  if (!commandExists(npmCommand())) {
    process.stderr.write("npm is required to install the JavaScript workspaces.\n");
    return false;
  }
  for (const workspace of javascriptWorkspaces) {
    if (!requireFile(join(workspace, "package-lock.json"), `${workspace} npm lockfile`)) {
      passed = false;
      continue;
    }
    passed =
      runStep(
        `${workspace} reproducible dependency install`,
        npmCommand(),
        ["ci", "--prefix", workspace],
        { timeout: 900_000 },
      ) && passed;
  }
  return passed;
}

export function runAndroidTests(label = "Android reference JVM tests") {
  const androidDirectory = join(root, "apps", "android");
  if (!requireFile("apps/android/settings.gradle.kts", "Android Gradle settings")) return false;

  const wrapper = process.platform === "win32" ? "gradlew.bat" : "gradlew";
  const wrapperPath = join(androidDirectory, wrapper);
  if (!existsSync(wrapperPath)) {
    process.stderr.write("The checked-in Android Gradle wrapper is required.\n");
    return false;
  }
  if (commandExists("java")) {
    const command = process.platform === "win32" ? join(androidDirectory, wrapper) : `./${wrapper}`;
    return runStep(label, command, ["--no-daemon", "test"], {
      cwd: androidDirectory,
      timeout: 900_000,
    });
  }

  if (!dockerAvailable()) return missingTool(label, "Java 17", versions.gradleImage);
  return runStep(
    `${label} (wrapper in pinned JDK 17 container)`,
    "docker",
    containerArgs(versions.gradleImage, ["bash", "./gradlew", "--no-daemon", "test"], {
      containerEnv: { GRADLE_USER_HOME: "/home/gradle/.gradle" },
      containerWorkdir: "/workspace/apps/android",
      volumes: ["antiflock-gradle-cache:/home/gradle/.gradle"],
    }),
    { timeout: 900_000 },
  );
}

function walk(directory, predicate, output) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (entry.isDirectory() && ignoredDirectoryNames.has(entry.name)) continue;
    const absolute = join(directory, entry.name);
    if (entry.isDirectory()) {
      walk(absolute, predicate, output);
    } else if (entry.isFile() && predicate(absolute)) {
      output.push(relative(root, absolute).split(sep).join("/"));
    }
  }
}

export function repositoryFiles(predicate) {
  const output = [];
  walk(root, predicate, output);
  return output.sort();
}

function gofmtInvocation(args) {
  if (commandExists("gofmt")) return { command: "gofmt", args };
  if (!dockerAvailable()) return null;
  return {
    command: "docker",
    args: containerArgs(versions.goImage, ["gofmt", ...args]),
  };
}

export function checkGoFormatting() {
  const files = repositoryFiles((path) => path.endsWith(".go"));
  process.stdout.write("\n==> Go formatting\n");
  if (files.length === 0) {
    process.stderr.write("No Go files were found; formatting cannot be verified.\n");
    return false;
  }
  const invocation = gofmtInvocation(["-l", ...files]);
  if (!invocation) return missingTool("Go formatting", "gofmt", versions.goImage);
  const result = run(invocation.command, invocation.args, { capture: true, timeout: 300_000 });
  if (result.status !== 0) {
    printFailure(result);
    return false;
  }
  const unformatted = (result.stdout ?? "").trim();
  if (unformatted) {
    process.stderr.write(`The following Go files need gofmt:\n${unformatted}\n`);
    return false;
  }
  return true;
}

export function formatGoFiles() {
  const files = repositoryFiles((path) => path.endsWith(".go"));
  if (files.length === 0) {
    process.stderr.write("No Go files were found; nothing was formatted.\n");
    return false;
  }
  const invocation = gofmtInvocation(["-w", ...files]);
  if (!invocation) return missingTool("Go formatting", "gofmt", versions.goImage);
  return runStep("Format Go sources", invocation.command, invocation.args, { timeout: 300_000 });
}

export function safeRemove(relativePath) {
  const absolute = resolve(root, relativePath);
  const rootPrefix = `${root}${sep}`;
  if (!absolute.startsWith(rootPrefix) || absolute === root) {
    throw new Error(`Refusing to remove path outside the repository: ${relativePath}`);
  }
  rmSync(absolute, { force: true, recursive: true });
}
