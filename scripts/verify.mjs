#!/usr/bin/env node

import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { join, relative, sep } from "node:path";
import {
  checkGoFormatting,
  installJavascriptWorkspaces,
  javascriptWorkspaces,
  readPackage,
  root,
  runAndroidTests,
  runBufStep,
  runGoStep,
  runGoToolStep,
  runStep,
  runWorkspaceScript,
  safeRemove,
  versions,
} from "./tooling.mjs";

const allowedSections = new Set(["proto", "go", "javascript", "android", "acceptance"]);
const requestedSections = new Set();
let install = false;
let lintOnly = false;

for (let index = 2; index < process.argv.length; index += 1) {
  const argument = process.argv[index];
  if (argument === "--install") {
    install = true;
  } else if (argument === "--lint-only") {
    lintOnly = true;
  } else if (argument === "--section") {
    const value = process.argv[index + 1];
    if (!value) throw new Error("--section requires a value");
    value.split(",").filter(Boolean).forEach((section) => requestedSections.add(section));
    index += 1;
  } else if (argument.startsWith("--section=")) {
    argument.slice("--section=".length).split(",").filter(Boolean).forEach((section) => requestedSections.add(section));
  } else {
    throw new Error(`Unknown verification argument: ${argument}`);
  }
}

const fullVerification = requestedSections.size === 0 && !lintOnly;
if (requestedSections.size === 0) {
  const defaults = lintOnly
    ? ["proto", "go", "javascript"]
    : ["proto", "go", "javascript", "android", "acceptance"];
  defaults.forEach((section) => requestedSections.add(section));
}
if (fullVerification) install = true;

for (const section of requestedSections) {
  if (!allowedSections.has(section)) {
    throw new Error(`Unknown verification section: ${section}`);
  }
}

const failures = [];

function check(label, passed) {
  if (!passed) failures.push(label);
  return passed;
}

function listTree(directory) {
  const files = new Map();
  if (!existsSync(directory) || !statSync(directory).isDirectory()) return files;

  function visit(current) {
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const absolute = join(current, entry.name);
      if (entry.isDirectory()) {
        visit(absolute);
      } else if (entry.isFile()) {
        files.set(relative(directory, absolute).split(sep).join("/"), readFileSync(absolute));
      }
    }
  }

  visit(directory);
  return files;
}

function verifyGeneratedCode() {
  const expectedDirectory = join(root, "api", "gen", "go");
  if (!existsSync(expectedDirectory)) {
    process.stderr.write("Generated Go API directory is missing: api/gen/go\n");
    return false;
  }

  const cacheRelative = `.cache/buf-verify-${process.pid}-${Date.now()}`;
  const cacheDirectory = join(root, cacheRelative);
  const outputRelative = `${cacheRelative}/api/gen/go`;
  const templateRelative = `${cacheRelative}/buf.gen.yaml`;
  const templatePath = join(root, templateRelative);
  const sourceTemplate = readFileSync(join(root, "buf.gen.yaml"), "utf8");
  const outputPattern = /(^\s*out:\s*)api\/gen\/go\s*$/gm;
  const outputMatches = sourceTemplate.match(outputPattern) ?? [];
  if (outputMatches.length === 0) {
    process.stderr.write("buf.gen.yaml has no api/gen/go output to verify.\n");
    return false;
  }

  mkdirSync(cacheDirectory, { recursive: true });
  writeFileSync(templatePath, sourceTemplate.replace(outputPattern, `$1${outputRelative}`));

  try {
    if (!runBufStep("Re-generate Go API into an isolated directory", ["generate", "--template", templateRelative], { timeout: 900_000 })) {
      return false;
    }

    const expected = listTree(expectedDirectory);
    const actual = listTree(join(root, outputRelative));
    const differences = [];

    for (const [path, expectedBytes] of expected) {
      const actualBytes = actual.get(path);
      if (!actualBytes) {
        differences.push(`missing generated file: ${path}`);
      } else if (!expectedBytes.equals(actualBytes)) {
        differences.push(`generated content differs: ${path}`);
      }
    }
    for (const path of actual.keys()) {
      if (!expected.has(path)) differences.push(`unexpected generated file: ${path}`);
    }

    if (expected.size === 0) differences.push("api/gen/go contains no generated files");
    if (differences.length > 0) {
      process.stderr.write(`Generated Go API is not reproducible:\n${differences.map((item) => `- ${item}`).join("\n")}\n`);
      return false;
    }
    return true;
  } finally {
    safeRemove(cacheRelative);
  }
}

function verifyProto() {
  check("Protocol Buffer formatting", runBufStep("Protocol Buffer formatting", ["format", "--diff", "--exit-code"]));
  check("Protocol Buffer lint", runBufStep("Protocol Buffer lint", ["lint"]));
  check("Protocol Buffer build", runBufStep("Protocol Buffer build", ["build"]));
  if (!lintOnly) check("Protocol Buffer generation reproducibility", verifyGeneratedCode());
}

function verifyGo() {
  check("Go formatting", checkGoFormatting());
  if (!lintOnly) {
    check("Go module reproducibility", runGoStep("Go module reproducibility", ["mod", "tidy", "-diff"], { cgo: false }));
    check("Go tests", runGoStep("Go tests", ["test", "./..."], { cgo: false, timeout: 900_000 }));
    check("Go race tests", runGoStep("Go race tests", ["test", "-race", "./..."], { timeout: 900_000 }));
  }
  check("Go vet", runGoStep("Go vet", ["vet", "./..."], { cgo: false, timeout: 900_000 }));
  if (!lintOnly) check("Go build", runGoStep("Go build", ["build", "./..."], { cgo: false, timeout: 900_000 }));
  check(
    "Staticcheck",
    runGoToolStep(
      "Staticcheck",
      "staticcheck",
      "honnef.co/go/tools/cmd/staticcheck",
      versions.staticcheck,
      ["./..."],
      { cgo: false, timeout: 900_000 },
    ),
  );
  if (!lintOnly) {
    check(
      "govulncheck",
      runGoToolStep(
        "govulncheck",
        "govulncheck",
        "golang.org/x/vuln/cmd/govulncheck",
        versions.govulncheck,
        ["./..."],
        { cgo: false, timeout: 900_000 },
      ),
    );
  }
}

function verifyJavascript() {
  const nodeMajor = Number.parseInt(process.versions.node.split(".")[0], 10);
  if (nodeMajor < 24) {
    process.stderr.write(`Node 24 or newer is required; running ${process.version}.\n`);
    failures.push("Node runtime");
    return;
  }

  check(
    "Tooling tests",
    runStep("Tooling tests", process.execPath, ["--test", "scripts/dev-environment.test.mjs"], {
      timeout: 300_000,
    }),
  );

  if (install) check("JavaScript dependency installation", installJavascriptWorkspaces());

  for (const workspace of javascriptWorkspaces) {
    const pkg = readPackage(workspace);
    if (!pkg) {
      failures.push(`${workspace} manifest`);
      continue;
    }

    if (!lintOnly) {
      check(`${workspace} build`, runWorkspaceScript(workspace, "build", { timeout: 900_000 }));
      check(`${workspace} tests`, runWorkspaceScript(workspace, "test", { timeout: 900_000 }));
    }

    const qualityScripts = ["check", "lint"].filter((script) => pkg.scripts?.[script]);
    if (qualityScripts.length === 0) {
      process.stdout.write(`\n==> ${workspace} has no optional check or lint script\n`);
    }
    for (const script of qualityScripts) {
      check(`${workspace} ${script}`, runWorkspaceScript(workspace, script, { timeout: 900_000 }));
    }
  }
}

if (requestedSections.has("proto")) verifyProto();
if (requestedSections.has("go")) verifyGo();
if (requestedSections.has("javascript")) verifyJavascript();
if (requestedSections.has("android") && !lintOnly) {
  check("Android JVM tests", runAndroidTests());
}
if (requestedSections.has("acceptance") && !lintOnly) {
  check(
    "Acceptance",
    runStep("Strict acceptance harness", process.execPath, ["scripts/acceptance.mjs", "--strict"], {
      timeout: 900_000,
    }),
  );
}

if (failures.length > 0) {
  process.stderr.write(`\nVerification failures (${failures.length}):\n${failures.map((failure) => `- ${failure}`).join("\n")}\n`);
  process.exitCode = 1;
} else {
  process.stdout.write("\nAll requested verification sections passed.\n");
}
