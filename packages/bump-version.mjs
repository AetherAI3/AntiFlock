#!/usr/bin/env node
// Bumps the version for both antiflock CLI packages (npm and PyPI) together,
// so a release never drifts them apart.
//
// Usage: node packages/bump-version.mjs <semver>

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));
const version = process.argv[2];

if (!version || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?$/.test(version)) {
  console.error("Usage: node packages/bump-version.mjs <semver>, e.g. 0.2.0");
  process.exit(2);
}

function bumpJSON(path, label) {
  const raw = readFileSync(path, "utf8");
  const pkg = JSON.parse(raw);
  const from = pkg.version;
  pkg.version = version;
  writeFileSync(path, `${JSON.stringify(pkg, null, 2)}\n`);
  console.log(`${label}: ${from} -> ${version}`);
}

function bumpRegex(path, pattern, label) {
  const raw = readFileSync(path, "utf8");
  const match = raw.match(pattern);
  if (!match) throw new Error(`Could not find a version to bump in ${path}`);
  const from = match[1];
  writeFileSync(path, raw.replace(pattern, (full) => full.replace(from, version)));
  console.log(`${label}: ${from} -> ${version}`);
}

bumpJSON(join(root, "npm-cli", "package.json"), "packages/npm-cli/package.json");
bumpRegex(
  join(root, "pypi-cli", "pyproject.toml"),
  /version = "([^"]+)"/,
  "packages/pypi-cli/pyproject.toml"
);
bumpRegex(
  join(root, "pypi-cli", "src", "antiflock", "__init__.py"),
  /__version__ = "([^"]+)"/,
  "packages/pypi-cli/src/antiflock/__init__.py"
);

console.log(
  "\nNext: review the diff, commit, then publish -- npm: `npm publish` from " +
    "packages/npm-cli or dispatch publish-npm.yml; PyPI: dispatch publish-pypi.yml."
);
