import { randomBytes, randomUUID } from "node:crypto";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

const tokenKeys = [
  "ANTIFLOCK_OPERATOR_TOKEN",
  "ANTIFLOCK_SDK_TOKEN",
  "ANTIFLOCK_AGENT_TOKEN",
  "ANTIFLOCK_DASHBOARD_TOKEN",
];

const idKeys = [
  "ANTIFLOCK_SDK_APPLICATION_ID",
  "ANTIFLOCK_SDK_NODE_ID",
  "ANTIFLOCK_AGENT_NODE_ID",
];

let cachedWindowsSid;

export const requiredDevelopmentEnvironmentKeys = Object.freeze([...tokenKeys, ...idKeys]);

function parseEnvironmentFile(contents) {
  const values = new Map();
  for (const [index, rawLine] of contents.split(/\r?\n/).entries()) {
    const line = rawLine.trim();
    if (line === "" || line.startsWith("#")) continue;
    const separator = line.indexOf("=");
    if (separator <= 0) {
      throw new Error(`Invalid development environment entry on line ${index + 1}.`);
    }
    const key = line.slice(0, separator).trim();
    const value = line.slice(separator + 1).trim();
    if (!/^[A-Z][A-Z0-9_]*$/.test(key) || /[\r\n]/.test(value)) {
      throw new Error(`Invalid development environment key on line ${index + 1}.`);
    }
    values.set(key, value);
  }
  return values;
}

function generatedValues() {
  return new Map([
    ["ANTIFLOCK_OPERATOR_TOKEN", randomBytes(32).toString("base64url")],
    ["ANTIFLOCK_SDK_TOKEN", randomBytes(32).toString("base64url")],
    ["ANTIFLOCK_AGENT_TOKEN", randomBytes(32).toString("base64url")],
    ["ANTIFLOCK_DASHBOARD_TOKEN", randomBytes(32).toString("base64url")],
    ["ANTIFLOCK_SDK_APPLICATION_ID", `demo-sdk-app-${randomUUID()}`],
    ["ANTIFLOCK_SDK_NODE_ID", `demo-sdk-node-${randomUUID()}`],
    ["ANTIFLOCK_AGENT_NODE_ID", `demo-agent-node-${randomUUID()}`],
  ]);
}

function validateRequiredValues(values) {
  for (const key of tokenKeys) {
    const value = values.get(key);
    if (!value || Buffer.byteLength(value, "utf8") < 32) {
      throw new Error(`${key} must contain at least 32 bytes.`);
    }
  }
  for (const key of idKeys) {
    const value = values.get(key);
    if (!value || !/^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/.test(value)) {
      throw new Error(`${key} must be a stable, non-empty opaque identifier.`);
    }
  }
}

function renderEnvironmentFile(values) {
  const required = requiredDevelopmentEnvironmentKeys.map((key) => `${key}=${values.get(key)}`);
  const extra = [...values.entries()]
    .filter(([key]) => !requiredDevelopmentEnvironmentKeys.includes(key))
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, value]) => `${key}=${value}`);
  return [
    "# Generated locally by AntiFlock. Keep private; never commit this file.",
    ...required,
    ...extra,
    "",
  ].join("\n");
}

function currentWindowsSid() {
  if (cachedWindowsSid) return cachedWindowsSid;
  const result = spawnSync("whoami.exe", ["/user", "/fo", "csv", "/nh"], {
    encoding: "utf8",
    windowsHide: true,
  });
  if (result.status !== 0) throw new Error("Unable to determine the current Windows security identifier.");
  const match = result.stdout.match(/S-\d(?:-\d+)+/);
  if (!match) throw new Error("Unable to parse the current Windows security identifier.");
  cachedWindowsSid = match[0];
  return cachedWindowsSid;
}

function restrictWindowsAcl(path, directory) {
  const sid = currentWindowsSid();
  const grant = directory ? `*${sid}:(OI)(CI)F` : `*${sid}:F`;
  const result = spawnSync(
    "icacls.exe",
    [path, "/inheritance:r", "/grant:r", grant],
    { encoding: "utf8", windowsHide: true },
  );
  if (result.status !== 0) {
    throw new Error(`Unable to restrict access to ${directory ? "the development state directory" : "the development environment file"}.`);
  }
}

function restrictPermissions(directory, environmentPath, includeDirectory = true) {
  if (includeDirectory) {
    chmodSync(directory, 0o700);
    if (process.platform === "win32") restrictWindowsAcl(directory, true);
  }
  if (environmentPath && existsSync(environmentPath)) {
    chmodSync(environmentPath, 0o600);
    if (process.platform === "win32") restrictWindowsAcl(environmentPath, false);
  }
}

function requireOrdinaryPath(path, kind) {
  const details = lstatSync(path);
  const expected = kind === "directory" ? details.isDirectory() : details.isFile();
  if (details.isSymbolicLink() || !expected) {
    throw new Error(`Refusing to use a development ${kind} that is not an ordinary ${kind}.`);
  }
}

export function ensureDevelopmentEnvironment(repositoryRoot) {
  const privateDirectory = join(repositoryRoot, ".antiflock");
  const environmentPath = join(privateDirectory, "dev.env");
  const existed = existsSync(environmentPath);

  mkdirSync(privateDirectory, { recursive: true, mode: 0o700 });
  requireOrdinaryPath(privateDirectory, "directory");
  if (existed) requireOrdinaryPath(environmentPath, "file");
  restrictPermissions(privateDirectory);

  const values = existed
    ? parseEnvironmentFile(readFileSync(environmentPath, "utf8"))
    : new Map();
  const defaults = generatedValues();
  let updated = !existed;
  for (const key of requiredDevelopmentEnvironmentKeys) {
    if (!values.has(key) || values.get(key) === "") {
      values.set(key, defaults.get(key));
      updated = true;
    }
  }
  validateRequiredValues(values);

  if (updated) {
    const temporaryPath = join(privateDirectory, `.dev.env-${process.pid}-${randomBytes(8).toString("hex")}.tmp`);
    try {
      writeFileSync(temporaryPath, renderEnvironmentFile(values), {
        encoding: "utf8",
        flag: "wx",
        mode: 0o600,
      });
      restrictPermissions(privateDirectory, temporaryPath, false);
      renameSync(temporaryPath, environmentPath);
    } finally {
      rmSync(temporaryPath, { force: true });
    }
  }

  restrictPermissions(privateDirectory, environmentPath, false);
  const mode = statSync(environmentPath).mode & 0o777;
  if (process.platform !== "win32") {
    const directoryMode = statSync(privateDirectory).mode & 0o777;
    if (directoryMode !== 0o700 || mode !== 0o600) {
      throw new Error("Development credentials require directory mode 0700 and file mode 0600.");
    }
  }

  return Object.freeze({
    environmentPath,
    created: !existed,
    updated: existed && updated,
  });
}
