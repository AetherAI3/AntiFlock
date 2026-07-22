import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  developmentSDKApplicationID,
  ensureDevelopmentEnvironment,
  requiredDevelopmentEnvironmentKeys,
} from "./dev-environment.mjs";

function parse(contents) {
  return new Map(
    contents
      .split(/\r?\n/)
      .filter((line) => line && !line.startsWith("#"))
      .map((line) => {
        const separator = line.indexOf("=");
        return [line.slice(0, separator), line.slice(separator + 1)];
      }),
  );
}

test("development credentials are private, complete, and stable without secret output", () => {
  const directory = mkdtempSync(join(tmpdir(), "antiflock-dev-env-"));
  const originalStdout = process.stdout.write;
  const originalStderr = process.stderr.write;
  let output = "";
  process.stdout.write = (chunk) => {
    output += String(chunk);
    return true;
  };
  process.stderr.write = (chunk) => {
    output += String(chunk);
    return true;
  };

  try {
    const first = ensureDevelopmentEnvironment(directory);
    const firstContents = readFileSync(first.environmentPath, "utf8");
    const firstValues = parse(firstContents);
    const second = ensureDevelopmentEnvironment(directory);
    const secondContents = readFileSync(second.environmentPath, "utf8");

    assert.equal(first.created, true);
    assert.equal(second.created, false);
    assert.equal(second.updated, false);
    assert.equal(secondContents, firstContents);
    assert.equal(output, "");
    assert.deepEqual([...firstValues.keys()], [...requiredDevelopmentEnvironmentKeys]);

    for (const key of ["ANTIFLOCK_OPERATOR_TOKEN", "ANTIFLOCK_SDK_TOKEN", "ANTIFLOCK_AGENT_TOKEN", "ANTIFLOCK_DASHBOARD_TOKEN"]) {
      const encoded = firstValues.get(key);
      assert.match(encoded, /^[A-Za-z0-9_-]+$/);
      assert.equal(Buffer.from(encoded, "base64url").length, 32);
      assert.equal(output.includes(encoded), false);
    }
    assert.equal(firstValues.get("ANTIFLOCK_SDK_APPLICATION_ID"), developmentSDKApplicationID);
    for (const key of ["ANTIFLOCK_SDK_NODE_ID", "ANTIFLOCK_AGENT_NODE_ID"]) {
      assert.match(firstValues.get(key), /^demo-[a-z-]+-[0-9a-f-]{36}$/);
      assert.equal(output.includes(firstValues.get(key)), false);
    }

    const withoutAgentID = firstContents
      .split(/\r?\n/)
      .filter((line) => !line.startsWith("ANTIFLOCK_AGENT_NODE_ID="))
      .join("\n");
    writeFileSync(first.environmentPath, withoutAgentID, "utf8");
    const repaired = ensureDevelopmentEnvironment(directory);
    const repairedValues = parse(readFileSync(repaired.environmentPath, "utf8"));
    assert.equal(repaired.updated, true);
    assert.equal(repairedValues.get("ANTIFLOCK_OPERATOR_TOKEN"), firstValues.get("ANTIFLOCK_OPERATOR_TOKEN"));
    assert.equal(repairedValues.get("ANTIFLOCK_SDK_TOKEN"), firstValues.get("ANTIFLOCK_SDK_TOKEN"));
    assert.equal(repairedValues.get("ANTIFLOCK_AGENT_TOKEN"), firstValues.get("ANTIFLOCK_AGENT_TOKEN"));
    assert.equal(repairedValues.get("ANTIFLOCK_DASHBOARD_TOKEN"), firstValues.get("ANTIFLOCK_DASHBOARD_TOKEN"));
    assert.notEqual(repairedValues.get("ANTIFLOCK_AGENT_NODE_ID"), firstValues.get("ANTIFLOCK_AGENT_NODE_ID"));
    assert.equal(output, "");

    const legacyValues = parse(readFileSync(repaired.environmentPath, "utf8"));
    legacyValues.set("ANTIFLOCK_SDK_APPLICATION_ID", "demo-sdk-app-00000000-0000-4000-8000-000000000000");
    writeFileSync(
      repaired.environmentPath,
      `${[...legacyValues].map(([key, value]) => `${key}=${value}`).join("\n")}\n`,
      "utf8",
    );
    const policyRepaired = ensureDevelopmentEnvironment(directory);
    const policyValues = parse(readFileSync(policyRepaired.environmentPath, "utf8"));
    assert.equal(policyRepaired.updated, true);
    assert.equal(policyValues.get("ANTIFLOCK_SDK_APPLICATION_ID"), developmentSDKApplicationID);
    assert.equal(policyValues.get("ANTIFLOCK_OPERATOR_TOKEN"), firstValues.get("ANTIFLOCK_OPERATOR_TOKEN"));
    assert.equal(output, "");

		const collidingValues = parse(readFileSync(policyRepaired.environmentPath, "utf8"));
		collidingValues.set("ANTIFLOCK_DASHBOARD_TOKEN", collidingValues.get("ANTIFLOCK_OPERATOR_TOKEN"));
		writeFileSync(
			policyRepaired.environmentPath,
			`${[...collidingValues].map(([key, value]) => `${key}=${value}`).join("\n")}\n`,
			"utf8",
		);
		const collisionRepaired = ensureDevelopmentEnvironment(directory);
		const collisionValues = parse(readFileSync(collisionRepaired.environmentPath, "utf8"));
		assert.equal(collisionRepaired.updated, true);
		assert.equal(collisionValues.get("ANTIFLOCK_OPERATOR_TOKEN"), policyValues.get("ANTIFLOCK_OPERATOR_TOKEN"));
		assert.notEqual(collisionValues.get("ANTIFLOCK_DASHBOARD_TOKEN"), collisionValues.get("ANTIFLOCK_OPERATOR_TOKEN"));
		assert.equal(new Set([
			collisionValues.get("ANTIFLOCK_OPERATOR_TOKEN"),
			collisionValues.get("ANTIFLOCK_SDK_TOKEN"),
			collisionValues.get("ANTIFLOCK_AGENT_TOKEN"),
			collisionValues.get("ANTIFLOCK_DASHBOARD_TOKEN"),
		]).size, 4);
		assert.equal(output, "");

    if (process.platform !== "win32") {
      assert.equal(statSync(first.environmentPath).mode & 0o777, 0o600);
    }
  } finally {
    process.stdout.write = originalStdout;
    process.stderr.write = originalStderr;
    rmSync(directory, { force: true, recursive: true });
  }
});

test("web container context excludes common credential files", () => {
  const rules = new Set(
    readFileSync(new URL("../apps/web/.dockerignore", import.meta.url), "utf8")
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith("#")),
  );

  for (const required of [".env*", ".antiflock/", "**/.antiflock/", "*.pem", "**/*.pem", "*.key", "**/*.key"]) {
    assert.equal(rules.has(required), true, `web Docker context must exclude ${required}`);
  }
});
