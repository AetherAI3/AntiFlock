#!/usr/bin/env node
// Deterministic AntiFlock -> AntiFl0ck rebrand of internal identifiers.
//
// The public branding (README, logo, tagline) is already AntiFl0ck. This script
// migrates the remaining in-tree identifiers so the codebase is internally
// consistent. It is intentionally SAFE:
//
//   * Dry-run by default — it only reports. `--apply` is required to write.
//   * The Go module path and repo URL `github.com/DBarr3/AntiFlock` are PRESERVED
//     (the GitHub repository keeps its name), so imports never break.
//   * Generated protobuf code, lockfiles, and go.sum are NOT string-edited —
//     they must be REGENERATED with the toolchain afterward (see docs/REBRAND.md).
//
// Run order (see docs/REBRAND.md for the full, verifiable checklist):
//   node scripts/rebrand-antifl0ck.mjs            # 1. review the dry-run report
//   node scripts/rebrand-antifl0ck.mjs --apply    # 2. rewrite text + rename dirs
//   npx buf generate                              # 3. regenerate api/gen from proto
//   go mod tidy && go build ./... && go test ./... # 4. compile + test
//   npm install && npm run verify                 # 5. the locked 10-gate release

import { readdirSync, readFileSync, writeFileSync, renameSync, statSync } from "node:fs";
import { join, sep, extname, basename } from "node:path";

const ROOT = process.cwd();
const APPLY = process.argv.includes("--apply");

// Ordered, case-specific token map. Longest/most-specific casings first.
const TOKENS = [
  ["AntiFlock", "AntiFl0ck"],
  ["ANTIFLOCK", "ANTIFL0CK"],
  ["antiflock", "antifl0ck"],
];

// Preserved verbatim — the module path / repo URL keep the original spelling.
const PRESERVE = ["DBarr3/AntiFlock"];

// Never descend into these directory names.
const SKIP_DIRS = new Set([
  ".git", "node_modules", "dist", "build", ".next", "coverage", "gen", ".turbo",
]);
// Never edit these files — regenerate them instead.
const SKIP_FILES = new Set(["go.sum", "package-lock.json", "REBRAND.md", basename(process.argv[1] || "")]);
const SKIP_EXT = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".wasm", ".gz", ".zip",
  ".jar", ".keystore", ".lock", ".sum",
]);
const SKIP_SUFFIX = [".pb.go"]; // generated protobuf — regenerate with buf.

function skipFile(name) {
  if (SKIP_FILES.has(name)) return true;
  if (SKIP_EXT.has(extname(name))) return true;
  if (SKIP_SUFFIX.some((s) => name.endsWith(s))) return true;
  return false;
}

function protectedRebrand(text) {
  let t = text;
  const restore = [];
  PRESERVE.forEach((p, i) => {
    const token = ` AF${i} `;
    if (t.includes(p)) {
      t = t.split(p).join(token);
      restore.push([token, p]);
    }
  });
  let count = 0;
  for (const [from, to] of TOKENS) {
    const parts = t.split(from);
    if (parts.length > 1) {
      count += parts.length - 1;
      t = parts.join(to);
    }
  }
  for (const [token, p] of restore) t = t.split(token).join(p);
  return { text: t, count };
}

const fileEdits = [];
const dirRenames = [];

function walk(dir) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const st = statSync(full);
    if (st.isDirectory()) {
      if (SKIP_DIRS.has(entry)) continue;
      walk(full);
      if (/antiflock/i.test(entry)) {
        const renamed = protectedRebrand(entry).text;
        if (renamed !== entry) dirRenames.push([full, join(dir, renamed)]);
      }
      continue;
    }
    if (skipFile(entry)) continue;
    let text;
    try {
      text = readFileSync(full, "utf8");
    } catch {
      continue; // unreadable / binary
    }
    if (!/antiflock/i.test(text)) continue;
    const { text: next, count } = protectedRebrand(text);
    if (next !== text) fileEdits.push({ full, count, next });
  }
}

walk(ROOT);

const rel = (p) => p.slice(ROOT.length + 1) || p;
console.log(`AntiFlock -> AntiFl0ck rebrand (${APPLY ? "APPLY" : "dry-run"})\n`);
console.log(`Files to edit: ${fileEdits.length}`);
for (const e of fileEdits.slice(0, 500)) console.log(`  ${rel(e.full)}  (${e.count})`);
console.log(`\nDirectories to rename: ${dirRenames.length}`);
for (const [from, to] of dirRenames) console.log(`  ${rel(from)}  ->  ${rel(to)}`);

if (!APPLY) {
  console.log(`\nNothing written. Re-run with --apply to perform the rewrite, then follow docs/REBRAND.md.`);
  process.exit(0);
}

for (const e of fileEdits) writeFileSync(e.full, e.next);
// Rename directories deepest-first so parent renames do not invalidate children.
dirRenames.sort((a, b) => b[0].length - a[0].length);
for (const [from, to] of dirRenames) renameSync(from, to);

console.log(`\nApplied. NEXT (required, needs the toolchain):`);
console.log(`  npx buf generate            # regenerate api/gen from the renamed proto`);
console.log(`  rm -rf api/gen/go/antiflock  # remove the stale generated package if present`);
console.log(`  go mod tidy && go build ./... && go test ./...`);
console.log(`  npm install && npm run verify`);
