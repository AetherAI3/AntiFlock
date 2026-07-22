#!/usr/bin/env node

import { safeRemove } from "./tooling.mjs";

const generatedPaths = [
  "bin",
  "coverage",
  "apps/web/dist",
  "apps/web/.next",
  "apps/aether-demo/dist",
  "sdk/typescript/dist",
  "apps/android/build",
  "apps/android/guard-domain/build",
  "apps/android/platform-adapters/build",
  "apps/android/reference-app/build",
];

for (const path of generatedPaths) {
  safeRemove(path);
  process.stdout.write(`Removed ${path}\n`);
}
