#!/usr/bin/env node

import { formatGoFiles, runBufStep } from "./tooling.mjs";

let passed = formatGoFiles();
passed = runBufStep("Format Protocol Buffer sources", ["format", "--write"]) && passed;
if (!passed) process.exitCode = 1;
