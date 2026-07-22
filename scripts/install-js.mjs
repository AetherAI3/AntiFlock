#!/usr/bin/env node

import { installJavascriptWorkspaces } from "./tooling.mjs";

if (!installJavascriptWorkspaces()) process.exitCode = 1;
