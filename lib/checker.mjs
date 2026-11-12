// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// The specification's checker, as the signer calls it. The checker is
// AstraPlugins' own Python (vendored; lib/vendored.mjs), reached through
// lib/check.py. The signer has no second copy of a schema or a rule.

import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const BRIDGE = path.join(path.dirname(fileURLToPath(import.meta.url)), "check.py");

function ask(request) {
  const out = execFileSync("python3", ["-I", "-B", BRIDGE], {
    input: JSON.stringify(request),
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
    // the checker needs nothing from the environment, and gets nothing
    env: { PATH: process.env.PATH ?? "/usr/bin:/bin" },
    stdio: ["pipe", "pipe", "inherit"],
  });
  return JSON.parse(out);
}

/** Why the bytes of `file` are not a strictly readable JSON document, or null. */
export function parseProblem(file) {
  return ask({ op: "parse", file }).problem;
}

/**
 * One envelope against the kind's schema, every semantic and pairing rule,
 * and (with `trust`, the `signed` member of trust.json) the kind's keys.
 *
 * @returns {{ok: boolean, parse: string|null, schema: string|null, rules: string[], verified_by: string[], reason: string|null}}
 */
export function checkDocument({ file, kind, doc, now, trust = null }) {
  return ask({ op: "document", file, kind, doc, now, trust });
}

/** One line saying why a document failed `checkDocument`. */
export function describe(result) {
  if (result.parse) return `unreadable (${result.parse})`;
  if (result.schema) return `refused by the schema (${result.schema})`;
  if (result.rules.length) return `refused by ${result.rules.join(", ")}`;
  if (result.reason) return `not verified (${result.reason})`;
  return "accepted";
}
