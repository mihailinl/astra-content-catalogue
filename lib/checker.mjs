// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// The specification's checker, as the signer calls it. The checker is
// AstraPlugins' own Python (vendored; lib/vendored.mjs), reached through
// lib/check.py. The signer has no second copy of a schema or a rule.
//
// The checker parses bytes the service chose, so it is started with nothing
// to lose: isolated mode (`-I`: no PYTHON* variable, no user site, no script
// directory on the path), an environment of PATH alone, and its standard
// error discarded, because a traceback can quote what it was parsing. It is
// never started by the step that holds a key: bin/sign.mjs does not import
// this module (test/workflows.test.mjs).

import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { Refused } from "./kinds.mjs";

const BRIDGE = path.join(path.dirname(fileURLToPath(import.meta.url)), "check.py");

/** How the checker is started: the arguments and the whole environment of the child. */
export function invocation(env = process.env) {
  return { command: "python3", args: ["-I", "-B", BRIDGE], env: { PATH: env.PATH ?? "/usr/bin:/bin" } };
}

function ask(request) {
  const { command, args, env } = invocation();
  let out;
  try {
    out = execFileSync(command, args, { input: JSON.stringify(request), encoding: "utf8", maxBuffer: 16 * 1024 * 1024, env, stdio: ["pipe", "pipe", "ignore"] });
    return JSON.parse(out);
  } catch {
    throw new Refused("E_CHECKER", "the specification's checker did not answer");
  }
}

/** How the checker's process was started, as it sees itself. */
export const checkerSelf = () => ask({ op: "self" });

/** A code saying why the bytes of `file` are not a strictly readable JSON document, or null. */
export function parseProblem(file) {
  const r = ask({ op: "parse", file });
  return r.ok ? null : r.problem;
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

/** Where a document failed `checkDocument`: a code and a location, never a value. */
export function whereFailed(result) {
  if (result.parse) return `parse/${result.parse}`;
  if (result.schema) return `schema/${result.schema}`;
  if (result.rules.length) return `rule/${result.rules.join("/")}`;
  if (result.reason) return `signature/${result.reason}`;
  return "";
}
