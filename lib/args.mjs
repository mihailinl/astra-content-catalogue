// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai

import fs from "node:fs";

/** A command was started with the wrong arguments. Its message is this repository's own words about its own options. */
export class UsageError extends Error {}

/** `--name value` pairs after the positional words. Every name in `names` is required unless listed in `optional`. */
export function parseArgs(argv, names, optional = []) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) out._.push(a);
    else if ([...names, ...optional].includes(a.slice(2)) && i + 1 < argv.length) out[a.slice(2)] = argv[++i];
    else throw new UsageError("unknown or incomplete argument (an option this command does not have, or one without its value)");
  }
  const missing = names.filter((n) => !(n in out));
  if (missing.length) throw new UsageError(`missing ${missing.map((n) => `--${n}`).join(", ")}`);
  return out;
}

/** Append one line to a GitHub Actions file (`GITHUB_OUTPUT`, `GITHUB_STEP_SUMMARY`), when the job has one. */
export function appendTo(envName, line, env = process.env) {
  if (env[envName]) fs.appendFileSync(env[envName], `${line}\n`);
}

/**
 * Run a step's `main` as a command: its number is the exit code, and an
 * error ends it with 1. What is printed for an error is a refusal's code and
 * sanitised location (lib/kinds.mjs), or `E_INTERNAL` and the error's class;
 * never a message, which could quote bytes the step was reading.
 */
export async function runAsCommand(main) {
  try {
    process.exit((await main(process.argv.slice(2))) ?? 0);
  } catch (e) {
    if (e instanceof UsageError) console.error(`usage: ${e.message}`);
    else console.error(typeof e?.line === "function" ? e.line() : `E_INTERNAL ${String(e?.code ?? e?.name ?? "Error").replace(/[^A-Za-z0-9_]/g, "").slice(0, 60)}`);
    process.exit(1);
  }
}

/** Whether this module is the file Node was started with. */
export const isMain = (meta) => meta.url === `file://${process.argv[1]}`;
