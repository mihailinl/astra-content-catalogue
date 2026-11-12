// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai

/** `--name value` pairs after the positional words. Every name in `names` is required unless listed in `optional`. */
export function parseArgs(argv, names, optional = []) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) out._.push(a);
    else if ([...names, ...optional].includes(a.slice(2)) && i + 1 < argv.length) out[a.slice(2)] = argv[++i];
    else throw new Error(`unknown or incomplete argument ${a}`);
  }
  const missing = names.filter((n) => !(n in out));
  if (missing.length) throw new Error(`missing ${missing.map((n) => `--${n}`).join(", ")}`);
  return out;
}

/** Append one line to a GitHub Actions file (`GITHUB_OUTPUT`, `GITHUB_STEP_SUMMARY`), when the job has one. */
export function appendTo(envName, line, env = process.env, fs) {
  if (env[envName]) fs.appendFileSync(env[envName], `${line}\n`);
}
