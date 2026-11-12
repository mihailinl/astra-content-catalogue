#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// The `data` branch, opened and moved forward. Both commands hold the job's
// token (GITHUB_TOKEN) and neither holds a key.
//
//   node bin/data.mjs open    --dir <dir> [--remote <url>]
//       check out the `data` branch into <dir>, or start it. Used by the
//       `work` job (to see when each kind was last signed), by the preparing
//       job (to read the last pair) and by the publishing job.
//   node bin/data.mjs publish --dir <dir> --signed <dir>
//       the last step of the publishing job: commit what bin/verify.mjs installed
//       and move `data` forward, then exit 1 if the signed withdrawn document
//       keeps a row that the service's answer omitted. Publishing comes first
//       on purpose: the kept row must reach clients, and the failed run is
//       how a person learns of it.

import fs from "node:fs";
import path from "node:path";

import { isMain, parseArgs, runAsCommand } from "../lib/args.mjs";
import { openData, publishData } from "../lib/data.mjs";

function remoteOf(args, env) {
  if (args.remote) return args.remote;
  if (!env.GITHUB_REPOSITORY) throw new Error("no --remote and no GITHUB_REPOSITORY");
  return `${env.GITHUB_SERVER_URL || "https://github.com"}/${env.GITHUB_REPOSITORY}.git`;
}

/** The first line of git's own complaint, without anything a log could take for a command. */
const gitSaid = (e) => String(e?.stderr ?? "").split("\n")[0].replace(/[^A-Za-z0-9 _./()'!>-]/g, "").slice(0, 200);

export function main(argv, o = {}) {
  try {
    return run(argv, o);
  } catch (e) {
    if (e?.stderr === undefined) throw e;
    (o.log ?? console.log)(`data: git failed (${gitSaid(e)})`);
    return 1;
  }
}

function run(argv, { env = process.env, log = console.log } = {}) {
  const [mode, ...rest] = argv;
  const token = env.GITHUB_TOKEN || null;
  if (mode === "open") {
    const args = parseArgs(rest, ["dir"], ["remote"]);
    const r = openData({ remote: remoteOf(args, env), dir: args.dir, token });
    log(r.exists ? `data is at ${r.head}` : "data does not exist yet; this run starts it");
    return 0;
  }
  if (mode === "publish") {
    const args = parseArgs(rest, ["dir", "signed"]);
    const report = JSON.parse(fs.readFileSync(path.join(args.signed, "report.json"), "utf8"));
    if (report.outcome === "signed") {
      const r = publishData({ dir: args.dir, message: `sign ${report.kind}: issued_at ${report.issued_at} under ${report.key_id}`, token });
      log(r.pushed ? `data moved forward to ${r.head}` : "nothing to publish");
    } else {
      log(`${report.kind}: ${report.outcome}; nothing to publish`);
    }
    if (report.carried > 0) {
      log(
        `${report.kind}: the published withdrawn document keeps ${report.carried} row(s) that the service's answer omitted without a lift. ` +
          "The rows stay published until the service lifts them or states them again. This run fails so that the difference is looked at.",
      );
      return 1;
    }
    return 0;
  }
  throw new Error("usage: node bin/data.mjs open|publish --dir <dir> [--signed <dir>] [--remote <url>]");
}

if (isMain(import.meta)) runAsCommand(main);
