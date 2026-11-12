#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// sign.yml, job `sign`, the two steps around the signing step. Neither holds
// the key; both hold the job's token (GITHUB_TOKEN, `contents: write`).
//
//   node bin/data.mjs open    --dir <dir> [--remote <url>]
//       check out the `data` branch into <dir>, or start it
//   node bin/data.mjs publish --dir <dir> --report <file>
//       commit what the signing step wrote and move `data` forward, then exit
//       1 if the signed withdrawn document keeps a row that the service's
//       answer omitted. Publishing comes first on purpose: the kept row must
//       reach clients, and the failed run is how a person learns of it.

import fs from "node:fs";

import { parseArgs } from "../lib/args.mjs";
import { openData, publishData } from "../lib/data.mjs";

function remoteOf(args, env) {
  if (args.remote) return args.remote;
  if (!env.GITHUB_REPOSITORY) throw new Error("no --remote and no GITHUB_REPOSITORY");
  return `${env.GITHUB_SERVER_URL || "https://github.com"}/${env.GITHUB_REPOSITORY}.git`;
}

export function main(argv, { env = process.env, log = console.log } = {}) {
  const [mode, ...rest] = argv;
  const token = env.GITHUB_TOKEN || null;
  if (mode === "open") {
    const args = parseArgs(rest, ["dir"], ["remote"]);
    const r = openData({ remote: remoteOf(args, env), dir: args.dir, token });
    log(r.exists ? `data is at ${r.head}` : "data does not exist yet; this run starts it");
    return 0;
  }
  if (mode === "publish") {
    const args = parseArgs(rest, ["dir", "report"]);
    const report = JSON.parse(fs.readFileSync(args.report, "utf8"));
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
  throw new Error("usage: node bin/data.mjs open|publish --dir <dir> [--report <file>] [--remote <url>]");
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    process.exit(main(process.argv.slice(2)));
  } catch (e) {
    // git's stderr may quote a URL; the token is never part of one (lib/data.mjs)
    console.error(String(e?.stderr || e?.message || e).slice(0, 2000));
    process.exit(1);
  }
}
