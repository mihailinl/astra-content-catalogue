#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// sign.yml, job `sign`: the ONE command of the one job that holds a key.
//
//   CONTENT_SIGNING_KEY=<one of the kind's two keys> \
//   node bin/sign.mjs --kind <kind> --work <prepared artifact> --out <dir>
//
// <work> is the prepared artifact of this kind: the order, the two unsigned
// bodies and trust.json (lib/workdir.mjs). It is admitted before anything in
// it is read, and nothing else is read. <out> receives the result and, when
// the kind is signed, the two signed documents; that directory is the job's
// only output.
//
// It starts no process and opens no connection: nothing it imports can
// (test/steps.test.mjs). The key arrives in the environment, never in an
// argument, and is removed from this process's environment as soon as it has
// been read. Nothing this command prints comes from a file it read.

import fs from "node:fs";
import path from "node:path";

import { isMain, parseArgs, runAsCommand } from "../lib/args.mjs";
import { signPrepared } from "../lib/keystep.mjs";
import { assertKind, Refused } from "../lib/kinds.mjs";
import { loadTrust } from "../lib/trust.mjs";
import { admitPrepared, RESULT_SCHEMA, writeJson } from "../lib/workdir.mjs";

export function main(argv, { env = process.env, now = Math.floor(Date.now() / 1000), roots, log = console.log } = {}) {
  const args = parseArgs(argv, ["kind", "work", "out"]);
  const kind = assertKind(args.kind);
  const secret = env.CONTENT_SIGNING_KEY;
  delete env.CONTENT_SIGNING_KEY;
  try {
    const order = admitPrepared(args.work, kind);
    const trust = order.outcome === "prepared" ? loadTrust({ file: path.join(args.work, "trust.json"), now, ...(roots ? { roots } : {}) }) : null;
    const result = signPrepared({ kind, workDir: args.work, outDir: args.out, trust, secret });
    if (result.outcome === "signed") log(`${kind}: signed with ${result.key_id}`);
    else if (result.outcome === "unchanged") log(`${kind}: unchanged; not signed again`);
    else if (result.outcome === "closed") log(`${kind}: service door not open`);
    else log(`${kind}: not prepared; nothing to sign`);
    if (result.role === "next") {
      // not a failure: a rotation in progress (README, "Rotating a key")
      log(`${kind}: the key in this job is the kind's NEXT key (${result.key_id}); trust.json still names the other key current`);
    }
    return 0;
  } catch (e) {
    if (!(e instanceof Refused)) throw e;
    // the publishing job is told why it has nothing to publish, in a word
    fs.mkdirSync(args.out, { recursive: true });
    for (const name of fs.readdirSync(args.out)) fs.rmSync(path.join(args.out, name), { recursive: true });
    writeJson(path.join(args.out, "result.json"), { schema: RESULT_SCHEMA, kind, outcome: "refused", code: e.code });
    log(`${kind}: not signed (${e.line()}); the last signed documents stay`);
    return 1;
  }
}

if (isMain(import.meta)) runAsCommand(main);
