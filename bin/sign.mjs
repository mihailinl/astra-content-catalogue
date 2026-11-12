#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// sign.yml, job `sign`, the ONE step that holds the key: sign what
// bin/prepare.mjs prepared (lib/keystep.mjs).
//
//   CONTENT_SIGNING_KEY=<one of the kind's two keys> \
//   node bin/sign.mjs --kind <kind> --trust <trust.json> --work <dir>
//
// It reads the order and the two prepared bodies in the work directory and
// trust.json, and writes the two signed envelopes and a result beside them.
// It starts no process and opens no connection: nothing it imports can
// (test/workflows.test.mjs). The key arrives in the environment, never in an
// argument, and is removed from this process's environment as soon as it has
// been read. Nothing this step prints comes from a file it read.

import fs from "node:fs";
import path from "node:path";

import { isMain, parseArgs, runAsCommand } from "../lib/args.mjs";
import { signPrepared } from "../lib/keystep.mjs";
import { assertKind, Refused } from "../lib/kinds.mjs";
import { loadTrust } from "../lib/trust.mjs";

export function main(argv, { env = process.env, now = Math.floor(Date.now() / 1000), roots, log = console.log } = {}) {
  const args = parseArgs(argv, ["kind", "trust", "work"]);
  const kind = assertKind(args.kind);
  const secret = env.CONTENT_SIGNING_KEY;
  delete env.CONTENT_SIGNING_KEY;
  try {
    let order = null;
    try {
      order = JSON.parse(fs.readFileSync(path.join(args.work, "order.json"), "utf8"));
    } catch {
      throw new Refused("E_PREPARED", "no order in the work directory");
    }
    if (order?.kind === kind && order.outcome === "closed") {
      log(`${kind}: service door not open`);
      return 0;
    }
    const trust = loadTrust({ file: args.trust, now, ...(roots ? { roots } : {}) });
    const result = signPrepared({ kind, workDir: args.work, trust, secret });
    log(result.outcome === "signed" ? `${kind}: signed with ${result.key_id}` : `${kind}: unchanged; not signed again`);
    if (result.role === "next") {
      // not a failure: a rotation in progress (README, "Rotating a key")
      log(`${kind}: the key in this job is the kind's NEXT key (${result.key_id}); trust.json still names the other key current`);
    }
    return 0;
  } catch (e) {
    if (!(e instanceof Refused)) throw e;
    log(`${kind}: not signed (${e.line()}); the last signed documents stay`);
    return 1;
  }
}

if (isMain(import.meta)) runAsCommand(main);
