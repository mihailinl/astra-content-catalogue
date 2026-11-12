#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// sign.yml, job `prepare`: read the answer the `work` job left and the
// kind's last signed pair on `data`, and write the prepared artifact: the two
// unsigned bodies, an order, and the trust.json that was used
// (lib/pipeline.mjs, prepareKind; lib/workdir.mjs). This job holds no key;
// it is the one that parses the service's bytes and runs the checker.
//
//   node bin/prepare.mjs --kind <kind> --exports <dir> --data <dir> --trust <trust.json> --work <dir>
//
// <work> always ends holding an order. `prepared`: with the bodies, for the
// key job. `closed`: the kind's door was not open; the later jobs do nothing.
// `refused`: the kind cannot be signed; this command exits 1, the later jobs
// do nothing, and the kind's last signed documents stay as they are.

import fs from "node:fs";
import path from "node:path";

import { appendTo, isMain, parseArgs, runAsCommand } from "../lib/args.mjs";
import { everHeld } from "../lib/data.mjs";
import { assertKind, Refused } from "../lib/kinds.mjs";
import { leaveOrder, prepareKind } from "../lib/pipeline.mjs";
import { loadRecovery } from "../lib/recovery.mjs";
import { loadTrust } from "../lib/trust.mjs";

export function main(argv, { env = process.env, now = Math.floor(Date.now() / 1000), roots, log = console.log, recovery } = {}) {
  const args = parseArgs(argv, ["kind", "exports", "data", "trust", "work"]);
  const kind = assertKind(args.kind);
  fs.rmSync(args.work, { recursive: true, force: true });
  fs.mkdirSync(args.work, { recursive: true });
  try {
    const workFile = path.join(args.exports, "work.json");
    const status = fs.existsSync(workFile) ? JSON.parse(fs.readFileSync(workFile, "utf8"))?.kinds?.[kind] : undefined;
    if (status === "closed") {
      leaveOrder(args.work, kind, "closed");
      log(`${kind}: service door not open`);
      return 0;
    }
    if (status !== "fetched") throw new Refused("E_EXPORT_ABSENT", `the work job left no export for ${kind}`);
    const trust = loadTrust({ file: args.trust, now, ...(roots ? { roots } : {}) });
    const order = prepareKind({
      kind,
      exportFile: path.join(args.exports, `export-${kind}.json`),
      dataDir: args.data,
      trust,
      now,
      workDir: args.work,
      everHeld: everHeld({ dir: args.data, kind }),
      accepted: recovery ?? loadRecovery(),
    });
    log(`${kind}: prepared for ${order.now}${order.carried ? `; ${order.carried} withdrawn row(s) kept that the answer omitted` : ""}`);
    return 0;
  } catch (e) {
    if (!(e instanceof Refused)) throw e;
    leaveOrder(args.work, kind, "refused");
    const line = `${kind}: not signed (${e.line()}); the last signed documents stay`;
    log(line);
    appendTo("GITHUB_STEP_SUMMARY", line, env);
    return 1;
  }
}

if (isMain(import.meta)) runAsCommand(main);
