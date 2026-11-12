#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// sign.yml, job `sign`, the step BEFORE the key: read the answer the `work`
// job left and the kind's last signed pair on `data`, and write the two
// unsigned bodies and an order into the work directory (lib/pipeline.mjs,
// prepareKind). This step holds no key and no token, and reaches no network;
// it is the one that parses the service's bytes and runs the checker.
//
//   node bin/prepare.mjs --kind <kind> --exports <dir> --data <dir> --trust <trust.json> --work <dir>
//
// Exit 1 when the kind cannot be signed: the later steps do not run and the
// kind's last signed documents stay as they are. A kind whose door was not
// open leaves an order saying `closed`, and the later steps do nothing.

import fs from "node:fs";
import path from "node:path";

import { appendTo, isMain, parseArgs, runAsCommand } from "../lib/args.mjs";
import { everHeld } from "../lib/data.mjs";
import { assertKind, Refused } from "../lib/kinds.mjs";
import { ORDER_SCHEMA, prepareKind } from "../lib/pipeline.mjs";
import { loadTrust } from "../lib/trust.mjs";

export function main(argv, { env = process.env, now = Math.floor(Date.now() / 1000), roots, log = console.log } = {}) {
  const args = parseArgs(argv, ["kind", "exports", "data", "trust", "work"]);
  const kind = assertKind(args.kind);
  fs.mkdirSync(args.work, { recursive: true });
  try {
    const workFile = path.join(args.exports, "work.json");
    const status = fs.existsSync(workFile) ? JSON.parse(fs.readFileSync(workFile, "utf8"))?.kinds?.[kind] : undefined;
    if (status === "closed") {
      fs.writeFileSync(path.join(args.work, "order.json"), `${JSON.stringify({ schema: ORDER_SCHEMA, kind, outcome: "closed" }, null, 2)}\n`);
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
    });
    log(`${kind}: prepared for ${order.now}${order.carried ? `; ${order.carried} withdrawn row(s) kept that the answer omitted` : ""}`);
    return 0;
  } catch (e) {
    if (!(e instanceof Refused)) throw e;
    const line = `${kind}: not signed (${e.line()}); the last signed documents stay`;
    log(line);
    appendTo("GITHUB_STEP_SUMMARY", line, env);
    return 1;
  }
}

if (isMain(import.meta)) runAsCommand(main);
