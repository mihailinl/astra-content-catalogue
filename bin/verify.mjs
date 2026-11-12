#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// sign.yml, job `sign`, the step AFTER the key: prove that what was signed
// is what was prepared and that it verifies under the kind's key in
// trust.json, by this repository's signing code and by the specification's
// verifier, and only then write the kind's three files into the data
// directory (lib/pipeline.mjs, verifyAndInstall). No key, no token, no
// network.
//
//   node bin/verify.mjs --kind <kind> --data <dir> --trust <trust.json> --work <dir>
//
// It leaves <work>/report.json for the publishing step:
//   signed      the three files are in the data directory; `carried` counts
//               rows kept that the answer omitted
//   unchanged   the same answer was signed less than six hours ago
//   closed      the service door was not open; nothing to do

import fs from "node:fs";
import path from "node:path";

import { appendTo, isMain, parseArgs, runAsCommand } from "../lib/args.mjs";
import { assertKind, Refused } from "../lib/kinds.mjs";
import { verifyAndInstall } from "../lib/pipeline.mjs";
import { loadTrust } from "../lib/trust.mjs";

export const REPORT_SCHEMA = "astra.content.signer-report/1";

export function main(argv, { env = process.env, now = Math.floor(Date.now() / 1000), roots, log = console.log } = {}) {
  const args = parseArgs(argv, ["kind", "data", "trust", "work"]);
  const kind = assertKind(args.kind);
  try {
    let order = null;
    try {
      order = JSON.parse(fs.readFileSync(path.join(args.work, "order.json"), "utf8"));
    } catch {
      throw new Refused("E_PREPARED", "no order in the work directory");
    }
    let report;
    if (order?.kind === kind && order.outcome === "closed") report = { kind, outcome: "closed", carried: 0 };
    else {
      const trust = loadTrust({ file: args.trust, now, ...(roots ? { roots } : {}) });
      report = verifyAndInstall({ kind, workDir: args.work, dataDir: args.data, trust });
    }
    fs.writeFileSync(path.join(args.work, "report.json"), `${JSON.stringify({ schema: REPORT_SCHEMA, ...report }, null, 2)}\n`);
    const line =
      report.outcome === "signed"
        ? `${kind}: signed at ${report.issued_at} with ${report.key_id} and verified (index ${report.bytes.index} bytes, withdrawn ${report.bytes.withdrawn} bytes)${report.carried ? `; ${report.carried} withdrawn row(s) kept that the answer omitted` : ""}`
        : report.outcome === "unchanged"
          ? `${kind}: unchanged since ${report.issued_at}; not signed again`
          : `${kind}: service door not open`;
    log(line);
    appendTo("GITHUB_STEP_SUMMARY", line, env);
    return 0;
  } catch (e) {
    if (!(e instanceof Refused)) throw e;
    const line = `${kind}: not published (${e.line()}); the last signed documents stay`;
    log(line);
    appendTo("GITHUB_STEP_SUMMARY", line, env);
    return 1;
  }
}

if (isMain(import.meta)) runAsCommand(main);
