#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// sign.yml, job `publish`, before the push: prove that what the key job
// signed is what the preparing job prepared, that it verifies under the
// kind's key in trust.json (by this repository's signing code and by the
// specification's verifier), and that `data` has not moved in between; only
// then write the kind's three files into the data directory
// (lib/pipeline.mjs, verifyAndInstall). No key, no token.
//
//   node bin/verify.mjs --kind <kind> --work <prepared artifact> --signed <signed artifact> --data <dir> --trust <trust.json>
//
// It leaves <signed>/report.json for the publishing step:
//   signed        the three files are in the data directory; `carried`
//                 counts rows kept that the answer omitted
//   unchanged     the same answer was signed less than six hours ago
//   closed        the service door was not open; nothing to do
//   not-prepared, not-signed
//                 the kind failed in an earlier job, which says why; nothing
//                 to do here

import fs from "node:fs";
import path from "node:path";

import { appendTo, isMain, parseArgs, runAsCommand } from "../lib/args.mjs";
import { everHeld } from "../lib/data.mjs";
import { assertKind, Refused } from "../lib/kinds.mjs";
import { verifyAndInstall } from "../lib/pipeline.mjs";
import { loadRecovery } from "../lib/recovery.mjs";
import { loadTrust } from "../lib/trust.mjs";

export const REPORT_SCHEMA = "astra.content.signer-report/1";

export function main(argv, { env = process.env, now = Math.floor(Date.now() / 1000), roots, log = console.log, recovery } = {}) {
  const args = parseArgs(argv, ["kind", "work", "signed", "data", "trust"]);
  const kind = assertKind(args.kind);
  try {
    const trust = loadTrust({ file: args.trust, now, ...(roots ? { roots } : {}) });
    const report = verifyAndInstall({
      kind,
      workDir: args.work,
      signedDir: args.signed,
      dataDir: args.data,
      trust,
      everHeld: everHeld({ dir: args.data, kind }),
      accepted: recovery ?? loadRecovery(),
    });
    fs.writeFileSync(path.join(args.signed, "report.json"), `${JSON.stringify({ schema: REPORT_SCHEMA, ...report }, null, 2)}\n`);
    const line =
      report.outcome === "signed"
        ? `${kind}: signed at ${report.issued_at} with ${report.key_id} and verified (index ${report.bytes.index} bytes, withdrawn ${report.bytes.withdrawn} bytes)${report.carried ? `; ${report.carried} withdrawn row(s) kept that the answer omitted` : ""}`
        : report.outcome === "unchanged"
          ? `${kind}: unchanged since ${report.issued_at}; not signed again`
          : report.outcome === "closed"
            ? `${kind}: service door not open`
            : `${kind}: ${report.outcome === "not-prepared" ? "not prepared" : "not signed"} in an earlier job; nothing to publish`;
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
