#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// sign.yml, job `sign`, the step that holds the key: sign one kind.
//
//   CONTENT_SIGNING_KEY=<the kind's current key> \
//   node bin/sign.mjs --kind <kind> --exports <dir> --data <dir> --trust <trust.json> --report <file>
//
// It reads the export the `work` job left, the kind's last signed documents
// in the data directory and trust.json, and writes the kind's two documents
// and its state file into the data directory (lib/pipeline.mjs). It reaches
// no network. The key arrives in the environment, never in an argument, and
// is removed from this process's environment as soon as it has been read.
//
// The report says what happened, for the publishing step:
//   signed      the three files are written; `carried` counts rows kept
//               that the answer omitted (the publishing step fails the run
//               for them, after it has published)
//   unchanged   the same answer was signed less than six hours ago
//   closed      the service door was not open; nothing to do
// Exit 1, with outcome `refused`, when the kind could not be signed: its
// last signed documents stay as they are.

import fs from "node:fs";
import path from "node:path";

import { appendTo, parseArgs } from "../lib/args.mjs";
import { assertKind, Refused } from "../lib/kinds.mjs";
import { signKind } from "../lib/pipeline.mjs";
import { loadTrust } from "../lib/trust.mjs";

export const REPORT_SCHEMA = "astra.content.signer-report/1";

export function main(argv, { env = process.env, now = Math.floor(Date.now() / 1000), roots, log = console.log } = {}) {
  const args = parseArgs(argv, ["kind", "exports", "data", "trust", "report"]);
  const kind = assertKind(args.kind);
  const secret = env.CONTENT_SIGNING_KEY;
  delete env.CONTENT_SIGNING_KEY;

  let report;
  try {
    const workFile = path.join(args.exports, "work.json");
    const status = fs.existsSync(workFile) ? JSON.parse(fs.readFileSync(workFile, "utf8"))?.kinds?.[kind] : undefined;
    if (status === "closed") {
      report = { kind, outcome: "closed" };
    } else if (status !== "fetched") {
      throw new Refused("E_EXPORT_ABSENT", `the work job left no export for ${kind}`);
    } else {
      const trust = loadTrust({ file: args.trust, now, ...(roots ? { roots } : {}) });
      report = signKind({ kind, exportFile: path.join(args.exports, `export-${kind}.json`), dataDir: args.data, trust, secret, now });
    }
  } catch (e) {
    if (!(e instanceof Refused)) throw e;
    report = { kind, outcome: "refused", code: e.code };
    log(e.message);
  }
  fs.mkdirSync(path.dirname(path.resolve(args.report)), { recursive: true });
  fs.writeFileSync(args.report, `${JSON.stringify({ schema: REPORT_SCHEMA, ...report }, null, 2)}\n`);
  const line =
    report.outcome === "signed"
      ? `${kind}: signed at ${report.issued_at} under ${report.key_id} (index ${report.bytes.index} bytes, withdrawn ${report.bytes.withdrawn} bytes)${report.carried ? `; ${report.carried} withdrawn row(s) kept that the answer omitted` : ""}`
      : report.outcome === "unchanged"
        ? `${kind}: unchanged since ${report.issued_at}; not signed again`
        : report.outcome === "closed"
          ? `${kind}: service door not open`
          : `${kind}: not signed (${report.code}); the last signed documents stay`;
  log(line);
  appendTo("GITHUB_STEP_SUMMARY", line, env);
  return report;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    process.exit(main(process.argv.slice(2)).outcome === "refused" ? 1 : 0);
  } catch (e) {
    console.error(String(e?.message ?? e));
    process.exit(1);
  }
}
