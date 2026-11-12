#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// sign.yml, job `work`: read the five kinds from the service and leave them
// for the signing jobs. This job holds an OIDC token and no key.
//
//   node bin/fetch.mjs --out <dir> --data <dir>
//
// <data> is a checkout of the `data` branch (bin/data.mjs open). It is read
// for one thing: when a kind was last signed, to tell a door that is not open
// yet from one that has stayed shut too long.
//
// Writes <out>/export-<kind>.json (the answer's bytes, untouched) for each
// kind that was answered, and <out>/work.json, which says for every kind:
//   fetched   an answer was written
//   closed    the door was not open, and the kind was never published or was
//             signed within the last twelve hours
//   overdue   the door was not open and the kind's last signature is older
//             than twelve hours (or cannot be read): the run fails
//   refused   the call was refused: the run fails
// Outputs: `todo` (a kind was fetched), `failed` (a kind is overdue or was
// refused). It exits 0 either way, so that the kinds that were fetched are
// still handed on; the workflow fails the job afterwards when `failed` is
// true.

import fs from "node:fs";
import path from "node:path";

import { appendTo, isMain, parseArgs, runAsCommand } from "../lib/args.mjs";
import { CLOSED_MAX_AGE, DOCS, documentPath, KINDS, statePath } from "../lib/kinds.mjs";
import { fetchAll } from "../lib/service.mjs";

export const WORK_SCHEMA = "astra.content.signer-work/1";

/**
 * When the kind was last signed, by what `data` says: null if the branch
 * holds none of the kind's files, a Unix second, or NaN when it holds some
 * and the second cannot be read. Nothing is verified here and nothing needs
 * to be: this only decides whether a quiet run becomes a failed one, and a
 * file that cannot be read makes it fail.
 */
export function lastSigned(dataDir, kind) {
  const files = [...DOCS.map((d) => documentPath(kind, d)), statePath(kind)].map((f) => path.join(dataDir, f));
  if (!files.some((f) => fs.existsSync(f))) return null;
  try {
    const serial = JSON.parse(fs.readFileSync(files[1], "utf8")).signed.issued_at;
    return Number.isSafeInteger(serial) ? serial : NaN;
  } catch {
    return NaN;
  }
}

export async function main(argv, { env = process.env, fetchImpl = fetch, token = null, log = console.log, now = Math.floor(Date.now() / 1000) } = {}) {
  const args = parseArgs(argv, ["out", "data"]);
  fs.mkdirSync(args.out, { recursive: true });
  const got = await fetchAll({ env, fetchImpl, token });
  const work = { schema: WORK_SCHEMA, kinds: {} };
  for (const kind of KINDS) {
    const r = got[kind];
    let status = r.status;
    let said = `refused (${r.why})`;
    if (status === "fetched") {
      fs.writeFileSync(path.join(args.out, `export-${kind}.json`), r.bytes);
      said = `fetched, ${r.bytes.length} bytes`;
    } else if (status === "closed") {
      const last = lastSigned(args.data, kind);
      if (last === null) said = `service door not open (${r.why}); the kind has never been published`;
      else if (now - last <= CLOSED_MAX_AGE) said = `service door not open (${r.why}); last signed ${now - last} s ago`;
      else {
        status = "overdue";
        said = `service door not open (${r.why}) and the kind was last signed ${Number.isNaN(last) ? "at a time that cannot be read" : `${now - last} s ago`}: over ${CLOSED_MAX_AGE} s, so this run fails`;
      }
    }
    work.kinds[kind] = status;
    log(`${kind}: ${said}`);
  }
  fs.writeFileSync(path.join(args.out, "work.json"), `${JSON.stringify(work, null, 2)}\n`);
  const statuses = Object.values(work.kinds);
  const todo = statuses.includes("fetched");
  const failed = statuses.includes("refused") || statuses.includes("overdue");
  appendTo("GITHUB_OUTPUT", `todo=${todo}`, env);
  appendTo("GITHUB_OUTPUT", `failed=${failed}`, env);
  if (!todo && !failed) {
    log("service door not open: nothing is signed, and every kind keeps its last signed documents");
    appendTo("GITHUB_STEP_SUMMARY", "Service door not open. Nothing was signed; the next run asks again.", env);
  }
  return work;
}

if (isMain(import.meta)) {
  runAsCommand(async (argv) => {
    await main(argv);
    return 0;
  });
}
