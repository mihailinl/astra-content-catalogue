#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// sign.yml, job `work`: read the five kinds from the service and leave them
// for the preparing jobs. This job holds an OIDC token and no key.
//
//   node bin/fetch.mjs --out <dir> --data <dir>
//
// <data> is a checkout of the `data` branch (bin/data.mjs open). It is read
// for one thing: when a kind was last signed, to tell a door that is not open
// yet from one that has stayed shut too long.
//
// <out> becomes the artifact the preparing jobs read, so nothing is written
// there that has not been checked: an answer goes to a scratch file first,
// is held to the export schema, to freshness and to the kind's document
// schemas and rules (lib/pipeline.mjs, admitAnswer), and only then is copied
// to <out>/export-<kind>.json. An answer that fails is deleted and its kind
// is `refused`. <out>/work.json says for every kind:
//   fetched   an answer was checked and written
//   closed    the door was not open, and the kind was never published or was
//             signed within the last twelve hours
//   overdue   the door was not open and the kind's last signature is older
//             than twelve hours, is dated in the future, or cannot be read:
//             the run fails
//   refused   the call was refused, or the answer was: the run fails
// Outputs: `todo` (a kind was fetched), `failed` (a kind is overdue or was
// refused). It exits 0 either way, so that the kinds that were fetched are
// still handed on; the workflow fails the job afterwards when `failed` is
// true.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { appendTo, isMain, parseArgs, runAsCommand } from "../lib/args.mjs";
import { everHeld } from "../lib/data.mjs";
import { CLOSED_MAX_AGE, documentPath, KINDS, Refused } from "../lib/kinds.mjs";
import { admitAnswer } from "../lib/pipeline.mjs";
import { fetchAll } from "../lib/service.mjs";

export const WORK_SCHEMA = "astra.content.signer-work/1";

/**
 * When the kind was last signed, by what `data` says: null if no commit on
 * the branch ever touched the kind (it has never been published), a Unix
 * second, or NaN when it was published and the second cannot be read, its
 * files having been removed included. Nothing is verified here and nothing
 * needs to be: this only decides whether a quiet run becomes a failed one,
 * and whatever cannot be read makes it fail.
 */
export function lastSigned(dataDir, kind) {
  if (!everHeld({ dir: dataDir, kind })) return null;
  try {
    const serial = JSON.parse(fs.readFileSync(path.join(dataDir, documentPath(kind, "withdrawn")), "utf8")).signed.issued_at;
    return Number.isSafeInteger(serial) ? serial : NaN;
  } catch {
    return NaN;
  }
}

/** Whether a kind last signed at `last` (see lastSigned) may stay quiet behind a closed door at `now`. */
export const quiet = (last, now) => last === null || (last <= now && now - last <= CLOSED_MAX_AGE);

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
      // scratch first: only an answer that passed is written where the artifact is taken from
      const scratch = fs.mkdtempSync(path.join(os.tmpdir(), `answer-${kind}-`));
      try {
        const file = path.join(scratch, "answer.json");
        fs.writeFileSync(file, r.bytes);
        admitAnswer({ file, kind, now, dir: scratch });
        fs.copyFileSync(file, path.join(args.out, `export-${kind}.json`));
        said = `fetched and checked, ${r.bytes.length} bytes`;
      } catch (e) {
        if (!(e instanceof Refused)) throw e;
        status = "refused";
        said = `the answer is refused (${e.line()})`;
      } finally {
        fs.rmSync(scratch, { recursive: true, force: true });
      }
    } else if (status === "closed") {
      const last = lastSigned(args.data, kind);
      if (last === null) said = `service door not open (${r.why}); the kind has never been published`;
      else if (quiet(last, now)) said = `service door not open (${r.why}); last signed ${now - last} s ago`;
      else {
        status = "overdue";
        const when = Number.isNaN(last) ? "at a time that cannot be read" : last > now ? "at a time in the future" : `${now - last} s ago`;
        said = `service door not open (${r.why}) and the kind was last signed ${when}: this run fails`;
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
