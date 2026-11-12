#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// sign.yml, job `work`: read the five kinds from the service and leave them
// for the signing jobs. This job holds an OIDC token and no key.
//
//   node bin/fetch.mjs --out <dir>
//
// Writes <dir>/export-<kind>.json (the answer's bytes, untouched) for each
// kind that was answered, and <dir>/work.json, which says for every kind
// whether it was fetched, the door was not open, or the call was refused.
// Outputs: `todo` (a kind was fetched), `failed` (a call was refused). It
// exits 0 either way, so that the kinds that were fetched are still handed
// on; the workflow fails the job afterwards when `failed` is true.

import fs from "node:fs";
import path from "node:path";

import { appendTo, parseArgs } from "../lib/args.mjs";
import { KINDS } from "../lib/kinds.mjs";
import { fetchAll } from "../lib/service.mjs";

export const WORK_SCHEMA = "astra.content.signer-work/1";

export async function main(argv, { env = process.env, fetchImpl = fetch, token = null, log = console.log } = {}) {
  const args = parseArgs(argv, ["out"]);
  fs.mkdirSync(args.out, { recursive: true });
  const got = await fetchAll({ env, fetchImpl, token });
  const work = { schema: WORK_SCHEMA, kinds: {} };
  for (const kind of KINDS) {
    const r = got[kind];
    work.kinds[kind] = r.status;
    if (r.status === "fetched") fs.writeFileSync(path.join(args.out, `export-${kind}.json`), r.bytes);
    log(`${kind}: ${r.status === "fetched" ? `fetched, ${r.bytes.length} bytes` : r.status === "closed" ? `service door not open (${r.why})` : `refused (${r.why})`}`);
  }
  fs.writeFileSync(path.join(args.out, "work.json"), `${JSON.stringify(work, null, 2)}\n`);
  const statuses = Object.values(work.kinds);
  const todo = statuses.includes("fetched");
  const failed = statuses.includes("refused");
  appendTo("GITHUB_OUTPUT", `todo=${todo}`, env, fs);
  appendTo("GITHUB_OUTPUT", `failed=${failed}`, env, fs);
  if (!todo && !failed) {
    log("service door not open: nothing is signed, and every kind keeps its last signed documents");
    appendTo("GITHUB_STEP_SUMMARY", "Service door not open. Nothing was signed; the next run asks again.", env, fs);
  }
  return work;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main(process.argv.slice(2)).catch((e) => {
    console.error(String(e?.message ?? e));
    process.exit(1);
  });
}
