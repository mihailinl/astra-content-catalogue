#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// Place each kind's CURRENT signing key as the one secret of that kind's
// environment. Run by the operator, on the machine that holds the keys, and
// by nobody else: no workflow and no agent runs this.
//
//   owner/secrets.sh <keys-dir>                  all five kinds
//   owner/secrets.sh <keys-dir> --rotate <kind>  one kind, after trust.json
//                                                has named a new current key
//   options: --trust <file>   use this trust.json instead of fetching the
//                             published one from astra-registry
//            --repo <o/n>     default mihailinl/astra-content-catalogue
//
// Which key is current is not decided here and is not read from a file name
// pattern: it is the `current` row of the kind in the plugin registry's
// trust.json, verified under the compiled root keys. That row's key id names
// the files, `<keys-dir>/<key id>.seed.b64` and `<keys-dir>/<key id>.private.pem`.
// For each kind this
//
//   1. derives the public half from the private file(s), locally;
//   2. refuses unless it equals the kind's current row, and refuses by name
//      a key that is the kind's `next` row: the next key stays offline;
//   3. only when every kind asked for has passed, runs
//        gh secret set ASTRA_<KIND>_SIGNING_KEY --env publish-<kind> --repo …
//      with the key file as gh's standard input.
//
// A key never appears in an argument, in the environment of a child process,
// or in what this prints. It prints one line per kind: the kind, the key id,
// and `match` or `mismatch`. A kind's next key file is never opened.

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import { publicKeyBase64 } from "../vendor/astra-registry/bot/lib/sign.mjs";
import { assertKind, environmentOf, KINDS, Refused, secretOf } from "../lib/kinds.mjs";
import { privateKeyFromSecret, roleOf } from "../lib/signer.mjs";
import { loadTrust } from "../lib/trust.mjs";

export const DEFAULT_REPO = "mihailinl/astra-content-catalogue";
export const TRUST_URL = "https://raw.githubusercontent.com/mihailinl/astra-registry/main/registry/v1/trust.json";
/** The private spellings of one key, the one uploaded first. */
export const PRIVATE_SUFFIXES = Object.freeze([".seed.b64", ".private.pem"]);

function parse(argv) {
  const o = { dir: null, rotate: null, trust: null, repo: DEFAULT_REPO };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--rotate" || a === "--trust" || a === "--repo") {
      if (i + 1 >= argv.length) throw new Error(`${a} needs a value`);
      o[a.slice(2)] = argv[++i];
    } else if (a.startsWith("--")) throw new Error(`unknown option ${a}`);
    else if (o.dir === null) o.dir = a;
    else throw new Error(`unexpected argument`);
  }
  if (!o.dir) throw new Error("usage: owner/secrets.sh <keys-dir> [--rotate <kind>] [--trust <file>] [--repo <owner/name>]");
  if (o.rotate) assertKind(o.rotate);
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(o.repo)) throw new Error("--repo is not owner/name");
  return o;
}

/**
 * The file to upload for a kind, or why there is none.
 * @returns {{kind: string, key_id: string, ok: boolean, file?: string, why?: string}}
 */
export function currentKeyFile(dir, kind, kindKeys) {
  const { key_id } = kindKeys.current;
  const base = { kind, key_id };
  const files = PRIVATE_SUFFIXES.map((s) => path.join(dir, `${key_id}${s}`)).filter((f) => fs.existsSync(f));
  if (files.length === 0) return { ...base, ok: false, why: "no private file for this key id" };
  for (const file of files) {
    const key = privateKeyFromSecret(fs.readFileSync(file, "utf8"));
    if (!key) return { ...base, ok: false, why: `${path.basename(file)} is not an Ed25519 private key` };
    const role = roleOf(publicKeyBase64(key), kindKeys);
    if (role === "next") return { ...base, ok: false, why: "the private file holds the kind's NEXT key; it stays offline" };
    if (role !== "current") return { ...base, ok: false, why: `${path.basename(file)} is not the key trust.json names current` };
  }
  return { ...base, ok: true, file: files[0] };
}

export async function main(argv, { roots, fetchImpl = fetch, log = console.log, env = process.env, now = Math.floor(Date.now() / 1000) } = {}) {
  const o = parse(argv);
  let doc;
  if (o.trust) doc = JSON.parse(fs.readFileSync(o.trust, "utf8"));
  else {
    const r = await fetchImpl(TRUST_URL, { redirect: "error" });
    if (!r.ok) throw new Error(`the published trust.json answered HTTP ${r.status}`);
    doc = await r.json();
  }
  const trust = loadTrust({ doc, now, ...(roots ? { roots } : {}) });

  const kinds = o.rotate ? [o.rotate] : KINDS;
  const found = kinds.map((kind) => currentKeyFile(o.dir, kind, trust.kindKeys(kind)));
  for (const f of found) log(`${f.kind} ${f.key_id} ${f.ok ? "match" : "mismatch"}${f.ok ? "" : ` (${f.why})`}`);
  if (found.some((f) => !f.ok)) {
    log("nothing was uploaded: every kind must match first");
    return 1;
  }
  for (const f of found) {
    const fd = fs.openSync(f.file, "r");
    try {
      const r = spawnSync("gh", ["secret", "set", secretOf(f.kind), "--env", environmentOf(f.kind), "--repo", o.repo], {
        stdio: [fd, "pipe", "pipe"],
        env: { PATH: env.PATH ?? "", HOME: env.HOME ?? "", ...(env.GH_TOKEN ? { GH_TOKEN: env.GH_TOKEN } : {}), ...(env.GH_CONFIG_DIR ? { GH_CONFIG_DIR: env.GH_CONFIG_DIR } : {}) },
        encoding: "utf8",
      });
      if (r.error || r.status !== 0) {
        log(`${f.kind} ${f.key_id} NOT uploaded: gh ${r.error ? "could not be run" : `exited ${r.status}`}${r.stderr ? ` (${r.stderr.trim().split("\n")[0].slice(0, 200)})` : ""}`);
        return 1;
      }
    } finally {
      fs.closeSync(fd);
    }
    log(`${f.kind} ${f.key_id} uploaded to ${environmentOf(f.kind)}`);
  }
  if (o.rotate) log(`${o.rotate}: the next Sign run signs both documents under the new current key`);
  return 0;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (e) => {
      console.error(e instanceof Refused ? e.message : String(e?.message ?? e));
      process.exit(1);
    },
  );
}
