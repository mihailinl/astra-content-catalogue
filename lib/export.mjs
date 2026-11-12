// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// The service's answer, `astra.content.export/1`, as the signer accepts it.
//
// The answer is data from a job that read another system. It is read
// strictly (no duplicate member name, integers only), and it must carry
// exactly the members below and no other: a member this file does not name
// is refused, whatever it holds, so that nothing the service adds by mistake
// can travel into a public repository. It must also be fresh: `generated_at`
// within the last thirty minutes of this machine's clock (and no more than
// five minutes ahead of it), so that a re-run of an old workflow run, or an
// answer kept and offered again, is not signed under a new serial as if it
// were the kind's state now. The entries, rows and lifts are not
// judged here; they go into the documents, and the specification's checker
// judges those (lib/pipeline.mjs).

import fs from "node:fs";

import { parseProblem } from "./checker.mjs";
import { assertKind, EXPORT_MAX_AGE, EXPORT_MAX_AHEAD, MAX_EXPORT_BYTES, Refused } from "./kinds.mjs";

export const EXPORT_SCHEMA = "astra.content.export/1";
export const EXPORT_MEMBERS = Object.freeze(["schema", "kind", "generated_at", "state_sha256", "entries", "withdrawn"]);
export const WITHDRAWN_MEMBERS = Object.freeze(["rows", "lifts"]);

const TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const SHA256 = /^[0-9a-f]{64}$/;
const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

function exactly(value, members, where) {
  if (!isObject(value)) throw new Refused("E_EXPORT_SHAPE", `${where} is not an object`);
  const extra = Object.keys(value).filter((k) => !members.includes(k));
  // the name is not reported: it is whatever the sender chose
  if (extra.length) throw new Refused("E_EXPORT_MEMBER", `${where} carries ${extra.length} member(s) outside ${EXPORT_SCHEMA}`, where);
  const missing = members.filter((k) => !(k in value));
  if (missing.length) throw new Refused("E_EXPORT_SHAPE", `${where} lacks a member`, `${where}/${missing[0]}`);
}

/** Hold a parsed answer to `astra.content.export/1` for `kind`, at the second `now`. */
export function validateExport(doc, kind, now) {
  assertKind(kind);
  exactly(doc, EXPORT_MEMBERS, "export");
  if (doc.schema !== EXPORT_SCHEMA) throw new Refused("E_EXPORT_SHAPE", `the export's schema is not ${EXPORT_SCHEMA}`);
  if (doc.kind !== kind) throw new Refused("E_EXPORT_KIND", `the export is not for ${kind}`);
  if (typeof doc.generated_at !== "string" || !TIME.test(doc.generated_at)) throw new Refused("E_EXPORT_SHAPE", "generated_at is not a time");
  if (typeof doc.state_sha256 !== "string" || !SHA256.test(doc.state_sha256)) throw new Refused("E_EXPORT_SHAPE", "state_sha256 is not 64 lowercase hex");
  const generated = Math.floor(Date.parse(doc.generated_at) / 1000);
  if (!Number.isSafeInteger(generated) || generated < now - EXPORT_MAX_AGE || generated > now + EXPORT_MAX_AHEAD) {
    throw new Refused("E_EXPORT_STALE", `the export was generated outside ${EXPORT_MAX_AGE} s before and ${EXPORT_MAX_AHEAD} s after this machine's clock`);
  }
  if (!Array.isArray(doc.entries)) throw new Refused("E_EXPORT_SHAPE", "entries is not an array");
  exactly(doc.withdrawn, WITHDRAWN_MEMBERS, "withdrawn");
  for (const m of WITHDRAWN_MEMBERS) {
    if (!Array.isArray(doc.withdrawn[m])) throw new Refused("E_EXPORT_SHAPE", `withdrawn.${m} is not an array`);
  }
  for (const [name, list] of [["entries", doc.entries], ["withdrawn.rows", doc.withdrawn.rows], ["withdrawn.lifts", doc.withdrawn.lifts]]) {
    if (!list.every(isObject)) throw new Refused("E_EXPORT_SHAPE", `${name} holds something that is not an object`);
  }
  return doc;
}

/** Read one kind's export from the file the fetching job left. */
export function readExport({ file, kind, now }) {
  if (!fs.existsSync(file)) throw new Refused("E_EXPORT_ABSENT", `no export for ${kind}`);
  if (fs.statSync(file).size > MAX_EXPORT_BYTES) throw new Refused("E_EXPORT_SIZE", `the export for ${kind} is over ${MAX_EXPORT_BYTES} bytes`);
  const bad = parseProblem(file);
  if (bad) throw new Refused("E_EXPORT_PARSE", `the export for ${kind} is not strictly readable JSON`, bad);
  return validateExport(JSON.parse(fs.readFileSync(file, "utf8")), kind, now);
}
