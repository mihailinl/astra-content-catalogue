// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// The service's answer, `astra.content.export/1`, as the signer accepts it.
//
// The answer is data from a job that read another system. It is read
// strictly (no duplicate member name, integers only), and it must carry
// exactly the members below and no other: a member this file does not name
// is refused, whatever it holds, so that nothing the service adds by mistake
// can travel into a public repository. The entries, rows and lifts are not
// judged here; they go into the documents, and the specification's checker
// judges those (lib/pipeline.mjs).

import fs from "node:fs";

import { parseProblem } from "./checker.mjs";
import { assertKind, MAX_EXPORT_BYTES, Refused } from "./kinds.mjs";

export const EXPORT_SCHEMA = "astra.content.export/1";
export const EXPORT_MEMBERS = Object.freeze(["schema", "kind", "generated_at", "state_sha256", "entries", "withdrawn"]);
export const WITHDRAWN_MEMBERS = Object.freeze(["rows", "lifts"]);

const TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const SHA256 = /^[0-9a-f]{64}$/;
const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

function exactly(value, members, where) {
  if (!isObject(value)) throw new Refused("E_EXPORT_SHAPE", `${where} is not an object`);
  const extra = Object.keys(value).filter((k) => !members.includes(k));
  // the name is not printed: it is whatever the sender chose
  if (extra.length) throw new Refused("E_EXPORT_MEMBER", `${where} carries ${extra.length} member(s) outside ${EXPORT_SCHEMA}`);
  const missing = members.filter((k) => !(k in value));
  if (missing.length) throw new Refused("E_EXPORT_SHAPE", `${where} lacks ${missing.join(", ")}`);
}

/** Hold a parsed answer to `astra.content.export/1` for `kind`. */
export function validateExport(doc, kind) {
  assertKind(kind);
  exactly(doc, EXPORT_MEMBERS, "the export");
  if (doc.schema !== EXPORT_SCHEMA) throw new Refused("E_EXPORT_SHAPE", `the export's schema is not ${EXPORT_SCHEMA}`);
  if (doc.kind !== kind) throw new Refused("E_EXPORT_KIND", `the export is not for ${kind}`);
  if (typeof doc.generated_at !== "string" || !TIME.test(doc.generated_at)) throw new Refused("E_EXPORT_SHAPE", "generated_at is not a time");
  if (typeof doc.state_sha256 !== "string" || !SHA256.test(doc.state_sha256)) throw new Refused("E_EXPORT_SHAPE", "state_sha256 is not 64 lowercase hex");
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
export function readExport({ file, kind }) {
  if (!fs.existsSync(file)) throw new Refused("E_EXPORT_ABSENT", `no export for ${kind}`);
  if (fs.statSync(file).size > MAX_EXPORT_BYTES) throw new Refused("E_EXPORT_SIZE", `the export for ${kind} is over ${MAX_EXPORT_BYTES} bytes`);
  const problem = parseProblem(file);
  if (problem) throw new Refused("E_EXPORT_PARSE", `the export for ${kind} is unreadable (${problem})`);
  return validateExport(JSON.parse(fs.readFileSync(file, "utf8")), kind);
}
