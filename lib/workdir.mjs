// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// What the three jobs of a kind hand to one another (lib/pipeline.mjs
// describes the jobs). Two directories travel, each as one artifact:
//
//   prepared-<kind>   from the preparing job to the key job and the
//                     publishing job:
//                       order.json            always
//                       index.signed.json     \
//                       withdrawn.signed.json  > only when the order is `prepared`
//                       trust.json            /
//   signed-<kind>     from the key job to the publishing job:
//                       result.json           always
//                       index.json            \  only when the result is `signed`
//                       withdrawn.json        /
//
// A directory that came out of an artifact is admitted before anything in it
// is read: exactly these names, each a regular file within its size bound,
// and nothing else: no other file, no directory, no link. The job that
// holds the key reads its input through `admitPrepared` and nothing besides.
//
// This module is imported by the key job, so it imports nothing that starts
// a process.

import fs from "node:fs";
import path from "node:path";

import { jcs } from "../vendor/astra-registry/tools/lib/canonical.mjs";
import { MAX_DOCUMENT_BYTES, Refused } from "./kinds.mjs";

export const ORDER_SCHEMA = "astra.content.signer-order/1";
export const RESULT_SCHEMA = "astra.content.signer-result/1";

/** The bytes of a document as published: RFC 8785 canonical JSON of the whole envelope. */
export const documentBytes = (envelope) => Buffer.from(jcs(envelope), "utf8");

/** A signature of the right length and no meaning, for measuring and checking a document before it is signed. */
export const UNSIGNED = "A".repeat(86) + "==";

export const bodyFile = (workDir, doc) => path.join(workDir, `${doc}.signed.json`);
export const envelopeFile = (workDir, doc) => path.join(workDir, `${doc}.json`);
export const readJson = (file, code) => {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    throw new Refused(code, "a file of the work directory is absent or not JSON", path.basename(file));
  }
};
export const writeJson = (file, value) => fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);


const SMALL = 8 * 1024;
/** The files of each artifact and the most bytes each may have. */
export const PREPARED_FILES = Object.freeze({ "order.json": SMALL, "index.signed.json": MAX_DOCUMENT_BYTES, "withdrawn.signed.json": MAX_DOCUMENT_BYTES, "trust.json": 256 * 1024 });
export const SIGNED_FILES = Object.freeze({ "result.json": SMALL, "index.json": MAX_DOCUMENT_BYTES, "withdrawn.json": MAX_DOCUMENT_BYTES });

function admit(dir, allowed, always, complete, what) {
  let names;
  try {
    if (!fs.lstatSync(dir).isDirectory()) throw new Error("not a directory");
    names = fs.readdirSync(dir).sort();
  } catch {
    throw new Refused("E_ARTIFACT", `no ${what} artifact`);
  }
  for (const name of names) {
    // the name is the sender's; it is reported only when it is one of ours
    if (!(name in allowed)) throw new Refused("E_ARTIFACT", `the ${what} artifact holds something it must not`);
    const st = fs.lstatSync(path.join(dir, name));
    if (!st.isFile()) throw new Refused("E_ARTIFACT", `a member of the ${what} artifact is not a regular file`, name);
    if (st.size > allowed[name]) throw new Refused("E_ARTIFACT", `a member of the ${what} artifact is over its size bound`, name);
  }
  if (!names.includes(always)) throw new Refused("E_ARTIFACT", `the ${what} artifact has no ${always}`, always);
  const head = readJson(path.join(dir, always), "E_ARTIFACT");
  const want = complete(head) ? Object.keys(allowed).sort() : [always];
  if (names.length !== want.length || names.some((n, i) => n !== want[i])) {
    throw new Refused("E_ARTIFACT", `the ${what} artifact does not hold exactly the files its ${always} calls for`);
  }
  return head;
}

/** Admit a `prepared-<kind>` directory and return its order. */
export function admitPrepared(dir, kind) {
  const order = admit(dir, PREPARED_FILES, "order.json", (o) => o?.outcome === "prepared", "prepared");
  if (order?.schema !== ORDER_SCHEMA || order.kind !== kind || !["prepared", "closed", "refused"].includes(order.outcome)) {
    throw new Refused("E_ARTIFACT", `the prepared artifact is not an order for ${kind}`);
  }
  return order;
}

/** Admit a `signed-<kind>` directory and return its result. */
export function admitSigned(dir, kind) {
  const result = admit(dir, SIGNED_FILES, "result.json", (r) => r?.outcome === "signed", "signed");
  if (result?.schema !== RESULT_SCHEMA || result.kind !== kind || !["signed", "unchanged", "closed", "not-prepared", "refused"].includes(result.outcome)) {
    throw new Refused("E_ARTIFACT", `the signed artifact is not a result for ${kind}`);
  }
  return result;
}
