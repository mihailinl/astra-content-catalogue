// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// What the three jobs of a kind hand to one another (lib/pipeline.mjs
// describes the jobs).
//
//   prepared-<kind>   an artifact, from the preparing job to the key job and
//                     the publishing job:
//                       order.json            always
//                       index.signed.json     \
//                       withdrawn.signed.json  > only when the order is `prepared`
//                       trust.json            /
//   the result        from the key job to the publishing job, as ONE LINE of
//                     job output (`resultLine`), never as an artifact: the
//                     result and, when signed, the two signatures. Artifacts
//                     of a public repository can be downloaded by anyone, so
//                     a signed document must not be one before the publishing
//                     job has checked it; a job output is not published. The
//                     publishing job rebuilds the signed directory from that
//                     line and the prepared bodies (`signedFromLine`):
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
import { DOCS, MAX_DOCUMENT_BYTES, ORDER_MAX_AGE, ORDER_MAX_AHEAD, Refused } from "./kinds.mjs";

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

/**
 * Refuse a prepared order whose second is not this job's own clock, within
 * ORDER_MAX_AGE behind and ORDER_MAX_AHEAD ahead (lib/kinds.mjs). `now` is
 * the clock of the job that calls this, never a value from an artifact.
 */
export function assertOrderClock(order, now) {
  if (!Number.isSafeInteger(now) || now < 1) throw new Refused("E_CLOCK", "this job's clock is not a Unix second");
  if (!Number.isSafeInteger(order.now)) throw new Refused("E_PREPARED", "the order names no second");
  if (order.now < now - ORDER_MAX_AGE || order.now > now + ORDER_MAX_AHEAD) {
    throw new Refused("E_ORDER_CLOCK", `the order's second (${order.now}) is not within ${ORDER_MAX_AGE} s behind and ${ORDER_MAX_AHEAD} s ahead of this job's clock (${now})`);
  }
}

/** Admit a `prepared-<kind>` directory and return its order. */
export function admitPrepared(dir, kind) {
  const order = admit(dir, PREPARED_FILES, "order.json", (o) => o?.outcome === "prepared", "prepared");
  if (order?.schema !== ORDER_SCHEMA || order.kind !== kind || !["prepared", "closed", "refused"].includes(order.outcome)) {
    throw new Refused("E_ARTIFACT", `the prepared artifact is not an order for ${kind}`);
  }
  return order;
}

/** Admit a signed directory (the key job's own, or the one signedFromLine rebuilt) and return its result. */
export function admitSigned(dir, kind) {
  const result = admit(dir, SIGNED_FILES, "result.json", (r) => r?.outcome === "signed", "signed");
  if (result?.schema !== RESULT_SCHEMA || result.kind !== kind || !["signed", "unchanged", "closed", "not-prepared", "refused"].includes(result.outcome)) {
    throw new Refused("E_ARTIFACT", `the key job's result is not a result for ${kind}`);
  }
  return result;
}

const SIGNATURE = /^[A-Za-z0-9+/]{86}==$/;
const KEY_ID = /^[A-Za-z0-9._-]{1,64}$/;

/**
 * The key job's result, as the one line its job output carries: the result
 * and, when the kind was signed, the two signatures. Never the documents.
 * `outDir` is the directory signPrepared wrote, on the key job's own runner.
 */
export function resultLine(outDir, kind) {
  const result = admitSigned(outDir, kind);
  if (result.outcome !== "signed") return JSON.stringify(result);
  const sig = {};
  for (const doc of DOCS) sig[doc] = readJson(envelopeFile(outDir, doc), "E_ARTIFACT").signatures?.[0]?.sig;
  return JSON.stringify({ ...result, sig });
}

/**
 * The publishing job: the key job's line back into a signed directory. Each
 * signed document is rebuilt from the prepared body and its signature, as
 * canonical JSON; admitSigned and verifyAndInstall then check it exactly as
 * they would check documents the key job had written. An absent line leaves
 * an empty directory, which admitSigned refuses.
 */
export function signedFromLine(line, workDir, signedDir, kind) {
  admitPrepared(workDir, kind);
  fs.rmSync(signedDir, { recursive: true, force: true });
  fs.mkdirSync(signedDir, { recursive: true });
  if (!line) return;
  let parsed;
  try {
    if (line.length > SMALL) throw new Error("long");
    parsed = JSON.parse(line);
  } catch {
    throw new Refused("E_ARTIFACT", "the key job's result is not one short JSON line");
  }
  const { sig, ...result } = parsed && typeof parsed === "object" ? parsed : {};
  if (result.outcome === "signed") {
    const ok = sig && typeof sig === "object" && Object.keys(sig).sort().join() === [...DOCS].sort().join() && DOCS.every((d) => SIGNATURE.test(sig[d] ?? "")) && KEY_ID.test(result.key_id ?? "");
    if (!ok) throw new Refused("E_ARTIFACT", "the key job's result does not carry one signature per document by a named key");
    for (const doc of DOCS) {
      const body = readJson(bodyFile(workDir, doc), "E_ARTIFACT");
      fs.writeFileSync(envelopeFile(signedDir, doc), documentBytes({ signed: body, signatures: [{ key_id: result.key_id, sig: sig[doc] }] }));
    }
  } else if (sig !== undefined) {
    throw new Refused("E_ARTIFACT", "the key job's result carries signatures for a kind it did not sign");
  }
  writeJson(path.join(signedDir, "result.json"), result);
}
