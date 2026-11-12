// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// Sign one kind, in three stages that run as three JOBS of the workflow,
// each on a runner of its own.
//
//   prepareKind       no key. Reads the service's answer and the kind's last
//                     signed pair, and writes the prepared artifact: the two
//                     UNSIGNED bodies, an order, and the trust.json it used.
//                     Everything that parses bytes somebody else chose
//                     happens here, the Python checker included.
//   signPrepared      (lib/keystep.mjs) the key. A fresh runner whose token
//                     has no permission at all. Node only: it starts no
//                     process and reads nothing but the prepared artifact.
//                     It refuses an order whose second is not its own clock,
//                     and hands on the result and two signatures as a job
//                     output, never a signed document as an artifact.
//   verifyAndInstall  no key. Proves that what was signed is what was
//                     prepared and that it verifies, twice (this repository's
//                     signing code, then the specification's verifier), that
//                     the order's second is its own clock and later than the
//                     serial it verified on `data`, that `data` has not moved
//                     since the kind was prepared, and only then writes the
//                     three files into the data directory.
//
// Why three jobs: steps of one job share a runner, so code that ran before
// the key step could leave something behind for it. The key job starts from
// a fresh machine and a fresh checkout, and the only thing that reaches it
// from the jobs that handled the service's bytes is one artifact of four
// named files, which it admits before reading (lib/workdir.mjs).
//
// The order of checks in prepareKind is the point.
//
//   1. trust.json is verified under the compiled roots (the caller).
//   2. The answer is read strictly, held to its schema, and must be fresh
//      (lib/export.mjs).
//   3. The kind's last pair on `data` is verified under the kind's keys
//      before anything is taken from it (lib/state.mjs).
//   4. This machine's clock must be later than the serial of that pair.
//   5. The withdrawn rows are the answer's plus every row of the verified
//      last document that the answer dropped without a lift (lib/carry.mjs).
//   6. `issued_at` = `serial` = the clock; `expires_at` is seven days on.
//   7. Neither document may exceed 1,048,576 bytes, and both are checked by
//      the specification's checker, before a key is anywhere near them.
//
// The files of the two artifacts are listed in lib/workdir.mjs.

import fs from "node:fs";
import path from "node:path";

import { jcs } from "../vendor/astra-registry/tools/lib/canonical.mjs";
import { verifyEnvelope } from "../vendor/astra-registry/bot/lib/sign.mjs";
import { assertKind, DOCS, DOCUMENT_LIFE, documentPath, domainOf, MAX_DOCUMENT_BYTES, Refused, statePath } from "./kinds.mjs";
import { carryRows } from "./carry.mjs";
import { checkDocument, whereFailed } from "./checker.mjs";
import { readExport } from "./export.mjs";
import { readPrevious, refuseSymlinks, stateOf, unchanged } from "./state.mjs";
import { publicKeyOf } from "./trust.mjs";
import { admitPrepared, admitSigned, assertOrderClock, bodyFile, documentBytes, envelopeFile, ORDER_SCHEMA, UNSIGNED, writeJson } from "./workdir.mjs";

export { signPrepared } from "./keystep.mjs";
export { documentBytes, ORDER_SCHEMA, RESULT_SCHEMA } from "./workdir.mjs";

/** The order a kind leaves when it was not prepared: `closed` (the door was not open) or `refused`. */
export function leaveOrder(workDir, kind, outcome) {
  fs.rmSync(workDir, { recursive: true, force: true });
  fs.mkdirSync(workDir, { recursive: true });
  writeJson(path.join(workDir, "order.json"), { schema: ORDER_SCHEMA, kind, outcome });
}

/** The two `signed` bodies for one second. */
export function buildBodies({ kind, exportDoc, rows, now }) {
  const head = (doc) => ({ schema: domainOf(kind, doc), serial: now, issued_at: now, expires_at: now + DOCUMENT_LIFE });
  return {
    index: { ...head("index"), entries: exportDoc.entries },
    withdrawn: { ...head("withdrawn"), rows, lifts: exportDoc.withdrawn.lifts },
  };
}

/**
 * Both bodies against the size bound and the specification's checker, as
 * documents carrying a signature of the right length and no meaning.
 * `dir` holds the probe files while they are checked, and nothing after.
 */
function checkBodies({ kind, bodies, now, keyId, dir }) {
  for (const doc of DOCS) {
    let unsigned;
    try {
      unsigned = documentBytes({ signed: bodies[doc], signatures: [{ key_id: keyId, sig: UNSIGNED }] });
    } catch {
      throw new Refused("E_DOCUMENT_REFUSED", `${kind} ${doc} cannot be written as canonical JSON`, `${doc}/canonical`);
    }
    if (unsigned.length > MAX_DOCUMENT_BYTES) {
      throw new Refused("E_DOCUMENT_SIZE", `${kind} ${doc} would be ${unsigned.length} bytes, over ${MAX_DOCUMENT_BYTES}; it is not signed`, doc);
    }
    const probe = path.join(dir, `${doc}.unsigned.json`);
    fs.writeFileSync(probe, unsigned);
    let verdict;
    try {
      verdict = checkDocument({ file: probe, kind, doc, now });
    } finally {
      fs.rmSync(probe, { force: true });
    }
    if (!verdict.ok) throw new Refused("E_DOCUMENT_REFUSED", `the specification's checker refuses ${kind} ${doc}; the kind is not signed`, `${doc}/${whereFailed(verdict)}`);
  }
}

/**
 * Whether an answer may leave the job that fetched it: read strictly, held to
 * the export schema and to freshness, and its entries, rows and lifts held to
 * the kind's document schemas and rules. An answer that fails is never
 * written where another job, or an artifact, could carry it: a member the
 * schemas do not name, anywhere in it, stops here.
 *
 * @param {{file: string, kind: string, now: number, dir: string}} o  `dir` is a scratch directory
 * @throws {Refused}
 */
export function admitAnswer({ file, kind, now, dir }) {
  const exportDoc = readExport({ file, kind, now });
  const bodies = buildBodies({ kind, exportDoc, rows: exportDoc.withdrawn.rows, now });
  checkBodies({ kind, bodies, now, keyId: `astra-${kind}-probe`, dir });
}

/**
 * Stage 1, no key.
 *
 * @param {{kind: string, exportFile: string, dataDir: string, trust: object, now: number, workDir: string, everHeld: boolean}} o
 * @returns {object} the order, also written to <workDir>/order.json
 * @throws {Refused} and writes no order
 */
export function prepareKind({ kind, exportFile, dataDir, trust, now, workDir, everHeld, accepted = [] }) {
  assertKind(kind);
  if (!Number.isSafeInteger(now) || now < 1) throw new Refused("E_CLOCK", "the clock is not a Unix second");
  const kindKeys = trust.kindKeys(kind);
  const exportDoc = readExport({ file: exportFile, kind, now });
  const previous = readPrevious({ dataDir, kind, kindKeys, everHeld, accepted });
  const floor = previous?.serial ?? 0;
  if (!(now > floor)) throw new Refused("E_SERIAL_BACK", `the clock (${now}) is not later than the serial signed last for ${kind} (${floor}); a serial never goes back`);

  const { rows, carried } = carryRows({ previousRows: previous?.withdrawn.rows ?? [], rows: exportDoc.withdrawn.rows, lifts: exportDoc.withdrawn.lifts });
  const bodies = buildBodies({ kind, exportDoc, rows, now });
  // measured and checked under the longer of the kind's two key ids, so that whichever key signs, the bound holds
  const keyId = [kindKeys.current.key_id, kindKeys.next.key_id].sort((a, b) => b.length - a.length)[0];

  fs.mkdirSync(workDir, { recursive: true });
  checkBodies({ kind, bodies, now, keyId, dir: workDir });
  for (const doc of DOCS) fs.writeFileSync(bodyFile(workDir, doc), jcs(bodies[doc]));
  fs.writeFileSync(path.join(workDir, "trust.json"), JSON.stringify(trust.doc));
  const order = {
    schema: ORDER_SCHEMA,
    kind,
    outcome: "prepared",
    now,
    state_sha256: exportDoc.state_sha256,
    carried: carried.length,
    last_key_id: previous?.keyId ?? null,
    last_issued_at: previous?.serial ?? null,
    last_carried: previous?.state.carried ?? 0,
    // the key under which this answer is already signed and fresh; any other key signs it again
    unchanged_under: unchanged({ previous, exportDoc, now }) ? previous.keyId : null,
  };
  writeJson(path.join(workDir, "order.json"), order);
  return order;
}

/**
 * Stage 3, no key. `verify` and `check` are the two verifiers; a test passes
 * its own to prove that each one alone refuses.
 *
 * @param {{kind: string, workDir: string, signedDir: string, dataDir: string, trust: object, everHeld: boolean, now: number}} o
 *   `workDir` is the prepared artifact and `signedDir` the key job's result;
 *   `trust` is trust.json read afresh by this job, not the copy the key job
 *   used; `now` is this job's own clock. The order's second must be within
 *   the window of it, and later than the serial of the pair this job itself
 *   verified on `data`: the order's word for either is not taken.
 * @returns {{kind: string, outcome: "signed"|"unchanged"|"closed"|"not-prepared"|"not-signed", issued_at?: number, key_id?: string, role?: string, carried: number, bytes?: object}}
 * @throws {Refused} and writes nothing into the data directory
 */
export function verifyAndInstall({ kind, workDir, signedDir, dataDir, trust, everHeld, now, accepted = [], verify = verifyEnvelope, check = checkDocument }) {
  assertKind(kind);
  const order = admitPrepared(workDir, kind);
  const result = admitSigned(signedDir, kind);
  // a kind that was not prepared, or not signed, failed in its own job; here there is nothing to do
  if (order.outcome === "refused") return { kind, outcome: "not-prepared", carried: 0 };
  if (order.outcome === "closed") {
    if (result.outcome !== "closed") throw new Refused("E_PREPARED", "the key job did something for a kind whose door was not open");
    return { kind, outcome: "closed", carried: 0 };
  }
  if (result.outcome === "refused") return { kind, outcome: "not-signed", carried: 0 };
  if (result.outcome !== "signed" && result.outcome !== "unchanged") throw new Refused("E_PREPARED", "the key job left no result for a prepared kind");
  assertOrderClock(order, now);

  const kindKeys = trust.kindKeys(kind);
  const row = ["current", "next"].map((r) => kindKeys[r]).find((k) => k.key_id === result.key_id);
  if (!row) throw new Refused("E_SELF_VERIFY", `the key job names a key that is not ${kind}'s`);
  const role = row.role;
  // `data` as it is now must be the `data` the kind was prepared against
  const previous = readPrevious({ dataDir, kind, kindKeys, everHeld, accepted });
  if ((previous?.serial ?? null) !== order.last_issued_at || (previous?.keyId ?? null) !== order.last_key_id) {
    throw new Refused("E_DATA_MOVED", `the data branch holds another pair for ${kind} than the one the kind was prepared against`);
  }
  // the floor is the serial this job verified, not the one the order names
  if (previous !== null && !(order.now > previous.serial)) {
    throw new Refused("E_SERIAL_BACK", `the order's second (${order.now}) is not later than the serial signed last for ${kind} (${previous.serial}); a serial never goes back`);
  }
  if (result.outcome === "unchanged") {
    if (order.unchanged_under === null || order.unchanged_under !== result.key_id) throw new Refused("E_PREPARED", "the key job left a kind unsigned that the order did not call unchanged");
    return { kind, outcome: "unchanged", issued_at: order.last_issued_at, key_id: result.key_id, role, carried: order.last_carried };
  }

  const published = {};
  for (const doc of DOCS) {
    const bytes = fs.readFileSync(envelopeFile(signedDir, doc));
    let envelope;
    try {
      envelope = JSON.parse(bytes.toString("utf8"));
    } catch {
      throw new Refused("E_SELF_VERIFY", "a signed document is not JSON", doc);
    }
    if (jcs(envelope) !== bytes.toString("utf8") || jcs(envelope.signed) !== fs.readFileSync(bodyFile(workDir, doc), "utf8")) {
      throw new Refused("E_SIGNED_OTHER", `the signed ${doc} is not the body that was prepared and checked`, doc);
    }
    if (!Array.isArray(envelope.signatures) || envelope.signatures.length !== 1 || envelope.signatures[0]?.key_id !== result.key_id) {
      throw new Refused("E_SELF_VERIFY", `the signed ${doc} does not carry exactly one signature, by the key the key job named`, doc);
    }
    const own = verify(envelope, domainOf(kind, doc), [{ key_id: row.key_id, publicKey: publicKeyOf(row) }]);
    if (!own.ok) throw new Refused("E_SELF_VERIFY_NODE", `${kind} ${doc} does not verify under ${row.key_id}`, doc);
    const verdict = check({ file: envelopeFile(signedDir, doc), kind, doc, now: order.now, trust: trust.signed });
    if (!verdict.ok || verdict.verified_by.length !== 1 || verdict.verified_by[0] !== row.key_id) {
      throw new Refused("E_SELF_VERIFY_SPEC", `${kind} ${doc} as signed does not pass the specification's verifier`, `${doc}/${whereFailed(verdict)}`);
    }
    published[doc] = bytes;
  }
  // one state: all three files, or none
  refuseSymlinks(dataDir);
  for (const doc of DOCS) {
    const dest = path.join(dataDir, documentPath(kind, doc));
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.writeFileSync(dest, published[doc]);
  }
  const stateFile = path.join(dataDir, statePath(kind));
  fs.mkdirSync(path.dirname(stateFile), { recursive: true });
  writeJson(stateFile, stateOf({ kind, stateSha256: order.state_sha256, issuedAt: order.now, keyId: result.key_id, carried: order.carried }));
  return { kind, outcome: "signed", issued_at: order.now, key_id: result.key_id, role, carried: order.carried, bytes: { index: published.index.length, withdrawn: published.withdrawn.length } };
}
