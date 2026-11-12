// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// Sign one kind, in three stages that run as three steps of the workflow.
//
//   prepareKind       no key. Reads the service's answer and the kind's last
//                     signed pair, and writes the two UNSIGNED bodies and an
//                     order into the work directory. Everything that parses
//                     bytes somebody else chose happens here, the Python
//                     checker included.
//   signPrepared      (lib/keystep.mjs) the key. Node only: it starts no process and reads
//                     nothing but the order, the two prepared bodies and
//                     trust.json. It writes the two signed envelopes.
//   verifyAndInstall  no key. Proves that what was signed is what was
//                     prepared and that it verifies, twice (this repository's
//                     signing code, then the specification's verifier), and
//                     only then writes the three files into the data
//                     directory.
//
// Why three: a process started by the step that holds the key can read that
// step's environment. So the step with the key runs one Node file that starts
// nothing, and every check that needs the Python checker runs before it or
// after it.
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
// Files in the work directory:
//   order.json                     what was prepared, and the facts the key step needs
//   index.signed.json, withdrawn.signed.json   the bodies, as RFC 8785 JSON
//   result.json                    what the key step did
//   index.json, withdrawn.json     the signed envelopes

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
import { bodyFile, documentBytes, envelopeFile, ORDER_SCHEMA, readJson, RESULT_SCHEMA, UNSIGNED, writeJson } from "./workdir.mjs";

export { signPrepared } from "./keystep.mjs";
export { documentBytes, ORDER_SCHEMA, RESULT_SCHEMA } from "./workdir.mjs";

/** The two `signed` bodies for one second. */
export function buildBodies({ kind, exportDoc, rows, now }) {
  const head = (doc) => ({ schema: domainOf(kind, doc), serial: now, issued_at: now, expires_at: now + DOCUMENT_LIFE });
  return {
    index: { ...head("index"), entries: exportDoc.entries },
    withdrawn: { ...head("withdrawn"), rows, lifts: exportDoc.withdrawn.lifts },
  };
}

/**
 * Stage 1, no key.
 *
 * @param {{kind: string, exportFile: string, dataDir: string, trust: object, now: number, workDir: string, everHeld: boolean}} o
 * @returns {object} the order, also written to <workDir>/order.json
 * @throws {Refused} and writes no order
 */
export function prepareKind({ kind, exportFile, dataDir, trust, now, workDir, everHeld }) {
  assertKind(kind);
  if (!Number.isSafeInteger(now) || now < 1) throw new Refused("E_CLOCK", "the clock is not a Unix second");
  const kindKeys = trust.kindKeys(kind);
  const exportDoc = readExport({ file: exportFile, kind, now });
  const previous = readPrevious({ dataDir, kind, kindKeys, everHeld });
  const floor = previous?.serial ?? 0;
  if (!(now > floor)) throw new Refused("E_SERIAL_BACK", `the clock (${now}) is not later than the serial signed last for ${kind} (${floor}); a serial never goes back`);

  const { rows, carried } = carryRows({ previousRows: previous?.withdrawn.rows ?? [], rows: exportDoc.withdrawn.rows, lifts: exportDoc.withdrawn.lifts });
  const bodies = buildBodies({ kind, exportDoc, rows, now });
  // measured and checked under the longer of the kind's two key ids, so that whichever key signs, the bound holds
  const keyId = [kindKeys.current.key_id, kindKeys.next.key_id].sort((a, b) => b.length - a.length)[0];

  fs.mkdirSync(workDir, { recursive: true });
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
    const probe = path.join(workDir, `${doc}.unsigned.json`);
    fs.writeFileSync(probe, unsigned);
    const verdict = checkDocument({ file: probe, kind, doc, now });
    fs.rmSync(probe);
    if (!verdict.ok) throw new Refused("E_DOCUMENT_REFUSED", `the specification's checker refuses ${kind} ${doc}; the kind is not signed`, `${doc}/${whereFailed(verdict)}`);
  }
  for (const doc of DOCS) fs.writeFileSync(bodyFile(workDir, doc), jcs(bodies[doc]));
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
 * @returns {{kind: string, outcome: "signed"|"unchanged", issued_at: number, key_id: string, role: string, carried: number, bytes?: object}}
 * @throws {Refused} and writes nothing into the data directory
 */
export function verifyAndInstall({ kind, workDir, dataDir, trust, verify = verifyEnvelope, check = checkDocument }) {
  assertKind(kind);
  const order = readJson(path.join(workDir, "order.json"), "E_PREPARED");
  const result = readJson(path.join(workDir, "result.json"), "E_PREPARED");
  if (order.schema !== ORDER_SCHEMA || order.kind !== kind || result.schema !== RESULT_SCHEMA || result.kind !== kind) {
    throw new Refused("E_PREPARED", `the work directory is not ${kind}'s`);
  }
  const kindKeys = trust.kindKeys(kind);
  const row = ["current", "next"].map((r) => kindKeys[r]).find((k) => k.key_id === result.key_id);
  if (!row) throw new Refused("E_SELF_VERIFY", `the key step names a key that is not ${kind}'s`);
  const role = row.role;
  if (result.outcome === "unchanged") {
    if (order.unchanged_under !== result.key_id) throw new Refused("E_PREPARED", "the key step left a kind unsigned that the order did not call unchanged");
    return { kind, outcome: "unchanged", issued_at: order.last_issued_at, key_id: result.key_id, role, carried: order.last_carried };
  }
  if (result.outcome !== "signed") throw new Refused("E_PREPARED", "the key step left no result");

  const published = {};
  for (const doc of DOCS) {
    const bytes = fs.readFileSync(envelopeFile(workDir, doc));
    if (bytes.length > MAX_DOCUMENT_BYTES) throw new Refused("E_DOCUMENT_SIZE", `${kind} ${doc} is over ${MAX_DOCUMENT_BYTES} bytes`, doc);
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
      throw new Refused("E_SELF_VERIFY", `the signed ${doc} does not carry exactly one signature, by the key the key step named`, doc);
    }
    const own = verify(envelope, domainOf(kind, doc), [{ key_id: row.key_id, publicKey: publicKeyOf(row) }]);
    if (!own.ok) throw new Refused("E_SELF_VERIFY_NODE", `${kind} ${doc} does not verify under ${row.key_id}`, doc);
    const verdict = check({ file: envelopeFile(workDir, doc), kind, doc, now: order.now, trust: trust.signed });
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
