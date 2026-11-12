// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// Sign one kind: an answer from the service in, two signed documents and a
// state file out, or a refusal that leaves the data directory untouched.
//
// The order is the point.
//
//   1. trust.json is verified under the compiled roots, and the key in the
//      job must be the kind's current key (lib/trust.mjs, lib/signer.mjs).
//      This comes first so that a misplaced key is a failed run at once and
//      not six hours later.
//   2. The answer is read strictly and held to its schema (lib/export.mjs).
//   3. An unchanged kind signed less than six hours ago is left alone.
//   4. The withdrawn rows are the answer's plus every row signed last time
//      that the answer dropped without a lift (lib/carry.mjs).
//   5. `issued_at` = `serial` = this machine's clock, which must be later
//      than every serial signed before; `expires_at` is seven days on.
//   6. Both documents are checked by the specification's checker BEFORE a
//      key touches them, and neither may exceed 1,048,576 bytes.
//   7. Both are signed with the current key, each under its own domain.
//   8. What was signed is verified with the public half from trust.json,
//      twice: by the vendored signing code and by the specification's own
//      verifier, which also runs the schema and the rules once more over the
//      exact bytes about to be published.
//   9. Only then are the three files written.
//
// This module reaches no network and starts no process but the checker.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { jcs } from "../vendor/astra-registry/tools/lib/canonical.mjs";
import { verifyEnvelope } from "../vendor/astra-registry/bot/lib/sign.mjs";
import { carryRows } from "./carry.mjs";
import { checkDocument, describe } from "./checker.mjs";
import { readExport } from "./export.mjs";
import { assertKind, DOCS, DOCUMENT_LIFE, documentPath, domainOf, MAX_DOCUMENT_BYTES, Refused, statePath } from "./kinds.mjs";
import { currentSigner, sign } from "./signer.mjs";
import { readPrevious, readState, stateOf, unchanged } from "./state.mjs";
import { publicKeyOf } from "./trust.mjs";

/** The bytes of a document as published: RFC 8785 canonical JSON of the whole envelope. */
export const documentBytes = (envelope) => Buffer.from(jcs(envelope), "utf8");

/** A signature of the right length and no meaning, for measuring and checking a document before it is signed. */
const UNSIGNED = "A".repeat(86) + "==";

/** The two `signed` bodies for one second. */
export function buildBodies({ kind, exportDoc, rows, now }) {
  const head = (doc) => ({ schema: domainOf(kind, doc), serial: now, issued_at: now, expires_at: now + DOCUMENT_LIFE });
  return {
    index: { ...head("index"), entries: exportDoc.entries },
    withdrawn: { ...head("withdrawn"), rows, lifts: exportDoc.withdrawn.lifts },
  };
}

/**
 * @param {{kind: string, exportFile: string, dataDir: string, trust: object, secret: string|undefined, now: number, tmpDir?: string}} o
 *   `trust` is what lib/trust.mjs `loadTrust` returned.
 * @returns {{kind: string, outcome: "signed"|"unchanged", issued_at: number, key_id: string, carried: number, bytes?: {index: number, withdrawn: number}}}
 * @throws {Refused} and writes nothing
 */
export function signKind({ kind, exportFile, dataDir, trust, secret, now, tmpDir = os.tmpdir() }) {
  assertKind(kind);
  if (!Number.isSafeInteger(now) || now < 1) throw new Refused("E_CLOCK", "the clock is not a Unix second");

  const kindKeys = trust.kindKeys(kind);
  const signer = currentSigner({ secret, kind, kindKeys, now });
  const exportDoc = readExport({ file: exportFile, kind });

  const state = readState(dataDir, kind);
  const previous = { index: readPrevious(dataDir, kind, "index"), withdrawn: readPrevious(dataDir, kind, "withdrawn") };
  if (unchanged({ state, exportDoc, keyId: signer.key_id, now })) {
    return { kind, outcome: "unchanged", issued_at: state.issued_at, key_id: state.key_id, carried: state.carried ?? 0 };
  }

  const floor = Math.max(state?.issued_at ?? 0, previous.index?.serial ?? 0, previous.withdrawn?.serial ?? 0);
  if (!(now > floor)) {
    throw new Refused("E_SERIAL_BACK", `the clock (${now}) is not later than the serial signed last for ${kind} (${floor}); a serial never goes back`);
  }

  const { rows, carried } = carryRows({ previousRows: previous.withdrawn?.rows ?? [], rows: exportDoc.withdrawn.rows, lifts: exportDoc.withdrawn.lifts });
  const bodies = buildBodies({ kind, exportDoc, rows, now });

  const scratch = fs.mkdtempSync(path.join(tmpDir, `sign-${kind}-`));
  try {
    const files = {};
    // before the key: size, schema, every semantic and pairing rule
    for (const doc of DOCS) {
      let unsigned;
      try {
        unsigned = documentBytes({ signed: bodies[doc], signatures: [{ key_id: signer.key_id, sig: UNSIGNED }] });
      } catch (e) {
        throw new Refused("E_DOCUMENT_REFUSED", `${kind} ${doc} cannot be written as canonical JSON (${String(e.message).slice(0, 200)})`);
      }
      if (unsigned.length > MAX_DOCUMENT_BYTES) {
        throw new Refused("E_DOCUMENT_SIZE", `${kind} ${doc} would be ${unsigned.length} bytes, over ${MAX_DOCUMENT_BYTES}; it is not signed`);
      }
      files[doc] = path.join(scratch, `${doc}.json`);
      fs.writeFileSync(files[doc], unsigned);
      const verdict = checkDocument({ file: files[doc], kind, doc, now });
      if (!verdict.ok) throw new Refused("E_DOCUMENT_REFUSED", `${kind} ${doc} is ${describe(verdict)}; the kind is not signed`);
    }
    // the key, then the proof that what it produced verifies
    const published = {};
    for (const doc of DOCS) {
      const envelope = sign({ domain: domainOf(kind, doc), signed: bodies[doc], signer });
      const own = verifyEnvelope(envelope, domainOf(kind, doc), [{ key_id: kindKeys.current.key_id, publicKey: publicKeyOf(kindKeys.current) }]);
      if (!own.ok) throw new Refused("E_SELF_VERIFY", `${kind} ${doc} does not verify under ${kindKeys.current.key_id}`);
      published[doc] = documentBytes(envelope);
      fs.writeFileSync(files[doc], published[doc]);
      const verdict = checkDocument({ file: files[doc], kind, doc, now, trust: trust.signed });
      if (!verdict.ok || verdict.verified_by.length !== 1 || verdict.verified_by[0] !== kindKeys.current.key_id) {
        throw new Refused("E_SELF_VERIFY", `${kind} ${doc} as signed is ${describe(verdict)} to the specification's verifier`);
      }
    }
    // one state: all three files, or none
    const state2 = stateOf({ kind, exportDoc, issuedAt: now, keyId: signer.key_id, carried: carried.length });
    for (const doc of DOCS) {
      const dest = path.join(dataDir, documentPath(kind, doc));
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      fs.writeFileSync(dest, published[doc]);
    }
    const stateFile = path.join(dataDir, statePath(kind));
    fs.mkdirSync(path.dirname(stateFile), { recursive: true });
    fs.writeFileSync(stateFile, `${JSON.stringify(state2, null, 2)}\n`);
    return {
      kind,
      outcome: "signed",
      issued_at: now,
      key_id: signer.key_id,
      carried: carried.length,
      bytes: { index: published.index.length, withdrawn: published.withdrawn.length },
    };
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
}
