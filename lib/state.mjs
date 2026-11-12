// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// What the signer knows about a kind from before: the two documents it signed
// last and state/<kind>.json, all on the `data` branch.
//
// `data` is a branch somebody could have written, so nothing on it is used
// until it is proven. The two documents are verified under the kind's keys in
// the root-signed trust.json, and everything the signer builds on comes from
// those verified envelopes: the rows to carry, the serial floor, and which
// key signed last. state/<kind>.json is a cache beside them:
//
//   { "schema": "astra.content.signer-state/1", "kind": K,
//     "state_sha256": the answer's, as signed last (never recomputed here),
//     "issued_at": the second both documents were signed at,
//     "key_id": the key that signed them,
//     "carried": how many rows the last signing kept that the answer omitted }
//
// Its `issued_at` and `key_id` must equal what the documents prove, or the
// kind is not signed. Only `state_sha256` and `carried` are taken on its
// word, and all they decide is whether a kind is left alone for up to six
// hours and whether the run fails for a kept row.
//
// One exception to "proven": a pair that an administrator has named, by the
// SHA-256 of its two files, in recovery.json on `main` (lib/recovery.mjs).
// It is built on although no key verifies it.
//
// A kind with no documents is new only if `data` never held it. The caller
// says so (`everHeld`, from the branch's first-parent history; lib/data.mjs):
// a pair that was there and is gone is a refusal, not a first signing, or
// deleting two files would drop every withdrawn row of the kind.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { verifyEnvelope } from "../vendor/astra-registry/bot/lib/sign.mjs";
import { DOCS, documentPath, domainOf, MAX_DOCUMENT_BYTES, RESIGN_AFTER, Refused, statePath } from "./kinds.mjs";
import { publicKeyOf } from "./trust.mjs";

export const STATE_SCHEMA = "astra.content.signer-state/1";

/** Refuse any symbolic link at or under registry/ and state/: a link would make a read or a write land outside the branch. */
export function refuseSymlinks(dataDir) {
  const walk = (rel) => {
    const p = path.join(dataDir, rel);
    let st;
    try {
      st = fs.lstatSync(p);
    } catch {
      return;
    }
    if (st.isSymbolicLink()) throw new Refused("E_DATA_SYMLINK", "a symbolic link on the data branch", rel);
    if (st.isDirectory()) for (const name of fs.readdirSync(p)) walk(`${rel}/${name}`);
    else if (!st.isFile()) throw new Refused("E_DATA_SYMLINK", "something on the data branch is neither a file nor a directory", rel);
  };
  for (const top of ["registry", "state"]) walk(top);
}

const sha256 = (file) => crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");

function readVerified(dataDir, kind, doc, kindKeys, waived) {
  const rel = documentPath(kind, doc);
  const file = path.join(dataDir, rel);
  if (fs.statSync(file).size > MAX_DOCUMENT_BYTES) throw new Refused("E_PREVIOUS_UNVERIFIED", "a document on the data branch is over the size bound", rel);
  let env;
  try {
    env = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    throw new Refused("E_PREVIOUS_UNVERIFIED", "a document on the data branch is not JSON", rel);
  }
  const keys = ["current", "next"].map((role) => ({ key_id: kindKeys[role].key_id, publicKey: publicKeyOf(kindKeys[role]) }));
  const v = verifyEnvelope(env, domainOf(kind, doc), keys);
  if (!v.ok && !waived) throw new Refused("E_PREVIOUS_UNVERIFIED", "a document on the data branch is not signed by a key of its kind", rel);
  const s = env.signed;
  const list = doc === "index" ? s?.entries : s?.rows;
  if (!Number.isSafeInteger(s?.serial) || s.serial !== s.issued_at || !Array.isArray(list)) {
    throw new Refused("E_PREVIOUS_SHAPE", "a document on the data branch is signed and is not a content document of its kind", rel);
  }
  return { signed: s, keyId: v.ok ? v.key_id : null };
}

/**
 * The kind's last signed pair, proven, or null when `data` has never held the kind.
 *
 * @param {{dataDir: string, kind: string, kindKeys: {current: object, next: object}, everHeld: boolean, accepted?: object[]}} o
 *   `accepted` is recovery.json's list (lib/recovery.mjs).
 * @returns {null | {index: object, withdrawn: object, serial: number, keyId: string|null, state: object}}
 *   `keyId` is null for a pair taken on an administrator's word.
 */
export function readPrevious({ dataDir, kind, kindKeys, everHeld, accepted = [] }) {
  refuseSymlinks(dataDir);
  const files = [...DOCS.map((d) => documentPath(kind, d)), statePath(kind)];
  const present = files.filter((f) => fs.existsSync(path.join(dataDir, f)));
  if (present.length === 0) {
    if (everHeld) throw new Refused("E_PREVIOUS_MISSING", `the data branch held ${kind} before and holds none of its files now`);
    return null;
  }
  if (present.length !== files.length) {
    throw new Refused("E_PREVIOUS_MISSING", `the data branch holds only part of ${kind}`, files.find((f) => !present.includes(f)));
  }
  const digest = Object.fromEntries(DOCS.map((d) => [d, sha256(path.join(dataDir, documentPath(kind, d)))]));
  const waived = accepted.some((a) => a.kind === kind && a.index_sha256 === digest.index && a.withdrawn_sha256 === digest.withdrawn);
  const index = readVerified(dataDir, kind, "index", kindKeys, waived);
  const withdrawn = readVerified(dataDir, kind, "withdrawn", kindKeys, waived);
  if (index.signed.serial !== withdrawn.signed.serial || index.keyId !== withdrawn.keyId) {
    throw new Refused("E_PREVIOUS_PAIR", `the two documents of ${kind} on the data branch were not signed together`);
  }
  let state;
  try {
    state = JSON.parse(fs.readFileSync(path.join(dataDir, statePath(kind)), "utf8"));
  } catch {
    throw new Refused("E_STATE_MISMATCH", "the state file is not JSON", statePath(kind));
  }
  if (
    state?.schema !== STATE_SCHEMA ||
    state.kind !== kind ||
    state.issued_at !== index.signed.serial ||
    (index.keyId !== null && state.key_id !== index.keyId) ||
    typeof state.state_sha256 !== "string" ||
    !/^[0-9a-f]{64}$/.test(state.state_sha256) ||
    !Number.isSafeInteger(state.carried) ||
    state.carried < 0
  ) {
    throw new Refused("E_STATE_MISMATCH", `state/${kind}.json does not agree with the documents beside it`, statePath(kind));
  }
  return { index: index.signed, withdrawn: withdrawn.signed, serial: index.signed.serial, keyId: index.keyId, state };
}

/** Whether the answer is the one signed last, less than six hours ago. */
export function unchanged({ previous, exportDoc, now }) {
  return previous !== null && previous.state.state_sha256 === exportDoc.state_sha256 && now - previous.serial < RESIGN_AFTER;
}

export function stateOf({ kind, stateSha256, issuedAt, keyId, carried }) {
  return { schema: STATE_SCHEMA, kind, state_sha256: stateSha256, issued_at: issuedAt, key_id: keyId, carried };
}
