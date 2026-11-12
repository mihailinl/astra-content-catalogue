// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// What the signer remembers about a kind between runs, all of it on the
// `data` branch: the two documents it signed last, and state/<kind>.json.
//
// state/<kind>.json:
//   { "schema": "astra.content.signer-state/1", "kind": K,
//     "state_sha256": the answer's, as signed last (never recomputed here),
//     "issued_at": the second both documents were signed at,
//     "key_id": the key that signed them,
//     "carried": how many rows the last signing kept that the answer omitted }

import fs from "node:fs";
import path from "node:path";

import { documentPath, RESIGN_AFTER, Refused, statePath } from "./kinds.mjs";

export const STATE_SCHEMA = "astra.content.signer-state/1";

function readJson(file, what) {
  if (!fs.existsSync(file)) return null;
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    throw new Refused("E_PREVIOUS_UNREADABLE", `${what} on the data branch is not JSON; nothing is signed over it`);
  }
}

/** state/<kind>.json, or null before the kind's first signing. */
export function readState(dataDir, kind) {
  const s = readJson(path.join(dataDir, statePath(kind)), `state/${kind}.json`);
  if (s === null) return null;
  if (s?.schema !== STATE_SCHEMA || s.kind !== kind || !Number.isSafeInteger(s.issued_at) || typeof s.state_sha256 !== "string") {
    throw new Refused("E_PREVIOUS_UNREADABLE", `state/${kind}.json is not a signer state for ${kind}`);
  }
  return s;
}

/** The `signed` body of the document signed last, or null before the first. */
export function readPrevious(dataDir, kind, doc) {
  const env = readJson(path.join(dataDir, documentPath(kind, doc)), `${kind}/${doc}.json`);
  if (env === null) return null;
  const s = env?.signed;
  const list = doc === "index" ? s?.entries : s?.rows;
  if (!Number.isSafeInteger(s?.serial) || !Array.isArray(list)) {
    throw new Refused("E_PREVIOUS_UNREADABLE", `${kind}/${doc}.json on the data branch is not a ${doc} document; nothing is signed over it`);
  }
  return s;
}

/**
 * Whether this run leaves the kind as it is: the answer is the one signed
 * last, by the key the job holds now, less than six hours ago.
 */
export function unchanged({ state, exportDoc, keyId, now }) {
  return (
    state !== null &&
    state.state_sha256 === exportDoc.state_sha256 &&
    state.key_id === keyId &&
    now >= state.issued_at &&
    now - state.issued_at < RESIGN_AFTER
  );
}

export function stateOf({ kind, exportDoc, issuedAt, keyId, carried }) {
  return { schema: STATE_SCHEMA, kind, state_sha256: exportDoc.state_sha256, issued_at: issuedAt, key_id: keyId, carried };
}
