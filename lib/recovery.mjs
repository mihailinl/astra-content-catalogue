// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// recovery.json: the one way to make the signer build on a pair it cannot
// verify (README, "When a kind cannot be signed over what data holds").
//
// The signer takes a kind's rows, serial and last key from the pair on
// `data` only after verifying the pair under the kind's keys. When both keys
// a pair was signed with have left trust.json, nothing verifies it, and the
// alternative to refusing for ever would be to start the kind with no rows.
// Instead an administrator names the exact pair, by the SHA-256 of its two
// files, in recovery.json on `main`. `main` is updated by administrators
// only, so an entry is a reviewed statement by a person: "these bytes are
// the kind's last pair". The signer then carries that pair's rows and keeps
// its serial as the floor, and signs the kind again; from then on the pair
// on `data` verifies and the entry matches nothing.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { KINDS, Refused } from "./kinds.mjs";

export const RECOVERY_SCHEMA = "astra.content.signer-recovery/1";
export const RECOVERY_FILE = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "recovery.json");
const SHA256 = /^[0-9a-f]{64}$/;

/** The accepted pairs: [{kind, index_sha256, withdrawn_sha256}]. A file that is not exactly that is a refusal, never an empty list. */
export function loadRecovery(file = RECOVERY_FILE) {
  let doc;
  try {
    doc = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    throw new Refused("E_RECOVERY", "recovery.json is absent or not JSON");
  }
  const ok =
    doc?.schema === RECOVERY_SCHEMA &&
    Array.isArray(doc.accept) &&
    doc.accept.every((a) => KINDS.includes(a?.kind) && SHA256.test(a.index_sha256 ?? "") && SHA256.test(a.withdrawn_sha256 ?? ""));
  if (!ok) throw new Refused("E_RECOVERY", "recovery.json is not a recovery list");
  return doc.accept.map(({ kind, index_sha256, withdrawn_sha256 }) => ({ kind, index_sha256, withdrawn_sha256 }));
}
