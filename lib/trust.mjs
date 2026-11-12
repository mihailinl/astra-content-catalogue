// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// Which key may sign a kind: the `kind_keys` member of the plugin registry's
// root-signed trust.json (AstraPlugins spec/content/trust-kind-keys-v1.md).
//
// trust.json is read from astra-registry and is believed only after it
// verifies under the root keys compiled into the vendored roots.mjs, under the
// domain astra.registry.trust/1, and has not expired. A kind has exactly two
// rows there, `current` and `next`. This repository signs with the current
// key only (lib/signer.mjs); it never holds the next one.
//
// The rules below are the specification's (§2 to §4), and the vendored checker
// applies them again when it verifies what was signed. A defect in a kind's
// rows costs that kind its keys; it is never repaired by choosing one.

import fs from "node:fs";

import { compiledRootKeys } from "../vendor/astra-registry/bot/lib/roots.mjs";
import { publicKeyFromBase64, TRUST_SCHEMA, verifyEnvelope } from "../vendor/astra-registry/bot/lib/sign.mjs";
import { Refused } from "./kinds.mjs";

const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const KEY_ID = /^[a-z0-9][a-z0-9-]{2,63}$/;
const toSeconds = (s) => Math.floor(Date.parse(s) / 1000);

/** The raw 32 bytes of a base64 Ed25519 public key, or null unless it is exactly that, canonically spelt. */
export function rawKey(b64) {
  if (typeof b64 !== "string") return null;
  const raw = Buffer.from(b64, "base64");
  return raw.length === 32 && raw.toString("base64") === b64 ? raw : null;
}

/**
 * The two keys of `kind` out of an already verified trust body.
 * @returns {{current: object, next: object}} each row, plus `notBefore` in Unix seconds
 */
export function kindKeysOf(signed, kind) {
  const all = Array.isArray(signed?.kind_keys) ? signed.kind_keys : null;
  if (!all) throw new Refused("E_TRUST_KIND_KEYS", "trust.json carries no kind_keys");
  const mine = all.filter((k) => k?.kind === kind);
  const roles = mine.map((k) => String(k.role)).sort();
  if (mine.length !== 2 || roles[0] !== "current" || roles[1] !== "next") {
    throw new Refused("E_TRUST_KIND_KEYS", `kind_keys must hold exactly one current and one next key for ${kind}; it holds ${JSON.stringify(roles)}`);
  }
  const out = {};
  for (const k of mine) {
    if (k.alg !== "ed25519") throw new Refused("E_TRUST_KIND_KEYS", `${kind} ${k.role}: alg is not ed25519`);
    if (typeof k.key_id !== "string" || !KEY_ID.test(k.key_id)) throw new Refused("E_TRUST_KIND_KEYS", `${kind} ${k.role}: key_id is not a key id`);
    if (!rawKey(k.public_key)) throw new Refused("E_TRUST_KIND_KEYS", `${k.key_id}: public_key is not base64 of 32 bytes`);
    if (typeof k.not_before !== "string" || !RFC3339.test(k.not_before)) throw new Refused("E_TRUST_KIND_KEYS", `${k.key_id}: not_before is not a time`);
    out[k.role] = { ...k, notBefore: toSeconds(k.not_before) };
  }
  if (!(out.next.notBefore > out.current.notBefore)) {
    throw new Refused("E_TRUST_KIND_KEYS", `${kind}'s next key does not start after its current key`);
  }
  if (out.current.key_id === out.next.key_id || out.current.public_key === out.next.public_key) {
    throw new Refused("E_TRUST_KIND_KEYS", `${kind}'s current and next are the same key`);
  }
  const elsewhere = [...all.filter((k) => k?.kind !== kind), ...(Array.isArray(signed.index_keys) ? signed.index_keys : [])];
  for (const k of [out.current, out.next]) {
    if (elsewhere.some((o) => o?.public_key === k.public_key || o?.key_id === k.key_id)) {
      throw new Refused("E_TRUST_KIND_KEYS", `${k.key_id} is also authorised for something other than ${kind}`);
    }
  }
  return out;
}

/**
 * Read and verify trust.json.
 *
 * @param {{file?: string, doc?: object, now: number, roots?: {keys: object[]}}} o
 *   `roots` is the seam the tests pass throwaway roots through; everything
 *   else gets the compiled set.
 * @returns {{signed: object, signedBy: string, kindKeys: (kind: string) => {current: object, next: object}}}
 */
export function loadTrust({ file, doc, now, roots = compiledRootKeys() }) {
  let trust = doc;
  if (!trust) {
    if (!file || !fs.existsSync(file)) throw new Refused("E_TRUST_ABSENT", `no trust.json at ${file}`);
    try {
      trust = JSON.parse(fs.readFileSync(file, "utf8"));
    } catch {
      throw new Refused("E_TRUST_UNVERIFIED", "trust.json is not JSON");
    }
  }
  if (!roots?.keys?.length) throw new Refused("E_TRUST_UNVERIFIED", "no root keys to verify trust.json with");
  const v = verifyEnvelope(trust, TRUST_SCHEMA, roots.keys);
  if (!v.ok) throw new Refused("E_TRUST_UNVERIFIED", `trust.json is not signed by a root key (${v.reason})`);
  const s = trust.signed;
  if (s?.schema !== TRUST_SCHEMA) throw new Refused("E_TRUST_UNVERIFIED", "trust.json's schema is not the trust schema");
  if (typeof s.expires_at !== "string" || !(toSeconds(s.expires_at) > now)) {
    throw new Refused("E_TRUST_EXPIRED", "trust.json has expired; a document signed under it would verify nowhere");
  }
  return { signed: s, signedBy: v.key_id, kindKeys: (kind) => kindKeysOf(s, kind) };
}

/** A row's public key as a key object. */
export const publicKeyOf = (row) => publicKeyFromBase64(row.public_key);
