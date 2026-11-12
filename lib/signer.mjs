// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// The one key a signing job holds, and the rule about which key it may be.
//
// A kind's environment holds one secret: the private half of one of the two
// keys that trust.json holds for that kind, `current` or `next`. The private
// half is read here, its public half is derived, and the job goes on only
// when that equals one of the kind's two rows and the row is valid now
// (`not_before`). Any other key is refused, another kind's included, so a
// secret placed in the wrong environment signs nothing.
//
// Both rows are accepted because that is how a kind is rotated without a gap
// (README, "Rotating a key"): the operator places the next key, the signer
// signs with it at once, and clients and the service already accept either
// key of the kind. The switch is one-way (trust-kind-keys-v1.md §6): once a
// kind has been signed with its next key, a client that saw that document
// refuses a later one signed with the current key alone, so a job that holds
// the current key after the next key has signed is refused here.
//
// A secret is the base64 of the raw 32-byte seed, or a PKCS#8 PEM. It arrives
// in the environment and never in an argument, and no message here carries
// any part of it.

import crypto from "node:crypto";

import { privateKeyFromSeed, publicKeyBase64, signEnvelope } from "../vendor/astra-registry/bot/lib/sign.mjs";
import { Refused } from "./kinds.mjs";

/** A private key from a secret's text, or null when the text is neither spelling. */
export function privateKeyFromSecret(text) {
  const t = String(text ?? "").trim();
  try {
    if (t.startsWith("-----BEGIN")) {
      const key = crypto.createPrivateKey({ key: t, format: "pem" });
      return key.asymmetricKeyType === "ed25519" ? key : null;
    }
    const seed = Buffer.from(t, "base64");
    return seed.length === 32 && seed.toString("base64") === t ? privateKeyFromSeed(seed) : null;
  } catch {
    return null;
  }
}

/** The role (`current`, `next`) a public key has for a kind, or null. */
export function roleOf(publicKey, kindKeys) {
  if (publicKey === kindKeys.current.public_key) return "current";
  if (publicKey === kindKeys.next.public_key) return "next";
  return null;
}

/**
 * The signer of a kind: one of the kind's two trusted keys, valid now, or a
 * refusal.
 *
 * @param {{secret: string|undefined, kind: string, kindKeys: {current: object, next: object}, now: number, lastKeyId?: string|null}} o
 *   `lastKeyId` is the key that signed the kind's documents last.
 * @returns {{key_id: string, role: "current"|"next", privateKey: crypto.KeyObject}}
 */
export function kindSigner({ secret, kind, kindKeys, now, lastKeyId = null }) {
  if (!secret || !String(secret).trim()) throw new Refused("E_KEY_ABSENT", `no signing key in this job for ${kind}`);
  const privateKey = privateKeyFromSecret(secret);
  if (!privateKey) throw new Refused("E_KEY_FORMAT", `the signing key for ${kind} is neither a base64 seed of 32 bytes nor an Ed25519 PEM`);
  const role = roleOf(publicKeyBase64(privateKey), kindKeys);
  if (role === null) {
    throw new Refused("E_KEY_NOT_TRUSTED", `the key in this job is neither of the two keys trust.json holds for ${kind} (${kindKeys.current.key_id}, ${kindKeys.next.key_id})`);
  }
  const row = kindKeys[role];
  if (!(row.notBefore <= now)) throw new Refused("E_KEY_NOT_YET", `${row.key_id} is not valid before ${row.not_before}`);
  if (role === "current" && lastKeyId === kindKeys.next.key_id) {
    throw new Refused("E_KEY_SWITCHED_BACK", `${kind} was last signed with its next key (${lastKeyId}); the switch is one-way, and the current key no longer signs it`);
  }
  return { key_id: row.key_id, role, privateKey };
}

/** One document signed by one key under the signer's own domain. */
export function sign({ domain, signed, signer }) {
  return signEnvelope({ domain, signed, signers: [{ key_id: signer.key_id, privateKey: signer.privateKey }] });
}
