// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// The one key a signing job holds, and the rule about which key it may be.
//
// A kind's environment holds one secret: the private half of the key that
// trust.json names `current` for that kind. The private half is read here,
// its public half is derived, and the job goes on only when that equals the
// kind's current row. It refuses the kind's `next` key by name: the next key
// stays offline with the operator and becomes usable here only after
// trust.json itself names it current (README, "Rotating a key"). It refuses
// any other key too, another kind's included, so a secret placed in the wrong
// environment signs nothing.
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
 * The signer of a kind: the current key, or a refusal.
 *
 * @param {{secret: string|undefined, kind: string, kindKeys: {current: object, next: object}, now: number}} o
 * @returns {{key_id: string, privateKey: crypto.KeyObject}}
 */
export function currentSigner({ secret, kind, kindKeys, now }) {
  if (!secret || !String(secret).trim()) throw new Refused("E_KEY_ABSENT", `no signing key in this job for ${kind}`);
  const privateKey = privateKeyFromSecret(secret);
  if (!privateKey) throw new Refused("E_KEY_FORMAT", `the signing key for ${kind} is neither a base64 seed of 32 bytes nor an Ed25519 PEM`);
  const role = roleOf(publicKeyBase64(privateKey), kindKeys);
  if (role === "next") {
    throw new Refused("E_KEY_IS_NEXT", `the key in this job is ${kind}'s next key (${kindKeys.next.key_id}); the signer signs with the current key only`);
  }
  if (role !== "current") throw new Refused("E_KEY_NOT_CURRENT", `the key in this job is not ${kind}'s current key (${kindKeys.current.key_id})`);
  if (!(kindKeys.current.notBefore <= now)) throw new Refused("E_KEY_NOT_YET", `${kindKeys.current.key_id} is not valid yet`);
  return { key_id: kindKeys.current.key_id, privateKey };
}

/** One document signed by one key under the signer's own domain. */
export function sign({ domain, signed, signer }) {
  return signEnvelope({ domain, signed, signers: [signer] });
}
