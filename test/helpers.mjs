// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// What the tests share. Every key here is either generated for one test and
// thrown away, or one of the specification's published TEST keys
// (vendor/astraplugins/testdata/content/README.md), which are trusted by
// nothing outside a test.

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { privateKeyFromSeed, publicKeyBase64, publicKeyFromBase64, signEnvelope, TRUST_SCHEMA } from "../vendor/astra-registry/bot/lib/sign.mjs";
import { KINDS } from "../lib/kinds.mjs";
import { loadTrust } from "../lib/trust.mjs";
import { ROOT } from "../lib/vendored.mjs";

export const GOLDENS = path.join(ROOT, "vendor", "astraplugins", "testdata", "content");
export const VECTORS = JSON.parse(fs.readFileSync(path.join(GOLDENS, "vectors.json"), "utf8"));
/** The goldens' clock. */
export const NOW = VECTORS.now;

export const golden = (rel) => JSON.parse(fs.readFileSync(path.join(GOLDENS, rel), "utf8"));

/** A scratch directory, removed when the test ends. Honour TMPDIR, which the build filesystem sets. */
export function scratch(t, name = "t") {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `content-catalogue-${name}-`));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

/** The seed of a published TEST key (contentlite.test_seed). */
export const testSeed = (keyId) => crypto.createHash("sha256").update(`astra-content-TEST-KEY-never-trusted:${keyId}`, "utf8").digest();
export const seedSecret = (seed) => seed.toString("base64");

/** The specification's TEST trust.json, loaded under its TEST root. */
export function goldenTrust(now = NOW) {
  const roots = { keys: [{ key_id: "test-root", publicKey: publicKeyFromBase64(VECTORS.trust.root_public_key) }] };
  return { trust: loadTrust({ file: path.join(GOLDENS, VECTORS.trust.file), now, roots }), roots };
}

/** A throwaway trust.json with fresh keys for every kind. Returns the seeds too. */
export function throwawayTrust({ now = NOW, kinds = KINDS, mutate = null, suffixes = ["a", "b"] } = {}) {
  const rootSeed = crypto.randomBytes(32);
  const root = privateKeyFromSeed(rootSeed);
  const seeds = {};
  const kind_keys = [];
  const iso = (s) => `${new Date(s * 1000).toISOString().slice(0, 19)}Z`;
  for (const kind of kinds) {
    seeds[kind] = { current: crypto.randomBytes(32), next: crypto.randomBytes(32) };
    for (const [role, suffix, nb] of [["current", suffixes[0], now - 30 * 86400], ["next", suffixes[1], now - 29 * 86400]]) {
      kind_keys.push({
        kind,
        role,
        key_id: `astra-${kind}-test${suffix}`,
        alg: "ed25519",
        public_key: publicKeyBase64(privateKeyFromSeed(seeds[kind][role])),
        not_before: iso(nb),
      });
    }
  }
  const signed = { schema: TRUST_SCHEMA, serial: 1, issued_at: iso(now - 31 * 86400), expires_at: iso(now + 365 * 86400), index_keys: [], reusable_workflow_shas: [], kind_keys };
  if (mutate) mutate(signed);
  const doc = signEnvelope({ domain: TRUST_SCHEMA, signed, signers: [{ key_id: "throwaway-root", privateKey: root }] });
  const roots = { keys: [{ key_id: "throwaway-root", publicKey: crypto.createPublicKey(root) }] };
  return { doc, roots, seeds, trust: loadTrust({ doc, now, roots }), rootSeed };
}

/** An `astra.content.export/1` answer. */
export function exportOf(kind, { entries = [], rows = [], lifts = [], state = null } = {}) {
  const body = { entries, withdrawn: { rows, lifts } };
  return {
    schema: "astra.content.export/1",
    kind,
    generated_at: "2026-12-31T00:00:00Z",
    state_sha256: state ?? crypto.createHash("sha256").update(JSON.stringify(body)).digest("hex"),
    ...body,
  };
}

/** Write an answer where the signing step reads it. `raw` writes bytes as they are. */
export function writeExport(dir, kind, doc, { raw = null } = {}) {
  const file = path.join(dir, `export-${kind}.json`);
  fs.writeFileSync(file, raw ?? JSON.stringify(doc));
  return file;
}

/** Every file under `dir` with its bytes, to prove a refusal wrote nothing. */
export function snapshot(dir) {
  const out = {};
  const walk = (rel) => {
    for (const d of fs.readdirSync(path.join(dir, rel), { withFileTypes: true })) {
      if (d.name === ".git") continue;
      const p = path.join(rel, d.name);
      if (d.isDirectory()) walk(p);
      else out[p] = fs.readFileSync(path.join(dir, p)).toString("base64");
    }
  };
  if (fs.existsSync(dir)) walk("");
  return out;
}
