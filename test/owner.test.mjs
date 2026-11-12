// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// A rehearsal of owner/ against a stand-in `gh` (test/fixtures/fake-gh.mjs)
// and keys made for the test. Nothing here reaches GitHub or reads a real key.

import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";

import { environmentOf, KINDS, secretOf } from "../lib/kinds.mjs";
import { ROOT } from "../lib/vendored.mjs";
import { main as secretsMain } from "../owner/secrets.mjs";
import { NOW, scratch, seedSecret, throwawayTrust } from "./helpers.mjs";

const REPO = "mihailinl/astra-content-catalogue";

/** A directory holding `gh`, to put first on PATH. */
function fakeGh(t) {
  const bin = scratch(t, "gh");
  fs.copyFileSync(path.join(ROOT, "test", "fixtures", "fake-gh.mjs"), path.join(bin, "gh"));
  fs.chmodSync(path.join(bin, "gh"), 0o755);
  return {
    bin,
    path: `${bin}:${process.env.PATH}`,
    state: () => (fs.existsSync(path.join(bin, "state.json")) ? JSON.parse(fs.readFileSync(path.join(bin, "state.json"), "utf8")) : { secrets: {} }),
    calls: () => (fs.existsSync(path.join(bin, "calls.jsonl")) ? fs.readFileSync(path.join(bin, "calls.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l)) : []),
  };
}

const pemOf = (seed) =>
  crypto.createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]), format: "der", type: "pkcs8" }).export({ format: "pem", type: "pkcs8" });

/** A keys directory as the operator's: for every key id of trust.json, the four files. */
function keysDir(t, trust, { only = null } = {}) {
  const dir = scratch(t, "keys");
  for (const kind of KINDS) {
    for (const role of ["current", "next"]) {
      const row = trust.trust.kindKeys(kind)[role];
      if (only && !only(kind, role)) continue;
      const seed = trust.seeds[kind][role];
      fs.writeFileSync(path.join(dir, `${row.key_id}.seed.b64`), `${seedSecret(seed)}\n`, { mode: 0o600 });
      fs.writeFileSync(path.join(dir, `${row.key_id}.private.pem`), pemOf(seed), { mode: 0o600 });
      fs.writeFileSync(path.join(dir, `${row.key_id}.pub.json`), JSON.stringify({ key_id: row.key_id, public_key: row.public_key }));
      fs.writeFileSync(path.join(dir, `${row.key_id}.kind-key.json`), JSON.stringify(row));
    }
  }
  return dir;
}

async function secrets(t, trust, argv, gh) {
  const trustFile = path.join(scratch(t, "trust"), "trust.json");
  fs.writeFileSync(trustFile, JSON.stringify(trust.doc));
  const lines = [];
  const code = await secretsMain([...argv, "--trust", trustFile], { roots: trust.roots, now: NOW, log: (l) => lines.push(l), env: { PATH: gh.path, HOME: gh.bin } });
  return { code, lines, trustFile };
}

test("owner/secrets: each kind's current key goes to its own environment, through stdin", async (t) => {
  const trust = throwawayTrust();
  const gh = fakeGh(t);
  const dir = keysDir(t, trust);
  const { code, lines } = await secrets(t, trust, [dir], gh);
  assert.equal(code, 0);
  assert.deepEqual(lines, [...KINDS.map((k) => `${k} astra-${k}-testa match`), ...KINDS.map((k) => `${k} astra-${k}-testa uploaded to publish-${k}`)]);

  const calls = gh.calls();
  assert.deepEqual(
    calls.map((c) => c.argv),
    KINDS.map((k) => ["secret", "set", secretOf(k), "--env", environmentOf(k), "--repo", REPO]),
    "five uploads, each naming one secret and one environment, and no value",
  );
  const { secrets: stored } = gh.state();
  for (const kind of KINDS) {
    const value = Buffer.from(stored[`${REPO}/${environmentOf(kind)}/${secretOf(kind)}`], "base64").toString("utf8");
    assert.equal(value.trim(), seedSecret(trust.seeds[kind].current), `${kind}: the current key`);
    assert.notEqual(value.trim(), seedSecret(trust.seeds[kind].next));
  }
  assert.equal(Object.keys(stored).length, KINDS.length, "and no secret for a next key");
  // nothing printed or passed as an argument is key material
  const said = lines.join("\n") + JSON.stringify(calls.map((c) => c.argv));
  for (const kind of KINDS) for (const role of ["current", "next"]) assert.ok(!said.includes(seedSecret(trust.seeds[kind][role])));
});

test("owner/secrets: a key that is not the kind's current key uploads nothing, for any kind", async (t) => {
  const trust = throwawayTrust();
  const cases = {
    "the next key under the current key's file name": (dir) =>
      fs.copyFileSync(path.join(dir, "astra-models-testb.seed.b64"), path.join(dir, "astra-models-testa.seed.b64")),
    "another kind's key": (dir) => fs.copyFileSync(path.join(dir, "astra-packs-testa.seed.b64"), path.join(dir, "astra-models-testa.seed.b64")),
    "a PEM that disagrees with the seed beside it": (dir) => fs.writeFileSync(path.join(dir, "astra-models-testa.private.pem"), pemOf(crypto.randomBytes(32))),
    "a file that is not a key": (dir) => fs.writeFileSync(path.join(dir, "astra-models-testa.seed.b64"), "hello\n"),
    "no private file": (dir) => ["seed.b64", "private.pem"].forEach((s) => fs.rmSync(path.join(dir, `astra-models-testa.${s}`))),
  };
  for (const [name, damage] of Object.entries(cases)) {
    const gh = fakeGh(t);
    const dir = keysDir(t, trust);
    damage(dir);
    const { code, lines } = await secrets(t, trust, [dir], gh);
    assert.equal(code, 1, name);
    assert.ok(lines.some((l) => l.startsWith("models astra-models-testa mismatch")), name);
    assert.equal(lines.filter((l) => l.endsWith(" match")).length, 4, `${name}: the other four are reported`);
    assert.deepEqual(gh.calls(), [], `${name}: gh is never called`);
  }
  // the next key's refusal says what it is
  const gh = fakeGh(t);
  const dir = keysDir(t, trust);
  cases["the next key under the current key's file name"](dir);
  assert.ok((await secrets(t, trust, [dir], gh)).lines.some((l) => l.includes("NEXT key")));
});

test("owner/secrets --rotate: after trust.json names a new current key, that key and only that kind", async (t) => {
  const before = throwawayTrust();
  const gh = fakeGh(t);
  const dir = keysDir(t, before);
  assert.equal((await secrets(t, before, [dir], gh)).code, 0);

  // Before the trust change, the next key cannot be uploaded: no option reaches it.
  const early = await secrets(t, before, [dir, "--rotate", "animsets"], gh);
  assert.deepEqual(early.lines.slice(0, 2), ["animsets astra-animsets-testa match", "animsets astra-animsets-testa uploaded to publish-animsets"]);
  assert.equal(Buffer.from(gh.state().secrets[`${REPO}/publish-animsets/ASTRA_ANIMSETS_SIGNING_KEY`], "base64").toString().trim(), seedSecret(before.seeds.animsets.current));

  // The ceremony: animsets' old next key becomes current, and a new next key appears.
  const after = throwawayTrust({
    suffixes: ["a", "b"],
    mutate: (signed) => {
      const fresh = crypto.randomBytes(32);
      signed.kind_keys = signed.kind_keys.flatMap((row) => {
        const old = before.trust.kindKeys(row.kind)[row.role];
        if (row.kind !== "animsets") return [{ ...old }];
        if (row.role === "current") return [{ ...before.trust.kindKeys("animsets").next, role: "current" }];
        const pub = crypto.createPublicKey(crypto.createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), fresh]), format: "der", type: "pkcs8" })).export({ format: "der", type: "spki" });
        return [{ ...row, key_id: "astra-animsets-testc", public_key: pub.subarray(pub.length - 32).toString("base64"), not_before: "2026-12-30T00:00:00Z" }];
      });
    },
  });
  const count = gh.calls().length;
  const rotated = await secrets(t, after, [dir, "--rotate", "animsets"], gh);
  assert.equal(rotated.code, 0);
  assert.deepEqual(rotated.lines, [
    "animsets astra-animsets-testb match",
    "animsets astra-animsets-testb uploaded to publish-animsets",
    "animsets: the next Sign run signs both documents under the new current key",
  ]);
  assert.equal(gh.calls().length, count + 1, "one upload");
  assert.equal(Buffer.from(gh.state().secrets[`${REPO}/publish-animsets/ASTRA_ANIMSETS_SIGNING_KEY`], "base64").toString().trim(), seedSecret(before.seeds.animsets.next));
  await assert.rejects(secrets(t, after, [dir, "--rotate", "games"], gh), /is not one of/);
});

test("owner/secrets as shipped believes only the compiled roots, and fails when gh does", async (t) => {
  const trust = throwawayTrust();
  const gh = fakeGh(t);
  const dir = keysDir(t, trust);
  const trustFile = path.join(scratch(t, "trust"), "trust.json");
  fs.writeFileSync(trustFile, JSON.stringify(trust.doc));
  // the command line has no way to name other roots: a trust.json signed by a throwaway root is refused
  const r = spawnSync("bash", [path.join(ROOT, "owner", "secrets.sh"), dir, "--trust", trustFile], { env: { PATH: gh.path, HOME: gh.bin }, encoding: "utf8" });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /E_TRUST_UNVERIFIED/);
  assert.deepEqual(gh.calls(), []);

  // gh failing is a failed run that says which kind, and stops there
  fs.writeFileSync(path.join(gh.bin, "gh"), "#!/bin/sh\necho 'HTTP 404: environment not found' >&2\nexit 1\n");
  const failed = await secrets(t, trust, [dir], gh);
  assert.equal(failed.code, 1);
  assert.deepEqual(failed.lines.slice(5), ["commands astra-commands-testa NOT uploaded: gh exited 1 (HTTP 404: environment not found)"]);
});

test("owner/create.sh: environments on main only, three rulesets, the two ids, and a second run changes nothing", (t) => {
  const gh = fakeGh(t);
  const run = () => execFileSync("bash", [path.join(ROOT, "owner", "create.sh")], { env: { PATH: gh.path, HOME: gh.bin }, encoding: "utf8" });
  const out = run();
  const first = gh.state();
  assert.deepEqual(Object.keys(first.environments), ["content-service", ...KINDS.map(environmentOf)]);
  for (const [name, env] of Object.entries(first.environments)) {
    assert.deepEqual(env.settings, { deployment_branch_policy: { protected_branches: false, custom_branch_policies: true } }, name);
    assert.deepEqual(env.policies, [{ name: "main", type: "branch" }], name);
  }
  const rules = Object.fromEntries(first.rulesets.map((r) => [r.name, r]));
  assert.deepEqual(Object.keys(rules), ["main: no deletion, no forced update", "data: forward only", "data: written by the workflow only"]);
  const types = (r) => r.rules.map((x) => x.type);
  assert.deepEqual(types(rules["main: no deletion, no forced update"]), ["deletion", "non_fast_forward"]);
  assert.deepEqual(rules["main: no deletion, no forced update"].conditions.ref_name.include, ["refs/heads/main"]);
  // nobody, the workflow included, may force or delete data
  assert.deepEqual(types(rules["data: forward only"]), ["deletion", "non_fast_forward"]);
  assert.deepEqual(rules["data: forward only"].bypass_actors, []);
  // and only the workflow's token may write it at all
  assert.deepEqual(types(rules["data: written by the workflow only"]), ["creation", "update"]);
  assert.deepEqual(rules["data: written by the workflow only"].bypass_actors, [{ actor_id: 15368, actor_type: "Integration", bypass_mode: "always" }]);
  for (const r of first.rulesets) assert.equal(r.enforcement, "active");
  assert.match(out, /repository_id {8}1000000001\nrepository_owner_id {2}2000000002\n$/);

  const calls = gh.calls().length;
  assert.equal(run(), out);
  assert.deepEqual(gh.state(), first, "the second run leaves the same environments and rulesets");
  const second = gh.calls().slice(calls);
  assert.ok(!second.some((c) => c.argv.includes("POST")), "and creates nothing a second time");
  assert.ok(!gh.calls().some((c) => c.argv[0] === "secret"), "create.sh never touches a secret");

  // an environment that also allows another branch stops the script
  const state = gh.state();
  state.environments["publish-packs"].policies.push({ name: "dev", type: "branch" });
  fs.writeFileSync(path.join(gh.bin, "state.json"), JSON.stringify(state));
  const r = spawnSync("bash", [path.join(ROOT, "owner", "create.sh")], { env: { PATH: gh.path, HOME: gh.bin }, encoding: "utf8" });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /environment publish-packs also allows: dev/);
});
