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

import { documentPath, environmentOf, KINDS, REPOSITORY_ID, REPOSITORY_OWNER_ID, secretOf } from "../lib/kinds.mjs";
import { ROOT } from "../lib/vendored.mjs";
import { main as secretsMain } from "../owner/secrets.mjs";
import { NOW, plant, scratch, seedSecret, throwawayTrust } from "./helpers.mjs";

const REPO = "mihailinl/astra-content-catalogue";

let createdState = null;

/** A directory holding `gh`, to put first on PATH. Unless `bare`, owner/create.sh has been run against it. */
function fakeGh(t, { bare = false } = {}) {
  const bin = scratch(t, "gh");
  fs.copyFileSync(path.join(ROOT, "test", "fixtures", "fake-gh.mjs"), path.join(bin, "gh"));
  fs.chmodSync(path.join(bin, "gh"), 0o755);
  if (!bare) {
    // owner/create.sh is run against the stand-in once, and each later stand-in starts from what it left
    if (createdState === null) {
      execFileSync("bash", [path.join(ROOT, "owner", "create.sh")], { env: { PATH: `${bin}:${process.env.PATH}`, HOME: bin }, encoding: "utf8" });
      createdState = fs.readFileSync(path.join(bin, "state.json"), "utf8");
      fs.rmSync(path.join(bin, "calls.jsonl"));
    } else fs.writeFileSync(path.join(bin, "state.json"), createdState);
  }
  return {
    bin,
    path: `${bin}:${process.env.PATH}`,
    setState: (f) => {
      const st = JSON.parse(fs.readFileSync(path.join(bin, "state.json"), "utf8"));
      f(st);
      fs.writeFileSync(path.join(bin, "state.json"), JSON.stringify(st));
    },
    uploads: () => (fs.existsSync(path.join(bin, "calls.jsonl")) ? fs.readFileSync(path.join(bin, "calls.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l)) : []).filter((c) => c.argv[0] === "secret"),
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

async function secrets(t, trust, argv, gh, extraEnv = {}) {
  const trustFile = path.join(scratch(t, "trust"), "trust.json");
  fs.writeFileSync(trustFile, JSON.stringify(trust.doc));
  const lines = [];
  const code = await secretsMain([...argv, "--trust", trustFile], { roots: trust.roots, now: NOW, log: (l) => lines.push(l), env: { PATH: gh.path, HOME: gh.bin, ...extraEnv } });
  return { code, lines, trustFile };
}

test("owner/secrets: each kind's current key goes to its own environment, through stdin", async (t) => {
  const trust = throwawayTrust();
  const gh = fakeGh(t);
  const dir = keysDir(t, trust);
  const { code, lines } = await secrets(t, trust, [dir], gh);
  assert.equal(code, 0);
  assert.deepEqual(lines, [...KINDS.map((k) => `${k} astra-${k}-testa match`), ...KINDS.map((k) => `${k} astra-${k}-testa uploaded to publish-${k}`)]);

  const calls = gh.uploads();
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
  assert.ok((await secrets(t, trust, [dir], gh)).lines.some((l) => l.includes("NEXT key") && l.includes("--rotate")));
});

test("owner/secrets --rotate: the kind's next key, and only that, before any trust change", async (t) => {
  const trust = throwawayTrust();
  const gh = fakeGh(t);
  const dir = keysDir(t, trust);
  const slot = `${REPO}/publish-animsets/ASTRA_ANIMSETS_SIGNING_KEY`;
  const held = () => Buffer.from(gh.state().secrets[slot], "base64").toString().trim();
  assert.equal((await secrets(t, trust, [dir], gh)).code, 0);
  assert.equal(held(), seedSecret(trust.seeds.animsets.current));

  const count = gh.uploads().length;
  const rotated = await secrets(t, trust, [dir, "--rotate", "animsets"], gh);
  assert.equal(rotated.code, 0);
  assert.deepEqual(rotated.lines, [
    "animsets astra-animsets-testb ROTATING",
    "animsets astra-animsets-testb uploaded to publish-animsets",
    "animsets: the next Sign run signs both documents with astra-animsets-testb; the trust change that names it current can follow",
  ]);
  assert.equal(gh.uploads().length, count + 1, "one upload, for the one kind");
  assert.equal(held(), seedSecret(trust.seeds.animsets.next));
  await assert.rejects(secrets(t, trust, [dir, "--rotate", "games"], gh), /is not one of/);

  // --rotate uploads nothing but the next key, and not before it is valid
  const refusedRotate = async (name, damage, why, when = trust) => {
    const gh2 = fakeGh(t);
    const d = keysDir(t, when);
    damage(d);
    const r = await secrets(t, when, [d, "--rotate", "animsets"], gh2);
    assert.equal(r.code, 1, name);
    assert.ok(r.lines[0].startsWith("animsets ") && r.lines[0].includes("mismatch") && r.lines[0].includes(why), `${name}: ${r.lines[0]}`);
    assert.deepEqual(gh2.calls(), [], `${name}: gh is never called`);
  };
  const next = (d) => path.join(d, "astra-animsets-testb.seed.b64");
  await refusedRotate("the current key under the next key's name", (d) => fs.copyFileSync(path.join(d, "astra-animsets-testa.seed.b64"), next(d)), "CURRENT key");
  await refusedRotate("another kind's next key", (d) => fs.copyFileSync(path.join(d, "astra-packs-testb.seed.b64"), next(d)), "is not the key trust.json names next");
  await refusedRotate("a key trust.json does not hold", (d) => fs.writeFileSync(next(d), `${seedSecret(crypto.randomBytes(32))}\n`), "is not the key trust.json names next");
  await refusedRotate("a PEM that disagrees", (d) => fs.writeFileSync(path.join(d, "astra-animsets-testb.private.pem"), pemOf(crypto.randomBytes(32))), "is not the key trust.json names next");
  await refusedRotate("a next key that is not valid yet", () => {}, "is not valid before", throwawayTrust({ now: NOW + 40 * 86400 }));

  // After the ceremony names the rotated key current, a plain run reports it as a match.
  const after = throwawayTrust({
    mutate: (signed) => {
      const fresh = signed.kind_keys.find((k) => k.kind === "animsets" && k.role === "next");
      signed.kind_keys = signed.kind_keys.flatMap((row) => {
        if (row.kind !== "animsets") return [{ ...trust.trust.kindKeys(row.kind)[row.role], notBefore: undefined }];
        if (row.role === "current") return [{ ...trust.trust.kindKeys("animsets").next, role: "current", notBefore: undefined }];
        return [{ ...fresh, key_id: "astra-animsets-testc", not_before: "2026-12-30T00:00:00Z" }];
      });
    },
  });
  const before = gh.calls().length;
  const dry = await secrets(t, after, [dir, "--no-upload"], gh);
  assert.equal(dry.code, 0);
  assert.ok(dry.lines.includes("animsets astra-animsets-testb match"));
  assert.ok(dry.lines.includes("animsets: current key id astra-animsets-testb; upload skipped (--no-upload)"));
  assert.equal(gh.calls().length, before, "--no-upload never calls gh");
  // without --no-upload it uploads the same key again, and says that it uploaded: it cannot know what GitHub holds
  const plain = await secrets(t, after, [dir], gh);
  assert.ok(plain.lines.includes("animsets astra-animsets-testb uploaded to publish-animsets"));
  assert.equal(held(), seedSecret(trust.seeds.animsets.next));
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

  // gh failing at the upload is a failed run that says which kind, and stops there
  const real = fs.readFileSync(path.join(gh.bin, "gh"), "utf8");
  fs.renameSync(path.join(gh.bin, "gh"), path.join(gh.bin, "gh-real"));
  fs.writeFileSync(path.join(gh.bin, "gh"), `#!/bin/sh\nif [ "$1" = secret ]; then echo 'HTTP 500: try again' >&2; exit 1; fi\nexec node "${gh.bin}/gh-real" "$@"\n`);
  fs.chmodSync(path.join(gh.bin, "gh"), 0o755);
  void real;
  const failed = await secrets(t, trust, [dir], gh);
  assert.equal(failed.code, 1);
  assert.deepEqual(failed.lines.slice(5), ["commands astra-commands-testa NOT uploaded: gh exited 1 (HTTP 500: try again)"]);
  // gh failing at a question is a failed run too: nothing is assumed about what could not be read
  fs.writeFileSync(path.join(gh.bin, "gh"), "#!/bin/sh\necho 'HTTP 403: forbidden' >&2\nexit 1\n");
  await assert.rejects(secrets(t, trust, [dir], gh), /gh api repos\/mihailinl\/astra-content-catalogue failed \(HTTP 403: forbidden\)/);
});

test("owner/secrets uploads no key until GitHub is set up as owner/create.sh sets it", async (t) => {
  const trust = throwawayTrust();
  const refusedBy = async (name, argv, prepare, why, o = {}) => {
    const gh = fakeGh(t, o);
    const dir = keysDir(t, trust);
    prepare(gh);
    const r = await secrets(t, trust, [dir, ...argv], gh);
    assert.equal(r.code, 1, name);
    assert.ok(r.lines.some((l) => l.startsWith("refused: ") && l.includes(why)), `${name}: ${r.lines.join(" | ")}`);
    assert.equal(r.lines.at(-1), "nothing was uploaded", name);
    assert.deepEqual(gh.uploads(), [], `${name}: no secret is set, for any kind`);
  };
  const ruleset = (st, name) => st.rulesets.find((r) => r.name === name);
  const ADMINS = "main: updated by administrators only";

  // main: the ruleset that keeps the code beside the keys out of every writer's reach
  await refusedBy("no ruleset restricts main", [], (gh) => gh.setState((st) => (st.rulesets = st.rulesets.filter((r) => r.name !== ADMINS))), "no active ruleset restricts updates of main");
  await refusedBy("the ruleset is not enforced", [], (gh) => gh.setState((st) => (ruleset(st, ADMINS).enforcement = "disabled")), "no active ruleset restricts updates of main");
  await refusedBy("the ruleset is only evaluated", [], (gh) => gh.setState((st) => (ruleset(st, ADMINS).enforcement = "evaluate")), "no active ruleset restricts updates of main");
  await refusedBy("the ruleset covers another branch", [], (gh) => gh.setState((st) => (ruleset(st, ADMINS).conditions.ref_name.include = ["refs/heads/dev"])), "no active ruleset restricts updates of main");
  await refusedBy("the ruleset excludes main again", [], (gh) => gh.setState((st) => (ruleset(st, ADMINS).conditions.ref_name.exclude = ["refs/heads/main"])), "no active ruleset restricts updates of main");
  await refusedBy("the ruleset does not restrict updates", [], (gh) => gh.setState((st) => (ruleset(st, ADMINS).rules = [{ type: "deletion" }])), "no active ruleset restricts updates of main");
  await refusedBy("GitHub Actions may bypass it", [], (gh) => gh.setState((st) => ruleset(st, ADMINS).bypass_actors.push({ actor_id: 15368, actor_type: "Integration", bypass_mode: "always" })), "no active ruleset restricts updates of main");
  await refusedBy("the write role may bypass it", [], (gh) => gh.setState((st) => (ruleset(st, ADMINS).bypass_actors = [{ actor_id: 4, actor_type: "RepositoryRole", bypass_mode: "always" }])), "no active ruleset restricts updates of main");

  // the kind's environment: main and nothing else
  await refusedBy("an environment that also deploys from dev", [], (gh) => gh.setState((st) => st.environments["publish-models"].policies.push({ name: "dev", type: "branch" })), "publish-models must deploy from main only");
  await refusedBy("an environment that deploys from dev only", [], (gh) => gh.setState((st) => (st.environments["publish-models"].policies = [{ name: "dev", type: "branch" }])), "publish-models must deploy from main only");
  await refusedBy("an environment with no branch named", [], (gh) => gh.setState((st) => (st.environments["publish-packs"].policies = [])), "publish-packs must deploy from main only");
  await refusedBy("an environment open to every branch", [], (gh) => gh.setState((st) => (st.environments["publish-packs"].settings.deployment_branch_policy = null)), "publish-packs is not restricted to named branches");
  await refusedBy("an environment restricted to protected branches instead", [], (gh) => gh.setState((st) => (st.environments["publish-packs"].settings.deployment_branch_policy = { protected_branches: true, custom_branch_policies: false })), "publish-packs is not restricted to named branches");
  await refusedBy("--rotate into an environment that also deploys from dev", ["--rotate", "models"], (gh) => gh.setState((st) => st.environments["publish-models"].policies.push({ name: "dev", type: "branch" })), "publish-models must deploy from main only");

  // another repository, whatever it is called
  await refusedBy("another repository", ["--repo", "mihailinl/astra-content-catalogue-staging"], () => {}, "is not the signer's repository");
  assert.equal(REPOSITORY_ID, 1454718826);

  // only the kinds asked for are looked at: a rotation of one kind does not wait on another kind's environment
  const gh = fakeGh(t);
  gh.setState((st) => st.environments["publish-packs"].policies.push({ name: "dev", type: "branch" }));
  assert.equal((await secrets(t, trust, [keysDir(t, trust), "--rotate", "models"], gh)).code, 0);
});

test("owner/secrets does not put the current key back over a rotation in progress", async (t) => {
  const trust = throwawayTrust();
  const gh = fakeGh(t);
  const dir = keysDir(t, trust);
  const slot = `${REPO}/publish-models/ASTRA_MODELS_SIGNING_KEY`;
  const held = () => Buffer.from(gh.state().secrets[slot], "base64").toString().trim();
  /** What `data` holds for a kind, as the signer would have published it under `role`'s key. */
  const published = (kind, role) => {
    const d = scratch(t, "data");
    plant(d, kind, { seed: trust.seeds[kind][role], keyId: trust.trust.kindKeys(kind)[role].key_id, serial: NOW - 60 });
    gh.setState((st) => {
      for (const doc of ["index", "withdrawn"]) st.data[documentPath(kind, doc)] = fs.readFileSync(path.join(d, documentPath(kind, doc)), "utf8");
    });
  };
  assert.equal((await secrets(t, trust, [dir], gh)).code, 0);
  published("models", "current");
  published("packs", "current");
  assert.equal((await secrets(t, trust, [dir], gh)).code, 0, "documents signed with the current key: a plain run uploads");

  // the rotation: the next key is placed, and the signer publishes under it
  assert.equal((await secrets(t, trust, [dir, "--rotate", "models"], gh)).code, 0);
  published("models", "next");
  assert.equal(held(), seedSecret(trust.seeds.models.next));

  // before the ceremony, a plain run for every kind: nothing is uploaded, and the next key stays in place
  const n = gh.uploads().length;
  const plain = await secrets(t, trust, [dir], gh);
  assert.equal(plain.code, 1);
  assert.ok(plain.lines.includes("refused: models was last signed with its NEXT key (a rotation is in progress); the current key would move it back, so it is not uploaded"));
  assert.equal(gh.uploads().length, n);
  assert.equal(held(), seedSecret(trust.seeds.models.next));
  // one next-signed document is enough: the index alone, with the withdrawn document still under the current key
  const d = scratch(t, "data");
  plant(d, "packs", { seed: trust.seeds.packs.next, keyId: "astra-packs-testb", serial: NOW - 30 });
  gh.setState((st) => (st.data[documentPath("packs", "index")] = fs.readFileSync(path.join(d, documentPath("packs", "index")), "utf8")));
  assert.ok((await secrets(t, trust, [dir], gh)).lines.some((l) => l.startsWith("refused: packs was last signed with its NEXT key")));
  // rotating again is still allowed, and a document that cannot be read is not taken for "no rotation"
  assert.equal((await secrets(t, trust, [dir, "--rotate", "models"], gh)).code, 0);
  gh.setState((st) => (st.data[documentPath("models", "index")] = "{"));
  await assert.rejects(secrets(t, trust, [dir], gh), /models's index on data is not JSON/);
});

test("owner/secrets gives gh its sign-in and nothing else of the environment", async (t) => {
  const trust = throwawayTrust();
  const gh = fakeGh(t);
  const dir = keysDir(t, trust);
  const r = await secrets(t, trust, [dir, "--rotate", "commands"], gh, { GH_TOKEN: "gh-token", GH_CONFIG_DIR: "/cfg", CONTENT_SIGNING_KEY: "canary", AWS_SECRET_ACCESS_KEY: "canary", SSH_AUTH_SOCK: "/s" });
  assert.equal(r.code, 0);
  const calls = gh.calls();
  assert.ok(calls.length >= 5);
  for (const c of calls) {
    // Node adds nothing of its own to a child's environment; the stand-in records every name it was given
    assert.deepEqual(c.env, ["GH_CONFIG_DIR", "GH_TOKEN", "HOME", "PATH"], c.argv.join(" "));
  }
});

test("owner/create.sh: environments on main only, four rulesets, the two ids, and a second run changes nothing", (t) => {
  const gh = fakeGh(t, { bare: true });
  const run = () => execFileSync("bash", [path.join(ROOT, "owner", "create.sh")], { env: { PATH: gh.path, HOME: gh.bin }, encoding: "utf8" });
  const out = run();
  const first = gh.state();
  assert.deepEqual(Object.keys(first.environments), ["content-service", ...KINDS.map(environmentOf)]);
  for (const [name, env] of Object.entries(first.environments)) {
    assert.deepEqual(env.settings, { deployment_branch_policy: { protected_branches: false, custom_branch_policies: true } }, name);
    assert.deepEqual(env.policies, [{ name: "main", type: "branch" }], name);
  }
  const rules = Object.fromEntries(first.rulesets.map((r) => [r.name, r]));
  assert.deepEqual(Object.keys(rules), ["main: no deletion, no forced update", "main: updated by administrators only", "data: forward only", "data: written by the workflow only"]);
  const types = (r) => r.rules.map((x) => x.type);
  // nobody forces or deletes main; and only an administrator updates it at all, which is what
  // keeps a signing leg's own contents-write token from changing the code the next run executes
  assert.deepEqual(rules["main: no deletion, no forced update"].bypass_actors, []);
  assert.deepEqual(types(rules["main: updated by administrators only"]), ["update"]);
  assert.deepEqual(rules["main: updated by administrators only"].conditions.ref_name, { include: ["refs/heads/main"], exclude: [] });
  assert.deepEqual(rules["main: updated by administrators only"].bypass_actors, [{ actor_id: 5, actor_type: "RepositoryRole", bypass_mode: "always" }]);
  assert.deepEqual(types(rules["main: no deletion, no forced update"]), ["deletion", "non_fast_forward"]);
  assert.deepEqual(rules["main: no deletion, no forced update"].conditions.ref_name.include, ["refs/heads/main"]);
  // nobody, the workflow included, may force or delete data
  assert.deepEqual(types(rules["data: forward only"]), ["deletion", "non_fast_forward"]);
  assert.deepEqual(rules["data: forward only"].bypass_actors, []);
  // and only the workflow's token may write it at all
  assert.deepEqual(types(rules["data: written by the workflow only"]), ["creation", "update"]);
  assert.deepEqual(rules["data: written by the workflow only"].bypass_actors, [{ actor_id: 15368, actor_type: "Integration", bypass_mode: "always" }]);
  for (const r of first.rulesets) assert.equal(r.enforcement, "active");
  assert.ok(out.endsWith(`repository_id        ${REPOSITORY_ID}\nrepository_owner_id  ${REPOSITORY_OWNER_ID}\n`), "the two ids the service pins, which are also the ones compiled here");

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
