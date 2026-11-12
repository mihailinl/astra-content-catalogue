// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// The three stages of a leg taken apart (lib/pipeline.mjs, lib/keystep.mjs):
// what the step with the key can reach, what each verifier refuses by itself,
// and what a refusal prints.

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";

import { main as prepareMain } from "../bin/prepare.mjs";
import { main as signMain } from "../bin/sign.mjs";
import { checkDocument, checkerSelf, invocation } from "../lib/checker.mjs";
import { DOCS, domainOf, Refused, sanitise } from "../lib/kinds.mjs";
import { documentBytes, leaveOrder, prepareKind, signPrepared, verifyAndInstall } from "../lib/pipeline.mjs";
import { kindKeysOf } from "../lib/trust.mjs";
import { ROOT } from "../lib/vendored.mjs";
import { privateKeyFromSeed, signEnvelope, verifyEnvelope } from "../vendor/astra-registry/bot/lib/sign.mjs";
import { exportOf, golden, NOW, scratch, seedSecret, snapshot, throwawayTrust, writeExport } from "./helpers.mjs";

const refusal = (code) => (e) => e instanceof Refused && e.code === code;

/** The preparing job and the key job done, the publishing job still to run. */
function signedWork(t, { kind = "commands", answer } = {}) {
  const { trust, seeds } = throwawayTrust();
  const dir = scratch(t);
  const dataDir = path.join(dir, "data");
  const workDir = path.join(dir, "prepared");
  const signedDir = path.join(dir, "signed");
  fs.mkdirSync(dataDir);
  const exportFile = writeExport(dir, kind, answer ?? exportOf(kind, { entries: golden(`index/${kind}/valid.json`).signed.entries }));
  prepareKind({ kind, exportFile, dataDir, trust, now: NOW, workDir, everHeld: false });
  signPrepared({ kind, workDir, outDir: signedDir, trust, secret: seedSecret(seeds[kind].current) });
  return { trust, seeds, dataDir, workDir, signedDir, kind, everHeld: false };
}

test("the job with the key can start no process and open no connection", () => {
  // every module bin/sign.mjs loads, followed through every import it spells, static or dynamic
  const seen = new Set();
  const builtins = new Set();
  const walk = (file) => {
    if (seen.has(file)) return;
    seen.add(file);
    const src = fs.readFileSync(file, "utf8");
    assert.ok(!/\brequire\s*\(|process\.binding|createRequire/.test(src), `${file}: only import statements`);
    for (const m of src.matchAll(/(?:\bfrom\s*|\bimport\s*\(?\s*)(["'])([^"']+)\1/g)) {
      if (m[2].startsWith("node:")) builtins.add(m[2]);
      else if (m[2].startsWith(".")) walk(path.resolve(path.dirname(file), m[2]));
      else assert.fail(`${file} imports ${m[2]}`);
    }
  };
  walk(path.join(ROOT, "bin", "sign.mjs"));
  assert.deepEqual([...builtins].sort(), ["node:crypto", "node:fs", "node:path"], "nothing that starts a process or opens a socket");
  const files = [...seen].map((f) => path.relative(ROOT, f)).sort();
  assert.deepEqual(files, [
    "bin/sign.mjs",
    "lib/args.mjs",
    "lib/keystep.mjs",
    "lib/kinds.mjs",
    "lib/signer.mjs",
    "lib/trust.mjs",
    "lib/workdir.mjs",
    "vendor/astra-registry/bot/lib/roots.mjs",
    "vendor/astra-registry/bot/lib/sign.mjs",
    "vendor/astra-registry/tools/lib/canonical.mjs",
  ]);
  const code = (f) => fs.readFileSync(f, "utf8").split("\n").filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l)).join("\n");
  for (const f of seen) assert.ok(!/\bfetch\s*\(|child_process|execFile|spawn/.test(code(f)), `${path.relative(ROOT, f)} neither fetches nor spawns`);
});

test("the job with the key reads one admitted artifact and signs only what could honestly have been prepared", (t) => {
  const { trust, seeds } = throwawayTrust();
  const secret = seedSecret(seeds.packs.current);
  const fresh = () => {
    const dir = scratch(t);
    const workDir = path.join(dir, "prepared");
    fs.mkdirSync(path.join(dir, "data"));
    prepareKind({ kind: "packs", exportFile: writeExport(dir, "packs", exportOf("packs")), dataDir: path.join(dir, "data"), trust, now: NOW, workDir, everHeld: false });
    return { workDir, outDir: path.join(dir, "signed") };
  };
  assert.deepEqual(fs.readdirSync(fresh().workDir).sort(), ["index.signed.json", "order.json", "trust.json", "withdrawn.signed.json"], "the prepared artifact is these four files");
  const body = (w, doc) => path.join(w, `${doc}.signed.json`);
  const edit = (file, f) => fs.writeFileSync(file, f(fs.readFileSync(file, "utf8")));
  const outside = scratch(t, "outside");
  fs.writeFileSync(path.join(outside, "x"), "{}");
  const cases = {
    // what is in the artifact
    E_ARTIFACT: {
      "another file beside the four": (w) => fs.writeFileSync(path.join(w, "run.sh"), "#!/bin/sh\n"),
      "a file named like a workflow command": (w) => fs.writeFileSync(path.join(w, "::error::x"), ""),
      "a directory": (w) => fs.mkdirSync(path.join(w, "node_modules")),
      "a link in a body's place": (w) => {
        fs.rmSync(body(w, "index"));
        fs.symlinkSync(path.join(outside, "x"), body(w, "index"));
      },
      "a link beside the four": (w) => fs.symlinkSync(outside, path.join(w, "more")),
      "a body over a mebibyte": (w) => fs.writeFileSync(body(w, "withdrawn"), Buffer.alloc(1048577, 0x20)),
      "an order over its bound": (w) => edit(path.join(w, "order.json"), (s) => s.replace("{", `{"pad":"${"x".repeat(9000)}",`)),
      "a trust.json over its bound": (w) => fs.writeFileSync(path.join(w, "trust.json"), Buffer.alloc(256 * 1024 + 1, 0x20)),
      "no trust.json": (w) => fs.rmSync(path.join(w, "trust.json")),
      "no withdrawn body": (w) => fs.rmSync(body(w, "withdrawn")),
      "no order": (w) => fs.rmSync(path.join(w, "order.json")),
      "an order that is not JSON": (w) => fs.writeFileSync(path.join(w, "order.json"), "{"),
      "an order for another kind": (w) => edit(path.join(w, "order.json"), (s) => s.replace('"packs"', '"models"')),
      "an order with an outcome of its own": (w) => edit(path.join(w, "order.json"), (s) => s.replace('"prepared"', '"ready"')),
      "a closed order that still carries bodies": (w) => edit(path.join(w, "order.json"), (s) => s.replace('"prepared"', '"closed"')),
    },
    // what the bodies are
    E_PREPARED: {
      "a body for another kind": (w) => edit(body(w, "index"), (s) => s.replace("astra.packs.index/1", "astra.models.index/1")),
      "the withdrawn body in the index's place": (w) => fs.copyFileSync(body(w, "withdrawn"), body(w, "index")),
      "a serial that is not the order's second": (w) => edit(body(w, "index"), (s) => s.replaceAll(String(NOW), String(NOW + 5))),
      "a longer life": (w) => edit(body(w, "withdrawn"), (s) => s.replace(String(NOW + 7 * 86400), String(NOW + 70 * 86400))),
      "a body that is not canonical JSON": (w) => edit(body(w, "index"), (s) => `${s} `),
      "a member named twice": (w) => edit(body(w, "index"), (s) => s.replace('{"entries":[]', '{"entries":[],"entries":[]')),
      "an order that names no second": (w) => edit(path.join(w, "order.json"), (s) => s.replace(`"now": ${NOW}`, '"now": "soon"')),
    },
  };
  for (const [code, group] of Object.entries(cases)) {
    for (const [name, damage] of Object.entries(group)) {
      const w = fresh();
      damage(w.workDir);
      assert.throws(() => signPrepared({ kind: "packs", ...w, trust, secret }), refusal(code), name);
      assert.deepEqual(fs.readdirSync(w.outDir), ["result.json"], `${name}: no signed document is left`);
      assert.deepEqual(JSON.parse(fs.readFileSync(path.join(w.outDir, "result.json"), "utf8")), { schema: "astra.content.signer-result/1", kind: "packs", outcome: "refused", code }, name);
    }
  }
  // untouched: the signed artifact is exactly three files
  const w = fresh();
  assert.equal(signPrepared({ kind: "packs", ...w, trust, secret }).outcome, "signed");
  assert.deepEqual(fs.readdirSync(w.outDir).sort(), ["index.json", "result.json", "withdrawn.json"]);
  // a closed or refused order asks for nothing, needs no key and no trust.json, and gets no signature
  for (const [outcome, said] of [["closed", "closed"], ["refused", "not-prepared"]]) {
    const dir = scratch(t);
    leaveOrder(path.join(dir, "prepared"), "packs", outcome);
    assert.equal(signPrepared({ kind: "packs", workDir: path.join(dir, "prepared"), outDir: path.join(dir, "signed"), trust: null, secret: undefined }).outcome, said);
    assert.deepEqual(fs.readdirSync(path.join(dir, "signed")), ["result.json"]);
  }
});

test("the publishing job admits both artifacts, and publishes only over the data the kind was prepared against", (t) => {
  // the signed artifact: three names, bounded, nothing else
  const bad = {
    "another file": (w) => fs.writeFileSync(path.join(w.signedDir, "extra.json"), "{}"),
    "a link": (w) => {
      fs.rmSync(path.join(w.signedDir, "index.json"));
      fs.symlinkSync(path.join(w.workDir, "index.signed.json"), path.join(w.signedDir, "index.json"));
    },
    "a document over a mebibyte": (w) => fs.writeFileSync(path.join(w.signedDir, "index.json"), Buffer.alloc(1048577, 0x20)),
    "a signed result with one document missing": (w) => fs.rmSync(path.join(w.signedDir, "withdrawn.json")),
    "no result": (w) => fs.rmSync(path.join(w.signedDir, "result.json")),
    "a result for another kind": (w) => fs.writeFileSync(path.join(w.signedDir, "result.json"), fs.readFileSync(path.join(w.signedDir, "result.json"), "utf8").replace('"commands"', '"models"')),
    "something added to the prepared artifact": (w) => fs.writeFileSync(path.join(w.workDir, "extra"), ""),
  };
  for (const [name, damage] of Object.entries(bad)) {
    const w = signedWork(t);
    damage(w);
    assert.throws(() => verifyAndInstall(w), refusal("E_ARTIFACT"), name);
    assert.deepEqual(snapshot(w.dataDir), {}, `${name}: nothing is installed`);
  }

  // data moved between the preparing job and this one: another pair is there now
  const { trust, seeds } = throwawayTrust();
  const dir = scratch(t);
  const dataDir = path.join(dir, "data");
  const secret = seedSecret(seeds.models.current);
  const heldNow = () => fs.existsSync(path.join(dataDir, "state", "models.json"));
  const jobs = (now, name) => {
    const workDir = path.join(dir, `${name}-prepared`);
    const signedDir = path.join(dir, `${name}-signed`);
    prepareKind({ kind: "models", exportFile: writeExport(dir, "models", exportOf("models", { at: now, state: name.padEnd(64, "0").replace(/[^0-9a-f]/g, "a") })), dataDir, trust, now, workDir, everHeld: heldNow() });
    signPrepared({ kind: "models", workDir, outDir: signedDir, trust, secret });
    return { kind: "models", workDir, signedDir, dataDir, trust, everHeld: heldNow() };
  };
  fs.mkdirSync(dataDir);
  const first = jobs(NOW, "a1");
  const second = jobs(NOW + 5, "b2"); // prepared against the same empty data
  assert.equal(verifyAndInstall(first).outcome, "signed");
  const held = snapshot(dataDir);
  assert.throws(() => verifyAndInstall({ ...second, everHeld: true }), refusal("E_DATA_MOVED"));
  assert.deepEqual(snapshot(dataDir), held);
  // and the other way: prepared over a pair that is no longer the one on data
  const third = jobs(NOW + 10, "c3");
  const fourth = jobs(NOW + 20, "d4");
  assert.equal(verifyAndInstall(third).outcome, "signed");
  assert.throws(() => verifyAndInstall(fourth), refusal("E_DATA_MOVED"));

  // a kind that was not prepared, or not signed, is nothing to do here, quietly
  const quiet = (order, result) => {
    const d = scratch(t);
    leaveOrder(path.join(d, "prepared"), "packs", order);
    fs.mkdirSync(path.join(d, "signed"));
    fs.writeFileSync(path.join(d, "signed", "result.json"), JSON.stringify({ schema: "astra.content.signer-result/1", kind: "packs", outcome: result }));
    return verifyAndInstall({ kind: "packs", workDir: path.join(d, "prepared"), signedDir: path.join(d, "signed"), dataDir, trust, everHeld: false }).outcome;
  };
  assert.equal(quiet("closed", "closed"), "closed");
  assert.equal(quiet("refused", "not-prepared"), "not-prepared");
  assert.throws(() => quiet("closed", "unchanged"), refusal("E_PREPARED"));
  const w = signedWork(t);
  fs.rmSync(path.join(w.signedDir, "index.json"));
  fs.rmSync(path.join(w.signedDir, "withdrawn.json"));
  fs.writeFileSync(path.join(w.signedDir, "result.json"), JSON.stringify({ schema: "astra.content.signer-result/1", kind: "commands", outcome: "refused", code: "E_KEY_NOT_TRUSTED" }));
  assert.equal(verifyAndInstall(w).outcome, "not-signed");
});

test("each verifier refuses by itself, and what was signed must be what was prepared", (t) => {
  const yes = () => ({ ok: true, key_id: "x" });
  const pass = ({ kind }) => ({ ok: true, parse: null, schema: null, rules: [], verified_by: [`astra-${kind}-testa`], reason: null });
  /** Replace the signed index with the same body signed by `seed`, as a compromised key step might. */
  const resign = (w, seed, domain = domainOf("commands", "index")) => {
    const signed = JSON.parse(fs.readFileSync(path.join(w.workDir, "index.signed.json"), "utf8"));
    fs.writeFileSync(path.join(w.signedDir, "index.json"), documentBytes(signEnvelope({ domain, signed, signers: [{ key_id: "astra-commands-testa", privateKey: privateKeyFromSeed(seed) }] })));
  };
  const cases = [
    ["another key's signature", (w) => resign(w, crypto.randomBytes(32))],
    ["the kind's other key under the first one's name", (w) => resign(w, w.seeds.commands.next)],
    ["the right key over the other document's domain", (w) => resign(w, w.seeds.commands.current, domainOf("commands", "withdrawn"))],
  ];
  for (const [name, damage] of cases) {
    // this repository's verifier alone (the specification's is told to pass everything)
    let w = signedWork(t);
    damage(w);
    assert.throws(() => verifyAndInstall({ ...w, check: pass }), refusal("E_SELF_VERIFY_NODE"), name);
    assert.deepEqual(snapshot(w.dataDir), {}, `${name}: nothing is installed`);
    // the specification's verifier alone
    w = signedWork(t);
    damage(w);
    assert.throws(() => verifyAndInstall({ ...w, verify: yes }), refusal("E_SELF_VERIFY_SPEC"), name);
    assert.deepEqual(snapshot(w.dataDir), {}, `${name}: nothing is installed`);
  }
  // the specification's verifier must name exactly the signing key, not merely say ok
  let w = signedWork(t);
  assert.throws(() => verifyAndInstall({ ...w, check: (o) => ({ ...checkDocument(o), verified_by: [] }) }), refusal("E_SELF_VERIFY_SPEC"));
  w = signedWork(t);
  assert.throws(() => verifyAndInstall({ ...w, check: (o) => ({ ...checkDocument(o), verified_by: ["astra-commands-testb"] }) }), refusal("E_SELF_VERIFY_SPEC"));

  // a validly signed document over a body other than the one that was checked
  w = signedWork(t);
  const other = { ...JSON.parse(fs.readFileSync(path.join(w.workDir, "index.signed.json"), "utf8")), entries: [] };
  fs.writeFileSync(path.join(w.signedDir, "index.json"), documentBytes(signEnvelope({ domain: domainOf("commands", "index"), signed: other, signers: [{ key_id: "astra-commands-testa", privateKey: privateKeyFromSeed(w.seeds.commands.current) }] })));
  assert.throws(() => verifyAndInstall(w), refusal("E_SIGNED_OTHER"));
  // two signatures, or a result naming a key of another kind
  w = signedWork(t);
  const env = JSON.parse(fs.readFileSync(path.join(w.signedDir, "index.json"), "utf8"));
  fs.writeFileSync(path.join(w.signedDir, "index.json"), documentBytes({ ...env, signatures: [...env.signatures, ...env.signatures] }));
  assert.throws(() => verifyAndInstall(w), refusal("E_SELF_VERIFY"));
  w = signedWork(t);
  fs.writeFileSync(path.join(w.signedDir, "result.json"), fs.readFileSync(path.join(w.signedDir, "result.json"), "utf8").replace("astra-commands-testa", "astra-models-testa"));
  assert.throws(() => verifyAndInstall(w), refusal("E_SELF_VERIFY"));
  // a key step that claims "unchanged" for an order that was not
  w = signedWork(t);
  fs.writeFileSync(path.join(w.signedDir, "result.json"), fs.readFileSync(path.join(w.signedDir, "result.json"), "utf8").replace('"signed"', '"unchanged"'));
  assert.throws(() => verifyAndInstall(w), refusal("E_ARTIFACT"), "an unchanged result that still carries documents");
  fs.rmSync(path.join(w.signedDir, "index.json"));
  fs.rmSync(path.join(w.signedDir, "withdrawn.json"));
  assert.throws(() => verifyAndInstall(w), refusal("E_PREPARED"));
  assert.deepEqual(snapshot(w.dataDir), {});

  // a link put where a document goes, after the kind was prepared: nothing is written through it
  w = signedWork(t);
  const outside = scratch(t, "outside");
  fs.mkdirSync(path.join(w.dataDir, "registry", "v1"), { recursive: true });
  fs.symlinkSync(outside, path.join(w.dataDir, "registry", "v1", "commands"));
  assert.throws(() => verifyAndInstall(w), refusal("E_DATA_SYMLINK"));
  assert.deepEqual(fs.readdirSync(outside), []);

  // untouched, both verifiers pass and the three files are installed
  w = signedWork(t);
  assert.equal(verifyAndInstall(w).outcome, "signed");
  assert.equal(Object.keys(snapshot(w.dataDir)).length, 3);
  void verifyEnvelope;
  void DOCS;
});

test("a refusal prints a code and a sanitised location, never a value", (t) => {
  assert.equal(sanitise("::error file=x::boom\n$/entries/0/owner e-mail a@b.org"), "errorfilexboom$/entries/0/ownere-maila.org".replace("a.org", "ab.org"));
  assert.equal(sanitise("x".repeat(500)).length, 200);
  assert.equal(new Refused("E_X", "prose with a value", "$/a b/::set-output::").line(), "E_X at $/ab/set-output");

  const { doc, roots, seeds } = throwawayTrust();
  const entry = golden("index/commands/valid.json").signed.entries[0];
  const secretWord = "PRIVATE-NOTE-41";
  const hostile = [
    // a value where the schema wants another, a member the schema does not have, and names that try to be workflow commands
    (a) => (a.entries[0].review = `::error::${secretWord}`),
    (a) => (a.entries[0][`::warning file=a::${secretWord}`] = "x"),
    (a) => (a[`::add-mask::${secretWord}`] = 1),
    (a) => (a.withdrawn[`\n::error::${secretWord}`] = []),
    (a) => (a.entries[0].published_at = 1.5),
    (a) => (a.entries[0].author = "\ud800"),
    (a) => (a.kind = `${secretWord}`),
  ];
  for (const [i, mutate] of hostile.entries()) {
    const dir = scratch(t);
    const exportsDir = path.join(dir, "exports");
    fs.mkdirSync(exportsDir);
    fs.mkdirSync(path.join(dir, "data"));
    const answer = structuredClone(exportOf("commands", { entries: [entry] }));
    mutate(answer);
    // written by a serialiser that keeps a lone surrogate as the service's might
    writeExport(exportsDir, "commands", answer);
    fs.writeFileSync(path.join(exportsDir, "work.json"), JSON.stringify({ kinds: { commands: "fetched" } }));
    fs.writeFileSync(path.join(dir, "trust.json"), JSON.stringify(doc));
    const lines = [];
    const summary = path.join(dir, "summary");
    const code = prepareMain(["--kind", "commands", "--exports", exportsDir, "--data", path.join(dir, "data"), "--trust", path.join(dir, "trust.json"), "--work", path.join(dir, "work")], {
      env: { GITHUB_STEP_SUMMARY: summary },
      now: NOW,
      roots,
      log: (l) => lines.push(l),
    });
    assert.equal(code, 1, `case ${i}`);
    const printed = lines.join("\n") + fs.readFileSync(summary, "utf8");
    assert.match(lines[0], /^commands: not signed \(E_[A-Z_]+( at [A-Za-z0-9_.\/$-]{1,200})?\); the last signed documents stay$/, `case ${i}: ${lines[0]}`);
    assert.ok(!printed.includes("::") && !printed.includes(secretWord.slice(0, 7)) && !printed.includes("@"), `case ${i}: ${printed}`);
  }
  // the job with the key prints nothing a file gave it either
  const dir = scratch(t);
  const { trust } = throwawayTrust();
  void trust;
  fs.mkdirSync(path.join(dir, "data"));
  const mine = throwawayTrust();
  prepareKind({ kind: "commands", exportFile: writeExport(dir, "commands", exportOf("commands")), dataDir: path.join(dir, "data"), trust: mine.trust, now: NOW, workDir: path.join(dir, "prepared"), everHeld: false });
  const orderFile = path.join(dir, "prepared", "order.json");
  fs.writeFileSync(orderFile, JSON.stringify({ ...JSON.parse(fs.readFileSync(orderFile, "utf8")), last_key_id: `::error::${secretWord}`, now: `::error::${secretWord}` }));
  fs.writeFileSync(path.join(dir, "prepared", `::notice::${secretWord}`), "");
  for (const remove of [false, true]) {
    if (remove) fs.rmSync(path.join(dir, "prepared", `::notice::${secretWord}`));
    const lines = [];
    const code = signMain(["--kind", "commands", "--work", path.join(dir, "prepared"), "--out", path.join(dir, "signed")], { env: { CONTENT_SIGNING_KEY: seedSecret(mine.seeds.commands.current) }, now: NOW, roots: mine.roots, log: (l) => lines.push(l) });
    assert.equal(code, 1);
    assert.deepEqual(lines, [`commands: not signed (${remove ? "E_PREPARED" : "E_ARTIFACT"}); the last signed documents stay`]);
    assert.deepEqual(fs.readdirSync(path.join(dir, "signed")), ["result.json"]);
    assert.ok(!fs.readFileSync(path.join(dir, "signed", "result.json"), "utf8").includes(secretWord));
  }
});

test("the checker is started isolated, with PATH and nothing else", (t) => {
  const self = checkerSelf();
  assert.equal(self.isolated, true, "python -I: no PYTHON* variable, no user site, no script directory on the path");
  // Python itself may add LC_CTYPE when it coerces the C locale; nothing of ours is there
  assert.deepEqual(self.env.filter((n) => n !== "LC_CTYPE"), ["PATH"]);
  const inv = invocation({ PATH: "/usr/bin", HOME: "/home/x", CONTENT_SIGNING_KEY: "k", GITHUB_TOKEN: "t", PYTHONPATH: "/evil", ACTIONS_ID_TOKEN_REQUEST_TOKEN: "o" });
  assert.deepEqual(inv.env, { PATH: "/usr/bin" });
  assert.deepEqual(inv.args.slice(0, 2), ["-I", "-B"]);
  // and it is: a PYTHONPATH in this process that shadows a module the checker imports changes nothing
  const evil = scratch(t, "evil");
  fs.writeFileSync(path.join(evil, "json.py"), "raise SystemExit('shadowed')\n");
  const before = process.env.PYTHONPATH;
  process.env.PYTHONPATH = evil;
  t.after(() => (before === undefined ? delete process.env.PYTHONPATH : (process.env.PYTHONPATH = before)));
  assert.equal(checkerSelf().isolated, true);
});

test("a kind's key is that kind's alone in trust.json", () => {
  const row = (kind, role, n, pub = crypto.randomBytes(32).toString("base64")) => ({ kind, role, key_id: `astra-${kind}-${n}`, alg: "ed25519", public_key: pub, not_before: role === "current" ? "2026-01-01T00:00:00Z" : "2026-01-02T00:00:00Z" });
  const base = () => [row("commands", "current", "a"), row("commands", "next", "b"), row("models", "current", "a"), row("models", "next", "b")];
  const bad = (name, signed) => assert.throws(() => kindKeysOf(signed, "commands"), refusal("E_TRUST_KIND_KEYS"), name);
  assert.equal(kindKeysOf({ kind_keys: base() }, "commands").current.key_id, "astra-commands-a");

  let k = base();
  k[2].public_key = k[0].public_key;
  bad("another kind's row holds the same public key", { kind_keys: k });
  k = base();
  k[3].key_id = k[1].key_id;
  bad("another kind's row holds the same key id", { kind_keys: k });
  k = base();
  bad("an index key holds the same public key", { kind_keys: k, index_keys: [{ key_id: "astra-index-x", public_key: k[1].public_key }] });
  k = base();
  bad("an index key holds the same key id", { kind_keys: k, index_keys: [{ key_id: k[0].key_id, public_key: crypto.randomBytes(32).toString("base64") }] });
  k = base();
  k[1].public_key = k[0].public_key;
  bad("current and next are one key", { kind_keys: k });
  k = base();
  k[1].not_before = k[0].not_before;
  bad("next does not start after current", { kind_keys: k });
  bad("three rows", { kind_keys: [...base(), row("commands", "next", "c")] });
  bad("no kind_keys", {});
});
