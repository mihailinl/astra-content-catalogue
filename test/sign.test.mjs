// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// The signing of one kind (lib/pipeline.mjs). No network: the answers are
// built here or taken from the specification's goldens.

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";

import { jcs } from "../vendor/astra-registry/tools/lib/canonical.mjs";
import { carryRows, lifts } from "../lib/carry.mjs";
import { checkDocument } from "../lib/checker.mjs";
import { prepareKind } from "../lib/pipeline.mjs";
import { DOCS, documentPath, EXPORT_MAX_AGE, EXPORT_MAX_AHEAD, KINDS, MAX_DOCUMENT_BYTES, MAX_EXPORT_BYTES, Refused, RESIGN_AFTER, statePath } from "../lib/kinds.mjs";
import { exportOf, golden, GOLDENS, goldenTrust, iso, NOW, plant, scratch, seedSecret, signKind, snapshot, testSeed, throwawayTrust, writeExport } from "./helpers.mjs";

const read = (dir, kind, doc) => JSON.parse(fs.readFileSync(path.join(dir, documentPath(kind, doc)), "utf8"));
const refusal = (code) => (e) => e instanceof Refused && e.code === code;

/** One run of the pipeline over a built answer, under throwaway keys unless told otherwise. */
function run(t, o) {
  const dir = o.dir ?? scratch(t);
  const dataDir = o.dataDir ?? path.join(dir, "data");
  fs.mkdirSync(dataDir, { recursive: true });
  const now = o.now ?? NOW;
  // an answer is generated when it is asked for, unless the test is about its age
  const answer = o.export && !o.keepTime ? { ...o.export, generated_at: iso(now) } : o.export;
  const exportFile = writeExport(dir, o.kind, answer, { raw: o.raw ?? null });
  return signKind({ kind: o.kind, exportFile, dataDir, trust: o.trust, secret: o.secret, now, tmpDir: dir, ...("everHeld" in o ? { everHeld: o.everHeld } : {}), verify: o.verify, check: o.check });
}

test("a golden round trip: the signer reproduces every valid golden, and the vendored verifier accepts it", (t) => {
  const { trust } = goldenTrust();
  for (const kind of KINDS) {
    const dir = scratch(t, kind);
    const dataDir = path.join(dir, "data");
    const want = { index: golden(`index/${kind}/valid.json`), withdrawn: golden(`withdrawn/${kind}/valid.json`) };
    const answer = exportOf(kind, { entries: want.index.signed.entries, rows: want.withdrawn.signed.rows, lifts: want.withdrawn.signed.lifts });
    const report = run(t, { dir, dataDir, kind, export: answer, trust, secret: seedSecret(testSeed(`astra-${kind}-2026a`)) });
    assert.equal(report.outcome, "signed");
    assert.equal(report.carried, 0);
    for (const doc of DOCS) {
      const got = read(dataDir, kind, doc);
      // Ed25519 is deterministic: the same body under the same key is the same signature
      assert.deepEqual(got.signed, want[doc].signed, `${kind} ${doc}: the signed body`);
      assert.deepEqual(got.signatures, want[doc].signatures, `${kind} ${doc}: the signature`);
      const verdict = checkDocument({ file: path.join(dataDir, documentPath(kind, doc)), kind, doc, now: NOW, trust: trust.signed });
      assert.deepEqual(verdict.verified_by, [`astra-${kind}-2026a`], `${kind} ${doc}: verified by the current key`);
      assert.equal(verdict.ok, true);
      // and under no other kind's keys, nor as the other document of its own kind
      const other = KINDS[(KINDS.indexOf(kind) + 1) % KINDS.length];
      assert.equal(checkDocument({ file: path.join(dataDir, documentPath(kind, doc)), kind: other, doc, now: NOW, trust: trust.signed }).ok, false);
    }
    const state = JSON.parse(fs.readFileSync(path.join(dataDir, statePath(kind)), "utf8"));
    assert.deepEqual(state, { schema: "astra.content.signer-state/1", kind, state_sha256: answer.state_sha256, issued_at: NOW, key_id: `astra-${kind}-2026a`, carried: 0 });
  }
});

test("an entry without a thumbnail is signed for four kinds, and refused for packs", (t) => {
  // AstraPlugins #177: the thumbnail is optional for commands, characters, models and animsets
  // (the member is absent, never null) and stays required for packs.
  const { trust } = goldenTrust();
  for (const kind of ["commands", "characters", "models", "animsets"]) {
    const want = golden(`index/${kind}/no-thumbnail.json`);
    assert.ok(want.signed.entries.length > 0 && want.signed.entries.every((e) => !("thumbnail" in e)), kind);
    const dir = scratch(t, kind);
    const report = run(t, { dir, kind, export: exportOf(kind, { entries: want.signed.entries }), trust, secret: seedSecret(testSeed(`astra-${kind}-2026a`)) });
    assert.equal(report.outcome, "signed", kind);
    const got = read(path.join(dir, "data"), kind, "index");
    assert.deepEqual(got.signed.entries, want.signed.entries, kind);
    assert.deepEqual(got.signatures, want.signatures, `${kind}: the golden's own signature`);
  }
  const refused = (kind, entries, where) => {
    const dir = scratch(t);
    assert.throws(
      () => run(t, { dir, kind, export: exportOf(kind, { entries }), trust, secret: seedSecret(testSeed(`astra-${kind}-2026a`)) }),
      (e) => e instanceof Refused && e.code === "E_DOCUMENT_REFUSED" && e.where === where,
      `${kind}: ${where}`,
    );
    assert.deepEqual(snapshot(path.join(dir, "data")), {});
  };
  refused("packs", golden("index/packs/no-thumbnail.json").signed.entries, "index/schema//signed/entries/0");
  refused("commands", golden("index/commands/thumbnail-null.json").signed.entries, "index/schema//signed/entries/0/thumbnail");
  // and a pack with its thumbnail is signed as before
  assert.equal(run(t, { kind: "packs", export: exportOf("packs", { entries: golden("index/packs/valid.json").signed.entries }), trust, secret: seedSecret(testSeed("astra-packs-2026a")) }).outcome, "signed");
});

test("the published bytes are canonical JSON and the same for the same input", (t) => {
  const { trust, seeds } = throwawayTrust();
  const entries = golden("index/commands/valid.json").signed.entries;
  const bytes = [entries, [...entries]].map((e) => {
    const dir = scratch(t);
    run(t, { dir, kind: "commands", export: exportOf("commands", { entries: e }), trust, secret: seedSecret(seeds.commands.current) });
    return fs.readFileSync(path.join(dir, "data", documentPath("commands", "index")));
  });
  assert.ok(bytes[0].equals(bytes[1]));
  const text = bytes[0].toString("utf8");
  assert.ok(text.startsWith('{"signatures":[{"key_id":"astra-commands-testa","sig":"'), "members in code-unit order, no whitespace");
  assert.ok(!/\s$/.test(text));
});

// The specification's own sequence: a security row is published (seq-1), the
// next answer leaves it out (seq-2), the next lifts it at the wrong second
// (seq-3), the last lifts it exactly (seq-4).
const seq = (n) => golden(`withdrawn/commands/${n}.json`).signed;

test("a_dropped_row_is_carried", (t) => {
  const { trust, seeds } = throwawayTrust();
  const dir = scratch(t);
  const dataDir = path.join(dir, "data");
  const base = { dir, dataDir, kind: "commands", trust, secret: seedSecret(seeds.commands.current) };
  const row = seq("seq-1-security").rows[0];

  assert.equal(run(t, { ...base, export: exportOf("commands", { rows: seq("seq-1-security").rows }), now: NOW }).carried, 0);

  // the answer drops the row and says nothing about it
  const dropped = run(t, { ...base, export: exportOf("commands", { rows: seq("seq-2-row-dropped").rows }), now: NOW + 3600 });
  assert.equal(dropped.outcome, "signed", "the kept row is published");
  assert.equal(dropped.carried, 1, "and the run is marked to fail");
  assert.deepEqual(read(dataDir, "commands", "withdrawn").signed.rows, [row]);
  assert.equal(JSON.parse(fs.readFileSync(path.join(dataDir, statePath("commands")), "utf8")).carried, 1);

  // the same answer again inside six hours: nothing is signed, and the run is still marked
  const again = run(t, { ...base, export: exportOf("commands", { rows: [] }), now: NOW + 3700 });
  assert.equal(again.outcome, "unchanged");
  assert.equal(again.carried, 1);

  // a row the answer states itself is not counted twice
  const restated = run(t, { ...base, export: exportOf("commands", { rows: [row], state: "a".repeat(64) }), now: NOW + 3800 });
  assert.equal(restated.carried, 0);
  assert.deepEqual(read(dataDir, "commands", "withdrawn").signed.rows, [row]);

  // an answer that brings a new row and drops the old one keeps both, the answer's first
  const fresh = { ...row, id: "another-item", at: row.at + 5 };
  const both = run(t, { ...base, export: exportOf("commands", { rows: [fresh] }), now: NOW + 3900 });
  assert.equal(both.carried, 1);
  assert.deepEqual(read(dataDir, "commands", "withdrawn").signed.rows, [fresh, row]);
});

test("a_lift_matches_its_row_by_strings", (t) => {
  const row = seq("seq-1-security").rows[0];
  const exact = seq("seq-4-lift").lifts[0];
  assert.equal(lifts(exact, row), true);
  assert.equal(lifts(seq("seq-3-lift-wrong-at").lifts[0], row), false, "one second off is another decision");
  assert.equal(lifts({ ...exact, id: "evil-shell-2" }, row), false);
  // the same versions, spelt another way: not this row's lift
  assert.equal(lifts({ ...exact, versions: ">=0.0.0,<=1.0.0" }, row), false);
  assert.equal(lifts({ ...exact, versions: "<1.0.1" }, row), false);
  assert.equal(lifts({ ...exact, lifts_at: String(row.at) }, row), false, "a second is a number");
  assert.deepEqual(carryRows({ previousRows: [row], rows: [], lifts: [exact] }), { rows: [], carried: [] });

  const { trust, seeds } = throwawayTrust();
  const dir = scratch(t);
  const dataDir = path.join(dir, "data");
  const base = { dir, dataDir, kind: "commands", trust, secret: seedSecret(seeds.commands.current) };
  run(t, { ...base, export: exportOf("commands", { rows: [row] }), now: NOW });

  const wrongAt = run(t, { ...base, export: exportOf("commands", { lifts: seq("seq-3-lift-wrong-at").lifts }), now: NOW + 10 });
  assert.equal(wrongAt.carried, 1, "a lift at another second lifts nothing");
  assert.deepEqual(read(dataDir, "commands", "withdrawn").signed.rows, [row]);

  const respelt = run(t, { ...base, export: exportOf("commands", { lifts: [{ ...exact, versions: ">=0.0.0,<=1.0.0" }] }), now: NOW + 20 });
  assert.equal(respelt.carried, 1, "a lift over an equal range spelt differently lifts nothing");

  const lifted = run(t, { ...base, export: exportOf("commands", { lifts: [exact] }), now: NOW + 30 });
  assert.equal(lifted.carried, 0);
  assert.deepEqual(read(dataDir, "commands", "withdrawn").signed, { ...read(dataDir, "commands", "withdrawn").signed, rows: [], lifts: [exact] });
});

test("serial_never_goes_back", (t) => {
  const { trust, seeds } = throwawayTrust();
  const dir = scratch(t);
  const dataDir = path.join(dir, "data");
  const base = { dir, dataDir, kind: "models", trust, secret: seedSecret(seeds.models.current) };
  const entries = golden("index/models/valid.json").signed.entries;
  run(t, { ...base, export: exportOf("models", { entries }), now: NOW });
  const before = snapshot(dataDir);
  const changed = exportOf("models", { entries: [] });

  for (const now of [NOW, NOW - 1, NOW - 86400]) {
    assert.throws(() => run(t, { ...base, export: changed, now }), refusal("E_SERIAL_BACK"), `a clock at ${now - NOW}s`);
    assert.deepEqual(snapshot(dataDir), before, "and the last pair is untouched");
  }
  // the floor is the serial the verified documents carry, never the state file's word for it:
  // a state file that names an earlier second is a mismatch, not a lower floor
  const stateFile = path.join(dataDir, statePath("models"));
  const state = JSON.parse(fs.readFileSync(stateFile, "utf8"));
  fs.writeFileSync(stateFile, JSON.stringify({ ...state, issued_at: NOW - 1000 }));
  assert.throws(() => run(t, { ...base, export: changed, now: NOW - 500 }), refusal("E_STATE_MISMATCH"));
  fs.writeFileSync(stateFile, JSON.stringify(state));
  // and each document's serial counts by itself: a pair whose two serials differ is no pair
  for (const doc of DOCS) {
    const d2 = scratch(t);
    plant(path.join(d2, "data"), "models", { seed: seeds.models.current, keyId: "astra-models-testa", serial: NOW, serials: { [doc]: NOW + 50 } });
    assert.throws(() => run(t, { ...base, dir: d2, dataDir: path.join(d2, "data"), export: changed, now: NOW + 10 }), refusal("E_PREVIOUS_PAIR"), doc);
  }

  const next = run(t, { ...base, export: changed, now: NOW + 1 });
  assert.equal(next.issued_at, NOW + 1);
  for (const doc of DOCS) {
    const s = read(dataDir, "models", doc).signed;
    assert.equal(s.serial, NOW + 1);
    assert.equal(s.issued_at, s.serial);
    assert.equal(s.expires_at, s.issued_at + 7 * 86400);
  }
});

test("over_one_mebibyte_is_not_signed", (t) => {
  const { trust, seeds } = throwawayTrust();
  const dir = scratch(t);
  const dataDir = path.join(dir, "data");
  const base = { dir, dataDir, kind: "commands", trust, secret: seedSecret(seeds.commands.current) };
  const entry = golden("index/commands/valid.json").signed.entries[0];
  const many = (n) => Array.from({ length: n }, (_, i) => ({ ...entry, id: `item-${i}` }));
  const one = Buffer.byteLength(jcs({ ...entry, id: "item-1000" })) + 1;

  run(t, { ...base, export: exportOf("commands", { entries: many(3) }), now: NOW });
  const before = snapshot(dataDir);

  const over = Math.ceil(MAX_DOCUMENT_BYTES / one) + 2;
  assert.throws(() => run(t, { ...base, export: exportOf("commands", { entries: many(over) }), now: NOW + 10 }), refusal("E_DOCUMENT_SIZE"));
  assert.deepEqual(snapshot(dataDir), before, "the last signed pair stays");

  // the withdrawn document has the same bound
  const row = { ...seq("seq-1-security").rows[0], reason_text: "x".repeat(500) };
  const rows = Array.from({ length: 1800 }, (_, i) => ({ ...row, id: `item-${i}` }));
  assert.throws(() => run(t, { ...base, export: exportOf("commands", { rows }), now: NOW + 20 }), refusal("E_DOCUMENT_SIZE"));
  assert.deepEqual(snapshot(dataDir), before);

  // just under the bound is signed, and what is published is within it
  const under = Math.floor((MAX_DOCUMENT_BYTES - 4096) / one);
  const ok = run(t, { ...base, export: exportOf("commands", { entries: many(under) }), now: NOW + 30 });
  assert.equal(ok.outcome, "signed");
  assert.ok(ok.bytes.index <= MAX_DOCUMENT_BYTES && ok.bytes.index > MAX_DOCUMENT_BYTES - 8192, `${ok.bytes.index} bytes`);
  assert.equal(fs.statSync(path.join(dataDir, documentPath("commands", "index"))).size, ok.bytes.index);
});

test("the_signer_signs_only_with_one_of_the_kinds_two_trusted_keys", (t) => {
  const { trust, seeds } = throwawayTrust();
  const answer = exportOf("packs", { entries: golden("index/packs/valid.json").signed.entries });
  const attempt = (secret, o = {}) => {
    const dir = o.dir ?? scratch(t);
    const report = run(t, { dir, kind: "packs", export: o.export ?? answer, trust: o.trust ?? trust, secret, now: o.now ?? NOW });
    return { report, dir: path.join(dir, "data") };
  };
  const nothing = (secret, code, o = {}) => {
    const dir = scratch(t);
    assert.throws(() => run(t, { dir, kind: "packs", export: answer, trust: o.trust ?? trust, secret, now: o.now ?? NOW }), refusal(code));
    assert.deepEqual(snapshot(path.join(dir, "data")), {}, `${code}: nothing is written`);
  };

  // a key of another kind, current or next; a key trust.json does not hold; no key; not a key
  nothing(seedSecret(seeds.models.current), "E_KEY_NOT_TRUSTED");
  nothing(seedSecret(seeds.models.next), "E_KEY_NOT_TRUSTED");
  nothing(seedSecret(crypto.randomBytes(32)), "E_KEY_NOT_TRUSTED");
  nothing(undefined, "E_KEY_ABSENT");
  nothing("  \n", "E_KEY_ABSENT");
  nothing("not a key", "E_KEY_FORMAT");
  nothing(crypto.randomBytes(31).toString("base64"), "E_KEY_FORMAT");

  // either key of the kind signs, alone, under its own key id, and the verifier names it
  for (const [role, keyId] of [["current", "astra-packs-testa"], ["next", "astra-packs-testb"]]) {
    const { report, dir } = attempt(seedSecret(seeds.packs[role]));
    assert.deepEqual({ key_id: report.key_id, role: report.role }, { key_id: keyId, role });
    for (const doc of DOCS) {
      const env = read(dir, "packs", doc);
      assert.deepEqual(env.signatures.map((s) => s.key_id), [keyId], `${doc}: one signature, by the key in the job`);
      const verdict = checkDocument({ file: path.join(dir, documentPath("packs", doc)), kind: "packs", doc, now: NOW, trust: trust.signed });
      assert.deepEqual(verdict.verified_by, [keyId]);
    }
    assert.equal(JSON.parse(fs.readFileSync(path.join(dir, statePath("packs")), "utf8")).key_id, keyId);
  }
  // the same key as a PKCS#8 PEM, with the newline a file ends in
  const pem = crypto
    .createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seeds.packs.current]), format: "der", type: "pkcs8" })
    .export({ format: "pem", type: "pkcs8" });
  assert.equal(attempt(`${pem}\n`).report.key_id, "astra-packs-testa");
  assert.equal(attempt(`${seedSecret(seeds.packs.current)}\n`).report.outcome, "signed");

  // a trusted key signs nothing before its not_before: the next key between the two starts, either key before both
  const late = throwawayTrust({ now: NOW + 40 * 86400 }); // current from NOW + 10 d, next from NOW + 11 d
  nothing(seedSecret(late.seeds.packs.current), "E_KEY_NOT_YET", { trust: late.trust });
  nothing(seedSecret(late.seeds.packs.next), "E_KEY_NOT_YET", { trust: late.trust, now: NOW + 10 * 86400 + 3600 });
  assert.equal(attempt(seedSecret(late.seeds.packs.current), { trust: late.trust, now: NOW + 10 * 86400 + 3600 }).report.role, "current");
  assert.equal(attempt(seedSecret(late.seeds.packs.next), { trust: late.trust, now: NOW + 11 * 86400 }).report.role, "next");
});

test("a rotation: the next key signs at once, and the current key does not sign again", (t) => {
  const { trust, seeds } = throwawayTrust();
  const dir = scratch(t);
  const dataDir = path.join(dir, "data");
  const answer = exportOf("models", { entries: golden("index/models/valid.json").signed.entries });
  const base = { dir, dataDir, kind: "models", export: answer, trust };
  assert.equal(run(t, { ...base, secret: seedSecret(seeds.models.current), now: NOW }).key_id, "astra-models-testa");

  // ten minutes later the environment holds the next key: the unchanged answer is signed again, now
  const rotated = run(t, { ...base, secret: seedSecret(seeds.models.next), now: NOW + 600 });
  assert.deepEqual({ outcome: rotated.outcome, key_id: rotated.key_id, role: rotated.role, issued_at: rotated.issued_at }, { outcome: "signed", key_id: "astra-models-testb", role: "next", issued_at: NOW + 600 });
  const after = snapshot(dataDir);

  // the switch is one-way: the old key back in the environment signs nothing
  assert.throws(() => run(t, { ...base, secret: seedSecret(seeds.models.current), now: NOW + 1200 }), refusal("E_KEY_SWITCHED_BACK"));
  assert.deepEqual(snapshot(dataDir), after);

  // the ceremony later names that key current, with a new next: the same secret goes on signing
  const promoted = throwawayTrust({
    mutate: (signed) => {
      const fresh = signed.kind_keys.find((k) => k.kind === "models" && k.role === "next");
      signed.kind_keys = signed.kind_keys.filter((k) => k.kind !== "models").concat([
        { ...trust.kindKeys("models").next, role: "current", notBefore: undefined },
        { ...fresh, key_id: "astra-models-testc", not_before: "2026-12-30T00:00:00Z" },
      ]);
    },
  });
  const later = run(t, { ...base, trust: promoted.trust, secret: seedSecret(seeds.models.next), now: NOW + 7 * 3600 });
  assert.deepEqual({ outcome: later.outcome, key_id: later.key_id, role: later.role }, { outcome: "signed", key_id: "astra-models-testb", role: "current" });
});

test("an_export_with_an_account_fact_is_refused", (t) => {
  const { trust, seeds } = throwawayTrust();
  const entries = golden("index/commands/valid.json").signed.entries;
  const w = golden("withdrawn/commands/valid.json").signed;
  const good = () => structuredClone(exportOf("commands", { entries, rows: w.rows, lifts: w.lifts }));
  const refused = (name, mutate, code) => {
    const dir = scratch(t);
    const answer = good();
    mutate(answer);
    assert.throws(() => run(t, { dir, kind: "commands", export: answer, trust, secret: seedSecret(seeds.commands.current) }), refusal(code), name);
    assert.deepEqual(snapshot(path.join(dir, "data")), {}, `${name}: nothing is written`);
  };
  // the unchanged answer is signed, so each refusal below is the one member's doing
  assert.equal(run(t, { kind: "commands", export: good(), trust, secret: seedSecret(seeds.commands.current) }).outcome, "signed");

  refused("a member beside the six", (a) => (a.owner_account_id = "acc_1"), "E_EXPORT_MEMBER");
  refused("a member with an empty value", (a) => (a.moderator = null), "E_EXPORT_MEMBER");
  refused("a member inside withdrawn", (a) => (a.withdrawn.reports = []), "E_EXPORT_MEMBER");
  refused("a member inside an entry", (a) => (a.entries[0].owner_account_id = "acc_1"), "E_DOCUMENT_REFUSED");
  refused("a member inside an entry's author facts", (a) => (a.entries[0].thumbnail.uploader_email = "a@example.org"), "E_DOCUMENT_REFUSED");
  refused("a member inside a row", (a) => (a.withdrawn.rows[0].moderator = "m"), "E_DOCUMENT_REFUSED");
  refused("a member inside a lift", (a) => (a.withdrawn.lifts[0].note = "n"), "E_DOCUMENT_REFUSED");

  refused("another kind's answer", (a) => (a.kind = "models"), "E_EXPORT_KIND");
  refused("another schema", (a) => (a.schema = "astra.content.export/2"), "E_EXPORT_SHAPE");
  refused("no lifts", (a) => delete a.withdrawn.lifts, "E_EXPORT_SHAPE");
  refused("a state that is not a digest", (a) => (a.state_sha256 = "ABC"), "E_EXPORT_SHAPE");

  // read strictly: a member named twice, and a number that is not an integer
  const raw = (name, text, code) => {
    const dir = scratch(t);
    assert.throws(() => run(t, { dir, kind: "commands", raw: text, trust, secret: seedSecret(seeds.commands.current) }), refusal(code), name);
  };
  const text = JSON.stringify(good());
  raw("a duplicate member name", text.replace('"kind":"commands"', '"kind":"models","kind":"commands"'), "E_EXPORT_PARSE");
  raw("a fraction", text.replace(/"published_at":(\d+)/, '"published_at":$1.5'), "E_EXPORT_PARSE");
  raw("not JSON", text.slice(0, -1), "E_EXPORT_PARSE");
});

test("a document the specification's checker refuses is not signed", (t) => {
  const { trust, seeds } = throwawayTrust();
  const base = { kind: "commands", trust, secret: seedSecret(seeds.commands.current) };
  const row = seq("seq-1-security").rows[0];
  const cases = {
    "lift-not-contradicted": exportOf("commands", { rows: [row], lifts: [{ id: row.id, versions: row.versions, lifts_at: row.at }] }),
    "security-pairs": exportOf("commands", { rows: [{ ...row, act: "retired", floor_effect: "disarm" }] }),
    "unique-id-version": exportOf("commands", { entries: [1, 2].map(() => golden("index/commands/valid.json").signed.entries[0]) }),
  };
  for (const [rule, answer] of Object.entries(cases)) {
    const dir = scratch(t);
    assert.throws(
      () => run(t, { ...base, dir, export: answer }),
      (e) => e instanceof Refused && e.code === "E_DOCUMENT_REFUSED" && e.line() === `E_DOCUMENT_REFUSED at ${rule === "unique-id-version" ? "index" : "withdrawn"}/rule/${rule}`,
      rule,
    );
    assert.deepEqual(snapshot(path.join(dir, "data")), {});
  }
});

test("an unchanged kind is signed again only after six hours, or under another key", (t) => {
  const { trust, seeds } = throwawayTrust();
  const dir = scratch(t);
  const dataDir = path.join(dir, "data");
  const base = { dir, dataDir, kind: "animsets", trust, secret: seedSecret(seeds.animsets.current) };
  const answer = exportOf("animsets", { entries: golden("index/animsets/valid.json").signed.entries });
  assert.equal(run(t, { ...base, export: answer, now: NOW }).outcome, "signed");
  const first = snapshot(dataDir);

  const soon = run(t, { ...base, export: { ...answer, generated_at: "2026-12-31T05:00:00Z" }, now: NOW + RESIGN_AFTER - 1 });
  assert.deepEqual(soon, { kind: "animsets", outcome: "unchanged", issued_at: NOW, key_id: "astra-animsets-testa", role: "current", carried: 0 });
  assert.deepEqual(snapshot(dataDir), first);

  assert.equal(run(t, { ...base, export: answer, now: NOW + RESIGN_AFTER }).issued_at, NOW + RESIGN_AFTER);
  assert.equal(run(t, { ...base, export: { ...answer, state_sha256: "b".repeat(64) }, now: NOW + RESIGN_AFTER + 60 }).outcome, "signed");

  // a trust.json that holds neither key the pair was signed with proves nothing about the pair:
  // the kind is not signed over it (README, "When both keys of a kind are replaced")
  const unrelated = throwawayTrust({ suffixes: ["c", "d"] });
  assert.throws(
    () => run(t, { ...base, export: answer, trust: unrelated.trust, secret: seedSecret(unrelated.seeds.animsets.current), now: NOW + RESIGN_AFTER + 120 }),
    refusal("E_PREVIOUS_UNVERIFIED"),
  );
});

test("what is on the data branch is proven before anything is built on it", (t) => {
  const { trust, seeds } = throwawayTrust();
  const rows = golden("withdrawn/characters/valid.json").signed.rows;
  const secret = seedSecret(seeds.characters.current);
  /** A data directory holding characters signed at NOW with one withdrawn row, then damaged. */
  const damaged = (name, damage, code, o = {}) => {
    const dir = scratch(t);
    const dataDir = path.join(dir, "data");
    const base = { dir, dataDir, kind: "characters", trust, secret };
    run(t, { ...base, export: exportOf("characters", { rows }), now: NOW });
    damage(dataDir);
    const before = snapshot(dataDir);
    assert.throws(() => run(t, { ...base, export: exportOf("characters"), now: NOW + 60, ...o }), refusal(code), name);
    if (!o.skipSnapshot) assert.deepEqual(snapshot(dataDir), before, `${name}: nothing is written`);
  };
  const withdrawn = (d) => path.join(d, documentPath("characters", "withdrawn"));
  const index = (d) => path.join(d, documentPath("characters", "index"));
  const state = (d) => path.join(d, statePath("characters"));
  const edit = (file, f) => fs.writeFileSync(file, JSON.stringify(f(JSON.parse(fs.readFileSync(file, "utf8")))));

  // an earlier document that is unreadable, or was changed after it was signed, is not "no earlier rows"
  damaged("not JSON", (d) => fs.writeFileSync(withdrawn(d), "{"), "E_PREVIOUS_UNVERIFIED");
  damaged("the rows removed after signing", (d) => edit(withdrawn(d), (e) => ({ ...e, signed: { ...e.signed, rows: [] } })), "E_PREVIOUS_UNVERIFIED");
  damaged("the serial lowered after signing", (d) => edit(index(d), (e) => ({ ...e, signed: { ...e.signed, serial: 1, issued_at: 1 } })), "E_PREVIOUS_UNVERIFIED");
  // a pair signed by a key that is not this kind's: another kind's current key, and a key nobody trusts
  damaged("signed by another kind's key", (d) => plant(d, "characters", { seed: seeds.models.current, keyId: "astra-characters-testa", serial: NOW }), "E_PREVIOUS_UNVERIFIED");
  damaged("signed by an unknown key", (d) => plant(d, "characters", { seed: crypto.randomBytes(32), keyId: "astra-characters-testa", serial: NOW }), "E_PREVIOUS_UNVERIFIED");
  // the withdrawn document offered where the index belongs: the right key over the wrong domain
  damaged("the withdrawn document as the index", (d) => fs.copyFileSync(withdrawn(d), index(d)), "E_PREVIOUS_UNVERIFIED");

  // a pair that was there and is gone is not a first signing
  const gone = (d) => [withdrawn(d), index(d), state(d)].forEach((f) => fs.rmSync(f));
  damaged("all three files deleted", gone, "E_PREVIOUS_MISSING", { everHeld: true });
  damaged("the withdrawn document deleted", (d) => fs.rmSync(withdrawn(d)), "E_PREVIOUS_MISSING");
  damaged("the state file deleted", (d) => fs.rmSync(state(d)), "E_PREVIOUS_MISSING");

  // the state file is a cache of what the documents prove
  damaged("the state names another key", (d) => edit(state(d), (s) => ({ ...s, key_id: "astra-characters-testb" })), "E_STATE_MISMATCH");
  damaged("the state names another second", (d) => edit(state(d), (s) => ({ ...s, issued_at: NOW + 1 })), "E_STATE_MISMATCH");
  damaged("the state is for another kind", (d) => edit(state(d), (s) => ({ ...s, kind: "models" })), "E_STATE_MISMATCH");

  // no symbolic link anywhere under registry/ or state/
  const outside = scratch(t, "outside");
  fs.writeFileSync(path.join(outside, "x.json"), "{}");
  damaged("a linked document", (d) => {
      fs.renameSync(withdrawn(d), path.join(outside, "w.json"));
      fs.symlinkSync(path.join(outside, "w.json"), withdrawn(d));
    }, "E_DATA_SYMLINK", { skipSnapshot: true });
  damaged("a linked directory of another kind", (d) => fs.symlinkSync(outside, path.join(d, "registry", "v1", "packs")), "E_DATA_SYMLINK", { skipSnapshot: true });
  damaged("a linked state directory", (d) => {
      fs.renameSync(path.join(d, "state"), path.join(outside, "state"));
      fs.symlinkSync(path.join(outside, "state"), path.join(d, "state"));
    }, "E_DATA_SYMLINK", { skipSnapshot: true });

  // the preparing step itself refuses a link, before it reads through one
  const linked = scratch(t);
  const linkedData = path.join(linked, "data");
  run(t, { dir: linked, dataDir: linkedData, kind: "characters", trust, secret, export: exportOf("characters", { rows }), now: NOW });
  fs.renameSync(withdrawn(linkedData), path.join(outside, "w2.json"));
  fs.symlinkSync(path.join(outside, "w2.json"), withdrawn(linkedData));
  assert.throws(
    () => prepareKind({ kind: "characters", exportFile: writeExport(linked, "characters", exportOf("characters", { at: NOW + 60 })), dataDir: linkedData, trust, now: NOW + 60, workDir: path.join(linked, "w"), everHeld: true }),
    refusal("E_DATA_SYMLINK"),
  );
  assert.ok(!fs.existsSync(path.join(linked, "w", "order.json")), "and leaves no order for the key step");

  // a kind the branch never held is signed for the first time; the same empty directory under a
  // branch that did hold it is refused (the first case above); and the row carried comes from the verified document
  const dir = scratch(t);
  const base = { dir, dataDir: path.join(dir, "data"), kind: "characters", trust, secret };
  assert.equal(run(t, { ...base, export: exportOf("characters", { rows }), now: NOW, everHeld: false }).outcome, "signed");
  assert.equal(run(t, { ...base, export: exportOf("characters"), now: NOW + 60 }).carried, rows.length);
});

test("an answer is signed only while it is fresh", (t) => {
  const { trust, seeds } = throwawayTrust();
  const base = { kind: "commands", trust, secret: seedSecret(seeds.commands.current), keepTime: true };
  const at = (seconds) => exportOf("commands", { at: NOW + seconds });
  for (const [age, ok] of [[0, true], [-EXPORT_MAX_AGE, true], [-EXPORT_MAX_AGE - 1, false], [-86400, false], [EXPORT_MAX_AHEAD, true], [EXPORT_MAX_AHEAD + 1, false]]) {
    const dir = scratch(t);
    if (ok) assert.equal(run(t, { ...base, dir, export: at(age) }).outcome, "signed", `${age} s`);
    else {
      assert.throws(() => run(t, { ...base, dir, export: at(age) }), refusal("E_EXPORT_STALE"), `${age} s`);
      assert.deepEqual(snapshot(path.join(dir, "data")), {});
    }
  }
  // the case this exists for: yesterday's run is run again, with yesterday's answer still in its artifact
  const dir = scratch(t);
  const dataDir = path.join(dir, "data");
  const row = seq("seq-1-security").rows[0];
  run(t, { ...base, dir, dataDir, export: exportOf("commands", { rows: [], at: NOW }), now: NOW });
  run(t, { ...base, dir, dataDir, export: exportOf("commands", { rows: [row], at: NOW + 3600 }), now: NOW + 3600 });
  const before = snapshot(dataDir);
  assert.throws(() => run(t, { ...base, dir, dataDir, export: exportOf("commands", { rows: [], at: NOW }), now: NOW + 86400 }), refusal("E_EXPORT_STALE"));
  assert.deepEqual(snapshot(dataDir), before);
  // an answer too large to be two documents is not read at all
  const big = scratch(t);
  assert.throws(() => run(t, { ...base, dir: big, raw: Buffer.alloc(MAX_EXPORT_BYTES + 1, 0x20) }), refusal("E_EXPORT_SIZE"));
});

test("trust.json is believed only under the roots, and only while it lasts", (t) => {
  const mine = throwawayTrust();
  const theirs = throwawayTrust();
  const answer = exportOf("commands");
  const go = (trustDoc, roots, now = NOW) => {
    const dir = scratch(t);
    const trustFile = path.join(dir, "trust.json");
    fs.writeFileSync(trustFile, JSON.stringify(trustDoc));
    return import("../lib/trust.mjs").then(({ loadTrust }) => loadTrust({ file: trustFile, now, roots }));
  };
  return Promise.all([
    assert.rejects(go(mine.doc, theirs.roots), refusal("E_TRUST_UNVERIFIED")),
    assert.rejects(go({ ...mine.doc, signed: { ...mine.doc.signed, serial: 2 } }, mine.roots), refusal("E_TRUST_UNVERIFIED")),
    assert.rejects(go(mine.doc, mine.roots, NOW + 366 * 86400), refusal("E_TRUST_EXPIRED")),
    go(mine.doc, mine.roots).then((trust) => {
      assert.equal(trust.kindKeys("commands").current.key_id, "astra-commands-testa");
      assert.throws(() => trust.kindKeys("games"), refusal("E_TRUST_KIND_KEYS"));
      void answer;
    }),
  ]);
});

test("the specification's goldens are judged through the bridge as vectors.json records", () => {
  // The bridge adds nothing to the checker; this holds it to that over every
  // index and withdrawn golden, so a bridge that swallowed a refusal is red.
  const { trust } = goldenTrust();
  const vectors = JSON.parse(fs.readFileSync(path.join(GOLDENS, "vectors.json"), "utf8"));
  let n = 0;
  for (const doc of DOCS) {
    for (const v of vectors[doc]) {
      const got = checkDocument({ file: path.join(GOLDENS, v.file), kind: v.kind, doc, now: v.now ?? vectors.now, trust: trust.signed });
      const label = `${doc}/${v.kind}/${v.name}`;
      if (v.verdict === "accept") assert.equal(got.ok, true, label);
      else if (v.check === "parse") assert.ok(got.parse, label);
      else if (v.check === "schema") assert.ok(got.schema, label);
      else if (v.check === "semantic") assert.deepEqual(got.rules, [v.rule], label);
      else if (v.check === "signature") assert.ok(!got.schema && !got.rules.length && got.verified_by.length === 0 && got.reason === v.reason, label);
      else assert.fail(`${label}: an unknown check ${v.check}`);
      n++;
    }
  }
  assert.ok(n >= 80, `${n} goldens`);
});
