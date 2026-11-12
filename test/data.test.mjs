// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// The `data` branch (lib/data.mjs, bin/data.mjs, bin/sign.mjs) against a bare
// repository on disk: opened, moved forward, never moved back.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";

import { main as dataMain } from "../bin/data.mjs";
import { main as signMain } from "../bin/sign.mjs";
import { documentPath, KINDS, statePath } from "../lib/kinds.mjs";
import { openData, publishData } from "../lib/data.mjs";
import { exportOf, golden, NOW, scratch, seedSecret, throwawayTrust, writeExport } from "./helpers.mjs";

const git = (dir, ...args) => execFileSync("git", ["-C", dir, ...args], { encoding: "utf8" }).trim();
function bare(t) {
  const dir = scratch(t, "remote");
  execFileSync("git", ["init", "-q", "--bare", "-b", "main", dir]);
  return dir;
}
const filesAt = (remote, ref = "data") => git(remote, "ls-tree", "-r", "--name-only", ref).split("\n").filter(Boolean);

/** One leg of sign.yml as its three steps run it, against `remote`. */
function leg(t, { remote, kind, answer, trust, secret, now, status = "fetched" }) {
  const dir = scratch(t, "leg");
  const exportsDir = path.join(dir, "exports");
  fs.mkdirSync(exportsDir);
  fs.writeFileSync(path.join(exportsDir, "work.json"), JSON.stringify({ kinds: { [kind]: status } }));
  if (answer) writeExport(exportsDir, kind, answer);
  const trustFile = path.join(dir, "trust.json");
  fs.writeFileSync(trustFile, JSON.stringify(trust.doc));
  const data = path.join(dir, "data");
  const report = path.join(dir, "report.json");
  const log = [];
  const say = (l) => log.push(l);
  assert.equal(dataMain(["open", "--dir", data, "--remote", remote], { env: {}, log: say }), 0);
  const env = { CONTENT_SIGNING_KEY: secret };
  const signed = signMain(["--kind", kind, "--exports", exportsDir, "--data", data, "--trust", trustFile, "--report", report], { env, now, roots: trust.roots, log: say });
  assert.equal("CONTENT_SIGNING_KEY" in env, false, "the key leaves the environment once read");
  const exit = signed.outcome === "refused" ? null : dataMain(["publish", "--dir", data, "--report", report], { env: {}, log: say });
  return { signed, exit, log, data };
}

test("the first signing starts data, and each later one moves it forward by one commit", (t) => {
  const remote = bare(t);
  const trust = throwawayTrust();
  const answer = (kind) => exportOf(kind, { entries: golden(`index/${kind}/valid.json`).signed.entries });
  let n = 0;
  for (const kind of KINDS) {
    const r = leg(t, { remote, kind, answer: answer(kind), trust, secret: seedSecret(trust.seeds[kind].current), now: NOW + n });
    assert.equal(r.signed.outcome, "signed");
    assert.equal(r.exit, 0);
    assert.equal(Number(git(remote, "rev-list", "--count", "data")), ++n);
  }
  assert.deepEqual(
    filesAt(remote),
    [...KINDS.flatMap((k) => [documentPath(k, "index"), documentPath(k, "withdrawn")]), ...KINDS.map(statePath)].sort(),
    "ten documents and five state files, and nothing else",
  );
  // one commit carries a kind's index, its withdrawn document and its state together
  assert.deepEqual(
    git(remote, "show", "--name-only", "--format=", "data").split("\n").sort(),
    [documentPath("packs", "index"), documentPath("packs", "withdrawn"), statePath("packs")].sort(),
  );
  assert.match(git(remote, "log", "-1", "--format=%s", "data"), /^sign packs: issued_at \d+ under astra-packs-testa$/);
  // every commit's parent is the commit before it: a straight line
  assert.equal(git(remote, "rev-list", "--merges", "--count", "data"), "0");

  // an unchanged kind inside six hours publishes nothing
  const head = git(remote, "rev-parse", "data");
  const again = leg(t, { remote, kind: "packs", answer: answer("packs"), trust, secret: seedSecret(trust.seeds.packs.current), now: NOW + 100 });
  assert.equal(again.signed.outcome, "unchanged");
  assert.equal(again.exit, 0);
  assert.equal(git(remote, "rev-parse", "data"), head);
});

test("a kept row is published first, and then the run fails", (t) => {
  const remote = bare(t);
  const trust = throwawayTrust();
  const row = golden("withdrawn/commands/seq-1-security.json").signed.rows[0];
  const secret = seedSecret(trust.seeds.commands.current);
  assert.equal(leg(t, { remote, kind: "commands", answer: exportOf("commands", { rows: [row] }), trust, secret, now: NOW }).exit, 0);

  const r = leg(t, { remote, kind: "commands", answer: exportOf("commands", { rows: [] }), trust, secret, now: NOW + 600 });
  assert.equal(r.exit, 1, "the run ends failed");
  const published = JSON.parse(git(remote, "show", `data:${documentPath("commands", "withdrawn")}`));
  assert.equal(published.signed.serial, NOW + 600, "after the new document reached data");
  assert.deepEqual(published.signed.rows, [row], "with the row in it");
  assert.ok(r.log.some((l) => l.includes("keeps 1 row(s)")));

  // the same answer ten minutes later: nothing new to publish, and the run still fails
  const still = leg(t, { remote, kind: "commands", answer: exportOf("commands", { rows: [] }), trust, secret, now: NOW + 1200 });
  assert.equal(still.signed.outcome, "unchanged");
  assert.equal(still.exit, 1);
});

test("data never moves back: a push over a remote that moved is refused", (t) => {
  const remote = bare(t);
  const dirs = [scratch(t, "a"), scratch(t, "b")];
  for (const d of dirs) openData({ remote, dir: d });
  for (const [i, d] of dirs.entries()) {
    fs.mkdirSync(path.join(d, "state"), { recursive: true });
    fs.writeFileSync(path.join(d, "state", "commands.json"), `{"n":${i}}\n`);
  }
  assert.equal(publishData({ dir: dirs[0], message: "first" }).pushed, true);
  const head = git(remote, "rev-parse", "data");
  // the second checkout was opened before the first pushed; its commit is not a descendant
  assert.throws(() => publishData({ dir: dirs[1], message: "second" }));
  assert.equal(git(remote, "rev-parse", "data"), head);

  // opened again from the new tip, the same change goes through as a descendant
  const fresh = scratch(t, "c");
  assert.equal(openData({ remote, dir: fresh }).head, head);
  fs.writeFileSync(path.join(fresh, "state", "commands.json"), '{"n":2}\n');
  const pushed = publishData({ dir: fresh, message: "third" });
  assert.equal(git(remote, "rev-parse", "data"), pushed.head);
  assert.equal(git(fresh, "rev-parse", "HEAD~1"), head);
  // only registry/ and state/ are ever committed
  fs.writeFileSync(path.join(fresh, "stray.txt"), "x");
  assert.equal(publishData({ dir: fresh, message: "nothing" }).pushed, false);
});

test("a leg with no export: a closed door is quiet, anything else fails", (t) => {
  const remote = bare(t);
  const trust = throwawayTrust();
  const secret = seedSecret(trust.seeds.models.current);
  const closed = leg(t, { remote, kind: "models", answer: null, trust, secret, now: NOW, status: "closed" });
  assert.equal(closed.signed.outcome, "closed");
  assert.equal(closed.exit, 0);
  const refused = leg(t, { remote, kind: "models", answer: null, trust, secret, now: NOW, status: "refused" });
  assert.deepEqual({ outcome: refused.signed.outcome, code: refused.signed.code }, { outcome: "refused", code: "E_EXPORT_ABSENT" });
  assert.equal(git(remote, "for-each-ref", "refs/heads/data"), "", "and data is not started for nothing");
});

test("the token reaches git through its environment and never through an argument", () => {
  const src = fs.readFileSync(new URL("../lib/data.mjs", import.meta.url), "utf8");
  assert.match(src, /GIT_CONFIG_VALUE_0: `AUTHORIZATION: basic \$\{basic\}`/);
  // every git invocation goes through one function, whose arguments are fixed words and paths
  assert.equal(src.match(/execFileSync\(/g).length, 1);
  assert.ok(!/args.*token|token.*args\b/.test(src.split("function git(")[1].split("\n}")[0]));
});
