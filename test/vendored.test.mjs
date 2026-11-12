// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// The vendored copies are their sources (lib/vendored.mjs).
//
// Without a checkout the test still proves that every vendored byte is the
// one vendor/pins.json recorded, which is what catches an edit made here.
// With ASTRAPLUGINS_CHECKOUT / ASTRA_REGISTRY_CHECKOUT (CI sets both) it
// proves each file equals the recorded commit in that checkout.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";

import { checkVendored, readPins, SOURCES, VENDOR } from "../lib/vendored.mjs";
import { scratch } from "./helpers.mjs";

const CHECKOUTS = { astraplugins: process.env.ASTRAPLUGINS_CHECKOUT, "astra-registry": process.env.ASTRA_REGISTRY_CHECKOUT };

for (const upstream of Object.keys(SOURCES)) {
  test(`${upstream}: every vendored file is the one pins.json records`, () => {
    assert.deepEqual(checkVendored({ upstream }), []);
    assert.match(readPins()[upstream].commit, /^[0-9a-f]{40}$/);
    assert.equal(readPins()[upstream].repo, SOURCES[upstream].repo);
  });

  test(`${upstream}: every vendored file equals the recorded commit in a checkout`, { skip: CHECKOUTS[upstream] ? false : `set ${upstream === "astraplugins" ? "ASTRAPLUGINS_CHECKOUT" : "ASTRA_REGISTRY_CHECKOUT"}` }, () => {
    assert.deepEqual(checkVendored({ upstream, checkout: CHECKOUTS[upstream] }), []);
  });
}

test("a vendored file that drifts from a checkout is reported", (t) => {
  // A copy of vendor/ that this test may damage, and a checkout made here:
  // one commit holding the vendored files, then one that changes a file.
  const vendorDir = path.join(scratch(t, "vendor"), "vendor");
  fs.cpSync(VENDOR, vendorDir, { recursive: true });
  const pins = readPins(vendorDir);
  const file = "tools/contentlite.py";
  const vendored = path.join(vendorDir, "astraplugins", file);
  const original = fs.readFileSync(vendored);

  const checkout = scratch(t, "upstream");
  const git = (...a) => execFileSync("git", ["-C", checkout, "-c", "user.name=t", "-c", "user.email=t@example.org", "-c", "commit.gpgsign=false", ...a], { encoding: "utf8" }).trim();
  git("init", "-q", "-b", "master");
  fs.cpSync(path.join(vendorDir, "astraplugins"), checkout, { recursive: true });
  git("add", "-A");
  git("commit", "-q", "-m", "as vendored");
  const same = git("rev-parse", "HEAD");
  fs.appendFileSync(path.join(checkout, file), "\n# changed upstream\n");
  git("commit", "-q", "-am", "upstream moves");
  const moved = git("rev-parse", "HEAD");
  const pinTo = (commit) => fs.writeFileSync(path.join(vendorDir, "pins.json"), JSON.stringify({ ...pins, astraplugins: { ...pins.astraplugins, commit } }));
  const check = (o = {}) => checkVendored({ upstream: "astraplugins", vendorDir, ...o });

  pinTo(same);
  assert.deepEqual(check({ checkout }), [], "equal to the checkout");
  assert.deepEqual(check({ checkout, upstreamRef: moved }), [`astraplugins: ${file} changed upstream after the recorded commit (${same}..${moved}); vendor again`]);

  // the checkout's commit differs from the copy
  pinTo(moved);
  assert.deepEqual(check({ checkout }), [`astraplugins: ${file} differs from mihailinl/AstraPlugins@${moved}`]);

  // the copy was edited here
  pinTo(same);
  fs.appendFileSync(vendored, "\n# edited here\n");
  assert.deepEqual(check({ checkout }), [`astraplugins: ${file} differs from the bytes pins.json records`]);
  fs.writeFileSync(vendored, original);

  // a file added beside the copies, and one removed
  const stray = path.join(vendorDir, "astraplugins", "tools", "extra.py");
  fs.writeFileSync(stray, "");
  assert.deepEqual(check(), ["astraplugins: tools/extra.py is in vendor/ and not in pins.json"]);
  fs.rmSync(stray);
  fs.rmSync(vendored);
  assert.deepEqual(check(), [`astraplugins: ${file} is recorded and not vendored`]);
  fs.writeFileSync(vendored, original);
  assert.deepEqual(check({ checkout }), []);
});
