#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// Copy, or check, the vendored files (lib/vendored.mjs).
//
//   node bin/vendor.mjs update --astraplugins <checkout>[@<commit>] --astra-registry <checkout>[@<commit>]
//       writes vendor/<upstream>/ and vendor/pins.json from a local checkout;
//       the commit defaults to the upstream's default branch on `origin`.
//   node bin/vendor.mjs check [--astraplugins <checkout>] [--astra-registry <checkout>] [--upstream-moved]
//       exits 1 when a copy differs from its record or, with a checkout, from
//       the recorded commit. `--upstream-moved` also fails when upstream has
//       changed one of the files since.

import { checkVendored, SOURCES, vendorFrom } from "../lib/vendored.mjs";

const [mode, ...rest] = process.argv.slice(2);
const given = {};
let upstreamMoved = false;
for (let i = 0; i < rest.length; i++) {
  if (rest[i] === "--upstream-moved") upstreamMoved = true;
  else if (rest[i].startsWith("--") && rest[i].slice(2) in SOURCES && rest[i + 1]) given[rest[i].slice(2)] = rest[++i];
  else {
    console.error(`unknown argument ${rest[i]}`);
    process.exit(2);
  }
}

if (mode === "update") {
  for (const [upstream, spec] of Object.entries(given)) {
    const at = spec.lastIndexOf("@");
    const checkout = at > 0 ? spec.slice(0, at) : spec;
    const commit = at > 0 ? spec.slice(at + 1) : `origin/${SOURCES[upstream].watch}`;
    const { commit: full, count } = vendorFrom(upstream, checkout, commit);
    console.log(`${upstream}: ${count} files at ${full}`);
  }
} else if (mode === "check") {
  let bad = 0;
  for (const upstream of Object.keys(SOURCES)) {
    const checkout = given[upstream] ?? null;
    const problems = checkVendored({ upstream, checkout, upstreamRef: checkout && upstreamMoved ? `origin/${SOURCES[upstream].watch}` : null });
    for (const p of problems) console.error(p);
    bad += problems.length;
    if (!problems.length) console.log(`${upstream}: equal to its record${checkout ? " and to the recorded commit" : ""}`);
  }
  process.exit(bad ? 1 : 0);
} else {
  console.error("usage: node bin/vendor.mjs update|check [--astraplugins <checkout>] [--astra-registry <checkout>] [--upstream-moved]");
  process.exit(2);
}
