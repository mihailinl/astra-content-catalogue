// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// The vendored files and the check that keeps them equal to their source.
//
// Two upstreams are copied under vendor/, byte for byte, at one commit each:
//
//   astraplugins     the content specification's own checker
//                    (tools/check-content-goldens.py and the two modules it
//                    imports), the document schemas it reads, and the index,
//                    withdrawn and trust goldens with their hand-stated
//                    verdicts. The signer checks every document with this code
//                    and never with a second reading of the specification.
//   astra-registry   the canonical JSON serialiser, the envelope signing
//                    functions and the compiled root keys, so that this signer,
//                    the plugin catalogue and a client agree on one digest.
//
// vendor/pins.json records, per upstream, the repository, the source commit
// and the SHA-256 of every copied file. `bin/vendor.mjs update` writes the
// copies and that record from a local checkout; `checkVendored` compares.
// The files keep upstream's relative layout so that their own imports and
// path arithmetic work unchanged, and they carry no added header, so the copy
// equals `git show <commit>:<path>` exactly.

import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
export const VENDOR = path.join(ROOT, "vendor");
export const PINS_FILE = path.join(VENDOR, "pins.json");

/** What is copied from each upstream: exact paths, or a directory prefix ending in "/". */
export const SOURCES = Object.freeze({
  astraplugins: {
    repo: "mihailinl/AstraPlugins",
    watch: "master",
    paths: [
      "tools/check-content-goldens.py",
      "tools/contentlite.py",
      "tools/schemalite.py",
      "spec/content/schemas/",
      "testdata/content/vectors.json",
      "testdata/content/trust/",
      "testdata/content/index/",
      "testdata/content/withdrawn/",
    ],
  },
  "astra-registry": {
    repo: "mihailinl/astra-registry",
    watch: "main",
    paths: ["tools/lib/canonical.mjs", "bot/lib/sign.mjs", "bot/lib/roots.mjs"],
  },
});

const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");

function git(checkout, args, opts = {}) {
  return execFileSync("git", ["-C", checkout, ...args], { maxBuffer: 256 * 1024 * 1024, ...opts });
}

export function readPins(vendorDir = VENDOR) {
  return JSON.parse(fs.readFileSync(path.join(vendorDir, "pins.json"), "utf8"));
}

/** Every regular file under `dir`, as paths relative to it, sorted. */
function walk(dir, rel = "") {
  const out = [];
  for (const d of fs.readdirSync(path.join(dir, rel), { withFileTypes: true })) {
    const p = rel ? `${rel}/${d.name}` : d.name;
    if (d.isDirectory()) out.push(...walk(dir, p));
    else out.push(p);
  }
  return out.sort();
}

/** The upstream paths `SOURCES[upstream]` names at `commit`, resolved against the tree. */
function upstreamFiles(upstream, checkout, commit) {
  const all = git(checkout, ["ls-tree", "-r", "--name-only", "-z", commit], { encoding: "utf8" }).split("\0").filter(Boolean);
  const files = [];
  for (const want of SOURCES[upstream].paths) {
    const hit = want.endsWith("/") ? all.filter((f) => f.startsWith(want)) : all.filter((f) => f === want);
    if (hit.length === 0) throw new Error(`${upstream}: ${want} names nothing at ${commit}`);
    files.push(...hit);
  }
  return [...new Set(files)].sort();
}

/**
 * Copy one upstream's files from a local checkout at `commit` and record
 * them. Files that were vendored before and are no longer named are removed.
 */
export function vendorFrom(upstream, checkout, commit) {
  const full = git(checkout, ["rev-parse", "--verify", `${commit}^{commit}`], { encoding: "utf8" }).trim();
  const dir = path.join(VENDOR, upstream);
  fs.rmSync(dir, { recursive: true, force: true });
  const files = {};
  for (const file of upstreamFiles(upstream, checkout, full)) {
    const bytes = git(checkout, ["show", `${full}:${file}`]);
    const dest = path.join(dir, file);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.writeFileSync(dest, bytes);
    files[file] = sha256(bytes);
  }
  const pins = fs.existsSync(PINS_FILE) ? readPins() : {};
  pins[upstream] = { repo: SOURCES[upstream].repo, commit: full, files };
  const ordered = Object.fromEntries(Object.keys(SOURCES).filter((k) => pins[k]).map((k) => [k, pins[k]]));
  fs.writeFileSync(PINS_FILE, `${JSON.stringify(ordered, null, 2)}\n`);
  return { commit: full, count: Object.keys(files).length };
}

/**
 * Every vendored file equals what vendor/pins.json records; nothing unrecorded
 * sits beside them; and, with a `checkout` of the upstream, every file equals
 * the recorded commit there, and (with `upstreamRef`, the upstream's default
 * branch) that commit is an ancestor of the branch and no vendored file has
 * changed on it since.
 *
 * @param {{upstream: string, checkout?: string|null, upstreamRef?: string|null, vendorDir?: string}} o
 *   `vendorDir` is where the copies and pins.json are: this repository's
 *   vendor/, or a copy of it that a test is free to damage.
 * @returns {string[]} problems; empty means the copy is the source
 */
export function checkVendored({ upstream, checkout = null, upstreamRef = null, vendorDir = VENDOR }) {
  const pin = readPins(vendorDir)[upstream];
  if (!pin) return [`${upstream}: vendor/pins.json records nothing`];
  const problems = [];
  const dir = path.join(vendorDir, upstream);
  const recorded = Object.keys(pin.files).sort();
  const present = fs.existsSync(dir) ? walk(dir).filter((f) => !f.includes("__pycache__")) : [];
  for (const f of present) if (!(f in pin.files)) problems.push(`${upstream}: ${f} is in vendor/ and not in pins.json`);
  for (const f of recorded) {
    const p = path.join(dir, f);
    if (!fs.existsSync(p)) {
      problems.push(`${upstream}: ${f} is recorded and not vendored`);
      continue;
    }
    const bytes = fs.readFileSync(p);
    if (sha256(bytes) !== pin.files[f]) {
      problems.push(`${upstream}: ${f} differs from the bytes pins.json records`);
      continue;
    }
    if (checkout) {
      let want;
      try {
        want = git(checkout, ["show", `${pin.commit}:${f}`], { stdio: ["ignore", "pipe", "pipe"] });
      } catch (e) {
        problems.push(`${upstream}: ${f} cannot be read at ${pin.commit} in the checkout: ${String(e.message).split("\n")[0]}`);
        continue;
      }
      if (!want.equals(bytes)) problems.push(`${upstream}: ${f} differs from ${pin.repo}@${pin.commit}`);
    }
  }
  if (checkout) {
    try {
      const want = upstreamFiles(upstream, checkout, pin.commit);
      for (const f of want) if (!(f in pin.files)) problems.push(`${upstream}: ${f} exists at ${pin.commit} and is not vendored`);
    } catch (e) {
      problems.push(`${upstream}: ${String(e.message).split("\n")[0]}`);
    }
  }
  if (checkout && upstreamRef) {
    // The recorded commit must be on the upstream's own branch: a commit that
    // exists in the checkout and was never merged (a fork's, a discarded
    // branch's) is not the upstream's code, whatever its files say.
    try {
      git(checkout, ["merge-base", "--is-ancestor", pin.commit, upstreamRef], { stdio: ["ignore", "pipe", "pipe"] });
    } catch {
      problems.push(`${upstream}: the recorded commit ${pin.commit} is not an ancestor of ${upstreamRef}`);
    }
    let changed = "";
    try {
      changed = git(checkout, ["diff", "--name-only", pin.commit, upstreamRef, "--", ...SOURCES[upstream].paths.map((p) => p.replace(/\/$/, ""))], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      }).trim();
    } catch (e) {
      problems.push(`${upstream}: cannot compare ${pin.commit} with ${upstreamRef}: ${String(e.message).split("\n")[0]}`);
    }
    for (const f of changed ? changed.split("\n") : []) {
      problems.push(`${upstream}: ${f} changed upstream after the recorded commit (${pin.commit}..${upstreamRef}); vendor again`);
    }
  }
  return problems;
}
