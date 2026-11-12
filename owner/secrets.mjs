#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// Place a kind's signing key as the one secret of that kind's environment.
// Run by the operator, on the machine that holds the keys, and by nobody
// else: no workflow and no agent runs this.
//
//   owner/secrets.sh <keys-dir>                  every kind's CURRENT key
//   owner/secrets.sh <keys-dir> --rotate <kind>  that kind's NEXT key: the
//                                                signer signs with it from
//                                                its next run
//   options: --no-upload      check and report only; gh is not called
//            --trust <file>   use this trust.json instead of fetching the
//                             published one from astra-registry
//            --repo <o/n>     default mihailinl/astra-content-catalogue; it
//                             must be the repository whose id is compiled
//                             into lib/kinds.mjs, whatever its name is now
//
// Which key is current and which is next is not decided here and is not read
// from a file name pattern: they are the two rows of the kind in the plugin
// registry's trust.json, verified under the compiled root keys. A row's key
// id names the files, `<keys-dir>/<key id>.seed.b64` and
// `<keys-dir>/<key id>.private.pem`. For each kind this
//
//   1. derives the public half from the private file(s), locally;
//   2. refuses unless it equals the row asked for: the current row in a
//      plain run, the next row with --rotate. A plain run never uploads a
//      next key, and --rotate never uploads anything but the next key, and
//      not before that key's `not_before`;
//   3. asks GitHub, for the repository and each kind asked for, and refuses
//      unless ALL of this holds:
//        - the repository's id is the compiled one;
//        - the environment publish-<kind> deploys from the branch `main`
//          and from nothing else (a policy of type `tag` does not count);
//        - an active ruleset restricts updates of `main` with nobody but the
//          admin role as bypass (owner/create.sh sets it). Without it, code
//          pushed to `main` by any writer would run beside the key. GitHub
//          shows a ruleset's bypass list only to an administrator, so a gh
//          signed in without that right is refused, and told so; a ruleset
//          aimed at `~DEFAULT_BRANCH` counts only while that branch is `main`;
//        - in a plain run: the kind's documents on `data` were not signed
//          with its NEXT key. After `--rotate <kind>` and before the trust
//          change, the environment holds the next key, and a plain run would
//          put the current key back over it;
//   4. only when every kind asked for has passed, runs
//        gh secret set ASTRA_<KIND>_SIGNING_KEY --env publish-<kind> --repo …
//      with the key file as gh's standard input.
//
// A key never appears in an argument, in the environment of a child process,
// or in what this prints. It prints one line per kind: the kind, the key id,
// and `match`, `ROTATING` or `mismatch`; then whether it uploaded.
//
// A secret cannot be read back from GitHub, so this never says what an
// environment holds: it says what it uploaded, or that it uploaded nothing.
// After a trust change has promoted a rotated key, a plain run reports that
// kind as `match` and uploads the same key again, which changes nothing; with
// --no-upload it only reports.

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import { publicKeyBase64, verifyEnvelope } from "../vendor/astra-registry/bot/lib/sign.mjs";
import { assertKind, DOCS, documentPath, domainOf, environmentOf, KINDS, Refused, REPOSITORY, REPOSITORY_ID, secretOf } from "../lib/kinds.mjs";
import { privateKeyFromSecret, roleOf } from "../lib/signer.mjs";
import { loadTrust, publicKeyOf } from "../lib/trust.mjs";

export const DEFAULT_REPO = REPOSITORY;
export const TRUST_URL = "https://raw.githubusercontent.com/mihailinl/astra-registry/main/registry/v1/trust.json";
/** The private spellings of one key, the one uploaded first. */
export const PRIVATE_SUFFIXES = Object.freeze([".seed.b64", ".private.pem"]);

function parse(argv) {
  const o = { dir: null, rotate: null, trust: null, repo: DEFAULT_REPO, upload: true };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--rotate" || a === "--trust" || a === "--repo") {
      if (i + 1 >= argv.length) throw new Error(`${a} needs a value`);
      o[a.slice(2)] = argv[++i];
    } else if (a === "--no-upload") o.upload = false;
    else if (a.startsWith("--")) throw new Error(`unknown option ${a}`);
    else if (o.dir === null) o.dir = a;
    else throw new Error(`unexpected argument`);
  }
  if (!o.dir) throw new Error("usage: owner/secrets.sh <keys-dir> [--rotate <kind>] [--no-upload] [--trust <file>] [--repo <owner/name>]");
  if (o.rotate) assertKind(o.rotate);
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(o.repo)) throw new Error("--repo is not owner/name");
  return o;
}

/**
 * The file to upload for a kind, or why there is none. `want` is the row the
 * run is about: `current` in a plain run, `next` with --rotate.
 * @returns {{kind: string, key_id: string, want: string, ok: boolean, file?: string, why?: string}}
 */
export function keyFile(dir, kind, kindKeys, want, now) {
  const row = kindKeys[want];
  const base = { kind, key_id: row.key_id, want };
  if (want === "next" && !(row.notBefore <= now)) return { ...base, ok: false, why: `the next key is not valid before ${row.not_before}; the signer would refuse it` };
  const files = PRIVATE_SUFFIXES.map((s) => path.join(dir, `${row.key_id}${s}`)).filter((f) => fs.existsSync(f));
  if (files.length === 0) return { ...base, ok: false, why: "no private file for this key id" };
  for (const file of files) {
    const key = privateKeyFromSecret(fs.readFileSync(file, "utf8"));
    if (!key) return { ...base, ok: false, why: `${path.basename(file)} is not an Ed25519 private key` };
    const role = roleOf(publicKeyBase64(key), kindKeys);
    if (role === want) continue;
    if (role === "next") return { ...base, ok: false, why: "the private file holds the kind's NEXT key; a plain run uploads the current key only (use --rotate)" };
    if (role === "current") return { ...base, ok: false, why: "the private file holds the kind's CURRENT key; --rotate uploads the next key only" };
    return { ...base, ok: false, why: `${path.basename(file)} is not the key trust.json names ${want}` };
  }
  return { ...base, ok: true, file: files[0] };
}

/** What a `gh` child gets of this process's environment: where to find gh and its sign-in, and nothing else. */
export function ghEnv(env) {
  const out = { PATH: env.PATH ?? "", HOME: env.HOME ?? "" };
  for (const name of ["GH_TOKEN", "GH_CONFIG_DIR"]) if (env[name]) out[name] = env[name];
  return out;
}

/** One `gh` call. `stdin` is a file descriptor or "ignore". */
function gh(args, env, stdin = "ignore") {
  const r = spawnSync("gh", args, { stdio: [stdin, "pipe", "pipe"], env: ghEnv(env), encoding: "utf8", maxBuffer: 8 * 1024 * 1024 });
  return { ok: !r.error && r.status === 0, status: r.error ? null : r.status, stdout: r.stdout ?? "", said: String(r.stderr ?? "").trim().split("\n")[0].slice(0, 200) };
}

function ghJson(route, env) {
  const r = gh(["api", route], env);
  if (!r.ok) throw new Error(`gh api ${route} failed${r.said ? ` (${r.said})` : ""}`);
  return JSON.parse(r.stdout);
}

/**
 * Why the repository's `main` is not protected as owner/create.sh sets it, or null.
 * `defaultBranch` is the repository's, so that a ruleset aimed at
 * `~DEFAULT_BRANCH` counts only while that branch is `main`.
 */
export function mainRulesetProblem(repo, env, defaultBranch) {
  let unseen = null;
  for (const brief of ghJson(`repos/${repo}/rulesets`, env)) {
    if (brief.target !== "branch" || brief.enforcement !== "active") continue;
    const rs = ghJson(`repos/${repo}/rulesets/${brief.id}`, env);
    const ref = rs.conditions?.ref_name ?? {};
    const coversMain = (ref.include ?? []).some((r) => r === "refs/heads/main" || (r === "~DEFAULT_BRANCH" && defaultBranch === "main")) && (ref.exclude ?? []).length === 0;
    const restrictsUpdate = (rs.rules ?? []).some((r) => r.type === "update");
    if (rs.target !== "branch" || rs.enforcement !== "active" || !coversMain || !restrictsUpdate) continue;
    // GitHub leaves the bypass list out for a token that cannot administer the repository;
    // an absent list is not an empty one, and nothing is concluded from it
    if (!Array.isArray(rs.bypass_actors)) {
      unseen = `GitHub did not show who may bypass ruleset ${brief.id} on main; gh must be signed in as an administrator of the repository`;
      continue;
    }
    if (rs.bypass_actors.every((a) => a.actor_type === "RepositoryRole" && a.actor_id === 5)) return null;
  }
  return unseen ?? "no active ruleset restricts updates of main to administrators (run owner/create.sh)";
}

/** Why the kind's environment may be entered from anything but the branch `main`, or null. */
export function environmentProblem(repo, kind, env) {
  const name = environmentOf(kind);
  const e = ghJson(`repos/${repo}/environments/${name}`, env);
  const p = e.deployment_branch_policy;
  if (!p || p.custom_branch_policies !== true || p.protected_branches !== false) return `${name} is not restricted to named branches (run owner/create.sh)`;
  const policies = ghJson(`repos/${repo}/environments/${name}/deployment-branch-policies`, env).branch_policies ?? [];
  // a policy of type `tag` named main would admit a TAG called main, from which anybody with write access could deploy
  if (policies.length !== 1 || policies[0].name !== "main" || policies[0].type !== "branch") return `${name} must deploy from the branch main only (run owner/create.sh)`;
  return null;
}

/**
 * Whether the kind's documents on `data` were last signed with its next key.
 * Absent documents (a kind never published) and documents signed by another
 * key are not.
 */
export function lastSignedWithNext(repo, kind, kindKeys, env) {
  for (const doc of DOCS) {
    const r = gh(["api", "-H", "Accept: application/vnd.github.raw", `repos/${repo}/contents/${documentPath(kind, doc)}?ref=data`], env);
    if (!r.ok) {
      if (/HTTP 404/.test(r.said)) continue;
      throw new Error(`gh could not read ${kind}'s ${doc} on data${r.said ? ` (${r.said})` : ""}`);
    }
    let envelope;
    try {
      envelope = JSON.parse(r.stdout);
    } catch {
      throw new Error(`${kind}'s ${doc} on data is not JSON`);
    }
    if (verifyEnvelope(envelope, domainOf(kind, doc), [{ key_id: kindKeys.next.key_id, publicKey: publicKeyOf(kindKeys.next) }]).ok) return true;
  }
  return false;
}

export async function main(argv, { roots, fetchImpl = fetch, log = console.log, env = process.env, now = Math.floor(Date.now() / 1000) } = {}) {
  const o = parse(argv);
  let doc;
  if (o.trust) doc = JSON.parse(fs.readFileSync(o.trust, "utf8"));
  else {
    const r = await fetchImpl(TRUST_URL, { redirect: "error" });
    if (!r.ok) throw new Error(`the published trust.json answered HTTP ${r.status}`);
    doc = await r.json();
  }
  const trust = loadTrust({ doc, now, ...(roots ? { roots } : {}) });

  const kinds = o.rotate ? [o.rotate] : KINDS;
  const want = o.rotate ? "next" : "current";
  const found = kinds.map((kind) => keyFile(o.dir, kind, trust.kindKeys(kind), want, now));
  for (const f of found) log(`${f.kind} ${f.key_id} ${f.ok ? (o.rotate ? "ROTATING" : "match") : "mismatch"}${f.ok ? "" : ` (${f.why})`}`);
  if (found.some((f) => !f.ok)) {
    log("nothing was uploaded: every kind must match first");
    return 1;
  }
  if (!o.upload) {
    for (const f of found) log(`${f.kind}: ${want} key id ${f.key_id}; upload skipped (--no-upload)`);
    return 0;
  }
  // what GitHub must look like before a key goes there
  const problems = [];
  const repo = ghJson(`repos/${o.repo}`, env);
  if (repo.id !== REPOSITORY_ID) problems.push(`${o.repo} is not the signer's repository (its id is not ${REPOSITORY_ID})`);
  else {
    const rules = mainRulesetProblem(o.repo, env, repo.default_branch);
    if (rules) problems.push(rules);
    for (const f of found) {
      const e = environmentProblem(o.repo, f.kind, env);
      if (e) problems.push(e);
      if (want === "current" && lastSignedWithNext(o.repo, f.kind, trust.kindKeys(f.kind), env)) {
        problems.push(`${f.kind} was last signed with its NEXT key (a rotation is in progress); the current key would move it back, so it is not uploaded`);
      }
    }
  }
  if (problems.length) {
    for (const p of problems) log(`refused: ${p}`);
    log("nothing was uploaded");
    return 1;
  }
  for (const f of found) {
    const fd = fs.openSync(f.file, "r");
    try {
      const r = gh(["secret", "set", secretOf(f.kind), "--env", environmentOf(f.kind), "--repo", o.repo], env, fd);
      if (!r.ok) {
        log(`${f.kind} ${f.key_id} NOT uploaded: gh ${r.status === null ? "could not be run" : `exited ${r.status}`}${r.said ? ` (${r.said})` : ""}`);
        return 1;
      }
    } finally {
      fs.closeSync(fd);
    }
    log(`${f.kind} ${f.key_id} uploaded to ${environmentOf(f.kind)}`);
  }
  if (o.rotate) log(`${o.rotate}: the next Sign run signs both documents with ${found[0].key_id}; the trust change that names it current can follow`);
  return 0;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (e) => {
      console.error(e instanceof Refused ? e.message : String(e?.message ?? e));
      process.exit(1);
    },
  );
}
