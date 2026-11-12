// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// The `data` branch: opened before a kind is signed, moved forward after.
//
// Both steps run without the signing key (the workflow gives the key to the
// signing step alone), and the signing step runs without the token used here.
// The token never appears in an argument or in a remote URL: git receives it
// as one configuration value through the environment.
//
// `data` only moves forward. The push names no force option, so a remote that
// has moved since it was opened refuses the push, and the next run starts
// from the new tip; the repository's ruleset refuses a forced update as well.

import { execFileSync } from "node:child_process";
import fs from "node:fs";

import { DATA_BRANCH } from "./kinds.mjs";

const IDENTITY = { name: "astra-content-catalogue", email: "41898282+github-actions[bot]@users.noreply.github.com" };

function gitEnv({ token }) {
  const env = { PATH: process.env.PATH ?? "/usr/bin:/bin", HOME: process.env.HOME ?? "/", GIT_TERMINAL_PROMPT: "0", GIT_CONFIG_NOSYSTEM: "1" };
  if (token) {
    const basic = Buffer.from(`x-access-token:${token}`, "utf8").toString("base64");
    Object.assign(env, { GIT_CONFIG_COUNT: "1", GIT_CONFIG_KEY_0: "http.extraheader", GIT_CONFIG_VALUE_0: `AUTHORIZATION: basic ${basic}` });
  }
  return env;
}

function git(dir, args, o) {
  return execFileSync("git", ["-C", dir, ...args], { env: gitEnv(o), encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}

/**
 * Make `dir` a checkout of the remote's `data`, or the start of one when the
 * branch does not exist yet.
 * @returns {{exists: boolean, head: string|null}}
 */
export function openData({ remote, dir, token = null }) {
  fs.mkdirSync(dir, { recursive: true });
  const o = { token };
  git(dir, ["init", "-q", "-b", DATA_BRANCH], o);
  git(dir, ["remote", "add", "origin", remote], o);
  const exists = git(dir, ["ls-remote", "--heads", "origin", DATA_BRANCH], o) !== "";
  if (!exists) return { exists, head: null };
  git(dir, ["fetch", "-q", "--depth", "1", "origin", `refs/heads/${DATA_BRANCH}`], o);
  git(dir, ["reset", "-q", "--hard", "FETCH_HEAD"], o);
  return { exists, head: git(dir, ["rev-parse", "HEAD"], o) };
}

/**
 * Commit what the signing step wrote and move the remote's `data` forward.
 * @returns {{pushed: boolean, head: string|null}}
 */
export function publishData({ dir, message, token = null }) {
  const o = { token };
  git(dir, ["add", "-A", "--", "registry", "state"], o);
  if (git(dir, ["status", "--porcelain"], o) === "") return { pushed: false, head: null };
  git(dir, ["-c", `user.name=${IDENTITY.name}`, "-c", `user.email=${IDENTITY.email}`, "-c", "commit.gpgsign=false", "commit", "-q", "-m", message], o);
  git(dir, ["push", "-q", "origin", `HEAD:refs/heads/${DATA_BRANCH}`], o);
  return { pushed: true, head: git(dir, ["rev-parse", "HEAD"], o) };
}
