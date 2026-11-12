#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// A stand-in for `gh`, for rehearsing owner/ without GitHub. A test copies it
// to a scratch directory as `gh` and puts that directory first on PATH. It
// keeps its state in state.json and one line per call in calls.jsonl, both
// beside itself, and answers only the calls owner/ makes: anything else exits
// 1, so a new call in owner/ fails the rehearsal until it is modelled here.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const here = path.dirname(process.argv[1]);
const stateFile = path.join(here, "state.json");
const state = fs.existsSync(stateFile) ? JSON.parse(fs.readFileSync(stateFile, "utf8")) : { environments: {}, rulesets: [], secrets: {}, data: {}, nextId: 1 };
const argv = process.argv.slice(2);
const stdin = () => fs.readFileSync(0);
const done = (out = "", record = {}) => {
  fs.writeFileSync(stateFile, JSON.stringify(state, null, 2));
  fs.appendFileSync(path.join(here, "calls.jsonl"), `${JSON.stringify({ argv, env: Object.keys(process.env).sort(), ...record })}\n`);
  if (out) process.stdout.write(out.endsWith("\n") ? out : `${out}\n`);
  process.exit(0);
};
const fail = (why) => {
  process.stderr.write(`fake gh: ${why}: ${argv.join(" ")}\n`);
  process.exit(1);
};

if (argv[0] === "secret" && argv[1] === "set") {
  const name = argv[2];
  const flags = Object.fromEntries([3, 5].map((i) => [argv[i], argv[i + 1]]));
  if (argv.length !== 7 || !flags["--env"] || !flags["--repo"]) fail("unexpected arguments");
  if (!(flags["--env"] in state.environments) && state.requireEnvironments) fail("no such environment");
  const value = stdin();
  state.secrets[`${flags["--repo"]}/${flags["--env"]}/${name}`] = value.toString("base64");
  done("", { stdin_sha256: crypto.createHash("sha256").update(value).digest("hex") });
}

if (argv[0] === "api") {
  let method = "GET";
  let jq = null;
  let input = false;
  let route = null;
  let raw = false;
  for (let i = 1; i < argv.length; i++) {
    if (argv[i] === "-H") raw = argv[++i] === "Accept: application/vnd.github.raw" || raw;
    else if (argv[i] === "--method") method = argv[++i];
    else if (argv[i] === "--jq") jq = argv[++i];
    else if (argv[i] === "--input") input = argv[++i] === "-";
    else if (argv[i] === "--paginate") continue;
    else if (route === null) route = argv[i];
    else fail("unexpected argument");
  }
  const body = input ? JSON.parse(stdin().toString("utf8")) : null;
  const REPO_ID = { "mihailinl/astra-content-catalogue": 1454718826 };
  let m;
  if ((m = /^repos\/([^/]+\/[^/]+)\/contents\/(.+)\?ref=data$/.exec(route)) && method === "GET" && raw) {
    if (!(m[2] in (state.data ?? {}))) {
      process.stderr.write("gh: Not Found (HTTP 404)\n");
      process.exit(1);
    }
    done(state.data[m[2]]);
  }
  if ((m = /^repos\/([^/]+\/[^/]+)\/environments\/([a-z-]+)$/.exec(route)) && method === "GET") {
    const env = state.environments[m[2]];
    if (!env) fail("no such environment");
    done(JSON.stringify({ name: m[2], deployment_branch_policy: env.settings.deployment_branch_policy }));
  }
  if ((m = /^repos\/([^/]+\/[^/]+)\/rulesets\/(\d+)$/.exec(route)) && method === "GET") {
    const r = state.rulesets.find((x) => x.id === Number(m[2]));
    if (!r) fail("no such ruleset");
    // GitHub shows the bypass list only to a token that can administer the repository
    if (state.notAdmin) {
      const { bypass_actors, ...seen } = r;
      done(JSON.stringify(seen));
    }
    done(JSON.stringify(r));
  }
  if ((m = /^repos\/([^/]+\/[^/]+)\/environments\/([a-z-]+)$/.exec(route)) && method === "PUT") {
    state.environments[m[2]] = { ...(state.environments[m[2]] ?? { policies: [] }), settings: body };
    done("{}");
  }
  if ((m = /^repos\/([^/]+\/[^/]+)\/environments\/([a-z-]+)\/deployment-branch-policies$/.exec(route))) {
    const env = state.environments[m[2]];
    if (!env) fail("no such environment");
    if (method === "POST") {
      env.policies.push(body);
      done("{}");
    }
    if (jq === null) done(JSON.stringify({ total_count: env.policies.length, branch_policies: env.policies }));
    if (jq === '.branch_policies[] | select(.type == "branch") | .name') done(env.policies.filter((p) => p.type === "branch").map((p) => p.name).join("\n"));
    if (jq === '[.branch_policies[] | select(.name != "main" or .type != "branch") | "\\(.type) \\(.name)"] | join(", ")') {
      done(env.policies.filter((p) => p.name !== "main" || p.type !== "branch").map((p) => `${p.type} ${p.name}`).join(", "));
    }
    fail("an unmodelled --jq");
  }
  if ((m = /^repos\/([^/]+\/[^/]+)\/rulesets$/.exec(route))) {
    if (method === "POST") {
      state.rulesets.push({ id: state.nextId++, ...body });
      done("{}");
    }
    if (jq === null) done(JSON.stringify(state.rulesets.map(({ id, name, target, enforcement }) => ({ id, name, target, enforcement }))));
    const sel = /^\.\[\] \| select\(\.name == "(.*)"\) \| \.id$/.exec(jq ?? "");
    if (!sel) fail("an unmodelled --jq");
    done(state.rulesets.filter((r) => r.name === sel[1]).map((r) => r.id).join("\n"));
  }
  if ((m = /^repos\/([^/]+\/[^/]+)\/rulesets\/(\d+)$/.exec(route)) && method === "PUT") {
    const i = state.rulesets.findIndex((r) => r.id === Number(m[2]));
    if (i < 0) fail("no such ruleset");
    state.rulesets[i] = { id: Number(m[2]), ...body };
    done("{}");
  }
  if ((m = /^repos\/([^/]+\/[^/]+)$/.exec(route)) && method === "GET") {
    const id = REPO_ID[m[1]] ?? 999;
    if (jq === null) done(JSON.stringify({ id, owner: { id: 193032699 }, default_branch: state.defaultBranch ?? "main" }));
    if (jq !== '"repository_id        \\(.id)\\nrepository_owner_id  \\(.owner.id)"') fail("an unmodelled --jq");
    done(`repository_id        ${id}\nrepository_owner_id  193032699`);
  }
}
fail("an unmodelled call");
