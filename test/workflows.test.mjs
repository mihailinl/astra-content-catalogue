// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// The workflows, read as data. What keeps a kind's key from every other job
// is written in sign.yml and nowhere else, so it is tested there.

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";

import { environmentOf, KINDS, secretOf, SERVICE_ENVIRONMENT } from "../lib/kinds.mjs";
import { ROOT } from "../lib/vendored.mjs";
import { parseYaml } from "./yaml.mjs";

const DIR = path.join(ROOT, ".github", "workflows");
const text = (name) => fs.readFileSync(path.join(DIR, name), "utf8");
const workflow = (name) => parseYaml(text(name));
/** Every place a workflow can name a secret or a token, as one string per job. */
const spelled = (job) => JSON.stringify(job);
/** An expression that reads the `secrets` context, however it is indexed. */
const READS_SECRET = /\$\{\{[^}]*\bsecrets\b/;

test("one_job_reads_one_kinds_key", () => {
  const wf = workflow("sign.yml");
  assert.deepEqual(Object.keys(wf.jobs), ["work", "sign"], "two jobs, and no third that could hold a key");
  assert.deepEqual(wf.permissions, {}, "no permission by default");
  const { work, sign } = wf.jobs;

  // work: the token for the service, and no secret
  assert.equal(work.environment, SERVICE_ENVIRONMENT);
  assert.deepEqual(work.permissions, { contents: "read", "id-token": "write" });
  assert.ok(!READS_SECRET.test(spelled(work)) && !/\bsecrets\b/.test(spelled(work)), "work names no secret");
  // its one use of the repository token is to read `data`, with a token that can only read
  assert.deepEqual(work.steps.filter((s) => s.env?.GITHUB_TOKEN).map((s) => s.run), ['node bin/data.mjs open --dir "$RUNNER_TEMP/data"']);
  assert.equal(work.env, undefined, "and no variable can point it at another service");
  assert.ok(!/\bvars\./.test(spelled(wf)), "no repository variable is read anywhere in sign.yml");

  // sign: one leg per kind, each naming its own environment and its own secret
  const legs = sign.strategy.matrix.include;
  assert.deepEqual(Object.keys(sign.strategy.matrix), ["include"], "the legs are listed, not multiplied");
  assert.deepEqual(legs.map((l) => l.kind), [...KINDS], "exactly the five kinds, once each");
  for (const leg of legs) {
    assert.deepEqual(leg, { kind: leg.kind, environment: environmentOf(leg.kind), secret: secretOf(leg.kind) }, leg.kind);
  }
  assert.equal(sign.environment, "${{ matrix.environment }}");
  assert.equal(sign.strategy["max-parallel"], 1);
  assert.equal(sign.strategy["fail-fast"], false);
  assert.deepEqual(sign.permissions, { contents: "write" }, "a signing leg can push data and cannot mint an OIDC token");
  assert.ok(!spelled(sign).includes("id-token"));

  // the key is in the environment of exactly one step of the leg, by the leg's own secret name
  const naming = sign.steps.filter((s) => READS_SECRET.test(spelled(s)));
  assert.equal(naming.length, 1, "one step sees the key");
  assert.deepEqual(naming[0].env, { CONTENT_SIGNING_KEY: "${{ secrets[matrix.secret] }}" }, "and it sees nothing else: no token");
  assert.equal(sign.steps.filter((s) => s.env && "CONTENT_SIGNING_KEY" in s.env).length, 1);
  assert.equal(sign.env?.CONTENT_SIGNING_KEY, undefined, "the key is not in the job's environment");
  // that step runs one Node file and nothing else: no second command, no pipe, no substitution, no action
  assert.equal(naming[0].uses, undefined);
  assert.match(naming[0].run, /^node bin\/sign\.mjs( --[a-z]+ ("\$[A-Z_]+(\/[a-z]+)?"|[A-Za-z0-9_.\/-]+))+$/);
  assert.equal(naming[0].run, 'node bin/sign.mjs --kind "$KIND" --trust registry-trust/registry/v1/trust.json --work "$RUNNER_TEMP/work"');
  assert.equal(naming[0].shell, undefined);
  const uncommented = text("sign.yml").split("\n").filter((l) => !l.trim().startsWith("#")).join("\n");
  assert.equal(uncommented.match(/secrets\b/g).length, 1, "`secrets` is written once in sign.yml");
  assert.ok(!/secrets:\s*inherit/.test(uncommented));
  for (const kind of KINDS) {
    assert.equal(uncommented.split(secretOf(kind)).length - 1, 1, `${secretOf(kind)} is named by one leg`);
    assert.equal(uncommented.split(environmentOf(kind)).length - 1, 1, `${environmentOf(kind)} is named by one leg`);
  }
  // the five steps of a leg, in order: the token only at the two ends, the key only in the middle,
  // and the two steps that run the checker on either side of the key with neither
  const commands = sign.steps.filter((s) => s.run).map((s) => ({ run: s.run.split(" ").slice(0, 3).join(" ").replace(/ --\w+$/, ""), env: Object.keys(s.env ?? {}) }));
  assert.deepEqual(commands, [
    { run: "node bin/data.mjs open", env: ["GITHUB_TOKEN"] },
    { run: "node bin/prepare.mjs", env: [] },
    { run: "node bin/sign.mjs", env: ["CONTENT_SIGNING_KEY"] },
    { run: "node bin/verify.mjs", env: [] },
    { run: "node bin/data.mjs publish", env: ["GITHUB_TOKEN"] },
  ]);
  assert.deepEqual(sign.env, { KIND: "${{ matrix.kind }}" });

  // no other workflow names a signing environment, a secret, or an OIDC token
  for (const name of fs.readdirSync(DIR).filter((n) => n !== "sign.yml")) {
    const other = workflow(name);
    for (const [id, job] of Object.entries(other.jobs)) {
      assert.equal(job.environment, undefined, `${name} ${id}: no environment`);
      assert.ok(!READS_SECRET.test(spelled(job)) && !/secrets:\s*inherit/.test(text(name)) && !spelled(job).includes("id-token"), `${name} ${id}: no secret and no OIDC token`);
    }
  }
});

test("sign.yml runs on main, every ten minutes and on a dispatch, one run at a time", () => {
  const wf = workflow("sign.yml");
  assert.deepEqual(wf.on, { schedule: [{ cron: "*/10 * * * *" }], workflow_dispatch: null });
  assert.deepEqual(wf.concurrency, { group: "content-sign", "cancel-in-progress": false });
  assert.equal(wf.jobs.work.if, "github.ref == 'refs/heads/main'");
  assert.equal(wf.jobs.sign.needs, "work");
  // a closed door leaves `todo` false, and then no signing leg starts
  assert.equal(wf.jobs.sign.if, "${{ !cancelled() && needs.work.outputs.todo == 'true' }}");
  assert.equal(wf.jobs.work.outputs.todo, "${{ steps.fetch.outputs.todo }}");
  // every checkout of this repository is of main, and leaves no credential behind
  for (const job of Object.values(wf.jobs)) {
    for (const step of job.steps.filter((s) => s.uses?.startsWith("actions/checkout@"))) {
      assert.equal(step.with.ref, "main");
      assert.equal(step.with["persist-credentials"], false);
    }
  }
});

test("every action is pinned by the full commit the pins table records", () => {
  const pins = JSON.parse(fs.readFileSync(path.join(ROOT, ".github", "action-pins.json"), "utf8"));
  let n = 0;
  for (const name of fs.readdirSync(DIR)) {
    for (const job of Object.values(workflow(name).jobs)) {
      for (const step of job.steps) {
        if (!step.uses) continue;
        const [action, sha] = step.uses.split("@");
        assert.match(sha, /^[0-9a-f]{40}$/, `${name}: ${step.uses}`);
        assert.equal(pins[action]?.sha, sha, `${name}: ${action} is not at the recorded commit`);
        n++;
      }
    }
    // and the comment beside each pin names the recorded tag
    for (const m of text(name).matchAll(/uses: (\S+)@([0-9a-f]{40}) # (\S+)/g)) assert.equal(pins[m[1]].tag, m[3], `${name}: ${m[1]}`);
  }
  assert.ok(n >= 8);
});

test("keepalive re-enables the scheduled workflows with the job's own token", () => {
  const wf = workflow("keepalive.yml");
  assert.deepEqual(wf.permissions, {});
  assert.deepEqual(wf.jobs.enable.permissions, { actions: "write" });
  assert.ok(wf.on.schedule.length === 1 && "workflow_dispatch" in wf.on);
  const run = wf.jobs.enable.steps[0].run;
  assert.match(run, /for workflow in sign\.yml keepalive\.yml; do/);
  assert.match(run, /gh api --method PUT "repos\/\$REPO\/actions\/workflows\/\$workflow\/enable"/);
});
