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
  assert.deepEqual(Object.keys(wf.jobs), ["work", "prepare", "sign", "publish"], "four jobs, and only `sign` may hold a key");
  assert.deepEqual(wf.permissions, {}, "no permission by default");
  const { work, prepare, sign, publish } = wf.jobs;

  // the key secret is read in exactly one job, and in one step of it
  const readers = Object.entries(wf.jobs).filter(([, job]) => READS_SECRET.test(spelled(job)) || /\bsecrets\b/.test(spelled(job)));
  assert.deepEqual(readers.map(([id]) => id), ["sign"], "the key secret appears in exactly one job");
  const uncommented = text("sign.yml").split("\n").filter((l) => !l.trim().startsWith("#")).join("\n");
  assert.equal(uncommented.match(/secrets\b/g).length, 1, "`secrets` is written once in sign.yml");
  assert.ok(!/secrets:\s*inherit/.test(uncommented));
  for (const kind of KINDS) {
    assert.equal(uncommented.split(secretOf(kind)).length - 1, 1, `${secretOf(kind)} is named by one leg`);
    assert.equal(uncommented.split(environmentOf(kind)).length - 1, 1, `${environmentOf(kind)} is named by one leg`);
  }
  assert.ok(!/\bvars\./.test(spelled(wf)), "no repository variable is read anywhere in sign.yml");
  assert.ok(!/GITHUB_(ENV|PATH)/.test(uncommented), "no step writes another step's environment or PATH");

  // work: the token for the service, and no secret
  assert.equal(work.environment, SERVICE_ENVIRONMENT);
  assert.deepEqual(work.permissions, { contents: "read", "id-token": "write" });
  // its one use of the repository token is to read `data`
  assert.deepEqual(work.steps.filter((s) => s.env?.GITHUB_TOKEN).map((s) => s.run), ['node bin/data.mjs open --dir "$RUNNER_TEMP/data"']);
  assert.equal(work.env, undefined, "and no variable can point it at another service");

  // no job but `work` can mint an OIDC token or enters an environment that is not a kind's
  for (const [id, job] of Object.entries(wf.jobs)) {
    if (id !== "work") assert.ok(!spelled(job).includes("id-token") && job.environment !== SERVICE_ENVIRONMENT, `${id}: no OIDC token`);
  }
  // prepare and publish enter no environment, so they can read no key
  assert.equal(prepare.environment, undefined);
  assert.equal(publish.environment, undefined);
  assert.deepEqual(prepare.permissions, { contents: "read" });
  assert.deepEqual(publish.permissions, { contents: "write" }, "only the publishing job, which holds no key, can push data");

  // sign: one leg per kind, each naming its own environment and its own secret
  const legs = sign.strategy.matrix.include;
  assert.deepEqual(Object.keys(sign.strategy.matrix), ["include"], "the legs are listed, not multiplied");
  assert.deepEqual(legs.map((l) => l.kind), [...KINDS], "exactly the five kinds, once each");
  for (const leg of legs) {
    assert.deepEqual(leg, { kind: leg.kind, environment: environmentOf(leg.kind), secret: secretOf(leg.kind) }, leg.kind);
  }
  assert.equal(sign.environment, "${{ matrix.environment }}");
  assert.equal(sign.strategy["fail-fast"], false);
  assert.deepEqual(sign.permissions, {}, "the key job's token has no permission: no contents, no OIDC token");
  assert.deepEqual(sign.env, { KIND: "${{ matrix.kind }}" }, "the job's environment is the kind's name and nothing else");
  // what leaves the key job: one job output per kind, set by the key step, and no artifact
  assert.deepEqual(sign.outputs, Object.fromEntries(KINDS.map((k) => [k, `\${{ steps.sign.outputs.${k} }}`])), "one output per kind, so that the legs do not overwrite one another");
  assert.equal(sign.needs, "prepare", "the key job waits on the preparing job alone");

  // its steps: one fresh checkout of this commit, one download of the kind's prepared artifact,
  // ONE node command; no setup action, no script, no upload, nothing else
  const shape = sign.steps.map((s) => (s.uses ? s.uses.split("@")[0] : `run:${s.run.split(" ").slice(0, 2).join(" ")}`));
  assert.deepEqual(shape, ["actions/checkout", "actions/download-artifact", "run:node bin/sign.mjs"]);
  const [checkout, download, key] = sign.steps;
  assert.deepEqual(checkout.with, { ref: "${{ github.sha }}", "persist-credentials": false }, "a fresh checkout of the same commit, no credential");
  // its input is the artifact the preparing job uploaded for this kind, and only that
  const prepared = prepare.steps.find((s) => s.uses?.startsWith("actions/upload-artifact@"));
  assert.equal(prepared.with.name, "prepared-${{ matrix.kind }}");
  assert.deepEqual(download.with, { name: prepared.with.name, path: "${{ runner.temp }}/prepared" }, "the input artifact is the preparing job's");
  assert.equal(sign.steps.filter((s) => s.uses?.startsWith("actions/download-artifact@")).length, 1);
  // the key is in the environment of that one step, by the leg's own secret name, and it sees nothing else
  assert.deepEqual(key.env, { CONTENT_SIGNING_KEY: "${{ secrets[matrix.secret] }}" }, "the key step sees the key and no token");
  assert.equal(key.shell, undefined);
  assert.equal(key.run, 'node bin/sign.mjs --kind "$KIND" --work "$RUNNER_TEMP/prepared" --out "$RUNNER_TEMP/signed"', "one Node file and nothing else: no second command, no pipe, no substitution");
  assert.equal(key.id, "sign");
  // no signed document is ever an artifact (a public repository's artifacts can be downloaded by anyone):
  // publish takes the key job's line for its kind, in the verifying step's environment
  assert.ok(!text("sign.yml").includes("signed-"), "no artifact named signed-<kind>");
  assert.deepEqual(publish.steps.filter((s) => s.uses?.startsWith("actions/download-artifact@")).map((s) => s.with.name), ["prepared-${{ matrix.kind }}"]);
  const verifyStep = publish.steps.find((s) => s.run?.startsWith("node bin/verify.mjs"));
  assert.deepEqual(verifyStep.env, { SIGNED_RESULT: "${{ needs.sign.outputs[matrix.kind] }}" });

  // the work job checks every answer before it becomes an artifact: the upload comes after the fetch, and takes its output dir
  const fetchAt = work.steps.findIndex((s) => s.id === "fetch");
  const uploadAt = work.steps.findIndex((s) => s.uses?.startsWith("actions/upload-artifact@"));
  assert.ok(fetchAt >= 0 && uploadAt > fetchAt, "the answers are checked before they are uploaded");
  assert.match(work.steps[fetchAt].run, /--out "\$RUNNER_TEMP\/exports"/);
  assert.equal(work.steps[uploadAt].with.path, "${{ runner.temp }}/exports");

  // the commands of the other jobs: the checker runs in prepare and publish, which hold no key
  const runs = (job) => job.steps.filter((s) => s.run).map((s) => ({ run: s.run.split(" ").slice(0, 3).join(" ").replace(/ --\w+$/, ""), env: Object.keys(s.env ?? {}) }));
  assert.deepEqual(runs(prepare), [
    { run: "node bin/data.mjs open", env: ["GITHUB_TOKEN"] },
    { run: "node bin/prepare.mjs", env: [] },
  ]);
  assert.deepEqual(runs(publish), [
    { run: "node bin/data.mjs open", env: ["GITHUB_TOKEN"] },
    { run: "node bin/verify.mjs", env: ["SIGNED_RESULT"] },
    { run: "node bin/data.mjs publish", env: ["GITHUB_TOKEN"] },
  ]);
  assert.equal(publish.strategy["max-parallel"], 1, "one push to data at a time");

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
  assert.equal(wf.jobs.work.outputs.todo, "${{ steps.fetch.outputs.todo }}");
  // a closed door leaves `todo` false, and then no later job starts
  assert.equal(wf.jobs.prepare.needs, "work");
  assert.equal(wf.jobs.prepare.if, "${{ !cancelled() && needs.work.outputs.todo == 'true' }}");
  assert.equal(wf.jobs.sign.if, "${{ !cancelled() && needs.prepare.result != 'skipped' }}");
  assert.deepEqual(wf.jobs.publish.needs, ["prepare", "sign"]);
  assert.equal(wf.jobs.publish.if, "${{ !cancelled() && needs.sign.result != 'skipped' }}");
  // every checkout of this repository is of the commit the run started from, and leaves no credential behind
  for (const [id, job] of Object.entries(wf.jobs)) {
    for (const step of job.steps.filter((s) => s.uses?.startsWith("actions/checkout@"))) {
      assert.equal(step.with["persist-credentials"], false, id);
      if (step.with.repository === undefined) assert.equal(step.with.ref, "${{ github.sha }}", id);
      else assert.deepEqual([step.with.repository, step.with.ref], ["mihailinl/astra-registry", "main"], `${id}: only trust.json is read from elsewhere`);
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
