// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// The call to the service's door (lib/service.mjs, bin/fetch.mjs), against a
// fetch written here. No network.

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";

import { main as fetchMain } from "../bin/fetch.mjs";
import { KINDS } from "../lib/kinds.mjs";
import { CLOSED_MAX_AGE, MAX_EXPORT_BYTES } from "../lib/kinds.mjs";
import { AUDIENCE, fetchAll, SERVICE_BASE } from "../lib/service.mjs";
import { commitData, exportOf, NOW, plant, scratch, throwawayTrust } from "./helpers.mjs";

const ENV = { ACTIONS_ID_TOKEN_REQUEST_URL: "https://oidc.invalid/token?v=1", ACTIONS_ID_TOKEN_REQUEST_TOKEN: "request-token" };
const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

/** A fetch that mints numbered tokens and answers the door with `door(kind, token)`. */
function fakeFetch(door) {
  const calls = { tokens: [], doors: [] };
  let n = 0;
  const impl = async (url, init = {}) => {
    const u = new URL(url);
    if (u.host === "oidc.invalid") {
      assert.equal(init.headers.Authorization, "Bearer request-token");
      calls.tokens.push(u.searchParams.get("audience"));
      return json(200, { value: `token-${++n}` });
    }
    const m = /^\/plugins\/v1\/bot\/content\/([a-z]+)\/accepted$/.exec(u.pathname);
    assert.ok(m, `an unexpected path ${u.pathname}`);
    assert.equal(init.method, "GET");
    assert.equal(init.redirect, "error", "a redirect would carry the bearer to another host");
    assert.equal(u.origin, "https://api.minice.ai");
    assert.equal(init.body, undefined, "the signer sends the token only");
    calls.doors.push({ kind: m[1], bearer: init.headers.Authorization });
    return door(m[1]);
  };
  return { impl, calls };
}

test("each kind is asked at its door with a token of its own, minted for the content audience", async () => {
  const { impl, calls } = fakeFetch((kind) => json(200, exportOf(kind)));
  const got = await fetchAll({ env: ENV, fetchImpl: impl });
  assert.deepEqual(Object.keys(got), [...KINDS]);
  assert.ok(Object.values(got).every((r) => r.status === "fetched"));
  assert.deepEqual(calls.doors.map((d) => d.kind), [...KINDS]);
  assert.equal(AUDIENCE, "https://api.minice.ai/plugins/v1/content");
  assert.deepEqual(calls.tokens, KINDS.map(() => AUDIENCE));
  // one token makes one call: five calls, five different tokens
  assert.equal(new Set(calls.doors.map((d) => d.bearer)).size, KINDS.length);
});

test("a door that is not open is quiet for a kind that was never published", async (t) => {
  for (const [name, answer] of [
    ["404", () => new Response("not found", { status: 404 })],
    ["unavailable", () => json(503, { error: "unavailable" })],
    ["a bare 503", () => new Response("", { status: 503 })],
  ]) {
    const { impl, calls } = fakeFetch(answer);
    const out = scratch(t);
    const data = scratch(t, "data");
    const outputs = path.join(out, "outputs");
    const lines = [];
    const work = await fetchMain(["--out", out, "--data", data], { env: { ...ENV, GITHUB_OUTPUT: outputs }, fetchImpl: impl, log: (l) => lines.push(l), now: NOW });
    assert.deepEqual(work.kinds, Object.fromEntries(KINDS.map((k) => [k, "closed"])), name);
    assert.equal(calls.doors.length, KINDS.length, `${name}: each kind is asked for itself`);
    assert.equal(fs.readFileSync(outputs, "utf8"), "todo=false\nfailed=false\n", name);
    assert.ok(lines.some((l) => l.includes("service door not open")), name);
    assert.deepEqual(fs.readdirSync(out).sort(), ["outputs", "work.json"], `${name}: no export is written`);
  }
});

test("a door that stays shut fails the run for a kind published more than twelve hours ago, kind by kind", async (t) => {
  const trust = throwawayTrust();
  const data = scratch(t, "data");
  const put = (kind, age) => plant(data, kind, { seed: trust.seeds[kind].current, keyId: `astra-${kind}-testa`, serial: NOW - age });
  put("commands", CLOSED_MAX_AGE + 1); // overdue
  put("characters", CLOSED_MAX_AGE); // still inside the twelve hours
  put("models", 600);
  put("animsets", 86400 * 3);
  fs.writeFileSync(path.join(data, "registry", "v1", "animsets", "withdrawn.json"), "{"); // published, and unreadable
  commitData(data, "four kinds"); // whether a kind was ever published is read from the branch's history
  // packs: never published. The door answers for models only.
  const { impl } = fakeFetch((kind) => (kind === "models" ? json(200, exportOf(kind)) : new Response("", { status: 404 })));
  const ask = async (fetchImpl) => {
    const out = scratch(t);
    const outputs = path.join(out, "outputs");
    const lines = [];
    const work = await fetchMain(["--out", out, "--data", data], { env: { ...ENV, GITHUB_OUTPUT: outputs }, fetchImpl, log: (l) => lines.push(l), now: NOW });
    return { kinds: work.kinds, outputs: fs.readFileSync(outputs, "utf8"), lines };
  };
  const first = await ask(impl);
  assert.deepEqual(first.kinds, { commands: "overdue", characters: "closed", models: "fetched", animsets: "overdue", packs: "closed" });
  assert.equal(first.outputs, "todo=true\nfailed=true\n", "the run fails, and the kind that was answered is still handed on");
  assert.ok(first.lines.some((l) => l.startsWith("commands: service door not open (HTTP 404) and the kind was last signed 43201 s ago")));

  const closed = fakeFetch(() => new Response("", { status: 404 })).impl;
  // inside the twelve hours again, and animsets' unreadable file mended: quiet
  put("commands", 3600);
  put("animsets", 3600);
  commitData(data, "mended");
  const quiet = await ask(closed);
  assert.deepEqual(Object.values(quiet.kinds), KINDS.map(() => "closed"));
  assert.equal(quiet.outputs, "todo=false\nfailed=false\n");

  // a kind whose files were removed was still published: history says so, and the run fails
  fs.rmSync(path.join(data, "registry", "v1", "animsets"), { recursive: true });
  fs.rmSync(path.join(data, "state", "animsets.json"));
  commitData(data, "remove animsets");
  const removed = await ask(closed);
  assert.equal(removed.kinds.animsets, "overdue");
  assert.ok(removed.lines.some((l) => l.startsWith("animsets: service door not open (HTTP 404) and the kind was last signed at a time that cannot be read")));
  assert.equal(removed.outputs, "todo=false\nfailed=true\n");

  // a last signature dated in the future is overdue, not fresh
  put("characters", -600);
  commitData(data, "from the future");
  const future = await ask(closed);
  assert.equal(future.kinds.characters, "overdue");
  assert.ok(future.lines.some((l) => l.startsWith("characters: service door not open (HTTP 404) and the kind was last signed at a time in the future")));

  // a kind with a state file and no documents was published too
  fs.mkdirSync(path.join(data, "state"), { recursive: true });
  fs.writeFileSync(path.join(data, "state", "packs.json"), "{}");
  commitData(data, "packs state");
  assert.equal((await ask(closed)).kinds.packs, "overdue");
});

test("a refused call fails the run and still hands on the kinds that were answered", async (t) => {
  const { impl } = fakeFetch((kind) => (kind === "models" ? json(429, { error: "rate_limited" }) : json(200, exportOf(kind))));
  const out = scratch(t);
  const outputs = path.join(out, "outputs");
  const lines = [];
  const work = await fetchMain(["--out", out, "--data", scratch(t, "data")], { env: { ...ENV, GITHUB_OUTPUT: outputs }, fetchImpl: impl, log: (l) => lines.push(l), now: NOW });
  assert.equal(work.kinds.models, "refused");
  assert.equal(work.kinds.commands, "fetched");
  assert.equal(work.kinds.packs, "fetched");
  assert.equal(fs.readFileSync(outputs, "utf8"), "todo=true\nfailed=true\n");
  assert.ok(lines.includes("models: refused (HTTP 429 rate_limited)"));
  assert.ok(!fs.existsSync(path.join(out, "export-models.json")));
  // the bytes handed on are the service's, untouched
  assert.equal(fs.readFileSync(path.join(out, "export-packs.json"), "utf8"), JSON.stringify(exportOf("packs")));
  // no token is ever written to the log or to the files
  const everything = lines.join("\n") + fs.readdirSync(out).map((f) => fs.readFileSync(path.join(out, f), "utf8")).join("\n");
  assert.ok(!/token-\d|request-token/.test(everything));
});

test("an answer becomes an artifact only after it is checked: a refused one is never written where the upload reads", async (t) => {
  const bad = {
    // a member the export schema does not name (an account fact, say)
    commands: (k) => json(200, { ...exportOf(k), moderator: "someone" }),
    // an entry the kind's index schema refuses
    characters: (k) => json(200, exportOf(k, { entries: [{ id: "x" }] })),
    // stale: generated an hour before the run
    models: (k) => json(200, exportOf(k, { at: NOW - 3600 })),
    // not JSON
    animsets: () => new Response("{", { status: 200, headers: { "content-type": "application/json" } }),
  };
  const { impl } = fakeFetch((kind) => (bad[kind] ? bad[kind](kind) : json(200, exportOf(kind))));
  const out = scratch(t);
  const outputs = path.join(out, "outputs");
  const lines = [];
  const work = await fetchMain(["--out", out, "--data", scratch(t, "data")], { env: { ...ENV, GITHUB_OUTPUT: outputs }, fetchImpl: impl, log: (l) => lines.push(l), now: NOW });
  assert.deepEqual(work.kinds, { commands: "refused", characters: "refused", models: "refused", animsets: "refused", packs: "fetched" });
  assert.deepEqual(fs.readdirSync(out).sort(), ["export-packs.json", "outputs", "work.json"], "only the answer that passed is in the artifact's directory");
  assert.equal(fs.readFileSync(outputs, "utf8"), "todo=true\nfailed=true\n");
  for (const kind of Object.keys(bad)) assert.ok(lines.some((l) => l.startsWith(`${kind}: the answer is refused (E_`)), kind);
  // and nothing the service chose is printed
  assert.ok(!lines.join("\n").includes("moderator") && !lines.join("\n").includes("someone"));
});

test("a refused token is not offered four more times", async () => {
  const { impl, calls } = fakeFetch(() => json(401, { error: "token_refused" }));
  const got = await fetchAll({ env: ENV, fetchImpl: impl });
  assert.equal(calls.doors.length, 1);
  assert.deepEqual(Object.values(got).map((r) => r.status), KINDS.map(() => "refused"));
  assert.equal(got.packs.why, "not asked: HTTP 401 token_refused");
});

test("other answers are refusals, not a closed door", async () => {
  for (const [status, body] of [[429, { error: "rate_limited" }], [409, { error: "replay" }], [400, { error: "invalid" }], [500, {}], [403, { error: "unavailable_soon" }]]) {
    const { impl } = fakeFetch(() => json(status, body));
    const got = await fetchAll({ env: ENV, fetchImpl: impl });
    assert.equal(got.commands.status, "refused", `HTTP ${status}`);
  }
  const big = fakeFetch(() => new Response(Buffer.alloc(MAX_EXPORT_BYTES + 1, 0x20), { status: 200 }));
  assert.equal(MAX_EXPORT_BYTES, 4 * 1048576);
  const fits = fakeFetch(() => new Response(Buffer.alloc(MAX_EXPORT_BYTES, 0x20), { status: 200 }));
  assert.equal((await fetchAll({ env: ENV, fetchImpl: fits.impl })).commands.status, "fetched");
  assert.equal((await fetchAll({ env: ENV, fetchImpl: big.impl })).commands.status, "refused");
  const down = fakeFetch(() => {
    throw new TypeError("fetch failed");
  });
  assert.equal((await fetchAll({ env: ENV, fetchImpl: down.impl })).commands.status, "refused");
});

test("the bearer goes to one compiled base, whatever the environment says", async () => {
  assert.equal(SERVICE_BASE, "https://api.minice.ai/plugins/v1");
  // the token is this repository's identity at the service: no variable may send it elsewhere
  const { impl, calls } = fakeFetch((kind) => json(200, exportOf(kind)));
  await fetchAll({ env: { ...ENV, CONTENT_SERVICE_URL: "https://elsewhere.example/plugins/v1", GAMES_SERVICE_URL: "https://elsewhere.example" }, fetchImpl: impl });
  assert.equal(calls.doors.length, KINDS.length, "every call went to the compiled host (the fetch above refuses any other)");
  await assert.rejects(fetchAll({ env: {}, fetchImpl: async () => json(200, {}) }), /id-token: write/);
});
