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
import { AUDIENCE, fetchAll, serviceBase } from "../lib/service.mjs";
import { exportOf, scratch } from "./helpers.mjs";

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

test("a door that is not open ends the run green, and is asked once", async (t) => {
  for (const [name, answer] of [
    ["404", () => new Response("not found", { status: 404 })],
    ["unavailable", () => json(503, { error: "unavailable" })],
    ["a bare 503", () => new Response("", { status: 503 })],
  ]) {
    const { impl, calls } = fakeFetch(answer);
    const out = scratch(t);
    const outputs = path.join(out, "outputs");
    const lines = [];
    const work = await fetchMain(["--out", out], { env: { ...ENV, GITHUB_OUTPUT: outputs }, fetchImpl: impl, log: (l) => lines.push(l) });
    assert.deepEqual(work.kinds, Object.fromEntries(KINDS.map((k) => [k, "closed"])), name);
    assert.equal(calls.doors.length, 1, `${name}: the other four kinds are not asked`);
    assert.equal(fs.readFileSync(outputs, "utf8"), "todo=false\nfailed=false\n", name);
    assert.ok(lines.some((l) => l.includes("service door not open")), name);
    assert.deepEqual(fs.readdirSync(out).sort(), ["outputs", "work.json"], `${name}: no export is written`);
  }
});

test("a refused call fails the run and still hands on the kinds that were answered", async (t) => {
  const { impl } = fakeFetch((kind) => (kind === "models" ? json(401, { error: "token_refused" }) : json(200, exportOf(kind))));
  const out = scratch(t);
  const outputs = path.join(out, "outputs");
  const lines = [];
  const work = await fetchMain(["--out", out], { env: { ...ENV, GITHUB_OUTPUT: outputs }, fetchImpl: impl, log: (l) => lines.push(l) });
  assert.equal(work.kinds.models, "refused");
  assert.equal(work.kinds.commands, "fetched");
  assert.equal(work.kinds.packs, "fetched");
  assert.equal(fs.readFileSync(outputs, "utf8"), "todo=true\nfailed=true\n");
  assert.ok(lines.includes("models: refused (HTTP 401 token_refused)"));
  assert.ok(!fs.existsSync(path.join(out, "export-models.json")));
  // the bytes handed on are the service's, untouched
  assert.equal(fs.readFileSync(path.join(out, "export-packs.json"), "utf8"), JSON.stringify(exportOf("packs")));
  // no token is ever written to the log or to the files
  const everything = lines.join("\n") + fs.readdirSync(out).map((f) => fs.readFileSync(path.join(out, f), "utf8")).join("\n");
  assert.ok(!/token-\d|request-token/.test(everything));
});

test("other answers are refusals, not a closed door", async () => {
  for (const [status, body] of [[429, { error: "rate_limited" }], [409, { error: "replay" }], [400, { error: "invalid" }], [500, {}], [403, { error: "unavailable_soon" }]]) {
    const { impl } = fakeFetch(() => json(status, body));
    const got = await fetchAll({ env: ENV, fetchImpl: impl });
    assert.equal(got.commands.status, "refused", `HTTP ${status}`);
  }
  const big = fakeFetch(() => new Response(Buffer.alloc(4 * 1048576 + 1, 0x20), { status: 200 }));
  assert.equal((await fetchAll({ env: ENV, fetchImpl: big.impl })).commands.status, "refused");
  const down = fakeFetch(() => {
    throw new TypeError("fetch failed");
  });
  assert.equal((await fetchAll({ env: ENV, fetchImpl: down.impl })).commands.status, "refused");
});

test("the service base is a plain https URL, and a job without id-token cannot ask", async () => {
  assert.equal(serviceBase({}), "https://api.minice.ai/plugins/v1");
  assert.equal(serviceBase({ CONTENT_SERVICE_URL: "https://stand.example/plugins/v1/" }), "https://stand.example/plugins/v1");
  for (const bad of ["http://api.minice.ai/plugins/v1", "https://user:pw@api.minice.ai/x", "https://api.minice.ai/x?y=1", "nonsense"]) {
    assert.throws(() => serviceBase({ CONTENT_SERVICE_URL: bad }), /CONTENT_SERVICE_URL/);
  }
  await assert.rejects(fetchAll({ env: {}, fetchImpl: async () => json(200, {}) }), /id-token: write/);
});
