// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// The one door the signer reads: GET <base>/bot/content/{kind}/accepted.
//
// The credential is a GitHub OIDC token minted by the calling job for the
// audience below. The service pins that audience, this repository, this
// workflow on `main` and the job's environment, and lets one token make one
// call, so a token is minted per call and never kept. There is no other
// credential: the job that runs this holds no secret.
//
// "Not open" is an answer the door can give: before the service opens it the
// door answers 404, and while the service is restarting or shut it answers
// `unavailable` (or a bare 503). For a kind that has never been published
// that ends the kind's part of the run quietly. For a kind that HAS been
// published it is quiet only while its last signature is fresh: bin/fetch.mjs
// fails the run once a published kind has gone twelve hours without being
// signed, because a door that stays shut means the kind's withdrawn document
// goes stale and nobody would be told. Every other refusal fails the run.
//
// The service base is a constant. The bearer token is this repository's
// identity at the service; a base that could be set from outside the code
// would send that token wherever it pointed.

import { assertKind, KINDS, MAX_EXPORT_BYTES } from "./kinds.mjs";

export const SERVICE_BASE = "https://api.minice.ai/plugins/v1";
/** The audience the service pins. An opaque string: it does not follow the base. */
export const AUDIENCE = "https://api.minice.ai/plugins/v1/content";
export const doorOf = (kind) => `bot/content/${assertKind(kind)}/accepted`;

/** A GitHub OIDC token for the content audience (the job needs `id-token: write`). */
export async function oidcToken({ env = process.env, fetchImpl = fetch } = {}) {
  const url = env.ACTIONS_ID_TOKEN_REQUEST_URL;
  const bearer = env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  if (!url || !bearer) throw new Error("this job cannot mint an OIDC token (permissions: id-token: write)");
  const r = await fetchImpl(`${url}&audience=${encodeURIComponent(AUDIENCE)}`, { headers: { Authorization: `Bearer ${bearer}` } });
  if (!r.ok) throw new Error(`the OIDC token request answered HTTP ${r.status}`);
  const { value } = await r.json();
  if (typeof value !== "string" || !value) throw new Error("the OIDC token answer carries no token");
  return value;
}

/** The refusal word of an error body: a short lowercase token, or null. Nothing else of the body is kept. */
async function refusalWord(res) {
  try {
    const b = await res.json();
    const t = b?.error ?? b?.code ?? b?.refusal ?? null;
    return typeof t === "string" && /^[a-z_]{1,40}$/.test(t) ? t : null;
  } catch {
    return null;
  }
}

/**
 * Ask for one kind.
 * @returns {Promise<{status: "fetched", bytes: Buffer} | {status: "closed", why: string} | {status: "refused", why: string}>}
 */
export async function fetchExport({ kind, env = process.env, fetchImpl = fetch, token = null }) {
  const base = SERVICE_BASE;
  const bearer = token ? await token() : await oidcToken({ env, fetchImpl });
  let res;
  try {
    res = await fetchImpl(`${base}/${doorOf(kind)}`, {
      method: "GET",
      headers: { Authorization: `Bearer ${bearer}`, Accept: "application/json" },
      redirect: "error",
      signal: AbortSignal.timeout(30_000),
    });
  } catch (e) {
    return { status: "refused", why: "no answer" };
  }
  if (!res.ok) {
    const word = await refusalWord(res);
    if (res.status === 404 || word === "unavailable" || (word === null && res.status === 503)) {
      return { status: "closed", why: `HTTP ${res.status}${word ? ` ${word}` : ""}` };
    }
    return { status: "refused", why: `HTTP ${res.status}${word ? ` ${word}` : ""}` };
  }
  const bytes = Buffer.from(await res.arrayBuffer());
  if (bytes.length > MAX_EXPORT_BYTES) return { status: "refused", why: `an answer of ${bytes.length} bytes` };
  return { status: "fetched", bytes };
}

/**
 * Ask for every kind, in order, each judged by itself: a door that is not
 * open for one kind is still asked for the next. Only a refusal of this
 * signer's token ends the asking, because the same token pins guard all five
 * and each refused token counts against the caller's address.
 * @returns {Promise<{[kind: string]: {status: string, why?: string, bytes?: Buffer}}>}
 */
export async function fetchAll(o = {}) {
  const out = {};
  let stop = null;
  for (const kind of KINDS) {
    if (stop) {
      out[kind] = stop;
      continue;
    }
    out[kind] = await fetchExport({ ...o, kind });
    if (out[kind].status === "refused" && / token_refused$/.test(out[kind].why)) stop = { status: "refused", why: `not asked: ${out[kind].why}` };
  }
  return out;
}
