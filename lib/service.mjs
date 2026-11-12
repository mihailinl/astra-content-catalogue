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
// "Not open" is an answer, not a failure. Before the service opens the door
// it answers 404, and while it is restarting or shut it answers `unavailable`
// (or a bare 503). A run that meets either ends without signing and without
// failing: the kinds keep their last signed documents, and the next run asks
// again. Every other refusal is a failed run.

import { assertKind, KINDS, MAX_EXPORT_BYTES } from "./kinds.mjs";

export const DEFAULT_BASE = "https://api.minice.ai/plugins/v1";
/** The audience the service pins. An opaque string: it does not follow the base. */
export const AUDIENCE = "https://api.minice.ai/plugins/v1/content";
export const doorOf = (kind) => `bot/content/${assertKind(kind)}/accepted`;

/** The service base: https only, no credentials, no query, no trailing slash. */
export function serviceBase(env = process.env) {
  const base = String(env.CONTENT_SERVICE_URL || DEFAULT_BASE).replace(/\/+$/, "");
  let u;
  try {
    u = new URL(base);
  } catch {
    throw new Error("CONTENT_SERVICE_URL is not a URL");
  }
  if (u.protocol !== "https:" || u.username || u.password || u.search || u.hash) throw new Error("CONTENT_SERVICE_URL is not a plain https base");
  return base;
}

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
  const base = serviceBase(env);
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
    return { status: "refused", why: `no answer (${e?.name ?? "error"})` };
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
 * Ask for every kind, in order. One door serves all five under one set of
 * pins, so an answer that is about the door and not about the kind ends the
 * asking: a door that is not open, or one that refuses this signer's token,
 * is not asked four more times.
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
    if (out[kind].status === "closed") stop = out[kind];
    else if (out[kind].status === "refused" && / token_refused$/.test(out[kind].why)) stop = { status: "refused", why: `not asked: ${out[kind].why}` };
  }
  return out;
}
