// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// The five kinds and every name derived from one. Each name is stated once,
// here; the workflow repeats three of them as literals because a workflow
// cannot import, and test/workflows.test.mjs holds the two together.

/** The document kinds, in the order the workflow signs them. */
export const KINDS = Object.freeze(["commands", "characters", "models", "animsets", "packs"]);
export const DOCS = Object.freeze(["index", "withdrawn"]);

/** The signature domain: the signer's own constant, never a document's `schema` (common-v1.md §1). */
export const domainOf = (kind, doc) => `astra.${kind}.${doc}/1`;

/** The GitHub environment that holds a kind's key, and nothing else. */
export const environmentOf = (kind) => `publish-${kind}`;
/** The one secret of that environment. */
export const secretOf = (kind) => `ASTRA_${kind.toUpperCase()}_SIGNING_KEY`;
/** The environment of the job that calls the service. It holds no secret. */
export const SERVICE_ENVIRONMENT = "content-service";

/** Where a kind's documents and state live on the `data` branch. */
export const DATA_BRANCH = "data";
export const documentPath = (kind, doc) => `registry/v1/${kind}/${doc}.json`;
export const statePath = (kind) => `state/${kind}.json`;

export const DAY = 86400;
/** A document's life: seven days, under the specification's bound of eight (common-v1.md §2). */
export const DOCUMENT_LIFE = 7 * DAY;
/** An unchanged kind is signed again once its last signature is this old. */
export const RESIGN_AFTER = 6 * 3600;
/** A document larger than this is not signed (1 MiB; common-v1.md §2). */
export const MAX_DOCUMENT_BYTES = 1_048_576;
/** An export larger than this is not read: it could not yield two documents of 1 MiB. */
export const MAX_EXPORT_BYTES = 4 * 1_048_576;

export function assertKind(kind) {
  if (!KINDS.includes(kind)) throw new Error(`${JSON.stringify(kind)} is not one of ${KINDS.join(", ")}`);
  return kind;
}

/** An answer older than this, or dated further ahead than EXPORT_MAX_AHEAD, is not signed. */
export const EXPORT_MAX_AGE = 30 * 60;
export const EXPORT_MAX_AHEAD = 5 * 60;
/** A published kind whose door stays shut for longer than this fails the run. */
export const CLOSED_MAX_AGE = 12 * 3600;

/** This repository, as the plugins service pins it (contract BOT-110). owner/secrets.mjs uploads a key nowhere else. */
export const REPOSITORY = "mihailinl/astra-content-catalogue";
export const REPOSITORY_ID = 1454718826;
export const REPOSITORY_OWNER_ID = 193032699;

/**
 * Text that came from outside (a member name, a path, another program's
 * message), made safe to print in a public log: only `A-Z a-z 0-9 _ . / $ -`
 * survive, and at most 200 characters. What is left can spell neither a
 * workflow command nor a sentence, so it can carry no fact about a person.
 */
export function sanitise(text) {
  return String(text ?? "").replace(/[^A-Za-z0-9_./$-]/g, "").slice(0, 200);
}

/**
 * A refusal with a stable code. Nothing is published when one is thrown.
 *
 * `message` is for a developer reading a test failure. A workflow prints
 * `line()` only: the code, and `where` (a path or a rule name) sanitised.
 * Callers put data in `where`, never in the explanation.
 */
export class Refused extends Error {
  constructor(code, explanation, where = "") {
    super(`${code}: ${explanation}`);
    this.code = code;
    this.where = sanitise(where);
  }
  line() {
    return this.where ? `${this.code} at ${this.where}` : this.code;
  }
}
