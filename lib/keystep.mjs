// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// The job that holds the key (lib/pipeline.mjs, the second of three).
//
// It reads one directory, the prepared artifact, after admitting it
// (lib/workdir.mjs), and writes one directory on its own runner, from which
// bin/sign.mjs takes the one line of job output that leaves the job. The
// trust.json it believes is the one in the prepared artifact, and only
// because it verifies under the root keys compiled into this repository.
//
// Everything this module imports, directly or through another module, is
// Node's own code or this repository's, and none of it starts a process or
// opens a connection. test/steps.test.mjs walks the imports and fails if a
// module that could do either ever appears.

import fs from "node:fs";
import path from "node:path";

import { jcs } from "../vendor/astra-registry/tools/lib/canonical.mjs";
import { assertKind, DOCS, DOCUMENT_LIFE, domainOf, MAX_DOCUMENT_BYTES, Refused } from "./kinds.mjs";
import { kindSigner, sign } from "./signer.mjs";
import { admitPrepared, assertOrderClock, bodyFile, documentBytes, envelopeFile, RESULT_SCHEMA, writeJson } from "./workdir.mjs";

/**
 * Sign what was prepared. Synchronous Node, no child process, no network.
 *
 * @param {{kind: string, workDir: string, outDir: string, trust: object|null, secret: string|undefined, now: number}} o
 *   `workDir` is an admitted prepared artifact; `trust` is its trust.json,
 *   loaded (null when the order is not `prepared`). `now` is this job's own
 *   clock: the order's second is signed only when it is within the window of
 *   it (lib/workdir.mjs, assertOrderClock), and the key must be valid at it.
 * @returns {object} the result, also written to <outDir>/result.json
 * @throws {Refused} after writing a result that says `refused`, and no signed document
 */
export function signPrepared({ kind, workDir, outDir, trust, secret, now }) {
  assertKind(kind);
  fs.mkdirSync(outDir, { recursive: true });
  const finish = (result) => {
    writeJson(path.join(outDir, "result.json"), { schema: RESULT_SCHEMA, kind, ...result });
    return { schema: RESULT_SCHEMA, kind, ...result };
  };
  try {
    const order = admitPrepared(workDir, kind);
    if (order.outcome === "closed") return finish({ outcome: "closed" });
    if (order.outcome === "refused") return finish({ outcome: "not-prepared" });
    assertOrderClock(order, now);
    const kindKeys = trust.kindKeys(kind);
    // the key must be valid at the second it signs (issued_at, TRUST-50) and at this job's own clock
    const signer = kindSigner({ secret, kind, kindKeys, now: Math.min(now, order.now), lastKeyId: order.last_key_id });
    if (order.unchanged_under !== null && order.unchanged_under === signer.key_id) {
      return finish({ outcome: "unchanged", key_id: signer.key_id, role: signer.role });
    }
    const signed = {};
    for (const doc of DOCS) {
      let text;
      let body;
      try {
        text = fs.readFileSync(bodyFile(workDir, doc), "utf8");
        body = JSON.parse(text);
      } catch {
        throw new Refused("E_PREPARED", "a prepared body is absent or not JSON", doc);
      }
      // only what the preparing job could honestly have written is signed
      if (jcs(body) !== text || body.schema !== domainOf(kind, doc) || body.serial !== order.now || body.issued_at !== order.now || body.expires_at !== order.now + DOCUMENT_LIFE) {
        throw new Refused("E_PREPARED", `the prepared ${doc} body is not a ${kind} ${doc} for the order's second`, doc);
      }
      signed[doc] = documentBytes(sign({ domain: domainOf(kind, doc), signed: body, signer }));
      if (signed[doc].length > MAX_DOCUMENT_BYTES) throw new Refused("E_DOCUMENT_SIZE", `${kind} ${doc} is over ${MAX_DOCUMENT_BYTES} bytes`, doc);
    }
    // both or neither
    for (const doc of DOCS) fs.writeFileSync(envelopeFile(outDir, doc), signed[doc]);
    return finish({ outcome: "signed", key_id: signer.key_id, role: signer.role });
  } catch (e) {
    if (e instanceof Refused) finish({ outcome: "refused", code: e.code });
    throw e;
  }
}
