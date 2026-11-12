// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// The step that holds the key (lib/pipeline.mjs, stage 2).
//
// Everything this module imports, directly or through another module, is
// Node's own code or this repository's, and none of it starts a process or
// opens a connection: a process started here could read the key from this
// one's environment. test/workflows.test.mjs walks the imports and fails if
// `node:child_process`, a network module or the checker ever appears.

import fs from "node:fs";
import path from "node:path";

import { jcs } from "../vendor/astra-registry/tools/lib/canonical.mjs";
import { assertKind, DOCS, DOCUMENT_LIFE, domainOf, MAX_DOCUMENT_BYTES, Refused } from "./kinds.mjs";
import { kindSigner, sign } from "./signer.mjs";
import { bodyFile, documentBytes, envelopeFile, ORDER_SCHEMA, readJson, RESULT_SCHEMA, writeJson } from "./workdir.mjs";

/**
 * Sign what was prepared. Synchronous Node, no child process, no network.
 *
 * @param {{kind: string, workDir: string, trust: object, secret: string|undefined}} o
 * @returns {object} the result, also written to <workDir>/result.json
 */
export function signPrepared({ kind, workDir, trust, secret }) {
  assertKind(kind);
  const order = readJson(path.join(workDir, "order.json"), "E_PREPARED");
  if (order.schema !== ORDER_SCHEMA || order.kind !== kind || order.outcome !== "prepared" || !Number.isSafeInteger(order.now)) {
    throw new Refused("E_PREPARED", `the work directory holds no prepared order for ${kind}`);
  }
  const kindKeys = trust.kindKeys(kind);
  const signer = kindSigner({ secret, kind, kindKeys, now: order.now, lastKeyId: order.last_key_id });
  let result;
  if (order.unchanged_under !== null && order.unchanged_under === signer.key_id) {
    result = { schema: RESULT_SCHEMA, kind, outcome: "unchanged", key_id: signer.key_id, role: signer.role };
  } else {
    for (const doc of DOCS) {
      let text;
      let body;
      try {
        text = fs.readFileSync(bodyFile(workDir, doc), "utf8");
        body = JSON.parse(text);
      } catch {
        throw new Refused("E_PREPARED", "a prepared body is absent or not JSON", doc);
      }
      // only what the preparing step could honestly have written is signed
      if (jcs(body) !== text || body.schema !== domainOf(kind, doc) || body.serial !== order.now || body.issued_at !== order.now || body.expires_at !== order.now + DOCUMENT_LIFE) {
        throw new Refused("E_PREPARED", `the prepared ${doc} body is not a ${kind} ${doc} for the order's second`, doc);
      }
      const bytes = documentBytes(sign({ domain: domainOf(kind, doc), signed: body, signer }));
      if (bytes.length > MAX_DOCUMENT_BYTES) throw new Refused("E_DOCUMENT_SIZE", `${kind} ${doc} is over ${MAX_DOCUMENT_BYTES} bytes`, doc);
      fs.writeFileSync(envelopeFile(workDir, doc), bytes);
    }
    result = { schema: RESULT_SCHEMA, kind, outcome: "signed", key_id: signer.key_id, role: signer.role };
  }
  writeJson(path.join(workDir, "result.json"), result);
  return result;
}

