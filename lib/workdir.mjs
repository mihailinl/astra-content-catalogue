// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// The work directory of one signing leg: the files its steps hand to one
// another (lib/pipeline.mjs describes the steps). This module only names
// and reads them; it is imported by the step that holds the key, so it
// imports nothing that starts a process.

import fs from "node:fs";
import path from "node:path";

import { jcs } from "../vendor/astra-registry/tools/lib/canonical.mjs";
import { Refused } from "./kinds.mjs";

export const ORDER_SCHEMA = "astra.content.signer-order/1";
export const RESULT_SCHEMA = "astra.content.signer-result/1";

/** The bytes of a document as published: RFC 8785 canonical JSON of the whole envelope. */
export const documentBytes = (envelope) => Buffer.from(jcs(envelope), "utf8");

/** A signature of the right length and no meaning, for measuring and checking a document before it is signed. */
export const UNSIGNED = "A".repeat(86) + "==";

export const bodyFile = (workDir, doc) => path.join(workDir, `${doc}.signed.json`);
export const envelopeFile = (workDir, doc) => path.join(workDir, `${doc}.json`);
export const readJson = (file, code) => {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    throw new Refused(code, "a file of the work directory is absent or not JSON", path.basename(file));
  }
};
export const writeJson = (file, value) => fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);

