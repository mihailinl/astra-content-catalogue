#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Minice — https://minice.ai
"""The bridge from the signer (Node) to the content specification's own
checker (vendor/astraplugins/tools/check-content-goldens.py).

Nothing here judges a document. This file loads the vendored checker, hands
it bytes, and reports what it said, so that the signer, the plugins service
and a client are held to one reading of spec/content/. Standard library only.

It never runs in the step that holds a signing key (lib/pipeline.mjs).

What it reports is a code and a location, never a value: the checker's own
messages quote the offending value, and a value chosen by the sender must not
reach a public log. A member NAME is chosen by the sender too, so a location
is spelt only in words the kind's schema itself uses (and array positions);
any other segment is reported as `unknown`.

It reads one JSON request on stdin and writes one JSON answer on stdout:

  {"op": "parse", "file": F}
      F read strictly: UTF-8, no duplicate member name anywhere, and every
      number an integer a 64-bit float holds exactly (common-v1.md §1).
      -> {"ok": bool, "problem": code|null}

  {"op": "document", "file": F, "kind": K, "doc": "index"|"withdrawn",
   "now": N, "trust": T|null}
      F is an envelope. The kind's schema, then every semantic and pairing
      rule over `signed`, then (when T, the `signed` member of trust.json, is
      given) every usable key of kind K that verifies a signature.
      -> {"ok": bool, "parse": code|null, "schema": path|null,
          "rules": [str], "verified_by": [str], "reason": str|null}

  {"op": "self"}
      -> {"isolated": bool, "env": [names]}   how this process was started
"""

from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
TOOLS = HERE.parent / "vendor" / "astraplugins" / "tools"
SAFE = 2**53 - 1


def load_checker():
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(TOOLS))
    spec = importlib.util.spec_from_file_location("check_content_goldens", TOOLS / "check-content-goldens.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def number_problem(v, at="$"):
    """(code, path) of the first number that is not an integer both readers hold exactly."""
    if isinstance(v, bool) or v is None or isinstance(v, str):
        return None
    if isinstance(v, float):
        return ("fraction", at)
    if isinstance(v, int):
        return None if -SAFE <= v <= SAFE else ("integer-too-large", at)
    if isinstance(v, list):
        for i, x in enumerate(v):
            p = number_problem(x, f"{at}/{i}")
            if p:
                return p
        return None
    for k, x in v.items():
        p = number_problem(x, f"{at}/{k}")
        if p:
            return p
    return None


def schema_words(schema) -> set:
    """Every property name the schema declares, anywhere in it."""
    out = set()

    def walk(v):
        if isinstance(v, dict):
            for k, x in v.items():
                if k == "properties" and isinstance(x, dict):
                    out.update(x.keys())
                walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)

    walk(schema)
    return out


def known_path(path: str, words: set) -> str:
    return "/".join(seg if (seg in words or seg.isdigit() or seg in ("", "$")) else "unknown" for seg in path.split("/"))


def strict_read(K, file):
    """(value, None, None) or (None, code, path)."""
    try:
        value = K.C.strict_loads(pathlib.Path(file).read_bytes())
    except K.C.DuplicateMember:
        return None, "duplicate-member", None
    except UnicodeDecodeError:
        return None, "not-utf8", None
    except (json.JSONDecodeError, RecursionError):
        return None, "not-json", None
    p = number_problem(value)
    return (None, p[0], p[1]) if p else (value, None, None)


def main() -> int:
    req = json.load(sys.stdin)
    if req["op"] == "self":
        json.dump({"isolated": bool(sys.flags.isolated), "env": sorted(os.environ)}, sys.stdout)
        return 0
    K = load_checker()
    if req["op"] == "parse":
        _, why, _ = strict_read(K, req["file"])
        out = {"ok": why is None, "problem": why}
    elif req["op"] == "document":
        kind, doc, now = req["kind"], req["doc"], req["now"]
        if kind not in K.KINDS or doc not in K.KIND_DOCS:
            raise SystemExit("not a content document")
        out = {"ok": False, "parse": None, "schema": None, "rules": [], "verified_by": [], "reason": None}
        env, why, _ = strict_read(K, req["file"])
        if why:
            out["parse"] = why
        else:
            sch = K.schema(f"{kind}-{doc}-v1.schema.json")
            try:
                K.schemalite.validate(env, sch)
                sok = True
            except K.schemalite.SchemaError as e:
                sok = False
                out["schema"] = known_path(e.path or "$", schema_words(sch))
            if sok:
                out["rules"] = K.failing_rules(env["signed"], kind, doc, now)
                if req.get("trust") is not None:
                    got, reason = K.verified_by(env, kind, doc, req["trust"], now)
                    out["verified_by"], out["reason"] = sorted(got), reason
                out["ok"] = not out["rules"] and (req.get("trust") is None or bool(out["verified_by"]))
    else:
        raise SystemExit("unknown op")
    json.dump(out, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
