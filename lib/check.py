#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Minice — https://minice.ai
"""The bridge from the signer (Node) to the content specification's own
checker (vendor/astraplugins/tools/check-content-goldens.py).

Nothing here judges a document. This file loads the vendored checker, hands
it bytes, and reports what it said, so that the signer, the plugins service
and a client are held to one reading of spec/content/. Standard library only.

It reads one JSON request on stdin and writes one JSON answer on stdout:

  {"op": "parse", "file": F}
      F read strictly: UTF-8, no duplicate member name anywhere, and every
      number an integer a 64-bit float holds exactly (common-v1.md §1).
      -> {"ok": bool, "problem": str|null}

  {"op": "document", "file": F, "kind": K, "doc": "index"|"withdrawn",
   "now": N, "trust": T|null}
      F is an envelope. The kind's schema, then every semantic and pairing
      rule over `signed`, then (when T, the `signed` member of trust.json, is
      given) every usable key of kind K that verifies a signature.
      -> {"ok": bool, "parse": str|null, "schema": str|null,
          "rules": [str], "verified_by": [str], "reason": str|null}
"""

from __future__ import annotations

import importlib.util
import json
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
    """The first number that is not an integer both readers hold exactly."""
    if isinstance(v, bool) or v is None or isinstance(v, str):
        return None
    if isinstance(v, float):
        return f"{at}: a number that is not an integer"
    if isinstance(v, int):
        return None if -SAFE <= v <= SAFE else f"{at}: an integer beyond 2^53 - 1"
    if isinstance(v, list):
        for i, x in enumerate(v):
            p = number_problem(x, f"{at}[{i}]")
            if p:
                return p
        return None
    for k, x in v.items():
        p = number_problem(x, f"{at}.{k}" if k.isascii() and k.isprintable() else f"{at}[…]")
        if p:
            return p
    return None


def strict_read(K, file):
    """(value, None) or (None, why)."""
    try:
        value = K.C.strict_loads(pathlib.Path(file).read_bytes())
    except K.C.DuplicateMember:
        return None, "a duplicate member name"
    except UnicodeDecodeError:
        return None, "not UTF-8"
    except (json.JSONDecodeError, RecursionError):
        return None, "not JSON"
    p = number_problem(value)
    return (None, p) if p else (value, None)


def main() -> int:
    req = json.load(sys.stdin)
    K = load_checker()
    if req["op"] == "parse":
        _, why = strict_read(K, req["file"])
        out = {"ok": why is None, "problem": why}
    elif req["op"] == "document":
        kind, doc, now = req["kind"], req["doc"], req["now"]
        if kind not in K.KINDS or doc not in K.KIND_DOCS:
            raise SystemExit(f"not a content document: {kind}/{doc}")
        out = {"ok": False, "parse": None, "schema": None, "rules": [], "verified_by": [], "reason": None}
        env, why = strict_read(K, req["file"])
        if why:
            out["parse"] = why
        else:
            sok, detail = K.schema_ok(env, K.schema(f"{kind}-{doc}-v1.schema.json"))
            if not sok:
                out["schema"] = detail or "refused"
            else:
                out["rules"] = K.failing_rules(env["signed"], kind, doc, now)
                if req.get("trust") is not None:
                    got, reason = K.verified_by(env, kind, doc, req["trust"], now)
                    out["verified_by"], out["reason"] = sorted(got), reason
                out["ok"] = not out["rules"] and (req.get("trust") is None or bool(out["verified_by"]))
    else:
        raise SystemExit(f"unknown op {req['op']!r}")
    json.dump(out, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
