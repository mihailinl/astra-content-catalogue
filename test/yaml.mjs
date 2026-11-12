// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// A reader for the YAML the workflows here are written in, so that
// test/workflows.test.mjs can assert on jobs, steps and matrix legs and not on
// text. It reads block maps, block lists, `|` and `>` scalars, quoted and
// plain scalars, `[a, b]` and `{}`. It refuses what it does not read (anchors,
// tags, multi-document files, tabs), so a workflow written beyond it fails
// the test instead of being half understood.

function scalar(text) {
  let t = text.trim();
  if (t.startsWith('"')) {
    const end = t.lastIndexOf('"');
    return JSON.parse(t.slice(0, end + 1));
  }
  if (t.startsWith("'")) return t.slice(1, t.lastIndexOf("'")).replaceAll("''", "'");
  const hash = t.search(/\s#/);
  if (hash >= 0) t = t.slice(0, hash).trim();
  if (t === "{}") return {};
  if (t === "[]") return [];
  if (t.startsWith("[") && t.endsWith("]")) return t.slice(1, -1).split(",").map((s) => scalar(s));
  if (/^[&*!|>{]/.test(t) && !t.startsWith("!cancelled")) throw new Error(`unsupported YAML: ${t}`);
  if (t === "true") return true;
  if (t === "false") return false;
  if (t === "" || t === "null" || t === "~") return null;
  if (/^-?\d+$/.test(t)) return Number(t);
  return t;
}

export function parseYaml(text) {
  if (text.includes("\t")) throw new Error("unsupported YAML: a tab");
  const raw = text.split("\n");
  const lines = raw.map((line, n) => ({ n, indent: line.length - line.trimStart().length, text: line.trim() }));
  const skip = (i) => {
    while (i < lines.length && (lines[i].text === "" || lines[i].text.startsWith("#"))) i++;
    return i;
  };
  const KEY = /^("[^"]*"|'[^']*'|[^\s"'\[{#-][^:#]*|-[^\s:][^:#]*):(?:\s+(.*))?$/;

  function block(i, indent) {
    i = skip(i);
    if (i >= lines.length || lines[i].indent < indent) return [null, i];
    return lines[i].text.startsWith("- ") || lines[i].text === "-" ? list(i, lines[i].indent) : map(i, lines[i].indent);
  }

  function value(rest, i, indent) {
    if (rest === undefined || rest === "" || rest.startsWith("#")) {
      const j = skip(i + 1);
      if (j < lines.length && lines[j].indent > indent) return block(j, lines[j].indent);
      return [null, i + 1];
    }
    if (/^[|>][-+]?$/.test(rest)) {
      const body = [];
      let j = i + 1;
      while (j < lines.length && (lines[j].text === "" || lines[j].indent > indent)) body.push(raw[j++]);
      while (body.length && body[body.length - 1].trim() === "") body.pop();
      const cut = Math.min(...body.filter((l) => l.trim()).map((l) => l.length - l.trimStart().length));
      const parts = body.map((l) => l.slice(cut));
      return [rest.startsWith("|") ? parts.join("\n") : parts.join(" "), j];
    }
    return [scalar(rest), i + 1];
  }

  function map(i, indent) {
    const out = {};
    for (i = skip(i); i < lines.length && lines[i].indent === indent; i = skip(i)) {
      const m = KEY.exec(lines[i].text);
      if (!m) throw new Error(`unsupported YAML at line ${lines[i].n + 1}: ${lines[i].text}`);
      const key = scalar(m[1]);
      if (key in out) throw new Error(`duplicate key ${key} at line ${lines[i].n + 1}`);
      [out[key], i] = value(m[2], i, indent);
    }
    if (i < lines.length && lines[i].indent > indent) throw new Error(`unexpected indent at line ${lines[i].n + 1}`);
    return [out, i];
  }

  function list(i, indent) {
    const out = [];
    for (i = skip(i); i < lines.length && lines[i].indent === indent && (lines[i].text.startsWith("- ") || lines[i].text === "-"); i = skip(i)) {
      const rest = lines[i].text.slice(1).trimStart();
      if (rest === "") {
        let v;
        [v, i] = block(i + 1, indent + 1);
        out.push(v);
      } else if (KEY.test(rest)) {
        // `- key: value`: a map whose first member sits on the dash's line
        const inner = indent + (lines[i].text.length - rest.length);
        lines[i] = { ...lines[i], indent: inner, text: rest };
        let v;
        [v, i] = map(i, inner);
        out.push(v);
      } else {
        out.push(scalar(rest));
        i++;
      }
    }
    return [out, i];
  }

  const [doc, end] = block(0, 0);
  if (skip(end) < lines.length) throw new Error(`unsupported YAML at line ${lines[skip(end)].n + 1}`);
  return doc;
}
