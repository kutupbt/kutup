#!/usr/bin/env python3
"""Byte columns are compared on their bytes (docs/plans/w7-schema.md §2).

Bytes are stored as bytea and converted at the SQL boundary: a query reads
`encode(col, 'hex')` / `kutup_b64(col)` and writes `decode($n, 'hex')` /
`kutup_unb64($n)`. A comparison must convert the parameter, never the column
(`col = decode($1, 'hex')`): `encode(col, 'hex') = $1` makes every lookup a
sequential scan. This check refuses a comparison with an encoded column in
the server's SQL (its Rust string literals), and encode(..., 'base64'), whose
output Postgres breaks into lines.

  scripts/check-sql-boundary.py
"""
import os
import re
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "crates", "kutup-server")

# encode(...) / kutup_b64(...) with balanced parentheses one level deep.
ENCODED = r"(?:encode|kutup_b64)\((?:[^()]|\([^()]*\))*\)"
COMPARED = re.compile(
    r"(?:" + ENCODED + r"\s*(?:=|<>|!=|\bIN\b|\bLIKE\b|=\s*ANY))"
    r"|(?:(?:=|<>|!=)\s*" + ENCODED + r")",
    re.IGNORECASE,
)
# Postgres breaks encode(..., 'base64') into 76-character lines: bytes go out
# through kutup_b64 instead.
RAW_BASE64 = re.compile(r"encode\((?:[^()]|\([^()]*\))*,\s*'base64'\s*\)", re.IGNORECASE)


def literals(src):
    """The contents of every Rust string literal (plain and raw)."""
    i, n = 0, len(src)
    while i < n:
        if src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j
            continue
        m = re.match(r'r(#*)"', src[i:]) if src[i] == "r" and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_")) else None
        if m:
            start = i + m.end()
            end = src.find('"' + m.group(1), start)
            yield start, end
            i = end + 1 + len(m.group(1))
            continue
        if src[i] == '"':
            j = i + 1
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            yield i + 1, j
            i = j + 1
            continue
        if src[i] == "'":
            m = re.match(r"'(\\.|[^\\'])'", src[i:])
            if m:
                i += m.end()
                continue
        i += 1


def allowed():
    """The reviewed exceptions (check-sql-boundary.allow)."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "check-sql-boundary.allow")
    entries = set()
    for line in open(path):
        line = line.strip()
        if line and not line.startswith("#"):
            entries.add(tuple(line.split("|", 1)))
    return entries


def main():
    allow = allowed()
    found = []
    for root, _, files in os.walk(ROOT):
        if "target" in root:
            continue
        for name in files:
            if not name.endswith(".rs"):
                continue
            path = os.path.join(root, name)
            src = open(path).read()
            for start, end in literals(src):
                for m in RAW_BASE64.finditer(src[start:end]):
                    line = src[: start + m.start()].count("\n") + 1
                    found.append(f"{os.path.relpath(path)}:{line}: {m.group(0)[:80]} (use kutup_b64)")
                for m in COMPARED.finditer(src[start:end]):
                    if (os.path.relpath(path, ROOT), m.group(0)) in allow:
                        continue
                    line = src[: start + m.start()].count("\n") + 1
                    found.append(f"{os.path.relpath(path)}:{line}: {m.group(0)[:80]}")
    if found:
        print("check-sql-boundary: compare the bytes, convert the parameter (col = decode($1, 'hex')):")
        for f in found:
            print("  " + f)
        sys.exit(1)
    print("check-sql-boundary: no comparison with an encoded column")


if __name__ == "__main__":
    main()
