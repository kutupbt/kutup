#!/usr/bin/env python3
"""Fails when the frontend lockfile resolves a runtime singleton twice.

Some packages must exist once in a page: React and its renderer, and every
library that keeps module state or a React context the whole app shares
(toasts, the query cache, i18n, routing, stores, Yjs). pnpm installs a
second copy of a package when the same version is resolved with different
peers, which a lockfile update can do silently: a Dependabot bump once moved
some workspace packages to another @types/react, so `sonner` was installed
twice, `toast()` and `<Toaster>` landed in different copies, and no toast
showed anywhere (#295). Each name below must have exactly one entry under
the lockfile's `snapshots:` (a version with its peers).

Radix UI is left out on purpose: Excalidraw pins its own Radix versions,
and its components never share a context with ours.

Usage: check-lockfile-singletons.py [frontend/pnpm-lock.yaml]
"""

import re
import sys
from collections import defaultdict

SINGLETONS = (
    "react",
    "react-dom",
    "scheduler",
    "sonner",
    "@tanstack/react-query",
    "i18next",
    "react-i18next",
    "zustand",
    "react-router",
    "react-router-dom",
    "yjs",
)

# A snapshot key: `  name@version(peers…):`, quoted when it needs to be.
SNAPSHOT = re.compile(
    r"^  (?P<q>'?)(?P<name>(?:@[^/@\s]+/)?[^@\s(':]+)@(?P<variant>[^:\s'][^:']*?)(?P=q):\s*$",
    re.M,
)


def variants(lockfile: str) -> dict[str, set[str]]:
    """Every package's resolved variants (version and peers) under `snapshots:`."""
    start = lockfile.find("\nsnapshots:\n")
    if start < 0:
        raise ValueError("no snapshots: section (not a pnpm 9 lockfile?)")
    found: dict[str, set[str]] = defaultdict(set)
    for match in SNAPSHOT.finditer(lockfile[start:]):
        found[match["name"]].add(match["variant"])
    return found


def duplicates(lockfile: str) -> dict[str, list[str]]:
    """The singletons resolved more than once, with their variants."""
    found = variants(lockfile)
    return {name: sorted(found[name]) for name in SINGLETONS if len(found.get(name, ())) > 1}


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else "frontend/pnpm-lock.yaml"
    with open(path, encoding="utf-8") as handle:
        twice = duplicates(handle.read())
    if not twice:
        print(f"{path}: every runtime singleton resolves once")
        return 0
    for name, found in twice.items():
        print(f"{path}: {name} resolves {len(found)} ways:", file=sys.stderr)
        for variant in found:
            print(f"  {name}@{variant}", file=sys.stderr)
    print(
        "Two copies of these break the app at runtime (one copy's state is invisible to the "
        "other). Run `pnpm -C frontend dedupe` and check again.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
