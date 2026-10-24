#!/usr/bin/env python3
"""The crates still allowed to name algorithms directly are exactly the ones
docs/plans/crypto-primitives.md lists as not yet moved ("Lint exceptions").

Each such crate carries a clippy.toml starting with "# W2: moving"; a move
deletes the file and strikes the crate out of the table. When every crate
has moved, no file may carry the marker.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
MARKER = "# W2: moving"
PLAN = ROOT / "docs/plans/crypto-primitives.md"


def marked() -> set[str]:
    found = set()
    for path in ROOT.glob("**/clippy.toml"):
        if "node_modules" in path.parts or "target" in path.parts:
            continue
        if path.read_text(encoding="utf-8").startswith(MARKER):
            found.add(path.parent.relative_to(ROOT).as_posix())
    return found


def listed() -> set[str]:
    text = PLAN.read_text(encoding="utf-8")
    section = text.split("## Lint exceptions", 1)[1].split("\n## ", 1)[0]
    pending = set()
    for line in section.splitlines():
        if not line.startswith("| ") or line.startswith("| Crate") or line.startswith("|---"):
            continue
        crates = line.split("|")[1]
        if "~~" in crates:
            continue
        pending.update(re.findall(r"`([^`]+)`", crates))
    return pending


def main() -> int:
    files, table = marked(), listed()
    ok = True
    for crate in sorted(files - table):
        print(f"{crate}: has a '{MARKER}' clippy.toml but the plan lists it as moved", file=sys.stderr)
        ok = False
    for crate in sorted(table - files):
        print(f"{crate}: the plan lists it as not yet moved but it has no '{MARKER}' clippy.toml", file=sys.stderr)
        ok = False
    if ok:
        print(f"crypto lint exceptions match the plan ({len(files)} crates still moving)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
