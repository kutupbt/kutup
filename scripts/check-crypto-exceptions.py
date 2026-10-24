#!/usr/bin/env python3
"""The crypto lint can be switched off only where docs/plans/crypto-primitives.md
says so ("Lint exceptions").

- A crate not yet moved carries a clippy.toml starting with "# W2: moving"
  that keeps only the root's non-crypto rules; the plan's "Crate" table lists
  exactly those crates. A move deletes the file and strikes the row out.
- Every other clippy.toml carries the root's rules unchanged, so none can
  drop the crypto rules without the marker.
- `clippy::disallowed_types` / `clippy::disallowed_methods` appear only in the
  Rust files the plan's "File" table lists.
- Nothing switches the rules off another way: no allow/expect of
  `clippy::style`, `clippy::all` or `warnings` in Rust code, no allowing
  `[lints]` table in a Cargo.toml, no rustflags or scripts passing
  `-A`/`--cap-lints` for them, and no `CLIPPY_CONF_DIR`.
"""
import pathlib
import re
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
MARKER = "# W2: moving"
PLAN = ROOT / "docs/plans/crypto-primitives.md"
LINTS = re.compile(r"clippy\s*::\s*disallowed[-_](?:types|methods)\b")
# Lints or groups whose allowing also switches the disallowed_* rules off.
GROUPS = {"clippy::style", "clippy::all", "warnings"}
TOML_GROUPS = {"disallowed_types", "disallowed_methods", "style", "all"}
# Cargo takes a lint name in a [lints] table with dashes as well.
ATTRIBUTE = re.compile(r"#!?\[\s*(?:allow|expect)\s*\(([^\]]*)\)\s*\]|cfg_attr\([^\]]*?\b(?:allow|expect)\s*\(([^)]*)\)")
FLAG = re.compile(
    r"(?:-A|--allow|--cap-lints|-W|--warn)[\s=]*(?:clippy\s*::\s*(?:disallowed[-_]\w+|style|all)|warnings|allow)\b"
)
SKIP = {"node_modules", "target", ".git"}


def walk(pattern: str):
    for path in ROOT.glob(pattern):
        if SKIP.isdisjoint(path.relative_to(ROOT).parts):
            yield path


def rules(path: pathlib.Path) -> set[str]:
    config = tomllib.loads(path.read_text(encoding="utf-8"))
    found = set()
    for key in ("disallowed-methods", "disallowed-types"):
        for rule in config.get(key, []):
            found.add(f"{key} {rule['path'] if isinstance(rule, dict) else rule}")
    return found


def table(header: str) -> list[str]:
    """The first cell of each row of the section's table that starts with `header`."""
    text = PLAN.read_text(encoding="utf-8")
    section = text.split("## Lint exceptions", 1)[1].split("\n## ", 1)[0]
    cells, inside = [], False
    for line in section.splitlines():
        if line.startswith(f"| {header}"):
            inside = True
            continue
        if not inside:
            continue
        if not line.startswith("|"):
            break
        if not line.startswith("|---"):
            cells.append(line.split("|")[1])
    return cells


def pending_crates() -> set[str]:
    pending = set()
    for cell in table("Crate"):
        if "~~" not in cell:
            pending.update(re.findall(r"`([^`]+)`", cell))
    return pending


def allowed_files() -> set[str]:
    return {f for cell in table("File") for f in re.findall(r"`([^`]+)`", cell)}


def allowed_level(value) -> bool:
    level = value.get("level") if isinstance(value, dict) else value
    return level in ("allow", "expect")


def rustflags(config) -> list[str]:
    """Every `rustflags` value in a .cargo/config, each as one string."""
    found = []
    if isinstance(config, dict):
        for key, value in config.items():
            if key in ("rustflags", "rustdocflags"):
                found.append(" ".join(value) if isinstance(value, list) else str(value))
            else:
                found.extend(rustflags(value))
    return found


def other_switches() -> list[str]:
    errors = []
    for path in walk("**/*.rs"):
        rel = path.relative_to(ROOT).as_posix()
        for match in ATTRIBUTE.finditer(path.read_text(encoding="utf-8", errors="replace")):
            names = {re.sub(r"\s+", "", n) for n in (match.group(1) or match.group(2) or "").split(",")}
            for name in sorted(names & GROUPS):
                errors.append(f"{rel}: allows `{name}`, which switches the crypto lint off too")
    for path in walk("**/Cargo.toml"):
        rel = path.relative_to(ROOT).as_posix()
        config = tomllib.loads(path.read_text(encoding="utf-8"))
        for table in (config.get("lints", {}), config.get("workspace", {}).get("lints", {})):
            for name, value in table.get("clippy", {}).items():
                if name.replace("-", "_") in TOML_GROUPS and allowed_level(value):
                    errors.append(f"{rel}: [lints] allows clippy::{name}")
            if allowed_level(table.get("rust", {}).get("warnings", "warn")):
                errors.append(f"{rel}: [lints] allows warnings")
    for path in [*walk("**/.cargo/config"), *walk("**/.cargo/config.toml")]:
        rel = path.relative_to(ROOT).as_posix()
        text = path.read_text(encoding="utf-8")
        config = tomllib.loads(text)
        if "CLIPPY_CONF_DIR" in config.get("env", {}):
            errors.append(f"{rel}: sets CLIPPY_CONF_DIR")
        if any(FLAG.search(flags) for flags in rustflags(config)):
            errors.append(f"{rel}: rustflags switch the crypto lint off")
    for pattern in ("scripts/**/*", ".github/**/*.yml", "**/Dockerfile*", "Makefile", "justfile"):
        for path in walk(pattern):
            if not path.is_file() or path.name == "check-crypto-exceptions.py":
                continue
            rel = path.relative_to(ROOT).as_posix()
            text = path.read_text(encoding="utf-8", errors="replace")
            if "CLIPPY_CONF_DIR" in text:
                errors.append(f"{rel}: sets CLIPPY_CONF_DIR")
            if FLAG.search(text):
                errors.append(f"{rel}: passes a flag that switches the crypto lint off")
    return errors


def main() -> int:
    errors = []
    root_rules = rules(ROOT / "clippy.toml")
    other_rules = {r for r in root_rules if " reqwest::" in r}
    if not other_rules or other_rules == root_rules:
        errors.append("clippy.toml: cannot tell the crypto rules from the others")

    marked = set()
    for path in [*walk("**/clippy.toml"), *walk("**/.clippy.toml")]:
        rel = path.relative_to(ROOT)
        if rel.parent == pathlib.Path(".") and path.name == "clippy.toml":
            continue
        crate = rel.parent.as_posix()
        if path.read_text(encoding="utf-8").startswith(MARKER):
            marked.add(crate)
            if rules(path) != other_rules:
                errors.append(f"{rel}: a '{MARKER}' file keeps exactly the root's non-crypto rules")
        elif rules(path) != root_rules:
            errors.append(f"{rel}: carries other rules than the root clippy.toml (crypto rules dropped?)")

    pending = pending_crates()
    for crate in sorted(marked - pending):
        errors.append(f"{crate}: has a '{MARKER}' clippy.toml but the plan lists it as moved")
    for crate in sorted(pending - marked):
        errors.append(f"{crate}: the plan lists it as not yet moved but it has no '{MARKER}' clippy.toml")

    allowed = allowed_files()
    used = set()
    for path in walk("**/*.rs"):
        rel = path.relative_to(ROOT).as_posix()
        if LINTS.search(path.read_text(encoding="utf-8", errors="replace")):
            used.add(rel)
            if rel not in allowed:
                errors.append(f"{rel}: allows a crypto lint but the plan doesn't list the file")
    for rel in sorted(allowed - used):
        errors.append(f"{rel}: the plan lists it but it allows no crypto lint (strike the row)")

    errors.extend(other_switches())

    for error in errors:
        print(error, file=sys.stderr)
    if errors:
        return 1
    print(f"crypto lint exceptions match the plan ({len(marked)} crates moving, {len(used)} files allowed)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
