#!/usr/bin/env python3
"""Validate repository-local links and path references in Markdown files."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote


INLINE_LINK = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
REFERENCE_LINK = re.compile(r"^\s*\[[^\]]+\]:\s*(\S+)", re.MULTILINE)
HTML_LINK = re.compile(r"\b(?:href|src)=[\"']([^\"']+)[\"']", re.IGNORECASE)
FENCED_CODE = re.compile(r"(?ms)^(?:`{3,}|~{3,}).*?^(?:`{3,}|~{3,})[ \t]*$")
REPOSITORY_PATHS = (
    re.compile(r"(?<![\w.-])(scripts/[A-Za-z0-9_.\-/]+)"),
    re.compile(r"(?<![\w.-])(tests/e2e/specs/[A-Za-z0-9_.\-/]+)"),
    re.compile(r"(?<![\w.-])(\.github/workflows/[A-Za-z0-9_.\-/]+)"),
)
EXTERNAL_PREFIXES = ("http://", "https://", "mailto:", "data:")
URI_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")


def markdown_files(root: Path) -> list[Path]:
    output = subprocess.check_output(
        [
            "git",
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
            "*.md",
            "*.mdx",
        ],
        cwd=root,
        text=True,
    )
    return [root / name for name in sorted(set(output.splitlines())) if name]


def normalize_target(raw: str) -> str | None:
    target = raw.strip()
    if target.startswith("<") and ">" in target:
        target = target[1 : target.index(">")]
    else:
        target = target.split(maxsplit=1)[0]
    target = unquote(target)
    if (
        not target
        or target.startswith("#")
        or target.startswith(EXTERNAL_PREFIXES)
        or URI_SCHEME.match(target)
    ):
        return None
    return target.split("#", 1)[0]


def resolve_target(root: Path, source: Path, target: str) -> Path:
    if target.startswith("/"):
        return (root / target.lstrip("/")).resolve()
    return (source.parent / target).resolve()


def line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def mask_fenced_code(text: str) -> str:
    """Hide fenced examples while retaining offsets and line numbering."""

    return FENCED_CODE.sub(
        lambda match: re.sub(r"[^\n]", " ", match.group(0)),
        text,
    )


def validate(root: Path) -> list[str]:
    errors: list[str] = []
    files = markdown_files(root)

    for source in files:
        text = source.read_text(encoding="utf-8")
        prose = mask_fenced_code(text)
        relative_source = source.relative_to(root)

        for pattern in (INLINE_LINK, REFERENCE_LINK, HTML_LINK):
            for match in pattern.finditer(prose):
                target = normalize_target(match.group(1))
                if target is None:
                    continue
                resolved = resolve_target(root, source, target)
                if root not in resolved.parents and resolved != root:
                    errors.append(
                        f"{relative_source}:{line_number(text, match.start())}: "
                        f"local link escapes repository: {target}"
                    )
                elif not resolved.exists():
                    errors.append(
                        f"{relative_source}:{line_number(text, match.start())}: "
                        f"missing local link target: {target}"
                    )

        for pattern in REPOSITORY_PATHS:
            for match in pattern.finditer(text):
                target = match.group(1).rstrip(".,;:)`")
                if "*" in target or "…" in target:
                    continue
                if not (root / target).exists():
                    errors.append(
                        f"{relative_source}:{line_number(text, match.start())}: "
                        f"missing referenced repository path: {target}"
                    )

    print(f"checked {len(files)} Markdown files")
    return errors


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    errors = validate(root)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("documentation links and referenced paths are valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
