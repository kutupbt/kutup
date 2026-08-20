#!/usr/bin/env python3
"""Regression tests for the dependency-free Markdown checker."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-docs.py")
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("check_docs", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
check_docs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check_docs)


class CheckDocsTests(unittest.TestCase):
    def test_normalize_target(self) -> None:
        self.assertIsNone(check_docs.normalize_target("https://example.com/docs"))
        self.assertIsNone(check_docs.normalize_target("tel:+15551234567"))
        self.assertIsNone(check_docs.normalize_target("#section"))
        self.assertEqual(
            check_docs.normalize_target("<docs/My%20Guide.md#setup>"),
            "docs/My Guide.md",
        )

    def test_fenced_examples_are_masked_without_moving_lines(self) -> None:
        text = "before\n```html\n<img src=\"/runtime/only\">\n```\nafter\n"
        masked = check_docs.mask_fenced_code(text)
        self.assertEqual(masked.count("\n"), text.count("\n"))
        self.assertNotIn("runtime/only", masked)
        self.assertIn("before", masked)
        self.assertIn("after", masked)

    def test_validate_accepts_real_links_and_ignores_fenced_routes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            (root / "docs").mkdir()
            (root / "scripts").mkdir()
            (root / "docs" / "guide.md").write_text("# Guide\n", encoding="utf-8")
            (root / "scripts" / "check.sh").write_text("#!/bin/sh\n", encoding="utf-8")
            (root / "README.md").write_text(
                "[Guide](docs/guide.md)\n"
                "`scripts/check.sh`\n"
                "```html\n<img src=\"/onlyoffice/runtime\">\n```\n",
                encoding="utf-8",
            )
            self.assertEqual(check_docs.validate(root), [])

    def test_validate_rejects_missing_local_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            (root / "README.md").write_text(
                "[Missing](docs/missing.md)\n",
                encoding="utf-8",
            )
            errors = check_docs.validate(root)
            self.assertEqual(len(errors), 1)
            self.assertIn("missing local link target", errors[0])


if __name__ == "__main__":
    unittest.main()
