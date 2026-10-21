#!/usr/bin/env python3
"""Tests for check-lockfile-singletons.py."""

import importlib.util
import pathlib
import unittest

HERE = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("singletons", HERE / "check-lockfile-singletons.py")
singletons = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(singletons)

LOCK = """lockfileVersion: '9.0'

packages:

  sonner@2.0.8:
    resolution: {integrity: sha512-x}

snapshots:

  '@tanstack/react-query@5.0.0(react@18.3.1)':
    dependencies:
      react: 18.3.1

  react@18.3.1: {}

  sonner@2.0.8(@types/react@18.3.28)(react-dom@18.3.1(react@18.3.1))(react@18.3.1):
    dependencies:
      react: 18.3.1
{extra}
"""


class Singletons(unittest.TestCase):
    def test_one_copy_each_passes(self):
        self.assertEqual(singletons.duplicates(LOCK.replace("{extra}", "")), {})

    def test_the_same_version_with_other_peers_is_a_second_copy(self):
        extra = "\n  sonner@2.0.8(@types/react@18.3.31)(react-dom@18.3.1(react@18.3.1))(react@18.3.1):\n    dependencies:\n      react: 18.3.1\n"
        twice = singletons.duplicates(LOCK.replace("{extra}", extra))
        self.assertEqual(list(twice), ["sonner"])
        self.assertEqual(len(twice["sonner"]), 2)

    def test_a_quoted_scoped_name_is_read(self):
        extra = "\n  '@tanstack/react-query@5.1.0(react@18.3.1)':\n    dependencies:\n      react: 18.3.1\n"
        self.assertEqual(list(singletons.duplicates(LOCK.replace("{extra}", extra))), ["@tanstack/react-query"])

    def test_other_packages_may_resolve_twice(self):
        extra = "\n  '@radix-ui/react-context@1.0.0(react@18.3.1)': {}\n\n  '@radix-ui/react-context@1.1.1(react@18.3.1)': {}\n"
        self.assertEqual(singletons.duplicates(LOCK.replace("{extra}", extra)), {})

    def test_a_lockfile_without_snapshots_is_refused(self):
        with self.assertRaises(ValueError):
            singletons.duplicates("lockfileVersion: '9.0'\n")


if __name__ == "__main__":
    unittest.main()
