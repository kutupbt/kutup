#!/usr/bin/env python3
"""The API pass's names stay (docs/plans/api-surface.md §8): no client path
outside /api/v1/ (but the unversioned few), no federation path outside
/api/fed/v2/, no user-named wire field, no old client storage name.

Run from the repository root; prints each offending line and exits 1.
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CODE_DIRS = [
    'crates/kutup-server/src',
    'crates/kutup-server/tests',
    'crates/kutup-cli/src',
    'crates/kutup-client-ffi/src',
    'frontend/packages',
    'frontend/apps',
    'tests/e2e/specs',
    'tests/e2e/fixtures',
]
SKIP_DIRS = {'node_modules', 'dist', 'target'}
EXTENSIONS = ('.rs', '.ts', '.tsx', '.js', '.mjs')

# A path in a string literal: /api/ then anything but the versioned and
# unversioned prefixes. The bare prefixes themselves are fine (`"/api/"`,
# `"/api/fed/"` in prefix checks).
# A path rewritten twice (`/api/v1/v…`) is as wrong as an unversioned one.
DOUBLE = re.compile(r"/api/v1/v[0-9\"'`]")
OLD_PATH = re.compile(r"""["'`]/api/(?!v1/|v1["'`]|v["'`]|fed/v2/|fed/["'`]|fed/v["'`]|health|csp-report|["'`])""")
OLD_FED = re.compile(r"""/api/fed/(?!v2/|v\{|v[0-9]|v["'`]|["'`])""")
WIRE = re.compile(
    r"""["'](userId|ownerUserId|uploaderUserId|recipientUserId|sharerUserId|collectionOwnerUserId|authorUserId|targetUserId|adminUserId|totalUsers|activeUsers)["']"""
    r"""|(?:\.|\?\.)(userId|ownerUserId|uploaderUserId|recipientUserId|sharerUserId|collectionOwnerUserId|authorUserId|targetUserId|adminUserId)\b"""
    r"""|\b(ownerUserId|uploaderUserId|recipientUserId|sharerUserId|collectionOwnerUserId|authorUserId|targetUserId|adminUserId|userId)\??:\s"""
)
OLD_STORAGE = re.compile(
    r"""["'`]kutup-(session|theme|lang|chat-v2|mail-search|pass-lock|pass-activity|pass-auto-lock-minutes|pass-unlock-mode"""
    r"""|calendar-prefs|calendar-push|drive-view|photos-info|meeting-hosts|meeting-seat|meeting-show-account|call-name"""
    r"""|md-mode-|fork|reload:|refresh|manifest-pins|account-records|revisions-v2|private-ciphertext-cache-v1"""
    r"""|pending-uploads|account-head:|revision:|upload:|chat-engine|chat-updates|chat-focus|chat-notifier|chat-call-desk|chat-in-call)\b"""
    r"""|kutup:chat:|kutup_cursor_color_v1|kutup\.sealed\.v1|kutup\.chat\.liveShares\.v1|kutup\.notes\.sourceMode|notificationBanner\.dismissed"""
)
# Where the old storage names are named on purpose: the sweep that clears
# them from browsers of before (instance.ts) and its tests.
STORAGE_ALLOWED = {
    'frontend/packages/session/src/instance.ts',
    'frontend/packages/session/src/instance.test.ts',
}
# Paths a test calls to see them refused: a client from before versions,
# and the federation routes long gone.
PATH_ALLOWED_LINES = ('{base}/api/user/me', '"/api/fed-proxy/incoming"')

problems = []
for top in CODE_DIRS:
    for dirpath, dirnames, filenames in os.walk(os.path.join(ROOT, top)):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if not name.endswith(EXTENSIONS):
                continue
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, ROOT)
            with open(path, encoding='utf-8', errors='replace') as handle:
                for number, line in enumerate(handle, 1):
                    stripped = line.strip()
                    if stripped.startswith(('//', '*', '/*', '#')):
                        continue
                    found = []
                    if OLD_PATH.search(line) and not any(a in line for a in PATH_ALLOWED_LINES):
                        found.append('an unversioned API path')
                    if DOUBLE.search(line):
                        found.append('a path versioned twice')
                    if OLD_FED.search(line):
                        found.append('a federation path outside /api/fed/v2')
                    if WIRE.search(line):
                        found.append('a user-named wire field')
                    if rel not in STORAGE_ALLOWED and OLD_STORAGE.search(line):
                        found.append('an old storage name')
                    for what in found:
                        problems.append(f'{rel}:{number}: {what}: {stripped[:140]}')

for problem in problems:
    print(problem)
if problems:
    print(f'check-api-names: {len(problems)} line(s) use names the API pass replaced', file=sys.stderr)
    sys.exit(1)
print('check-api-names: every path, wire field and storage name is the API pass\'s')
