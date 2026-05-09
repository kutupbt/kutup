#!/usr/bin/env bash
#
# Optional installer for the OnlyOffice client JS + x2t WASM converter.
# kutup itself is AGPL-3.0-only; OnlyOffice client JS is AGPL-3.0-or-later.
# Running this script downloads AGPL-licensed assets into
# frontend/public/onlyoffice/ (gitignored).
#
# Bundle sources: cryptpad's pinned forks of OnlyOffice and x2t-wasm.
# We mirror a CryptPad approach but pin v9 only — older versions are
# omitted to save ~80% of disk; we'll backfill if a real legacy doc breaks.
#
# Usage:  ./install-onlyoffice.sh
#         ./install-onlyoffice.sh --check   # verify versions, exit nonzero on drift
#         ./install-onlyoffice.sh --yes     # skip the AGPL prompt (CI)
#
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
DEST="$SCRIPT_DIR/frontend/public/onlyoffice/dist"

# Pinned versions. Bumping these means re-testing the OnlyOffice integration;
# private API signatures (asc_nativeGetFile, asc_setRestriction, …) can drift.
OO_VERSION="v9.2.0.119+5"
OO_SHA512="1f1184fb04cf72a7eb2a49a9740074b5419486c79e1fd713e1f8c09b8594a826050ae941fed6ac6a96807ba73cc751d7c807bd7e6b73de9e4f8e74cd5ed04cfa"
X2T_VERSION="v7.3+1"
X2T_SHA512="ab0c05b0e4c81071acea83f0c6a8e75f5870c360ec4abc4af09105dd9b52264af9711ec0b7020e87095193ac9b6e20305e446f2321a541f743626a598e5318c1"

# CryptPad source tree commit that hosts the three "empty document" templates
# (oodoc_base.js / oocell_base.js / ooslide_base.js). These template JS files
# are NOT in the cryptpad/onlyoffice-editor release tarball — they live in
# cryptpad/cryptpad. Pinning by commit so reinstalls are reproducible.
CRYPTPAD_TEMPLATES_COMMIT="2025.6.0"  # latest stable tag at time of writing

CHECK=0
ASSUME_YES=0
for arg in "$@"; do
    case "$arg" in
        --check) CHECK=1 ;;
        --yes|-y) ASSUME_YES=1 ;;
        *) echo "Unknown arg: $arg" >&2; exit 2 ;;
    esac
done

ensure_command() {
    if ! command -v "$1" &>/dev/null; then
        echo "Error: '$1' not found in PATH. Install it and re-run." >&2
        exit 1
    fi
}

ensure_command curl
ensure_command sha512sum
ensure_command unzip

agree_to_agpl() {
    if [ "$ASSUME_YES" = 1 ] || [ "$CHECK" = 1 ]; then return 0; fi
    cat <<'EOF'

This installer downloads AGPL-3.0-or-later licensed assets into
  frontend/public/onlyoffice/
which is gitignored — the AGPL JS does not enter your kutup repo. By
proceeding, you agree to distribute these assets under AGPL terms when you
deploy this kutup instance with the OnlyOffice integration enabled.

Source:
  - OnlyOffice editor (cryptpad-pinned fork)
  - x2t WASM converter

EOF
    read -rp "Continue? [y/N] " ans
    if [[ ! "$ans" =~ ^[yY]$ ]]; then
        echo "Aborted."
        exit 1
    fi
}

install_oo() {
    local FULL_DIR="$DEST/v9"
    local actual="not installed"
    if [ -e "$FULL_DIR/.version" ]; then
        actual=$(cat "$FULL_DIR/.version")
    fi

    if [ "$actual" = "$OO_VERSION" ]; then
        echo "OnlyOffice $OO_VERSION already installed."
        return 0
    fi

    if [ "$CHECK" = 1 ]; then
        echo "OnlyOffice version drift. Expected: $OO_VERSION. Found: $actual" >&2
        return 1
    fi

    echo "Installing OnlyOffice $OO_VERSION → $FULL_DIR"
    rm -rf "$FULL_DIR"
    mkdir -p "$FULL_DIR"
    cd "$FULL_DIR"
    curl -fL "https://github.com/cryptpad/onlyoffice-editor/releases/download/$OO_VERSION/onlyoffice-editor.zip" \
        --output onlyoffice-editor.zip
    echo "$OO_SHA512  onlyoffice-editor.zip" > onlyoffice-editor.zip.sha512
    if ! sha512sum -c onlyoffice-editor.zip.sha512; then
        echo "Checksum mismatch; aborting." >&2
        rm -rf "$FULL_DIR"
        exit 1
    fi
    unzip -q onlyoffice-editor.zip
    rm onlyoffice-editor.zip onlyoffice-editor.zip.sha512
    echo "$OO_VERSION" > "$FULL_DIR/.version"
    # OnlyOffice's editor index.html files unconditionally register a
    # service worker at ../../../../document_editor_service_worker.js
    # (resolves to /onlyoffice/dist/v9/document_editor_service_worker.js).
    # The CryptPad build doesn't ship that file → 404 every editor open.
    # Drop a no-op stub so registration succeeds silently. Empty install
    # listener is enough; OO's caching needs aren't required for kutup.
    cat > "$FULL_DIR/document_editor_service_worker.js" <<'SW_EOF'
// kutup: no-op stub. OnlyOffice's editor index.html unconditionally
// registers this path; without a real file the browser logs a 404 on
// every editor open. We don't need the upstream caching behaviour.
self.addEventListener('install', () => self.skipWaiting())
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()))
SW_EOF
    cd "$SCRIPT_DIR"
}

install_x2t() {
    local FULL_DIR="$DEST/x2t"
    local actual="not installed"
    if [ -e "$FULL_DIR/.version" ]; then
        actual=$(cat "$FULL_DIR/.version")
    fi

    if [ "$actual" = "$X2T_VERSION" ]; then
        echo "x2t $X2T_VERSION already installed."
        return 0
    fi

    if [ "$CHECK" = 1 ]; then
        echo "x2t version drift. Expected: $X2T_VERSION. Found: $actual" >&2
        return 1
    fi

    echo "Installing x2t $X2T_VERSION → $FULL_DIR"
    rm -rf "$FULL_DIR"
    mkdir -p "$FULL_DIR"
    cd "$FULL_DIR"
    curl -fL "https://github.com/cryptpad/onlyoffice-x2t-wasm/releases/download/$X2T_VERSION/x2t.zip" \
        --output x2t.zip
    echo "$X2T_SHA512  x2t.zip" > x2t.zip.sha512
    if ! sha512sum -c x2t.zip.sha512; then
        echo "Checksum mismatch; aborting." >&2
        rm -rf "$FULL_DIR"
        exit 1
    fi
    unzip -q x2t.zip
    rm x2t.zip x2t.zip.sha512
    echo "$X2T_VERSION" > "$FULL_DIR/.version"
    cd "$SCRIPT_DIR"
}

install_templates() {
    local TMPL_DIR="$DEST/../templates"
    local actual="not installed"
    if [ -e "$TMPL_DIR/.version" ]; then
        actual=$(cat "$TMPL_DIR/.version")
    fi

    if [ "$actual" = "$CRYPTPAD_TEMPLATES_COMMIT" ]; then
        echo "OnlyOffice empty-doc templates @ $CRYPTPAD_TEMPLATES_COMMIT already installed."
        return 0
    fi

    if [ "$CHECK" = 1 ]; then
        echo "Templates version drift. Expected: $CRYPTPAD_TEMPLATES_COMMIT. Found: $actual" >&2
        return 1
    fi

    echo "Installing OnlyOffice empty-doc templates @ $CRYPTPAD_TEMPLATES_COMMIT → $TMPL_DIR"
    rm -rf "$TMPL_DIR"
    mkdir -p "$TMPL_DIR"
    local BASE="https://raw.githubusercontent.com/cryptpad/cryptpad/$CRYPTPAD_TEMPLATES_COMMIT/www/common/onlyoffice"
    for tmpl in oodoc_base.js oocell_base.js ooslide_base.js; do
        curl -fL "$BASE/$tmpl" --output "$TMPL_DIR/$tmpl"
    done
    echo "$CRYPTPAD_TEMPLATES_COMMIT" > "$TMPL_DIR/.version"
}

mkdir -p "$DEST"

agree_to_agpl
install_oo
install_x2t
install_templates

echo
echo "Done. OnlyOffice client JS + x2t are installed at:"
echo "  $DEST"
echo
echo "Rebuild the frontend (pnpm build / docker compose build frontend) to"
echo "pick up the new public/ assets."
