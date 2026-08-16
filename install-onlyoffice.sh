#!/usr/bin/env bash
#
# Development installer for the OnlyOffice client JS + x2t WASM converter.
# Normal Docker builds consume the verified kutup-office-assets OCI image.
# This fallback downloads the same pinned third-party assets and applicable
# license texts into frontend/public/onlyoffice/ (gitignored).
#
# Bundle sources: cryptpad's pinned forks of OnlyOffice and x2t-wasm.
# We mirror a CryptPad approach but pin v9 only — older versions are
# omitted to save ~80% of disk; we'll backfill if a real legacy doc breaks.
#
# Usage:  ./install-onlyoffice.sh
#         ./install-onlyoffice.sh --check   # verify versions, exit nonzero on drift
#         ./install-onlyoffice.sh --yes     # skip the AGPL prompt (CI)
# Set KUTUP_ONLYOFFICE_ROOT to install into a non-default staging directory.
#
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
ASSET_ROOT=${KUTUP_ONLYOFFICE_ROOT:-"$SCRIPT_DIR/frontend/public/onlyoffice"}
DEST="$ASSET_ROOT/dist"
LICENSE_DEST="$ASSET_ROOT/LICENSES"

# Pinned versions. Bumping these means re-testing the OnlyOffice integration;
# private API signatures (asc_nativeGetFile, asc_setRestriction, …) can drift.
OO_VERSION="v9.2.0.119+5"
OO_SOURCE_COMMIT="4fcd833d00b3ba9852165874533925c7db2c4c56"
OO_SHA512="1f1184fb04cf72a7eb2a49a9740074b5419486c79e1fd713e1f8c09b8594a826050ae941fed6ac6a96807ba73cc751d7c807bd7e6b73de9e4f8e74cd5ed04cfa"
X2T_VERSION="v7.3+1"
X2T_SOURCE_COMMIT="a9b92bc026dea7c2160fb31839ef74d58d9c3652"
X2T_SHA512="ab0c05b0e4c81071acea83f0c6a8e75f5870c360ec4abc4af09105dd9b52264af9711ec0b7020e87095193ac9b6e20305e446f2321a541f743626a598e5318c1"

# CryptPad source tree commit that hosts the three "empty document" templates
# (oodoc_base.js / oocell_base.js / ooslide_base.js). These template JS files
# are NOT in the cryptpad/onlyoffice-editor release tarball — they live in
# cryptpad/cryptpad. Pinning by commit so reinstalls are reproducible.
CRYPTPAD_TEMPLATES_VERSION="2025.6.0"
CRYPTPAD_TEMPLATES_COMMIT="ae5da10f8dad9d07a90751b8069f7ea101409a7c"
OOCELL_SHA512="93be3572fa10c09be609f0bd78e7b77f20cb20a19761863db22935305489e33028b94e576eabe75d1f148463501c095dec86eb6cc68fed37ec95aece964f07ad"
OODOC_SHA512="7e6f64972e6fff2a04454ea8534cee11dc00aba02a0b9e311a0e58742bd04320451bc3df192425fb81e2400ab9c0dff5428e5ae13020396cc869fdc3dae7b185"
OOSLIDE_SHA512="8457790509b752e000de8996c3c1ea58f1784061fa3d010267212f668e8e04a9416eb2b4b8082d6c7776b3d09a0a20709db841aa97aaa7e532c685ecf3168c45"
LICENSE_SET_VERSION="$OO_SOURCE_COMMIT:$X2T_SOURCE_COMMIT:$CRYPTPAD_TEMPLATES_COMMIT"

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
ensure_command cmp
ensure_command sha512sum
ensure_command unzip

verify_sha512() {
    local file=$1
    local expected=$2
    [ -f "$file" ] && printf '%s  %s\n' "$expected" "$file" | sha512sum --check --status
}

download_verified() {
    local label=$1
    local url=$2
    local expected=$3
    local destination=$4
    local partial="$destination.partial"

    curl --fail --location --continue-at - --proto '=https' --tlsv1.2 --retry 3 \
        "$url" --output "$partial"
    if ! verify_sha512 "$partial" "$expected"; then
        rm -f -- "$partial"
        echo "$label checksum mismatch; aborting." >&2
        exit 1
    fi
    mv "$partial" "$destination"
}

template_sha512() {
    case "$1" in
        oocell_base.js) printf '%s\n' "$OOCELL_SHA512" ;;
        oodoc_base.js) printf '%s\n' "$OODOC_SHA512" ;;
        ooslide_base.js) printf '%s\n' "$OOSLIDE_SHA512" ;;
        *) echo "Unknown template: $1" >&2; return 1 ;;
    esac
}

validate_zip_paths() {
    local archive=$1
    if unzip -Z1 "$archive" | grep -Eq '(^/|(^|/)\.\.(/|$))'; then
        echo "Unsafe path in archive: $archive" >&2
        return 1
    fi
}

editor_install_valid() {
    local directory=$1
    local required
    for required in \
        web-apps/apps/api/documents/api.js \
        web-apps/apps/documenteditor/main/index.html \
        web-apps/apps/spreadsheeteditor/main/index.html \
        web-apps/apps/presentationeditor/main/index.html \
        web-apps/apps/common/main/resources/img/header/header-logo_s.svg; do
        [ -s "$directory/$required" ] || return 1
    done
}

x2t_install_valid() {
    local directory=$1
    [ -s "$directory/x2t.js" ] && [ -s "$directory/x2t.wasm" ]
}

agree_to_agpl() {
    if [ "$ASSUME_YES" = 1 ] || [ "$CHECK" = 1 ]; then return 0; fi
    cat <<'EOF'

This installer downloads the pinned CryptPad/OnlyOffice client assets into
  frontend/public/onlyoffice/
which is gitignored. OnlyOffice-derived source headers carry AGPLv3 Section 7
terms requiring Appropriate Legal Notices and the original Product logo,
denying trademark rights, and applying CC BY-SA 4.0 to identified GUI/content
material. Kutup preserves the visible original Product logo and attribution.

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

install_oo() (
    local FULL_DIR="$DEST/v9"
    local actual="not installed"
    if [ -e "$FULL_DIR/.version" ]; then
        actual=$(cat "$FULL_DIR/.version")
    fi

    if [ "$actual" = "$OO_VERSION" ] && editor_install_valid "$FULL_DIR"; then
        echo "OnlyOffice $OO_VERSION already installed."
        return 0
    fi

    if [ "$CHECK" = 1 ]; then
        echo "OnlyOffice version drift. Expected: $OO_VERSION. Found: $actual" >&2
        return 1
    fi

    echo "Installing OnlyOffice $OO_VERSION → $FULL_DIR"
    local stage archive
    stage=$(mktemp -d "$DEST/.v9-install.XXXXXX")
    archive="$stage/onlyoffice-editor.zip"
    trap 'rm -rf -- "$stage"' EXIT
    download_verified "OnlyOffice editor" \
        "https://github.com/cryptpad/onlyoffice-editor/releases/download/$OO_VERSION/onlyoffice-editor.zip" \
        "$OO_SHA512" "$archive"
    validate_zip_paths "$archive"
    unzip -q "$archive" -d "$stage/content"
    rm -f -- "$archive"
    editor_install_valid "$stage/content" || {
        echo "OnlyOffice archive is missing required runtime files; aborting." >&2
        exit 1
    }
    echo "$OO_VERSION" > "$stage/content/.version"
    # OnlyOffice's editor index.html files unconditionally register a
    # service worker at ../../../../document_editor_service_worker.js
    # (resolves to /onlyoffice/dist/v9/document_editor_service_worker.js).
    # The CryptPad build doesn't ship that file → 404 every editor open.
    # Drop a no-op stub so registration succeeds silently. Empty install
    # listener is enough; OO's caching needs aren't required for kutup.
    cat > "$stage/content/document_editor_service_worker.js" <<'SW_EOF'
// kutup: no-op stub. OnlyOffice's editor index.html unconditionally
// registers this path; without a real file the browser logs a 404 on
// every editor open. We don't need the upstream caching behaviour.
self.addEventListener('install', () => self.skipWaiting())
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()))
SW_EOF
    rm -rf -- "$FULL_DIR"
    mv "$stage/content" "$FULL_DIR"
)

install_x2t() (
    local FULL_DIR="$DEST/x2t"
    local actual="not installed"
    if [ -e "$FULL_DIR/.version" ]; then
        actual=$(cat "$FULL_DIR/.version")
    fi

    if [ "$actual" = "$X2T_VERSION" ] && x2t_install_valid "$FULL_DIR"; then
        echo "x2t $X2T_VERSION already installed."
        return 0
    fi

    if [ "$CHECK" = 1 ]; then
        echo "x2t version drift. Expected: $X2T_VERSION. Found: $actual" >&2
        return 1
    fi

    echo "Installing x2t $X2T_VERSION → $FULL_DIR"
    local stage archive
    stage=$(mktemp -d "$DEST/.x2t-install.XXXXXX")
    archive="$stage/x2t.zip"
    trap 'rm -rf -- "$stage"' EXIT
    download_verified "x2t WASM" \
        "https://github.com/cryptpad/onlyoffice-x2t-wasm/releases/download/$X2T_VERSION/x2t.zip" \
        "$X2T_SHA512" "$archive"
    validate_zip_paths "$archive"
    unzip -q "$archive" -d "$stage/content"
    rm -f -- "$archive"
    x2t_install_valid "$stage/content" || {
        echo "x2t archive is missing required runtime files; aborting." >&2
        exit 1
    }
    echo "$X2T_VERSION" > "$stage/content/.version"
    rm -rf -- "$FULL_DIR"
    mv "$stage/content" "$FULL_DIR"
)

install_templates() (
    local TMPL_DIR="$DEST/../templates"
    local actual="not installed"
    if [ -e "$TMPL_DIR/.version" ]; then
        actual=$(cat "$TMPL_DIR/.version")
    fi

    local valid=1
    local tmpl
    for tmpl in oodoc_base.js oocell_base.js ooslide_base.js; do
        verify_sha512 "$TMPL_DIR/$tmpl" "$(template_sha512 "$tmpl")" || valid=0
    done

    if [ "$actual" = "$CRYPTPAD_TEMPLATES_VERSION" ] && [ "$valid" = 1 ]; then
        echo "OnlyOffice empty-doc templates $CRYPTPAD_TEMPLATES_VERSION @ $CRYPTPAD_TEMPLATES_COMMIT already installed."
        return 0
    fi

    if [ "$CHECK" = 1 ]; then
        echo "Templates version drift. Expected: $CRYPTPAD_TEMPLATES_VERSION. Found: $actual" >&2
        return 1
    fi

    echo "Installing OnlyOffice empty-doc templates $CRYPTPAD_TEMPLATES_VERSION @ $CRYPTPAD_TEMPLATES_COMMIT → $TMPL_DIR"
    local stage
    stage=$(mktemp -d "$ASSET_ROOT/.templates-install.XXXXXX")
    trap 'rm -rf -- "$stage"' EXIT
    mkdir -p "$stage/content"
    local BASE="https://raw.githubusercontent.com/cryptpad/cryptpad/$CRYPTPAD_TEMPLATES_COMMIT/www/common/onlyoffice"
    for tmpl in oodoc_base.js oocell_base.js ooslide_base.js; do
        download_verified "template $tmpl" "$BASE/$tmpl" \
            "$(template_sha512 "$tmpl")" "$stage/content/$tmpl"
    done
    echo "$CRYPTPAD_TEMPLATES_VERSION" > "$stage/content/.version"
    rm -rf -- "$TMPL_DIR"
    mv "$stage/content" "$TMPL_DIR"
)

install_licenses() (
    local actual="not installed"
    if [ -e "$LICENSE_DEST/.version" ]; then
        actual=$(cat "$LICENSE_DEST/.version")
    fi

    local specs=(
        "editor-wrapper-AGPL-3.0-or-later.txt|https://raw.githubusercontent.com/cryptpad/onlyoffice-editor/$OO_SOURCE_COMMIT/LICENSES/AGPL-3.0-or-later.txt|3edf11dc2de2f03f707fb3efb40092ddbf17cb17ec48951dd71cafb87f5857438b7d2ff3f89497a2921f018c3371fc760e7cbc2b7cb9b52ba7ebcbb36f8f04e2"
        "editor-wrapper-CC0-1.0.txt|https://raw.githubusercontent.com/cryptpad/onlyoffice-editor/$OO_SOURCE_COMMIT/LICENSES/CC0-1.0.txt|1eb4436f8d58766cbe99db97e5e8c0db8a706376afd291c337de1ba7a6b066d3791dc85ad034bdd54ea336bed6e6e8e7a037d8b04b2773c9c7517b9d9921d1fa"
        "editor-sdkjs-AGPL-3.0.txt|https://raw.githubusercontent.com/cryptpad/onlyoffice-editor/$OO_SOURCE_COMMIT/sdkjs/LICENSE.txt|6e90d46be391aa645bcf4dfaa67f452cb15a73749f1895633789c7763b43cc0b65d391e5e95652c9a9a2063c956e0e8099a4e1ce4b70b0636629f9eac39c1080"
        "editor-web-apps-AGPL-3.0.txt|https://raw.githubusercontent.com/cryptpad/onlyoffice-editor/$OO_SOURCE_COMMIT/web-apps/LICENSE.txt|a0a86214ea153fb07ff35ceec0848dd1703eae22de036a825efc8394e50f65e3044832f3b49cf7e45a39edc470bdf738abc36a3a78ca7df3a6e73c14eaef94a8"
        "x2t-core-AGPL-3.0.txt|https://raw.githubusercontent.com/cryptpad/onlyoffice-x2t-wasm/$X2T_SOURCE_COMMIT/core/LICENSE.txt|a0a86214ea153fb07ff35ceec0848dd1703eae22de036a825efc8394e50f65e3044832f3b49cf7e45a39edc470bdf738abc36a3a78ca7df3a6e73c14eaef94a8"
        "cryptpad-templates-AGPL-3.0.txt|https://raw.githubusercontent.com/cryptpad/cryptpad/$CRYPTPAD_TEMPLATES_COMMIT/LICENSE|a0a86214ea153fb07ff35ceec0848dd1703eae22de036a825efc8394e50f65e3044832f3b49cf7e45a39edc470bdf738abc36a3a78ca7df3a6e73c14eaef94a8"
        "CC-BY-SA-4.0.txt|https://creativecommons.org/licenses/by-sa/4.0/legalcode.txt|a0ddd81c4f9af3702ae874d8c04aac4d23f17267ae23ef187e92b119d17c3527ad9a8615dd213c5d2d0f19c69739fe98145c14072a562babaa25286937988984"
    )

    local valid=1
    local spec name url sha512
    for spec in "${specs[@]}"; do
        IFS='|' read -r name url sha512 <<<"$spec"
        verify_sha512 "$LICENSE_DEST/$name" "$sha512" || valid=0
    done

    if [ "$actual" = "$LICENSE_SET_VERSION" ] && [ "$valid" = 1 ]; then
        echo "OnlyOffice license set already installed."
        return 0
    fi

    if [ "$CHECK" = 1 ]; then
        echo "OnlyOffice license set is missing or invalid." >&2
        return 1
    fi

    local stage
    stage=$(mktemp -d "$ASSET_ROOT/.licenses-install.XXXXXX")
    trap 'rm -rf -- "$stage"' EXIT
    mkdir -p "$stage/content"
    for spec in "${specs[@]}"; do
        IFS='|' read -r name url sha512 <<<"$spec"
        download_verified "license $name" "$url" "$sha512" "$stage/content/$name"
    done
    echo "$LICENSE_SET_VERSION" >"$stage/content/.version"
    rm -rf -- "$LICENSE_DEST"
    mv "$stage/content" "$LICENSE_DEST"
)

install_source_metadata() (
    local destination="$ASSET_ROOT/SOURCE.json"
    local candidate
    candidate=$(mktemp "$ASSET_ROOT/.source-metadata.XXXXXX")
    trap 'rm -f -- "$candidate"' EXIT
    cat >"$candidate" <<EOF
{
  "bundle_version": "2026.08.16-cryptpad-v9",
  "packaging_repository": "https://github.com/kutupbt/kutup-office-assets",
  "editor": {
    "version": "$OO_VERSION",
    "source_commit": "$OO_SOURCE_COMMIT",
    "source_url": "https://github.com/cryptpad/onlyoffice-editor/tree/$OO_SOURCE_COMMIT",
    "artifact_sha512": "$OO_SHA512"
  },
  "x2t": {
    "version": "$X2T_VERSION",
    "source_commit": "$X2T_SOURCE_COMMIT",
    "source_url": "https://github.com/cryptpad/onlyoffice-x2t-wasm/tree/$X2T_SOURCE_COMMIT",
    "artifact_sha512": "$X2T_SHA512"
  },
  "templates": {
    "version": "$CRYPTPAD_TEMPLATES_VERSION",
    "source_commit": "$CRYPTPAD_TEMPLATES_COMMIT",
    "source_url": "https://github.com/cryptpad/cryptpad/tree/$CRYPTPAD_TEMPLATES_COMMIT/www/common/onlyoffice",
    "oocell_sha512": "$OOCELL_SHA512",
    "oodoc_sha512": "$OODOC_SHA512",
    "ooslide_sha512": "$OOSLIDE_SHA512"
  }
}
EOF

    if [ -f "$destination" ] && cmp -s "$candidate" "$destination"; then
        echo "OnlyOffice source metadata already installed."
        return 0
    fi
    if [ "$CHECK" = 1 ]; then
        echo "OnlyOffice source metadata is missing or invalid." >&2
        return 1
    fi
    mv "$candidate" "$destination"
    echo "OnlyOffice source metadata installed."
)

mkdir -p "$DEST"

agree_to_agpl
install_oo
install_x2t
install_templates
install_licenses
install_source_metadata

echo
echo "Done. OnlyOffice client JS + x2t are installed at:"
echo "  $DEST"
echo
echo "Rebuild the frontend (pnpm build / docker compose build frontend) to"
echo "pick up the new public/ assets."
