#!/bin/sh
#
# install-cli.sh — install the `kutup` command-line client from a GitHub
# release, checking the archive's SHA-256 against the release's checksums.
#
#   curl -fsSL https://raw.githubusercontent.com/kutupbt/kutup/master/scripts/install-cli.sh | sh
#   curl -fsSL …/install-cli.sh | sh -s -- --version v0.2.0 --dir ~/bin
#
# Options (or the environment variable beside each):
#   --version vX.Y.Z   KUTUP_VERSION      a CLI release tag (default: the newest
#                                         published one; desktop-v… tags are not
#                                         CLI releases and are skipped)
#   --dir DIR          KUTUP_INSTALL_DIR  where `kutup` goes (default ~/.local/bin)
#
# KUTUP_DOWNLOAD_BASE (default https://github.com/kutupbt/kutup/releases/download)
# points at a mirror laid out as <base>/<tag>/<asset>.
#
# Linux and macOS, x86-64 and ARM64. No root needed: nothing is written
# outside the install directory and a temporary directory removed on exit.

set -eu

REPO="kutupbt/kutup"
API="https://api.github.com/repos/$REPO"
BASE="${KUTUP_DOWNLOAD_BASE:-https://github.com/$REPO/releases/download}"
VERSION="${KUTUP_VERSION:-}"
INSTALL_DIR="${KUTUP_INSTALL_DIR:-}"

say() { printf 'kutup-install: %s\n' "$*" >&2; }
die() {
  say "error: $*"
  exit 1
}

usage() {
  cat <<'EOF'
Install the kutup CLI.

  install-cli.sh [--version vX.Y.Z] [--dir DIR]

  --version   the release tag to install (KUTUP_VERSION; default: the newest)
  --dir       the install directory (KUTUP_INSTALL_DIR; default: ~/.local/bin)
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version)
      [ "$#" -ge 2 ] || die "--version needs a value (e.g. --version v0.2.0)"
      VERSION="$2"
      shift 2
      ;;
    --version=*)
      VERSION="${1#--version=}"
      shift
      ;;
    --dir)
      [ "$#" -ge 2 ] || die "--dir needs a value"
      INSTALL_DIR="$2"
      shift 2
      ;;
    --dir=*)
      INSTALL_DIR="${1#--dir=}"
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      die "unknown option: $1"
      ;;
  esac
done

if [ -z "$INSTALL_DIR" ]; then
  [ -n "${HOME:-}" ] || die "HOME is not set; give --dir or KUTUP_INSTALL_DIR"
  INSTALL_DIR="$HOME/.local/bin"
fi

# --- tools ---------------------------------------------------------------

if command -v curl >/dev/null 2>&1; then
  DOWNLOADER=curl
elif command -v wget >/dev/null 2>&1; then
  DOWNLOADER=wget
else
  die "neither curl nor wget is installed"
fi

# download URL FILE — 0 when FILE holds the body of a successful answer.
download() {
  if [ "$DOWNLOADER" = curl ]; then
    curl -fsSL --retry 3 -o "$2" "$1"
  else
    wget -q -O "$2" "$1"
  fi
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$1" | awk '{print $NF}'
  else
    die "no SHA-256 tool found (sha256sum, shasum or openssl); refusing to install unchecked"
  fi
}

command -v tar >/dev/null 2>&1 || die "tar is not installed"

# --- platform ------------------------------------------------------------

case "$(uname -s)" in
  Linux) OS=linux ;;
  Darwin) OS=darwin ;;
  *)
    die "unsupported OS: $(uname -s) (Linux and macOS here; on Windows use install-cli.ps1)"
    ;;
esac

case "$(uname -m)" in
  x86_64 | amd64) ARCH=amd64 ;;
  aarch64 | arm64) ARCH=arm64 ;;
  *) die "unsupported CPU: $(uname -m) (x86-64 and ARM64 only)" ;;
esac

# A shell under Rosetta reports x86_64 on an Apple Silicon Mac: take the
# native build.
if [ "$OS" = darwin ] && [ "$ARCH" = amd64 ] &&
  [ "$(sysctl -n hw.optional.arm64 2>/dev/null || echo 0)" = 1 ]; then
  ARCH=arm64
fi

case "$OS/$ARCH" in
  linux/amd64) TARGET=x86_64-unknown-linux-gnu ;;
  linux/arm64) TARGET=aarch64-unknown-linux-gnu ;;
  darwin/amd64) TARGET=x86_64-apple-darwin ;;
  darwin/arm64) TARGET=aarch64-apple-darwin ;;
esac

if [ "$OS" = linux ] && ldd --version 2>&1 | grep -qi musl; then
  say "warning: this system uses musl libc; the Linux builds need glibc"
  say "warning: build from source instead if kutup does not start"
fi

TMP="$(mktemp -d 2>/dev/null || mktemp -d -t kutup-install)"
trap 'rm -rf "$TMP"' EXIT
trap 'exit 130' INT TERM

# --- version -------------------------------------------------------------

# The newest published CLI release: tags vX.Y.Z, not drafts or prereleases
# (desktop releases are tagged desktop-v… and skipped).
latest_version() {
  url="$API/releases?per_page=100"
  if [ "$DOWNLOADER" = curl ]; then
    status="$(curl -sSL --retry 3 -o "$TMP/releases.json" -w '%{http_code}' \
      -H 'Accept: application/vnd.github+json' "$url")" ||
      die "could not reach the GitHub API ($url)"
    case "$status" in
      200) ;;
      403 | 429)
        if grep -qi 'rate limit' "$TMP/releases.json"; then
          die "GitHub API rate limit reached for this address; wait an hour or set KUTUP_VERSION (e.g. KUTUP_VERSION=v0.2.0)"
        fi
        die "the GitHub API answered $status; set KUTUP_VERSION to skip it"
        ;;
      *) die "the GitHub API answered $status for $url; set KUTUP_VERSION to skip it" ;;
    esac
  else
    wget -q -O "$TMP/releases.json" "$url" ||
      die "could not list releases from the GitHub API (its rate limit is 60 requests an hour per address); set KUTUP_VERSION to skip it"
  fi
  # The API pretty-prints one field per line; in each release, tag_name
  # comes before draft and prerelease.
  awk '
    /"tag_name":/ { tag = $0; sub(/.*"tag_name":[ ]*"/, "", tag); sub(/".*/, "", tag); draft = "" }
    /"draft":/ { draft = ($0 ~ /true/) ? "true" : "false" }
    /"prerelease":/ {
      if (tag ~ /^v[0-9]/ && draft == "false" && $0 ~ /false/) { print tag; exit }
      tag = ""
    }
  ' "$TMP/releases.json"
}

if [ -z "$VERSION" ]; then
  say "finding the newest kutup CLI release…"
  VERSION="$(latest_version)"
  [ -n "$VERSION" ] || die "no published CLI release (tag vX.Y.Z) found in $REPO"
fi
case "$VERSION" in
  v[0-9]*) ;;
  [0-9]*) VERSION="v$VERSION" ;;
  *) die "not a CLI release tag: $VERSION (CLI tags look like v0.2.0)" ;;
esac

# --- download and check --------------------------------------------------

# Two release layouts: the Rust build (.github/workflows/release.yml) names
# each archive after its target with a .sha256 file beside it; v0.1.0 (the
# earlier Go build) names them <version>_<os>_<arch> with one checksums.txt.
NUMBER="${VERSION#v}"
if download "$BASE/$VERSION/kutup_${VERSION}_${TARGET}.sha256" "$TMP/sums" 2>/dev/null; then
  ARCHIVE="kutup_${VERSION}_${TARGET}.tar.gz"
elif download "$BASE/$VERSION/checksums.txt" "$TMP/sums" 2>/dev/null; then
  ARCHIVE="kutup_${NUMBER}_${OS}_${ARCH}.tar.gz"
else
  die "release $VERSION has no checksums for $OS/$ARCH (is $VERSION a published CLI release? see https://github.com/$REPO/releases)"
fi

say "downloading kutup $VERSION for $OS/$ARCH…"
download "$BASE/$VERSION/$ARCHIVE" "$TMP/$ARCHIVE" ||
  die "could not download $BASE/$VERSION/$ARCHIVE"

# The entry for this archive: "<sha256>  <name>" (or "*<name>" in binary mode).
WANT="$(awk -v name="$ARCHIVE" '{ n = $2; sub(/^\*/, "", n) } n == name { print tolower($1); exit }' "$TMP/sums")"
[ -n "$WANT" ] || die "the release's checksums do not list $ARCHIVE; refusing to install"
GOT="$(sha256_of "$TMP/$ARCHIVE" | tr 'A-F' 'a-f')"
if [ "$GOT" != "$WANT" ]; then
  die "checksum mismatch for $ARCHIVE (expected $WANT, got $GOT); refusing to install"
fi
say "checksum verified (SHA-256 $GOT)"

mkdir "$TMP/x"
tar -xzf "$TMP/$ARCHIVE" -C "$TMP/x" || die "could not unpack $ARCHIVE"
BIN="$(find "$TMP/x" -type f -name kutup | head -n 1)"
[ -n "$BIN" ] || die "$ARCHIVE holds no kutup binary"

# --- install -------------------------------------------------------------

mkdir -p "$INSTALL_DIR" || die "could not create $INSTALL_DIR"
[ -w "$INSTALL_DIR" ] || die "$INSTALL_DIR is not writable; choose another with --dir"
# Copied beside the target, then renamed over it: a running kutup keeps its
# old file, and a failed copy leaves the old one in place.
cp "$BIN" "$INSTALL_DIR/.kutup.new.$$"
chmod 755 "$INSTALL_DIR/.kutup.new.$$"
mv -f "$INSTALL_DIR/.kutup.new.$$" "$INSTALL_DIR/kutup"

INSTALLED="$("$INSTALL_DIR/kutup" version 2>/dev/null | head -n 1 || true)"
say "installed ${INSTALLED:-kutup $VERSION} to $INSTALL_DIR/kutup"

case ":${PATH:-}:" in
  *":$INSTALL_DIR:"*) ;;
  *)
    say "$INSTALL_DIR is not on your PATH; add it, e.g. in ~/.profile:"
    say "  export PATH=\"$INSTALL_DIR:\$PATH\""
    ;;
esac
