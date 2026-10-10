#!/bin/sh
# Stores a gzip (-9) and a brotli (-q 11) copy beside every compressible
# file of 1 KB or more under $1, for nginx's gzip_static and brotli_static
# (frontend/Dockerfile). An existing copy is kept. OnlyOffice's help pages,
# hundreds of MB that are rarely opened, get gzip only.
set -eu
root=$1
jobs=$(nproc 2>/dev/null || echo 2)

files() {
  find "$root" -type f -size +1k \
    \( -name '*.js' -o -name '*.mjs' -o -name '*.css' -o -name '*.html' -o -name '*.json' \
       -o -name '*.wasm' -o -name '*.svg' -o -name '*.ttf' -o -name '*.otf' -o -name '*.txt' \
       -o -name '*.xml' -o -name '*.ico' -o -name '*.webmanifest' \) "$@"
}

files | xargs -r -P "$jobs" -n 50 sh -c 'for f; do [ -e "$f.gz" ] || gzip -9 -k -n "$f"; done' sh
files ! -path '*/help/*' | xargs -r -P "$jobs" -n 20 sh -c 'for f; do [ -e "$f.br" ] || brotli -q 11 -k "$f"; done' sh

gz=$(find "$root" -name '*.gz' | wc -l)
br=$(find "$root" -name '*.br' | wc -l)
echo "precompress: $gz gzip and $br brotli copies under $root"
