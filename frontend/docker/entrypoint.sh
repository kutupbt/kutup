#!/bin/sh
# Writes the per-hostname sites (kutup-hosts.sh), then runs nginx in the
# foreground.
set -eu
/usr/local/bin/kutup-hosts.sh
exec nginx -g 'daemon off;'
