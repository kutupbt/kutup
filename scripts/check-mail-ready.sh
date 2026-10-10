#!/usr/bin/env bash
# Is a domain ready for Kutup Mail (docs/self-hosting.md, "Moving MX to
# Kutup")? Checks DNS, port 25 with STARTTLS and its certificate, and Web Key
# Directory, and prints one line per check. Run it from a machine outside the
# server (from the server itself, port 25 only tests its own loopback), before
# the MX switch and after:
#
#   scripts/check-mail-ready.sh kutup.dev
#   scripts/check-mail-ready.sh kutup.dev --dkim-selector <selector> --address dev@kutup.dev --after
#
# --dkim-selector  a selector from Stalwart's DKIM records (repeatable)
# --address        also fetch this Kutup address's key through WKD
# --host           the mail host (default mail.<domain>)
# --after          the MX must already point at the mail host (before the
#                  switch it is reported but does not fail)
#
# Needs dig, openssl and curl (and python3 for --address). Exits non-zero when
# a check fails.
set -uo pipefail

domain="${1:?usage: check-mail-ready.sh <domain> [--host mail.<domain>] [--dkim-selector s]... [--address a@domain] [--after]}"
shift
host="mail.$domain"
selectors=()
address=""
after=0
while [ $# -gt 0 ]; do
  case "$1" in
    --host) host="${2:?--host needs a name}"; shift 2 ;;
    --dkim-selector) selectors+=("${2:?--dkim-selector needs a selector}"); shift 2 ;;
    --address) address="${2:?--address needs an address}"; shift 2 ;;
    --after) after=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
for tool in dig openssl curl; do
  command -v "$tool" >/dev/null || { echo "check-mail-ready needs $tool" >&2; exit 2; }
done

failed=0
pass() { printf 'PASS  %-14s %s\n' "$1" "$2"; }
fail() { printf 'FAIL  %-14s %s\n' "$1" "$2"; failed=1; }
note() { printf 'WAIT  %-14s %s\n' "$1" "$2"; }
txt() { dig +short TXT "$1" | sed 's/" "//g; s/^"//; s/"$//'; }
http_code() {
  local code
  code="$(curl -sS -o /dev/null -m 15 -w '%{http_code}' "$1" 2>/dev/null)"
  printf '%s' "${code:-000}" | tail -c 3
}

# The mail host and its reverse name.
ip="$(dig +short A "$host" | grep -E '^[0-9.]+$' | head -n 1)"
if [ -z "$ip" ]; then
  fail "A" "$host has no IPv4 address"
else
  pass "A" "$host → $ip"
  ptr="$(dig +short -x "$ip" | sed 's/\.$//' | head -n 1)"
  if [ "$ptr" = "$host" ]; then pass "PTR" "$ip → $ptr"; else fail "PTR" "$ip → ${ptr:-nothing} (set it to $host at the hosting provider)"; fi
fi

# MX: the switch itself.
mx="$(dig +short MX "$domain" | sort -n | awk '{print $2}' | sed 's/\.$//' | paste -sd ' ')"
if [ -n "$mx" ] && [ "$(printf '%s\n' $mx | grep -cvx "$host")" = 0 ]; then
  pass "MX" "$domain → $mx"
elif [ "$after" = 1 ]; then
  fail "MX" "$domain → ${mx:-nothing}; expected only $host"
else
  note "MX" "$domain → ${mx:-nothing}; switch to '10 $host' last"
fi

# SPF: one record, naming the server's address, and no earlier service.
spf="$(txt "$domain" | grep -i '^v=spf1' || true)"
if [ -z "$spf" ]; then
  fail "SPF" "no v=spf1 record on $domain"
elif [ "$(printf '%s\n' "$spf" | wc -l)" -gt 1 ]; then
  fail "SPF" "more than one v=spf1 record (receivers reject both)"
elif [ -n "$ip" ] && ! printf '%s' "$spf" | grep -q "ip4:$ip"; then
  fail "SPF" "\"$spf\" does not name ip4:$ip"
elif printf '%s' "$spf" | grep -q '_spf.mx.cloudflare.net'; then
  fail "SPF" "\"$spf\" still includes Cloudflare Email Routing"
else
  pass "SPF" "$spf"
fi

# DKIM: Stalwart's selectors, as its records name them.
if [ "${#selectors[@]}" = 0 ]; then
  note "DKIM" "pass --dkim-selector for each record Stalwart generated"
else
  for selector in "${selectors[@]}"; do
    record="$(txt "$selector._domainkey.$domain")"
    if printf '%s' "$record" | grep -q 'p=[A-Za-z0-9+/]'; then
      pass "DKIM" "$selector._domainkey.$domain has a public key"
    else
      fail "DKIM" "$selector._domainkey.$domain has no public key"
    fi
  done
fi

# DMARC.
dmarc="$(txt "_dmarc.$domain" | grep -i '^v=DMARC1' || true)"
if [ -z "$dmarc" ]; then
  fail "DMARC" "no v=DMARC1 record on _dmarc.$domain"
elif ! printf '%s' "$dmarc" | grep -qi 'p=\(none\|quarantine\|reject\)'; then
  fail "DMARC" "\"$dmarc\" has no policy"
else
  pass "DMARC" "$dmarc"
fi

# Port 25 with STARTTLS and a certificate valid for the mail host. Many
# networks block outbound port 25: then nothing here can tell, so say so.
if ! timeout 10 bash -c '</dev/tcp/gmail-smtp-in.l.google.com/25' 2>/dev/null; then
  printf 'SKIP  %-14s %s\n' "SMTP 25" "this machine cannot reach any port 25 (its network blocks it); run from one that can"
else
smtp="$(timeout 20 openssl s_client -starttls smtp -connect "$host:25" -servername "$host" \
  -verify_return_error -verify_hostname "$host" -brief </dev/null 2>&1)"
if printf '%s' "$smtp" | grep -q 'Verification: OK'; then
  pass "SMTP 25" "STARTTLS with a valid certificate for $host"
elif [ -z "$smtp" ] || printf '%s' "$smtp" | grep -qi 'connect\|timed out\|refused\|didn.t find starttls'; then
  fail "SMTP 25" "no SMTP answer from $host:25 (port closed in the firewall, or Stalwart not running)"
else
  fail "SMTP 25" "STARTTLS or the certificate failed: $(printf '%s' "$smtp" | grep -i 'error\|verif' | head -n 1)"
fi
fi

# Web Key Directory, both methods.
code="$(http_code "https://$domain/.well-known/openpgpkey/policy")"
if [ "$code" = 200 ]; then pass "WKD direct" "https://$domain/.well-known/openpgpkey/policy"; else fail "WKD direct" "https://$domain/.well-known/openpgpkey/policy answered $code"; fi
if [ -n "$(dig +short "openpgpkey.$domain")" ]; then
  code="$(http_code "https://openpgpkey.$domain/.well-known/openpgpkey/$domain/policy")"
  if [ "$code" = 200 ]; then
    pass "WKD advanced" "https://openpgpkey.$domain/.well-known/openpgpkey/$domain/policy"
  else
    fail "WKD advanced" "openpgpkey.$domain resolves but answered $code (clients ask it first: serve it or remove the name)"
  fi
else
  pass "WKD advanced" "openpgpkey.$domain does not resolve; clients use the direct method"
fi
if [ -n "$address" ]; then
  local_part="${address%@*}"
  hash="$(python3 -c '
import hashlib, sys
a = "ybndrfg8ejkmcpqxot1uwisza345h769"
d = hashlib.sha1(sys.argv[1].lower().encode()).digest()
bits = "".join(f"{b:08b}" for b in d)
print("".join(a[int(bits[i:i + 5].ljust(5, "0"), 2)] for i in range(0, len(bits), 5)))
' "$local_part")"
  code="$(http_code "https://$domain/.well-known/openpgpkey/hu/$hash?l=$local_part")"
  if [ "$code" = 200 ]; then pass "WKD key" "$address"; else fail "WKD key" "$address answered $code"; fi
fi

exit "$failed"
