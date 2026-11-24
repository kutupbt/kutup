#!/usr/bin/env python3
"""Checks the Koru edge configuration koru/render.sh writes against the
nginx edge's rules (nginx/nginx.conf): the same hosts, limits, timeouts,
rate limits, edge headers and log privacy. Runs without Koru itself, in
the static gate; scripts/test-koru-edge.sh runs Koru on the result.
"""

import os
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RENDER = ROOT / "koru" / "render.sh"

BASE_ENV = {
    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    "KUTUP_BASE_DOMAIN": "example.org",
    "MAIL_HOSTNAME": "mx.example.org",
    "KUTUP_ACME_EXTRA_DOMAINS": "sfu.example.org,turn.example.org,sfu-turn.example.org,www.example.org",
    "CHAT_SFU_URL": "wss://sfu.example.org",
}
APPS = ["account", "drive", "chat", "office", "maps", "photos", "contacts", "mail", "pass", "calendar"]


def render(**extra: str) -> subprocess.CompletedProcess:
    env = dict(BASE_ENV)
    env.update(extra)
    return subprocess.run(["sh", str(RENDER), "print"], env=env, capture_output=True, text=True)


def config(**extra: str) -> dict:
    done = render(**extra)
    if done.returncode != 0:
        sys.exit(f"render.sh failed: {done.stderr}")
    return tomllib.loads(done.stdout)


def route(site: dict, path: str) -> dict:
    """The route Koru picks for a path: the first that matches."""
    for r in site.get("route", []):
        p = r["path"]
        if p.endswith("*"):
            prefix = p[:-1]
            if path.startswith(prefix) or path == prefix.rstrip("/"):
                return r
        elif p == path:
            return r
    return {}


def main() -> None:
    failures: list[str] = []

    def check(ok: bool, what: str) -> None:
        if not ok:
            failures.append(what)

    cfg = config()
    sites = cfg["site"]
    main_site, editor, sfu = sites
    check(main_site["hosts"][: len(APPS)] == [f"{a}.example.org" for a in APPS], "every app host on the main site")
    check("mx.example.org" in main_site["hosts"] and "www.example.org" in main_site["hosts"], "MAIL_HOSTNAME and extra names")
    check(editor["hosts"] == ["editor.example.org"], "the editor sandbox has a site of its own")
    check(sfu["hosts"] == ["sfu.example.org"], "the SFU has a site of its own")
    streams = {tuple(s["hosts"]): s for s in cfg["stream"]}
    check(("turn.example.org",) in streams and ("sfu-turn.example.org",) in streams, "TURN names are passed through")
    check(all("proxy_protocol" not in s for s in cfg["stream"]), "no PROXY header to relays by default")

    for site in sites:
        check(site["mode"] == "detect", "detect is the default mode")
        check(site["https_redirect"] is True, "plain HTTP is redirected")
        check(site["tls"] == {"cert": "/certs/fullchain.pem", "key": "/certs/privkey.pem"}, "certificate files by default")
        headers = site["response_headers"]
        check(headers.get("Strict-Transport-Security") == "max-age=31536000; includeSubDomains", "HSTS at the edge")
        check(headers.get("X-Content-Type-Options") == "nosniff", "nosniff at the edge")
        # Each app's Content-Security-Policy comes from the frontend container.
        check(not any(h.lower().startswith("content-security-policy") for h in headers), "no CSP at the edge")
    check(main_site["response_headers"].get("Referrer-Policy") == "strict-origin-when-cross-origin", "Referrer-Policy")
    check(main_site["max_body_size"] == "1MB", "1 MB bodies outside /api (client_max_body_size 1m)")

    # Log privacy: a calendar link's key is in its query, its id in its path.
    for path in ["/api/v1/calendar/links/0d5a1d3e/calendar.ics", "/api/v1/drive/public-links/abc"]:
        r = route(main_site, path)
        check(r.get("log_query") is False and r.get("log_path") == "prefix", f"{path}: logged without query or id")
    check(route(main_site, "/api/v1/calendar/links/x").get("inspect_body") is not False, "calendar links inspected")

    # Credential-facing requests: nginx's `auth` zone, 10 a minute and a burst of 5.
    for p in ["login/start", "login/2fa", "register", "recover/grant"]:
        r = route(main_site, f"/api/v1/auth/{p}")
        check(r.get("rate_limit") == {"requests": 15, "window_secs": 60}, f"auth/{p} rate limit")
        check(r.get("inspect_body") is not False, f"auth/{p} bodies inspected")
    check(route(main_site, "/api/v1/auth/login/finish").get("rate_limit", {}).get("requests") == 1000, "a sign-in finish is no attempt")

    for path, timeout in [
        ("/api/v1/chat/ws", 3600),
        ("/api/v1/chat/provisioning", 900),
        ("/api/v1/drive/files/x/collab/ws", 3600),
        ("/api/v1/drive/federation/file-shares/x/collab/ws", 3600),
        ("/api/v1/drive/uploads/x", 3600),
        ("/api/v1/admin/settings", 300),
    ]:
        r = route(main_site, path)
        check(r.get("read_timeout_secs") == timeout and r.get("write_timeout_secs") == timeout, f"{path}: {timeout} s")
    for path in ["/api/v1/chat/ws", "/api/v1/drive/uploads/x", "/api/v1/mail/messages", "/api/v1/chat/messages",
                 "/api/fed/v2/chat/sealed/messages", "/api/fed/v2/drive/collab/push"]:
        check(route(main_site, path).get("inspect_body") is False, f"{path}: ciphertext not held back")
    for path in ["/api/v1/chat/call-links/token", "/api/fed/v2/accounts/lookup", "/api/v1/admin/settings"]:
        check(route(main_site, path).get("inspect_body") is not False, f"{path}: body inspected")
    for r in main_site["route"]:
        if r["path"].startswith("/api"):
            check(r.get("max_body_size") == "10GB", f"{r['path']}: 10 GB like nginx's /api/")
            check("rate_limit" in r, f"{r['path']}: rate limited")
            check(r["upstreams"] == ["http://backend:3000"], f"{r['path']}: to the backend")
    paths = [r["path"] for r in main_site["route"]]
    check(paths.index("/api/*") > max(i for i, p in enumerate(paths) if p.startswith("/api/") and p != "/api/*"),
          "the /api/* catch-all comes after every more specific route")
    for p in ["/.well-known/kutup/federation.json", "/.well-known/security.txt", "/.well-known/openpgpkey/hu/x"]:
        check(route(main_site, p).get("upstreams") == ["http://backend:3000"], f"{p}: to the backend")
    check(main_site["error_pages"]["429"].endswith("/429.json"), "429 answers carry code rateLimited")

    rules = editor.get("rule", [])
    check(any(r["action"] == "block" and r.get("status") == 404 and r["path"] == "/api/*" for r in rules),
          "no API on the editor sandbox (404)")
    check(sfu["read_timeout_secs"] == 3600 and sfu["upstreams"] == ["http://host.docker.internal:7880"], "SFU socket for the whole call")

    acme = config(KORU_TLS="acme", KORU_MODE="block", KUTUP_ACME_STAGING="1", KUTUP_ACME_EMAIL="ops@example.org")
    check(all("tls" not in s for s in acme["site"]), "acme: sites take the [server.acme] certificate")
    certs = acme["server"]["acme"]["certificate"]
    check("editor.example.org" in certs[0]["hosts"] and "sfu.example.org" in certs[0]["hosts"], "acme: web names")
    check(certs[1]["hosts"] == ["turn.example.org", "sfu-turn.example.org"], "acme: relay names apart")
    check("staging" in acme["server"]["acme"]["directory"], "acme: staging")
    check(all(s["mode"] == "block" for s in acme["site"]), "KORU_MODE=block")

    # certbot renewing the files (docker-compose.koru-certbot.yml): its HTTP-01 answers on every
    # site, and on a plain-HTTP catch-all for names with no site (the TURN names).
    plain = config()
    check(all(r["path"] != "/.well-known/acme-challenge/*" for s in plain["site"] for r in s.get("route", [])),
          "no ACME route without KORU_ACME_WEBROOT")
    webroot = config(KORU_ACME_WEBROOT="/var/www/acme")
    named_sites = [s for s in webroot["site"] if s["hosts"] != ["*"]]
    check(all(any(r["path"] == "/.well-known/acme-challenge/*" and r.get("root") == "/var/www/acme"
                  and r.get("mode") == "off" for r in s.get("route", [])) for s in named_sites),
          "every site answers ACME challenges from the webroot, uninspected")
    catch_all = [s for s in webroot["site"] if s["hosts"] == ["*"]]
    check(len(catch_all) == 1 and catch_all[0].get("root") == "/var/www/acme"
          and catch_all[0].get("https_redirect") is False and "tls" not in catch_all[0]
          and "upstreams" not in catch_all[0], "a plain-HTTP catch-all serves only the webroot")

    # The names nginx's certificate covers instead of the apps' (KUTUP_ACME_DOMAINS) are served too.
    named = config(KUTUP_ACME_DOMAINS="kutup.example.org,turn.example.org")
    check("kutup.example.org" in named["site"][0]["hosts"], "KUTUP_ACME_DOMAINS names are sites")
    check(any(s["hosts"] == ["turn.example.org"] for s in named["stream"]), "KUTUP_ACME_DOMAINS relay names are streams")
    # A list naming the editor sandbox (as KUTUP_ACME_DOMAINS replacing the apps' would) keeps its own site.
    listed = config(KUTUP_ACME_DOMAINS="account.example.org,editor.example.org")
    check([s["hosts"] for s in listed["site"]][1] == ["editor.example.org"], "an editor named in KUTUP_ACME_DOMAINS keeps its site")
    check("editor.example.org" not in listed["site"][0]["hosts"], "the editor is not an app host")
    # An editor sharing an app's host name (another port): no editor site, and no error.
    shared = config(KUTUP_EDITOR_URL="https://drive.example.org:8443")
    check(all(s["hosts"] != ["editor.example.org"] for s in shared["site"]), "an editor on an app's host name has no site of its own")

    relay = config(KORU_RELAY_PROXY_PROTOCOL="v2", KORU_PROXY_PROTOCOL_FROM="10.0.0.5,10.1.0.0/16")
    check(all(s.get("proxy_protocol") == "v2" for s in relay["stream"]), "KORU_RELAY_PROXY_PROTOCOL")
    check(relay["server"]["proxy_protocol_from"] == ["10.0.0.5", "10.1.0.0/16"], "KORU_PROXY_PROTOCOL_FROM")

    for bad in [{"KORU_MODE": "loud"}, {"KORU_TLS": "self"}, {"KORU_TRUSTED_PROXIES": 'x"y'},
                {"KUTUP_DRIVE_URL": 'https://dr"ive.example.org'}, {"KUTUP_BASE_DOMAIN": ""}]:
        check(render(**bad).returncode != 0, f"refused: {bad}")

    if failures:
        print("Koru edge configuration:", *failures, sep="\n  ", file=sys.stderr)
        sys.exit(1)
    print("Koru edge configuration: ok")


if __name__ == "__main__":
    main()
