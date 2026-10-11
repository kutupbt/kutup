"""The mail gate's stand-in for the outside web (tests/mail/compose.yml):
serves the GnuPG correspondent's key by WKD from /keys, and records POSTs
(RFC 8058 one-click unsubscribes) for the live tests to read back at
GET /__posts."""

import http.server
import json

POSTS = []


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory="/keys", **kwargs)

    def do_POST(self):  # noqa: N802 (http.server's naming)
        length = int(self.headers.get("Content-Length") or 0)
        POSTS.append(
            {
                "path": self.path,
                "contentType": self.headers.get("Content-Type", ""),
                "body": self.rfile.read(length).decode("utf-8", "replace"),
            }
        )
        self.send_response(200)
        self.end_headers()

    def do_GET(self):  # noqa: N802
        if self.path == "/__posts":
            data = json.dumps(POSTS).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        super().do_GET()


http.server.ThreadingHTTPServer(("", 8080), Handler).serve_forever()
