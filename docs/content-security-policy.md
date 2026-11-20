# Content-Security-Policy

Every Kutup web app (account, Drive, Chat, Maps, Photos, Office, Contacts,
Mail, Pass, Calendar) runs on its own origin, holds decrypted keys and
content in its pages, and so must not run a script it did not ship or send
anything anywhere but its own server. The browser enforces that with each
app's Content-Security-Policy, which the frontend container writes at start
(`frontend/docker/40-kutup-hosts.sh`).

## Rollout: report-only first

There are two policies today:

- the **old policy**, enforced: it still allows `'unsafe-inline'` and
  `'unsafe-eval'` scripts (Pass excepted), WebSockets to any host
  (`connect-src … wss:`) and, in Mail, remote images over `https:`;
- the **strict policy** below, sent as `Content-Security-Policy-Report-Only`
  beside it. Browsers block nothing because of it; they report what it
  would have blocked to `POST /api/csp-report` (`report-uri`, and
  `report-to kutup-csp` through a `Reporting-Endpoints` header).

`KUTUP_CSP_ENFORCE=1` on the frontend container enforces the strict policy
and drops the old one (and sends `X-Frame-Options: DENY` everywhere). It
will become the default once the reports from real use have been read and
whatever they show fixed ([`roadmap.md`](roadmap.md), item 10).

## The strict policy

The base, for every app (`<ws-origin>` is the app's own origin as `wss://`,
or `ws://` on a plain-HTTP test stack; `<nonce>` is new for every response,
below):

```
default-src 'none'; script-src 'self' 'wasm-unsafe-eval';
style-src 'self' 'nonce-<nonce>'; img-src 'self' data: blob:;
font-src 'self' data:; media-src 'self' blob:;
connect-src 'self' <ws-origin>; worker-src 'self'; manifest-src 'self';
frame-src 'none'; frame-ancestors 'none'; object-src 'none';
base-uri 'none'; form-action 'self';
report-uri /api/csp-report; report-to kutup-csp
```

Additions per app:

| App | Adds | Why |
| --- | --- | --- |
| Drive | `frame-src blob:`; `style-src-attr 'unsafe-inline'` | Quick Look shows a decrypted PDF in a frame of its `blob:` URL; whiteboards (Excalidraw), mermaid diagrams and KaTeX write `style` attributes into the SVG and HTML they make |
| Photos | `connect-src blob:` | the viewer reads a decrypted original back from its `blob:` URL to convert it |
| Chat | `connect-src` the SFU (`CHAT_SFU_URL` as `wss://` and `https://`); `frame-src blob:` | group calls (LiveKit); PDF attachments |
| Mail | `frame-src blob:`; `style-src-attr 'unsafe-inline'` | PDF attachments. The message body is a sandboxed `srcdoc` frame, which inherits this policy and adds its own (`img-src data: blob:`); messages keep their senders' (sanitized) `style` attributes |
| Office | `frame-src <editor sandbox origin> blob:`; `style-src-attr 'unsafe-inline'` | documents and PDFs open in the OnlyOffice sandbox; whiteboards, diagrams and maths as in Drive |
| Pass | `connect-src blob:` | site icons come back from the server as `blob:` URLs and are read again |
| account, Chat, Maps, Photos (the apps whose bundles draw maps) | `connect-src` and `img-src`: the origins in `KUTUP_MAP_DIRECT_ORIGINS` | maps loaded straight from a provider (below) |
| Calendar, Contacts, Maps | nothing else | |

No app allows `'unsafe-inline'` or `'unsafe-eval'` anywhere; only the
editor sandbox does (below).

Scripts are never inline: each page loads its reload guard
(`/kutup-reload-guard.js`), style nonce (`/kutup-style-nonce.js`) and
no-flash theme (`/theme.js`) as files that the shared Vite config
(`frontend/packages/config/vite.ts`) emits, and
`scripts/check-app-bundles.mjs` fails the web gate if a built
`dist/index.html` has an inline script, event handler or style, or lacks
the nonce placeholder and script ahead of its modules.

### Styles: the nonce

A `<style>` element applies only with the page's nonce. For every page
response nginx takes `$request_id` (128 random bits) as the nonce, names it
in the policy, and writes it over the placeholder in the page's
`<meta name="csp-nonce" content="__KUTUP_CSP_NONCE__">` (`sub_filter`, in
the `location = /index.html` that every app route ends in). That response is
never served from the stored gzip/brotli copies (nginx compresses it as it
goes) and carries no `ETag` or `Last-Modified`, so no cache can revalidate
an old page with an old nonce.

The libraries the apps use add their `<style>` elements from script, most
with no way to take a nonce: Radix's scroll lock (react-style-singleton),
sonner, next-themes, tiptap, CodeMirror (style-mod), pdf.js's font loader,
mermaid, cytoscape, emoji-mart. `/kutup-style-nonce.js`
(`frontend/packages/config/src/styleNonce.ts`), a classic script that runs
before any module, reads the meta and makes `document.createElement` and
`createElementNS` give every `style` element the nonce. That keeps what the
nonce is for: style markup injected into a page (HTML parsing never calls
`createElement`) does not apply, while the apps' own scripts, the only ones
`script-src` lets run, style the page as they could anyway through the CSSOM
or constructed style sheets, neither of which CSP governs.

Two places put a `<style>` into the page as markup, and add the nonce
themselves (`styleNonce()` in `@kutup/ui/lib/cspNonce`): mermaid's SVG in
the Markdown preview (Drive, Office) and the Mail reader's frame document,
whose own style sheet sets the message's look. Mail's sanitizer still
removes every `<style>` a message carries.

`style` attributes set through the CSSOM (`element.style.x = …`, React's
`style={…}`, Radix, MapLibre) are not subject to CSP. Ones written as
markup or with `setAttribute('style', …)` are, and only Drive, Office and
Mail allow them (`style-src-attr 'unsafe-inline'`): Excalidraw sets them on
the SVG it draws, mermaid (through d3) and KaTeX write them into theirs,
and a message's HTML keeps its sender's inline styles. Neither hashes
(they would need `'unsafe-hashes'` and a hash for every value, which are
made at run time) nor nonces (attributes cannot carry one) can cover them.
The other apps send no `style-src-attr`, so `style-src` applies: no style
attributes in markup.

### What the build does for it

- **MapLibre** (v6) loads its worker from a file the build emits
  (`maplibre-gl-worker.mjs?worker&url`, `setWorkerUrl`;
  `frontend/packages/map/src/maplibre.ts`). MapLibre 6 has no separate
  "CSP build" any more and uses no eval; without the worker URL it looked
  for the worker beside its own module, which the bundle does not keep.
- **pdf.js** (6.x, Drive thumbnails) evaluates no code: the
  `isEvalSupported` option and the eval-compiled font paths it switched off
  were removed upstream, so there is nothing to set.
- **Excalidraw** loads its fonts from `window.EXCALIDRAW_ASSET_PATH`, else
  from esm.sh. Apps whose bundle holds Excalidraw (Drive, Office) serve the
  fonts at `/excalidraw-assets/fonts/`, and `@kutup/editors` points
  Excalidraw there before it loads
  (`frontend/packages/editors/src/whiteboard/assets.ts`).
- **Excalidraw's font subsetting** (when a whiteboard is exported or
  thumbnailed) runs an Emscripten build of woff2 whose embind glue builds
  functions with `new Function`. The build rewrites those three spots
  (`kutup-excalidraw-no-eval` in `frontend/packages/config/vite.ts`) into
  the closures Emscripten itself emits when built with
  `-sDYNAMIC_EXECUTION=0`, so no app needs `'unsafe-eval'`. The rewrite
  matches Excalidraw 0.18's published minified code exactly; when an
  upgrade changes it, or a `new Function` is left in that package, the
  build fails rather than ship eval. (A `pnpm patch` would carry the
  bundle's 800 KB minified lines whole.) The other `Function(…)` calls
  left in the bundles are lodash's `Function('return this')`, which runs
  only where there is no `globalThis` or `self`, and zod's test for eval,
  which Account turns off (`z.config({ jitless: true })`,
  `frontend/apps/account/src/zodConfig.ts`) so it neither tries nor
  reports. MapLibre's worker evaluates a script only to load the RTL text
  plugin, which no app sets.

### Mail's remote images

Remote images load through the Kutup image proxy (`POST /api/v1/mail/images`,
shown as `blob:` URLs) or not at all; Mail's policy has no `https:` in
`img-src`. Tracker protection, when on, also counts and never asks for
known tracking pixels and cleans links; turning it off no longer makes the
browser load images from the sender.

### Maps

By default every map comes through the server's relay
(`/api/v1/maps/proxy/…`, on the app's own origin). `KUTUP_MAP_DIRECT_ORIGINS`
(comma-separated origins, e.g.
`https://tile.openstreetmap.org,https://tiles.openfreemap.org`), given to
both the backend and the frontend container, lists the providers browsers
may load from directly: the frontend container adds them to the map apps'
`connect-src` and `img-src`, and the server offers direct loading only for
providers whose origin is in it. The admin Maps page shows which providers
are relay-only and offers relay mode "Off" only when every offered provider
is listed; the server refuses it otherwise.

### The editor sandbox

The OnlyOffice sandbox origin keeps `'unsafe-inline'` (scripts and styles)
and `'unsafe-eval'`: OnlyOffice's client builds code with `eval`/`new
Function`, and its bridge pages and editor write inline scripts and
`<style>` elements and style attributes throughout, from a build Kutup
ships but does not rewrite. It is the only origin with any `'unsafe-*'`
source other than `'wasm-unsafe-eval'`, which is why it is its own origin holding no
session and no API: the reverse proxy (`nginx/nginx.conf`) and the server
(by `KUTUP_EDITOR_URL`) answer `404` for `/api/` on its host. Its strict
policy adds `object-src 'none'`; `frame-ancestors` stays `'self'` plus the
Office origin, because OnlyOffice nests its own frames and the check covers
every ancestor. It sends no reports (it has no API to send them to); the e2e
listener below still sees them.

## API responses

Every `/api/` answer carries `Content-Security-Policy: default-src 'none';
frame-ancestors 'none'` unless it sets a policy of its own (the sandboxing
ones on proxied mail images and Pass site icons): an API answer opened as a
page runs nothing and cannot be framed. Apps read the API with `fetch`, to
which a response's policy does not apply, so downloads and public share
pages are unaffected.

## Reports

`POST /api/csp-report` ([`api.md`](api.md#post-apicsp-report)) takes
`application/csp-report` and `application/reports+json`, with no account,
at most 64 KiB, and at most 60 a minute per address
(`RATE_LIMIT_CSP_REPORTS_PER_MIN`, also on the admin Rate limits page). A
body is read by its shape, not its content type: WebKit posts its
`report-to` report as `application/csp-report`, one Reporting API object
with no array around it. The server logs each at warn level as `content security policy violation` with
only the app's host, the directive, the blocked resource's origin (or its
kind: `inline`, `eval`, `data`, `blob`) and the disposition; never a path
or a query, which can carry share tokens or file ids. Nothing is stored.

Checking the sites `40-kutup-hosts.sh` writes: the frontend image runs
`nginx -t` on them, report-only and enforced, when it is built; the command
for doing the same without building it is in
[`contributing.md`](contributing.md#running-tests).

## Tests

The e2e fixture (`tests/e2e/fixtures/test.ts`) records every page's
`securitypolicyviolation` events, report-only ones included, and attaches
them to the test; `E2E_CSP_STRICT=1` fails a test that saw any
([`tests/e2e/README.md`](../tests/e2e/README.md)).

## Known gaps before enforcing

- Drive's warm-up frame for the office editor (`FileEditorPage`) is not in
  Drive's `frame-src`, as it was not in the old policy's either.
