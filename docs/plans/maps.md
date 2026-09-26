# Maps

**Status:** decisions agreed 2026-09-26; slice 1 done. Branch
`feat/frontend-rewrite`. Roadmap entry: `docs/roadmap.md` → "New apps (after
v1)" → Maps.

## What maps are for

Not a navigation app: no routing and no turn-by-turn directions; a place can
be opened in the device's own maps app. Three uses, each in its own app:

| Use | App |
|---|---|
| Pinned place lists: end-to-end encrypted, edited together, shared with people here and on other servers like Drive folders, KML/GPX import and export | `maps.` |
| Sending a place once, and live location for a set time (like WhatsApp) | `chat.` |
| Places: a map of where each photo was taken (like Ente) | `photos.` |

All three draw the map with one shared package (`@kutup/map`, MapLibre GL
JS). Places are chosen by dropping a pin or using the device's current
location.

## How Ente does it (reference)

From `kutup-references/ente`:
- The map is off by default. Turning it on shows: *"Approximate coordinates
  will be sent to privacy conscious third parties like OpenStreetMap to show
  the map and location."*
- Tiles come straight from `tile.openstreetmap.org` (Leaflet on the web,
  `flutter_map` with a 200 MB tile cache on mobile). Ente stores no map data.
- Editing a photo's location searches OpenStreetMap's public Nominatim.
- City search is private: the client downloads one world-cities list and
  matches on the device.

CoMaps (`kutup-references/comaps`) is the opposite end: about 1,150 region
files (about 99 GB for the world) downloaded to the device, everything
offline, no web build. Hosting map data ourselves is future work (below).

## Decisions (product owner, 2026-09-26)

1. **No map data on the server for now.** Tiles come from a map provider;
   the providers offered need no API key: OpenFreeMap (vector) and
   OpenStreetMap (raster).
2. **The admin decides what is available:**
   - which providers users may choose: OpenFreeMap, OpenStreetMap, and
     optionally the server's own tile server (a URL the admin sets, e.g. a
     self-hosted OpenFreeMap or OpenStreetMap tile server);
   - the proxy: **off**, **available** or **enforced**. Through the proxy
     the browser asks the Kutup server, which fetches and caches the tiles
     (admin-capped cache), so providers see the server and never users'
     addresses. Enforced means every user's map traffic goes through it;
   - maps off entirely, for servers that want no third party at all.
3. **Each user decides within that:**
   - maps on or off: **off by default**, with an Ente-style notice when
     turning them on (which provider, and whether it sees their address or
     only the server's);
   - the provider, from the admin's list;
   - through the server or direct, when the admin made the proxy
     available.
4. **Users cannot add tile servers.** Only the admin configures upstream
   URLs, so the proxy never fetches an address a user chose (no SSRF path).
5. **Each viewer's own setting governs what they see.** With maps off, a
   shared place or live location shows as a card with the place's
   coordinates and "Open in maps app", and a photo's location as text; no
   request goes to any provider.
6. **One shared cache, for the relay only (agreed 2026-09-26).** Direct
   traffic never touches the server; the browser caches as usual. The relay
   keeps one cache for all users, sized by the admin, oldest tiles evicted
   first. It keeps the relay within OpenStreetMap's tile usage policy (no
   repeated fetches of the same tiles), makes common areas fast, and means
   the provider sees an occasional fetch rather than every view. Size `0`
   turns it off and the relay only forwards; the admin page warns that this
   breaks OpenStreetMap's policy at any real volume. A per-user cache was
   rejected: its only gain is hiding a timing hint (that *someone* on the
   server recently viewed an area, never who), at the cost of multiplying
   disk use and upstream fetches.
7. **City search like Ente's:** a world-cities list (e.g. GeoNames
   `cities15000`, CC BY 4.0) shipped with the web apps and served from our
   own origin; matching happens on the device. Searching places by name
   through a geocoder is later, and would follow the same provider model.

## Live location (decided 2026-09-26)

A live location is its own short-lived channel, not a stream of chat
messages, for 1:1 chats and groups alike.

- **Why not chat messages:** every group message is sealed once per
  recipient device, so an update every 15 s for 8 h in a 50-person group
  (about 150 devices) would be about 290,000 envelopes; offline devices
  would come back to hundreds of stale positions; and the steady beat would
  show the server that someone in the conversation is sharing.
- **Start:** the sharer's app makes a random stream ID, a random stream key
  and a write secret, and sends them to the conversation in one ordinary
  end-to-end encrypted message together with the end time ("until 14:30").
  That message is the only trace in the chat.
- **Updates:** each update is encrypted once with the stream key (and a
  counter) and written to the stream's single slot on the sharer's server,
  which keeps only the latest update. Writing needs the write secret, not
  the sharer's account, so the server does not learn whose stream it is or
  which conversation it belongs to. Members read the slot while the map is
  open; members on other servers read through their own server.
- **Keys:** one key per stream and a counter per update, so a reader can
  open the latest update directly, with no ratchet to skip through. A new
  key every hour, and at once when anyone leaves the conversation, goes out
  in a new ordinary group message to the remaining members only; a removed
  member's key shows nothing new. (WhatsApp ratchets per update and added a
  fast-forward for missed updates; with shares of at most 8 hours, hourly
  and on-leave rekeying gives most of that for much less.)
- **Temporary:** updates are never chat history, previews or backups. The
  stream is deleted when the sharer stops or the end time passes; if the
  sharer's app vanishes, readers stop at the end time from the start
  message and the server deletes the slot.
- **Rate:** about every 15–30 s while moving; a heartbeat every few minutes
  while still; the map shows how old the last update is.
- **Devices:** every device of every member can follow a live location
  (WhatsApp limits this to primary phones). On the web, sharing continues
  only while a Kutup tab is open; background sharing comes with the native
  apps.
- **What the server sees:** that a stream exists, its size and how often it
  is written and read, and which servers read it; never coordinates, the
  sharer or the conversation.

Signal has no live location (a static location on Android only), so this
goes beyond Signal parity.

## What the server learns

- **Direct:** the provider sees the user's IP address and the tiles, i.e.
  the area being looked at (which, for a friend's live location or a
  photo's place, is roughly where they are). This is the trade-off the
  notice states.
- **Through the proxy:** the provider sees only the Kutup server; the Kutup
  server sees which tiles its users load. Coordinates themselves (places,
  live locations, photo locations) stay end-to-end encrypted and are placed
  on the map in the browser.
- **Maps off:** nothing.

## Server details to settle in slice 1

- Settings live with the other site settings (admin) and per-account
  preferences (user); the admin page is in the account app.
- The proxy serves only the admin-configured upstreams, through the existing
  SSRF-safe client (`crates/kutup-server/src/ssrf.rs`), with bounded paths
  (`z/x/y`, style, glyphs, sprites) and the shared cache (decision 6), which
  honours upstream cache headers. For vector styles the proxy rewrites the style's
  tile, glyph and sprite URLs to its own paths.
- OpenStreetMap's tile usage policy applies to their servers: an
  identifying User-Agent, no bulk downloads, respect caching. The proxy
  sends one identifying User-Agent per server and caches; the admin page
  links the policy.
- Content Security Policy: each app allows only the providers the admin
  enabled (and its own origin for the proxy), and none when the relay is
  enforced. This lands with the per-origin CSP for account, Drive and Chat
  in phase 5 of docs/plans/multi-app-web-rewrite.md; until then "always"
  is what the apps do, not what the browser enforces.

## Slices

1. (done) **Map foundation:**
   - admin settings in `site_settings.maps` (providers, own tile server,
     relay mode, cache size, maps off) on the account app's admin **Maps**
     page;
   - each person's choice in `user_map_preferences` (migration 055) on the
     account app's **Maps** page, with the notice and a preview map;
   - the relay `GET /api/maps/proxy/{provider}/{path}`
     (`kutup-server/src/maps.rs`): signed-in people only, offered providers
     only, plain paths, map resource types only, 4 MiB, 1,200 requests a
     minute per person; style JSON rewritten to point back at the relay;
     the shared on-disk cache in `MAPS_CACHE_DIR`, least recently used out
     first, upstream lifetimes within 1 hour–30 days, an expired copy served
     when the provider is down;
   - `@kutup/map`: `useMapConfig`, `effectiveMap`, and `MapView` (MapLibre,
     loaded lazily), which sends the session token only to the relay.
   Checked in a browser against the real providers: OpenFreeMap and
   OpenStreetMap through the relay with no request reaching the provider,
   and directly; the admin's "always" reaching people's pages.
2. **Chat: send a place once:** pin or current location; an end-to-end
   encrypted location message; the map card (or the coordinates card with
   maps off); "Open in maps app"; the cities list (moved here from slice 1:
   the place picker is its first user) for jumping to a city.
3. **Chat: live location:** 15 minutes / 1 hour / 8 hours, stop at any
   time; the live channel above.
4. **The Maps app (`maps.`):** pinned place lists, shared and edited
   together (local and federated), KML/GPX import and export.
5. **Photos' Places:** with the Photos app.

## Open questions

None at the moment.

## Future work

Self-hosted map data the CoMaps way (regions the admin picks, downloaded
whole to the device so the server learns only the region), and offline
regions in the browser and the native apps. Not needed for the uses above.
