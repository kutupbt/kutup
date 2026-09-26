# Maps

**Status:** decisions agreed 2026-09-26; slices 1–3 done. Branch
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
2. (done) **Chat: send a place once:**
   - the `location` content kind (`kutup-chat-proto/src/locations.rs`,
     docs/chat-protocol.md "Locations"), validated on every receive path,
     Direct and MLS, and able to disappear;
   - "Send a location" in the composer: tap the map (maps on), use this
     device's location, or jump to a city from the on-device list
     (`scripts/build-cities.py` → `@kutup/map` `assets/cities.json`,
     GeoNames cities15000, CC BY 4.0, 34,149 places, 1.3 MB, downloaded only
     when someone searches); an optional name;
   - the bubble: a small map while it is on screen (maps on) or the
     coordinates, the name, "Open in maps" (Apple Maps on iOS, `geo:` on
     Android, OpenStreetMap elsewhere, only when tapped) and "Copy";
     "Location: …" in previews, replies and notifications; coordinates in
     exports; the label is searchable.
   Checked in a browser: 1:1 by city with maps off on both sides, the
   receiver turning maps on and seeing the map, and a group by current
   location with a name.
3. (done) **Chat: live location:** 15 minutes / 1 hour / 8 hours from
   "Send a location", stop from the message (on any of the sharer's
   devices):
   - `LiveLocationUpdateV1` in kutup-crypto with a canonical vector (Rust
     and WASM);
   - the `liveLocation` and `liveLocationStop` kinds, validated on every
     receive path;
   - `live_location_streams` (migration 056) and the stream endpoints,
     with the federated read under `/api/fed/chat/` and a sweeper;
   - the sharing tab's manager: pacing, re-keying hourly and when someone
     leaves (the old stream deleted), ending at the end time or when nobody
     else is left, surviving a reload of the tab (session storage).
   Checked: in a browser, 1:1 (position, a move, stop) and a group of three
   where one member leaves mid-share (one stream left open; the remaining
   member keeps seeing moves; the one who left sees the share end at their
   last known position); across two servers at the API level (reading
   through one's own server, wrong capability, older update, wrong write
   secret, reading after the end).
4. **The Maps app (`maps.`):** pinned place lists, shared and edited
   together, KML/GPX import and export. Decided 2026-09-26:
   - **Lists are Drive files**, like Google My Maps in Google Drive: each
     list is a `.kutupmap` file (a Yjs document: title, places with name,
     note, coordinates, who added them and when). Drive's encryption,
     sharing, versions, trash and quota apply.
   - **A list can live in any folder, like a note.** In Drive, New → Map
     (and the right-click menu on empty space) creates one in the current
     folder; opening it, or right-click → Open in Maps, takes it to the Maps
     app. A list made in the Maps app goes into My files (the root), as
     Google My Maps does in Google Drive; it can be moved like any file.
     Maps settings has "Save new maps to", a folder of your own (default My
     files); if that folder is gone or in the trash, new maps go to My files
     and the setting says so. The choice is kept with the account's map
     preferences, so it follows you across devices. The Maps
     app shows every list you can reach: your own, wherever they are, and
     those shared with you (on their own or in a shared folder).
   - **Everything is done in the Maps app:** create, rename, delete, share,
     see who has access and remove them, and edit together live. Nobody
     needs to open Drive for a list.
   - **A list is shared on its own**, with Drive's single-file sharing
     (docs/plans/drive-file-sharing.md, decided 2026-09-26: like Proton Drive
     and CryptPad, any file can be shared by itself). For now only the owner
     shares
     (as in Drive); anyone in a list can send one of its places into a chat
     as a location message. "Editors can share" (the owner allowing members
     to add people) is a later change to Drive sharing as a whole.
   - Editing a list with someone on another server waits for editing across
     servers in Drive generally (notes included); they can view and
     download it.
   4a progress (2026-09-26): the `maps.` origin (KUTUP_MAPS_URL, `web-maps`
   sessions, migration 057, the frontend image); Drive's core in
   `@kutup/drive-core`; the live editing session in `@kutup/collab/session`,
   which also fixed a data-losing bug: a saved note recorded its client
   counter as the log position, so saving trimmed the whole relay log and
   people who joined later missed edits (now the relay announces positions,
   saves record the applied one, and positions never restart; migration
   058). Also fixed: opening a Drive or Chat link while signed out now
   lands on that link after signing in (the app's start ran twice in
   development and the retry forgot the link).
   4b progress (2026-09-26): lists work end to end.
   - The `.kutupmap` format is in `@kutup/map/list`: a Yjs map of places
     keyed by id, and JSON when stored or downloaded.
   - The Maps app (`apps/maps`):
     - your maps: your own lists wherever they are, those in folders shared
       with you, and those shared with you by themselves;
     - a new map is saved to the "Save new maps to" folder, kept as
       `saveFolderId` in the map preferences, migration 060;
     - a list page with the map, the places, and adding a place by clicking
       the map, by a city found on the device, or by coordinates;
     - editing and removing places live with everyone in the list;
     - rename, download, and move to the trash.
   - Drive: New → Map; a list opens in Maps, from the folder, search, Shared
     with me, or an old `/file/…` link; a list has its own file kind; a
     download gives the current places.
   Checked in the browser:
   - a map made in Maps, with places added all three ways;
   - two browsers editing live;
   - a person the list is shared with by itself (edit) adding a place that
     the owner sees live;
   - Drive's download holding the current places;
   - Drive opening the list in Maps;
   - New → Map from Drive;
   - the save folder.
   Lists in folders on other servers are left out of the Maps app until
   editing across servers exists.
   Parts: 4a groundwork (the `maps.` origin; Drive's core and the live
   co-editing session moved into shared packages, Drive unchanged); then
   single-file sharing in Drive; 4b lists (format, the app, live
   co-editing); 4c sharing a list from Maps, Drive integration, KML/GPX.
5. **Photos' Places:** with the Photos app.

## Open questions

None at the moment.

## Future work

Self-hosted map data the CoMaps way (regions the admin picks, downloaded
whole to the device so the server learns only the region), and offline
regions in the browser and the native apps. Not needed for the uses above.
