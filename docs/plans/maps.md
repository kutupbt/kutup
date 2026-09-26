# Maps

**Status:** decisions agreed 2026-09-26; slices not started. Branch
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
  enabled (and its own origin for the proxy).

## Slices

1. **Map foundation:** admin settings (providers, own tile server, proxy
   mode, cache cap, maps off); the proxy; the user's switch, notice and
   choices (account app → a "Maps" section); `@kutup/map`; the cities list.
2. **Chat: send a place once:** pin or current location; an end-to-end
   encrypted location message; the map card (or the coordinates card with
   maps off); "Open in maps app".
3. **Chat: live location:** 15 minutes / 1 hour / 8 hours, stop at any
   time; encrypted updates at a bounded rate; groups (open question below).
4. **The Maps app (`maps.`):** pinned place lists, shared and edited
   together (local and federated), KML/GPX import and export.
5. **Photos' Places:** with the Photos app.

## Open questions

- Live location in groups: delivering frequent updates without the server
  learning more than message timing, and without exhausting MLS key
  packages.

## Future work

Self-hosted map data the CoMaps way (regions the admin picks, downloaded
whole to the device so the server learns only the region), and offline
regions in the browser and the native apps. Not needed for the uses above.
