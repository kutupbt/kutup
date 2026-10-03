/**
 * The typefaces, self-hosted.
 *
 * Three roles from one superfamily (see `docs/frontend.md`):
 *
 * - **IBM Plex Sans Condensed 600** — page and section titles.
 * - **IBM Plex Sans 400/500/600** — UI, labels, and prose a person wrote.
 * - **IBM Plex Mono 400/500** — everything the *system* asserts: key
 *   fingerprints, device and session IDs, exact sizes, absolute timestamps.
 *
 * The cuts are metrically related by design, which is what makes the
 * machine-voice / human-voice split read as one typographic system rather than
 * two fonts stapled together.
 *
 * **These are imports, not a stylesheet link, and that is the point.** Kutup
 * is self-hosted and its CSP allows no third-party origins, so a
 * `fonts.googleapis.com` URL would both leak every page view to a third party
 * and render the UI in a fallback face. Vite fingerprints and bundles the
 * woff2 files; nothing is fetched at runtime.
 *
 * **latin-ext is not optional.** Turkish needs `ğ ı İ ş`, and every one of them
 * lives in that subset — shipping `latin` alone would drop the `tr` locale into
 * a fallback mid-sentence.
 */

// Body and UI.
import '@fontsource/ibm-plex-sans/latin-400.css'
import '@fontsource/ibm-plex-sans/latin-ext-400.css'
import '@fontsource/ibm-plex-sans/latin-500.css'
import '@fontsource/ibm-plex-sans/latin-ext-500.css'
import '@fontsource/ibm-plex-sans/latin-600.css'
import '@fontsource/ibm-plex-sans/latin-ext-600.css'

// Display. One weight — a display face used at more than one weight stops
// being a display face.
import '@fontsource/ibm-plex-sans-condensed/latin-600.css'
import '@fontsource/ibm-plex-sans-condensed/latin-ext-600.css'

// The machine voice. 500 exists for values that carry emphasis — the digits
// of a safety number a person is comparing.
import '@fontsource/ibm-plex-mono/latin-400.css'
import '@fontsource/ibm-plex-mono/latin-ext-400.css'
import '@fontsource/ibm-plex-mono/latin-500.css'
import '@fontsource/ibm-plex-mono/latin-ext-500.css'
