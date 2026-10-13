// Tracking parameters leave links (docs/plans/mail-parity.md, P5), as
// Proton's "Protect against email tracking" cleans them with tidy-url: the
// campaign tags and click identifiers that marketing mail adds so the click
// can be tied to the reader. The rest of the link stays as it was.

/** Parameters that only identify the reader or the campaign. */
const TRACKING_PARAMS = new Set([
  'fbclid', 'gclid', 'gclsrc', 'dclid', 'gbraid', 'wbraid', 'msclkid', 'yclid', 'twclid', 'ttclid',
  'li_fat_id', 'igshid', 'mc_cid', 'mc_eid', '_hsenc', '_hsmi', '__hssc', '__hstc', '__hsfp',
  'hsctatracking', 'mkt_tok', 'oly_anon_id', 'oly_enc_id', 'vero_conv', 'vero_id', 'rb_clickid',
  's_cid', '_openstat', 'ml_subscriber', 'ml_subscriber_hash', 'sc_cid', 'wickedid', 'trk_contact',
  'trk_msg', 'trk_module', 'trk_sid', 'ref_src', '__s', '_kx', 'ck_subscriber_id', 'mkcid', 'mkevt',
  'spm', 'ncid', 'cmpid', 'elqtrackid', 'elqtrack', 'elqaid', 'elqat', 'srsltid',
])

export interface CleanedLink {
  original: string
  cleaned: string
  /** The parameters taken out. */
  removed: string[]
}

function tracking(name: string): boolean {
  const key = name.toLowerCase()
  return key.startsWith('utm_') || TRACKING_PARAMS.has(key)
}

/** An http(s) link without its tracking parameters; null when it has none. */
export function cleanTrackingLink(href: string): CleanedLink | null {
  let url: URL
  try {
    url = new URL(href.trim())
  } catch {
    return null
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return null
  const removed = [...url.searchParams.keys()].filter(tracking)
  if (removed.length === 0) return null
  // Rebuilt by hand so the parameters that stay keep their exact spelling.
  const kept = url.search
    .slice(1)
    .split('&')
    .filter((pair) => {
      const name = pair.split('=')[0] ?? ''
      let decoded = name
      try {
        decoded = decodeURIComponent(name.replace(/\+/g, ' '))
      } catch {
        // keep the raw name
      }
      return pair !== '' && !tracking(decoded)
    })
  url.search = kept.length ? `?${kept.join('&')}` : ''
  return { original: href, cleaned: url.toString(), removed: [...new Set(removed)] }
}
