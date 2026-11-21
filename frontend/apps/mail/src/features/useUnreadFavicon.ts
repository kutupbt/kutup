import { useEffect } from 'react'

/**
 * The app's icon with the unread count on it, as an SVG: Proton's
 * "Show unread count in favicon" (`useMailboxFavicon`, which ships 100
 * pre-drawn icons; Kutup draws one). Above 99 it reads 99+.
 */
export function badgeFavicon(svg: string, count: number): string {
  const label = count > 99 ? '99+' : String(count)
  const size = label.length > 2 ? 13 : 18
  const badge =
    `<circle cx="40" cy="16" r="16" fill="#dc2626"/>` +
    `<text x="40" y="16" dy="0.35em" text-anchor="middle" font-family="system-ui, sans-serif" font-weight="700" font-size="${size}" fill="#fff">${label}</text>`
  return svg.replace(/<\/svg>\s*$/, `${badge}</svg>`)
}

let baseSvg: Promise<string> | null = null

/** The tab's icon carries `count` while `on` and above 0; the plain icon otherwise. */
export function useUnreadFavicon(count: number, on: boolean) {
  useEffect(() => {
    const link = document.querySelector<HTMLLinkElement>('link[rel="icon"]')
    if (!link) return
    // The page's own icon, kept to fetch it once and to put back.
    const base = link.dataset.base ?? link.getAttribute('href') ?? '/favicon.svg'
    link.dataset.base = base
    if (!on || count <= 0) {
      link.setAttribute('href', base)
      return
    }
    let current = true
    baseSvg ??= fetch(base).then((r) => (r.ok ? r.text() : Promise.reject(new Error(`favicon ${r.status}`))))
    baseSvg
      .then((svg) => {
        if (current) link.setAttribute('href', `data:image/svg+xml,${encodeURIComponent(badgeFavicon(svg, count))}`)
      })
      .catch(() => {
        // Without the icon's source the plain icon stays (Proton gives up the same way).
        baseSvg = null
      })
    return () => {
      current = false
    }
  }, [count, on])
}
