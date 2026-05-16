import { useEffect, useState } from 'react'

/**
 * Reactor for the `(max-width: 767px)` media query — the `<md:` Tailwind
 * breakpoint. Returns true on phone-sized viewports.
 *
 * Tailwind responsive classes (`md:hidden`, `hidden md:flex`, etc.) handle most
 * style branching directly in CSS — prefer those when possible. Use this hook
 * only when component rendering must fork (e.g. `<Vaul>` vs `<Sheet>`, or
 * mobile vs desktop layout in `Drive.tsx`) so that data-fetching hooks don't
 * end up double-mounted.
 *
 * SSR-safe: returns `false` on the server (matches the desktop-default render),
 * then re-evaluates on hydration.
 */
export function useIsMobile(): boolean {
  const query = '(max-width: 767px)'
  const [isMobile, setIsMobile] = useState<boolean>(() => {
    if (typeof window === 'undefined') return false
    return window.matchMedia(query).matches
  })

  useEffect(() => {
    if (typeof window === 'undefined') return
    const mql = window.matchMedia(query)
    const onChange = (e: MediaQueryListEvent) => setIsMobile(e.matches)
    setIsMobile(mql.matches)
    mql.addEventListener('change', onChange)
    return () => mql.removeEventListener('change', onChange)
  }, [])

  return isMobile
}
