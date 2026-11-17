import { useState, type MouseEvent } from 'react'
import { useLocation } from 'react-router-dom'

export interface SidebarRefresh {
  /** The button's name, e.g. "Refresh Inbox". */
  label: string
  run: () => Promise<unknown>
}

/** At least this long spinning, so a quick fetch still reads as done (Proton waits a second too). */
const REFRESH_MIN_MS = 1000

export function useSidebarRefresh(to: string, refresh: SidebarRefresh | undefined) {
  const [busy, setBusy] = useState(false)
  const location = useLocation()
  const start = () => {
    if (!refresh || busy) return
    setBusy(true)
    void Promise.all([refresh.run().catch(() => undefined), new Promise((done) => setTimeout(done, REFRESH_MIN_MS))]).finally(() => setBusy(false))
  }
  return {
    busy,
    start,
    // A click on the place already open fetches it again instead of navigating.
    onClick: (e: MouseEvent<HTMLAnchorElement>) => {
      if (!refresh || e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return
      // Only the place exactly as the link opens it: page 2 or a search goes back to its start.
      if (location.pathname !== to || location.search !== '') return
      e.preventDefault()
      start()
    },
  }
}
