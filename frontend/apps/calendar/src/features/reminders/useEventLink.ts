import { useEffect } from 'react'
import { useSearchParams } from 'react-router-dom'
import { loadEvent, useCalendars } from '@kutup/calendar-core/api'
import { useMailAccount } from '@kutup/mail-core/api'
import { openEditor } from '../editorState'

/**
 * `/?event=<id>`, where a reminder (its notification, its email) leads:
 * the event opens in the editor, found in whichever of the account's
 * calendars holds it, and the link is cleared.
 */
export function useEventLink(): void {
  const [params, setParams] = useSearchParams()
  const eventId = params.get('event')
  const account = useMailAccount()
  const calendars = useCalendars()
  useEffect(() => {
    if (!eventId || !account.data || !calendars.data) return
    let cancelled = false
    void (async () => {
      for (const calendar of calendars.data.calendars) {
        try {
          const event = await loadEvent(account.data, calendar, eventId)
          if (!cancelled) openEditor({ kind: 'edit', event })
          break
        } catch {
          // Not in this calendar (or not readable): the next one.
        }
      }
      if (!cancelled) {
        setParams((now) => {
          const next = new URLSearchParams(now)
          next.delete('event')
          return next
        })
      }
    })()
    return () => {
      cancelled = true
    }
  }, [eventId, account.data, calendars.data, setParams])
}
