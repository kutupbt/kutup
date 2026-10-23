import { useEffect } from 'react'
import { useSearchParams } from 'react-router-dom'
import { loadEvent, useCalendars } from '@kutup/calendar-core/api'
import { useMailAccount } from '@kutup/mail-core/api'
import { openEditor } from '../editorState'

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

/**
 * `/?event=<id>`, where a reminder (its notification, its email) leads:
 * the event opens in the editor, found in whichever of the account's
 * calendars holds it, and the link is cleared.
 */
export function useEventLink(): void {
  const [params, setParams] = useSearchParams()
  // An event's id, and nothing else: the link is anyone's to write.
  const asked = params.get('event')
  const eventId = asked && UUID.test(asked) ? asked : null
  const account = useMailAccount()
  const calendars = useCalendars()
  // A malformed one is dropped.
  useEffect(() => {
    if (asked === null || eventId !== null) return
    setParams((now) => {
      const next = new URLSearchParams(now)
      next.delete('event')
      return next
    })
  }, [asked, eventId, setParams])
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
