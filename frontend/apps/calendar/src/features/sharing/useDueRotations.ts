import { useCallback, useEffect, useRef, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useCalendars } from '@kutup/calendar-core/api'
import { useDriveIdentity } from '@kutup/drive-core/identity'
import { useMailAccount } from '@kutup/mail-core/api'
import { useRequiredSession } from '@kutup/session/store'
import { compactKeys, COMPACT_AT, dueRotation, keyGenerationCap } from './client'

/**
 * The owner's upkeep of its calendars' keys, as the app loads them
 * (docs/plans/calendar-e3.md, T1 and "Compaction"):
 * - a rotation that is due (someone who held a key left) is made unasked
 *   only when everyone who gets the new key is someone the owner already
 *   trusts; otherwise, or when it fails, the calendar is listed as pending
 *   review, and the row says so ("Key change pending — review");
 * - a calendar nearing the site's key-generation cap is compacted.
 * Once per calendar a page.
 */
export function useKeyUpkeep(): { pending: ReadonlySet<string>; settle: (calendarId: string) => void } {
  const session = useRequiredSession()
  const me = useDriveIdentity()
  const account = useMailAccount()
  const calendars = useCalendars()
  const queryClient = useQueryClient()
  const tried = useRef(new Set<string>())
  const compacted = useRef(new Set<string>())
  const [pending, setPending] = useState<ReadonlySet<string>>(new Set())
  const mark = useCallback((calendarId: string, on: boolean) => {
    setPending((now) => {
      const next = new Set(now)
      if (on) next.add(calendarId)
      else next.delete(calendarId)
      return next
    })
  }, [])
  useEffect(() => {
    if (!me.data || !account.data || !calendars.data) return
    for (const calendar of calendars.data.calendars) {
      if (!calendar.owned) continue
      if (calendar.rotationDue && !tried.current.has(calendar.id)) {
        tried.current.add(calendar.id)
        dueRotation(session, me.data, account.data, calendar).then(
          (outcome) => {
            if (outcome.kind === 'review') mark(calendar.id, true)
            else void queryClient.invalidateQueries({ queryKey: ['calendar'] })
          },
          () => mark(calendar.id, true),
        )
        continue
      }
      if (!calendar.rotationDue && calendar.keyGenerations > 1 && !compacted.current.has(calendar.id)) {
        compacted.current.add(calendar.id)
        void keyGenerationCap().then(async (cap) => {
          if (calendar.keyGenerations < cap * COMPACT_AT) return
          try {
            await compactKeys(calendar)
            await queryClient.invalidateQueries({ queryKey: ['calendar'] })
          } catch {
            // Tried again on the next load; the dialog offers it by hand.
          }
        })
      }
    }
  }, [session, me.data, account.data, calendars.data, queryClient, mark])
  return { pending, settle: useCallback((calendarId: string) => mark(calendarId, false), [mark]) }
}
