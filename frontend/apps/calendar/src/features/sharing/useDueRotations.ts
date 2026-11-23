import { useEffect, useRef } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useCalendars } from '@kutup/calendar-core/api'
import { useDriveIdentity } from '@kutup/drive-core/identity'
import { useMailAccount } from '@kutup/mail-core/api'
import { useRequiredSession } from '@kutup/session/store'
import { rotateKey } from './client'

/**
 * The owner's side of a rotation that is due (docs/plans/calendar-e3.md,
 * "Review fixes", T1): someone who held a calendar's key no longer may
 * (left it, or read an invitation that then went), so the owner's app makes
 * the next key generation as a removal does, with nobody removed. Once per
 * calendar a page; a rotation that can't go now (a person whose identity
 * changed, another device's rotation first) waits for the next load.
 */
export function useDueRotations() {
  const session = useRequiredSession()
  const me = useDriveIdentity()
  const account = useMailAccount()
  const calendars = useCalendars()
  const queryClient = useQueryClient()
  const tried = useRef(new Set<string>())
  useEffect(() => {
    if (!me.data || !account.data || !calendars.data) return
    for (const calendar of calendars.data.calendars) {
      if (!calendar.owned || !calendar.rotationDue || tried.current.has(calendar.id)) continue
      tried.current.add(calendar.id)
      void rotateKey(session, me.data, account.data, calendar, null).then(
        () => queryClient.invalidateQueries({ queryKey: ['calendar'] }),
        () => undefined,
      )
    }
  }, [session, me.data, account.data, calendars.data, queryClient])
}
