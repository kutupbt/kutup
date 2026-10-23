import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect } from 'react'
import { loadCalendarZone, saveCalendarZone } from '@kutup/calendar-core/api'
import { setPrefs, useCalendarPrefs, zoneChosen } from '../prefs'

/**
 * The calendar zone is the account's (Proton's calendar user settings): the
 * server fires all-day reminders in it. A zone this device chose goes to the
 * account; a device that never chose one takes the account's.
 */
export function useAccountZone(): void {
  const prefs = useCalendarPrefs()
  const queryClient = useQueryClient()
  const account = useQuery({ queryKey: ['calendar', 'settings'], queryFn: loadCalendarZone, staleTime: 5 * 60_000 })
  const stored = account.data
  useEffect(() => {
    if (stored === undefined || stored === prefs.zone) return
    if (stored !== null && !zoneChosen()) {
      setPrefs({ zone: stored })
      return
    }
    void saveCalendarZone(prefs.zone).then(() => queryClient.invalidateQueries({ queryKey: ['calendar', 'settings'] }))
  }, [stored, prefs.zone, queryClient])
}
