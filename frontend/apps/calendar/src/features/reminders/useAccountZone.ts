import { useQuery } from '@tanstack/react-query'
import { useEffect } from 'react'
import { loadCalendarZone, saveCalendarZone } from '@kutup/calendar-core/api'
import { setAccountZone, useCalendarPrefs } from '../prefs'

/**
 * The calendar zone is the account's (Proton's primary time zone): the
 * server fires all-day reminders in it. A device shows it unless it chose
 * its own in the settings (which also sets the account's: `chooseZone`), and
 * never writes it otherwise. An account without one yet takes this
 * device's, once (as Proton's is set from the browser's at the start).
 */
export function useAccountZone(): void {
  const prefs = useCalendarPrefs()
  const account = useQuery({ queryKey: ['calendar', 'settings'], queryFn: loadCalendarZone, staleTime: 5 * 60_000 })
  const zone = account.data
  const { refetch } = account
  useEffect(() => {
    if (zone === undefined) return
    if (zone !== null) {
      setAccountZone(zone)
      return
    }
    void saveCalendarZone(prefs.zone).then(() => refetch())
  }, [zone, prefs.zone, refetch])
}
