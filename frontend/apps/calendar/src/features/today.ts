import { useQuery } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import type { CivilDate } from '@kutup/calendar-core/time'
import { utcToLocal } from '@kutup/crypto/calendar'

/** Today in `zone`, through the bundled time zone database; checked every minute. */
export function useToday(zone: string): CivilDate | undefined {
  return useQuery({
    queryKey: ['calendar', 'today', zone],
    queryFn: async () => (await utcToLocal(new Date().toISOString().replace(/\.\d+Z$/, 'Z'), zone)).slice(0, 10),
    refetchInterval: 60_000,
  }).data
}

/** The current minute of the day in `zone`, refreshed every 30 seconds (Proton's). */
export function useNowMinutes(zone: string): number {
  const read = () => {
    const parts = new Intl.DateTimeFormat('en-GB', { timeZone: zone, hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }).formatToParts(new Date())
    const value = (type: string) => Number(parts.find((p) => p.type === type)?.value ?? 0)
    return value('hour') * 60 + value('minute')
  }
  const [now, setNow] = useState(read)
  useEffect(() => {
    const timer = window.setInterval(() => setNow(read()), 30_000)
    return () => window.clearInterval(timer)
    // eslint-disable-next-line react-hooks/exhaustive-deps -- the zone is the dependency
  }, [zone])
  return now
}
