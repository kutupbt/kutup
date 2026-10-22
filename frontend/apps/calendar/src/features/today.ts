import { useQuery } from '@tanstack/react-query'
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
