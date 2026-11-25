import { useQuery, useQueryClient } from '@tanstack/react-query'
import type { Calendar } from '@kutup/calendar-core/api'
import { addPendingInvitations, loadInviteSettings } from '@kutup/calendar-core/invitations'
import { useMailAccount } from '@kutup/mail-core/api'
import { useRequiredSession } from '@kutup/session/store'

/** How often the invitations listed for this account are looked at while the calendar is open. */
const EVERY_MS = 2 * 60 * 1000

/**
 * "Add to calendar and mark as pending" for Kutup invitations (Proton's
 * `AutoImportInvite`; docs/plans/calendar-e4.md §6): what organizers on this
 * server invited this account to goes into its default calendar at once,
 * pending until answered, without a mail being opened.
 */
export function useAutoAdd(calendars: Calendar[] | undefined) {
  const session = useRequiredSession()
  const account = useMailAccount()
  const queryClient = useQueryClient()
  const settings = useQuery({ queryKey: ['calendar', 'invite-settings'], queryFn: loadInviteSettings, staleTime: 60_000 })
  useQuery({
    queryKey: ['calendar-invitations', 'auto-add', session.sessionId, calendars?.map((c) => c.id).join(',')],
    enabled: !!account.data && !!calendars && settings.data?.autoAdd === true,
    refetchInterval: EVERY_MS,
    queryFn: async () => {
      const added = await addPendingInvitations(session, account.data!, calendars!)
      if (added > 0) await queryClient.invalidateQueries({ queryKey: ['calendar', 'events'] })
      return added
    },
  })
}
