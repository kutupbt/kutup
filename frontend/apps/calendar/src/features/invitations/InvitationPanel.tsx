import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Check, CircleHelp, Minus, X } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { useCalendarMutation, type Calendar, type CalendarEvent } from '@kutup/calendar-core/api'
import { answerFromCopy, attendeeAnswers, loadInviteSettings, sendLanguage } from '@kutup/calendar-core/invitations'
import type { Partstat } from '@kutup/crypto/calendar'
import { useMailAccount, usePinnedKeys } from '@kutup/mail-core/api'
import { Button } from '@kutup/ui/components/button'
import { Input } from '@kutup/ui/components/input'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'

/** An answer's mark (Proton's `AttendeeStatusIcon`). */
function Mark({ partstat }: { partstat: Partstat }) {
  const { t } = useTranslation()
  const label = t(`invitations.partstat.${partstat}`)
  const icon =
    partstat === 'accepted' ? <Check className="size-3.5 text-status-ok" /> : partstat === 'declined' ? <X className="size-3.5 text-destructive" /> : partstat === 'tentative' ? <CircleHelp className="size-3.5" /> : <Minus className="size-3.5 text-muted-foreground" />
  return (
    <span title={label} className="inline-flex shrink-0">
      {icon}
      <span className="sr-only">{label}</span>
    </span>
  )
}

/**
 * An invitation's participants and their answers in the event view, and
 * for an attendee the answer buttons (Proton's `RsvpSection`, "Attending?
 * Yes / Maybe / No"): the answer is written to the organizer's event, then
 * mailed to the organizer (docs/plans/calendar-e4.md §5–6).
 */
export function InvitationPanel({ calendar, event, canAnswer }: { calendar: Calendar; event: CalendarEvent; canAnswer: boolean }) {
  const { t, i18n } = useTranslation()
  const account = useMailAccount()
  const pinned = usePinnedKeys()
  const queryClient = useQueryClient()
  const [note, setNote] = useState('')
  const answers = useQuery({
    queryKey: ['calendar', 'answers', event.id, event.revision, event.attendeeRows.map((r) => `${r.token}:${r.answerUpdatedAt}`).join(',')],
    enabled: !!account.data,
    queryFn: () => attendeeAnswers(account.data!, calendar, event),
  })
  const mine = answers.data?.find((a) => account.data?.isOwnAddress(a.email))
  const answer = useCalendarMutation(async (partstat: Exclude<Partstat, 'needs-action'>) => {
    if (!account.data) throw new Error('no account')
    const lng = sendLanguage(await loadInviteSettings().catch(() => undefined), i18n.language)
    const failures = await answerFromCopy({ account: account.data, pinned: pinned ?? (() => undefined), calendar, event, partstat, note: note.trim() || null, lng })
    return failures
  })
  return (
    <div className="mt-2 space-y-2" data-testid="event-invitation">
      <ul className="space-y-0.5">
        {(answers.data ?? event.attendees ?? []).map((attendee) => {
          const partstat = 'partstat' in attendee ? (attendee.partstat as Partstat) : 'needs-action'
          return (
            <li key={attendee.email} className="flex items-center gap-1.5" data-testid="event-attendee" data-partstat={partstat}>
              <Mark partstat={partstat} />
              <span className="min-w-0 truncate">{attendee.name || attendee.email}</span>
              {attendee.optional ? <span className="text-xs text-muted-foreground">{t('invitations.optional')}</span> : null}
              {account.data?.isOwnAddress(attendee.email) ? <span className="text-xs text-muted-foreground">({t('invitation.widget.you')})</span> : null}
            </li>
          )
        })}
      </ul>
      {canAnswer && mine ? (
        <div className="space-y-1.5 border-t pt-2">
          <p className="text-xs font-medium">{t('invitation.widget.attending')}</p>
          <div className="flex gap-1.5">
            {(['accepted', 'tentative', 'declined'] as const).map((partstat) => (
              <Button
                key={partstat}
                type="button"
                size="sm"
                variant={mine.partstat === partstat ? 'default' : 'outline'}
                loading={answer.isPending && answer.variables === partstat}
                onClick={() =>
                  answer.mutate(partstat, {
                    onSuccess: (failures) => {
                      void queryClient.invalidateQueries({ queryKey: ['calendar'] })
                      if (failures.length) toast.error(t('invitation.widget.sendFailed'))
                      else toast.success(t('invitation.widget.sent'))
                    },
                  })
                }
                data-testid={`event-rsvp-${partstat}`}
              >
                {t(`invitation.widget.${partstat === 'accepted' ? 'yes' : partstat === 'tentative' ? 'maybe' : 'no'}`)}
              </Button>
            ))}
          </div>
          <Input value={note} onChange={(e) => setNote(e.target.value)} maxLength={500} placeholder={t('invitation.widget.note')} className="h-8 text-xs" />
          {answer.error ? <p className="text-xs text-destructive">{apiErrorMessage(answer.error, t('invitation.widget.sendFailed'))}</p> : null}
        </div>
      ) : null}
    </div>
  )
}
