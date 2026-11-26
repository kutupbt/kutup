import { Copy, Video, X } from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { isKutupMeeting, makeMeeting, meetingsAvailable } from '@kutup/calendar-core/meetings'
import { useRequiredSession } from '@kutup/session/store'
import { Button } from '@kutup/ui/components/button'
import { Label } from '@kutup/ui/components/label'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import type { Draft } from '../eventDraft'
import { draftMeetingInfo } from './draftMeeting'

/**
 * The editor's video meeting (docs/plans/calendar.md, E5c): "Add Kutup
 * meeting" makes a Chat meeting titled and timed as the event; once added,
 * its link, Join, Copy and Remove. Removing it from the event leaves the
 * meeting in Chat's list.
 */
export function MeetingRow({ draft, weekStart, onChange }: { draft: Draft; weekStart: number; onChange: (conference: string | null) => void }) {
  const { t } = useTranslation()
  const session = useRequiredSession()
  const [busy, setBusy] = useState(false)
  // A server without a call server hosts no meetings: nothing to add then.
  const available = useQuery({ queryKey: ['calendar', 'meetingsAvailable'], queryFn: meetingsAvailable, staleTime: 5 * 60_000 })
  const add = async () => {
    setBusy(true)
    try {
      const meeting = await makeMeeting(session, await draftMeetingInfo(draft, weekStart, t('meetings.untitled')))
      onChange(meeting.url)
    } catch (error) {
      toast.error(apiErrorMessage(error, t('meetings.addFailed')))
    } finally {
      setBusy(false)
    }
  }
  const link = draft.conference
  if (!link && available.data !== true) return null
  return (
    <div className="space-y-1.5" data-testid="event-meeting">
      <Label>{t('meetings.label')}</Label>
      {link ? (
        <div className="flex items-center gap-2 rounded-md border px-3 py-2 text-sm">
          <Video className="size-4 shrink-0 text-muted-foreground" aria-hidden />
          <span className="min-w-0 flex-1 truncate" title={link} data-testid="event-meeting-link">
            {isKutupMeeting(link) ? t('meetings.kutup') : link}
          </span>
          <Button asChild size="sm" variant="outline">
            <a href={link} target="_blank" rel="noopener noreferrer" data-testid="event-meeting-join">
              {t('meetings.join')}
            </a>
          </Button>
          <Button
            type="button"
            size="icon"
            variant="ghost"
            aria-label={t('meetings.copy')}
            onClick={() =>
              void navigator.clipboard.writeText(link).then(
                () => toast.success(t('meetings.copied')),
                () => toast.error(t('meetings.copyFailed')),
              )
            }
          >
            <Copy className="size-4" aria-hidden />
          </Button>
          <Button type="button" size="icon" variant="ghost" aria-label={t('meetings.remove')} onClick={() => onChange(null)} data-testid="event-meeting-remove">
            <X className="size-4" aria-hidden />
          </Button>
        </div>
      ) : (
        <Button type="button" variant="outline" size="sm" loading={busy} onClick={() => void add()} data-testid="event-meeting-add">
          <Video className="size-4" aria-hidden />
          {t('meetings.add')}
        </Button>
      )}
    </div>
  )
}
