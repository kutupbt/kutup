import { CalendarPlus, CalendarClock, Copy, DoorOpen, History, Link2, Loader2, Pencil, Trash2, Video, X } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { PageBody, PageHeader, Section } from '@kutup/ui/components/page'
import { apiErrorCode } from '@kutup/ui/lib/apiError'
import { useChat } from '../../app/chatStore'
import { formatDuration } from '../../lib/callText'
import { useNow } from '../../lib/useNow'
import { callLinkUrl, type OwnedCallLink } from './callLinks'
import { rememberCallName } from './callName'
import { downloadMeetingIcs } from './ics'
import { MeetingDialog } from './MeetingDialog'
import type { JoinedMeeting } from './meetingHistory'
import { isUpcoming, meetingStartText } from './meetingTime'
import { useJoinedMeetings, useMeetings, type MeetingDraft } from './useMeetings'

/**
 * Meetings: calls anyone with the link can join, with or without a Kutup
 * account. The account's own (those with a time still ahead first), and the
 * ones the account joined, on any of its devices.
 */
export function MeetingsPage() {
  const { t } = useTranslation()
  const { capabilities } = useChat()
  const now = useNow(60_000)
  const { list, create, change, remove } = useMeetings()
  const { entries: history, forget, clear } = useJoinedMeetings()
  const [dialog, setDialog] = useState<{ kind: 'schedule' } | { kind: 'edit'; meeting: OwnedCallLink } | null>(null)
  const [deleting, setDeleting] = useState<OwnedCallLink | null>(null)
  const [clearing, setClearing] = useState(false)

  if (!capabilities?.callLinks) {
    return (
      <div className="h-[calc(100svh-3.5rem)] overflow-y-auto p-4 md:p-6">
        <PageBody width="prose">
          <PageHeader title={t('chat.meetings.title')} />
          <Alert variant="info">{t('chat.meetings.unavailable')}</Alert>
        </PageBody>
      </div>
    )
  }

  const meetings = list.data ?? []
  const upcoming = meetings
    .filter((meeting) => isUpcoming(meeting.info, now))
    .sort((a, b) => (a.info.startsAtMs ?? 0) - (b.info.startsAtMs ?? 0))
  const others = meetings.filter((meeting) => !isUpcoming(meeting.info, now))

  function createFailed(error: unknown) {
    toast.error(apiErrorCode(error) === 'conflict' ? t('chat.meetings.tooMany') : t('chat.meetings.createFailed'))
  }

  async function startNow() {
    try {
      const meeting = await create.mutateAsync({ info: { title: t('chat.meetings.defaultTitle') }, waitingRoom: false })
      await copyLink(meeting.url, t('chat.meetings.startedCopied'), t('chat.meetings.started'))
    } catch (error) {
      createFailed(error)
    }
  }

  async function submit(draft: MeetingDraft) {
    if (dialog?.kind === 'edit') {
      await change.mutateAsync({ meeting: dialog.meeting, draft })
      return
    }
    try {
      await create.mutateAsync(draft)
    } catch (error) {
      createFailed(error)
      throw error
    }
  }

  return (
    <div className="h-[calc(100svh-3.5rem)] overflow-y-auto p-4 md:p-6" data-testid="chat-meetings">
      <PageBody width="prose">
        <PageHeader
          title={t('chat.meetings.title')}
          description={t('chat.meetings.description')}
          actions={
            <>
              <Button variant="outline" onClick={() => setDialog({ kind: 'schedule' })} data-testid="chat-meeting-schedule">
                <CalendarClock />
                {t('chat.meetings.schedule')}
              </Button>
              <Button onClick={() => void startNow()} disabled={create.isPending} data-testid="chat-meeting-new">
                {create.isPending ? <Loader2 className="animate-spin" /> : <Video />}
                {t('chat.meetings.new')}
              </Button>
            </>
          }
        />
        {list.isError ? <Alert variant="error">{t('chat.meetings.loadFailed')}</Alert> : null}
        {list.isPending ? (
          <p className="flex items-center gap-2 text-sm text-muted-foreground">
            <Loader2 className="size-4 animate-spin" aria-hidden />
            {t('common.loading')}
          </p>
        ) : null}

        {upcoming.length > 0 ? (
          <Section title={t('chat.meetings.upcoming')}>
            <ul className="space-y-3" data-testid="chat-meetings-upcoming">
              {upcoming.map((meeting) => (
                <MeetingRow key={meeting.roomId} meeting={meeting} onEdit={() => setDialog({ kind: 'edit', meeting })} onDelete={() => setDeleting(meeting)} />
              ))}
            </ul>
          </Section>
        ) : null}

        {list.data ? (
          <Section title={t('chat.meetings.yours')}>
            {others.length === 0 ? (
              <p className="text-sm text-muted-foreground" data-testid="chat-meetings-empty">
                {upcoming.length > 0 ? t('chat.meetings.noOthers') : t('chat.meetings.empty')}
              </p>
            ) : (
              <ul className="space-y-3" data-testid="chat-meetings-yours">
                {others.map((meeting) => (
                  <MeetingRow key={meeting.roomId} meeting={meeting} onEdit={() => setDialog({ kind: 'edit', meeting })} onDelete={() => setDeleting(meeting)} />
                ))}
              </ul>
            )}
          </Section>
        ) : null}

        <Section title={t('chat.meetings.history')} description={t('chat.meetings.historyDescription')}>
          {history.length === 0 ? (
            <p className="text-sm text-muted-foreground" data-testid="chat-meetings-history-empty">
              {t('chat.meetings.historyEmpty')}
            </p>
          ) : (
            <>
              <ul className="divide-y divide-border rounded-lg border border-border" data-testid="chat-meetings-history">
                {history.map((entry) => (
                  <HistoryRow
                    key={entry.id}
                    entry={entry}
                    onForget={() => forget.mutate(entry, { onError: () => toast.error(t('chat.meetings.historyForgetFailed')) })}
                  />
                ))}
              </ul>
              <Button variant="ghost" size="sm" className="text-muted-foreground" onClick={() => setClearing(true)} data-testid="chat-meetings-history-clear">
                <Trash2 />
                {t('chat.meetings.historyClear')}
              </Button>
            </>
          )}
        </Section>
      </PageBody>

      <MeetingDialog
        open={dialog !== null}
        onOpenChange={(next) => {
          if (!next) setDialog(null)
        }}
        initial={dialog?.kind === 'edit' ? { info: dialog.meeting.info, waitingRoom: dialog.meeting.waitingRoom } : undefined}
        scheduled={dialog?.kind === 'schedule'}
        heading={dialog?.kind === 'edit' ? t('chat.meetings.editTitle') : t('chat.meetings.scheduleTitle')}
        submitLabel={dialog?.kind === 'edit' ? t('common.save') : t('chat.meetings.schedule')}
        onSubmit={submit}
      />
      <ConfirmDestructive
        open={deleting !== null}
        onOpenChange={(next) => {
          if (!next) setDeleting(null)
        }}
        title={t('chat.meetings.deleteTitle', { title: deleting?.info.title ?? '' })}
        description={t('chat.meetings.deleteDescription')}
        submit={t('chat.meetings.delete')}
        pending={remove.isPending}
        error={remove.error}
        errorFallback={t('chat.meetings.deleteFailed')}
        onConfirm={() => {
          if (deleting) remove.mutate(deleting, { onSuccess: () => setDeleting(null) })
        }}
      />
      <ConfirmDestructive
        open={clearing}
        onOpenChange={setClearing}
        title={t('chat.meetings.historyClearTitle')}
        description={t('chat.meetings.historyClearDescription')}
        submit={t('chat.meetings.historyClear')}
        pending={clear.isPending}
        error={clear.error}
        errorFallback={t('chat.meetings.historyClearFailed')}
        onConfirm={() => clear.mutate(undefined, { onSuccess: () => setClearing(false) })}
      />
    </div>
  )
}

async function copyLink(url: string, copied: string, notCopied: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(url)
    toast.success(copied)
  } catch {
    toast.message(notCopied)
  }
}

/** Opens the meeting in a new tab, with this account's name filled in. */
function JoinLink({ url, label, testId }: { url: string; label: string; testId: string }) {
  const { snapshot, self } = useChat()
  return (
    <Button size="sm" asChild>
      <a href={url} target="_blank" rel="noreferrer" onClick={() => rememberCallName(snapshot.profile?.displayName || self?.account.username || '')} data-testid={testId}>
        <Video />
        {label}
      </a>
    </Button>
  )
}

function MeetingRow({ meeting, onEdit, onDelete }: { meeting: OwnedCallLink; onEdit: () => void; onDelete: () => void }) {
  const { t, i18n } = useTranslation()
  const { info } = meeting
  return (
    <li className="space-y-3 rounded-lg border border-border p-3" data-testid="chat-meeting" data-title={info.title}>
      <div className="min-w-0">
        <p className="flex items-center gap-2">
          <span className="truncate font-medium">{info.title}</span>
          {meeting.waitingRoom ? (
            <span className="inline-flex shrink-0 items-center gap-1 rounded-full bg-muted px-2 py-0.5 text-xs text-muted-foreground" data-testid="chat-meeting-has-waiting-room">
              <DoorOpen className="size-3" aria-hidden />
              {t('chat.meetings.waitingRoomBadge')}
            </span>
          ) : null}
        </p>
        <p className="text-sm text-muted-foreground" data-testid="chat-meeting-when">
          {info.startsAtMs !== undefined
            ? info.durationMinutes
              ? t('chat.meetings.whenWithLength', { when: meetingStartText(info.startsAtMs, i18n.language), length: t('chat.meetings.minutes', { count: info.durationMinutes }) })
              : meetingStartText(info.startsAtMs, i18n.language)
            : t('chat.meetings.anyTime')}
        </p>
      </div>
      <p className="flex items-center gap-2 truncate font-mono text-xs text-muted-foreground">
        <Link2 className="size-3.5 shrink-0" aria-hidden />
        <span className="truncate" data-testid="chat-meeting-url">
          {meeting.url}
        </span>
      </p>
      <div className="flex flex-wrap gap-2">
        <JoinLink url={meeting.url} label={t('chat.meetings.join')} testId="chat-meeting-join" />
        <Button size="sm" variant="outline" onClick={() => void copyLink(meeting.url, t('chat.meetings.copied'), t('chat.meetings.copyFailed'))} data-testid="chat-meeting-copy">
          <Copy />
          {t('chat.meetings.copy')}
        </Button>
        {info.startsAtMs !== undefined ? (
          <Button size="sm" variant="outline" onClick={() => downloadMeetingIcs(meeting)} data-testid="chat-meeting-ics">
            <CalendarPlus />
            {t('chat.meetings.addToCalendar')}
          </Button>
        ) : null}
        <Button size="sm" variant="ghost" onClick={onEdit} data-testid="chat-meeting-edit">
          <Pencil />
          {t('chat.meetings.edit')}
        </Button>
        <Button size="sm" variant="ghost" className="ml-auto text-destructive" onClick={onDelete} data-testid="chat-meeting-delete">
          <Trash2 />
          {t('chat.meetings.delete')}
        </Button>
      </div>
    </li>
  )
}

function HistoryRow({ entry, onForget }: { entry: JoinedMeeting; onForget: () => void }) {
  const { t, i18n } = useTranslation()
  return (
    <li className="flex flex-wrap items-center gap-3 px-3 py-2" data-testid="chat-meeting-history-entry" data-title={entry.title}>
      <History className="size-4 shrink-0 text-muted-foreground" aria-hidden />
      <div className="min-w-0 flex-1">
        <p className="truncate text-sm font-medium">{entry.title}</p>
        <p className="text-xs text-muted-foreground">
          {t('chat.meetings.historyWhen', {
            when: new Date(entry.joinedAtMs).toLocaleString(i18n.language, { dateStyle: 'medium', timeStyle: 'short' }),
            length: formatDuration(entry.seconds),
          })}
        </p>
      </div>
      <JoinLink url={callLinkUrl(entry.fragment)} label={t('chat.meetings.rejoin')} testId="chat-meeting-rejoin" />
      <Button size="icon" variant="ghost" onClick={onForget} aria-label={t('chat.meetings.historyForget')} title={t('chat.meetings.historyForget')}>
        <X />
      </Button>
    </li>
  )
}
