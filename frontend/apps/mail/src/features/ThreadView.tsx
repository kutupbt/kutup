import { Archive, ArrowLeft, Inbox, MailOpen, OctagonAlert, Star, Trash2, Undo2 } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { toast } from 'sonner'
import { useDeleteMessages, useThread, useUpdateMessages, type FolderId, type MailAccount, type MessageChange } from '@kutup/mail-core/api'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { Skeleton } from '@kutup/ui/components/skeleton'
import { Tooltip } from '@kutup/ui/components/tooltip'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { MessageView } from './MessageView'

function Action({ label, onClick, children, disabled }: { label: string; onClick: () => void; children: React.ReactNode; disabled?: boolean }) {
  return (
    <Tooltip label={label}>
      <Button variant="ghost" size="icon" aria-label={label} onClick={onClick} disabled={disabled}>
        {children}
      </Button>
    </Tooltip>
  )
}

/** A thread in the reading pane: its messages, oldest first, the newest and unread ones open. */
export function ThreadView({
  account,
  folder,
  threadId,
  onClose,
}: {
  account: MailAccount
  folder: FolderId
  threadId: string
  onClose: () => void
}) {
  const { t } = useTranslation()
  const thread = useThread(threadId)
  const update = useUpdateMessages()
  const remove = useDeleteMessages()
  const [confirming, setConfirming] = useState(false)
  const messages = useMemo(() => thread.data ?? [], [thread.data])
  // Trash shows what is in the Trash; elsewhere, what is not.
  const shown = useMemo(
    () => messages.filter((m) => (folder === 'trash' ? m.folder === 'trash' : m.folder !== 'trash')),
    [messages, folder],
  )
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const initialised = useRef<string | null>(null)

  useEffect(() => {
    if (shown.length === 0 || initialised.current === threadId) return
    initialised.current = threadId
    setExpanded(new Set([shown[shown.length - 1].id, ...shown.filter((m) => !m.seen).map((m) => m.id)]))
  }, [shown, threadId])

  // Opening a thread reads it.
  const unseen = shown.filter((m) => !m.seen).map((m) => m.id)
  useEffect(() => {
    if (unseen.length > 0) update.mutate({ ids: unseen, seen: true })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [unseen.join(',')])

  const ids = shown.map((m) => m.id)
  const starred = shown.some((m) => m.starred)
  const inbound = shown.some((m) => m.direction === 'inbound')
  const subject = shown[shown.length - 1]?.subject || t('list.noSubject')

  function apply(change: Omit<MessageChange, 'ids'>, done?: string, close = true) {
    update.mutate(
      { ids, ...change },
      {
        onSuccess: () => {
          if (done) toast.success(done)
          if (close) onClose()
        },
        onError: (error) => toast.error(apiErrorMessage(error, t('common.tryAgain'))),
      },
    )
  }

  /** Back where each message belongs: received mail to the Inbox, sent mail to Sent. */
  function moveHome(done: string) {
    const received = shown.filter((m) => m.direction === 'inbound').map((m) => m.id)
    const sent = shown.filter((m) => m.direction === 'outbound').map((m) => m.id)
    void Promise.all([
      received.length ? update.mutateAsync({ ids: received, folder: 'inbox' }) : null,
      sent.length ? update.mutateAsync({ ids: sent, folder: 'sent' }) : null,
    ]).then(
      () => {
        toast.success(done)
        onClose()
      },
      (error: unknown) => toast.error(apiErrorMessage(error, t('common.tryAgain'))),
    )
  }

  if (thread.isPending) {
    return (
      <div className="space-y-3 p-6">
        <Skeleton className="h-6 w-1/2" />
        <Skeleton className="h-24 w-full" />
      </div>
    )
  }
  if (thread.isError || shown.length === 0) {
    return (
      <div className="p-6">
        <Alert>{t('read.notFound')}</Alert>
      </div>
    )
  }

  return (
    <div className="flex min-h-0 flex-col">
      <div className="flex items-center gap-1 border-b border-border px-2 py-1">
        <Button variant="ghost" size="icon" className="md:hidden" asChild aria-label={t('read.back')}>
          <Link to={`/${folder}`}>
            <ArrowLeft />
          </Link>
        </Button>
        {folder === 'trash' || folder === 'spam' ? (
          <>
            <Action label={t('actions.restore')} onClick={() => moveHome(t('toasts.restored'))}>
              <Undo2 />
            </Action>
            <Action label={t('actions.deleteForever')} onClick={() => setConfirming(true)}>
              <Trash2 />
            </Action>
          </>
        ) : folder !== 'drafts' ? (
          <>
            {folder === 'archive' ? (
              <Action label={t('actions.moveToInbox')} onClick={() => moveHome(t('toasts.movedToInbox'))}>
                <Inbox />
              </Action>
            ) : (
              <Action label={t('actions.archive')} onClick={() => apply({ folder: 'archive' }, t('toasts.archived'))}>
                <Archive />
              </Action>
            )}
            {inbound ? (
              <Action label={t('actions.spam')} onClick={() => apply({ folder: 'spam' }, t('toasts.spam'))}>
                <OctagonAlert />
              </Action>
            ) : null}
            <Action label={t('actions.trash')} onClick={() => apply({ folder: 'trash' }, t('toasts.trashed'))}>
              <Trash2 />
            </Action>
          </>
        ) : (
          <Action label={t('actions.deleteDraft')} onClick={() => setConfirming(true)}>
            <Trash2 />
          </Action>
        )}
        <span className="flex-1" />
        <Action label={t('actions.markUnread')} onClick={() => apply({ seen: false }, undefined, true)}>
          <MailOpen />
        </Action>
        <Action label={starred ? t('actions.unstar') : t('actions.star')} onClick={() => apply({ starred: !starred }, undefined, false)}>
          <Star className={starred ? 'fill-status-warn text-status-warn' : undefined} />
        </Action>
      </div>
      <div className="min-h-0 flex-1 space-y-3 overflow-y-auto p-4">
        <h2 className="font-display text-xl font-semibold">{subject}</h2>
        {shown.map((message) => (
          <MessageView
            key={message.id}
            account={account}
            message={message}
            expanded={expanded.has(message.id)}
            onToggle={() =>
              setExpanded((now) => {
                const next = new Set(now)
                if (next.has(message.id)) next.delete(message.id)
                else next.add(message.id)
                return next
              })
            }
          />
        ))}
      </div>
      <ConfirmDestructive
        open={confirming}
        onOpenChange={setConfirming}
        title={t('actions.deleteForeverTitle', { count: ids.length })}
        description={t('actions.deleteForeverDescription', { count: ids.length })}
        submit={t('actions.deleteForever')}
        pending={remove.isPending}
        error={remove.error}
        errorFallback={t('common.tryAgain')}
        onConfirm={() =>
          remove.mutate(ids, {
            onSuccess: () => {
              setConfirming(false)
              toast.success(t('toasts.deleted', { count: ids.length }))
              onClose()
            },
          })
        }
      />
    </div>
  )
}
