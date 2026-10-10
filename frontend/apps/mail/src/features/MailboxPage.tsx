import { Archive, Inbox as InboxIcon, Mail, MailOpen, OctagonAlert, Paperclip, Star, Trash2 } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link, Navigate, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { toast } from 'sonner'
import {
  FOLDERS,
  NoAddressKey,
  useDeleteMessages,
  useFolder,
  useMailAccount,
  useUpdateMessages,
  type FolderId,
  type MailMessage,
  type MessageChange,
} from '@kutup/mail-core/api'
import { appUrl } from '@kutup/session/apps'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { Skeleton } from '@kutup/ui/components/skeleton'
import { EmptyState } from '@kutup/ui/components/states'
import { Tooltip } from '@kutup/ui/components/tooltip'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { cn } from '@kutup/ui/lib/cn'
import { formatFileDate, formatInstant } from '@kutup/ui/lib/format'
import { openComposer } from './composerState'
import { Padlock } from './Padlock'
import { ThreadView } from './ThreadView'

const KNOWN = new Set<string>([...FOLDERS, 'all'])

/** Who a row names: the sender for received mail, the recipients for sent mail and drafts. */
function correspondent(message: MailMessage, t: (key: string) => string): string {
  if (message.direction === 'outbound') {
    const names = [...message.to, ...message.cc].map((m) => m.name || m.address)
    return names.length ? `${t('list.to')} ${names.join(', ')}` : t('list.noRecipients')
  }
  return message.from ? message.from.name || message.from.address : t('list.unknownSender')
}

function ToolbarButton({ label, onClick, children }: { label: string; onClick: () => void; children: React.ReactNode }) {
  return (
    <Tooltip label={label}>
      <Button variant="ghost" size="icon" aria-label={label} onClick={onClick}>
        {children}
      </Button>
    </Tooltip>
  )
}

/** A folder: the list beside the open thread, as Proton's column layout. */
export function MailboxPage() {
  const { t, i18n } = useTranslation()
  const { folder: folderParam = 'inbox', threadId } = useParams()
  const [params] = useSearchParams()
  const q = params.get('q') ?? ''
  const navigate = useNavigate()
  const account = useMailAccount()
  const folder = (KNOWN.has(folderParam) ? folderParam : 'inbox') as FolderId
  const list = useFolder(folder, q)
  const update = useUpdateMessages()
  const remove = useDeleteMessages()
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [confirming, setConfirming] = useState(false)
  const messages = useMemo(() => list.data?.pages.flatMap((page) => page.messages) ?? [], [list.data])
  const chosen = messages.filter((m) => selected.has(m.id))
  const search = q ? `?q=${encodeURIComponent(q)}` : ''

  useEffect(() => setSelected(new Set()), [folder, q])

  // Proton's list shortcuts (`packages/shared/lib/shortcuts/mail.ts`).
  useEffect(() => {
    function onKey(event: KeyboardEvent) {
      const target = event.target as HTMLElement | null
      if (event.metaKey || event.ctrlKey || event.altKey) return
      if (target && (target.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName))) return
      if (document.querySelector('[role="dialog"]')) return
      const index = messages.findIndex((m) => m.threadId === threadId)
      if (event.key === 'n') {
        event.preventDefault()
        openComposer({ kind: 'new' })
      } else if (event.key === '/') {
        event.preventDefault()
        document.querySelector<HTMLInputElement>('[data-mail-search]')?.focus()
      } else if ((event.key === 'j' || event.key === 'ArrowDown') && messages.length) {
        event.preventDefault()
        const next = messages[Math.min(index + 1, messages.length - 1)]
        void navigate(`/${folder}/${next.threadId}${search}`)
      } else if ((event.key === 'k' || event.key === 'ArrowUp') && messages.length) {
        event.preventDefault()
        const previous = messages[Math.max(index - 1, 0)]
        void navigate(`/${folder}/${previous.threadId}${search}`)
      } else if (event.key === 'Escape' && threadId) {
        void navigate(`/${folder}${search}`)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [messages, threadId, folder, search, navigate])

  if (!KNOWN.has(folderParam)) return <Navigate to="/inbox" replace />

  if (account.isError) {
    return (
      <div className="p-6">
        {account.error instanceof NoAddressKey ? (
          <Alert title={t('account.noKeyTitle')}>
            {t('account.noKey')}{' '}
            <a className="underline" href={appUrl('account', '/settings/keys')}>
              {t('account.openAccount')}
            </a>
          </Alert>
        ) : (
          <Alert variant="error">{apiErrorMessage(account.error, t('common.tryAgain'))}</Alert>
        )}
      </div>
    )
  }

  function apply(change: Omit<MessageChange, 'ids'>, done?: string) {
    const ids = chosen.map((m) => m.id)
    update.mutate(
      { ids, ...change },
      {
        onSuccess: () => {
          setSelected(new Set())
          if (done) toast.success(done)
        },
        onError: (error) => toast.error(apiErrorMessage(error, t('common.tryAgain'))),
      },
    )
  }

  const listPane = (
    <section
      aria-label={t(`folders.${folder}`)}
      className={cn('flex min-h-0 flex-1 flex-col border-border md:w-[26rem] md:flex-none md:shrink-0 md:border-r', threadId && 'hidden md:flex')}
    >
      <div className="flex min-h-12 items-center gap-1 border-b border-border px-2">
        <Checkbox
          className="mx-2"
          aria-label={t('list.selectAll')}
          checked={messages.length > 0 && chosen.length === messages.length ? true : chosen.length > 0 ? 'indeterminate' : false}
          onCheckedChange={(on) => setSelected(on === true ? new Set(messages.map((m) => m.id)) : new Set())}
        />
        {chosen.length > 0 ? (
          <>
            <span className="px-1 text-sm">{t('list.selected', { count: chosen.length })}</span>
            <span className="flex-1" />
            <ToolbarButton label={t('actions.markRead')} onClick={() => apply({ seen: true })}>
              <MailOpen />
            </ToolbarButton>
            <ToolbarButton label={t('actions.markUnread')} onClick={() => apply({ seen: false })}>
              <Mail />
            </ToolbarButton>
            {folder === 'trash' || folder === 'spam' || folder === 'drafts' ? (
              <ToolbarButton label={t('actions.deleteForever')} onClick={() => setConfirming(true)}>
                <Trash2 />
              </ToolbarButton>
            ) : (
              <>
                <ToolbarButton label={t('actions.archive')} onClick={() => apply({ folder: 'archive' }, t('toasts.archived'))}>
                  <Archive />
                </ToolbarButton>
                <ToolbarButton label={t('actions.trash')} onClick={() => apply({ folder: 'trash' }, t('toasts.trashed'))}>
                  <Trash2 />
                </ToolbarButton>
              </>
            )}
            {folder === 'spam' ? (
              <ToolbarButton label={t('actions.notSpam')} onClick={() => apply({ folder: 'inbox' }, t('toasts.movedToInbox'))}>
                <InboxIcon />
              </ToolbarButton>
            ) : folder !== 'trash' && folder !== 'drafts' && folder !== 'sent' ? (
              <ToolbarButton label={t('actions.spam')} onClick={() => apply({ folder: 'spam' }, t('toasts.spam'))}>
                <OctagonAlert />
              </ToolbarButton>
            ) : null}
          </>
        ) : (
          <h1 className="truncate px-1 font-display text-base font-semibold">
            {q ? t('list.searchResults', { q }) : t(`folders.${folder}`)}
          </h1>
        )}
      </div>
      {list.isPending || account.isPending ? (
        <div className="space-y-2 p-3">
          {[0, 1, 2, 3, 4].map((i) => (
            <Skeleton key={i} className="h-14 w-full" />
          ))}
        </div>
      ) : list.isError ? (
        <Alert variant="error" className="m-3">
          {apiErrorMessage(list.error, t('common.tryAgain'))}
        </Alert>
      ) : messages.length === 0 ? (
        <div className="p-3">
          <EmptyState title={q ? t('list.noMatches') : t(`empty.${folder}`)} description={q ? t('list.noMatchesHint') : t(`emptyHint.${folder}`)} />
        </div>
      ) : (
        <ul className="min-h-0 flex-1 overflow-y-auto">
          {messages.map((message) => {
            const open = message.threadId === threadId
            return (
              <li key={message.id} className={cn('group border-b border-border/60', open && 'bg-accent', !message.seen && !open && 'bg-primary/5')}>
                <div className="flex items-start gap-2 px-2 py-2">
                  <Checkbox
                    className="m-2"
                    checked={selected.has(message.id)}
                    onCheckedChange={(on) =>
                      setSelected((now) => {
                        const next = new Set(now)
                        if (on === true) next.add(message.id)
                        else next.delete(message.id)
                        return next
                      })
                    }
                    aria-label={t('list.select', { subject: message.subject || t('list.noSubject') })}
                  />
                  <Link to={`/${folder}/${message.threadId}${search}`} className="min-w-0 flex-1 py-1" aria-current={open ? 'true' : undefined}>
                    <span className="flex items-center gap-2">
                      <span className={cn('min-w-0 flex-1 truncate text-sm', !message.seen ? 'font-semibold' : 'text-muted-foreground')}>
                        {correspondent(message, t)}
                      </span>
                      {message.attachmentCount > 0 ? <Paperclip className="size-3.5 text-muted-foreground" aria-label={t('list.hasAttachments')} /> : null}
                      <span className="shrink-0 text-xs text-muted-foreground" title={formatInstant(message.receivedAt, i18n.language) ?? undefined}>
                        {formatFileDate(message.receivedAt, i18n.language)}
                      </span>
                    </span>
                    <span className="mt-0.5 flex items-center gap-2">
                      <Padlock message={message} className="[&_svg]:size-3.5" />
                      <span className={cn('min-w-0 flex-1 truncate text-sm', !message.seen && 'font-medium')}>
                        {message.subject || t('list.noSubject')}
                      </span>
                      {folder === 'all' || folder === 'starred' ? (
                        <span className="shrink-0 rounded bg-muted px-1.5 text-[11px] text-muted-foreground">{t(`folders.${message.folder}`)}</span>
                      ) : null}
                    </span>
                  </Link>
                  <button
                    type="button"
                    className={cn('m-1 rounded p-1 hover:bg-muted', !message.starred && 'opacity-0 group-hover:opacity-100 focus-visible:opacity-100')}
                    aria-label={message.starred ? t('actions.unstar') : t('actions.star')}
                    aria-pressed={message.starred}
                    onClick={() => update.mutate({ ids: [message.id], starred: !message.starred })}
                  >
                    <Star className={cn('size-4', message.starred ? 'fill-status-warn text-status-warn' : 'text-muted-foreground')} />
                  </button>
                </div>
              </li>
            )
          })}
          {list.hasNextPage ? (
            <li className="p-3 text-center">
              <Button variant="outline" size="sm" onClick={() => void list.fetchNextPage()} disabled={list.isFetchingNextPage}>
                {t('list.more')}
              </Button>
            </li>
          ) : null}
        </ul>
      )}
    </section>
  )

  return (
    <div className="flex h-full min-h-0">
      {listPane}
      <div className={cn('min-h-0 min-w-0 flex-1 overflow-hidden', !threadId && 'hidden md:block')}>
        {threadId && account.data ? (
          <ThreadView account={account.data} folder={folder} threadId={threadId} onClose={() => void navigate(`/${folder}${search}`)} />
        ) : (
          <div className="flex h-full flex-col items-center justify-center gap-3 p-6 text-center text-muted-foreground">
            <Mail className="size-10" aria-hidden />
            <p className="text-sm">{t('read.pick')}</p>
          </div>
        )}
      </div>
      <ConfirmDestructive
        open={confirming}
        onOpenChange={setConfirming}
        title={t('actions.deleteForeverTitle', { count: chosen.length })}
        description={t('actions.deleteForeverDescription', { count: chosen.length })}
        submit={t('actions.deleteForever')}
        pending={remove.isPending}
        error={remove.error}
        errorFallback={t('common.tryAgain')}
        onConfirm={() =>
          remove.mutate(
            chosen.map((m) => m.id),
            {
              onSuccess: () => {
                toast.success(t('toasts.deleted', { count: chosen.length }))
                setSelected(new Set())
                setConfirming(false)
              },
            },
          )
        }
      />
    </div>
  )
}
