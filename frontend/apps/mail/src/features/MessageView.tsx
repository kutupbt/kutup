import { Download, Forward, Paperclip, Reply, ReplyAll, UserPlus } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { useOpenedMessage, type MailAccount, type MailMessage } from '@kutup/mail-core/api'
import { appUrl } from '@kutup/session/apps'
import type { Mailbox, ParsedAttachment } from '@kutup/mail-core/mime'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Skeleton } from '@kutup/ui/components/skeleton'
import { Tooltip } from '@kutup/ui/components/tooltip'
import { formatBytes, formatInstant, formatFileDate } from '@kutup/ui/lib/format'
import { cn } from '@kutup/ui/lib/cn'
import { openComposer } from './composerState'
import { MailBody } from './MailBody'
import { Padlock } from './Padlock'

function who(mailbox: Mailbox | null | undefined): string {
  return mailbox ? mailbox.name || mailbox.address : ''
}

function download(name: string, type: string, bytes: Uint8Array) {
  const url = URL.createObjectURL(new Blob([bytes as BlobPart], { type }))
  const link = document.createElement('a')
  link.href = url
  link.download = name
  link.click()
  setTimeout(() => URL.revokeObjectURL(url), 30_000)
}

function Recipients({ label, list }: { label: string; list: Mailbox[] }) {
  if (list.length === 0) return null
  return (
    <p className="truncate text-xs text-muted-foreground">
      <span className="font-medium">{label}</span>{' '}
      {list.map((m) => (m.name ? `${m.name} <${m.address}>` : m.address)).join(', ')}
    </p>
  )
}

function Attachments({ list }: { list: ParsedAttachment[] }) {
  const { t, i18n } = useTranslation()
  const files = list.filter((a) => !(a.inline && a.contentId))
  if (files.length === 0) return null
  return (
    <section aria-label={t('read.attachments', { count: files.length })} className="flex flex-wrap gap-2">
      {files.map((file, i) => (
        <button
          key={`${file.filename}-${i}`}
          type="button"
          onClick={() => download(file.filename || t('read.unnamed'), file.mimeType, file.content)}
          className="flex max-w-xs items-center gap-2 rounded-md border border-border px-3 py-2 text-left text-sm hover:bg-muted/60"
        >
          <Paperclip className="size-4 shrink-0 text-muted-foreground" aria-hidden />
          <span className="min-w-0">
            <span className="block truncate font-medium">{file.filename || t('read.unnamed')}</span>
            <span className="block text-xs text-muted-foreground">{formatBytes(file.content.length, i18n.language)}</span>
          </span>
          <Download className="size-4 shrink-0 text-muted-foreground" aria-hidden />
        </button>
      ))}
    </section>
  )
}

/** One message of a thread: a line when folded, the whole message when open. */
export function MessageView({
  account,
  message,
  expanded,
  onToggle,
}: {
  account: MailAccount
  message: MailMessage
  expanded: boolean
  onToggle: () => void
}) {
  const { t, i18n } = useTranslation()
  const opened = useOpenedMessage(account, expanded ? message : undefined)
  const parsed = opened.data?.parsed
  const from = parsed?.from ?? message.from
  const draft = message.folder === 'drafts'

  if (!expanded) {
    return (
      <button
        type="button"
        onClick={onToggle}
        className="flex w-full items-center gap-3 rounded-lg border border-border px-4 py-3 text-left hover:bg-muted/40"
      >
        <span className={cn('min-w-0 flex-1 truncate text-sm', !message.seen && 'font-semibold')}>{who(message.from)}</span>
        <Padlock message={message} />
        <span className="shrink-0 text-xs text-muted-foreground">{formatFileDate(message.receivedAt, i18n.language)}</span>
      </button>
    )
  }

  return (
    <article className="rounded-lg border border-border" aria-label={t('read.messageFrom', { name: who(from) })}>
      <header className="flex items-start gap-3 border-b border-border px-4 py-3">
        <button type="button" onClick={onToggle} className="min-w-0 flex-1 text-left">
          <p className="flex items-center gap-2 text-sm">
            <span className="truncate font-semibold">{who(from)}</span>
            {from?.name ? <span className="truncate text-xs text-muted-foreground">&lt;{from.address}&gt;</span> : null}
          </p>
          <Recipients label={t('read.to')} list={parsed?.to ?? message.to} />
          <Recipients label={t('read.cc')} list={parsed?.cc ?? message.cc} />
          <Recipients label={t('read.bcc')} list={message.bcc} />
        </button>
        <div className="flex shrink-0 items-center gap-2">
          <Padlock message={message} opened={opened.data} />
          <span className="text-xs text-muted-foreground" title={formatInstant(message.receivedAt, i18n.language) ?? undefined}>
            {formatFileDate(message.receivedAt, i18n.language)}
          </span>
        </div>
      </header>
      <div className="space-y-3 px-4 py-3">
        {opened.isPending ? (
          <div className="space-y-2" aria-label={t('read.opening')}>
            <Skeleton className="h-4 w-3/4" />
            <Skeleton className="h-4 w-2/3" />
            <Skeleton className="h-4 w-1/2" />
          </div>
        ) : opened.isError || !opened.data ? (
          <Alert variant="error">{t('read.cannotOpen')}</Alert>
        ) : (
          <>
            {opened.data.signed && !opened.data.verified && message.protection === 'end_to_end' ? (
              <Alert variant="warn">{t('read.signatureFailed')}</Alert>
            ) : null}
            <MailBody parsed={opened.data.parsed} />
            <Attachments list={opened.data.parsed.attachments} />
            <div className="flex flex-wrap gap-2 pt-1">
              {draft ? (
                <Button size="sm" onClick={() => openComposer({ kind: 'draft', message, opened: opened.data })}>
                  {t('read.editDraft')}
                </Button>
              ) : (
                <>
                  <Button variant="outline" size="sm" onClick={() => openComposer({ kind: 'reply', message, opened: opened.data })}>
                    <Reply />
                    {t('read.reply')}
                  </Button>
                  <Button variant="outline" size="sm" onClick={() => openComposer({ kind: 'replyAll', message, opened: opened.data })}>
                    <ReplyAll />
                    {t('read.replyAll')}
                  </Button>
                  <Button variant="outline" size="sm" onClick={() => openComposer({ kind: 'forward', message, opened: opened.data })}>
                    <Forward />
                    {t('read.forward')}
                  </Button>
                </>
              )}
              <Tooltip label={t('read.downloadOriginal')}>
                <Button
                  variant="ghost"
                  size="sm"
                  aria-label={t('read.downloadOriginal')}
                  onClick={() => download(`${(parsed?.subject || 'message').slice(0, 80)}.eml`, 'message/rfc822', opened.data.raw)}
                >
                  <Download />
                </Button>
              </Tooltip>
              {from && from.address !== account.address && message.direction === 'inbound' ? (
                <Tooltip label={t('read.addSender')}>
                  <Button
                    variant="ghost"
                    size="sm"
                    aria-label={t('read.addSender')}
                    onClick={() =>
                      window.open(appUrl('contacts', `/?add=${encodeURIComponent(from.address)}`), '_blank', 'noopener')
                    }
                  >
                    <UserPlus />
                  </Button>
                </Tooltip>
              ) : null}
            </div>
          </>
        )}
      </div>
    </article>
  )
}
