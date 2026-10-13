import { useQueryClient } from '@tanstack/react-query'
import { ChevronDown, Code, Hourglass, Download, Forward, MoreHorizontal, Printer, Reply, ReplyAll, ScrollText, UserPlus, X } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { useContactLookup, usePinKey } from '@kutup/contacts-core/api'
import { formatFingerprint } from '@kutup/contacts-core/model'
import { useOpenedMessage, usePinnedKeys, type MailAccount, type MailMessage, type OpenedMessage } from '@kutup/mail-core/api'
import { oneTimeCode } from '@kutup/mail-core/oneTimeCode'
import type { Mailbox } from '@kutup/mail-core/mime'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from '@kutup/ui/components/dropdown-menu'
import { Skeleton } from '@kutup/ui/components/skeleton'
import { Tooltip } from '@kutup/ui/components/tooltip'
import { formatInstant, formatFileDate } from '@kutup/ui/lib/format'
import { cn } from '@kutup/ui/lib/cn'
import { AttachmentList } from './AttachmentList'
import { download } from './attachments'
import { openComposer } from './composerState'
import { onReplyCommand } from './messageCommands'
import { printDocument, printHtml } from './printMessage'
import { MailBody } from './MailBody'
import { useGroupScope, useMailboxScope } from './mailboxScope'
import { Padlock } from './Padlock'
import { Person, PersonAvatar } from './Person'
import { OneTimeCodeButton } from './OneTimeCode'
import { ReadReceipt } from './ReadReceipt'
import { ScheduledBanner } from './ScheduledBanner'
import { nameFor } from './personName'
import { useSaveContact } from './saveContactState'
import { UnsubscribeBanner } from './Unsubscribe'
import { getSession } from '@kutup/session/store'

function who(mailbox: Mailbox | null | undefined): string {
  return mailbox ? mailbox.name || mailbox.address : ''
}


/** The header block of a raw message, as it arrived (Proton's "View headers"). */
function headerBlock(raw: Uint8Array): string {
  const text = new TextDecoder().decode(raw.subarray(0, Math.min(raw.length, 512 * 1024)))
  const end = text.search(/\r?\n\r?\n/)
  return (end >= 0 ? text.slice(0, end) : text).replace(/\r\n/g, '\n')
}

type Lookup = ReturnType<typeof useContactLookup>

function Recipients({ label, list, contacts, own }: { label: string; list: Mailbox[]; contacts: Lookup; own: string }) {
  if (list.length === 0) return null
  return (
    <p className="flex min-w-0 flex-wrap items-baseline gap-x-1 text-xs text-muted-foreground">
      <span className="font-medium">{label}</span>
      {list.map((m, i) => (
        <span key={`${m.address}-${i}`} className="min-w-0 max-w-full">
          <Person mailbox={m} contact={contacts.find(m.address)} role="recipient" own={m.address.toLowerCase() === own} className="inline" />
          {i < list.length - 1 ? ',' : ''}
        </span>
      ))}
    </p>
  )
}

/**
 * The people on a message who are not in the address book, each with Save
 * to contacts (docs/plans/contacts.md: never saved without the person's
 * action). Dismissed addresses stay dismissed on this device.
 */
function NotInContacts({ people, contacts }: { people: Mailbox[]; contacts: Lookup }) {
  const { t } = useTranslation()
  const save = useSaveContact()
  const [dismissed, setDismissed] = useState(readDismissed)
  if (!contacts.ready) return null
  const seen = new Set<string>()
  const unknown = people.filter((m) => {
    const address = m.address.toLowerCase()
    if (seen.has(address) || contacts.find(address) || dismissed.has(address)) return false
    seen.add(address)
    return true
  })
  if (unknown.length === 0) return null
  return (
    <div className="space-y-1">
      {unknown.slice(0, 3).map((m) => (
        <div key={m.address} className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-muted/50 px-3 py-1.5 text-sm">
          <UserPlus className="size-4 shrink-0 text-muted-foreground" aria-hidden />
          <span className="min-w-0 flex-1 truncate">{t('read.notInContacts', { name: m.name || m.address })}</span>
          <Button variant="outline" size="sm" onClick={() => save(m)}>
            {t('read.saveToContacts')}
          </Button>
          <Tooltip label={t('read.dismiss')}>
            <Button
              variant="ghost"
              size="icon"
              className="size-7"
              aria-label={t('read.dismiss')}
              onClick={() => {
                const next = new Set(dismissed).add(m.address.toLowerCase())
                setDismissed(next)
                writeDismissed(next)
              }}
            >
              <X />
            </Button>
          </Tooltip>
        </div>
      ))}
    </div>
  )
}

const DISMISSED = 'kutup.mail.notInContactsDismissed'

/** Per account: two accounts in one browser keep their own lists. */
function dismissedKey(): string | null {
  const userId = getSession()?.userId
  return userId ? `${DISMISSED}:${userId}` : null
}

function readDismissed(): Set<string> {
  try {
    // The unkeyed list from before was shared by every account here.
    localStorage.removeItem(DISMISSED)
  } catch {
    // Storage blocked.
  }
  const key = dismissedKey()
  if (!key) return new Set()
  try {
    return new Set(JSON.parse(localStorage.getItem(key) ?? '[]') as string[])
  } catch {
    return new Set()
  }
}

function writeDismissed(addresses: Set<string>) {
  const key = dismissedKey()
  if (!key) return
  try {
    localStorage.setItem(key, JSON.stringify([...addresses].slice(-500)))
  } catch {
    // Private windows: dismissed for this page only.
  }
}

/**
 * A key the sender offers (Autocrypt, attached key): trusting it pins it to
 * their contact (docs/plans/mail.md, C3), never without the person's action.
 */
function OfferedKey({ address, name, offered }: { address: string; name: string; offered: NonNullable<OpenedMessage['offeredKey']> }) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const pin = usePinKey()
  const fingerprint = formatFingerprint(offered.fingerprint)
  return (
    <Alert variant={offered.replacesPinned ? 'warn' : 'info'} title={t(offered.replacesPinned ? 'read.replaceKeyTitle' : 'read.trustKeyTitle', { address })}>
      <p className="break-all">{t(offered.replacesPinned ? 'read.replaceKeyDescription' : 'read.trustKeyDescription', { fingerprint })}</p>
      <Button
        size="sm"
        variant="outline"
        className="mt-2"
        disabled={pin.isPending}
        onClick={() =>
          pin.mutate(
            { address, name, publicKey: offered.publicKey },
            {
              onSuccess: () => {
                toast.success(t('read.keyTrusted', { address }))
                // Opened again with the key: signatures now check against it.
                void queryClient.invalidateQueries({ queryKey: ['mail', 'content'] })
                void queryClient.invalidateQueries({ queryKey: ['mail', 'protection'] })
              },
              onError: () => toast.error(t('read.trustFailed')),
            },
          )
        }
      >
        {t('read.trustKey')}
      </Button>
    </Alert>
  )
}

/** One message of a thread: a line when folded, the whole message when open. */
export function MessageView({
  account,
  message,
  expanded,
  onToggle,
  latest = false,
  onCodeCopied,
}: {
  account: MailAccount
  message: MailMessage
  expanded: boolean
  onToggle: () => void
  /** The open conversation's newest message: R, Shift+R and Shift+F answer it. */
  latest?: boolean
  /** Its one-time code was copied (Proton moves the message to Trash). */
  onCodeCopied?: () => void
}) {
  const { t, i18n } = useTranslation()
  const contacts = useContactLookup()
  const own = account.address.toLowerCase()
  const pinned = usePinnedKeys()
  const { group } = useMailboxScope()
  const scope = useGroupScope(account)
  const opened = useOpenedMessage(account, expanded ? message : undefined, pinned, scope)
  const parsed = opened.data?.parsed
  const from = parsed?.from ?? message.from
  const draft = message.folder === 'drafts'
  // Proton's "View HTML": the body's source in place of the body.
  const [source, setSource] = useState(false)
  const [headersOpen, setHeadersOpen] = useState(false)
  const openedData = opened.data
  // Proton's one-time code in an opened message: from the subject and the body's text.
  const code = useMemo(() => {
    if (!openedData || draft || message.direction !== 'inbound' || message.folder === 'spam') return null
    const { parsed } = openedData
    const text = parsed.text ?? (parsed.html ? (new DOMParser().parseFromString(parsed.html, 'text/html').body.textContent ?? '') : '')
    return oneTimeCode({ subject: parsed.subject || message.subject, text, at: Date.parse(message.receivedAt) })
  }, [openedData, draft, message])

  useEffect(() => {
    if (!latest || draft || !openedData) return
    return onReplyCommand((kind) => openComposer({ kind, message, opened: openedData, fromGroup: group }))
  }, [latest, draft, openedData, message, group])

  function print() {
    if (!openedData) return
    const inline = new Map<string, string>()
    for (const part of openedData.parsed.attachments) {
      if (part.contentId && part.mimeType.startsWith('image/')) inline.set(part.contentId, URL.createObjectURL(new Blob([part.content as BlobPart], { type: part.mimeType })))
    }
    const when = formatInstant(message.sentAt ?? message.receivedAt, i18n.language) ?? ''
    printHtml(printDocument(openedData.parsed, { from: t('read.from'), to: t('read.to'), cc: t('read.cc'), date: t('read.date') }, when, inline))
  }

  if (!expanded) {
    return (
      <button
        type="button"
        onClick={onToggle}
        className="flex w-full items-center gap-3 rounded-lg border border-border px-4 py-3 text-left hover:bg-muted/40"
      >
        <PersonAvatar mailbox={message.from} contact={contacts.find(message.from?.address)} size={32} />
        <span className={cn('min-w-0 flex-1 truncate text-sm', !message.seen && 'font-semibold')}>{nameFor(message.from, contacts.find(message.from?.address)) || who(message.from)}</span>
        <Padlock message={message} />
        <span className="shrink-0 text-xs text-muted-foreground">{formatFileDate(message.receivedAt, i18n.language)}</span>
      </button>
    )
  }

  return (
    <article className="rounded-lg border border-border" aria-label={t('read.messageFrom', { name: who(from) })}>
      <header
        className="flex cursor-pointer items-start gap-3 border-b border-border px-4 py-3"
        onClick={(e) => {
          // Clicks on people and links open their cards; the rest folds the message. Clicks in its
          // menus and dialogs (portals, outside the header) bubble here through React too: not those.
          if (!e.currentTarget.contains(e.target as Node)) return
          if ((e.target as HTMLElement).closest('button, a') || window.getSelection()?.toString()) return
          onToggle()
        }}
      >
        <PersonAvatar mailbox={from} contact={contacts.find(from?.address)} size={48} />
        <div className="min-w-0 flex-1">
          <p className="flex min-w-0 items-baseline gap-2 text-sm">
            {from ? (
              <Person mailbox={from} contact={contacts.find(from.address)} role="sender" own={from.address.toLowerCase() === own} className="font-semibold" />
            ) : (
              <span className="font-semibold">{t('read.unknownSender')}</span>
            )}
            {from && nameFor(from, contacts.find(from.address)) !== from.address ? (
              <span className="truncate text-xs text-muted-foreground">&lt;{from.address}&gt;</span>
            ) : null}
          </p>
          <Recipients label={t('read.to')} list={parsed?.to ?? message.to} contacts={contacts} own={own} />
          <Recipients label={t('read.cc')} list={parsed?.cc ?? message.cc} contacts={contacts} own={own} />
          <Recipients label={t('read.bcc')} list={message.bcc} contacts={contacts} own={own} />
          {message.sentBy ? <p className="text-xs text-muted-foreground">{t('read.sentBy', { name: message.sentBy })}</p> : null}
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <Padlock message={message} opened={opened.data} />
          <span className="text-xs text-muted-foreground" title={formatInstant(message.receivedAt, i18n.language) ?? undefined}>
            {formatFileDate(message.receivedAt, i18n.language)}
          </span>
          {openedData ? (
            <DropdownMenu>
              <Tooltip label={t('read.more')}>
                <DropdownMenuTrigger asChild>
                  <button type="button" aria-label={t('read.more')} className="rounded p-0.5 text-muted-foreground hover:bg-muted">
                    <MoreHorizontal className="size-4" />
                  </button>
                </DropdownMenuTrigger>
              </Tooltip>
              <DropdownMenuContent align="end" className="w-56">
                <DropdownMenuItem onSelect={() => download(`${(parsed?.subject || 'message').slice(0, 80)}.eml`, 'message/rfc822', openedData.raw)}>
                  <Download />
                  {t('read.export')}
                </DropdownMenuItem>
                <DropdownMenuItem onSelect={print}>
                  <Printer />
                  {t('read.print')}
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem onSelect={() => setHeadersOpen(true)}>
                  <ScrollText />
                  {t('read.viewHeaders')}
                </DropdownMenuItem>
                <DropdownMenuItem onSelect={() => setSource((on) => !on)}>
                  <Code />
                  {source ? t('read.viewRendered') : t('read.viewHtml')}
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          ) : null}
          <Tooltip label={t('read.collapse')}>
            <button type="button" onClick={onToggle} aria-label={t('read.collapse')} aria-expanded className="rounded p-0.5 text-muted-foreground hover:bg-muted">
              <ChevronDown className="size-4" />
            </button>
          </Tooltip>
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
            {opened.data.pgp ? (
              opened.data.pgp.pinned && opened.data.signed && !opened.data.verified ? (
                <Alert variant="warn">{t('read.pgpSignatureFailed')}</Alert>
              ) : null
            ) : opened.data.signed && !opened.data.verified && message.protection === 'end_to_end' ? (
              <Alert variant="warn">{t('read.signatureFailed')}</Alert>
            ) : null}
            {opened.data.parsed.autoReply ? <Alert variant="info">{t('read.autoReply')}</Alert> : null}
            {message.expiresAt ? (
              // Proton's ExtraExpiration.
              <p role="status" className="flex items-center gap-2 rounded-md border border-border bg-muted/50 px-3 py-2 text-sm">
                <Hourglass className="size-4 text-muted-foreground" aria-hidden />
                {t('expiry.banner', { date: formatInstant(message.expiresAt, i18n.language) ?? '' })}
              </p>
            ) : null}
            {draft ? null : <UnsubscribeBanner account={account} message={message} raw={opened.data.raw} group={group} />}
            {draft || group ? null : <ReadReceipt account={account} message={message} parsed={opened.data.parsed} />}
            {code ? (
              <div className="flex flex-wrap items-center gap-2 text-sm text-muted-foreground">
                {t('oneTimeCode.found')}
                <OneTimeCodeButton code={code} size="default" onCopied={() => onCodeCopied?.()} />
              </div>
            ) : null}
            {draft ? null : (
              <NotInContacts
                people={(message.direction === 'inbound' ? (from ? [from] : []) : [...(parsed?.to ?? message.to), ...(parsed?.cc ?? message.cc)]).filter(
                  (m) => m.address.toLowerCase() !== own,
                )}
                contacts={contacts}
              />
            )}
            {opened.data.offeredKey && from ? <OfferedKey address={from.address} name={from.name} offered={opened.data.offeredKey} /> : null}
            {source ? (
              <pre aria-label={t('read.htmlSource')} className="max-h-[32rem] overflow-auto whitespace-pre-wrap break-all rounded-md border border-border bg-muted/40 p-3 font-mono text-xs">
                {opened.data.parsed.html ?? opened.data.parsed.text ?? ''}
              </pre>
            ) : (
              <MailBody parsed={opened.data.parsed} suspicious={message.folder === 'spam'} sender={message.direction === 'inbound' ? (from?.address ?? undefined) : undefined} />
            )}
            <AttachmentList list={opened.data.parsed.attachments.filter((a) => !a.inline)} subject={opened.data.parsed.subject || message.subject} />
            <div className="flex flex-wrap gap-2 pt-1">
              {message.folder === 'scheduled' && message.outboxId ? (
                <ScheduledBanner message={message} opened={opened.data} />
              ) : draft ? (
                <Button size="sm" onClick={() => openComposer({ kind: 'draft', message, opened: opened.data })}>
                  {t('read.editDraft')}
                </Button>
              ) : (
                <>
                  <Button variant="outline" size="sm" onClick={() => openComposer({ kind: 'reply', message, opened: opened.data, fromGroup: group })}>
                    <Reply />
                    {t('read.reply')}
                  </Button>
                  <Button variant="outline" size="sm" onClick={() => openComposer({ kind: 'replyAll', message, opened: opened.data, fromGroup: group })}>
                    <ReplyAll />
                    {t('read.replyAll')}
                  </Button>
                  <Button variant="outline" size="sm" onClick={() => openComposer({ kind: 'forward', message, opened: opened.data, fromGroup: group })}>
                    <Forward />
                    {t('read.forward')}
                  </Button>
                </>
              )}
            </div>
          </>
        )}
      </div>
      {headersOpen && openedData ? (
        <Dialog open onOpenChange={(open) => !open && setHeadersOpen(false)}>
          <DialogContent className="max-w-3xl">
            <DialogHeader>
              <DialogTitle>{t('read.headersTitle')}</DialogTitle>
            </DialogHeader>
            <pre className="max-h-[60vh] overflow-auto whitespace-pre-wrap break-all rounded-md border border-border bg-muted/40 p-3 font-mono text-xs">{headerBlock(openedData.raw)}</pre>
            <DialogFooter>
              <Button variant="outline" onClick={() => setHeadersOpen(false)}>
                {t('common.close')}
              </Button>
              <Button onClick={() => download(`headers - ${(parsed?.subject || 'message').slice(0, 80)}.txt`, 'text/plain', new TextEncoder().encode(headerBlock(openedData.raw)))}>
                {t('read.download')}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      ) : null}
    </article>
  )
}
