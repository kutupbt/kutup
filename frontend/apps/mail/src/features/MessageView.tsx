import { useQueryClient } from '@tanstack/react-query'
import { ChevronDown, Download, Forward, Paperclip, Reply, ReplyAll, UserPlus, X } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { useContactLookup, usePinKey } from '@kutup/contacts-core/api'
import { formatFingerprint } from '@kutup/contacts-core/model'
import { useOpenedMessage, usePinnedKeys, type MailAccount, type MailMessage, type OpenedMessage } from '@kutup/mail-core/api'
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
import { Person, PersonAvatar } from './Person'
import { nameFor } from './personName'
import { useSaveContact } from './saveContactState'

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

function readDismissed(): Set<string> {
  try {
    return new Set(JSON.parse(localStorage.getItem(DISMISSED) ?? '[]') as string[])
  } catch {
    return new Set()
  }
}

function writeDismissed(addresses: Set<string>) {
  try {
    localStorage.setItem(DISMISSED, JSON.stringify([...addresses].slice(-500)))
  } catch {
    // Private windows: dismissed for this page only.
  }
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
}: {
  account: MailAccount
  message: MailMessage
  expanded: boolean
  onToggle: () => void
}) {
  const { t, i18n } = useTranslation()
  const contacts = useContactLookup()
  const own = account.address.toLowerCase()
  const pinned = usePinnedKeys()
  const opened = useOpenedMessage(account, expanded ? message : undefined, pinned)
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
          // Clicks on people and links open their cards; the rest folds the message.
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
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <Padlock message={message} opened={opened.data} />
          <span className="text-xs text-muted-foreground" title={formatInstant(message.receivedAt, i18n.language) ?? undefined}>
            {formatFileDate(message.receivedAt, i18n.language)}
          </span>
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
            {draft ? null : (
              <NotInContacts
                people={(message.direction === 'inbound' ? (from ? [from] : []) : [...(parsed?.to ?? message.to), ...(parsed?.cc ?? message.cc)]).filter(
                  (m) => m.address.toLowerCase() !== own,
                )}
                contacts={contacts}
              />
            )}
            {opened.data.offeredKey && from ? <OfferedKey address={from.address} name={from.name} offered={opened.data.offeredKey} /> : null}
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
            </div>
          </>
        )}
      </div>
    </article>
  )
}
