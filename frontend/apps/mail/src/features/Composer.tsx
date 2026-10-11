import Placeholder from '@tiptap/extension-placeholder'
import { EditorContent, useEditor, type Editor } from '@tiptap/react'
import StarterKit from '@tiptap/starter-kit'
import { Bold, Italic, List, ListOrdered, Loader2, LockKeyhole, LockKeyholeOpen, Maximize2, Minimize2, Paperclip, Quote, Send, Signature, Trash2, X } from 'lucide-react'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import {
  addDraftAttachment,
  draftAttachmentPart,
  emptyDraft,
  removeDraftAttachment,
  saveDraft,
  sendDraft,
  UnknownRecipient,
  useMailAccount,
  useMailRefresh,
  useMailSettings,
  usePinnedKeys,
  useSendingStatus,
  type Draft,
  type MailAccount,
  type SendAs,
} from '@kutup/mail-core/api'
import { GroupNotAllowed } from '@kutup/mail-core/keys'
import { armorMailPublicKey } from '@kutup/crypto'
import { attachmentPart, describePart, type Mailbox, type ParsedMessage } from '@kutup/mail-core/mime'
import { KeyLookupFailed, PinnedKeyUnusable } from '@kutup/mail-core/protection'
import { groupKeys, heldKeys, useMyGroups, type MailGroup } from '@kutup/mail-core/groups'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@kutup/ui/components/select'
import api from '@kutup/session/client'
import { Button } from '@kutup/ui/components/button'
import { Input } from '@kutup/ui/components/input'
import { Tooltip } from '@kutup/ui/components/tooltip'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { cn } from '@kutup/ui/lib/cn'
import { formatBytes, formatInstant } from '@kutup/ui/lib/format'
import { closeComposer, useComposer, type ComposerTarget } from './composerState'
import { RecipientField } from './RecipientField'
import { isAddress } from './recipients'

/** Proton's limit for one message, attachments included. */
const MAX_ATTACHMENTS_BYTES = 25 * 1024 * 1024
/** Proton's autosave pause (`useAutoSave`, 2 s debounce). */
const AUTOSAVE_MS = 2000

interface Attachment {
  key: string
  /** The server's id once uploaded with the draft. */
  id?: string
  name: string
  size: number
  /** The MIME part, when this browser has it. */
  part?: Uint8Array
  status: 'uploading' | 'ready' | 'failed'
  /** Your public key, attached by the setting (Proton's Attach public key): sent from here, never uploaded with the draft. */
  publicKey?: true
}

function escapeHtml(text: string): string {
  return text.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]!)
}

/** The quoted text of a message, as paragraphs inside a blockquote (plain text: nothing active can come along). */
function quoted(parsed: ParsedMessage): string {
  const text = parsed.text ?? new DOMParser().parseFromString(parsed.html ?? '', 'text/html').body.textContent ?? ''
  return text
    .split(/\r?\n/)
    .map((line) => `<p>${escapeHtml(line) || '<br>'}</p>`)
    .join('')
}

function prefixed(prefix: string, subject: string): string {
  return new RegExp(`^${prefix}:`, 'i').test(subject.trim()) ? subject : `${prefix}: ${subject}`
}

function without(list: Mailbox[], addresses: Set<string>): Mailbox[] {
  const seen = new Set(addresses)
  return list.filter((m) => {
    if (seen.has(m.address)) return false
    seen.add(m.address)
    return true
  })
}

interface Initial {
  draft: Draft
  html: string
  attachments: Attachment[]
}

/**
 * Where the signature goes, as Proton places it (`messageSignature.ts`): two
 * empty lines to write on, then the signature; in a reply or forward, above
 * the quoted message. Nothing without a signature.
 */
function withSignature(account: MailAccount, rest = ''): string {
  return account.signature ? `<p></p><p></p>${account.signature}${rest ? `<p></p>${rest}` : ''}` : `<p></p>${rest}`
}

/** The composer's starting fields for what it was opened for. */
function initial(account: MailAccount, target: ComposerTarget, t: (key: string, options?: Record<string, unknown>) => string, locale: string): Initial {
  if (target.kind === 'new') {
    return {
      draft: emptyDraft(account, { to: target.to ? [{ address: target.to.toLowerCase(), name: '' }] : [] }),
      html: account.signature ? withSignature(account) : '',
      attachments: [],
    }
  }
  const { message, opened } = target
  const parsed = opened.parsed
  if (target.kind === 'draft') {
    return {
      draft: {
        id: message.id,
        to: message.to,
        cc: message.cc,
        bcc: message.bcc,
        subject: message.subject,
        html: parsed.html ?? '',
        text: parsed.text ?? '',
        messageId: message.messageId ?? emptyDraft(account).messageId,
        inReplyTo: message.inReplyTo,
        references: message.references,
        threadId: message.threadId,
        attachments: [],
      },
      html: parsed.html ?? (parsed.text ? quoted({ ...parsed, html: null }) : ''),
      attachments: [],
    }
  }
  const from = parsed.from ?? message.from
  const when = formatInstant(parsed.date?.toISOString() ?? message.receivedAt, locale) ?? ''
  const name = from ? from.name || from.address : ''
  if (target.kind === 'forward') {
    const header = [
      `<p>${escapeHtml(t('compose.forwardedHeader'))}</p>`,
      `<p>${escapeHtml(t('compose.forwardedFrom', { from: from ? `${name} <${from.address}>` : '' }))}</p>`,
      `<p>${escapeHtml(t('compose.forwardedDate', { date: when }))}</p>`,
      `<p>${escapeHtml(t('compose.forwardedSubject', { subject: parsed.subject }))}</p>`,
    ].join('')
    const files = parsed.attachments.filter((a) => !(a.inline && a.contentId))
    return {
      draft: emptyDraft(account, { subject: prefixed('Fwd', parsed.subject || message.subject) }),
      html: withSignature(account, `${header}<blockquote>${quoted(parsed)}</blockquote>`),
      attachments: files.map((file, i) => ({
        key: `fwd-${i}`,
        name: file.filename || t('read.unnamed'),
        size: file.content.length,
        part: attachmentPart({ name: file.filename || 'attachment', type: file.mimeType, bytes: file.content }),
        status: 'uploading' as const,
      })),
    }
  }
  const self = new Set([account.address])
  const replyTo = parsed.replyTo.length ? parsed.replyTo : from ? [from] : []
  const sentByMe = message.direction === 'outbound'
  const to = sentByMe ? without(parsed.to.length ? parsed.to : message.to, self) : without(replyTo, self)
  const cc =
    target.kind === 'replyAll' ? without([...(sentByMe ? [] : parsed.to), ...parsed.cc], new Set([...self, ...to.map((m) => m.address)])) : []
  const parentId = parsed.messageId ?? message.messageId
  return {
    draft: emptyDraft(account, {
      to,
      cc,
      subject: prefixed('Re', parsed.subject || message.subject),
      inReplyTo: parentId,
      references: [...(parsed.references.length ? parsed.references : message.references), ...(parentId ? [parentId] : [])].slice(-50),
      threadId: message.threadId,
    }),
    html: withSignature(account, `<p>${escapeHtml(t('compose.wrote', { date: when, name }))}</p><blockquote>${quoted(parsed)}</blockquote>`),
    attachments: [],
  }
}

function ToolbarToggle({ editor, label, active, onClick, children }: { editor: Editor | null; label: string; active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <Tooltip label={label}>
      <Button type="button" variant={active ? 'secondary' : 'ghost'} size="icon" className="size-8" aria-label={label} aria-pressed={active} disabled={!editor} onClick={onClick}>
        {children}
      </Button>
    </Tooltip>
  )
}

/** Writing as a shared mailbox: its primary key and the writer's share of it. */
class NoGroupShare extends Error {
  constructor() {
    super('you hold no share of this mailbox\'s current key')
  }
}

async function sendAs(account: MailAccount, group: MailGroup): Promise<SendAs> {
  const rows = await groupKeys(group.id)
  const primary = rows.find((row) => row.primary)
  const key = primary ? heldKeys([primary], [account.key, ...account.olderKeys])[0] : undefined
  if (!primary || !key) throw new NoGroupShare()
  return { groupId: group.id, address: group.address, name: group.displayName, publicKey: primary.publicKey, key }
}

/** The docked composer, as Proton's: one at a time, minimised or maximised. */
export function Composer() {
  const { target, generation } = useComposer()
  const account = useMailAccount()
  if (!target || !account.data) return null
  return <ComposerPanel key={generation} account={account.data} target={target} />
}

function ComposerPanel({ account, target }: { account: MailAccount; target: ComposerTarget }) {
  const { t, i18n } = useTranslation()
  const refresh = useMailRefresh()
  const sendingStatus = useSendingStatus()
  const pinned = usePinnedKeys()
  const mailSettings = useMailSettings()
  // Shared mailboxes this account may write as (docs/plans/mail-groups.md).
  const groups = useMyGroups()
  const sendAsChoices = (groups.data ?? []).filter((group) => group.kind === 'shared' && group.myCanSendAs)
  const [fromGroup, setFromGroup] = useState<string | undefined>(target.fromGroup)
  const from = sendAsChoices.find((group) => group.id === fromGroup)
  const start = useMemo(() => initial(account, target, t, i18n.language), [account, target, t, i18n.language])
  const [to, setTo] = useState(start.draft.to)
  const [cc, setCc] = useState(start.draft.cc)
  const [bcc, setBcc] = useState(start.draft.bcc)
  // Before the server's mail setup is checked, only Kutup addresses are reachable.
  const outsideRecipients = [...to, ...cc, ...bcc].filter((m) => isAddress(m.address) && !m.address.toLowerCase().endsWith(`@${account.domain}`))
  const outsideBlocked = sendingStatus.data?.outsideAllowed === false && outsideRecipients.length > 0
  const [showCopies, setShowCopies] = useState(start.draft.cc.length > 0 || start.draft.bcc.length > 0)
  const [subject, setSubject] = useState(start.draft.subject)
  const [attachments, setAttachments] = useState<Attachment[]>(start.attachments)
  const [minimised, setMinimised] = useState(false)
  // Opens as the Appearance setting says (Proton's ComposerMode); the mailbox has loaded the settings.
  const [maximised, setMaximised] = useState(() => mailSettings.data?.composerMode === 'maximized')
  const [status, setStatus] = useState<'idle' | 'saving' | 'saved' | 'failed'>('idle')
  const [sending, setSending] = useState(false)
  // Encrypt and Sign for this message (docs/plans/mail-encrypt-sign.md).
  const [encrypt, setEncrypt] = useState(true)
  // Sign starts on for Kutup recipients; for outside ones from "Sign outside
  // mail" or a contact's Sign flag, as Proton's "Sign external messages".
  // Pressing the button decides it for this message.
  const [signChoice, setSignChoice] = useState<boolean | undefined>()
  const signOutside = mailSettings.data?.signOutside ?? true
  const sign = signChoice ?? (signOutside || outsideRecipients.length === 0 || outsideRecipients.some((m) => pinned?.(m.address)?.sign))
  const kutupRecipients = [...to, ...cc, ...bcc].some((m) => isAddress(m.address) && m.address.toLowerCase().endsWith(`@${account.domain}`))
  const [revision, setRevision] = useState(0)
  const draftId = useRef<string | undefined>(start.draft.id)
  const saving = useRef<Promise<void>>(Promise.resolve())
  const closed = useRef(false)
  const files = useRef<HTMLInputElement>(null)

  const editor = useEditor({
    extensions: [
      StarterKit.configure({ link: { openOnClick: false, autolink: true, defaultProtocol: 'https' } }),
      Placeholder.configure({ placeholder: t('compose.bodyPlaceholder') }),
    ],
    content: start.html,
    autofocus: target.kind === 'new' && !start.draft.to.length ? false : 'start',
    editorProps: { attributes: { role: 'textbox', 'aria-multiline': 'true', 'aria-label': t('compose.body'), class: 'mail-editor min-h-48 px-3 py-2 text-sm focus:outline-none' } },
    onUpdate: () => setRevision((r) => r + 1),
  })

  const current = useCallback(
    (): Draft => ({
      ...start.draft,
      id: draftId.current,
      to,
      cc,
      bcc,
      subject,
      html: editor?.getHTML() ?? '',
      text: editor?.getText({ blockSeparator: '\n' }) ?? '',
      attachments: attachments.filter((a) => a.id).map((a) => ({ id: a.id!, name: a.name, type: '', size: a.size })),
    }),
    [start.draft, to, cc, bcc, subject, editor, attachments],
  )

  /** Saves the draft now, after any save still running; resolves to its id. */
  const save = useCallback((): Promise<string | undefined> => {
    const run = saving.current.then(async () => {
      if (closed.current) return
      setStatus('saving')
      try {
        const saved = await saveDraft(account, current())
        draftId.current = saved.id
        setStatus('saved')
        refresh()
      } catch {
        setStatus('failed')
      }
    })
    saving.current = run
    return run.then(() => draftId.current)
  }, [account, current, refresh])

  // Autosave a moment after the last change.
  const first = useRef(true)
  useEffect(() => {
    if (first.current) {
      first.current = false
      return
    }
    const timer = setTimeout(() => void save(), AUTOSAVE_MS)
    return () => clearTimeout(timer)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [to, cc, bcc, subject, revision])

  // A saved draft's attachments: the parts are fetched to show their names.
  useEffect(() => {
    if (target.kind !== 'draft' || !draftId.current) return
    const id = draftId.current
    void api
      .get<{ id: string; size: number }[]>(`/mail/drafts/${id}/attachments`)
      .then(async ({ data }) => {
        const loaded = await Promise.all(
          data.map(async (row) => {
            const part = await draftAttachmentPart(account, id, row.id)
            const info = describePart(part)
            return { key: row.id, id: row.id, name: info.name, size: info.size, part, status: 'ready' as const }
          }),
        )
        setAttachments(loaded)
      })
      .catch(() => toast.error(t('compose.attachmentsFailed')))
  }, [account, target.kind, t])

  const upload = useCallback(
    async (attachment: Attachment) => {
      const id = await save()
      if (!id || !attachment.part) throw new Error('no draft')
      const serverId = await addDraftAttachment(account, id, attachment.part)
      setAttachments((list) => list.map((a) => (a.key === attachment.key ? { ...a, id: serverId, status: 'ready' } : a)))
    },
    [account, save],
  )

  // Attach public key (Proton's): a new message, reply or forward starts with
  // your key attached, `publickey - <address> - 0x<fingerprint>.asc`, which
  // you may remove.
  const keyAttached = useRef(false)
  useEffect(() => {
    if (keyAttached.current || target.kind === 'draft' || !mailSettings.data?.attachPublicKey) return
    keyAttached.current = true
    void armorMailPublicKey(account.publicKey).then(
      (armored) => {
        const name = `publickey - ${account.address} - 0x${account.key.fingerprint.slice(0, 8).toUpperCase()}.asc`
        const bytes = new TextEncoder().encode(armored)
        const attachment: Attachment = {
          key: crypto.randomUUID(),
          name,
          size: bytes.length,
          part: attachmentPart({ name, type: 'application/pgp-keys', bytes }),
          status: 'ready',
          publicKey: true,
        }
        setAttachments((now) => [attachment, ...now])
      },
      () => toast.error(t('compose.publicKeyFailed')),
    )
  }, [account, mailSettings.data?.attachPublicKey, t, target.kind])

  // Forwarded files go up with the draft once.
  const forwarded = useRef(false)
  useEffect(() => {
    if (forwarded.current || target.kind !== 'forward') return
    forwarded.current = true
    for (const attachment of start.attachments) {
      void upload(attachment).catch(() =>
        setAttachments((list) => list.map((a) => (a.key === attachment.key ? { ...a, status: 'failed' } : a))),
      )
    }
  }, [start.attachments, target.kind, upload])

  async function addFiles(list: FileList | null) {
    if (!list?.length) return
    const used = attachments.reduce((n, a) => n + a.size, 0)
    const incoming = [...list]
    if (used + incoming.reduce((n, f) => n + f.size, 0) > MAX_ATTACHMENTS_BYTES) {
      toast.error(t('compose.tooLarge'))
      return
    }
    for (const file of incoming) {
      const attachment: Attachment = {
        key: crypto.randomUUID(),
        name: file.name,
        size: file.size,
        part: attachmentPart({ name: file.name, type: file.type, bytes: new Uint8Array(await file.arrayBuffer()) }),
        status: 'uploading',
      }
      setAttachments((now) => [...now, attachment])
      void upload(attachment).catch(() =>
        setAttachments((now) => now.map((a) => (a.key === attachment.key ? { ...a, status: 'failed' } : a))),
      )
    }
  }

  async function removeAttachment(attachment: Attachment) {
    setAttachments((now) => now.filter((a) => a.key !== attachment.key))
    if (attachment.id && draftId.current) await removeDraftAttachment(draftId.current, attachment.id).catch(() => undefined)
  }

  const hasContent = to.length + cc.length + bcc.length > 0 || subject.trim() !== '' || !!editor?.getText().trim() || attachments.some((a) => !a.publicKey)

  async function close() {
    if (hasContent && !sending) {
      await save()
      toast(t('compose.draftSaved'))
    }
    closed.current = true
    closeComposer()
  }

  async function discard() {
    closed.current = true
    await saving.current
    if (draftId.current) {
      await api.post('/mail/messages/delete', { ids: [draftId.current] }).catch(() => undefined)
      refresh()
    }
    closeComposer()
  }

  async function send() {
    const everyone = [...to, ...cc, ...bcc]
    if (everyone.length === 0) {
      toast.error(t('compose.noRecipients'))
      return
    }
    const invalid = everyone.find((m) => !isAddress(m.address))
    if (invalid) {
      toast.error(t('compose.invalidRecipient', { address: invalid.address }))
      return
    }
    if (outsideBlocked) {
      toast.error(t('compose.outsideOff'))
      return
    }
    if (attachments.some((a) => a.status !== 'ready')) {
      toast.error(t('compose.attachmentsPending'))
      return
    }
    setSending(true)
    try {
      await saving.current
      closed.current = true
      const parts = await Promise.all(
        attachments.map((a) => (a.part ? Promise.resolve(a.part) : draftAttachmentPart(account, draftId.current!, a.id!))),
      )
      const results = await sendDraft(account, current(), parts, pinned ?? (() => undefined), from ? await sendAs(account, from) : undefined, { encrypt, sign, pgpScheme: mailSettings.data?.pgpScheme })
      const full = results.filter((r) => r.status === 'full').map((r) => r.address)
      const failed = results.filter((r) => r.status === 'failed').map((r) => r.address)
      if (full.length) toast.warning(t('compose.notDeliveredFull', { addresses: full.join(', ') }))
      if (failed.length) toast.warning(t('compose.notSentRefused', { addresses: failed.join(', ') }))
      if (!full.length && !failed.length) toast.success(t('compose.sent'))
      refresh()
      closeComposer()
    } catch (error) {
      closed.current = false
      setSending(false)
      if (error instanceof UnknownRecipient) toast.error(t('compose.unknownRecipient', { address: error.address }))
      else if (error instanceof NoGroupShare) toast.error(t('compose.noGroupShare'))
      else if (error instanceof GroupNotAllowed) toast.error(t('compose.groupNotAllowed', { address: error.address }))
      else if (error instanceof PinnedKeyUnusable) toast.error(t('compose.pinnedKeyUnusable', { address: error.address }))
      else if (error instanceof KeyLookupFailed) toast.error(t('compose.keyLookupFailed', { address: error.address }))
      else {
        const data = (error as { response?: { data?: { code?: string; newAccount?: boolean; perDay?: number } } }).response?.data
        toast.error(
          data?.code === 'notAllowed'
            ? t('compose.groupNotAllowed', { address: (data as { address?: string }).address ?? '' })
            : data?.code === 'outsideSendingOff'
            ? t('compose.outsideOff')
            : data?.code === 'sendingPaused'
            ? t('compose.sendingPaused')
            : data?.code === 'sendLimit'
              ? data.newAccount
                ? t('compose.sendLimitNew', { perDay: data.perDay })
                : t('compose.sendLimit')
              : apiErrorMessage(error, t('compose.sendFailed')),
        )
      }
    }
  }

  const title = subject.trim() || t('compose.newMessage')
  return (
    <>
    {maximised && !minimised ? (
      // Maximised, the composer is the thing to look at (Gmail's full-screen
      // compose): the app behind it dims, and a click there docks it again.
      <div aria-hidden className="fixed inset-0 z-40 hidden bg-foreground/40 backdrop-blur-[1px] md:block" onClick={() => setMaximised(false)} />
    ) : null}
    <section
      role="dialog"
      aria-label={title}
      aria-modal={maximised && !minimised}
      onKeyDown={(e) => {
        if (e.key === 'Tab' && maximised && !minimised) {
          // Maximised, Tab stays in the composer, as in a dialog.
          const focusable = [...e.currentTarget.querySelectorAll<HTMLElement>('a[href], button:not([disabled]), input:not([disabled]), textarea, [contenteditable="true"], [tabindex]:not([tabindex="-1"])')].filter(
            (el) => el.offsetParent !== null,
          )
          const first = focusable[0]
          const last = focusable[focusable.length - 1]
          if (e.shiftKey && document.activeElement === first) {
            e.preventDefault()
            last?.focus()
          } else if (!e.shiftKey && document.activeElement === last) {
            e.preventDefault()
            first?.focus()
          }
        } else if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
          e.preventDefault()
          void send()
        } else if (e.key === 'Escape') {
          e.preventDefault()
          // Escape first docks a maximised composer, then closes it.
          if (maximised && !minimised) setMaximised(false)
          else void close()
        }
      }}
      className={cn(
        'fixed z-40 flex flex-col overflow-hidden border border-border bg-background shadow-2xl',
        maximised
          ? 'inset-4 rounded-xl md:inset-10'
          : 'inset-0 md:inset-auto md:bottom-0 md:right-6 md:w-[36rem] md:rounded-t-xl',
        minimised && 'md:h-11',
      )}
    >
      <header className="flex h-11 shrink-0 items-center gap-1 bg-chrome px-3 text-chrome-foreground">
        <button type="button" className="min-w-0 flex-1 truncate text-left text-sm font-medium" onClick={() => setMinimised((m) => !m)}>
          {title}
        </button>
        <span className="text-xs text-chrome-muted" aria-live="polite">
          {status === 'saving' ? t('compose.saving') : status === 'saved' ? t('compose.saved') : status === 'failed' ? t('compose.saveFailed') : ''}
        </span>
        <Button variant="ghost" size="icon" className="size-8 text-chrome-foreground" aria-label={minimised ? t('compose.restore') : t('compose.minimise')} onClick={() => setMinimised((m) => !m)}>
          <Minimize2 />
        </Button>
        <Button variant="ghost" size="icon" className="hidden size-8 text-chrome-foreground md:inline-flex" aria-label={maximised ? t('compose.unmaximise') : t('compose.maximise')} onClick={() => setMaximised((m) => !m)}>
          <Maximize2 />
        </Button>
        <Button variant="ghost" size="icon" className="size-8 text-chrome-foreground" aria-label={t('compose.close')} onClick={() => void close()}>
          <X />
        </Button>
      </header>
      {minimised ? null : (
        <>
          {outsideBlocked ? (
            <p role="status" className="shrink-0 border-b border-border bg-status-warn/20 px-3 py-2 text-xs">
              {t('compose.outsideOffNotice')}
            </p>
          ) : null}
          {sendingStatus.data?.outsideAllowed && sendingStatus.data.paused ? (
            <p role="status" className="shrink-0 border-b border-border bg-status-warn/20 px-3 py-2 text-xs">
              {t('compose.pausedNotice')}
            </p>
          ) : null}
          <div className="shrink-0">
            <div className="flex min-h-10 items-center border-b border-border px-3 text-sm">
              <span className="w-10 shrink-0 text-muted-foreground" id="compose-from">
                {t('compose.from')}
              </span>
              {sendAsChoices.length > 0 ? (
                <Select value={from?.id ?? 'self'} onValueChange={(value) => setFromGroup(value === 'self' ? undefined : value)}>
                  <SelectTrigger className="h-8 w-auto max-w-full border-0 px-1 shadow-none" aria-labelledby="compose-from">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="self">{account.name ? `${account.name} <${account.address}>` : account.address}</SelectItem>
                    {sendAsChoices.map((group) => (
                      <SelectItem key={group.id} value={group.id}>
                        {group.displayName ? `${group.displayName} <${group.address}>` : group.address}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              ) : (
                <span className="truncate">{account.name ? `${account.name} <${account.address}>` : account.address}</span>
              )}
            </div>
            <div className="relative">
              <RecipientField label={t('compose.to')} value={to} onChange={setTo} domain={account.domain} pinned={pinned} encrypt={encrypt} autoFocus={target.kind === 'new' && !start.draft.to.length} />
              {!showCopies ? (
                <button type="button" className="absolute right-3 top-2 text-xs text-muted-foreground hover:text-foreground" onClick={() => setShowCopies(true)}>
                  {t('compose.ccBcc')}
                </button>
              ) : null}
            </div>
            {showCopies ? (
              <>
                <RecipientField label={t('compose.cc')} value={cc} onChange={setCc} domain={account.domain} pinned={pinned} encrypt={encrypt} />
                <RecipientField label={t('compose.bcc')} value={bcc} onChange={setBcc} domain={account.domain} pinned={pinned} encrypt={encrypt} />
              </>
            ) : null}
            <Input
              value={subject}
              onChange={(e) => setSubject(e.target.value)}
              placeholder={t('compose.subject')}
              aria-label={t('compose.subject')}
              className="h-10 rounded-none border-0 border-b border-border px-3 shadow-none focus-visible:ring-0"
            />
          </div>
          <div className="flex shrink-0 items-center gap-0.5 border-b border-border px-2 py-1">
            <ToolbarToggle editor={editor} label={t('compose.bold')} active={!!editor?.isActive('bold')} onClick={() => editor?.chain().focus().toggleBold().run()}>
              <Bold />
            </ToolbarToggle>
            <ToolbarToggle editor={editor} label={t('compose.italic')} active={!!editor?.isActive('italic')} onClick={() => editor?.chain().focus().toggleItalic().run()}>
              <Italic />
            </ToolbarToggle>
            <ToolbarToggle editor={editor} label={t('compose.bulletList')} active={!!editor?.isActive('bulletList')} onClick={() => editor?.chain().focus().toggleBulletList().run()}>
              <List />
            </ToolbarToggle>
            <ToolbarToggle editor={editor} label={t('compose.orderedList')} active={!!editor?.isActive('orderedList')} onClick={() => editor?.chain().focus().toggleOrderedList().run()}>
              <ListOrdered />
            </ToolbarToggle>
            <ToolbarToggle editor={editor} label={t('compose.quote')} active={!!editor?.isActive('blockquote')} onClick={() => editor?.chain().focus().toggleBlockquote().run()}>
              <Quote />
            </ToolbarToggle>
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto">
            <EditorContent editor={editor} />
          </div>
          {attachments.length ? (
            <ul aria-label={t('compose.attachments')} className="flex max-h-28 shrink-0 flex-wrap gap-2 overflow-y-auto border-t border-border p-2">
              {attachments.map((attachment) => (
                <li key={attachment.key} className={cn('flex max-w-60 items-center gap-2 rounded-md border px-2 py-1 text-xs', attachment.status === 'failed' ? 'border-destructive text-destructive' : 'border-border')}>
                  {attachment.status === 'uploading' ? <Loader2 className="size-3.5 animate-spin" aria-label={t('compose.uploading')} /> : <Paperclip className="size-3.5" aria-hidden />}
                  <span className="min-w-0 flex-1 truncate">{attachment.name}</span>
                  <span className="text-muted-foreground">{formatBytes(attachment.size, i18n.language)}</span>
                  <button type="button" className="rounded p-0.5 hover:bg-muted" aria-label={t('compose.removeAttachment', { name: attachment.name })} onClick={() => void removeAttachment(attachment)}>
                    <X className="size-3" />
                  </button>
                </li>
              ))}
            </ul>
          ) : null}
          {!encrypt ? (
            <p role="status" className="shrink-0 border-t border-border bg-status-warn/20 px-3 py-2 text-xs">
              {kutupRecipients ? t('compose.notEncryptedKutup') : t('compose.notEncrypted')}
            </p>
          ) : null}
          <footer className="flex shrink-0 items-center gap-2 border-t border-border px-3 py-2">
            <Button onClick={() => void send()} disabled={sending}>
              {sending ? <Loader2 className="animate-spin" /> : <Send />}
              {sending ? t('compose.sending') : t('compose.send')}
            </Button>
            <input ref={files} type="file" multiple hidden onChange={(e) => void addFiles(e.target.files).finally(() => (e.target.value = ''))} />
            <Tooltip label={t('compose.attach')}>
              <Button variant="ghost" size="icon" aria-label={t('compose.attach')} onClick={() => files.current?.click()}>
                <Paperclip />
              </Button>
            </Tooltip>
            <Tooltip label={encrypt ? t('compose.encryptOn') : t('compose.encryptOff')}>
              <Button variant={encrypt ? 'ghost' : 'outline'} size="sm" aria-pressed={encrypt} onClick={() => setEncrypt((on) => !on)}>
                {encrypt ? <LockKeyhole className="text-primary" /> : <LockKeyholeOpen className="text-status-warn" />}
                {t('compose.encrypt')}
              </Button>
            </Tooltip>
            <Tooltip label={sign ? t('compose.signOn') : t('compose.signOff')}>
              <Button variant={sign ? 'ghost' : 'outline'} size="sm" aria-pressed={sign} onClick={() => setSignChoice(!sign)}>
                <Signature className={sign ? 'text-primary' : 'text-muted-foreground'} />
                {t('compose.sign')}
              </Button>
            </Tooltip>
            <span className="flex-1" />
            <Tooltip label={t('compose.discard')}>
              <Button variant="ghost" size="icon" aria-label={t('compose.discard')} onClick={() => void discard()}>
                <Trash2 />
              </Button>
            </Tooltip>
          </footer>
        </>
      )}
    </section>
    </>
  )
}
