import { ArchiveRestore, Copy, Download, ExternalLink, Eye, EyeOff, FolderInput, History, Paperclip, Pencil, Trash2 } from 'lucide-react'
import { useEffect, useRef, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Alert } from '@kutup/ui/components/alert'
import { Badge } from '@kutup/ui/components/badge'
import { Button } from '@kutup/ui/components/button'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuTrigger } from '@kutup/ui/components/dropdown-menu'
import { copyText } from '@kutup/ui/lib/clipboard'
import { formatBytes, formatInstant } from '@kutup/ui/lib/format'
import type { VaultSession } from '../sync/vaultSession'
import { fieldValue, STANDARD_FIELDS, type EntryView, type OtpView, type VaultView } from '../vault/types'
import { HistoryDialog } from './HistoryDialog'

/** A copied secret is cleared from the clipboard after this, if it is still there. */
const CLEAR_CLIPBOARD_MS = 30_000

async function copySecret(value: string, done: string, cleared: string, notCleared: string) {
  await copyText(value)
  toast.success(done)
  setTimeout(() => {
    // Only what this copied is cleared: reading the clipboard needs the
    // browser's permission, and without it the person is told to clear it.
    void navigator.clipboard
      .readText()
      .then((now) => {
        if (now === value) return navigator.clipboard.writeText('').then(() => toast(cleared))
      })
      .catch(() => toast.warning(notCleared))
  }, CLEAR_CLIPBOARD_MS)
}

function Row({ label, children, actions }: { label: string; children: ReactNode; actions?: ReactNode }) {
  return (
    <div className="flex items-start gap-3 border-b border-border py-3 last:border-b-0">
      <div className="min-w-0 flex-1">
        <dt className="text-xs text-muted-foreground">{label}</dt>
        <dd className="mt-0.5 break-words text-sm">{children}</dd>
      </div>
      {actions ? <div className="flex shrink-0 gap-1">{actions}</div> : null}
    </div>
  )
}

function SecretValue({ value, label }: { value: string; label: string }) {
  const { t } = useTranslation()
  const [shown, setShown] = useState(false)
  return (
    <Row
      label={label}
      actions={
        <>
          <Button variant="ghost" size="icon" onClick={() => setShown(!shown)} aria-label={shown ? t('common.hidePassword') : t('common.showPassword')}>
            {shown ? <EyeOff /> : <Eye />}
          </Button>
          <Button variant="ghost" size="icon" onClick={() => void copySecret(value, t('detail.copied', { what: label }), t('detail.clipboardCleared'), t('detail.clipboardNotCleared'))} aria-label={t('detail.copy', { what: label })}>
            <Copy />
          </Button>
        </>
      }
    >
      <span className="font-mono">{shown ? value : '•'.repeat(Math.min(Math.max(value.length, 8), 24))}</span>
    </Row>
  )
}

function OtpRow({ session, entryId }: { session: VaultSession; entryId: string }) {
  const { t } = useTranslation()
  const [otp, setOtp] = useState<OtpView | null>(null)
  useEffect(() => {
    let live = true
    const tick = () => {
      void session
        .vault()
        .otp(entryId)
        .then((next) => live && setOtp(next))
        .catch(() => live && setOtp(null))
    }
    tick()
    const timer = setInterval(tick, 1000)
    return () => {
      live = false
      clearInterval(timer)
    }
  }, [session, entryId])
  if (!otp) return null
  const grouped = otp.code.length > 4 ? `${otp.code.slice(0, Math.ceil(otp.code.length / 2))} ${otp.code.slice(Math.ceil(otp.code.length / 2))}` : otp.code
  return (
    <Row
      label={t('detail.otp')}
      actions={
        <Button variant="ghost" size="icon" onClick={() => void copySecret(otp.code, t('detail.copied', { what: t('detail.otp') }), t('detail.clipboardCleared'), t('detail.clipboardNotCleared'))} aria-label={t('detail.copy', { what: t('detail.otp') })}>
          <Copy />
        </Button>
      }
    >
      <span className="flex items-center gap-3">
        <span className="font-mono text-lg tracking-widest" aria-live="polite">
          {grouped}
        </span>
        <span className="text-xs tabular-nums text-muted-foreground">{t('detail.otpRemaining', { count: otp.remaining })}</span>
      </span>
    </Row>
  )
}

function downloadBytes(bytes: Uint8Array, name: string) {
  const url = URL.createObjectURL(new Blob([bytes as BlobPart], { type: 'application/octet-stream' }))
  const a = document.createElement('a')
  a.href = url
  a.download = name
  a.click()
  setTimeout(() => URL.revokeObjectURL(url), 10_000)
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = ''
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000))
  return btoa(binary)
}

/** One entry: its fields to copy, its one-time code, attachments, history and what to do with it. */
export function EntryDetail({ session, entry, view, onEdit, onGone }: { session: VaultSession; entry: EntryView; view: VaultView; onEdit: () => void; onGone: () => void }) {
  const { t, i18n } = useTranslation()
  const [history, setHistory] = useState(false)
  const [confirmDelete, setConfirmDelete] = useState(false)
  const attachInput = useRef<HTMLInputElement>(null)
  const canEdit = session.canEdit
  const title = fieldValue(entry, 'Title') || t('entry.untitled')
  const userName = fieldValue(entry, 'UserName')
  const password = fieldValue(entry, 'Password')
  const url = fieldValue(entry, 'URL')
  const notes = fieldValue(entry, 'Notes')
  const custom = entry.fields.filter((f) => !(STANDARD_FIELDS as readonly string[]).includes(f.key) && f.key !== 'otp')
  const groups = view.groups.filter((g) => !g.inRecycleBin)
  const safeUrl = /^https?:\/\//i.test(url) ? url : null
  const run = (op: Parameters<VaultSession['apply']>[0], done?: string) =>
    session.apply(op).then(
      () => done && toast.success(done),
      () => toast.error(t('entry.saveFailed')),
    )

  return (
    <article className="flex h-full flex-col" aria-label={title}>
      <header className="flex items-start gap-3 border-b border-border p-4">
        <div className="min-w-0 flex-1">
          <h2 className="truncate font-display text-lg font-semibold tracking-tight">{title}</h2>
          {entry.tags.length > 0 ? (
            <div className="mt-1 flex flex-wrap gap-1">
              {entry.tags.map((tag) => (
                <Badge key={tag} variant="neutral">
                  {tag}
                </Badge>
              ))}
            </div>
          ) : null}
        </div>
        {canEdit ? (
          <div className="flex shrink-0 gap-1">
            {entry.inRecycleBin ? (
              <Button variant="outline" size="sm" onClick={() => void run({ op: 'moveEntry', id: entry.id, groupId: view.rootGroupId }, t('detail.restored'))}>
                <ArchiveRestore />
                {t('detail.restore')}
              </Button>
            ) : (
              <Button variant="outline" size="sm" onClick={onEdit}>
                <Pencil />
                {t('detail.edit')}
              </Button>
            )}
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="icon" aria-label={t('detail.move')}>
                  <FolderInput />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuLabel>{t('detail.moveTo')}</DropdownMenuLabel>
                {groups.map((g) => (
                  <DropdownMenuItem key={g.id} disabled={g.id === entry.groupId} onSelect={() => void run({ op: 'moveEntry', id: entry.id, groupId: g.id }, t('detail.moved'))}>
                    <span style={{ paddingInlineStart: `${g.depth * 0.75}rem` }}>{g.name}</span>
                  </DropdownMenuItem>
                ))}
              </DropdownMenuContent>
            </DropdownMenu>
            <Button variant="ghost" size="icon" onClick={() => setConfirmDelete(true)} aria-label={t('detail.delete')}>
              <Trash2 />
            </Button>
          </div>
        ) : null}
      </header>
      <div className="flex-1 overflow-y-auto p-4">
        {entry.review.length > 0 ? (
          <Alert variant="warn" title={t('review.title')} className="mb-4">
            <p>{t('review.description', { fields: entry.review.join(', ') })}</p>
            <div className="mt-2 flex gap-2">
              <Button size="sm" variant="outline" onClick={() => setHistory(true)}>
                {t('review.compare')}
              </Button>
              {canEdit ? (
                <Button size="sm" onClick={() => void run({ op: 'clearReview', id: entry.id }, t('review.done'))}>
                  {t('review.markDone')}
                </Button>
              ) : null}
            </div>
          </Alert>
        ) : null}
        {entry.expires && entry.expiry && new Date(entry.expiry) < new Date() ? (
          <Alert variant="warn" className="mb-4">
            {t('detail.expired', { when: formatInstant(entry.expiry, i18n.language) })}
          </Alert>
        ) : null}
        <dl>
          {userName ? (
            <Row
              label={t('entry.userName')}
              actions={
                <Button variant="ghost" size="icon" onClick={() => void copyText(userName).then(() => toast.success(t('detail.copied', { what: t('entry.userName') })))} aria-label={t('detail.copy', { what: t('entry.userName') })}>
                  <Copy />
                </Button>
              }
            >
              {userName}
            </Row>
          ) : null}
          {password ? <SecretValue value={password} label={t('entry.password')} /> : null}
          <OtpRow session={session} entryId={entry.id} />
          {url ? (
            <Row
              label={t('entry.url')}
              actions={
                safeUrl ? (
                  <Button variant="ghost" size="icon" asChild>
                    <a href={safeUrl} target="_blank" rel="noopener noreferrer" aria-label={t('detail.openUrl')}>
                      <ExternalLink />
                    </a>
                  </Button>
                ) : undefined
              }
            >
              <span className="break-all">{url}</span>
            </Row>
          ) : null}
          {custom.map((f) =>
            f.protected ? (
              <SecretValue key={f.key} value={f.value} label={f.key} />
            ) : (
              <Row
                key={f.key}
                label={f.key}
                actions={
                  <Button variant="ghost" size="icon" onClick={() => void copyText(f.value).then(() => toast.success(t('detail.copied', { what: f.key })))} aria-label={t('detail.copy', { what: f.key })}>
                    <Copy />
                  </Button>
                }
              >
                <span className="break-all">{f.value}</span>
              </Row>
            ),
          )}
          {notes ? (
            <Row label={t('entry.notes')}>
              <span className="whitespace-pre-wrap">{notes}</span>
            </Row>
          ) : null}
        </dl>
        <section className="mt-6" aria-label={t('detail.attachments')}>
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-medium">{t('detail.attachments')}</h3>
            {canEdit && !entry.inRecycleBin ? (
              <>
                <input
                  ref={attachInput}
                  type="file"
                  hidden
                  onChange={(e) => {
                    const file = e.target.files?.[0]
                    e.target.value = ''
                    if (!file) return
                    if (file.size > 50 * 1024 * 1024) {
                      toast.error(t('detail.attachmentTooLarge'))
                      return
                    }
                    void file.arrayBuffer().then((buffer) =>
                      run({ op: 'addAttachment', entryId: entry.id, name: file.name, data: bytesToBase64(new Uint8Array(buffer)) }, t('detail.attached')),
                    )
                  }}
                />
                <Button variant="ghost" size="sm" onClick={() => attachInput.current?.click()}>
                  <Paperclip />
                  {t('detail.attach')}
                </Button>
              </>
            ) : null}
          </div>
          {entry.attachments.length === 0 ? (
            <p className="mt-1 text-xs text-muted-foreground">{t('detail.noAttachments')}</p>
          ) : (
            <ul className="mt-2 space-y-1">
              {entry.attachments.map((a) => (
                <li key={a.name} className="flex items-center gap-2 rounded-md border border-border px-3 py-2 text-sm">
                  <Paperclip className="size-4 shrink-0 text-muted-foreground" aria-hidden />
                  <span className="min-w-0 flex-1 truncate">{a.name}</span>
                  <span className="text-xs text-muted-foreground">{formatBytes(a.size, i18n.language)}</span>
                  <Button
                    variant="ghost"
                    size="icon"
                    aria-label={t('detail.download', { name: a.name })}
                    onClick={() => void session.vault().attachment(entry.id, a.name).then((bytes) => downloadBytes(bytes, a.name))}
                  >
                    <Download />
                  </Button>
                  {canEdit ? (
                    <Button variant="ghost" size="icon" aria-label={t('detail.removeAttachment', { name: a.name })} onClick={() => void run({ op: 'removeAttachment', entryId: entry.id, name: a.name })}>
                      <Trash2 />
                    </Button>
                  ) : null}
                </li>
              ))}
            </ul>
          )}
        </section>
        <footer className="mt-6 space-y-1 text-xs text-muted-foreground">
          {entry.modified ? <p>{t('detail.modified', { when: formatInstant(entry.modified, i18n.language) })}</p> : null}
          {entry.created ? <p>{t('detail.created', { when: formatInstant(entry.created, i18n.language) })}</p> : null}
          <Button variant="link" size="sm" className="h-auto p-0 text-xs" onClick={() => setHistory(true)}>
            <History className="size-3" />
            {t('detail.history', { count: entry.historyCount })}
          </Button>
        </footer>
      </div>
      <HistoryDialog session={session} entry={entry} open={history} onOpenChange={setHistory} />
      <ConfirmDestructive
        open={confirmDelete}
        onOpenChange={setConfirmDelete}
        title={entry.inRecycleBin || !view.recycleBinEnabled ? t('detail.deleteForGoodTitle') : t('detail.deleteTitle')}
        description={entry.inRecycleBin || !view.recycleBinEnabled ? t('detail.deleteForGoodDescription', { title }) : t('detail.deleteDescription', { title })}
        submit={t('detail.delete')}
        errorFallback={t('entry.saveFailed')}
        onConfirm={() => {
          setConfirmDelete(false)
          void run({ op: 'deleteEntry', id: entry.id }, t('detail.deleted')).then(onGone)
        }}
      />
    </article>
  )
}
