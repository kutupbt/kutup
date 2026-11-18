import { Download, Eye, Paperclip, Pencil, Trash2 } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Input } from '@kutup/ui/components/input'
import { Label } from '@kutup/ui/components/label'
import { formatBytes } from '@kutup/ui/lib/format'
import type { VaultSession } from '../sync/vaultSession'
import type { EntryView } from '../vault/types'
import { bytesToBase64 } from '../lib/bytes'
import { extension, IMAGE_TYPES, previewKind } from '../lib/attachmentPreview'

/** An attachment's largest size (kutup_pass::edit::MAX_ATTACHMENT_BYTES). */
const MAX_BYTES = 50 * 1024 * 1024
/** The most text a preview shows; a longer file is cut, and says so. */
const MAX_TEXT_BYTES = 1024 * 1024
function downloadBytes(bytes: Uint8Array, name: string) {
  const url = URL.createObjectURL(new Blob([bytes as BlobPart], { type: 'application/octet-stream' }))
  const a = document.createElement('a')
  a.href = url
  a.download = name
  a.click()
  setTimeout(() => URL.revokeObjectURL(url), 10_000)
}

type Run = (op: Parameters<VaultSession['apply']>[0], done?: string) => Promise<boolean>

/**
 * An entry's attachments (KeePassXC's Advanced → Attachments): add one or
 * several, download, preview an image or a text file, rename, remove.
 */
export function AttachmentsSection({ entry, session, canEdit, run }: { entry: EntryView; session: VaultSession; canEdit: boolean; run: Run }) {
  const { t, i18n } = useTranslation()
  const input = useRef<HTMLInputElement>(null)
  const [renaming, setRenaming] = useState<string | null>(null)
  const [previewing, setPreviewing] = useState<string | null>(null)

  // Files whose names the entry has already, waiting for "replace" or "skip".
  const [clashing, setClashing] = useState<{ files: File[]; names: string[] } | null>(null)

  const attach = async (files: File[]) => {
    let added = 0
    for (const file of files) {
      const data = bytesToBase64(new Uint8Array(await file.arrayBuffer()))
      if (await run({ op: 'addAttachment', entryId: entry.id, name: file.name, data })) added++
    }
    if (added) toast.success(t('detail.attachedCount', { count: added }))
  }

  const add = (picked: File[]) => {
    const files = picked.filter((file) => {
      if (file.size <= MAX_BYTES) return true
      toast.error(t('detail.attachmentTooLargeNamed', { name: file.name }))
      return false
    })
    // As KeePassXC: one of the same name is replaced only when asked.
    const taken = new Set(entry.attachments.map((a) => a.name))
    const names = files.map((f) => f.name).filter((n) => taken.has(n))
    if (names.length) setClashing({ files, names })
    else if (files.length) void attach(files)
  }

  const download = (name: string) => void session.vault().attachment(entry.id, name).then((bytes) => downloadBytes(bytes, name))

  return (
    <section className="mt-6" aria-label={t('detail.attachments')}>
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium">{t('detail.attachments')}</h3>
        {canEdit && !entry.inRecycleBin ? (
          <>
            <input
              ref={input}
              type="file"
              multiple
              hidden
              data-testid="attachment-input"
              onChange={(e) => {
                const files = Array.from(e.target.files ?? [])
                e.target.value = ''
                if (files.length) add(files)
              }}
            />
            <Button variant="ghost" size="sm" onClick={() => input.current?.click()}>
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
            <li key={a.name} className="flex items-center gap-2 rounded-md border border-border px-3 py-2 text-sm" data-testid="attachment-row">
              <Paperclip className="size-4 shrink-0 text-muted-foreground" aria-hidden />
              <span className="min-w-0 flex-1 truncate">{a.name}</span>
              <span className="text-xs text-muted-foreground">{formatBytes(a.size, i18n.language)}</span>
              {previewKind(a.name) ? (
                <Button variant="ghost" size="icon" aria-label={t('detail.preview', { name: a.name })} onClick={() => setPreviewing(a.name)}>
                  <Eye />
                </Button>
              ) : null}
              <Button variant="ghost" size="icon" aria-label={t('detail.download', { name: a.name })} onClick={() => download(a.name)}>
                <Download />
              </Button>
              {canEdit && !entry.inRecycleBin ? (
                <>
                  <Button variant="ghost" size="icon" aria-label={t('detail.renameAttachment', { name: a.name })} onClick={() => setRenaming(a.name)}>
                    <Pencil />
                  </Button>
                  <Button variant="ghost" size="icon" aria-label={t('detail.removeAttachment', { name: a.name })} onClick={() => void run({ op: 'removeAttachment', entryId: entry.id, name: a.name })}>
                    <Trash2 />
                  </Button>
                </>
              ) : null}
            </li>
          ))}
        </ul>
      )}
      {renaming ? (
        <RenameDialog
          name={renaming}
          taken={entry.attachments.map((a) => a.name).filter((n) => n !== renaming)}
          onClose={() => setRenaming(null)}
          onRename={async (newName) => {
            if (await run({ op: 'renameAttachment', entryId: entry.id, name: renaming, newName }, t('detail.attachmentRenamed'))) setRenaming(null)
          }}
        />
      ) : null}
      {clashing ? (
        <Dialog open onOpenChange={(o) => !o && setClashing(null)}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>{t('detail.replaceAttachmentsTitle', { count: clashing.names.length })}</DialogTitle>
              <DialogDescription>{t('detail.replaceAttachments')}</DialogDescription>
            </DialogHeader>
            <ul className="list-inside list-disc text-sm">
              {clashing.names.map((n) => (
                <li key={n} className="truncate">
                  {n}
                </li>
              ))}
            </ul>
            <DialogFooter>
              <Button
                variant="ghost"
                onClick={() => {
                  const rest = clashing.files.filter((f) => !clashing.names.includes(f.name))
                  setClashing(null)
                  if (rest.length) void attach(rest)
                }}
              >
                {t('detail.skipExisting')}
              </Button>
              <Button
                onClick={() => {
                  const files = clashing.files
                  setClashing(null)
                  void attach(files)
                }}
              >
                {t('detail.replace')}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      ) : null}
      {previewing ? <PreviewDialog session={session} entryId={entry.id} name={previewing} onClose={() => setPreviewing(null)} /> : null}
    </section>
  )
}

function RenameDialog({ name, taken, onClose, onRename }: { name: string; taken: string[]; onClose: () => void; onRename: (newName: string) => Promise<void> }) {
  const { t } = useTranslation()
  const [value, setValue] = useState(name)
  const [pending, setPending] = useState(false)
  const trimmed = value.trim()
  const clash = taken.includes(trimmed)
  return (
    <Dialog open onOpenChange={(o) => !o && !pending && onClose()}>
      <DialogContent>
        <form
          onSubmit={(e) => {
            e.preventDefault()
            if (!trimmed || clash || trimmed === name) return
            setPending(true)
            void onRename(trimmed).finally(() => setPending(false))
          }}
        >
          <DialogHeader>
            <DialogTitle>{t('detail.renameAttachmentTitle')}</DialogTitle>
          </DialogHeader>
          <div className="mt-4 space-y-1.5">
            <Label htmlFor="attachment-name">{t('detail.attachmentName')}</Label>
            <Input id="attachment-name" value={value} maxLength={256} onChange={(e) => setValue(e.target.value)} autoFocus />
            {clash ? <p className="text-xs text-destructive">{t('detail.attachmentNameTaken')}</p> : null}
          </div>
          <DialogFooter className="mt-4">
            <Button type="button" variant="ghost" onClick={onClose} disabled={pending}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" loading={pending} disabled={!trimmed || clash || trimmed === name}>
              {t('detail.rename')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

/**
 * An image or a text file shown in place. The image is a blob: URL (the
 * page's img-src allows it), revoked when the dialog closes; text is
 * decoded as UTF-8 and shown as text, never as markup.
 */
function PreviewDialog({ session, entryId, name, onClose }: { session: VaultSession; entryId: string; name: string; onClose: () => void }) {
  const { t } = useTranslation()
  const kind = previewKind(name)
  const [image, setImage] = useState<string | null>(null)
  const [text, setText] = useState<{ body: string; cut: boolean } | null>(null)
  const [failed, setFailed] = useState(false)
  useEffect(() => {
    let url: string | null = null
    let current = true
    session
      .vault()
      .attachment(entryId, name)
      .then((bytes) => {
        if (!current) return
        if (kind === 'image') {
          url = URL.createObjectURL(new Blob([bytes as BlobPart], { type: IMAGE_TYPES[extension(name)] }))
          setImage(url)
        } else {
          const cut = bytes.byteLength > MAX_TEXT_BYTES
          setText({ body: new TextDecoder('utf-8').decode(cut ? bytes.slice(0, MAX_TEXT_BYTES) : bytes), cut })
        }
      })
      .catch(() => current && setFailed(true))
    return () => {
      current = false
      if (url) URL.revokeObjectURL(url)
    }
  }, [session, entryId, name, kind])
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-3xl" data-testid="attachment-preview">
        <DialogHeader>
          <DialogTitle className="truncate">{name}</DialogTitle>
          <DialogDescription>{t('detail.previewHint')}</DialogDescription>
        </DialogHeader>
        {failed ? (
          <p className="text-sm text-destructive">{t('detail.previewFailed')}</p>
        ) : image ? (
          <img src={image} alt={name} className="mx-auto max-h-[70vh] max-w-full object-contain" />
        ) : text ? (
          <>
            <pre className="max-h-[60vh] overflow-auto whitespace-pre-wrap break-words rounded-md border border-border bg-muted/40 p-3 font-mono text-xs">{text.body}</pre>
            {text.cut ? <p className="text-xs text-muted-foreground">{t('detail.previewCut')}</p> : null}
          </>
        ) : (
          <p className="text-sm text-muted-foreground">{t('common.loading')}</p>
        )}
      </DialogContent>
    </Dialog>
  )
}
