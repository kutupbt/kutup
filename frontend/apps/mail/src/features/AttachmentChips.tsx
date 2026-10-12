import { File, FileArchive, FileAudio, FileImage, FileSpreadsheet, FileText, FileVideo, Loader2 } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { openMessage, useMailAccount, usePinnedKeys, type MailMessage } from '@kutup/mail-core/api'
import type { ParsedAttachment } from '@kutup/mail-core/mime'
import api from '@kutup/session/client'
import { Tooltip } from '@kutup/ui/components/tooltip'
import { cn } from '@kutup/ui/lib/cn'
import { Preview } from './AttachmentList'
import { listedAttachments } from './attachments'
import { useGroupScope, useMailboxScope } from './mailboxScope'

function FileIcon({ type, className }: { type: string; className?: string }) {
  const t = type.toLowerCase()
  const Icon = t.startsWith('image/')
    ? FileImage
    : t.startsWith('video/')
      ? FileVideo
      : t.startsWith('audio/')
        ? FileAudio
        : t.includes('zip') || t.includes('compressed') || t.includes('tar')
          ? FileArchive
          : t.includes('sheet') || t.includes('excel') || t === 'text/csv'
            ? FileSpreadsheet
            : t.startsWith('text/') || t.includes('pdf') || t.includes('word') || t.includes('document')
              ? FileText
              : File
  return <Icon className={className} aria-hidden />
}

/**
 * Proton's ItemAttachmentThumbnails: a row's files as chips under its
 * subject, a few then "+N". A chip opens the preview: the message is
 * decrypted here, on the device, and the files found by name and size.
 */
export function AttachmentChips({ row, max }: { row: MailMessage; max: number }) {
  const { t } = useTranslation()
  const account = useMailAccount()
  const pinned = usePinnedKeys()
  const { group } = useMailboxScope()
  const scope = useGroupScope(account.data)
  const [opening, setOpening] = useState<number | null>(null)
  const [preview, setPreview] = useState<{ files: ParsedAttachment[]; index: number } | null>(null)
  const files = listedAttachments(row.conversation?.attachments ?? row.attachments ?? [])
  if (files.length === 0) return null
  const rest = files.slice(max)

  async function open(index: number) {
    if (!account.data || opening !== null) return
    setOpening(index)
    try {
      // The messages holding the files: the row's own, or its conversation's.
      const ids = [...new Set(files.map((f) => f.message ?? row.id))]
      const messages = row.conversation
        ? (await api.get<MailMessage[]>(`/mail/threads/${row.threadId}`, { params: group ? { group } : {} })).data.filter((m) => ids.includes(m.id))
        : [row]
      const parsed = new Map<string, ParsedAttachment[]>()
      for (const message of messages) {
        const opened = await openMessage(account.data, message, pinned ?? (() => undefined), scope ?? undefined)
        parsed.set(message.id, opened.parsed.attachments.filter((a) => !a.inline))
      }
      // Each listed file, by name and size in its message (Proton matches the same way).
      const found: ParsedAttachment[] = []
      let at = 0
      files.forEach((file, i) => {
        const pool = parsed.get(file.message ?? row.id) ?? []
        const match = pool.find((a) => a.filename === file.name && a.content.length === file.size) ?? pool.find((a) => a.filename === file.name)
        if (match) {
          if (i === index) at = found.length
          found.push(match)
        }
      })
      if (found.length === 0) throw new Error('not found')
      setPreview({ files: found, index: at })
    } catch {
      toast.error(t('attachments.openFailed'))
    } finally {
      setOpening(null)
    }
  }

  return (
    <>
      <span className="mt-1 flex min-w-0 flex-nowrap items-center gap-1.5">
        {files.slice(0, max).map((file, i) => (
          <button
            key={`${file.message ?? row.id}-${i}`}
            type="button"
            className="flex min-w-0 max-w-48 items-center gap-1 rounded-md border border-border bg-background px-1.5 py-0.5 text-xs hover:bg-muted"
            aria-label={t('attachments.previewNamed', { name: file.name })}
            onClick={(event) => {
              event.preventDefault()
              event.stopPropagation()
              void open(i)
            }}
          >
            {opening === i ? <Loader2 className="size-3.5 shrink-0 animate-spin" aria-hidden /> : <FileIcon type={file.type} className="size-3.5 shrink-0 text-muted-foreground" />}
            <span className="truncate">{file.name}</span>
          </button>
        ))}
        {rest.length ? (
          <Tooltip label={rest.map((f) => f.name).join(', ')}>
            <span className={cn('shrink-0 rounded-md border border-border px-1.5 py-0.5 text-xs text-muted-foreground')}>+{rest.length}</span>
          </Tooltip>
        ) : null}
      </span>
      {preview ? (
        <Preview files={preview.files} index={preview.index} onIndex={(index) => setPreview({ ...preview, index })} onClose={() => setPreview(null)} name={(f) => f.filename || t('read.unnamed')} />
      ) : null}
    </>
  )
}
