import { ChevronLeft, ChevronRight, Download, Paperclip } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import type { ParsedAttachment } from '@kutup/mail-core/mime'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Tooltip } from '@kutup/ui/components/tooltip'
import { formatBytes } from '@kutup/ui/lib/format'
import { download, previewKind, TEXT_PREVIEW_BYTES, zipAttachments } from './attachments'

/**
 * A message's files, as Proton lists them (AttachmentList): how many, each
 * opening in a preview when it can (images, PDFs, video, audio, text) and
 * downloading otherwise, and Download all as one zip.
 */
export function AttachmentList({ list, subject }: { list: ParsedAttachment[]; subject: string }) {
  const { t, i18n } = useTranslation()
  const files = list.filter((a) => !(a.inline && a.contentId))
  const [open, setOpen] = useState<number | null>(null)
  if (files.length === 0) return null
  const name = (file: ParsedAttachment) => file.filename || t('read.unnamed')
  return (
    <section aria-label={t('read.attachments', { count: files.length })} className="space-y-2">
      <div className="flex items-center gap-2 text-sm text-muted-foreground">
        <Paperclip className="size-4" aria-hidden />
        <span className="flex-1">{t('attachments.count', { count: files.length })}</span>
        {files.length > 1 ? (
          <Tooltip label={t('attachments.downloadAll')}>
            <Button
              variant="ghost"
              size="sm"
              aria-label={t('attachments.downloadAll')}
              onClick={() => download(`Attachments-${subject || t('read.unnamed')}.zip`.replace(/[/\\]/g, '_'), 'application/zip', zipAttachments(files, t('read.unnamed')))}
            >
              <Download />
            </Button>
          </Tooltip>
        ) : null}
      </div>
      <div className="flex flex-wrap gap-2">
        {files.map((file, i) => (
          <div key={`${file.filename}-${i}`} className="flex max-w-xs items-center rounded-md border border-border text-sm">
            <button
              type="button"
              onClick={() => (previewKind(file) ? setOpen(i) : download(name(file), file.mimeType, file.content))}
              className="flex min-w-0 items-center gap-2 px-3 py-2 text-left hover:bg-muted/60"
              title={previewKind(file) ? t('attachments.preview') : t('attachments.download')}
            >
              <Paperclip className="size-4 shrink-0 text-muted-foreground" aria-hidden />
              <span className="min-w-0">
                <span className="block truncate font-medium">{name(file)}</span>
                <span className="block text-xs text-muted-foreground">{formatBytes(file.content.length, i18n.language)}</span>
              </span>
            </button>
            <Tooltip label={t('attachments.downloadNamed', { name: name(file) })}>
              <button
                type="button"
                aria-label={t('attachments.downloadNamed', { name: name(file) })}
                onClick={() => download(name(file), file.mimeType, file.content)}
                className="self-stretch border-l border-border px-2 text-muted-foreground hover:bg-muted/60"
              >
                <Download className="size-4" />
              </button>
            </Tooltip>
          </div>
        ))}
      </div>
      {open !== null && files[open] ? (
        <Preview files={files} index={open} onIndex={setOpen} onClose={() => setOpen(null)} name={name} />
      ) : null}
    </section>
  )
}

/** One file shown in place, with the others a step away (Proton's preview has previous and next). */
function Preview({ files, index, onIndex, onClose, name }: { files: ParsedAttachment[]; index: number; onIndex: (i: number) => void; onClose: () => void; name: (file: ParsedAttachment) => string }) {
  const { t, i18n } = useTranslation()
  const file = files[index]
  const kind = previewKind(file)
  const url = useMemo(() => {
    if (kind === 'text' || !kind) return null
    // A PDF is opened by the browser's PDF viewer only under its own type; nothing else gets a document type.
    const type = kind === 'pdf' ? 'application/pdf' : file.mimeType
    return URL.createObjectURL(new Blob([file.content as BlobPart], { type }))
  }, [file, kind])
  useEffect(() => () => (url ? URL.revokeObjectURL(url) : undefined), [url])
  const text = useMemo(
    () => (kind === 'text' ? new TextDecoder().decode(file.content.subarray(0, TEXT_PREVIEW_BYTES)) : ''),
    [file, kind],
  )
  const step = (delta: number) => onIndex((index + delta + files.length) % files.length)
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent
        className="max-w-5xl"
        onKeyDown={(e) => {
          if (files.length < 2) return
          if (e.key === 'ArrowRight') step(1)
          else if (e.key === 'ArrowLeft') step(-1)
        }}
      >
        <DialogHeader>
          <DialogTitle className="truncate">{name(file)}</DialogTitle>
          <DialogDescription>
            {t('attachments.position', { index: index + 1, count: files.length })} · {formatBytes(file.content.length, i18n.language)}
          </DialogDescription>
        </DialogHeader>
        <div className="flex max-h-[70vh] min-h-48 items-center justify-center overflow-auto rounded-md bg-muted/40">
          {kind === 'image' && url ? <img src={url} alt={name(file)} className="max-h-[70vh] max-w-full object-contain" /> : null}
          {kind === 'pdf' && url ? <iframe src={url} title={name(file)} className="h-[70vh] w-full border-0" /> : null}
          {kind === 'video' && url ? <video src={url} controls className="max-h-[70vh] max-w-full" aria-label={name(file)} /> : null}
          {kind === 'audio' && url ? <audio src={url} controls aria-label={name(file)} /> : null}
          {kind === 'text' ? (
            <pre aria-label={name(file)} className="h-full w-full whitespace-pre-wrap break-words p-4 font-mono text-xs">
              {text}
            </pre>
          ) : null}
        </div>
        <div className="flex items-center justify-between gap-2">
          {files.length > 1 ? (
            <div className="flex gap-1">
              <Button variant="outline" size="sm" onClick={() => step(-1)} aria-label={t('attachments.previous')}>
                <ChevronLeft />
              </Button>
              <Button variant="outline" size="sm" onClick={() => step(1)} aria-label={t('attachments.next')}>
                <ChevronRight />
              </Button>
            </div>
          ) : (
            <span />
          )}
          <Button onClick={() => download(name(file), file.mimeType, file.content)}>
            <Download />
            {t('attachments.download')}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  )
}
