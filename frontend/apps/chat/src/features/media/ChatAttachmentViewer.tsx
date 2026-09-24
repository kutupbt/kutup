import { useEffect, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@kutup/ui/components/dialog'
import type { PrivateCiphertextCacheV1 } from '@kutup/files/mediaCache'
import type { ChatAttachmentDescriptorV1 } from '@kutup/chat-core/types'
import { openCachedChatMediaV1, type OpenedChatMediaV1 } from '@kutup/chat-core/media'

export function ChatAttachmentViewer({
  open,
  onOpenChange,
  cache,
  attachment,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  cache: PrivateCiphertextCacheV1
  attachment: ChatAttachmentDescriptorV1
}) {
  const { t } = useTranslation()
  const [opened, setOpened] = useState<(OpenedChatMediaV1 & { url: string }) | null>(null)
  const [failed, setFailed] = useState(false)

  useEffect(() => {
    if (!open) {
      setFailed(false)
      return
    }
    const controller = new AbortController()
    let url: string | null = null
    setOpened(null)
    setFailed(false)
    void openCachedChatMediaV1(cache, attachment, controller.signal)
      .then((result) => {
        if (controller.signal.aborted) return
        url = URL.createObjectURL(result.blob)
        setOpened({ ...result, url })
      })
      .catch((cause: unknown) => {
        if (controller.signal.aborted) return
        // The protocol's reason is diagnostic, not user copy.
        console.warn('chat: attachment could not be opened', cause)
        setFailed(true)
      })
    return () => {
      controller.abort()
      if (url) URL.revokeObjectURL(url)
    }
  }, [attachment, cache, open])

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[92vh] max-w-4xl overflow-auto">
        <DialogHeader>
          <DialogTitle className="break-all pr-8">{attachment.filename}</DialogTitle>
          <DialogDescription>{t('chat.attachments.viewer.description')}</DialogDescription>
        </DialogHeader>
        {!opened && !failed && (
          <div
            className="flex min-h-48 items-center justify-center text-muted-foreground"
            role="status"
            aria-label={t('chat.attachments.viewer.opening')}
          >
            <Loader2 className="h-7 w-7 animate-spin" />
          </div>
        )}
        {failed && (
          <p className="rounded-lg border border-destructive/30 bg-destructive/5 p-4 text-sm text-destructive">
            {t('chat.attachments.viewer.openFailed')}
          </p>
        )}
        {opened?.kind === 'image' && (
          <img
            src={opened.url}
            alt={attachment.filename}
            className="max-h-[75vh] w-full object-contain"
          />
        )}
        {opened?.kind === 'audio' && (
          <audio
            src={opened.url}
            controls
            controlsList="nodownload noremoteplayback"
            className="w-full"
          />
        )}
        {opened?.kind === 'video' && (
          <video
            src={opened.url}
            controls
            controlsList="nodownload noremoteplayback"
            disablePictureInPicture
            className="max-h-[75vh] w-full bg-black"
          />
        )}
        {opened?.kind === 'pdf' && (
          <iframe
            src={opened.url}
            title={attachment.filename}
            className="h-[75vh] w-full border-0 bg-background"
          />
        )}
      </DialogContent>
    </Dialog>
  )
}
