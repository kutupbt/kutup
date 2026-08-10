import { useEffect, useState } from 'react'
import { Loader2 } from 'lucide-react'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import type { PrivateCiphertextCacheV1 } from '@/mediaCache'
import type { ChatAttachmentDescriptorV1 } from './types'
import { openCachedChatMediaV1, type OpenedChatMediaV1 } from './media'

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
  const [opened, setOpened] = useState<(OpenedChatMediaV1 & { url: string }) | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!open) {
      setError(null)
      return
    }
    const controller = new AbortController()
    let url: string | null = null
    setOpened(null)
    setError(null)
    void openCachedChatMediaV1(cache, attachment, controller.signal)
      .then(result => {
        if (controller.signal.aborted) return
        url = URL.createObjectURL(result.blob)
        setOpened({ ...result, url })
      })
      .catch(cause => {
        if (!controller.signal.aborted) {
          setError(cause instanceof Error ? cause.message : 'attachment could not be opened')
        }
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
          <DialogDescription>
            Verified locally from Kutup's encrypted cache. Closing removes the temporary view.
          </DialogDescription>
        </DialogHeader>
        {!opened && !error && (
          <div className="flex min-h-48 items-center justify-center" aria-label="Opening attachment">
            <Loader2 className="h-7 w-7 animate-spin" />
          </div>
        )}
        {error && (
          <p className="rounded-md border border-destructive/30 bg-destructive/5 p-4 text-sm text-destructive">
            {error}
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
      </DialogContent>
    </Dialog>
  )
}
