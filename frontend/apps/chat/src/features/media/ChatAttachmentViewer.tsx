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
import {
  chatMediaViewerKindV1,
  openCachedChatMediaV1,
  openChatMediaPlaybackV1,
  type ChatMediaViewerKindV1,
} from '@kutup/chat-core/media'
import type { PlaybackFallback } from '@kutup/files/stream/playback'

/** What the viewer shows: a verified Blob's URL, or a stream's (`close` ends it). */
interface Shown {
  kind: ChatMediaViewerKindV1
  url: string
  close: () => void
}

/**
 * Video and audio stream (docs/plans/drive-block-format.md §4): from the
 * account's own server through the service worker, each block checked
 * against the manifest the descriptor commits to before it plays. Pictures
 * and PDFs open from the private cache, their bytes sniffed first.
 */
async function openShown(
  cache: PrivateCiphertextCacheV1,
  attachment: ChatAttachmentDescriptorV1,
  signal: AbortSignal,
  onReplaced: (next: Shown | 'busy' | 'tooLarge' | 'failed') => void,
): Promise<Shown | 'busy' | 'tooLarge'> {
  const hinted = chatMediaViewerKindV1(attachment)
  if (hinted === 'video' || hinted === 'audio') {
    // A stream that fails before it plays is replaced by a whole download;
    // the first playback's close ends it too.
    const replaced = (next: PlaybackFallback) =>
      onReplaced(next.kind === 'ready' ? { kind: hinted, url: next.src, close: next.close } : next.kind)
    const playback = await openChatMediaPlaybackV1(attachment, cache, signal, replaced)
    if (playback.kind !== 'ready') return playback.kind
    return { kind: hinted, url: playback.src, close: playback.close }
  }
  const result = await openCachedChatMediaV1(cache, attachment, signal)
  const url = URL.createObjectURL(result.blob)
  return { kind: result.kind, url, close: () => URL.revokeObjectURL(url) }
}

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
  const [opened, setOpened] = useState<Shown | null>(null)
  const [failed, setFailed] = useState<false | 'failed' | 'busy' | 'tooLarge'>(false)

  useEffect(() => {
    if (!open) {
      setFailed(false)
      return
    }
    const controller = new AbortController()
    let shown: Shown | null = null
    setOpened(null)
    setFailed(false)
    const replaced = (next: Shown | 'busy' | 'tooLarge' | 'failed') => {
      if (controller.signal.aborted) return
      if (typeof next === 'string') {
        setOpened(null)
        setFailed(next)
      } else setOpened(next)
    }
    void openShown(cache, attachment, controller.signal, replaced)
      .then((result) => {
        if (typeof result === 'string') {
          if (!controller.signal.aborted) setFailed(result)
          return
        }
        if (controller.signal.aborted) {
          result.close()
          return
        }
        shown = result
        setOpened(result)
      })
      .catch((cause: unknown) => {
        if (controller.signal.aborted) return
        // The protocol's reason is diagnostic, not user copy.
        console.warn('chat: attachment could not be opened', cause)
        setFailed('failed')
      })
    return () => {
      controller.abort()
      shown?.close()
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
            {failed === 'busy'
              ? t('chat.attachments.viewer.tooManyStreams')
              : failed === 'tooLarge'
                ? t('chat.attachments.viewer.tooLargeToPlay')
                : t('chat.attachments.viewer.openFailed')}
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
