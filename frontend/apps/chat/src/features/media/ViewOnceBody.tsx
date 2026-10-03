import { Eye, Loader2 } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { downloadChatMediaToCacheV1, openCachedChatMediaV1 } from '@kutup/chat-core/media'
import type { ChatAttachmentDescriptorV1 } from '@kutup/chat-core/types'
import { freshAccessToken } from '@kutup/session/client'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { cn } from '@kutup/ui/lib/cn'
import { useChat } from '../../app/chatStore'

/** Signal's "view once" mark: a 1 in a dashed circle. */
export function ViewOnceIcon({ className }: { className?: string }) {
  return (
    <span
      aria-hidden
      className={cn('inline-flex size-5 shrink-0 items-center justify-center rounded-full border-2 border-dashed border-current text-[0.625rem] font-bold', className)}
    >
      1
    </span>
  )
}

/**
 * A view-once photo or video in its bubble, as Signal shows it: no picture,
 * just "Photo" or "Video". The recipient opens it once; when the viewer
 * closes it is removed on all of their devices ("Viewed" stays). The sender
 * cannot open it here either.
 */
export function ViewOnceBody({
  attachment,
  outgoing,
  accepted,
  onViewed,
}: {
  attachment: ChatAttachmentDescriptorV1
  outgoing: boolean
  accepted: boolean
  /** Called once the viewer closes. */
  onViewed: () => void
}) {
  const { t } = useTranslation()
  const { mediaCache: cache } = useChat()
  const [state, setState] = useState<'idle' | 'loading' | 'open'>('idle')
  const [media, setMedia] = useState<{ url: string; kind: string } | null>(null)
  const viewed = useRef(false)
  const video = attachment.mediaClass === 'video'
  const label = video ? t('chat.viewOnce.video') : t('chat.viewOnce.photo')
  const binding = useMemo(
    () => ({
      product: 'chat' as const,
      suite: attachment.suite,
      objectId: attachment.attachmentId,
      ciphertextBytes: attachment.ciphertextBytes,
      ciphertextSha256: attachment.ciphertextSha256,
    }),
    [attachment],
  )

  useEffect(() => () => {
    if (media) URL.revokeObjectURL(media.url)
  }, [media])

  async function open() {
    if (!cache || !accepted || outgoing || state !== 'idle') return
    setState('loading')
    try {
      await downloadChatMediaToCacheV1(cache, attachment, await freshAccessToken())
      const opened = await openCachedChatMediaV1(cache, attachment)
      setMedia({ url: URL.createObjectURL(opened.blob), kind: opened.kind })
      setState('open')
    } catch {
      setState('idle')
      toast.error(t('chat.attachments.downloadFailed'))
    }
  }

  function close() {
    setState('idle')
    if (media) URL.revokeObjectURL(media.url)
    setMedia(null)
    void cache?.remove(binding).catch(() => undefined)
    if (!viewed.current) {
      viewed.current = true
      onViewed()
    }
  }

  return (
    <>
      <button
        type="button"
        onClick={() => void open()}
        disabled={outgoing || !accepted || state !== 'idle'}
        className={cn(
          'flex items-center gap-2 rounded-lg px-1 py-1 text-sm font-medium outline-none',
          'focus-visible:ring-2 focus-visible:ring-ring disabled:cursor-default',
        )}
        data-testid="chat-view-once"
      >
        {state === 'loading' ? <Loader2 className="size-5 animate-spin" aria-hidden /> : <ViewOnceIcon />}
        <span>{outgoing ? (video ? t('chat.viewOnce.sentVideo') : t('chat.viewOnce.sentPhoto')) : label}</span>
      </button>
      <Dialog open={state === 'open'} onOpenChange={(next) => !next && close()}>
        <DialogContent className="max-h-[92vh] max-w-4xl overflow-auto" data-testid="chat-view-once-viewer">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Eye className="size-4" aria-hidden />
              {label}
            </DialogTitle>
            <DialogDescription>{t('chat.viewOnce.viewerHint')}</DialogDescription>
          </DialogHeader>
          {media?.kind === 'image' ? (
            <img src={media.url} alt="" className="mx-auto max-h-[70vh] w-auto" onContextMenu={(e) => e.preventDefault()} draggable={false} />
          ) : media?.kind === 'video' ? (
            <video src={media.url} controls autoPlay className="mx-auto max-h-[70vh]" controlsList="nodownload" onContextMenu={(e) => e.preventDefault()} />
          ) : null}
        </DialogContent>
      </Dialog>
    </>
  )
}

/** What stays of a view-once photo or video once opened. */
export function ViewedOnce({ video }: { video: boolean }) {
  const { t } = useTranslation()
  return (
    <p className="flex items-center gap-2 text-sm italic opacity-80" data-testid="chat-view-once-viewed">
      <ViewOnceIcon className="opacity-60" />
      {video ? t('chat.viewOnce.viewedVideo') : t('chat.viewOnce.viewedPhoto')}
    </p>
  )
}
