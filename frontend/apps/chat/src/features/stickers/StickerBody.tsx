import { useEffect, useState } from 'react'
import { downloadChatMediaToCacheV1, openCachedChatMediaV1 } from '@kutup/chat-core/media'
import type { ChatAttachmentDescriptorV1 } from '@kutup/chat-core/types'
import { freshAccessToken } from '@kutup/session/client'
import { useChat } from '../../app/chatStore'

/**
 * A sticker in the timeline: fetched and shown at once (stickers are small),
 * large and without a bubble; the thumbnail stands in until then.
 */
export function StickerBody({ attachment, accepted }: { attachment: ChatAttachmentDescriptorV1; accepted: boolean }) {
  const { mediaCache: cache } = useChat()
  const [url, setUrl] = useState<string | null>(null)

  useEffect(() => {
    if (!cache || !accepted) return
    const controller = new AbortController()
    let objectUrl: string | null = null
    void (async () => {
      try {
        await downloadChatMediaToCacheV1(cache, attachment, await freshAccessToken(), undefined, controller.signal)
        const opened = await openCachedChatMediaV1(cache, attachment, controller.signal)
        if (controller.signal.aborted) return
        objectUrl = URL.createObjectURL(opened.blob)
        setUrl(objectUrl)
      } catch (error) {
        if (!controller.signal.aborted) console.warn('chat: sticker not shown', error)
      }
    })()
    return () => {
      controller.abort()
      if (objectUrl) URL.revokeObjectURL(objectUrl)
    }
  }, [cache, attachment, accepted])

  const preview = attachment.preview ? `data:${attachment.preview.mimeType};base64,${attachment.preview.data}` : null
  const source = url ?? preview
  return source ? (
    <img src={source} alt="" className="size-40 object-contain" data-testid="chat-sticker-image" />
  ) : (
    <span className="block size-40 animate-pulse rounded-2xl bg-muted" aria-hidden />
  )
}
