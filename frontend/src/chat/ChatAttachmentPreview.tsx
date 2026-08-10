import { useEffect, useMemo, useState } from 'react'
import { cn } from '@/lib/utils'
import type { ChatAttachmentDescriptorV1 } from './types'
import { decodeChatMediaPreviewV1 } from './media-preview'

export function ChatAttachmentPreview({
  attachment,
  className,
  visible = true,
}: {
  attachment: ChatAttachmentDescriptorV1
  className?: string
  visible?: boolean
}) {
  const decoded = useMemo(() => {
    if (!visible) return null
    if (!attachment.preview) return null
    try {
      return decodeChatMediaPreviewV1(attachment.preview)
    } catch {
      return null
    }
  }, [attachment.preview, visible])
  const [rasterUrl, setRasterUrl] = useState<string | null>(null)

  useEffect(() => {
    if (decoded?.kind !== 'raster') {
      setRasterUrl(null)
      return
    }
    const url = URL.createObjectURL(new Blob([decoded.bytes.slice()], { type: decoded.mimeType }))
    setRasterUrl(url)
    return () => URL.revokeObjectURL(url)
  }, [decoded])

  if (!decoded) return null
  if (decoded.kind === 'waveform') {
    return (
      <div
        className={cn('flex h-12 items-center gap-px overflow-hidden rounded-lg bg-black/10 px-2', className)}
        role="img"
        aria-label={`Audio waveform for ${attachment.filename}`}
        data-testid="chat-audio-waveform-preview"
      >
        {Array.from(decoded.samples, (sample, index) => (
          <span
            // The authenticated sample position is stable and has no identity semantics.
            key={index}
            className="min-w-px flex-1 rounded-full bg-current opacity-70"
            style={{ height: `${Math.max(2, Math.round(sample / 255 * 36))}px` }}
          />
        ))}
      </div>
    )
  }
  if (!rasterUrl) return null
  return (
    <div className={cn('overflow-hidden rounded-lg bg-black/10', className)}>
      <img
        src={rasterUrl}
        alt={`Preview of ${attachment.filename}`}
        className="max-h-48 w-full object-cover"
        draggable={false}
        data-testid="chat-raster-preview"
      />
    </div>
  )
}
