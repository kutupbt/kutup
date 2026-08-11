import { useEffect, useMemo, useState } from 'react'
import { cn } from '@/lib/utils'
import type { ChatAttachmentDescriptorV1 } from './types'
import { decodeChatMediaPreviewV1 } from './media-preview'

export function ChatAttachmentPreview({
  attachment,
  className,
  visible = true,
  onActivate,
  activationLabel,
  activationMode = 'open',
  disabled = false,
  progress = 0,
  onSeek,
}: {
  attachment: ChatAttachmentDescriptorV1
  className?: string
  visible?: boolean
  onActivate?: () => void
  activationLabel?: string
  activationMode?: 'open' | 'download'
  disabled?: boolean
  progress?: number
  onSeek?: (position: number) => void
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
    const waveform = (
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
            className={cn(
              'min-w-px flex-1 rounded-full bg-current transition-opacity',
              index < decoded.samples.length * progress ? 'opacity-80' : 'opacity-25',
            )}
            style={{ height: `${Math.max(2, Math.round(sample / 255 * 36))}px` }}
          />
        ))}
      </div>
    )
    if (!onActivate && !onSeek) return waveform
    return (
      <button
        type="button"
        className="block w-full rounded-lg text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-60"
        onClick={event => {
          if (onSeek) {
            const bounds = event.currentTarget.getBoundingClientRect()
            onSeek(Math.min(1, Math.max(0, (event.clientX - bounds.left) / bounds.width)))
          } else {
            onActivate?.()
          }
        }}
        aria-label={activationLabel ?? `Play ${attachment.filename}`}
        disabled={disabled}
        aria-valuemin={onSeek ? 0 : undefined}
        aria-valuemax={onSeek ? 100 : undefined}
        aria-valuenow={onSeek ? Math.round(progress * 100) : undefined}
      >
        {waveform}
      </button>
    )
  }
  if (!rasterUrl) return null
  const raster = (
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
  if (!onActivate) return raster
  return (
    <button
      type="button"
      className={cn(
        'block w-full rounded-lg text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-60',
        activationMode === 'download' ? 'cursor-pointer' : 'cursor-zoom-in',
      )}
      onClick={onActivate}
      aria-label={activationLabel ?? `Open ${attachment.filename}`}
      disabled={disabled}
    >
      {raster}
    </button>
  )
}
