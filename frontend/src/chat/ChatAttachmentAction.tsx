import { Download, Eye, HardDrive, Loader2, Play, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import type { ChatMediaViewerKindV1 } from './media'
import type { ChatAttachmentDescriptorV1 } from './types'

const PROGRESS_RING_RADIUS = 14
const PROGRESS_RING_LENGTH = 2 * Math.PI * PROGRESS_RING_RADIUS

export type ChatAttachmentCacheState = 'checking' | 'remote' | 'downloading' | 'available'

export function ChatAttachmentAction({
  attachment,
  cacheState,
  downloadProgress,
  viewerKind,
  outgoing = false,
  disabled = false,
  onDownload,
  onCancel,
  onOpen,
  onError,
}: {
  attachment: ChatAttachmentDescriptorV1
  cacheState: ChatAttachmentCacheState
  downloadProgress: number
  viewerKind: ChatMediaViewerKindV1 | null
  outgoing?: boolean
  disabled?: boolean
  onDownload: () => Promise<void>
  onCancel: () => void
  onOpen: () => void
  onError: () => void
}) {
  const canOpen = cacheState === 'available' && viewerKind !== null
  const label = cacheState === 'downloading'
    ? `Cancel download of ${attachment.filename}`
    : cacheState === 'remote'
      ? `Download ${attachment.filename} into Kutup`
      : canOpen
        ? `Open ${attachment.filename}`
        : cacheState === 'available'
          ? `${attachment.filename} is available in Kutup`
          : `Preparing ${attachment.filename}`

  const handleAction = async () => {
    if (cacheState === 'downloading') {
      onCancel()
      return
    }
    if (cacheState === 'remote') {
      try {
        await onDownload()
      } catch (cause) {
        if (!(cause instanceof DOMException && cause.name === 'AbortError')) onError()
      }
      return
    }
    if (canOpen) onOpen()
  }

  return (
    <div className="relative h-8 w-8 shrink-0">
      <Button
        type="button"
        size="icon"
        variant={outgoing ? 'secondary' : 'ghost'}
        className="h-8 w-8 rounded-full"
        disabled={disabled || cacheState === 'checking' || cacheState === 'available' && !viewerKind}
        onClick={() => { void handleAction() }}
        aria-label={label}
      >
        {cacheState === 'checking'
          ? <Loader2 className="h-4 w-4 animate-spin" />
          : cacheState === 'remote'
            ? <Download className="h-4 w-4" />
            : cacheState === 'downloading'
              ? <X className="h-3.5 w-3.5" />
              : viewerKind === 'video'
                ? <Play className="h-4 w-4" />
                : viewerKind === 'image' || viewerKind === 'pdf'
                  ? <Eye className="h-4 w-4" />
                  : <HardDrive className="h-4 w-4" />}
      </Button>
      {cacheState === 'downloading' && (
        <svg
          viewBox="0 0 32 32"
          className="pointer-events-none absolute inset-0 h-8 w-8 -rotate-90 text-primary"
          aria-hidden="true"
          data-testid="chat-attachment-download-progress"
        >
          <circle cx="16" cy="16" r={PROGRESS_RING_RADIUS} fill="none" stroke="currentColor" strokeOpacity="0.2" strokeWidth="2" />
          <circle
            cx="16"
            cy="16"
            r={PROGRESS_RING_RADIUS}
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeDasharray={PROGRESS_RING_LENGTH}
            strokeDashoffset={PROGRESS_RING_LENGTH * (1 - Math.min(100, Math.max(0, downloadProgress)) / 100)}
          />
        </svg>
      )}
    </div>
  )
}
