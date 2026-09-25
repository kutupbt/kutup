import { Loader2, X } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import type { ChatLinkPreviewV1 } from '@kutup/chat-core/types'
import { Button } from '@kutup/ui/components/button'
import { cn } from '@kutup/ui/lib/cn'

function host(url: string): string {
  try {
    return new URL(url).host
  } catch {
    return url
  }
}

/** A link preview in a message bubble: picture, title, description, site. */
export function LinkPreviewCard({ preview, outgoing }: { preview: ChatLinkPreviewV1; outgoing: boolean }) {
  return (
    <a
      href={preview.url}
      target="_blank"
      rel="noopener noreferrer nofollow"
      className={cn(
        'mb-1.5 block overflow-hidden rounded-xl border outline-none focus-visible:ring-2 focus-visible:ring-ring',
        outgoing ? 'border-primary-foreground/25 bg-primary-foreground/10' : 'border-border bg-background/60',
      )}
      data-testid="chat-link-preview"
    >
      {preview.image ? (
        <img
          src={`data:${preview.image.contentType};base64,${preview.image.data}`}
          alt=""
          className="max-h-48 w-full object-cover"
        />
      ) : null}
      <span className="block px-3 py-2">
        <span className="line-clamp-2 block text-sm font-semibold">{preview.title}</span>
        {preview.description ? (
          <span className={cn('line-clamp-2 block text-xs', outgoing ? 'opacity-85' : 'text-muted-foreground')}>{preview.description}</span>
        ) : null}
        <span className={cn('mt-0.5 block truncate text-xs', outgoing ? 'opacity-75' : 'text-muted-foreground')}>{host(preview.url)}</span>
      </span>
    </a>
  )
}

/** The preview above the message box while writing, with a way to drop it. */
export function ComposerLinkPreview({
  state,
  onDismiss,
}: {
  state: { status: 'loading'; url: string } | { status: 'ready'; preview: ChatLinkPreviewV1 }
  onDismiss: () => void
}) {
  const { t } = useTranslation()
  return (
    <div className="mb-2 flex items-center gap-3 rounded-lg border border-border bg-muted/60 p-2 text-sm" data-testid="chat-composer-link-preview">
      {state.status === 'loading' ? (
        <>
          <Loader2 className="size-4 shrink-0 animate-spin text-muted-foreground" aria-hidden />
          <span className="min-w-0 flex-1 truncate text-muted-foreground">{t('chat.linkPreviews.loading', { host: host(state.url) })}</span>
        </>
      ) : (
        <>
          {state.preview.image ? (
            <img
              src={`data:${state.preview.image.contentType};base64,${state.preview.image.data}`}
              alt=""
              className="size-12 shrink-0 rounded-md object-cover"
            />
          ) : null}
          <span className="min-w-0 flex-1">
            <span className="block truncate font-semibold">{state.preview.title}</span>
            {state.preview.description ? (
              <span className="block truncate text-xs text-muted-foreground">{state.preview.description}</span>
            ) : null}
            <span className="block truncate text-xs text-muted-foreground">{host(state.preview.url)}</span>
          </span>
        </>
      )}
      <Button type="button" variant="ghost" size="icon" className="size-7 shrink-0" onClick={onDismiss} aria-label={t('chat.linkPreviews.remove')}>
        <X />
      </Button>
    </div>
  )
}
