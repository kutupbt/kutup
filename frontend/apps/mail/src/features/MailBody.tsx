import { ImageOff } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import { useTheme } from 'next-themes'
import { useTranslation } from 'react-i18next'
import type { ParsedMessage } from '@kutup/mail-core/mime'
import { plainTextDocument, sanitizeMailHtml, type FrameLook } from '@kutup/mail-core/sanitize'
import { Button } from '@kutup/ui/components/button'
import { cn } from '@kutup/ui/lib/cn'

/** The theme's own colours, for a body that follows the theme. */
function themeColors(): FrameLook['colors'] {
  const style = getComputedStyle(document.documentElement)
  const read = (name: string, fallback: string) => style.getPropertyValue(name).trim() || fallback
  return {
    background: read('--background', '#111318'),
    text: read('--foreground', '#e5e7eb'),
    muted: read('--muted-foreground', '#9ca3af'),
    link: read('--primary', '#93c5fd'),
    border: read('--border', '#374151'),
  }
}

/**
 * A message's body in a sandboxed iframe: no scripts, its own CSP, sized to
 * its content. Remote images stay blocked until the reader loads them for
 * this message, as Proton offers (it proxies them; Kutup has no proxy yet).
 */
export function MailBody({ parsed }: { parsed: ParsedMessage }) {
  const { t } = useTranslation()
  const { resolvedTheme } = useTheme()
  const darkTheme = resolvedTheme === 'dark'
  const [allowRemote, setAllowRemote] = useState(false)
  const frame = useRef<HTMLIFrameElement>(null)
  const [height, setHeight] = useState(120)

  // Inline images (cid:) from the message's own parts.
  const inline = useMemo(() => {
    const urls = new Map<string, string>()
    for (const part of parsed.attachments) {
      if (part.contentId && part.mimeType.startsWith('image/')) {
        urls.set(part.contentId, URL.createObjectURL(new Blob([part.content as BlobPart], { type: part.mimeType })))
      }
    }
    return urls
  }, [parsed])
  useEffect(() => () => inline.forEach((url) => URL.revokeObjectURL(url)), [inline])

  const rendered = useMemo(() => {
    const look: FrameLook = { dark: darkTheme, colors: themeColors(), quoteLabel: t('read.showQuoted') }
    if (parsed.html) return sanitizeMailHtml(parsed.html, { allowRemote, inlineImages: inline, look })
    return { document: plainTextDocument(parsed.text ?? '', look), remoteBlocked: false, dark: darkTheme, themed: true }
  }, [parsed, allowRemote, inline, darkTheme, t])

  useEffect(() => {
    const iframe = frame.current
    if (!iframe) return
    let observer: ResizeObserver | null = null
    const fit = () => {
      const body = iframe.contentDocument?.body
      if (!body) return
      setHeight(Math.max(60, body.scrollHeight + 8))
      observer?.disconnect()
      observer = new ResizeObserver(() => setHeight(Math.max(60, body.scrollHeight + 8)))
      observer.observe(body)
    }
    iframe.addEventListener('load', fit)
    return () => {
      iframe.removeEventListener('load', fit)
      observer?.disconnect()
    }
  }, [rendered])

  return (
    <div className="space-y-2">
      {rendered.remoteBlocked ? (
        <div className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-muted/50 px-3 py-2 text-sm">
          <ImageOff className="size-4 text-muted-foreground" aria-hidden />
          <span className="flex-1">{t('read.remoteBlocked')}</span>
          <Button variant="outline" size="sm" onClick={() => setAllowRemote(true)}>
            {t('read.loadRemote')}
          </Button>
        </div>
      ) : null}
      <iframe
        ref={frame}
        title={t('read.body')}
        srcDoc={rendered.document}
        sandbox="allow-same-origin allow-popups allow-popups-to-escape-sandbox"
        referrerPolicy="no-referrer"
        className={cn(
          'w-full border-0',
          // Mail that paints itself keeps its sender's look: on white, in a frame, as Proton shows it.
          rendered.themed ? 'bg-transparent' : darkTheme ? 'rounded-md bg-white p-3' : 'bg-white',
        )}
        style={{ height: height + (darkTheme && !rendered.themed ? 24 : 0) }}
      />
    </div>
  )
}
