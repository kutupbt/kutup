import { ImageOff } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import { useTheme } from 'next-themes'
import { useTranslation } from 'react-i18next'
import { useMailSettings } from '@kutup/mail-core/api'
import type { ParsedMessage } from '@kutup/mail-core/mime'
import { plainTextDocument, sanitizeMailHtml, type FrameLook } from '@kutup/mail-core/sanitize'
import { Button } from '@kutup/ui/components/button'
import { cn } from '@kutup/ui/lib/cn'
import { openComposer } from './composerState'
import { LinkConfirm } from './LinkConfirm'
import { leadsOutside } from './links'

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
export function MailBody({ parsed, suspicious = false }: { parsed: ParsedMessage; suspicious?: boolean }) {
  const { t } = useTranslation()
  const settings = useMailSettings()
  // Proton's Confirm link URLs: on unless turned off; always for a message filed as spam.
  const confirmLinks = suspicious || (settings.data?.confirmLink ?? true)
  const [confirming, setConfirming] = useState<string | null>(null)
  const linkHandler = useRef<(event: MouseEvent) => void>(() => undefined)
  linkHandler.current = (event: MouseEvent) => {
    const anchor = (event.target as Element | null)?.closest?.('a[href]')
    const href = anchor?.getAttribute('href') ?? ''
    if (!anchor || !href) return
    const doc = frame.current?.contentDocument
    // A link within the message: scroll to it.
    if (href.startsWith('#')) {
      event.preventDefault()
      const id = decodeURIComponent(href.slice(1))
      doc?.querySelector(`[id="${CSS.escape(id)}"], [name="${CSS.escape(id)}"]`)?.scrollIntoView({ behavior: 'smooth', block: 'start' })
      return
    }
    // mailto: opens the composer, as Proton's.
    if (href.toLowerCase().startsWith('mailto:')) {
      event.preventDefault()
      const to = decodeURIComponent(href.slice(7).split('?')[0] ?? '')
      openComposer({ kind: 'new', to })
      return
    }
    if (confirmLinks && leadsOutside(href)) {
      event.preventDefault()
      setConfirming(href)
    }
  }
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
    // Clicks on links, read through the same-origin frame (it runs no scripts of its own).
    const click = (event: MouseEvent) => linkHandler.current(event)
    const attach = () => iframe.contentDocument?.addEventListener('click', click)
    iframe.addEventListener('load', fit)
    iframe.addEventListener('load', attach)
    return () => {
      iframe.removeEventListener('load', fit)
      iframe.removeEventListener('load', attach)
      iframe.contentDocument?.removeEventListener('click', click)
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
      {confirming ? <LinkConfirm href={confirming} suspicious={suspicious} onClose={() => setConfirming(null)} /> : null}
    </div>
  )
}
