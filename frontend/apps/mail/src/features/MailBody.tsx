import { ImageOff, ShieldCheck } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import { useTheme } from 'next-themes'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { useAddImageSender, useImageSenders, useMailSettings } from '@kutup/mail-core/api'
import type { ParsedMessage } from '@kutup/mail-core/mime'
import { plainTextDocument, sanitizeMailHtml, type FrameLook, type SanitizedHtml } from '@kutup/mail-core/sanitize'
import type { CleanedLink } from '@kutup/mail-core/trackingLinks'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { cn } from '@kutup/ui/lib/cn'
import { openComposer } from './composerState'
import { LinkConfirm } from './LinkConfirm'
import { leadsOutside } from './links'
import { useImageProxy } from './useImageProxy'

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
 * this message, as Proton offers. With tracker protection (on unless turned
 * off) they come through the Kutup image proxy, known tracking pixels never
 * load, and links lose their tracking parameters; an image the proxy cannot
 * get loads directly only when the reader asks.
 */
export function MailBody({ parsed, suspicious = false, sender }: { parsed: ParsedMessage; suspicious?: boolean; sender?: string }) {
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
  // Remote images load at once when the reader said so for every sender or
  // for this one (never in Spam); otherwise after the reader's question.
  const imageSenders = useImageSenders()
  const addImageSender = useAddImageSender()
  const trusted = !suspicious && (settings.data?.remoteImages === 'always' || (!!sender && (imageSenders.data?.some((s) => s.address === sender.toLowerCase()) ?? false)))
  const [loaded, setLoaded] = useState(false)
  const allowRemote = loaded || trusted
  const protect = settings.data?.imageProxy ?? true
  // The message's remote addresses, read from the last rendering (they do not
  // depend on what loaded).
  const [remoteUrls, setRemoteUrls] = useState<string[]>([])
  const proxy = useImageProxy(remoteUrls, { enabled: protect, load: allowRemote })
  const [direct, setDirect] = useState(false)
  const [showingTrackers, setShowingTrackers] = useState(false)
  const [askingImages, setAskingImages] = useState(false)
  const [always, setAlways] = useState(false)
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

  const rendered = useMemo<SanitizedHtml>(() => {
    const look: FrameLook = { dark: darkTheme, colors: themeColors(), quoteLabel: t('read.showQuoted') }
    const resolveRemote = protect
      ? (url: string) => {
          if (proxy.trackers.has(url)) return null
          const image = proxy.images.get(url)
          if (image) return image
          return image === null && direct ? url : null
        }
      : undefined
    if (parsed.html) return sanitizeMailHtml(parsed.html, { allowRemote, resolveRemote, cleanLinks: protect, inlineImages: inline, look })
    const cleanedLinks: CleanedLink[] = []
    const document = plainTextDocument(parsed.text ?? '', look, protect ? cleanedLinks : undefined)
    return { document, remoteBlocked: false, remoteUrls: [], cleanedLinks, dark: darkTheme, themed: true }
  }, [parsed, allowRemote, protect, proxy, direct, inline, darkTheme, t])
  const remoteKey = rendered.remoteUrls.join('\n')
  useEffect(() => {
    setRemoteUrls(remoteKey ? remoteKey.split('\n') : [])
  }, [remoteKey])
  const trackerCount = proxy.trackers.size
  const cleanedCount = rendered.cleanedLinks.length

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
          <Button variant="outline" size="sm" onClick={() => setAskingImages(true)}>
            {t('read.loadRemote')}
          </Button>
        </div>
      ) : null}
      {protect && allowRemote && proxy.failed.length > 0 && !direct ? (
        <div className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-muted/50 px-3 py-2 text-sm">
          <ImageOff className="size-4 text-muted-foreground" aria-hidden />
          <span className="flex-1">{t('tracking.proxyFailed')}</span>
          <Button variant="outline" size="sm" title={t('tracking.loadDirectHint')} onClick={() => setDirect(true)}>
            {t('tracking.loadDirect')}
          </Button>
        </div>
      ) : null}
      {protect && (trackerCount > 0 || cleanedCount > 0) ? (
        <button
          type="button"
          className="flex items-center gap-1.5 rounded-md text-xs text-muted-foreground hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          onClick={() => setShowingTrackers(true)}
        >
          <ShieldCheck className="size-3.5 text-status-ok" aria-hidden />
          {[
            trackerCount > 0 ? t('tracking.trackersBlocked', { count: trackerCount }) : null,
            cleanedCount > 0 ? t('tracking.linksCleaned', { count: cleanedCount }) : null,
          ]
            .filter(Boolean)
            .join(' · ')}
        </button>
      ) : null}
      {showingTrackers ? (
        <Dialog open onOpenChange={(open) => !open && setShowingTrackers(false)}>
          <DialogContent className="max-w-lg">
            <DialogHeader>
              <DialogTitle>{t('tracking.title')}</DialogTitle>
              <DialogDescription>{t('tracking.body')}</DialogDescription>
            </DialogHeader>
            <div className="max-h-[50vh] space-y-4 overflow-y-auto text-sm">
              <section>
                <h3 className="font-medium">{t('tracking.trackersBlocked', { count: trackerCount })}</h3>
                {trackerCount > 0 ? (
                  <ul className="mt-1 space-y-1" aria-label={t('tracking.trackersList')}>
                    {[...proxy.trackers].map(([url, provider]) => (
                      <li key={url} className="min-w-0">
                        <span className="font-medium">{provider || t('tracking.unknownProvider')}</span>
                        <span className="block truncate text-xs text-muted-foreground" title={url}>
                          {url}
                        </span>
                      </li>
                    ))}
                  </ul>
                ) : null}
              </section>
              <section>
                <h3 className="font-medium">{t('tracking.linksCleaned', { count: cleanedCount })}</h3>
                {cleanedCount > 0 ? (
                  <ul className="mt-1 space-y-2" aria-label={t('tracking.linksList')}>
                    {rendered.cleanedLinks.map((link, index) => (
                      <li key={`${index}-${link.original}`} className="min-w-0">
                        <span className="block truncate" title={link.cleaned}>
                          {link.cleaned}
                        </span>
                        <span className="block text-xs text-muted-foreground">{t('tracking.removed', { names: link.removed.join(', ') })}</span>
                      </li>
                    ))}
                  </ul>
                ) : null}
              </section>
            </div>
            <DialogFooter>
              <Button onClick={() => setShowingTrackers(false)}>{t('common.close')}</Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      ) : null}
      {askingImages ? (
        <Dialog open onOpenChange={(open) => !open && setAskingImages(false)}>
          <DialogContent className="max-w-md">
            <DialogHeader>
              <DialogTitle>{t('remoteImages.title')}</DialogTitle>
              <DialogDescription>
                {t('remoteImages.body')} {protect ? t('remoteImages.bodyProxy') : null}
              </DialogDescription>
            </DialogHeader>
            {sender && !suspicious ? (
              <label className="flex items-center gap-2 text-sm">
                <Checkbox checked={always} onCheckedChange={(on) => setAlways(on === true)} />
                <span className="min-w-0 break-all">{t('remoteImages.always', { address: sender })}</span>
              </label>
            ) : null}
            <DialogFooter>
              <Button variant="outline" onClick={() => setAskingImages(false)}>
                {t('common.cancel')}
              </Button>
              <Button
                onClick={() => {
                  setLoaded(true)
                  setAskingImages(false)
                  if (always && sender && !suspicious) {
                    addImageSender.mutate(sender, {
                      onSuccess: () => toast.success(t('remoteImages.remembered', { address: sender })),
                      onError: (error) => toast.error(apiErrorMessage(error, t('common.tryAgain'))),
                    })
                  }
                }}
              >
                {t('remoteImages.load')}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
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
