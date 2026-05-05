// OfficeEditor — React wrapper around the OnlyOffice bridge iframe.
//
// Phase 2a (this version): mounts /onlyoffice/inner.html in an iframe, does a
// postMessage handshake, displays bridge status. No DocsAPI, no x2t, no
// collab plumbing. The actual editor mount lands in phase 2b.
//
// The split is intentional: the bridge page is plain HTML/JS so it can run
// inside its own origin-shaped sandbox alongside OnlyOffice's deeply-nested
// iframes; this React wrapper owns the user-facing chrome (status text,
// errors) and is the only side that talks to kutup state via Redux.

import { useEffect, useRef, useState } from 'react'

interface Props {
  fileId: string
  filename: string
  collectionMaster: Uint8Array
  initialBytes?: Uint8Array
}

type DocType = 'docx' | 'xlsx' | 'pptx'

function detectType(filename: string): DocType | null {
  const ext = filename.split('.').pop()?.toLowerCase() ?? ''
  if (ext === 'docx') return 'docx'
  if (ext === 'xlsx') return 'xlsx'
  if (ext === 'pptx') return 'pptx'
  return null
}

// All postMessage envelopes we exchange with inner.html. Phase 2b/2c/2d will
// add init, save, op, lock, etc. Keeping the shape narrow + typed up front
// so additions don't drift.
type FromBridge =
  | { type: 'ready'; docType: string | null }
  | { type: 'pong' }
  | { type: 'init-ack' }
type ToBridge =
  | { type: 'ping' }
  | { type: 'init'; payload: InitPayload }

interface InitPayload {
  type: DocType
  filename: string
  fileId: string
}

export default function OfficeEditor({ fileId, filename }: Props) {
  const iframeRef = useRef<HTMLIFrameElement>(null)
  const [bridgeReady, setBridgeReady] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const docType = detectType(filename)

  useEffect(() => {
    if (!docType) {
      setError(`Unsupported office extension for ${filename}`)
      return
    }

    function send(msg: ToBridge) {
      const iframe = iframeRef.current
      if (!iframe || !iframe.contentWindow) return
      iframe.contentWindow.postMessage(msg, window.location.origin)
    }

    function onMessage(e: MessageEvent<FromBridge>) {
      if (e.origin !== window.location.origin) return
      const iframe = iframeRef.current
      if (!iframe || e.source !== iframe.contentWindow) return
      const msg = e.data
      if (!msg || typeof msg !== 'object') return

      switch (msg.type) {
        case 'ready':
          setBridgeReady(true)
          send({
            type: 'init',
            payload: { type: docType!, filename, fileId },
          })
          return
        case 'init-ack':
          // Phase 2b will start the actual editor mount in response.
          return
      }
    }

    window.addEventListener('message', onMessage)
    return () => window.removeEventListener('message', onMessage)
  }, [docType, filename, fileId])

  if (error) {
    return (
      <div className="flex h-full w-full items-center justify-center p-6 text-sm text-destructive">
        {error}
      </div>
    )
  }

  return (
    <div className="flex h-full w-full flex-col">
      <div className="flex h-9 shrink-0 items-center gap-2 border-b border-border bg-muted/30 px-4 text-xs text-muted-foreground">
        <span className={`inline-block h-2 w-2 rounded-full ${bridgeReady ? 'bg-emerald-500' : 'bg-amber-500 animate-pulse'}`} />
        <span>
          OnlyOffice bridge · {bridgeReady ? 'connected' : 'connecting…'}
          {docType && ` · ${docType}`}
        </span>
      </div>
      <iframe
        ref={iframeRef}
        title={filename}
        src={`/onlyoffice/inner.html?type=${docType}&fileId=${encodeURIComponent(fileId)}`}
        className="flex-1 border-0"
        // sandbox left default for now; phase 2b will narrow once we know
        // exactly which capabilities OnlyOffice's editor needs.
      />
    </div>
  )
}
