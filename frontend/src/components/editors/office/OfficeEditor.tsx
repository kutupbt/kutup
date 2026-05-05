// SPDX-FileCopyrightText: 2026 kutup contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Part of kutup's optional OnlyOffice integration. This file is licensed
// AGPL-3.0-or-later because it drives the AGPL OnlyOffice bridge. Code
// outside frontend/src/components/editors/office/ and
// frontend/public/onlyoffice/ remains MIT. See ./LICENSE.md.
//
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

import { useEffect, useImperativeHandle, useRef, useState, forwardRef, type Ref } from 'react'

export interface OfficeEditorHandle {
  /** Asks inner.html to extract the doc binary, run x2t to OOXML, and
   *  return the bytes. Resolves with the converted bytes + format
   *  ('docx'|'xlsx'|'pptx') so callers know what extension to encode. */
  save: () => Promise<{ bytes: Uint8Array; format: 'docx' | 'xlsx' | 'pptx' }>
}

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
  | { type: 'save-result'; requestId: number; bytes?: Uint8Array; format?: DocType; error?: string }
type ToBridge =
  | { type: 'ping' }
  | { type: 'init'; payload: InitPayload }
  | { type: 'save-request'; requestId: number }

interface InitPayload {
  type: DocType
  filename: string
  fileId: string
  /** Decrypted OOXML bytes for an existing file. Phase 3b: inner.html runs
   *  x2tConvert to turn this into OnlyOffice's .bin format on first open.
   *  Undefined or 1-byte placeholders mean "freshly created — use the empty
   *  template instead". */
  initialBytes?: Uint8Array
}

function OfficeEditorBase(
  { fileId, filename, initialBytes }: Props,
  ref: Ref<OfficeEditorHandle>,
) {
  const iframeRef = useRef<HTMLIFrameElement>(null)
  const [bridgeReady, setBridgeReady] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const docType = detectType(filename)
  // requestId → resolver/rejecter for in-flight save() calls.
  const pendingSavesRef = useRef<Map<number, {
    resolve: (v: { bytes: Uint8Array; format: DocType }) => void
    reject: (e: Error) => void
  }>>(new Map())
  const nextSaveIdRef = useRef(1)

  useImperativeHandle(ref, () => ({
    save: () =>
      new Promise((resolve, reject) => {
        const iframe = iframeRef.current
        if (!iframe || !iframe.contentWindow) {
          reject(new Error('editor iframe not mounted'))
          return
        }
        if (!docType) {
          reject(new Error('unsupported file extension'))
          return
        }
        const requestId = nextSaveIdRef.current++
        pendingSavesRef.current.set(requestId, { resolve, reject })
        iframe.contentWindow.postMessage(
          { type: 'save-request', requestId } satisfies ToBridge,
          window.location.origin,
        )
      }),
  }), [docType])

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
            payload: {
              type: docType!,
              filename,
              fileId,
              initialBytes,
            },
          })
          return
        case 'init-ack':
          // Phase 2b will start the actual editor mount in response.
          return
        case 'save-result': {
          const pending = pendingSavesRef.current.get(msg.requestId)
          if (!pending) return
          pendingSavesRef.current.delete(msg.requestId)
          if (msg.error) {
            pending.reject(new Error(msg.error))
          } else if (msg.bytes && msg.format) {
            const u8 = msg.bytes instanceof Uint8Array ? msg.bytes : new Uint8Array(msg.bytes)
            pending.resolve({ bytes: u8, format: msg.format })
          } else {
            pending.reject(new Error('save returned no bytes'))
          }
          return
        }
      }
    }

    window.addEventListener('message', onMessage)
    return () => window.removeEventListener('message', onMessage)
  }, [docType, filename, fileId, initialBytes])

  if (error) {
    return (
      <div className="flex h-full w-full items-center justify-center p-6 text-sm text-destructive">
        {error}
      </div>
    )
  }

  // bridgeReady is read by FileEditorPage via a custom event to surface the
  // status in the page header instead of stealing vertical space here.
  void bridgeReady

  return (
    <iframe
      ref={iframeRef}
      title={filename}
      src={`/onlyoffice/inner.html?type=${docType}&fileId=${encodeURIComponent(fileId)}`}
      className="block h-full w-full border-0"
    />
  )
}

const OfficeEditor = forwardRef<OfficeEditorHandle, Props>(OfficeEditorBase)
export default OfficeEditor
