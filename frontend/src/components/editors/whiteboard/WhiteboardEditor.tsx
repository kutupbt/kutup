// SPDX-FileCopyrightText: 2026 kutup contributors
// SPDX-License-Identifier: AGPL-3.0-only
//
// WhiteboardEditor — React wrapper around Excalidraw.
//
// Mounts <Excalidraw /> in a flex container; loads existing scene from
// initialBytes if present (decoded as the .excalidraw JSON shape), or
// starts empty for cold-create.
//
// Imperative save() handle: extracts the current scene via the
// excalidrawAPI ref, calls serializeAsJSON to get the canonical
// .excalidraw JSON, encodes to UTF-8 bytes. Parent (FileEditorPage)
// encrypts + uploads via the existing snapshot endpoints.
//
// Excalidraw's CSS must be imported globally — see app entry / this file.

import {
  forwardRef,
  Suspense,
  lazy,
  useImperativeHandle,
  useMemo,
  useRef,
  type Ref,
} from 'react'
import { serializeAsJSON } from '@excalidraw/excalidraw'
import type {
  ExcalidrawImperativeAPI,
  ExcalidrawInitialDataState,
} from '@excalidraw/excalidraw/types'

// Excalidraw's stylesheet must be loaded for the canvas + UI chrome.
// Imported once at module level so any consumer of this component pulls
// it in transparently.
import '@excalidraw/excalidraw/index.css'

const Excalidraw = lazy(() =>
  import('@excalidraw/excalidraw').then((m) => ({ default: m.Excalidraw })),
)

export interface WhiteboardEditorHandle {
  /** Returns the current scene as the canonical .excalidraw JSON bytes. */
  save: () => Promise<{ bytes: Uint8Array }>
}

interface Props {
  fileId: string
  filename: string
  collectionMaster: Uint8Array
  initialBytes?: Uint8Array
}

function WhiteboardEditorBase(
  { initialBytes }: Props,
  ref: Ref<WhiteboardEditorHandle>,
) {
  const apiRef = useRef<ExcalidrawImperativeAPI | null>(null)

  // Parse initialBytes once. Excalidraw's JSON wrapper has shape
  // {type, version, source, elements, appState, files}; we map it to
  // ExcalidrawInitialDataState which only needs {elements, appState, files}.
  const initialData = useMemo<ExcalidrawInitialDataState | null>(() => {
    if (!initialBytes || initialBytes.length === 0) return null
    try {
      const text = new TextDecoder().decode(initialBytes)
      const json = JSON.parse(text)
      // Strip live UI state that shouldn't carry across sessions.
      const appState = { ...(json.appState ?? {}) }
      delete appState.collaborators
      return {
        elements: json.elements ?? [],
        appState,
        files: json.files ?? {},
        scrollToContent: true,
      }
    } catch (err) {
      console.warn('whiteboard: failed to parse initialBytes', err)
      return null
    }
  }, [initialBytes])

  useImperativeHandle(
    ref,
    () => ({
      save: async () => {
        const api = apiRef.current
        if (!api) throw new Error('whiteboard editor not ready')
        const elements = api.getSceneElements()
        const appState = api.getAppState()
        const files = api.getFiles()
        // 'local' shape preserves UI state (zoom, theme, etc.) — what we
        // want for a personal-document save flow. 'database' would strip
        // some fields suited for shared backends.
        const json = serializeAsJSON(elements, appState, files, 'local')
        const bytes = new TextEncoder().encode(json)
        return { bytes }
      },
    }),
    [],
  )

  return (
    <div className="h-full w-full">
      <Suspense
        fallback={<div className="p-4 text-sm text-muted-foreground">Loading whiteboard…</div>}
      >
        <Excalidraw
          initialData={initialData ?? undefined}
          excalidrawAPI={(api) => { apiRef.current = api }}
        />
      </Suspense>
    </div>
  )
}

const WhiteboardEditor = forwardRef<WhiteboardEditorHandle, Props>(WhiteboardEditorBase)
export default WhiteboardEditor
