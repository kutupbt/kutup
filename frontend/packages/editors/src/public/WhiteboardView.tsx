// A whiteboard as last saved, to look at: Excalidraw in its view mode, with
// no session and no live editing (a public link's page). Pictures saved in
// the file show at once; any it lists without carrying them are fetched
// through the link, as the editor fetches them from Drive.

import { Suspense, lazy, useMemo, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import type { BinaryFileData, DataURL, ExcalidrawImperativeAPI, ExcalidrawInitialDataState } from '@excalidraw/excalidraw/types'
import type { OrderedExcalidrawElement } from '@excalidraw/excalidraw/element/types'
import { fetchAsset } from '@kutup/collab/whiteboardAssets'
import { useResolvedTheme } from '../useResolvedTheme'

import '@excalidraw/excalidraw/index.css'

const Excalidraw = lazy(() => import('@excalidraw/excalidraw').then((m) => ({ default: m.Excalidraw })))

export interface WhiteboardViewProps {
  fileId: string
  /** The file's current key and its generation. */
  fileKey: Uint8Array
  keyGeneration: number
  /** The file key of an older generation: pictures stored before a re-key. */
  fileKeyAt: (generation: number) => Promise<Uint8Array>
  /** Where the file's pictures are fetched (`${assetBase}/assets/:id`). */
  assetBase: string
  /** The .excalidraw file. */
  bytes: Uint8Array
}

export default function WhiteboardView({ fileId, fileKey, keyGeneration, fileKeyAt, assetBase, bytes }: WhiteboardViewProps) {
  const { t } = useTranslation()
  const theme = useResolvedTheme()
  const fetched = useRef(new Set<string>())

  const initialData = useMemo<ExcalidrawInitialDataState | null>(() => {
    try {
      const json = JSON.parse(new TextDecoder().decode(bytes)) as {
        elements?: OrderedExcalidrawElement[]
        appState?: Record<string, unknown>
        files?: Record<string, BinaryFileData>
      }
      const appState = { ...(json.appState ?? {}) }
      delete appState.collaborators
      return { elements: json.elements ?? [], appState, files: json.files ?? {}, scrollToContent: true }
    } catch {
      return null
    }
  }, [bytes])

  function fetchMissing(api: ExcalidrawImperativeAPI) {
    const have = api.getFiles()
    for (const element of initialData?.elements ?? []) {
      if (element.type !== 'image') continue
      const id = element.fileId
      if (element.isDeleted || !id || have[id] || fetched.current.has(id)) continue
      fetched.current.add(id)
      void fetchAsset({ fileId, assetId: id, generation: keyGeneration }, fileKey, fileKeyAt, assetBase)
        .then((plain) => {
          const dataURL = new TextDecoder().decode(plain)
          const mimeType = (/^data:([^;]+);/i.exec(dataURL)?.[1] ?? 'image/png') as BinaryFileData['mimeType']
          api.addFiles([{ id, mimeType, dataURL: dataURL as DataURL, created: Date.now() }])
        })
        .catch(() => undefined)
    }
  }

  if (!initialData) {
    return <div className="flex h-full items-center justify-center p-6 text-sm text-muted-foreground">{t('editor.whiteboard.unreadable')}</div>
  }
  return (
    <div className="h-full w-full">
      <Suspense fallback={<div className="p-4 text-sm text-muted-foreground">{t('editor.whiteboard.loading')}</div>}>
        <Excalidraw theme={theme} initialData={initialData} viewModeEnabled excalidrawAPI={fetchMissing} />
      </Suspense>
    </div>
  )
}
