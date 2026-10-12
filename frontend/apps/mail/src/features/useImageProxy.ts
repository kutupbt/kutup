import { useEffect, useState } from 'react'
import { checkMailImages, fetchMailImage } from '@kutup/mail-core/api'

// The image proxy's side of a message (docs/plans/mail-parity.md, P5), as
// Proton's: its remote image addresses are checked against the known
// trackers as soon as it shows (nothing is fetched), and once the reader
// loads images each one comes through the Kutup server as a blob: URL.

const PARALLEL = 6

export interface ImageProxy {
  /** Known tracking pixels: address → provider ("" when only the fetch said so). */
  trackers: ReadonlyMap<string, string>
  /** Proxied images: address → blob: URL, or null when the proxy could not get it. */
  images: ReadonlyMap<string, string | null>
  /** Addresses the proxy could not get (not trackers). */
  failed: string[]
}

const NONE: ImageProxy = { trackers: new Map(), images: new Map(), failed: [] }

export function useImageProxy(urls: string[], { enabled, load }: { enabled: boolean; load: boolean }): ImageProxy {
  const key = urls.join('\n')
  const [state, setState] = useState<{ key: string } & ImageProxy>({ key, ...NONE })
  const current = state.key === key ? state : { key, ...NONE }

  // Trackers, for the reader's count and so they never load.
  useEffect(() => {
    if (!enabled || !key) return
    let live = true
    checkMailImages(key.split('\n'))
      .then((found) => {
        if (!live || found.size === 0) return
        setState((before) => {
          const base = before.key === key ? before : { key, ...NONE }
          return { ...base, trackers: new Map([...base.trackers, ...found]) }
        })
      })
      .catch(() => undefined)
    return () => {
      live = false
    }
  }, [enabled, key])

  // The images, a few at a time, shown together once all have answered.
  useEffect(() => {
    if (!enabled || !load || !key) return
    let live = true
    const created: string[] = []
    const queue = key.split('\n')
    const images = new Map<string, string | null>()
    const trackers = new Map<string, string>()
    const next = async (): Promise<void> => {
      const url = queue.shift()
      if (url === undefined || !live) return
      const result = await fetchMailImage(url)
      if (result.kind === 'image') {
        const blob = URL.createObjectURL(result.blob)
        created.push(blob)
        images.set(url, blob)
      } else if (result.kind === 'tracker') {
        trackers.set(url, '')
      } else {
        images.set(url, null)
      }
      return next()
    }
    void Promise.all(Array.from({ length: PARALLEL }, next)).then(() => {
      if (!live) return
      setState((before) => {
        const base = before.key === key ? before : { key, ...NONE }
        const allTrackers = new Map([...trackers, ...base.trackers])
        const failed = [...images].filter(([url, blob]) => blob === null && !allTrackers.has(url)).map(([url]) => url)
        return { key, trackers: allTrackers, images, failed }
      })
    })
    return () => {
      live = false
      created.forEach((blob) => URL.revokeObjectURL(blob))
    }
  }, [enabled, load, key])

  return current
}
