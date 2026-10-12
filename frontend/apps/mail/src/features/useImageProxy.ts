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

const NONE: ImageProxy & { checked: boolean } = { trackers: new Map(), images: new Map(), failed: [], checked: false }

export function useImageProxy(urls: string[], { enabled, load }: { enabled: boolean; load: boolean }): ImageProxy {
  const key = urls.join('\n')
  const [state, setState] = useState<{ key: string; checked: boolean } & ImageProxy>({ key, ...NONE })
  const current = state.key === key ? state : { key, ...NONE }

  // Trackers, for the reader's count and so they never load.
  useEffect(() => {
    if (!enabled || !key) return
    let live = true
    const done = (found: Map<string, string>) => {
      if (!live) return
      setState((before) => {
        const base = before.key === key ? before : { key, ...NONE }
        return { ...base, checked: true, trackers: new Map([...base.trackers, ...found]) }
      })
    }
    checkMailImages(key.split('\n'))
      .then(done)
      .catch(() => done(new Map()))
    return () => {
      live = false
    }
  }, [enabled, key])

  // The images, a few at a time, shown together once all have answered;
  // known trackers are never asked for.
  const checked = current.checked
  const known = current.trackers
  useEffect(() => {
    if (!enabled || !load || !key || !checked) return
    let live = true
    const created: string[] = []
    const queue = key.split('\n').filter((url) => !known.has(url))
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
        return { key, checked: true, trackers: allTrackers, images, failed }
      })
    })
    return () => {
      live = false
      created.forEach((blob) => URL.revokeObjectURL(blob))
    }
    // `known` is settled once `checked` is: the check runs once per message.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, load, key, checked])

  return current
}
