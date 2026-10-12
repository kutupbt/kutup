import { useEffect, useMemo, useState } from 'react'
import { fetchMailImage } from '@kutup/mail-core/api'
import { trackerOf } from '@kutup/mail-core/trackers'

// The image proxy's side of a message (docs/plans/mail-parity.md, P5), as
// Proton's: its remote image addresses are checked against the known
// trackers here (nothing is sent), and once the reader loads images each
// other one comes through the Kutup server as a blob: URL.

const PARALLEL = 6

export interface ImageProxy {
  /** Known tracking pixels: address → provider ("" when only the server said so, after a redirect). */
  trackers: ReadonlyMap<string, string>
  /** Proxied images: address → blob: URL, or null when the proxy could not get it. */
  images: ReadonlyMap<string, string | null>
  /** Addresses the proxy could not get (not trackers, not refused for being busy). */
  failed: string[]
}

interface Loaded {
  key: string
  trackers: Map<string, string>
  images: Map<string, string | null>
  failed: string[]
}

export function useImageProxy(urls: string[], { enabled, load }: { enabled: boolean; load: boolean }): ImageProxy {
  const key = urls.join('\n')
  // Trackers, for the reader's count and so they never load.
  const known = useMemo(() => {
    const found = new Map<string, string>()
    if (!enabled) return found
    for (const url of key ? key.split('\n') : []) {
      const provider = trackerOf(url)
      if (provider) found.set(url, provider)
    }
    return found
  }, [enabled, key])
  const [loaded, setLoaded] = useState<Loaded | null>(null)

  // The images, a few at a time, shown together once all have answered.
  useEffect(() => {
    if (!enabled || !load || !key) return
    let live = true
    const created: string[] = []
    const queue = key.split('\n').filter((url) => !known.has(url))
    const images = new Map<string, string | null>()
    const trackers = new Map<string, string>()
    const failed: string[] = []
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
        // Busy or over a limit: a sender can cause that, so it never offers loading directly.
        if (result.kind === 'failed') failed.push(url)
      }
      return next()
    }
    void Promise.all(Array.from({ length: PARALLEL }, next)).then(() => {
      if (live) setLoaded({ key, trackers, images, failed })
    })
    return () => {
      live = false
      created.forEach((blob) => URL.revokeObjectURL(blob))
    }
  }, [enabled, load, key, known])

  return useMemo(() => {
    const current = loaded?.key === key ? loaded : null
    return {
      trackers: current ? new Map([...current.trackers, ...known]) : known,
      images: current?.images ?? new Map(),
      failed: current?.failed ?? [],
    }
  }, [loaded, key, known])
}
