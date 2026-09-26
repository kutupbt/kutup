import { useEffect, useState } from 'react'
import { thumbnailUrl } from '@kutup/drive-core/thumbnails'
import type { Photo } from '../library/library'

/** A photo's small thumbnail as a URL, once loaded (null while there is none). */
export function useThumbnail(photo: Photo, variant: 'sm' | 'lg' = 'sm'): string | null {
  const [url, setUrl] = useState<string | null>(null)
  const stamp = photo.file.thumbnails[variant]
  useEffect(() => {
    let alive = true
    setUrl(null)
    void thumbnailUrl(photo.file, variant).then((u) => alive && setUrl(u))
    return () => {
      alive = false
    }
    // The stored version decides; the file object churns with each listing.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [photo.id, stamp, variant])
  return url
}
