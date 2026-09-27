import { useEffect, useState } from 'react'
import type { DriveFile } from '@kutup/drive-core/model'
import { thumbnailUrl } from '@kutup/drive-core/thumbnails'

/** A file's thumbnail as a URL, once loaded (null while there is none). */
export function useThumbnail(file: DriveFile, variant: 'sm' | 'lg' = 'sm'): string | null {
  const [url, setUrl] = useState<string | null>(null)
  const stamp = file.thumbnails[variant]
  useEffect(() => {
    let alive = true
    setUrl(null)
    void thumbnailUrl(file, variant).then((u) => alive && setUrl(u))
    return () => {
      alive = false
    }
    // The stored version decides; the file object churns with each listing.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [file.id, stamp, variant])
  return url
}
