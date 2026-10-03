import { useEffect, useState } from 'react'
import { fileLocation, thumbnailPath, type DriveFile, type Folder } from '@kutup/drive-core/model'
import { thumbnailUrl } from '@kutup/drive-core/thumbnails'

/**
 * A file's thumbnail as a URL, once loaded (null while there is none). The
 * folder says where it is read: here, or relayed from another server.
 */
export function useThumbnail(file: DriveFile, variant: 'sm' | 'lg' = 'sm', folder?: Folder): string | null {
  const [url, setUrl] = useState<string | null>(null)
  const stamp = file.thumbnails[variant]
  useEffect(() => {
    let alive = true
    setUrl(null)
    const path = folder ? thumbnailPath(fileLocation(folder), file.id, variant) : undefined
    if (path === null) return
    void thumbnailUrl(file, variant, path).then((u) => alive && setUrl(u))
    return () => {
      alive = false
    }
    // The stored version decides; the file object churns with each listing.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [file.id, stamp, variant])
  return url
}
