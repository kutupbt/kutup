import { useEffect, useState } from 'react'
import { listVersions, type VersionRow as VR } from '../../api/collab'
import VersionRow from './VersionRow'

interface Props {
  fileId: string
  /** Optional callback when the user clicks "Restore" on a version. The editor
   *  is responsible for actually restoring; the panel just emits the click. */
  onRestore?: (versionId: string) => void
}

export default function VersionHistoryPanel({ fileId, onRestore }: Props) {
  const [versions, setVersions] = useState<VR[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let alive = true
    setLoading(true)
    setError(null)
    ;(async () => {
      try {
        const v = await listVersions(fileId)
        if (alive) setVersions(v)
      } catch (e) {
        if (alive) setError(e instanceof Error ? e.message : 'load failed')
      } finally {
        if (alive) setLoading(false)
      }
    })()
    return () => { alive = false }
  }, [fileId])

  if (loading) {
    return (
      <div className="flex items-center justify-center p-8 text-sm text-muted-foreground">
        <span className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent" />
        <span className="ml-2">Loading versions…</span>
      </div>
    )
  }
  if (error) return <div className="p-4 text-sm text-destructive">Error: {error}</div>
  if (versions.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center px-4 py-12 text-center text-sm text-muted-foreground">
        <p className="font-medium text-foreground">No versions yet</p>
        <p className="mt-1 text-xs">
          Versions are saved automatically as you edit, or when you click <span className="font-medium">Save version</span>.
        </p>
      </div>
    )
  }

  return (
    <div className="flex flex-col divide-y divide-border">
      {versions.map((v) => (
        <VersionRow
          key={v.id}
          fileId={fileId}
          v={v}
          onChange={(updated) => setVersions((arr) => arr.map((x) => (x.id === v.id ? updated : x)))}
          onRestore={onRestore}
        />
      ))}
    </div>
  )
}
