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

  if (loading) return <div className="p-4 text-sm text-muted-foreground">Loading…</div>
  if (error) return <div className="p-4 text-sm text-destructive">Error: {error}</div>
  if (versions.length === 0) return <div className="p-4 text-sm text-muted-foreground">No versions yet.</div>

  return (
    <div className="flex flex-col divide-y">
      {versions.map(v => (
        <VersionRow
          key={v.id}
          fileId={fileId}
          v={v}
          onChange={(updated) => setVersions(arr => arr.map(x => x.id === v.id ? updated : x))}
          onRestore={onRestore}
        />
      ))}
    </div>
  )
}
