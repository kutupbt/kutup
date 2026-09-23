import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Loader2 } from 'lucide-react'
import { listVersions, type VersionRow as VR } from '@kutup/collab/api'
import VersionRow from './VersionRow'

interface Props {
  fileId: string
  /** Optional callback when the user clicks "Restore" on a version. The editor
   *  is responsible for actually restoring; the panel just emits the click. */
  onRestore?: (versionId: string) => void
}

export default function VersionHistoryPanel({ fileId, onRestore }: Props) {
  const { t } = useTranslation()
  const [versions, setVersions] = useState<VR[]>([])
  const [loading, setLoading] = useState(true)
  const [failed, setFailed] = useState(false)

  useEffect(() => {
    let alive = true
    setLoading(true)
    setFailed(false)
    void (async () => {
      try {
        const v = await listVersions(fileId)
        if (alive) setVersions(v)
      } catch {
        if (alive) setFailed(true)
      } finally {
        if (alive) setLoading(false)
      }
    })()
    return () => { alive = false }
  }, [fileId])

  if (loading) {
    return (
      <div className="flex items-center justify-center gap-2 p-8 text-sm text-muted-foreground">
        <Loader2 className="size-4 animate-spin" aria-hidden />
        {t('editor.versions.loading')}
      </div>
    )
  }
  if (failed) return <div className="p-4 text-sm text-destructive">{t('editor.versions.loadFailed')}</div>
  if (versions.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center px-4 py-12 text-center text-sm text-muted-foreground">
        <p className="font-medium text-foreground">{t('editor.versions.empty')}</p>
        <p className="mt-1 text-xs">{t('editor.versions.emptyHint')}</p>
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
